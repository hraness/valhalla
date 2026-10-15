#!/usr/bin/env python3
"""Private, bounded MCP grant client for a future independent-agent journey.

This module is a fixture seam, NOT a two-agent qualification result. A separate
orchestrator must create two clients on distinct machines, perform the pinned
host exchange and refuse a pass unless its live cases and cleanup complete.
Owner-admin calls here issue/revoke grants only; agent data calls use MCP.
Never upload the grant file, process input/output, home or message content.
"""

import json
import os
from pathlib import Path
import re
import stat
import time

import headless_mcp_qualification as mcp
import headless_qualification as public


# A finite ceiling, not an allowance to exhaust during an unbounded poll.
BUDGET = {"calls": 512, "send_attempts": 8, "body_bytes": 4096,
          "read_records": 2048, "read_bytes": 8 * 1024 * 1024}
PERMISSIONS = {name: True for name in ("status", "messages", "send", "outbox_status")}
MAX_GRANT_BYTES = 16384
MAX_FRAME_BYTES = 65536


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def fixed_public_scope(status, pin):
    """Bind an agent to the selected signed room, never a caller-supplied room."""
    require(isinstance(status, dict) and status.get("kind") == "public"
            and status.get("pin") == pin and isinstance(pin, str)
            and re.fullmatch(r"[a-f0-9]{64}", pin), "agent room is not the pinned public room")
    policy = status.get("policy")
    require(isinstance(policy, dict) and isinstance(policy.get("id"), str)
            and re.fullmatch(r"[a-f0-9]{64}", policy["id"])
            and type(policy.get("revision")) is int and policy["revision"] >= 0
            and isinstance(status.get("author"), str)
            and re.fullmatch(r"[a-f0-9]{64}", status["author"]),
            "agent room has no verified author and policy")
    return {"kind": "public", "pin": pin, "author": status["author"],
            "policy": policy["id"], "revision": policy["revision"]}


def check_grant_path(path):
    parent = path.parent.lstat()
    require(stat.S_ISDIR(parent.st_mode) and not path.parent.is_symlink()
            and parent.st_uid == os.geteuid() and parent.st_mode & 0o077 == 0
            and not path.exists() and not path.is_symlink(), "grant path is not new and private")


def private_grant(path, grant):
    """Create a non-public one-use launch file without following any links."""
    check_grant_path(path)
    require(isinstance(grant, dict) and set(grant) == {"generation", "token"}
            and all(isinstance(grant[key], str) and re.fullmatch(r"[a-f0-9]{64}", grant[key])
                    for key in ("generation", "token")), "invalid grant credentials")
    raw = (json.dumps(grant, sort_keys=True, separators=(",", ":")) + "\n").encode()
    require(len(raw) <= MAX_GRANT_BYTES, "grant file exceeds bound")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


class AgentRefusal(Exception):
    """A typed MCP refusal, with no untrusted text or private values."""
    def __init__(self, code):
        super().__init__("scoped MCP operation refused")
        self.code = code


class ScopedAgent:
    """One independently issued grant consumed only by MCP on its home VM.

    The daemon object is the existing owned headless public fixture daemon.
    `exchange` uses its bounded, no-shell pipe transport and process group.
    No owner-admin send/read shortcut is available through this object.
    """

    def __init__(self, daemon, room, pin, grant_path, *, transport=public.exchange,
                 clock=time.time):
        require(isinstance(room, str) and re.fullmatch(r"[a-f0-9]{32}", room)
                and room != "0" * 32, "invalid local room")
        require(isinstance(grant_path, Path) and grant_path.is_absolute(),
                "grant file must be absolute")
        require(grant_path.parent == Path(daemon.config["work"])
                and grant_path.parent != daemon.home, "grant must stay in the owned private work")
        self.daemon, self.room, self.pin = daemon, room, pin
        self.grant_path = grant_path
        self.transport, self.clock = transport, clock
        self.scope = None
        self.grant = None
        self.owns_file = False

    def revoke(self):
        revoked = self.daemon.call("grant.revoke", **self.grant)
        require(revoked.get("revoked") is True, "grant revocation unconfirmed")
        self.grant = None

    def issue(self, operation):
        require(self.grant is None and not self.owns_file, "agent grant already issued")
        require(isinstance(operation, str) and re.fullmatch(r"[a-f0-9]{32}", operation)
                and operation != "0" * 32, "invalid grant operation")
        check_grant_path(self.grant_path)  # Refuse an existing file before minting anything.
        status = self.daemon.call("room.status", room=self.room)
        self.scope = fixed_public_scope(status, self.pin)
        now = int(self.clock())
        result = self.daemon.call("grant.issue", operation=operation, room=self.room,
            grant={"scope": self.scope, "permissions": PERMISSIONS, "budget": BUDGET,
                   "not_before": now - 1, "expires_at": now + 600})
        # A successful but unexpected owner reply may already have minted a live
        # grant. Capture its credentials before checking display metadata so it
        # can be revoked; without credentials the outcome cannot be reconciled.
        credentials = {name: result.get(name) for name in ("generation", "token")} if isinstance(result, dict) else {}
        require(all(isinstance(credentials.get(name), str)
                    and re.fullmatch(r"[a-f0-9]{64}", credentials[name])
                    for name in ("generation", "token")),
                "issued grant credentials unavailable; revocation unconfirmed")
        self.grant = credentials
        try:
            require(result.get("room") == self.room and result.get("scope") == self.scope
                    and result.get("permissions") == PERMISSIONS
                    and result.get("expires_at") == now + 600,
                    "issued grant differs from selected scope")
            # Strip owner-only display metadata before writing the private launcher.
            private_grant(self.grant_path, credentials)
            self.owns_file = True
        except BaseException:
            # No retry of issuance. If revocation is uncertain, surface it.
            self.revoke()
            raise
        return {"scope": self.scope.copy(), "permissions": PERMISSIONS.copy(),
                "budget": BUDGET.copy(), "expires_in_seconds": 600}

    def call(self, name, **arguments):
        require(self.grant is not None and self.owns_file, "MCP grant has not been issued")
        require(name in mcp.TOOLS, "unknown scoped MCP operation")
        initialize = {"jsonrpc": "2.0", "id": "initialize", "method": "initialize", "params": {
            "protocolVersion": mcp.INITIALIZE_PROTOCOL, "capabilities": {},
            "clientInfo": {"name": "valhalla-agent-qualification", "version": "1"}}}
        notification = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        request = mcp.tool(1, name, **arguments)
        payload = b"".join(json.dumps(item, separators=(",", ":")).encode() + b"\n"
                           for item in (initialize, notification, request))
        require(len(payload) <= MAX_FRAME_BYTES, "MCP input exceeds bound")
        argv = self.daemon.argv + ["mcp", "--home", str(self.daemon.home),
                                   "--grant", str(self.grant_path)]
        code, raw = self.transport(argv, payload, self.daemon.env, timeout=35)
        require(code == 0 and len(raw) <= public.MAX_REPLY and raw.endswith(b"\n"),
                "MCP process failed or output is incomplete")
        require(all(self.grant[key].encode() not in raw for key in ("generation", "token")),
                "MCP output exposed grant credentials")
        require(len(raw.splitlines()) == 2, "MCP protocol output differs")
        first, second = [json.loads(line) for line in raw.splitlines()]
        require(first.get("jsonrpc") == "2.0" and first.get("id") == "initialize"
                and first.get("result", {}).get("protocolVersion") == mcp.INITIALIZE_PROTOCOL
                and first["result"].get("serverInfo", {}).get("name") == "valhalla",
                "MCP handshake differs")
        require(second.get("jsonrpc") == "2.0" and second.get("id") == 1,
                "MCP reply ID differs")
        if "error" in second:
            error = second["error"]
            require(isinstance(error, dict) and type(error.get("code")) is int,
                    "untyped MCP protocol refusal")
            raise AgentRefusal(error["code"])
        result = second.get("result")
        require(isinstance(result, dict) and type(result.get("isError")) is bool
                and isinstance(result.get("structuredContent"), dict),
                "MCP result is not structured")
        data = result["structuredContent"]
        if result["isError"]:
            require(data.get("status") == "refused" and isinstance(data.get("code"), str),
                    "untyped daemon refusal")
            raise AgentRefusal(data["code"])
        require(data.get("room") == self.room, "agent response escaped selected room")
        return data

    def status(self):
        data = self.call("agent.status")
        require(data.get("kind") == "public" and data.get("author") == self.scope["author"],
                "agent status changed public author")
        return data

    def send(self, operation, text):
        result = self.call("agent.send", operation=operation, text=text)
        require(result.get("operation") == operation and type(result.get("exact_retry")) is bool
                and result.get("delivery") == "not asserted"
                and isinstance(result.get("frame_hash"), str)
                and re.fullmatch(r"[a-f0-9]{64}", result["frame_hash"]),
                "agent send has unsupported delivery or retry claim")
        return result

    def messages(self, after=0, limit=4):
        require(type(after) is int and after >= 0 and type(limit) is int and 1 <= limit <= 16,
                "invalid bounded page")
        result = self.call("agent.messages", after=after, limit=limit)
        records = result.get("records")
        require(isinstance(records, list) and len(records) <= limit
                and all(isinstance(row, dict) and row.get("trust") == "inert untrusted room content"
                        for row in records), "message page is not inert bounded data")
        return records

    def close(self):
        """Revoke and remove our private file; do not hide an uncertain revoke."""
        if self.grant is None:
            return
        try:
            self.revoke()
        finally:
            if self.owns_file:
                self.grant_path.unlink(missing_ok=True)
                self.owns_file = False
