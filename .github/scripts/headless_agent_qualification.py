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
MAX_MESSAGE_PAGES = 16
MAX_OUTBOX_PAGES = 16
MAX_U64 = (1 << 64) - 1


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def no_duplicate_fields(pairs):
    """Never let a repeated field change how a scoped MCP reply is interpreted."""
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate MCP JSON field")
        value[key] = item
    return value


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
        # One owner grant.issue per role. A lost reply may already have minted a
        # grant, and a lost revoke reply may already have removed it. Neither
        # ambiguity permits another owner write from this fixture instance.
        self.issue_attempted = False
        self.revoke_uncertain = False

    def revoke(self):
        require(self.grant is not None and not self.revoke_uncertain,
                "grant revocation unconfirmed; do not retry")
        self.revoke_uncertain = True
        revoked = self.daemon.call("grant.revoke", **self.grant)
        require(isinstance(revoked, dict) and revoked.get("revoked") is True,
                "grant revocation unconfirmed")
        self.grant = None
        self.revoke_uncertain = False

    def issue(self, operation):
        require(not self.issue_attempted and self.grant is None and not self.owns_file,
                "agent grant already attempted or issued")
        require(isinstance(operation, str) and re.fullmatch(r"[a-f0-9]{32}", operation)
                and operation != "0" * 32, "invalid grant operation")
        check_grant_path(self.grant_path)  # Refuse an existing file before minting anything.
        status = self.daemon.call("room.status", room=self.room)
        require(isinstance(status, dict) and status.get("room") == self.room,
                "room status differs from selected room")
        self.scope = fixed_public_scope(status, self.pin)
        now = int(self.clock())
        self.issue_attempted = True
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
        first, second = [json.loads(line, object_pairs_hook=no_duplicate_fields)
                         for line in raw.splitlines()]
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
        require(data.get("kind") == "public" and data.get("author") == self.scope["author"]
                and data.get("policy") == self.scope["policy"]
                and type(data.get("revision")) is int
                and data["revision"] == self.scope["revision"],
                "agent status changed pinned public scope")
        remaining = data.get("remaining")
        require(data.get("freshness") == "local authenticated state"
                and isinstance(remaining, dict) and set(remaining) == set(BUDGET)
                and all(type(remaining[name]) is int and 0 <= remaining[name] <= maximum
                        for name, maximum in BUDGET.items()),
                "agent status lacks finite authenticated allowance")
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

    def peer_event(self, peer, text):
        """Find one locally admitted signed peer event, not delivery or execution.

        The caller must independently pin the peer author and use a unique
        synthetic text. Scan a complete stable local MCP inbox, not an owner
        read or a single page; never return the message body in the summary.
        """
        require(self.scope is not None and isinstance(peer, str)
                and re.fullmatch(r"[a-f0-9]{64}", peer)
                and peer != self.scope["author"] and isinstance(text, str)
                and 0 < len(text.encode("utf-8")) <= BUDGET["body_bytes"],
                "invalid pinned peer event intent")
        after, head, match = 0, None, None
        for _ in range(MAX_MESSAGE_PAGES):
            page = self.call("agent.messages", after=after, limit=16)
            rows = page.get("records")
            require(page.get("kind") == "public"
                    and type(page.get("head")) is int and after <= page["head"] <= MAX_U64
                    and "next" in page
                    and (page["next"] is None or (type(page["next"]) is int
                        and after < page["next"] < page["head"]))
                    and isinstance(rows, list) and len(rows) <= 16,
                    "peer message page is incomplete or unsupported")
            if head is None:
                head = page["head"]
            require(page["head"] == head, "local inbox changed during peer check")
            previous = after
            for row in rows:
                require(isinstance(row, dict) and type(row.get("cursor")) is int
                        and previous < row["cursor"] <= head
                        and type(row.get("sequence")) is int and 0 <= row["sequence"] <= MAX_U64
                        and all(isinstance(row.get(key), str)
                                and re.fullmatch(r"[a-f0-9]{64}", row[key])
                                for key in ("event", "author", "policy"))
                        and row.get("visibility") in ("Provisional", "OwnerSealed",
                                                       "ContinuityOnly", "Incomplete")
                        and row.get("trust") == "inert untrusted room content"
                        and isinstance(row.get("text"), str)
                        and len(row["text"].encode("utf-8")) <= BUDGET["body_bytes"],
                        "peer message row lacks bounded signed metadata")
                previous = row["cursor"]
                if row["text"] == text:
                    require(row["author"] == peer and row["policy"] == self.scope["policy"]
                            and row["visibility"] in ("Provisional", "OwnerSealed"),
                            "peer message is not admitted under the pinned author and policy")
                    require(match is None, "peer message was duplicated")
                    match = {"event": row["event"], "author": peer,
                             "sequence": row["sequence"], "visibility": row["visibility"],
                             "local_signed_event_once": True, "delivery": "not asserted"}
            require(page["next"] is None or previous <= page["next"],
                    "peer message cursor regressed")
            if page["next"] is None:
                require(match is not None, "pinned peer event not found in local inbox")
                return match
            after = page["next"]
        raise ValueError("local inbox exceeded peer scan bound")

    def outbox_status(self, after=0, limit=16):
        """Local completion metadata only; neither remote delivery nor execution."""
        require(type(after) is int and 0 <= after <= MAX_U64
                and type(limit) is int and 1 <= limit <= 16,
                "invalid bounded outbox page")
        page = self.call("agent.outbox_status", after=after, limit=limit)
        rows = page.get("operations")
        require(page.get("kind") == "public" and page.get("delivery") == "not asserted"
                and type(page.get("head")) is int and after <= page["head"] <= MAX_U64
                and "next" in page
                and (page["next"] is None or (type(page["next"]) is int
                    and after < page["next"] < page["head"]))
                and isinstance(rows, list) and len(rows) <= limit,
                "local outbox page is incomplete or unsupported")
        previous = after
        for row in rows:
            require(isinstance(row, dict) and type(row.get("cursor")) is int
                    and previous < row["cursor"] <= page["head"]
                    and isinstance(row.get("operation"), str)
                    and re.fullmatch(r"[a-f0-9]{32}", row["operation"])
                    and row.get("kind") in ("Event", "Policy")
                    and isinstance(row.get("frame_hash"), str)
                    and re.fullmatch(r"[a-f0-9]{64}", row["frame_hash"]),
                    "local outbox row is not bounded completion metadata")
            previous = row["cursor"]
        require(page["next"] is None or previous <= page["next"],
                "local outbox cursor regressed")
        return page

    def exact_local_retry(self, operation, text):
        """Check two successful MCP sends against one complete local outbox scan.

        Never retry after an ambiguous send. This proves neither the remote
        peer's delivery nor a human read; the two-machine runner must check both.
        """
        require(isinstance(operation, str) and re.fullmatch(r"[a-f0-9]{32}", operation)
                and operation != "0" * 32 and isinstance(text, str)
                and 0 < len(text.encode("utf-8")) * 2 <= BUDGET["body_bytes"],
                "invalid bounded retry intent")
        first = self.send(operation, text)
        require(first.get("state") in ("Provisional", "OwnerSealed"),
                "first send is not locally admitted")
        require(first["exact_retry"] is False, "first send was already an exact retry")
        second = self.send(operation, text)
        require(second.get("state") in ("Provisional", "OwnerSealed"),
                "exact retry is not locally admitted")
        require(second["exact_retry"] is True and second["frame_hash"] == first["frame_hash"],
                "exact retry changed signed frame")
        after, head, matches = 0, None, []
        for _ in range(MAX_OUTBOX_PAGES):
            page = self.outbox_status(after)
            if head is None:
                head = page["head"]
            require(page["head"] == head, "local outbox changed during retry check")
            matches.extend(row for row in page["operations"] if row["operation"] == operation)
            if page["next"] is None:
                require(len(matches) == 1 and matches[0]["kind"] == "Event"
                        and matches[0]["frame_hash"] == first["frame_hash"],
                        "retry has no unique local signed completion")
                return {"frame_hash": first["frame_hash"], "local_completion_once": True,
                        "delivery": "not asserted"}
            after = page["next"]
        raise ValueError("local outbox exceeded retry scan bound")

    def close(self):
        """Revoke and remove our private file; do not hide an uncertain revoke."""
        try:
            if self.grant is not None:
                self.revoke()
            else:
                require(not self.revoke_uncertain,
                        "grant revocation unconfirmed; do not retry")
        finally:
            if self.owns_file:
                self.grant_path.unlink(missing_ok=True)
                self.owns_file = False


def issue_agent_pair(first, second, operations, machine_ids):
    """Mint two disjoint scoped grants after checking one pinned public room.

    Machine IDs are caller declarations, NOT evidence of independent hardware.
    This is only an issuance fixture: no MCP call, network peer, delivery or
    physical placement is established. The runner must independently verify
    placement, exchange, restart, refusals, and cleanup before publishing a pass.
    """
    require(isinstance(first, ScopedAgent) and isinstance(second, ScopedAgent)
            and first is not second and first.daemon is not second.daemon
            and first.daemon.home.resolve() != second.daemon.home.resolve()
            and first.grant_path.parent.resolve() != second.grant_path.parent.resolve()
            and all(not agent.issue_attempted and agent.grant is None and not agent.owns_file
                    for agent in (first, second)),
            "paired agents must have separate homes and private work roots")
    require(isinstance(machine_ids, (tuple, list)) and len(machine_ids) == 2
            and all(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value)
                    and value != "0" * 64 for value in machine_ids)
            and machine_ids[0] != machine_ids[1],
            "paired machine identifiers must be distinct declarations")
    require(isinstance(operations, (tuple, list)) and len(operations) == 2
            and all(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{32}", value)
                    and value != "0" * 32 for value in operations)
            and operations[0] != operations[1], "paired grant operations must be distinct")
    scopes = []
    for agent in (first, second):
        check_grant_path(agent.grant_path)
        status = agent.daemon.call("room.status", room=agent.room)
        require(isinstance(status, dict) and status.get("room") == agent.room,
                "paired room status differs from selected room")
        scopes.append(fixed_public_scope(status, agent.pin))
    require(all(scopes[0][key] == scopes[1][key] for key in ("pin", "policy", "revision"))
            and scopes[0]["author"] != scopes[1]["author"],
            "paired rooms lack a shared pin and policy with distinct authors")
    issued_agents, issued = [], []
    try:
        for agent, operation, scope in zip((first, second), operations, scopes):
            summary = agent.issue(operation)  # Re-check each room at issuance.
            issued_agents.append(agent)
            require(summary["scope"] == scope, "paired room changed during issuance")
            issued.append(summary)
        require(first.grant != second.grant, "paired grants reused credentials")
    except BaseException:
        # A failing issue already tried its own revocation. Never repeat an
        # uncertain revoke; clean up only earlier, successfully issued grants.
        failures = []
        for agent in reversed(issued_agents):
            if agent.grant is not None:
                try:
                    agent.close()
                except BaseException as failure:
                    failures.append(failure)
        if failures:
            raise ValueError("paired grant cleanup unconfirmed") from failures[0]
        raise
    return {"agents": [{"declared_machine_id": machine, **summary}
                       for machine, summary in zip(machine_ids, issued)],
            "machine_identity": "caller declared; placement unverified",
            "delivery": "not asserted"}
