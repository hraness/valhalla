#!/usr/bin/env python3
"""Exercise a real foreground daemon and MCP executable through bounded pipes.

Use a new private work directory and a read-only, immutable candidate. No build,
installed service, external peer, relay, existing home, or user grant is used.
Only receipt.json is shareable; retained homes, grants and diagnostics are private.
Run through the shared compute lane. The same adapter can qualify installed bytes
after copying them to an immutable task-owned candidate.
"""

import argparse
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time

from headless_managed_qualification import (cleanup_signals, digest, require,
                                           run_command, stamp, write_json)

SCHEMA = "valhalla.headless-mcp-process.v1"
PROTOCOL = "2026-07-28"
INITIALIZE_PROTOCOL = "2025-11-25"
TOOLS = {"agent.status", "agent.messages", "agent.send", "agent.outbox_status"}
CASES = ("fresh_daemon", "initialize_handshake", "four_tools_discovered", "fixed_room_status", "granted_send",
         "exact_retry", "granted_read", "granted_outbox", "reconnect_budget_refused",
         "single_retained_message", "protocol_only_stdout", "credentials_not_exposed")
MESSAGE = "synthetic MCP process qualification message"
JOURNEY_SECONDS = 120
COMMAND_SECONDS = 20


def frame(number, method, **params):
    return {"jsonrpc": "2.0", "id": number, "method": method, "params": {
        "_meta": {"io.modelcontextprotocol/protocolVersion": PROTOCOL,
                  "io.modelcontextprotocol/clientCapabilities": {}}, **params}}


def tool(number, name, **arguments):
    return frame(number, "tools/call", name=name, arguments=arguments)


def replies(raw, requests):
    """Require complete newline frames, exact request IDs and protocol-only output."""
    require(raw.endswith(b"\n"), "MCP output is not newline terminated")
    lines = raw.splitlines()
    require(len(lines) == len(requests), "MCP reply count differs")
    values = [json.loads(line) for line in lines]
    for value, request in zip(values, requests):
        require(isinstance(value, dict) and value.get("jsonrpc") == "2.0"
                and value.get("id") == request["id"] and "error" not in value
                and isinstance(value.get("result"), dict), "MCP protocol reply differs")
    return [value["result"] for value in values]


def content(value):
    require(value.get("isError") is False and isinstance(value.get("structuredContent"), dict),
            "MCP tool did not return successful structured content")
    return value["structuredContent"]


class McpRun:
    def __init__(self, binary, expected_digest, work, source_sha, *, runner=run_command,
                 popen=subprocess.Popen, clock=time.monotonic, sleep=time.sleep):
        require(re.fullmatch(r"[a-f0-9]{64}", expected_digest), "invalid binary digest")
        require(re.fullmatch(r"[a-f0-9]{40}", source_sha), "invalid source revision")
        require(binary.is_absolute() and not binary.is_symlink(), "candidate must be absolute and regular")
        self.binary = binary.resolve(strict=True)
        info = self.binary.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and info.st_nlink == 1 and info.st_mode & 0o6222 == 0
                and info.st_mode & 0o111 != 0, "candidate must be owned, immutable and executable")
        self.binary_stamp = stamp(info)
        self.binary_digest = expected_digest
        require(digest(self.binary) == expected_digest, "candidate digest differs")
        require(work.is_absolute() and work.name not in ("", ".", "..")
                and not work.exists() and not work.is_symlink(), "work must be a new absolute directory")
        self.work = work.parent.resolve(strict=True) / work.name
        self.home = self.work / "home"
        require(len(os.fsencode(self.home / "control/admin.sock")) < 104, "synthetic home exceeds socket bound")
        self.work.mkdir(mode=0o700)
        self.grant_file = self.work / "grant.json"
        self.env = {"HOME": os.environ["HOME"], "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                    "RUST_BACKTRACE": "0", "HRANESS_NO_UPDATE": "1"}
        self.runner, self.popen, self.clock, self.sleep = runner, popen, clock, sleep
        self.deadline = clock() + JOURNEY_SECONDS
        self.child = None
        self.version = None
        self.phase = "preflight"
        self.last_command = None
        self.result = dict(schema=SCHEMA, source_sha=source_sha, binary_sha256=expected_digest,
                           runner_sha256=digest(Path(__file__)), platform=sys.platform,
                           scope="one fresh public room; actual foreground daemon and MCP pipes; no network peer",
                           passed=False, cleanup_confirmed=False, cleanup_fallback_used=False,
                           started_unix=int(time.time()), cases={name: False for name in CASES})

    def check_candidate(self, full=False):
        require(stamp(self.binary.lstat()) == self.binary_stamp, "candidate file changed")
        if full:
            require(digest(self.binary) == self.binary_digest, "candidate bytes changed")

    def command(self, action, payload=b"", extra=()):
        self.check_candidate()
        remaining = self.deadline - self.clock()
        require(remaining > 0, "MCP qualification deadline")
        argv = [str(self.binary), "--no-update", "daemon", action, "--home", str(self.home), *extra]
        self.last_command = {"action": action}
        code, raw, err = self.runner(argv, payload, self.env, min(COMMAND_SECONDS, remaining))
        self.last_command.update(exit_code=code, stdout=raw.decode("utf-8", errors="replace"),
                                 stderr=err.decode("utf-8", errors="replace"))
        return code, raw

    def cli(self, action, request=None):
        payload = b"" if request is None else json.dumps(request).encode() + b"\n"
        code, raw = self.command(action, payload)
        value = json.loads(raw)
        require(code == 0 and isinstance(value, dict) and value.get("ok") is True
                and isinstance(value.get("result"), dict), "owner command refused")
        return value["result"]

    def call(self, op, **fields):
        return self.cli("call", dict(op=op, **fields))

    def start(self):
        self.check_candidate()
        remaining = self.deadline - self.clock()
        require(remaining > 0, "MCP qualification deadline")
        code, raw, _err = self.runner([str(self.binary), "--version"], b"", self.env,
                                     min(COMMAND_SECONDS, remaining))
        matched = re.fullmatch(rb"vhalla ([0-9]+\.[0-9]+\.[0-9]+) features=\[[a-z0-9,-]*\]\n?", raw)
        require(code == 0 and matched is not None, "candidate version output differs")
        self.version = matched.group(1).decode("ascii")
        require(self.cli("init") == {"initialized": True}, "new daemon initialization failed")
        self.check_candidate()
        log_path = self.work / "daemon.log"
        with log_path.open("xb") as log:
            os.chmod(log_path, 0o600)
            self.child = self.popen([str(self.binary), "--no-update", "daemon", "run", "--home",
                                     str(self.home), "--bind", "127.0.0.1:0"],
                                    stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                    env=self.env, start_new_session=True)
        end = min(self.deadline, self.clock() + 30)
        while self.clock() < end:
            require(self.child.poll() is None, "daemon exited before readiness")
            code, raw = self.command("status")
            value = json.loads(raw)
            if code == 0 and value.get("ok") is True:
                status = value["result"]
                require(status.get("headless") is True and status["network"]["listening"] is True
                        and status["network"]["configured"]["relay_url"] is None
                        and status["network"]["configured"]["relay_only"] is False,
                        "daemon did not expose the selected headless configuration")
                return
            require(value.get("error", {}).get("code") in ("owner-unavailable", "not-found"),
                    "unexpected readiness refusal")
            self.sleep(0.1)
        raise TimeoutError("daemon readiness deadline")

    def mcp(self, requests, grant):
        # Exercise the ordinary handshake as well as the current explicit
        # per-request protocol metadata. The adapter supports both on one pipe.
        initialize = {"jsonrpc": "2.0", "id": "initialize", "method": "initialize", "params": {
            "protocolVersion": INITIALIZE_PROTOCOL, "capabilities": {},
            "clientInfo": {"name": "valhalla-process-qualification", "version": "1"}}}
        notification = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        payload = b"".join(json.dumps(request).encode() + b"\n"
                           for request in [initialize, notification, *requests])
        code, raw = self.command("mcp", payload, ("--grant", str(self.grant_file)))
        require(code == 0, "MCP process failed")
        initialized, *values = replies(raw, [initialize, *requests])
        require(initialized.get("protocolVersion") == INITIALIZE_PROTOCOL
                and initialized.get("capabilities", {}).get("tools") == {}
                and initialized.get("serverInfo", {}).get("name") == "valhalla"
                and initialized.get("serverInfo", {}).get("version") == self.version,
                "MCP initialization differs from the candidate")
        require(all(grant[name].encode() not in raw for name in ("token", "generation")),
                "MCP output exposed launch credentials")
        self.result["cases"]["initialize_handshake"] = True
        return values

    def journey(self):
        self.phase = "daemon"
        self.start()
        self.result["cases"]["fresh_daemon"] = True
        room = self.call("room.create", operation=f"{1:032x}", kind="public",
                         limits={"max_records": 128, "max_record_bytes": 1048576})
        now = int(time.time())
        grant = self.call("grant.issue", operation=f"{2:032x}", room=room["room"], grant={
            "scope": {"kind": "public", "pin": room["pin"], "author": room["author"],
                      "policy": room["policy"]["id"], "revision": room["policy"]["revision"]},
            "permissions": {name: True for name in ("status", "messages", "send", "outbox_status")},
            "budget": {"calls": 5, "send_attempts": 2, "body_bytes": 1024,
                       "read_records": 4, "read_bytes": 1048576},
            "not_before": now - 1, "expires_at": now + 300})
        write_json(self.grant_file, grant)
        self.phase = "mcp_tools"
        operation = f"{3:032x}"
        requests = [frame(1, "tools/list"), tool(2, "agent.status"),
                    tool(3, "agent.send", operation=operation, text=MESSAGE),
                    tool(4, "agent.send", operation=operation, text=MESSAGE),
                    tool(5, "agent.messages", after=0, limit=4),
                    tool(6, "agent.outbox_status", after=0, limit=16)]
        listed, status, sent, retry, page, outbox = self.mcp(requests, grant)
        require({item["name"] for item in listed["tools"]} == TOOLS and len(listed["tools"]) == 4,
                "MCP discovery differs")
        require(all(item["inputSchema"].get("additionalProperties") is False
                    and "room" not in item["inputSchema"].get("properties", {}) for item in listed["tools"]),
                "MCP discovery permits room selection")
        self.result["cases"]["four_tools_discovered"] = True
        status, sent, retry, page, outbox = [content(value) for value in (status, sent, retry, page, outbox)]
        require(all(value.get("room") == room["room"] for value in (status, sent, retry, page, outbox)),
                "MCP result escaped the granted room")
        self.result["cases"]["fixed_room_status"] = True
        require(sent["operation"] == operation and sent["exact_retry"] is False, "first send differs")
        self.result["cases"]["granted_send"] = True
        require(retry["operation"] == operation and retry["exact_retry"] is True
                and retry["frame_hash"] == sent["frame_hash"], "retry changed signed bytes")
        self.result["cases"]["exact_retry"] = True
        require(len(page["records"]) == 1 and page["records"][0]["text"] == MESSAGE, "granted read differs")
        self.result["cases"]["granted_read"] = True
        matching = [row for row in outbox["operations"] if row["operation"] == operation]
        require(len(matching) == 1 and matching[0]["frame_hash"] == sent["frame_hash"], "outbox differs")
        self.result["cases"]["granted_outbox"] = True
        self.phase = "reconnect"
        refused = self.mcp([tool(1, "agent.status")], grant)[0]
        require(refused.get("isError") is True
                and refused.get("structuredContent", {}).get("code") == "permission-denied",
                "new MCP process replenished an exhausted grant")
        self.result["cases"]["reconnect_budget_refused"] = True
        owner_page = self.call("room.messages", room=room["room"], after=0, limit=4)
        require(len(owner_page["records"]) == 1 and owner_page["records"][0]["body"] == MESSAGE,
                "exact retry duplicated retained message")
        for case in ("single_retained_message", "protocol_only_stdout", "credentials_not_exposed"):
            self.result["cases"][case] = True
        self.check_candidate(full=True)

    def cleanup(self):
        if self.child is None:
            return True
        child = self.child
        try:
            require(child.poll() is None, "daemon exited before cleanup")
            self.cli("stop")
            require(child.wait(timeout=15) == 0, "daemon did not stop cleanly")
        except BaseException:
            self.result["cleanup_fallback_used"] = True
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=5)
        finally:
            self.child = None
        return child.poll() is not None

    def run(self):
        try:
            self.journey()
        except BaseException as failure:
            self.result.update(error_class=type(failure).__name__, failed_phase=self.phase)
            try:
                write_json(self.work / "diagnostic.json", {"phase": self.phase,
                    "error_class": type(failure).__name__, "error": str(failure), "command": self.last_command})
            except BaseException as diagnostic_failure:
                self.result["diagnostic_error_class"] = type(diagnostic_failure).__name__
        finally:
            with cleanup_signals():
                self.deadline = self.clock() + 40
                try:
                    self.result["cleanup_confirmed"] = self.cleanup()
                except BaseException as failure:
                    self.result["cleanup_error_class"] = type(failure).__name__
                self.result["passed"] = ("error_class" not in self.result and self.result["cleanup_confirmed"]
                    and not self.result["cleanup_fallback_used"] and all(self.result["cases"].values()))
                self.result["finished_unix"] = int(time.time())
                write_json(self.work / "receipt.json", self.result)
        return self.result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    require(os.name == "posix", "MCP daemon qualification requires Unix")
    def interrupted(_signal, _frame):
        raise InterruptedError("MCP qualification interrupted")
    for selected in (signal.SIGINT, signal.SIGTERM):
        signal.signal(selected, interrupted)
    result = McpRun(args.binary, args.binary_sha256, args.work, args.source_sha).run()
    print(json.dumps({name: result[name] for name in ("passed", "cleanup_confirmed", "cleanup_fallback_used")}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as failure:
        print(f"MCP qualification refused: {type(failure).__name__}", file=sys.stderr)
        sys.exit(1)
