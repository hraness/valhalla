#!/usr/bin/env python3
"""Bounded, synthetic, real-process private-room measurements (Python 3.11+).

No build, installation, launchd operation, grant renewal or state reset occurs.
All state and even failed-run evidence is retained in a new private directory.
See docs/performance.md before using a result as qualification evidence.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import time

TOOLS = {"private_status", "private_inbox", "private_prepare", "private_queue", "private_outbox_status"}
SCENARIOS = {"smoke": 2, "load": 100, "quiet": 1, "offline": 32}
WINDOW = 16
DRAIN_SECONDS = 120
POLL_SECONDS = 0.5
MAX_LINE = 1024 * 1024
MAX_LOG = 32 * 1024 * 1024
RPC_SECONDS = 30
CLEANUP_SECONDS = 60
GRANT = {"lifetime": 900, "max-preparations": 110, "max-messages": 110,
         "max-body-bytes": 1048576, "max-read-records": 256, "max-read-bytes": 33554432}
PRIVATE_OK = b"private operation completed; consult the retained result for delivery status\n"


class MeasurementError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise MeasurementError(message)


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + ".pending")
    with temporary.open("w", encoding="utf-8") as out:
        os.chmod(temporary, 0o600)
        json.dump(value, out, indent=2, sort_keys=True)
        out.write("\n")
        out.flush()
        os.fsync(out.fileno())
    os.replace(temporary, path)


def body_for(index):
    prefix = f"valhalla-runtime-{index:03d}|"
    return prefix + "x" * (128 - len(prefix))


def percentiles(values):
    ordered = sorted(values)
    if not ordered:
        return None
    return {f"p{p}": ordered[max(0, math.ceil(len(ordered) * p / 100) - 1)]
            for p in (50, 95, 99)}


def footprint(root):
    result = {"regular_files": 0, "logical_bytes": 0, "allocated_regular_bytes": 0}
    for parent, directories, files in os.walk(root, followlinks=False):
        directories[:] = [d for d in directories if not (Path(parent) / d).is_symlink()]
        for name in files:
            info = (Path(parent) / name).lstat()
            if stat.S_ISREG(info.st_mode):
                result["regular_files"] += 1
                result["logical_bytes"] += info.st_size
                result["allocated_regular_bytes"] += info.st_blocks * 512
    return result


def git(source, *args):
    return subprocess.check_output(["git", "-C", str(source), *args], timeout=15).decode().strip()


def native_fingerprint(source):
    # Browser work may proceed independently. All tracked native crate inputs,
    # workspace manifests and lockfiles must still match the candidate's HEAD.
    paths = [p for p in git(source, "ls-files", "crates", "Cargo.toml", "Cargo.lock", "rust-toolchain.toml").splitlines()
             if not p.startswith("crates/vhalla-cli/tools/")]
    unchanged = subprocess.run(["git", "-C", str(source), "diff", "--quiet", "HEAD", "--", *paths], timeout=15)
    require(unchanged.returncode == 0, "tracked native inputs differ from candidate HEAD")
    digest = hashlib.sha256()
    for name in paths:
        path = source / name
        require(path.is_file() and not path.is_symlink(), f"native input missing or symlink: {name}")
        actual = path.read_bytes()
        digest.update(name.encode() + b"\0" + hashlib.sha256(actual).digest())
    return digest.hexdigest()


def admit_candidate(cli, provenance, source):
    value = json.loads(provenance.read_text())
    require(value.get("passed") is True, "candidate provenance does not report passed")
    require(value.get("source_clean_at_build") is True, "candidate build was not clean")
    head = git(source, "rev-parse", "HEAD")
    tree = git(source, "rev-parse", "HEAD^{tree}")
    require(value.get("source_commit") == head, "candidate source_commit differs from checkout HEAD")
    require(value.get("source_tree") == tree, "candidate source_tree differs from checkout tree")
    require(value.get("lockfile_sha256") == sha256(source / "Cargo.lock"), "candidate Cargo.lock differs")
    digest = sha256(cli)
    require(value.get("artifact", {}).get("sha256") == digest, "candidate binary SHA256 differs")
    require(cli.is_file() and os.access(cli, os.X_OK), "candidate is not executable")
    return {"source_commit": head, "source_tree": tree, "cli": str(cli), "cli_sha256": digest,
            "provenance": str(provenance), "provenance_sha256": sha256(provenance),
            "lockfile_sha256": sha256(source / "Cargo.lock"),
            "native_inputs_sha256": native_fingerprint(source),
            "runner_sha256": sha256(Path(__file__)), "python": sys.version,
            "platform": platform.platform(), "machine": platform.machine()}


class Log:
    def __init__(self, path):
        self.path = path
        self.file = path.open("xb")
        os.chmod(path, 0o600)
        self.size = 0

    def add(self, value):
        data = (json.dumps(value, separators=(",", ":")) + "\n").encode()
        require(self.size + len(data) <= MAX_LOG, f"evidence log bound exceeded: {self.path.name}")
        self.file.write(data)
        self.file.flush()
        self.size += len(data)

    def close(self):
        self.file.flush()
        os.fsync(self.file.fileno())
        self.file.close()


class Child:
    def __init__(self, process, label, log):
        self.process, self.label, self.log = process, label, log
        self.stderr = asyncio.create_task(self.drain(process.stderr, "stderr"))
        self.forced = False
        self.closed = False
        self.sampled_start_identity = None

    async def drain(self, stream, channel):
        while data := await stream.read(16384):
            self.log.add({"monotonic_ns": time.monotonic_ns(), "process": self.label,
                          "channel": channel, "text": data.decode(errors="replace")})

    async def line(self):
        try:
            line = await asyncio.wait_for(self.process.stdout.readline(), 30)
        except ValueError as error:
            raise MeasurementError(f"{self.label}: oversized stdout line") from error
        require(line, f"{self.label}: unexpected stdout EOF")
        require(len(line) <= MAX_LINE, f"{self.label}: stdout line bound")
        self.log.add({"monotonic_ns": time.monotonic_ns(), "process": self.label,
                      "channel": "stdout", "text": line.decode(errors="replace")})
        return json.loads(line)

    async def close(self, host=False):
        if self.closed:
            return
        process = self.process
        if process.returncode is None:
            if host:
                process.send_signal(signal.SIGTERM)
            elif process.stdin:
                process.stdin.close()
            try:
                await asyncio.wait_for(process.wait(), 25)
            except asyncio.TimeoutError:
                self.forced = True
                process.kill()
                await asyncio.wait_for(process.wait(), 10)
        await asyncio.wait_for(self.stderr, 5)
        self.closed = True
        require(not self.forced and process.returncode == 0,
                f"{self.label}: unclean exit {process.returncode}, forced={self.forced}")


class Agent:
    def __init__(self, child, grant, context):
        self.child, self.grant, self.context = child, grant, context
        self.lock = asyncio.Lock()
        self.counter = 0

    async def ask(self, method, params):
        # A stream of notifications or a stalled pipe must not extend an RPC's
        # total deadline. This also bounds requests made during shutdown.
        return await asyncio.wait_for(self._ask(method, params), RPC_SECONDS)

    async def _ask(self, method, params):
        async with self.lock:
            self.counter += 1
            request = {"jsonrpc": "2.0", "id": self.counter, "method": method, "params": params}
            self.child.log.add({"monotonic_ns": time.monotonic_ns(), "process": self.child.label,
                                "channel": "request", "value": request})
            self.child.process.stdin.write((json.dumps(request) + "\n").encode())
            await self.child.process.stdin.drain()
            for _ in range(32):
                response = await self.child.line()
                if "id" not in response:
                    continue
                require(response.get("id") == self.counter, "MCP response ID mismatch")
                require("error" not in response and "result" in response, f"MCP {method} refused: {response}")
                return response["result"]
            raise MeasurementError("MCP notification bound exceeded")

    async def call(self, name, **args):
        result = await self.ask("tools/call", {"name": name, "arguments": {**args, "session": self.grant["grant_id"]}})
        require(not result.get("isError"), f"{name} returned an error: {result}")
        content = result.get("structuredContent")
        require(isinstance(content, dict), f"{name}: missing structuredContent")
        return content

    async def initialize(self):
        result = await self.ask("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                               "clientInfo": {"name": "valhalla-runtime-measurement", "version": "1"}})
        require(result.get("protocolVersion") == "2025-11-25", "MCP protocol mismatch")
        self.child.process.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        await self.child.process.stdin.drain()
        listed = (await self.ask("tools/list", {}))["tools"]
        require({item["name"] for item in listed} == TOOLS and len(listed) == 5, "MCP tool set changed")
        for item in listed:
            require(item["inputSchema"]["properties"]["session"]["const"] == self.grant["grant_id"], "MCP session schema mismatch")
        status = await self.call("private_status")
        require(status.get("status") == "live" and status.get("session") == self.grant["grant_id"], "agent is not live")
        require(status["context"]["device"] == self.context["device"], "agent device mismatch")
        return status


def check_inbox(records, expected, sender, observed):
    for record in records:
        sequence = int(record["sequence"])
        body = bytes.fromhex(record["body_hex"])
        require(body in expected, "unexpected received body")
        require(record["sender"] == sender, "unexpected received sender")
        require(sequence not in observed, "duplicate inbox sequence within one traversal")
        require(body not in observed.values(), "same message accepted at multiple inbox sequences")
        observed[sequence] = body


def next_cursor(page, previous):
    # `next` is the last raw record, including filtered acceptance records.
    cursor = int(page["next"]) if page.get("next") is not None else int(page["head"])
    require(cursor >= previous, "inbox cursor moved backwards")
    return cursor


class Fixture:
    def __init__(self, cli, root, scenario):
        self.cli, self.root, self.scenario = cli, root, scenario
        root.mkdir(mode=0o700)
        self.log = Log(root / "events.jsonl")
        self.children = []
        self.agents = {}
        self.generations = {"a": 0, "b": 0}
        self.contexts = {}
        self.keys = {}
        self.messages = {}
        self.offers = []
        self.max_outstanding = 0
        self.seen = {}
        self.cursor = 0
        self.host = None
        self.monitor_task = None
        self.monitor_stop = False
        self.samples = []
        self.resource_task = None
        self.checkpoints = {}
        self.reopens = []
        self.budgets = []
        self.cleanup = []
        self.command_index = 0
        self.last_observation_ns = None

    def env(self):
        return {**os.environ, "HRANESS_SUPPORT": "off", "XDG_STATE_HOME": str(self.root / "xdg-state")}

    def private_args(self, command, who, include_room=True, **flags):
        args = ["private", command, str(self.root / who / "identity")]
        if include_room:
            args.append(str(self.root / who / "room"))
        for key, value in flags.items():
            args += ["--" + key.replace("_", "-"), str(value)]
        return args

    async def spawn(self, label, args):
        process = await asyncio.create_subprocess_exec(str(self.cli), *args, stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=self.env(),
                    limit=MAX_LINE + 1)
        child = Child(process, label, self.log)
        self.children.append(child)
        self.log.add({"event": "spawn", "process": label, "pid": process.pid, "argv": args,
                      "monotonic_ns": time.monotonic_ns()})
        return child

    async def command(self, args):
        self.command_index += 1
        child = await self.spawn(f"command-{self.command_index}", args)
        child.process.stdin.close()
        result = bytearray()
        async def read():
            while data := await child.process.stdout.read(16384):
                result.extend(data)
                require(len(result) <= MAX_LINE, "command output exceeds bound")
        await asyncio.wait_for(read(), 30)
        await child.close()
        self.log.add({"event": "command-result", "process": child.label,
                      "text": result.decode(errors="replace")})
        return bytes(result)

    async def private(self, command, who, include_room=True, **flags):
        result = await self.command(self.private_args(command, who, include_room, **flags))
        require(result == PRIVATE_OK, f"private {command}: unexpected completion")

    async def setup(self):
        for who in ("a", "b"):
            (self.root / who).mkdir(mode=0o700)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        require(port not in (9473, 8790, 19473), "ephemeral port overlaps maintained fixture port")
        self.addr = f"127.0.0.1:{port}"
        host = self.root / "host"
        initialized = json.loads(await self.command(["private-host", "init", str(host), "--listen", self.addr,
                                "--tls-name", "runtime.test.invalid", "--executable", str(self.cli)]))
        require(initialized.get("status") == "initialized", "host initialization refused")
        self.connection = json.loads((host / "connection.json").read_text())
        self.host = await self.spawn("host", ["private-host", "serve", str(host)])
        ready = await self.host.line()
        require(ready.get("status") == "listening" and ready.get("listen") == self.addr, "host readiness mismatch")
        self.host_stdout = asyncio.create_task(self.host.drain(self.host.process.stdout, "stdout"))
        self.resource_task = asyncio.create_task(self.sample_resources())
        for who in ("a", "b"):
            raw = (await self.command(["identity", "init", str(self.root / who / "identity")])).decode().strip()
            require(raw.startswith("application-key ") and len(raw.split()[-1]) == 64, "identity output changed")
            self.keys[who] = raw.split()[-1]
        now = int(time.time())
        validity = {"not_before": now - 30, "expires": now + 7200}
        offer, review, request, response = [self.root / name for name in ("offer.secret", "offer-review.json", "request.cipher", "response.cipher")]
        await self.private("create", "a", **validity)
        await self.private("offer", "a", not_before=now-30, expires=now+3600,
                           recipient=self.keys["b"], operation=f"{1:032x}", out=offer)
        await self.private("offer-inspect", "b", False, offer=offer, owner=self.keys["a"], out=review)
        reviewed = json.loads(review.read_text())
        require(reviewed.get("kind") == "confidential-offer-metadata", "offer review kind changed")
        await self.private("import", "b", **validity, offer=offer, owner=self.keys["a"],
                           room=reviewed["room"], anchor=reviewed["anchor"])
        await self.private("request", "b", offer=offer, operation=f"{1:032x}", out=request)
        await self.private("accept", "a", not_before=now-30, expires=now+3600,
                           request=request, operation=f"{2:032x}", out=response)
        await self.private("join", "b", response=response)
        for index, who in enumerate(("a", "b"), 1):
            home = self.root / who
            await self.private("inspect", who, out=home / "inspect.json")
            context = json.loads((home / "inspect.json").read_text())["status"]
            self.contexts[who] = {k: context[k] for k in ("room", "anchor", "account", "device")}
            for name, origin in (("ca.der", "ca.der"), ("token.hex", f"client-{index}.token")):
                (home / name).write_bytes((host / origin).read_bytes())
                os.chmod(home / name, 0o600)
            write_json(home / "delivery.json", {"version": 1, "context": self.contexts[who],
                "namespace": self.connection["namespace"], "addr": self.addr, "tls_name": "runtime.test.invalid",
                "ca": str(home / "ca.der"), "token": str(home / "token.hex"), "state": str(home / "delivery-state"),
                "max_jobs": 1024, "max_bytes": 67108864, "max_attempts": 20, "initial_backoff_secs": 5,
                "max_backoff_secs": 300, "emit_acceptance": True, "initial_cursor": 0})
            await self.private("delivery-init", who, config=home / "delivery.json")
            write_json(home / "disclosure.json", {"host": f"synthetic runtime measurement {who}", "provider": "none",
                "model": "fixture", "processing_policy": "local synthetic content only", "allow_cooperating_host": True})
            await self.open_agent(who)
        # Give setup controls an explicit bounded settling interval. No synthetic
        # warm-up applications are hidden in the timed message counts.
        await asyncio.sleep(5)
        self.checkpoints["setup"] = footprint(self.root)

    async def open_agent(self, who):
        require(who not in self.agents, "agent already running")
        self.generations[who] += 1
        generation = self.generations[who]
        home = self.root / who
        grant_path, claim = home / f"grant-{generation}.json", home / f"claim-{generation}.json"
        started = time.monotonic_ns()
        await self.private("agent-grant", who, mode="read-write", disclosure=home / "disclosure.json",
                           receipt=claim, out=grant_path, follow_inbox="true", **GRANT)
        require(not claim.exists(), "grant unexpectedly consumed before serving")
        grant = json.loads(grant_path.read_text())
        spawned = time.monotonic_ns()
        child = await self.spawn(f"agent-{who}-{generation}", self.private_args("agent-serve", who,
                                  grant=grant_path, delivery=home / "delivery.json"))
        agent = Agent(child, grant, self.contexts[who])
        status = await agent.initialize()
        require(claim.is_file(), "agent did not retain its one-use claim")
        self.agents[who] = agent
        self.budgets.append({"who": who, "generation": generation, "grant": str(grant_path),
                             "initial_status": status, "limits": GRANT, "claim": str(claim)})
        self.reopens.append({"who": who, "generation": generation, "grant_start_ns": started,
                             "spawn_ns": spawned, "live_ns": time.monotonic_ns()})

    async def close_agent(self, who):
        agent = self.agents[who]
        status = await agent.call("private_status")
        self.budgets.append({"who": who, "generation": self.generations[who], "final_status": status})
        await agent.child.close()
        del self.agents[who]

    async def queue(self, index, scheduled_ns):
        agent = self.agents["a"]
        body = body_for(index)
        prepared_at = time.monotonic_ns()
        self.offers[index]["prepare_request_ns"] = prepared_at
        prepared = await agent.call("private_prepare", body=body)
        require(prepared.get("status") == "prepared_exact_content", "prepare did not retain exact content")
        before = time.monotonic_ns()
        operation = f"{4096 + index:032x}"
        queued = await agent.call("private_queue", draft=prepared["draft"], operation=operation)
        after = time.monotonic_ns()
        require(queued.get("status") == "durable_local_only" and "relay" not in queued, "queue result changed")
        sequence = int(queued["sequence"])
        require(sequence not in self.messages, "duplicate local outbox sequence")
        self.messages[sequence] = {"index": index, "operation": operation, "body_hex": body.encode().hex(),
            "scheduled_ns": scheduled_ns, "prepare_request_ns": prepared_at, "queue_request_ns": before,
            "queue_reply_ns": after, "sequence": sequence}
        self.offers[index]["sequence"] = sequence
        self.offers[index]["queue_reply_ns"] = after
        self.max_outstanding = max(self.max_outstanding, sum("claim_observed_ns" not in m for m in self.messages.values()))
        self.log.add({"event": "queued", **self.messages[sequence]})

    async def observe(self):
        pending = [seq for seq, message in self.messages.items()
                   if "claim_observed_ns" not in message or "retained_observed_ns" not in message]
        if pending:
            cursor = min(pending) - 1
            # Offline messages remain pending for acceptance. Always continue
            # past the first page to observe later relay retention as well.
            for _ in range(7):  # at most 100 planned applications / 16 per page
                page = await self.agents["a"].call("private_outbox_status", after=str(cursor), limit=16)
                now = time.monotonic_ns()
                self.last_observation_ns = now
                require(len(page["records"]) <= 16, "outbox page exceeds bound")
                for record in page["records"]:
                    sequence = int(record["sequence"])
                    require(sequence > cursor, "outbox page failed to advance")
                    cursor = sequence
                    message = self.messages.get(sequence)
                    if message is None:
                        continue
                    relay = record.get("relay") or {}
                    require(relay.get("state") not in ("uncertain", "stopped"), "delivery entered an uncertain/stopped state")
                    if relay.get("state") == "retained":
                        require(relay.get("uncertain") is False, "retained relay evidence is uncertain")
                        require(relay.get("position") is not None, "retained relay position missing")
                        message.setdefault("retained_observed_ns", now)
                        message["relay_position"] = relay["position"]
                    claims = record.get("member_acceptances", [])
                    require(len(claims) <= 1, "unexpected number of member acceptances")
                    if claims:
                        require(claims[0]["recipient"] == self.contexts["b"]["device"], "wrong acceptance recipient")
                        message.setdefault("claim_observed_ns", now)
                        message["received_sequence"] = int(claims[0]["received_sequence"])
                if cursor >= max(pending) or page.get("next") is None:
                    break
            else:
                raise MeasurementError("outbox observation page bound exceeded")
        if "b" in self.agents:
            page = await self.agents["b"].call("private_inbox", after=str(self.cursor), limit=16)
            now = time.monotonic_ns()
            self.last_observation_ns = now
            expected = {bytes.fromhex(m["body_hex"]): m for m in self.messages.values()}
            check_inbox(page["records"], expected, self.contexts["a"]["device"], self.seen)
            for record in page["records"]:
                message = expected[bytes.fromhex(record["body_hex"])]
                message.setdefault("receiver_observed_ns", now)
                message["inbox_sequence"] = int(record["sequence"])
            self.cursor = next_cursor(page, self.cursor)

    async def monitor(self):
        while not self.monitor_stop:
            await self.observe()
            await asyncio.sleep(POLL_SECONDS)

    def monitor_check(self):
        if self.monitor_task and self.monitor_task.done():
            self.monitor_task.result()
            require(self.monitor_stop, "observation task stopped unexpectedly")

    async def wait_until(self, predicate, seconds):
        deadline = time.monotonic() + seconds
        while not predicate():
            self.monitor_check()
            require(time.monotonic() < deadline, f"{seconds}s bounded drain expired")
            await asyncio.sleep(0.1)
        self.monitor_check()

    def complete(self):
        return all("claim_observed_ns" in m and "receiver_observed_ns" in m and "retained_observed_ns" in m
                   for m in self.messages.values())

    async def stop_monitor(self):
        self.monitor_stop = True
        if self.monitor_task:
            await self.monitor_task
            self.monitor_task = None

    async def workload(self):
        count = SCENARIOS[self.scenario]
        if self.scenario == "quiet":
            self.quiet_start_ns = time.monotonic_ns()
            await asyncio.sleep(90)
            self.quiet_end_ns = time.monotonic_ns()
        if self.scenario == "offline":
            await self.close_agent("b")
        self.monitor_task = asyncio.create_task(self.monitor())
        start = time.monotonic_ns()
        self.offers = [{"index": index, "scheduled_ns": start + index * 1_000_000_000 if self.scenario == "load" else None}
                       for index in range(count)]
        last_admission = None
        for index in range(count):
            planned = start + index * 1_000_000_000 if self.scenario == "load" else time.monotonic_ns()
            self.offers[index]["scheduled_ns"] = planned
            if self.scenario == "load":
                # Preserve the 1Hz ceiling when delayed; never catch up by
                # bursting. Original scheduled times expose every missed slot.
                due = max(planned, (last_admission + 1_000_000_000) if last_admission else planned)
                await asyncio.sleep(max(0, (due - time.monotonic_ns()) / 1e9))
                await self.wait_until(lambda: sum("claim_observed_ns" not in m for m in self.messages.values()) < WINDOW, DRAIN_SECONDS)
            self.monitor_check()
            last_admission = time.monotonic_ns()
            await self.queue(index, planned)
            if self.scenario == "offline":
                # Bound outstanding work while B is down by observed relay
                # retention, never by an acknowledgement that cannot yet exist.
                await self.wait_until(lambda: all("retained_observed_ns" in m for m in self.messages.values()), DRAIN_SECONDS)
        if self.scenario == "offline":
            require(not self.seen and all("claim_observed_ns" not in m for m in self.messages.values()), "offline B appears to have accepted")
            self.checkpoints["offline_retained"] = footprint(self.root)
            await self.stop_monitor()
            await self.open_agent("b")  # explicit generation 2; never rearm grant 1
            self.monitor_stop = False
            self.monitor_task = asyncio.create_task(self.monitor())
        await self.wait_until(self.complete, DRAIN_SECONDS)
        await self.stop_monitor()
        require(len(self.messages) == count and len(self.seen) == count, "final exact message count mismatch")
        for message in self.messages.values():
            require(message["received_sequence"] == message["inbox_sequence"], "acceptance/inbox sequence mismatch")
        self.checkpoints["drained"] = footprint(self.root)
        if self.scenario == "offline":
            first = dict(self.seen)
            await self.close_agent("b")
            await self.open_agent("b")  # generation 3 measures cold process reopen
            replay, cursor = {}, 0
            for _ in range(17):
                page = await self.agents["b"].call("private_inbox", after=str(cursor), limit=16)
                check_inbox(page["records"], set(first.values()), self.contexts["a"]["device"], replay)
                cursor = next_cursor(page, cursor)
                if page.get("next") is None:
                    break
            require(replay == first, "reopened inbox differs from exact accepted set")
            self.reopens[-1]["exact_inbox_observed_ns"] = time.monotonic_ns()
            # Sender recovery must retain the same authenticated member claims.
            await self.close_agent("a")
            await self.open_agent("a")
            for sequence, message in self.messages.items():
                page = await self.agents["a"].call("private_outbox_status", after=str(sequence-1), limit=1)
                require(len(page["records"]) == 1, "reopened outbox record missing")
                record = page["records"][0]
                require(int(record["sequence"]) == sequence, "reopened outbox sequence mismatch")
                claims = record.get("member_acceptances", [])
                require(len(claims) == 1 and claims[0]["recipient"] == self.contexts["b"]["device"]
                        and int(claims[0]["received_sequence"]) == message["received_sequence"], "reopened exact acceptance changed")
            self.reopens[-1]["exact_claims_observed_ns"] = time.monotonic_ns()
            self.checkpoints["reopened"] = footprint(self.root)

    async def sample_resources(self):
        while True:
            active = {str(c.process.pid): c for c in self.children if c.process.returncode is None
                      and (c is self.host or c.label.startswith("agent-"))}
            if active:
                process = await asyncio.create_subprocess_exec("/bin/ps", "-o", "pid=,lstart=,rss=", "-p", ",".join(active),
                                      stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                try:
                    output, error = await asyncio.wait_for(process.communicate(), 5)
                finally:
                    if process.returncode is None:
                        process.kill()
                        await process.wait()
                require(process.returncode in (0, 1) and not error, "RSS sampler failed")
                sample = {"monotonic_ns": time.monotonic_ns(), "rss_bytes": {}, "process_start_identity": {}}
                for line in output.decode().splitlines():
                    parts = line.split()
                    require(len(parts) == 7, "RSS sampler start identity format changed")
                    pid, rss, identity = parts[0], parts[-1], " ".join(parts[1:-1])
                    require(pid in active, "RSS sampler returned unowned PID")
                    child = active[pid]
                    if child.process.returncode is not None:
                        continue  # no sample after the owned child was reaped
                    require(child.sampled_start_identity in (None, identity), "owned PID start identity changed")
                    child.sampled_start_identity = identity
                    sample["rss_bytes"][child.label] = int(rss) * 1024
                    sample["process_start_identity"][child.label] = {"pid": int(pid), "lstart": identity}
                self.samples.append(sample)
                require(len(self.samples) <= 1200, "resource sample bound exceeded")
            await asyncio.sleep(1)

    async def shutdown(self):
        errors = []
        try:
            await asyncio.wait_for(self._shutdown(), CLEANUP_SECONDS)
        except Exception as error:
            errors.append(f"graceful cleanup: {type(error).__name__}: {error}")
        finally:
            # Every CLI child stays in the scheduler's process group. We may
            # signal only handles created by this fixture, never scan/kill by
            # executable name or reuse a PID from a previous invocation.
            live = [child for child in self.children if child.process.returncode is None]
            for child in live:
                child.forced = True
                child.process.kill()
            if live:
                errors.append("forced cleanup required")
                try:
                    await asyncio.wait_for(asyncio.gather(*(child.process.wait() for child in live)), 10)
                except Exception as error:
                    errors.append(f"forced reap: {type(error).__name__}: {error}")
            tasks = [child.stderr for child in self.children]
            tasks += [task for task in (self.monitor_task, self.resource_task, getattr(self, "host_stdout", None)) if task]
            for task in tasks:
                if not task.done():
                    task.cancel()
            if tasks:
                try:
                    await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), 5)
                except Exception as error:
                    errors.append(f"task drain: {type(error).__name__}: {error}")
            self.cleanup = [{"process": child.label, "pid": child.process.pid, "returncode": child.process.returncode,
                             "forced": child.forced} for child in self.children]
        require(not errors, "; ".join(errors))

    async def _shutdown(self):
        errors = []
        if self.monitor_task:
            self.monitor_task.cancel()
            result = await asyncio.gather(self.monitor_task, return_exceptions=True)
            if isinstance(result[0], Exception) and not isinstance(result[0], asyncio.CancelledError):
                errors.append(str(result[0]))
        for who in list(self.agents):
            try:
                await self.close_agent(who)
            except Exception as error:
                errors.append(str(error))
        # Include children created before an initialization/command failed.
        for child in reversed(self.children):
            try:
                await child.close(host=child is self.host)
            except Exception as error:
                errors.append(str(error))
        if self.host:
            try:
                await self.host_stdout
            except Exception as error:
                errors.append(str(error))
        if self.resource_task:
            self.resource_task.cancel()
            result = await asyncio.gather(self.resource_task, return_exceptions=True)
            if isinstance(result[0], Exception) and not isinstance(result[0], asyncio.CancelledError):
                errors.append(str(result[0]))
        require(not errors, "; ".join(errors))

    def mailbox_report(self):
        # Diagnostic only, after the host has exited: no repair or write-capable
        # FileStore open, and no credential/token bytes in this report.
        path = self.root / "host" / self.connection["mailbox"] / "relay.db"
        with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as database:
            require(database.execute("SELECT format FROM meta WHERE id=1").fetchone() == (2,), "relay schema changed")
            limits = database.execute("SELECT max_items,max_bytes FROM meta WHERE id=1").fetchone()
            items = database.execute("SELECT position,hex(operation),kind,hex(digest),length(payload) FROM items ORDER BY position").fetchall()
            quotas = database.execute("SELECT hex(k.id),k.max_items,k.max_bytes,count(c.digest),coalesce(sum(c.bytes),0) "
                "FROM tls_keys k LEFT JOIN tls_charges c ON k.id=c.key_id GROUP BY k.id ORDER BY k.id").fetchall()
        require(len(items) <= limits[0], "mailbox item bound exceeded")
        for _, max_items, max_bytes, used_items, used_bytes in quotas:
            require(used_items <= max_items and used_bytes <= max_bytes, "credential quota exceeded")
        for message in self.messages.values():
            matches = [row for row in items if row[1].lower() == message["operation"]]
            require(len(matches) == 1 and matches[0][2] == 5, "application operation not retained exactly once with Application kind")
        return {"coverage": "stopped, schema-bound read-only SQLite diagnostic; not a delivery receipt",
                "limits": {"items": limits[0], "bytes": limits[1]}, "items": items,
                "credential_quotas": quotas, "row_fields": ["position", "operation", "kind", "digest", "payload_bytes"],
                "quota_fields": ["credential_id", "max_items", "max_bytes", "used_items", "used_bytes"]}

    def metrics(self):
        ended = time.monotonic_ns()
        result = {"messages": sorted(self.messages.values(), key=lambda m: m["index"]), "count": len(self.messages),
                  "expected_count": SCENARIOS[self.scenario], "checkpoints": self.checkpoints, "reopens": self.reopens,
                  "grants": self.budgets, "cleanup": self.cleanup, "rss_samples": self.samples,
                  "rss_scope": "1s samples of owned CLI PIDs; observed maximum is a lower bound, not lifetime maximum RSS"}
        result["measurement_ended_ns"] = ended
        result["last_delivery_observation_ns"] = self.last_observation_ns
        result["offers"] = self.offers
        result["counts"] = {"planned": SCENARIOS[self.scenario], "scheduled": len(self.offers),
            "attempted": sum("prepare_request_ns" in offer for offer in self.offers),
            "admitted": len(self.messages), "relay_retained_observed": sum("retained_observed_ns" in m for m in self.messages.values()),
            "receiver_observed": sum("receiver_observed_ns" in m for m in self.messages.values()),
            "member_acceptance_observed": sum("claim_observed_ns" in m for m in self.messages.values())}
        result["max_outstanding_without_observed_acceptance"] = self.max_outstanding
        result["missed_1hz_slots"] = (sum("prepare_request_ns" not in offer or
            offer["prepare_request_ns"] - offer["scheduled_ns"] >= 1_000_000_000 for offer in self.offers)
            if self.scenario == "load" else None)
        by_index = {m["index"]: m for m in self.messages.values()}
        result["censored"] = [{"index": index, "observed_until_ns": self.last_observation_ns,
            "missing": [field for field in ("queue_reply_ns", "retained_observed_ns", "receiver_observed_ns", "claim_observed_ns")
                        if field not in by_index.get(index, {})]}
            for index in range(SCENARIOS[self.scenario])
            if any(field not in by_index.get(index, {}) for field in ("retained_observed_ns", "receiver_observed_ns", "claim_observed_ns"))]
        for name, end, start in (("queue_rpc_ms", "queue_reply_ns", "queue_request_ns"),
                ("queue_to_retention_observation_ms", "retained_observed_ns", "queue_request_ns"),
                ("queue_to_receiver_observation_ms", "receiver_observed_ns", "queue_request_ns"),
                ("queue_to_acceptance_observation_ms", "claim_observed_ns", "queue_request_ns"),
                ("scheduling_lateness_ms", "prepare_request_ns", "scheduled_ns")):
            values = [(m[end]-m[start])/1e6 for m in self.messages.values() if end in m]
            result[name] = {"observed_count": len(values), "percentiles": percentiles(values), "maximum": max(values, default=None)}
        latency = result["queue_to_receiver_observation_ms"]
        result["receiver_p95_under_5s"] = (latency["observed_count"] == SCENARIOS[self.scenario]
                                         and latency["percentiles"]["p95"] < 5000)
        acceptance = result["queue_to_acceptance_observation_ms"]
        result["acceptance_p95_under_5s"] = (acceptance["observed_count"] == SCENARIOS[self.scenario]
                                            and acceptance["percentiles"]["p95"] < 5000)
        result["quiet_ns"] = (getattr(self, "quiet_end_ns", 0) - getattr(self, "quiet_start_ns", 0))
        result["observed_rss_max_bytes_by_process"] = {}
        for sample in self.samples:
            for label, value in sample["rss_bytes"].items():
                result["observed_rss_max_bytes_by_process"][label] = max(value, result["observed_rss_max_bytes_by_process"].get(label, 0))
        return result


async def run_scenario(cli, root, scenario):
    fixture = Fixture(cli, root, scenario)
    errors = []
    try:
        async with asyncio.timeout(600):
            await fixture.setup()
            await fixture.workload()
    except (Exception, asyncio.CancelledError) as error:
        errors.append(f"{type(error).__name__}: {error}")
    finally:
        try:
            await fixture.shutdown()
        except Exception as error:
            errors.append(f"cleanup: {error}")
        if not errors:
            try:
                write_json(root / "mailbox.json", fixture.mailbox_report())
            except Exception as error:
                errors.append(f"mailbox: {error}")
        receipt = {"schema": 1, "scenario": scenario, "correctness_passed": not errors,
                   "errors": errors, **fixture.metrics()}
        write_json(root / "receipt.json", receipt)
        fixture.log.close()
    return receipt


async def main_async(args):
    os.umask(0o077)
    # Remain in the scheduler's process group. Catchable group cancellation
    # preserves the receipt; owned children also receive the wrapper's signal.
    loop, task = asyncio.get_running_loop(), asyncio.current_task()
    for sig in (signal.SIGTERM, signal.SIGHUP):
        loop.add_signal_handler(sig, task.cancel)
    cli, provenance, source = [Path(p).resolve(strict=True) for p in (args.cli, args.provenance, args.source)]
    root = Path(args.out).absolute()
    require(not root.exists() and not root.is_symlink(), "--out must be a new directory")
    root.mkdir(mode=0o700, parents=False)
    receipt = {"schema": 1, "passed": False, "evidence": str(root), "scenarios": [],
               "scope": "synthetic loopback native process measurement; no browser, two-Mac, soak or power-loss claim",
               "started_unix_ns": time.time_ns(), "scenario_contract": {"counts": SCENARIOS, "load_hz": 1,
                   "body_bytes": 128, "outstanding_window": WINDOW, "drain_seconds": DRAIN_SECONDS,
                   "quiet_seconds": 90, "observation_poll_seconds": POLL_SECONDS, "grant_limits": GRANT}}
    try:
        receipt["candidate"] = admit_candidate(cli, provenance, source)
        write_json(root / "receipt.json", receipt)
        names = ["load", "quiet", "offline"] if args.scenario == "all" else [args.scenario]
        for name in names:
            result = await run_scenario(cli, root / name, name)
            receipt["scenarios"].append({"scenario": name, "receipt": f"{name}/receipt.json",
                "correctness_passed": result["correctness_passed"], "receiver_p95_under_5s": result["receiver_p95_under_5s"],
                "acceptance_p95_under_5s": result["acceptance_p95_under_5s"], "counts": result["counts"],
                "missed_1hz_slots": result["missed_1hz_slots"]})
            require(result["correctness_passed"], f"{name} failed; preserved {root / name / 'receipt.json'}")
        require(admit_candidate(cli, provenance, source) == receipt["candidate"], "candidate/source changed during measurement")
        receipt["passed"] = True
    except (Exception, asyncio.CancelledError) as error:
        receipt["error"] = f"{type(error).__name__}: {error}"
    finally:
        receipt["finished_unix_ns"] = time.time_ns()
        write_json(root / "receipt.json", receipt)
    print(json.dumps({"passed": receipt["passed"], "receipt": str(root / "receipt.json"), "error": receipt.get("error")}))
    return 0 if receipt["passed"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("cli", "provenance", "source", "out"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--scenario", choices=[*SCENARIOS, "all"], required=True)
    args = parser.parse_args()
    try:
        return asyncio.run(main_async(args))
    except (MeasurementError, OSError, ValueError) as error:
        print(f"measurement refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
