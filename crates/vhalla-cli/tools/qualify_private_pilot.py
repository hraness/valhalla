#!/usr/bin/env python3
"""Finite synthetic work exchange through two real agent-launch MCP processes.

Uses a never-used private fixture directory. No model call, installation, grant
renewal, remote machine or production state is involved. Raw evidence stays in
the private fixture; receipt.json contains only explicitly selected fields.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import sys
import time

import measure_private_runtime as runtime

STAGES = ("request", "result", "review", "completion")
SENDERS = ("a", "b", "a", "b")
CASES = ("launcher", "exchange", "restart", "inbox", "ciphertext", "removal", "retention", "cleanup", "identity")
POLICY = {"version": 1, "mode": "read-write", "follow_inbox": True, "lifetime": 900,
          "max_preparations": 8, "max_messages": 4, "max_body_bytes": 8192,
          "max_read_records": 512, "max_read_bytes": 8388608, "max_launches": 4,
          "disclosure": {"host": "synthetic private-room pilot", "provider": "none", "model": "fixture",
                         "processing_policy": "local synthetic content only", "allow_cooperating_host": True}}
require = runtime.require


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def digest(body):
    return hashlib.sha256(body.encode()).hexdigest()


def stage_body(index, prior=None):
    """Compute each result from the previously authenticated, exact input."""
    value = {"version": 1, "task": "synthetic-statistics-1", "stage": STAGES[index]}
    if index == 0:
        value.update(values=[11, 7, 19, 3], requested=["count", "sum", "min", "max"])
    else:
        require(prior is not None, "stage requires its authenticated predecessor")
        previous = json.loads(prior)
        require(previous == json.loads(stage_body(index - 1, predecessor(index - 1))), "wrong predecessor")
        value["previous_sha256"] = digest(prior)
        if index == 1:
            values = previous["values"]
            value["result"] = {"count": len(values), "sum": sum(values), "min": min(values), "max": max(values)}
        elif index == 2:
            require(previous["result"] == {"count": 4, "sum": 40, "min": 3, "max": 19}, "incorrect result")
            value["accepted"] = True
        else:
            require(previous["accepted"] is True, "review did not accept the result")
            value["completed_after_restart"] = True
    body = encode(value)
    require(len(body.encode()) < 1024, "pilot body exceeds bound")
    return body


def predecessor(index):
    body = None
    for number in range(index):
        body = stage_body(number, body)
    return body


def accept_record(record, body, sender, seen):
    sequence = int(record["sequence"])
    require(sequence > 0 and record["sender"] == sender, "unexpected authenticated sender")
    require(bytes.fromhex(record["body_hex"]) == body.encode(), "unexpected application content")
    require(sequence not in seen and digest(body) not in seen.values(), "duplicate application")
    seen[sequence] = digest(body)
    return sequence


def retained_acceptance(record, sent, recipient):
    require(int(record["sequence"]) == sent["outbox_sequence"], "wrong local outbox record")
    require(record["operation"] == sent["operation"] and record["kind"] == "application", "wrong outbox operation")
    relay = record.get("relay") or {}
    require(relay.get("state") not in ("uncertain", "stopped"), "delivery needs reconciliation")
    claims = record.get("member_acceptances", [])
    require(len(claims) <= 1, "unexpected acceptance count")
    if claims:
        require(claims[0]["recipient"] == recipient, "wrong acceptance device")
        require(int(claims[0]["received_sequence"]) == sent["inbox_sequence"], "wrong acceptance sequence")
    if relay.get("state") != "retained" or not claims:
        return False
    require(relay.get("uncertain") is False and int(relay["position"]) > 0, "invalid retention evidence")
    sent["relay_position"] = int(relay["position"])
    return True


def public_identity(candidate):
    return {key: candidate[key] for key in (
        "source_commit", "source_tree", "cli_sha256", "provenance_sha256", "lockfile_sha256",
        "native_inputs_sha256", "source_kind", "source_clean_at_build", "source_patch_sha256",
        "source_identity_scope", "runner_sha256", "python", "platform", "machine")}


def passed(receipt):
    return all(receipt["cases"].get(case) == "PASS" for case in CASES)


def remaining(status):
    value = {key: int(status["remaining"][key]) for key in
             ("preparations", "messages", "body_bytes", "read_records", "read_bytes")}
    require(all(number >= 0 for number in value.values()), "invalid remaining allowance")
    return value


def validate_claim(claim, grant, grant_hash):
    require(claim.get("format") == "vhalla-agent-launch-claim-v1", "claim format mismatch")
    require(claim.get("grant_id") == grant["grant_id"] and claim.get("grant_sha256") == grant_hash,
            "claim belongs to another grant")
    require(claim.get("context") == grant["context"] and str(claim.get("epoch")) == str(grant["epoch"])
            and claim.get("roster") == grant["roster"] and claim.get("expires_at") == grant["expires_at"],
            "claim scope differs from reviewed grant")


class Pilot(runtime.Fixture):
    def __init__(self, cli, root):
        super().__init__(cli, root, "pilot")
        self.receipt = {"schema": "private-room-pilot-v1", "scenario": "local-deterministic-mcp",
                        "cases": dict.fromkeys(CASES, "NOT_RUN"), "stages": [], "launches": [],
                        "external_device": "DEFERRED", "real_model_agent": "NOT_RUN",
                        "removal_scope": "authenticated control applied locally", "passed": False}
        self.cursors = {"a": 0, "b": 0}
        self.observed = {"a": {}, "b": {}}
        self.prior_grants = {}
        self.minted_ids = set()
        self.retained_sessions = {}
        self.expected_failures = set()

    async def sample_resources(self):
        # The performance runner owns resource measurement. This pilot needs no
        # process census and does not claim CPU/RSS evidence.
        return

    def launch_args(self, who, delivery=True):
        home = self.root / who
        args = self.private_args("agent-launch", who, policy=home / "policy.json", session_dir=home / "sessions")
        if delivery:
            args += ["--delivery", str(home / "delivery.json")]
        return args

    async def launch(self, who, delivery):
        self.generations[who] += 1
        generation = self.generations[who]
        home = self.root / who
        child = await self.spawn(f"agent-{who}-{generation}", self.launch_args(who, delivery))
        grant_path = home / "sessions" / f"{generation:04}-grant.json"
        claim = home / "sessions" / f"{generation:04}-claim.json"
        async with asyncio.timeout(30):
            while not grant_path.is_file():
                require(child.process.returncode is None, "launcher exited before retaining its grant")
                await asyncio.sleep(0.05)
        # Successful initialization proves launch has finished writing the
        # grant. File existence alone can race write_all/fsync.
        agent = runtime.Agent(child, {}, self.contexts[who])
        result = await agent.ask("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                 "clientInfo": {"name": "valhalla-private-pilot", "version": "1"}})
        require(result.get("protocolVersion") == "2025-11-25", "MCP protocol mismatch")
        grant = json.loads(grant_path.read_text())
        require(grant["grant_id"] not in self.minted_ids, "launcher reused a minted grant identifier")
        self.minted_ids.add(grant["grant_id"])
        agent.grant = grant
        child.process.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        await child.process.stdin.drain()
        listed = (await agent.ask("tools/list", {}))["tools"]
        require(len(listed) == 5 and {item["name"] for item in listed} == runtime.TOOLS, "tool set changed")
        require(all(item["inputSchema"]["properties"]["session"]["const"] == grant["grant_id"] for item in listed),
                "tool schema grant mismatch")
        entry = {"role": who, "generation": generation, "delivery": delivery,
                 "discovery_completed": True, "claimed": claim.exists()}
        self.receipt["launches"].append(entry)
        if not delivery:
            require(not claim.exists(), "registration without delivery consumed a claim")
            await child.close()
            require(not claim.exists(), "registration shutdown consumed a claim")
            return
        if who in self.prior_grants:
            require(self.prior_grants[who] != grant["grant_id"], "launcher reused grant identifier")
            refused = await agent.ask("tools/call", {"name": "private_status",
                "arguments": {"session": self.prior_grants[who]}})
            require(refused.get("isError") is True, "stale grant accepted")
            entry["stale_session_refused"] = True
        status = await agent.call("private_status")
        require(status.get("status") == "live" and status["context"]["device"] == self.contexts[who]["device"],
                "launcher context mismatch")
        require(claim.is_file(), "delivery session has no retained claim")
        validate_claim(json.loads(claim.read_text()), grant, runtime.sha256(grant_path))
        entry["claimed"] = True
        entry["initial_remaining"] = remaining(status)
        self.prior_grants[who] = grant["grant_id"]
        self.agents[who] = agent

    async def close_agent(self, who):
        agent = self.agents[who]
        final = remaining(await agent.call("private_status"))
        entry = next(item for item in reversed(self.receipt["launches"]) if item["role"] == who)
        require(all(final[key] <= value for key, value in entry["initial_remaining"].items()), "allowance increased")
        entry["final_remaining"] = final
        await agent.child.close()
        del self.agents[who]

    def session_inventory(self):
        return {str(path.relative_to(self.root)): runtime.sha256(path)
                for who in ("a", "b") for path in (self.root / who / "sessions").iterdir() if path.is_file()}

    async def open_agent(self, who):
        if self.generations[who] == 0:
            runtime.write_json(self.root / who / "policy.json", POLICY)
            await self.launch(who, False)
        await self.launch(who, True)

    async def exchange(self, index, prior):
        sender = SENDERS[index]
        receiver = "b" if sender == "a" else "a"
        body = stage_body(index, prior)
        agent = self.agents[sender]
        prepared = await agent.call("private_prepare", body=body)
        require(prepared.get("status") == "prepared_exact_content", "exact preparation missing")
        operation = f"{8192 + index:032x}"
        queued = await agent.call("private_queue", draft=prepared["draft"], operation=operation)
        require(queued.get("status") == "durable_local_only" and "relay" not in queued, "queue overclaims delivery")
        require(queued.get("operation") == operation and queued.get("kind") == "application", "queue operation mismatch")
        sent = {"stage": STAGES[index], "sender": sender, "recipient": receiver,
                "body_sha256": digest(body), "outbox_sequence": int(queued["sequence"])}
        require(sent["outbox_sequence"] > 0, "invalid queued sequence")
        self.messages[index] = {"operation": operation, "sender": sender, **sent}
        async with asyncio.timeout(120):
            while "inbox_sequence" not in sent:
                page = await self.agents[receiver].call("private_inbox", after=str(self.cursors[receiver]), limit=16)
                require(len(page["records"]) <= 1, "unexpected pilot inbox records")
                for record in page["records"]:
                    sent["inbox_sequence"] = accept_record(record, body, self.contexts[sender]["device"], self.observed[receiver])
                self.cursors[receiver] = runtime.next_cursor(page, self.cursors[receiver])
                if "inbox_sequence" not in sent:
                    await asyncio.sleep(0.5)
            while True:
                page = await agent.call("private_outbox_status", after=str(sent["outbox_sequence"] - 1), limit=1)
                require(len(page["records"]) == 1, "queued record missing")
                checked = {**sent, "operation": operation}
                if retained_acceptance(page["records"][0], checked, self.contexts[receiver]["device"]):
                    sent["relay_position"] = checked["relay_position"]
                    break
                await asyncio.sleep(0.5)
        self.receipt["stages"].append(sent)
        self.log.add({"event": "pilot-stage", "body": body, **sent})
        return body

    async def ciphertexts(self, label):
        result = {}
        for index, message in self.messages.items():
            target = self.root / f"{label}-{index}.cipher"
            await self.private("export", message["sender"], sequence=message["outbox_sequence"], out=target)
            result[index] = runtime.sha256(target)
        return result

    async def restarted_review(self, body):
        stage = self.receipt["stages"][2]
        page = await self.agents["b"].call("private_inbox", after=str(stage["inbox_sequence"] - 1), limit=1)
        require(len(page["records"]) == 1, "retained review missing after restart")
        require(accept_record(page["records"][0], body, self.contexts["a"]["device"], {}) == stage["inbox_sequence"],
                "retained review sequence changed")
        # Re-reading is intentional here; it is not another accepted message.

    async def audit_inboxes_and_close(self):
        for who in ("a", "b"):
            expected = {stage["inbox_sequence"]: index for index, stage in enumerate(self.receipt["stages"])
                        if stage["recipient"] == who}
            cursor, seen = 0, {}
            for _ in range(16):
                page = await self.agents[who].call("private_inbox", after=str(cursor), limit=16)
                for record in page["records"]:
                    index = expected.get(int(record["sequence"]))
                    require(index is not None, "unexpected final application sequence")
                    accept_record(record, stage_body(index, predecessor(index)),
                                  self.contexts[SENDERS[index]]["device"], seen)
                cursor = runtime.next_cursor(page, cursor)
                if page.get("next") is None:
                    break
            else:
                raise runtime.MeasurementError("final inbox audit exceeded page bound")
            require(set(seen) == set(expected), "final inbox differs from four-stage exchange")
            await self.close_agent(who)
            target = self.root / f"final-{who}-inspect.json"
            await self.private("inspect", who, out=target)
            require(int(json.loads(target.read_text())["status"]["inbox_head"]) == cursor,
                    "inbox changed between final audit and shutdown")

    async def removal(self):
        control = self.root / "remove-b.control"
        await self.private("remove", "a", device=self.contexts["b"]["device"], operation=f"{9000:032x}", out=control)
        await self.private("apply", "b", control=control)
        inspected = self.root / "removed-inspect.json"
        await self.private("inspect", "b", out=inspected)
        state = json.loads(inspected.read_text())["status"]
        require(state["phase"].lower() == "removed", "member removal not applied")
        inbox = self.root / "removed-inbox.json"
        await self.private("inbox", "b", after=0, limit=16, out=inbox)
        records = json.loads(inbox.read_text())["records"]
        for stage in (0, 2):
            retained = [record for record in records if int(record["sequence"]) == self.receipt["stages"][stage]["inbox_sequence"]]
            require(len(retained) == 1, "removal lost retained history")
            accept_record(retained[0], stage_body(stage, predecessor(stage)), self.contexts["a"]["device"], {})
        text = self.root / "removed-send.txt"
        text.write_text("synthetic denied send")
        text.chmod(0o600)
        target = self.root / "removed-send.cipher"
        def room_inventory():
            room = self.root / "b" / "room"
            return {str(path.relative_to(room)): runtime.sha256(path) for path in room.rglob("*") if path.is_file()}
        before = room_inventory()
        child = await self.spawn("expected-removed-send-refusal", self.private_args("send", "b", text=text,
            operation=f"{9001:032x}", epoch=state["epoch"], roster=state["roster"], out=target))
        child.process.stdin.close()
        output = await asyncio.wait_for(child.process.stdout.read(runtime.MAX_LINE + 1), 30)
        await asyncio.wait_for(child.process.wait(), 30)
        await asyncio.wait_for(child.stderr, 5)
        require(child.process.returncode == 1 and not output and not target.exists(), "removed member published")
        errors = "".join(entry["text"] for line in self.log.path.read_text().splitlines()
                         if (entry := json.loads(line)).get("process") == child.label and entry.get("channel") == "stderr")
        require(errors == "vhalla: local private membership is not currently authorized; no text prepared\n",
                "send failed for a reason other than removed membership")
        require(room_inventory() == before, "removed send changed stored room evidence")
        child.closed = True
        self.expected_failures.add(child.label)

    async def journey(self):
        await self.setup()
        self.receipt["cases"]["launcher"] = "PASS"
        body = None
        for index in range(3):
            body = await self.exchange(index, body)
        for who in ("a", "b"):
            await self.close_agent(who)
        self.retained_sessions = self.session_inventory()
        before = await self.ciphertexts("before-reopen")
        for who in ("a", "b"):
            await self.open_agent(who)
        await self.restarted_review(body)
        self.receipt["cases"]["restart"] = "PASS"
        await self.exchange(3, body)
        self.receipt["cases"]["exchange"] = "PASS"
        await self.audit_inboxes_and_close()
        self.receipt["cases"]["inbox"] = "PASS"
        require(all(self.session_inventory().get(path) == checksum for path, checksum in self.retained_sessions.items()),
                "reopen changed original grant or claim")
        after = await self.ciphertexts("after-reopen")
        require(all(after[index] == checksum for index, checksum in before.items()), "restart changed original ciphertext")
        self.receipt["cases"]["ciphertext"] = "PASS"
        await self.removal()
        self.receipt["cases"]["removal"] = "PASS"


async def run(args):
    os.umask(0o077)
    cli, source, provenance = [Path(getattr(args, name)).resolve(strict=True) for name in ("cli", "source", "provenance")]
    candidate = runtime.admit_candidate(cli, provenance, source)
    pilot = Pilot(cli, Path(args.out).resolve())
    pilot.receipt.update(candidate=public_identity(candidate), pilot_sha256=runtime.sha256(Path(__file__)),
                         started_unix_ns=time.time_ns())
    try:
        async with asyncio.timeout(600):
            await pilot.journey()
    except (Exception, asyncio.CancelledError) as error:
        pilot.log.add({"event": "pilot-error", "type": type(error).__name__, "detail": str(error)})
        for case, status in pilot.receipt["cases"].items():
            if status == "NOT_RUN":
                pilot.receipt["cases"][case] = "FAIL"
                break
        pilot.receipt["error"] = "PILOT_FAILED_SEE_PRIVATE_EVIDENCE"
    finally:
        try:
            await pilot.shutdown()
            require(all(not child["forced"] and child["returncode"] == (1 if child["process"] in pilot.expected_failures else 0)
                        for child in pilot.cleanup), "owned process cleanup failed")
            pilot.receipt["cases"]["cleanup"] = "PASS"
            report = pilot.mailbox_report()
            runtime.write_json(pilot.root / "mailbox-private.json", report)
            require(len(pilot.messages) == 4, "pilot did not retain four operations")
            for index, message in pilot.messages.items():
                rows = [row for row in report["items"] if row[1].lower() == message["operation"]]
                require(len(rows) == 1 and rows[0][0] == pilot.receipt["stages"][index]["relay_position"],
                        "relay receipt position differs from exact retained operation")
            pilot.receipt["cases"]["retention"] = "PASS"
            require(runtime.admit_candidate(cli, provenance, source) == candidate, "artifact changed during pilot")
            require(runtime.sha256(Path(__file__)) == pilot.receipt["pilot_sha256"], "pilot changed during run")
            pilot.receipt["cases"]["identity"] = "PASS"
        except (Exception, asyncio.CancelledError) as error:
            pilot.log.add({"event": "cleanup-error", "type": type(error).__name__, "detail": str(error)})
            # A journey failure keeps its own label; the final-check failure is
            # recorded beside it rather than replacing it.
            pilot.receipt.setdefault("error", "FINAL_CHECK_FAILED_SEE_PRIVATE_EVIDENCE")
            pilot.receipt["final_check_failed"] = True
        pilot.receipt["cleanup"] = {"owned_children": len(pilot.cleanup),
                                    "forced_children": sum(item["forced"] for item in pilot.cleanup)}
        pilot.receipt["passed"] = passed(pilot.receipt)
        pilot.receipt["finished_unix_ns"] = time.time_ns()
        runtime.write_json(pilot.root / "receipt.json", pilot.receipt)
        pilot.log.close()
    print(json.dumps({"passed": pilot.receipt["passed"], "receipt": str(pilot.root / "receipt.json")}))
    return 0 if pilot.receipt["passed"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("cli", "provenance", "source", "out"):
        parser.add_argument("--" + name, required=True)
    try:
        return asyncio.run(run(parser.parse_args()))
    except (Exception, KeyboardInterrupt):
        # Input/provenance errors may contain private filesystem information.
        print("pilot refused; validate the selected artifact and new private output directory", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
