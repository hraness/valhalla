#!/usr/bin/env python3
"""Real local host and two native controllers crossing one drained generation.

Uses only fresh synthetic private homes. No browser, external device, model,
installation or running service outside this fixture is selected.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import sys
import time

import qualify_private_pilot as pilot
import measure_private_runtime as runtime

require = runtime.require
CASES = ("exchange_before", "drain_pause", "host_fence", "cutover", "exchange_after", "inbox", "retention", "cleanup", "identity")
HEX_FIELDS = ("room", "anchor", "account", "device", "controller_id", "original_profile_binding", "transition")


def native_receipt(raw):
    """Strict observation of the production native format; host decodes it again."""
    require(len(raw) == 650 and raw[:9] == b"VHCDRAIN\x01" and raw[425] == 0,
            "not the canonical native pause receipt")
    offset, value = 9, {}
    def take(size):
        nonlocal offset
        result = raw[offset:offset+size]
        offset += size
        return result
    def number():
        return int.from_bytes(take(8), "big")
    for name in HEX_FIELDS:
        value[name] = take(32).hex()
    value["generation"] = number()
    for name in ("namespace", "endpoint", "profile_binding"):
        value[name] = take(32).hex()
    value["terminal_head"] = number()
    value["items_commitment"] = take(32).hex()
    value["outbox_head"], value["control_head"] = number(), number()
    value["image_commitment"] = take(32).hex()
    require(take(1) == b"\0", "receipt counter mode changed")
    for stream in ("normal", "controls"):
        ledger = {name: number() for name in ("outgoing", "applied", "retained_jobs", "canonical_bytes", "charged_attempts", "outages", "resumes")}
        ledger["commitment"] = take(32).hex()
        value[stream] = ledger
    value["normal_ceiling"], value["control_ceiling"] = number(), number()
    value["prior_ledger_commitment"] = take(32).hex()
    require(offset == len(raw) and value["generation"] < 16, "receipt generation or length")
    context = b"".join(bytes.fromhex(value[k]) for k in ("room", "anchor", "account", "device"))
    identity = hashlib.sha256(b"vhalla/private/controller-id/v1\0" + context + bytes.fromhex(value["original_profile_binding"])).hexdigest()
    require(identity == value["controller_id"], "receipt controller identity mismatch")
    require(value["normal"]["outgoing"] == value["outbox_head"] and value["normal"]["applied"] == value["terminal_head"]
            and value["controls"]["outgoing"] == value["control_head"] and value["controls"]["applied"] == 0,
            "receipt authenticated heads mismatch")
    for stream, ceiling in (("normal", "normal_ceiling"), ("controls", "control_ceiling")):
        require(0 < value[ceiling] <= 1024**3 and value[stream]["canonical_bytes"] <= value[ceiling], "receipt spend exceeds finite ceiling")
    value["receipt_commitment"] = hashlib.sha256(b"vhalla/private/controller-pause-receipt/v1\0" + raw).hexdigest()
    return value


def inventory(root):
    return {str(path.relative_to(root)): runtime.sha256(path) for path in root.rglob("*") if path.is_file()}


def preserved(before, after):
    require(all(after.get(name) == digest for name, digest in before.items()), "retained file changed or disappeared")


def mailbox(path):
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as db:
        version = db.execute("SELECT format FROM meta WHERE id=1").fetchone()[0]
        require(version in (2, 3), "mailbox format changed")
        items = db.execute("SELECT position,lower(hex(operation)),kind,lower(hex(digest)),length(payload) FROM items ORDER BY position").fetchall()
        tls = db.execute("SELECT format FROM tls_meta WHERE id=1").fetchone()[0]
        rows = db.execute("SELECT lower(hex(k.id)),k.max_items,k.max_bytes,count(c.digest),coalesce(sum(c.bytes),0) FROM tls_keys k LEFT JOIN tls_charges c ON k.id=c.key_id GROUP BY k.id ORDER BY k.id").fetchall()
        budgets = {}
        for key, max_items, max_bytes, items_now, bytes_now in rows:
            if tls == 2:
                prior_items, prior_bytes, allowed_items, allowed_bytes = db.execute("SELECT prior_items,prior_bytes,authorized_items,authorized_bytes FROM tls_budget WHERE lower(hex(key_id))=?", (key,)).fetchone()
            else:
                require(tls == 1, "TLS ledger version")
                prior_items, prior_bytes, allowed_items, allowed_bytes = 0, 0, max_items, max_bytes
            budgets[key] = {"spent_items": prior_items + items_now, "spent_bytes": prior_bytes + bytes_now,
                            "authorized_items": allowed_items, "authorized_bytes": allowed_bytes,
                            "max_items": max_items, "max_bytes": max_bytes}
    return {"items": items, "budgets": budgets}


def carry_checked(before, after, exact=False):
    require(set(before) == set(after), "credential identities changed")
    for key, old in before.items():
        new = after[key]
        require(all(new[field] == old[field] for field in ("authorized_items", "authorized_bytes", "max_items", "max_bytes")), "credential authority reset or increased")
        for field in ("spent_items", "spent_bytes"):
            require(new[field] == old[field] if exact else new[field] >= old[field], "credential spend lost")


class GenerationPilot(pilot.Pilot):
    def __init__(self, cli, root):
        super().__init__(cli, root)
        self.receipt["schema"] = "private-generation-pilot-v1"
        self.receipt["cases"] = dict.fromkeys(CASES, "NOT_RUN")
        self.receipt["removal_scope"] = "NOT_RUN"
        self.selected_receipts = {}
        self.transition = "71" * 32
        self.successor = "72" * 32

    async def private(self, command, who, include_room=True, **flags):
        if command == "delivery-init":
            # The inherited fixture created these new, unconsumed profiles.
            # Select direct host addresses before their first binding is made;
            # the performance fixture's proxies are deliberately not used.
            path = Path(flags["config"])
            config = json.loads(path.read_text())
            require(not Path(config["state"]).exists(), "profile already consumed")
            config["addr"] = self.addr
            runtime.write_json(path, config)
        return await super().private(command, who, include_room, **flags)

    async def stop_host(self):
        await self.host.close(host=True)
        await self.host_stdout

    async def start_host(self, address, label):
        self.host = await self.spawn(label, ["private-host", "serve", str(self.root / "host")])
        ready = await self.host.line()
        require(ready["status"] == "listening" and ready["listen"] == address, "host selected wrong generation")
        self.host_stdout = asyncio.create_task(self.host.drain(self.host.process.stdout, "stdout"))

    async def expected_refusal(self, label, args, stderr_part):
        child = await self.spawn(label, args)
        child.process.stdin.close()
        output = await asyncio.wait_for(child.process.stdout.read(runtime.MAX_LINE + 1), 30)
        await asyncio.wait_for(child.process.wait(), 30)
        await asyncio.wait_for(child.stderr, 5)
        errors = "".join(entry["text"] for line in self.log.path.read_text().splitlines()
                         if (entry := json.loads(line)).get("process") == label and entry.get("channel") == "stderr")
        require(child.process.returncode == 1 and not output and stderr_part in errors, "unexpected refusal reason")
        child.closed = True
        self.expected_failures.add(label)

    def current_head(self, name="mailbox"):
        return len(mailbox(self.root / "host" / name / "relay.db")["items"])

    async def drain_and_close(self):
        async with asyncio.timeout(120):
            while True:
                head = self.current_head()
                complete = True
                for who in ("a", "b"):
                    status = await self.agents[who].call("private_status")
                    state = self.root / who / "delivery-state"
                    for stream in ("jobs", "controls"):
                        with sqlite3.connect((state / stream / "delivery.db").as_uri() + "?mode=ro", uri=True) as db:
                            outgoing, applied = db.execute("SELECT outgoing,applied FROM driver WHERE id=1").fetchone()
                            pending = db.execute("SELECT COUNT(*) FROM jobs WHERE state!=2 OR uncertain!=0").fetchone()[0]
                        complete &= pending == 0
                        if stream == "jobs":
                            complete &= outgoing == int(status["outbox_head"]) and applied == head
                if complete and head == self.current_head():
                    break
                await asyncio.sleep(0.5)
        for who in ("a", "b"):
            await self.close_agent(who)
        require(head == self.current_head(), "mailbox changed during controller close")
        return head

    async def pause_both(self, head):
        directory = self.root / "controller-receipts"
        directory.mkdir(mode=0o700)
        self.before_images = {who: inventory(self.root / who / "room") for who in ("a", "b")}
        self.old_profiles = {}
        for who in ("a", "b"):
            home = self.root / who
            config = json.loads((home / "delivery.json").read_text())
            require(config["version"] == 2 and config["addr"] == self.addr, "initial native profile binding")
            self.old_profiles[who] = config
            old = home / "old-profile.json"
            old.write_bytes((home / "delivery.json").read_bytes()); old.chmod(0o600)
            bootstrap = []
            for path in (home / "delivery-state" / "applied").glob("*.json"):
                value = json.loads(path.read_text())
                if value["state"] == "dedicated-bootstrap-command-required":
                    bootstrap.append(value["digest"])
            review = home / "reviewed-bootstrap.json"
            runtime.write_json(review, sorted(bootstrap))
            target = home / "pause.receipt"
            await self.private("delivery-pause", who, config=home / "delivery.json", transition=self.transition,
                               head=head, out=target, reviewed_bootstrap=review)
            raw = target.read_bytes()
            value = native_receipt(raw)
            require(value["terminal_head"] == head and value["transition"] == self.transition and value["namespace"] == self.connection["namespace"], "pause selected wrong transition")
            require({key: value[key] for key in self.contexts[who]} == self.contexts[who], "pause selected wrong private context")
            copy = directory / (value["controller_id"] + ".receipt")
            copy.write_bytes(raw); copy.chmod(0o600)
            self.selected_receipts[who] = value
            # Direct native authoring must refuse while the exact kernel pause
            # is held, without replacing image or publishing an output.
            before = inventory(home / "room")
            body = home / "paused.txt"; body.write_text("synthetic forbidden paused send"); body.chmod(0o600)
            out = home / "paused.cipher"
            inspect = home / "paused-inspect.json"
            await self.private("inspect", who, out=inspect)
            status = json.loads(inspect.read_text())["status"]
            await self.expected_refusal("expected-paused-send-"+who, self.private_args("send", who,
                text=body, operation=f"{9900 + (who == 'b'):032x}", epoch=status["epoch"], roster=status["roster"], out=out), "private operation refused")
            require(not out.exists() and inventory(home / "room") == before, "paused authoring altered room")
        values = list(self.selected_receipts.values())
        require(values[0]["items_commitment"] == values[1]["items_commitment"], "controllers did not drain identical retained items")
        return directory

    async def journey(self):
        await self.setup()
        body = None
        for index in range(3):
            body = await self.exchange(index, body)
        self.receipt["cases"]["exchange_before"] = "PASS"
        head = await self.drain_and_close()
        sessions = self.session_inventory()
        original = await self.ciphertexts("before-transition")
        old_item = self.root / "original-relay-item.bin"
        await self.private("relay-export", "a", namespace=self.connection["namespace"],
                           sequence=self.messages[0]["outbox_sequence"], out=old_item)
        receipts = await self.pause_both(head)
        self.receipt["cases"]["drain_pause"] = "PASS"
        await self.stop_host()
        old_database = self.root / "host" / "mailbox" / "relay.db"
        before_host = mailbox(old_database)
        host_config = json.loads((self.root / "host" / "config.json").read_text())
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            next_address = "127.0.0.1:" + str(reservation.getsockname()[1])
        require(next_address != self.addr, "successor address repeats predecessor")
        controllers = []
        for index, who in enumerate(("a", "b")):
            value = self.selected_receipts[who]
            controllers.append({key: value[key] for key in ("room", "anchor", "account", "device", "controller_id", "original_profile_binding", "profile_binding", "endpoint", "receipt_commitment")})
            controllers[-1]["credential_id"] = host_config["credential_ids"][index]
        plan = {"version": 1, "complete_controller_inventory": True,
                "config_sha256": runtime.sha256(self.root / "host" / "config.json"),
                "transition": self.transition, "generation": 0, "predecessor": self.connection["namespace"],
                "successor": self.successor, "successor_address": next_address, "expected_head": head,
                "items_commitment": self.selected_receipts["a"]["items_commitment"], "controllers": controllers, "allowances": []}
        plan_path = self.root / "generation-plan.json"; runtime.write_json(plan_path, plan)
        for action in ("generation-check", "generation-prepare"):
            await self.command(["private-host", action, str(self.root / "host"), "--plan", str(plan_path), "--receipts", str(receipts)])
        for action in ("generation-fence", "generation-fence", "generation-cutover", "generation-recover"):
            await self.command(["private-host", action, str(self.root / "host")])
        require(mailbox(old_database) == before_host, "host transition altered predecessor retained items/spend")
        carry_checked(before_host["budgets"], mailbox(self.root / "host" / "mailbox-2" / "relay.db")["budgets"], exact=True)
        self.receipt["cases"]["host_fence"] = "PASS"
        for who in ("a", "b"):
            home = self.root / who
            next_profile = {**self.old_profiles[who], "addr": next_address, "namespace": self.successor, "state": str(home / "delivery-state-2")}
            target = home / "successor.json"; runtime.write_json(target, next_profile)
            flags = dict(config=home / "delivery.json", successor=target, receipt=home / "pause.receipt", fence=self.root / "host" / "generation-1.fence.json")
            await self.private("delivery-transition", who, **flags)
            await self.private("delivery-transition", who, **flags)
            preserved(self.before_images[who], inventory(home / "room"))
            require((home / "pause.receipt").read_bytes() == (Path(self.old_profiles[who]["state"]) / "generation.pause").read_bytes(), "original pause receipt changed")
            # Inspect the real successor's empty queues and inherited ledgers
            # before any driver can author or charge successor work.
            raw_receipt = (home / "pause.receipt").read_bytes()
            for stream, raw, outgoing in (("jobs", raw_receipt[426:514], self.selected_receipts[who]["outbox_head"]),
                                           ("controls", raw_receipt[514:602], self.selected_receipts[who]["control_head"])):
                with sqlite3.connect((home / "delivery-state-2" / stream / "delivery.db").as_uri() + "?mode=ro", uri=True) as db:
                    generation, prior, commitment = db.execute("SELECT generation,prior,receipt FROM lineage WHERE id=1").fetchone()
                    require(generation == 1 and prior == raw and commitment.hex() == self.selected_receipts[who]["receipt_commitment"], "successor reset queue ledger")
                    require(db.execute("SELECT outgoing,applied FROM driver WHERE id=1").fetchone() == (outgoing, 0), "successor advanced incoming or replayed outgoing history")
                    require(db.execute("SELECT COUNT(*) FROM jobs").fetchone() == (0,), "successor copied historical jobs")
            grant, claim = home / "stale-profile-grant.json", home / "stale-profile-claim.json"
            await self.private("agent-grant", who, mode="read-write", disclosure=home / "disclosure.json", receipt=claim,
                               out=grant, lifetime=120, follow_inbox="true", max_preparations=1, max_messages=1,
                               max_body_bytes=1024, max_read_records=8, max_read_bytes=8192)
            before_stale = inventory(home / "room")
            await self.expected_refusal("expected-stale-profile-"+who, self.private_args("agent-serve", who,
                grant=grant, delivery=home / "old-profile.json"), "host delivery refused")
            require(not claim.exists() and inventory(home / "room") == before_stale, "stale profile claimed authority or changed room")
        self.receipt["cases"]["cutover"] = "PASS"
        preserved(sessions, self.session_inventory())
        await self.start_host(next_address, "host-successor")
        receipt_path = self.root / "old-exact-retry.json"
        await self.command(["private", "relay-submit", str(old_item), "--namespace", self.connection["namespace"],
            "--addr", self.addr, "--tls-ca", str(self.root / "a" / "ca.der"), "--tls-name", "runtime.test.invalid",
            "--token", str(self.root / "a" / "token.hex"), "--out", str(receipt_path)])
        exact = json.loads(receipt_path.read_text())
        require(exact["duplicate"] is True and int(exact["position"]) == self.receipt["stages"][0]["relay_position"], "old retry changed retention identity")
        for who in ("a", "b"):
            await self.open_agent(who)
        await self.restarted_review(body)
        await self.exchange(3, body)
        self.receipt["cases"]["exchange_after"] = "PASS"
        await self.audit_inboxes_and_close()
        self.receipt["cases"]["inbox"] = "PASS"
        after = await self.ciphertexts("after-transition")
        require(all(after[index] == checksum for index, checksum in original.items()), "generation changed old ciphertext")
        preserved(sessions, self.session_inventory())
        # A newly authored successor message is never an exact retry in the
        # predecessor namespace, even with the same retained MLS ciphertext.
        forbidden = self.root / "forbidden-old-item.bin"
        await self.private("relay-export", "b", namespace=self.connection["namespace"], sequence=self.messages[3]["outbox_sequence"], out=forbidden)
        await self.expected_refusal("expected-fenced-put", ["private", "relay-submit", str(forbidden),
            "--namespace", self.connection["namespace"], "--addr", self.addr, "--tls-ca", str(self.root / "b" / "ca.der"),
            "--tls-name", "runtime.test.invalid", "--token", str(self.root / "b" / "token.hex"), "--out", str(self.root / "forbidden-receipt.json")], "relay storage or work budget exhausted")
        await self.stop_host()
        old_final = mailbox(old_database)
        new_final = mailbox(self.root / "host" / "mailbox-2" / "relay.db")
        require(old_final == before_host, "old generation changed after exact retry or refused PUT")
        carry_checked(before_host["budgets"], new_final["budgets"])
        for index, stage in enumerate(self.receipt["stages"]):
            rows = [row for row in (old_final if index < 3 else new_final)["items"] if row[1] == self.messages[index]["operation"]]
            require(len(rows) == 1 and rows[0][0] == stage["relay_position"] and rows[0][2] == 5, "receipt does not match exact generation mailbox row")
        require(all(row[1] not in {self.messages[i]["operation"] for i in range(3)} for row in new_final["items"]), "predecessor applications replayed into successor")
        self.receipt["cases"]["retention"] = "PASS"
        self.receipt["transition"] = {"generations": 2, "controllers": 2, "old_items": len(old_final["items"]),
            "new_items": len(new_final["items"]), "finite_allowance_increase": False,
            "pause_receipt_sha256": {who: runtime.sha256(self.root / who / "pause.receipt") for who in ("a", "b")},
            "original_ciphertext_sha256": original, "counter_scope": "native split queues and TLS stable credential ledgers"}


async def run(args):
    os.umask(0o077)
    cli, source, provenance = [Path(getattr(args, name)).resolve(strict=True) for name in ("cli", "source", "provenance")]
    candidate = runtime.admit_candidate(cli, provenance, source)
    task = GenerationPilot(cli, Path(args.out).resolve())
    drivers = {str(Path(file).resolve()): runtime.sha256(Path(file)) for file in (__file__, pilot.__file__, runtime.__file__)}
    task.receipt.update(candidate=pilot.public_identity(candidate), driver_sha256=list(drivers.values()), started_unix_ns=time.time_ns())
    try:
        async with asyncio.timeout(600):
            await task.journey()
    except (Exception, asyncio.CancelledError) as error:
        task.log.add({"event": "generation-error", "type": type(error).__name__, "detail": str(error)})
        task.receipt["error"] = "GENERATION_FAILED_SEE_PRIVATE_EVIDENCE"
        failed = next((case for case in CASES if task.receipt["cases"][case] != "PASS"), None)
        if failed is not None:
            task.receipt["cases"][failed] = "FAIL"
    finally:
        try:
            await task.shutdown()
            require(all(not child["forced"] and child["returncode"] == (1 if child["process"] in task.expected_failures else 0) for child in task.cleanup), "unclean owned child")
            task.receipt["cases"]["cleanup"] = "PASS"
            require(runtime.admit_candidate(cli, provenance, source) == candidate, "candidate changed")
            require(all(runtime.sha256(Path(file)) == checksum for file, checksum in drivers.items()), "runner dependency changed")
            task.receipt["cases"]["identity"] = "PASS"
        except (Exception, asyncio.CancelledError) as error:
            task.log.add({"event": "final-check-error", "type": type(error).__name__, "detail": str(error)})
            task.receipt["error"] = "FINAL_CHECK_FAILED_SEE_PRIVATE_EVIDENCE"
            failed = "cleanup" if task.receipt["cases"]["cleanup"] != "PASS" else "identity"
            task.receipt["cases"][failed] = "FAIL"
        task.receipt["passed"] = "error" not in task.receipt and all(task.receipt["cases"].get(case) == "PASS" for case in CASES)
        task.receipt["cleanup"] = {"owned_children": len(task.cleanup), "forced_children": sum(c["forced"] for c in task.cleanup)}
        task.receipt["finished_unix_ns"] = time.time_ns()
        runtime.write_json(task.root / "receipt.json", task.receipt)
        task.log.close()
    print(json.dumps({"passed": task.receipt["passed"], "receipt": str(task.root / "receipt.json")}))
    return 0 if task.receipt["passed"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("cli", "source", "provenance", "out"):
        parser.add_argument("--" + name, required=True)
    try:
        return asyncio.run(run(parser.parse_args()))
    except (Exception, KeyboardInterrupt):
        print("generation pilot refused; inspect the private fixture and selected artifact", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
