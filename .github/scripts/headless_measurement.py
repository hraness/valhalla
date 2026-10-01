#!/usr/bin/env python3
"""Small actual-CLI public/private measurements on one machine, direct loopback.

Use a fresh work directory and a root-supplied build manifest. This script never
infers a binary's source from the current checkout. It reuses qualification
helpers, retains all task data and joins only its own daemon/mailbox processes.
Run the actual journey through the repository's host scheduler.
Only measurement-receipt.json is a shareable artifact; never upload the work
directory, native homes, delivery profiles, credentials or private diagnostics.
"""
import argparse
import json
import math
import os
from pathlib import Path
import platform
import re
import secrets
import signal
import stat
import sys
import time

import headless_qualification as public
import headless_private_qualification as private

SCHEMA = "valhalla.headless-local-measurement.v1"
ROOM = public.operation(1)
MAX_RECEIPT = 1024 * 1024
POLL_SECONDS = 0.025
RESOURCE_SECONDS = 1.0
require = public.require
write_json = public.write_json


def manifest(path, binary):
    value = public.read_json(path)
    required = {"binary_sha256", "source_sha", "dirty_source", "toolchain"}
    require(isinstance(value, dict) and required <= set(value) <= required | {"lock_sha256"},
            "build manifest fields are missing or unsupported")
    private.hex_value(value["binary_sha256"])
    private.hex_value(value["source_sha"], 40)
    if "lock_sha256" in value:
        private.hex_value(value["lock_sha256"])
    require(type(value["dirty_source"]) is bool, "manifest must state whether build source was dirty")
    require(isinstance(value["toolchain"], str) and 0 < len(value["toolchain"]) <= 256
            and all(32 <= ord(c) < 127 for c in value["toolchain"]), "invalid toolchain declaration")
    require(public.controller.digest(binary) == value["binary_sha256"], "binary differs from build manifest")
    return dict(value, manifest_sha256=public.controller.digest(path),
                provenance="root-supplied build manifest; binary digest verified by this runner",
                exact_committed_source=value["dirty_source"] is False,
                source_scope=("declared clean committed candidate" if not value["dirty_source"]
                              else "base commit plus uncommitted changes; exact source not attested"))


def workload(messages, message_bytes, offline_messages):
    require(type(messages) is int and type(offline_messages) is int
            and 1 <= messages <= 48 and 1 <= offline_messages <= 16 and messages + offline_messages <= 56,
            "workload needs 1..48 live and 1..16 offline messages, at most 56 combined")
    require(type(message_bytes) is int and 64 <= message_bytes <= 4096, "message bytes must be 64..4096")
    return dict(messages=messages, message_bytes=message_bytes, offline_messages=offline_messages,
                payload_encoding="UTF-8 ASCII subset", direction="one sender to one receiver",
                ordering="one queued send followed by verified visibility before the next send",
                warmup_messages=1, poll_sleep_ms=POLL_SECONDS * 1000,
                performance_threshold=None, capacity_claim=False)


def body(nonce, kind, index, size):
    prefix = f"measure {nonce[:16]} {kind} {index:04d} "
    require(len(prefix.encode()) <= size, "message size cannot contain its identity")
    value = prefix + "x" * (size - len(prefix.encode()))
    require(len(value.encode("utf-8")) == size, "message byte count changed")
    return value


def latency(values):
    require(values and all(type(value) in (int, float) and math.isfinite(value) and value >= 0
                           for value in values), "invalid latency samples")
    ordered = sorted(values)
    def quantile(fraction):
        return round(ordered[max(0, math.ceil(fraction * len(ordered)) - 1)], 3)
    return dict(samples=len(values), unit="ms", method="nearest rank; no interpolation",
                p50=quantile(.50), p95=quantile(.95), p99=quantile(.99),
                minimum=round(ordered[0], 3), maximum=round(ordered[-1], 3))


def cpu_seconds(value):
    require(isinstance(value, str) and re.fullmatch(r"(?:(\d+)-)?\d+:\d{2}(?::\d{2})?(?:\.\d+)?", value),
            "unsupported ps cumulative CPU format")
    days, selected = value.split("-", 1) if "-" in value else ("0", value)
    parts = selected.split(":")
    require(len(parts) in (2, 3), "unsupported ps CPU fields")
    if len(parts) == 2:
        hours, minutes, seconds = 0, int(parts[0]), float(parts[1])
    else:
        hours, minutes, seconds = int(parts[0]), int(parts[1]), float(parts[2])
        require(minutes < 60, "invalid ps CPU minutes")
    require(seconds < 60, "invalid ps CPU seconds")
    return round(int(days) * 86400 + hours * 3600 + minutes * 60 + seconds, 6)


class Resources:
    def __init__(self, config):
        self.env = public.controller.child_env(Path(config["work"]) / "config.json")
        self.started = time.monotonic()
        self.last = self.started - RESOURCE_SECONDS
        self.entries = []
        self.samples = []

    def register(self, label, child):
        require(child is not None and child.poll() is None, "resource subject is not an owned live child")
        require(re.fullmatch(r"(public|private)\.(sender|receiver|mailbox)\.[12]", label), "unknown resource subject")
        require(all(entry["label"] != label for entry in self.entries), "duplicate process incarnation")
        self.entries.append(dict(label=label, pid=child.pid, child=child))

    def sample(self, phase, force=False):
        now = time.monotonic()
        if not force and now - self.last < RESOURCE_SECONDS:
            return
        live = [entry for entry in self.entries if entry["child"].poll() is None]
        if not live:
            return
        selected = {entry["pid"]: entry["label"] for entry in live}
        require(len(selected) == len(live), "owned process IDs collided")
        started = time.monotonic()
        code, raw = public.exchange(["/bin/ps", "-p", ",".join(str(pid) for pid in sorted(selected)),
            "-o", "pid=", "-o", "rss=", "-o", "time="], b"", self.env, timeout=5)
        ended = time.monotonic()
        require(code == 0 and len(raw) <= 8192, "owned process sample failed")
        measured = {}
        for line in raw.decode("ascii").splitlines():
            fields = line.split()
            require(len(fields) == 3 and fields[0].isdigit() and fields[1].isdigit(), "invalid ps sample")
            pid = int(fields[0])
            require(pid in selected and pid not in measured, "ps returned an unselected process")
            measured[pid] = dict(rss_bytes=int(fields[1]) * 1024, cpu_seconds=cpu_seconds(fields[2]))
        require(set(measured) == set(selected) and all(entry["child"].poll() is None for entry in live),
                "owned process ended during resource sampling")
        require(len(self.samples) + len(live) <= 4096, "resource sample bound reached")
        for pid, values in measured.items():
            self.samples.append(dict(process=selected[pid], pid=pid, phase=phase,
                interval_start_ms=round((started-self.started)*1000, 3),
                interval_end_ms=round((ended-self.started)*1000, 3), **values))
        self.last = ended

    def report(self):
        processes = []
        for entry in self.entries:
            rows = [row for row in self.samples if row["process"] == entry["label"]]
            require(rows, "an owned process had no resource sample")
            require(all(right["cpu_seconds"] >= left["cpu_seconds"] for left, right in zip(rows, rows[1:])),
                    "cumulative process CPU moved backward")
            intervals = [right["interval_start_ms"] - left["interval_end_ms"] for left, right in zip(rows, rows[1:])]
            processes.append(dict(process=entry["label"], pid=entry["pid"], samples=len(rows),
                first_interval_start_ms=rows[0]["interval_start_ms"], last_interval_end_ms=rows[-1]["interval_end_ms"],
                maximum_observed_rss_bytes=max(row["rss_bytes"] for row in rows),
                first_observed_cpu_seconds=rows[0]["cpu_seconds"], last_observed_cpu_seconds=rows[-1]["cpu_seconds"],
                maximum_gap_between_samples_ms=round(max(intervals), 3) if intervals else None))
        return dict(source="ps RSS and cumulative CPU TIME for exact owned native child PIDs",
                    rss_scope="maximum observed samples, not true peak RSS; process RSS is not additive physical memory",
                    cpu_scope="daemon/mailbox cumulative CPU since process start; last sample precedes shutdown; excludes short-lived CLI and harness CPU",
                    cpu_precision="ps TIME format is platform-dependent; commonly seconds on Linux and hundredths on macOS",
                    cadence="phase boundaries, after every live send, and at most once per second while polling",
                    minimum_poll_interval_ms=RESOURCE_SECONDS * 1000,
                    process_count=len(processes), sample_count=len(self.samples), processes=processes, samples=self.samples)


def usage(value):
    require(isinstance(value, dict), "storage accounting missing")
    keys = ("records", "bytes", "max_records", "max_record_bytes")
    require(all(type(value.get(key)) is int and value[key] >= 0 for key in keys), "invalid storage accounting")
    result = {key: value[key] for key in keys}
    for key in ("immutable_limits",):
        if key in value:
            require(type(value[key]) is bool, "invalid storage policy")
            result[key] = value[key]
    return result


def queue_usage(value):
    require(isinstance(value, dict), "delivery capacity missing")
    keys = ("jobs", "max_jobs", "bytes", "max_bytes")
    require(all(type(value.get(key)) is int and value[key] >= 0 for key in keys), "invalid delivery capacity")
    return {key: value[key] for key in keys}


def profile_limits(value):
    numbers = ("max_jobs", "max_bytes", "max_attempts", "initial_backoff_secs", "max_backoff_secs", "initial_cursor")
    require(all(type(value.get(key)) is int and value[key] >= 0 for key in numbers), "invalid profile limits")
    require(type(value.get("emit_acceptance")) is bool and value.get("mailbox_polling") in ("interactive", "adaptive"),
            "invalid profile policy")
    return {key: value[key] for key in (*numbers, "emit_acceptance", "mailbox_polling")}


def disk_usage(root):
    root = root.resolve(strict=True)
    seen = set()
    result = dict(logical_file_bytes=0, allocated_bytes=0, regular_files=0, directories=0, special_files=0)
    pending = [root]
    while pending:
        path = pending.pop()
        info = path.lstat()
        require(not stat.S_ISLNK(info.st_mode), "task data contains a symlink; disk accounting refused")
        identity = (info.st_dev, info.st_ino)
        if identity in seen:
            continue
        seen.add(identity)
        require(len(seen) <= 100000, "task-data walk exceeds bounded workload")
        result["allocated_bytes"] += info.st_blocks * 512
        if stat.S_ISDIR(info.st_mode):
            result["directories"] += 1
            pending.extend(Path(entry.path) for entry in os.scandir(path))
        elif stat.S_ISREG(info.st_mode):
            result["regular_files"] += 1
            result["logical_file_bytes"] += info.st_size
        else:
            result["special_files"] += 1
    return result


def settled_disk(root):
    before = disk_usage(root)
    started = time.monotonic()
    for _ in range(5):
        time.sleep(.2)
        after = disk_usage(root)
        if before == after:
            return dict(after, settled=True, stable_sample_interval_ms=round((time.monotonic()-started)*1000, 3),
                        scope="joined task scenario directory, including native homes, profiles and local diagnostics",
                        allocation_note="filesystem st_blocks times 512; hardlinks counted once; APFS clone sharing is not deduplicated")
        before = after
        started = time.monotonic()
    raise ValueError("task disk accounting did not settle after owned processes joined")


class Inbox:
    def __init__(self, kind, sender, nonce):
        self.kind, self.sender, self.nonce = kind, sender, nonce
        self.cursor = 0
        self.records = {}
        self.observed_ns = {}
        self.identities = set()
        self.polls = 0

    def poll(self, daemon, wanted):
        if wanted in self.records:
            return self.records[wanted]
        page = daemon.call("room.messages", room=ROOM, after=self.cursor, limit=32 if self.kind == "public" else 16)
        observed_ns = time.perf_counter_ns()
        self.polls += 1
        require(page.get("coverage") == "local" and type(page.get("head")) is int, "invalid local message page")
        after = self.cursor
        for row in page["records"]:
            require(type(row.get("cursor")) is int and row["cursor"] > after, "message cursor did not advance")
            after = row["cursor"]
            text = row.get("body")
            if not isinstance(text, str) or not text.startswith(f"measure {self.nonce[:16]} "):
                continue
            require(row.get("author" if self.kind == "public" else "sender") == self.sender,
                    "measurement message has another authenticated sender")
            if self.kind == "public":
                require(row.get("visibility") in ("provisional", "owner_sealed"), "message visibility is not verified")
                identity = private.hex_value(row.get("event"))
            else:
                identity = row["cursor"]
            require(text not in self.records and identity not in self.identities, "duplicate measured message")
            self.identities.add(identity)
            self.records[text] = identity
            self.observed_ns[text] = observed_ns
        next_cursor = page.get("next")
        require(next_cursor is None or type(next_cursor) is int, "invalid message continuation")
        selected = page["head"] if next_cursor is None else next_cursor
        require(selected >= after, "message continuation regressed")
        self.cursor = selected
        return self.records.get(wanted)


class Measurement:
    def __init__(self, config, selected):
        self.config, self.selected = config, selected
        self.work = Path(config["work"])
        self.resources = Resources(config)
        self.owned = []
        self.mailboxes = []
        self.outputs = {}
        self.phase = "initializing"
        self.deadline = time.monotonic() + 1200

    def daemon(self, kind, name):
        daemon = public.Daemon(self.config | {"work": str(self.work / kind)}, name)
        self.owned.append(daemon)
        started = time.perf_counter_ns()
        daemon.start()
        elapsed = (time.perf_counter_ns()-started)/1e6
        self.resources.register(f"{kind}.{name}.1", daemon.child)
        self.resources.sample(self.phase, True)
        return daemon, elapsed

    def wait(self, probe, seconds=120):
        deadline = min(self.deadline, time.monotonic()+seconds)
        while time.monotonic() < deadline:
            if (self.work / "stop").exists():
                raise InterruptedError("measurement stop requested")
            result = probe()
            if result is not None and result is not False:
                return result
            self.resources.sample(self.phase)
            time.sleep(POLL_SECONDS)
        raise TimeoutError("measured phase deadline")

    def prepare_public(self, sender, receiver):
        created = sender.call("room.create", operation=ROOM, kind="public", limits=public.LIMITS)
        sender.call("public.publish", room=ROOM, operation=public.operation(2))
        helper = public.Journey(self.config | {"role": "host"})
        descriptor = helper.descriptor(sender, ROOM)
        inspected = helper.inspect(receiver, descriptor)
        member = receiver.call("room.join_public", operation=ROOM, genesis=inspected["genesis"],
                               pin=descriptor["pin"], limits=public.LIMITS)
        receiver.call("public.publish", room=ROOM, operation=public.operation(2))
        receiver.call("public.source", room=ROOM, operation=public.operation(3), source=inspected["source"])
        sender.call("public.set_writers", room=ROOM, operation=public.operation(4),
                    writers=sorted({created["owner"], created["author"], member["author"]}))
        self.wait(lambda: receiver.call("room.status", room=ROOM)["can_send"])
        return created["author"], {}, helper

    def prepare_private(self, sender, receiver, mailbox, connection):
        validity = dict(not_before=int(time.time())-60, expires_at=int(time.time())+1800)
        created = sender.call("room.create", operation=ROOM, kind="private", limits=public.LIMITS, validity=validity)
        account = receiver.call("service.status")["account"]
        offer = sender.call("private.offer", room=ROOM, operation=public.operation(2), recipient=account, validity=validity)
        joined = receiver.call("room.join_private", operation=ROOM, offer=offer["offer"],
            expected_owner=created["context"]["account"], validity=validity, limits=public.LIMITS)
        accepted = sender.call("private.accept_contact", room=ROOM, operation=public.operation(3),
                               request=joined["request"], validity=validity)
        member = receiver.call("private.join_contact", room=ROOM, response=accepted["artifact"])
        require(member["phase"] == "member_joined", "private member did not join")
        descriptor = dict(owner={key: created["context"][key] for key in ("room", "anchor", "account", "device")},
                          endpoint=connection["endpoint"], namespace=connection["namespace"])
        helper = private.Journey(self.config | {"role": "host", "work": str(self.work / "private")})
        for daemon, number in ((sender, 1), (receiver, 2)):
            helper.profile(daemon, descriptor, (mailbox.home / f"client-{number}.token").read_text().strip())
        status = sender.call("room.status", room=ROOM)
        require(status["epoch"] == member["epoch"] and status["roster"] == member["roster"], "private rosters differ")
        return created["context"]["device"], dict(epoch=status["epoch"], roster=status["roster"]), helper

    def send(self, daemon, number, text, bindings):
        value = daemon.call("room.send", room=ROOM, operation=public.operation(number), body=text, **bindings)
        require(value.get("queued_locally") is True and value.get("exact_retry") is False, "send was not new queued output")
        private.hex_value(value.get("operation"), 32)
        require(value["operation"] == public.operation(number), "send acknowledged another operation")
        require(isinstance(value.get("artifact"), str) and value["artifact"], "send has no retained artifact")
        return value

    def retry(self, daemon, number, text, bindings, original):
        started = time.perf_counter_ns()
        value = daemon.call("room.send", room=ROOM, operation=public.operation(number), body=text, **bindings)
        elapsed = (time.perf_counter_ns()-started)/1e6
        require(value.get("exact_retry") is True and value.get("artifact") == original["artifact"]
                and value.get("sequence") == original.get("sequence"), "retry did not return exact retained output")
        return elapsed

    def quotas(self, kind, sender, receiver):
        result = {}
        for label, daemon in (("sender", sender), ("receiver", receiver)):
            item = dict(service=usage(daemon.call("service.status")["storage"]),
                        native=usage(daemon.call("room.status", room=ROOM)["storage"]))
            if kind == "public":
                sync = daemon.call("public.sync_storage", room=ROOM)
                item["sync"] = dict(replica=usage(sync["replica"]), projection=usage(sync["projection"]),
                    metadata=usage(sync["metadata"]), metadata_expandable=sync["metadata_expandable"],
                    followers=[usage(row["storage"]) if row["storage"] is not None else None for row in sync["followers"]])
            else:
                delivery = daemon.call("private.delivery_status", room=ROOM, after=0, limit=16)
                require(delivery["state"] == "active", "private delivery is not active")
                item["delivery"] = {name: queue_usage(delivery[name]["capacity"]) for name in ("application", "controls")}
                profile = public.read_json(daemon.home.parent / (daemon.home.name + "-delivery") / "delivery.json")
                item["profile_limits"] = profile_limits(profile)
            result[label] = item
        if kind == "private":
            result["mailbox"] = {"storage_quota": None, "scope": "current private-host CLI does not report retained mailbox storage accounting"}
        return result

    def scenario(self, kind):
        self.phase = kind + ".bootstrap"
        directory = self.work / kind
        directory.mkdir(mode=0o700)
        config = self.config | {"work": str(directory)}
        write_json(directory / "config.json", config)
        mailbox = None
        if kind == "private":
            mailbox = private.Mailbox(config)
            self.mailboxes.append(mailbox)
            connection = mailbox.start()
            require(connection["endpoint"]["relay_url"] is None, "measurement selected an external relay")
            self.resources.register("private.mailbox.1", mailbox.child)
            self.resources.sample(self.phase, True)
        sender, sender_start = self.daemon(kind, "sender")
        receiver, receiver_start = self.daemon(kind, "receiver")
        identity, bindings, helper = (self.prepare_public(sender, receiver) if kind == "public"
                                    else self.prepare_private(sender, receiver, mailbox, connection))
        inbox = Inbox(kind, identity, self.config["nonce"])
        make_body = lambda number: body(self.config["nonce"], kind, number, self.selected["message_bytes"])
        warmup = make_body(0)
        self.send(sender, 100, warmup, bindings)
        self.wait(lambda: inbox.poll(receiver, warmup))
        quotas_before = self.quotas(kind, sender, receiver)
        self.phase = kind + ".sequential"
        self.resources.sample(self.phase, True)
        samples = []
        retained = None
        for index in range(1, self.selected["messages"]+1):
            text = make_body(index)
            polls = inbox.polls
            started = time.perf_counter_ns()
            output = self.send(sender, 100+index, text, bindings)
            queued = time.perf_counter_ns()
            self.wait(lambda: inbox.poll(receiver, text))
            visible = time.perf_counter_ns()
            samples.append(dict(index=index, queued_ms=round((queued-started)/1e6, 6),
                verified_visibility_ms=round((visible-started)/1e6, 6),
                after_queue_visibility_ms=round((visible-queued)/1e6, 6), receiver_polls=inbox.polls-polls))
            if retained is None:
                retained = output
            self.resources.sample(self.phase, True)
        self.phase = kind + ".exact_retry"
        retry_before = self.retry(sender, 101, make_body(1), bindings, retained)
        self.phase = kind + ".offline"
        self.resources.sample(self.phase, True)
        receiver.stop()
        offline_samples = []
        for index in range(1, self.selected["offline_messages"]+1):
            number = 1000+index
            started = time.perf_counter_ns()
            self.send(sender, number, make_body(number), bindings)
            offline_samples.append(dict(index=index, queued_ms=round((time.perf_counter_ns()-started)/1e6, 6)))
        self.resources.sample(self.phase, True)
        self.phase = kind + ".receiver_restart"
        restart_started = time.perf_counter_ns()
        receiver.start(initialize=False)
        restart_ready = time.perf_counter_ns()
        self.resources.register(f"{kind}.receiver.2", receiver.child)
        self.resources.sample(self.phase, True)
        for index in range(1, self.selected["offline_messages"]+1):
            self.wait(lambda index=index: inbox.poll(receiver, make_body(1000+index)))
            offline_samples[index-1]["visible_from_restart_ms"] = round(
                (inbox.observed_ns[make_body(1000+index)]-restart_started)/1e6, 6)
        self.phase = kind + ".sender_restart"
        self.resources.sample(self.phase, True)
        sender.stop()
        sender_restart_started = time.perf_counter_ns()
        sender.start(initialize=False)
        sender_restart_ms = (time.perf_counter_ns()-sender_restart_started)/1e6
        self.resources.register(f"{kind}.sender.2", sender.child)
        self.resources.sample(self.phase, True)
        if kind == "public":
            sender.call("public.publish", room=ROOM, operation=public.operation(2))
            descriptor = helper.descriptor(sender, ROOM)
            inspected = helper.inspect(receiver, descriptor)
            require(sender.call("room.status", room=ROOM)["author"] == identity, "sender restart changed public identity")
            receiver.call("public.source", room=ROOM, operation=public.operation(5), source=inspected["source"])
        else:
            require(sender.call("room.status", room=ROOM)["context"]["device"] == identity,
                    "sender restart changed private identity")
        retry_after = self.retry(sender, 101, make_body(1), bindings, retained)
        self.phase = kind + ".restart_delivery"
        final_text = make_body(2000)
        final = self.send(sender, 2000, final_text, bindings)
        self.wait(lambda: inbox.poll(receiver, final_text))
        # Full retained scan after retries/restarts confirms no duplicate body
        # or authenticated identity, without imposing timing on the scan.
        verify = Inbox(kind, identity, self.config["nonce"])
        self.wait(lambda: verify.poll(receiver, final_text))
        expected = self.selected["messages"] + self.selected["offline_messages"] + 2
        require(len(verify.records) == expected and verify.records == inbox.records,
                "restart/retry changed measured retained messages")
        if kind == "private":
            recipient = receiver.call("room.status", room=ROOM)["context"]["device"]
            self.wait(lambda: helper.accepted(sender, final["sequence"], [recipient]))
        quotas_after = self.quotas(kind, sender, receiver)
        output = dict(scope="actual headless CLI processes on one host; direct loopback, no external relay",
            samples=samples, queued_latency=latency([row["queued_ms"] for row in samples]),
            verified_visibility_latency=latency([row["verified_visibility_ms"] for row in samples]),
            after_queue_visibility_latency=latency([row["after_queue_visibility_ms"] for row in samples]),
            latency_definition="monotonic wall time; queued includes sender CLI spawn/RPC, visibility includes receiver CLI/polling, protocol verification and resource sampling overhead",
            message_samples=len(samples), measured_message_bytes=self.selected["message_bytes"],
            authenticated_visibility="public verified signed event" if kind == "public" else "private MLS-authenticated plaintext",
            private_recipient_receipts=("enabled; final signed recipient acceptance verified" if kind == "private" else "not applicable"),
            initial_ready_ms=dict(sender=round(sender_start, 3), receiver=round(receiver_start, 3)),
            initial_ready_scope="fresh daemon init plus run-to-ready, including CLI overhead",
            exact_retry=dict(before_restart_ms=round(retry_before, 3), after_sender_restart_ms=round(retry_after, 3),
                             retained_bytes_unchanged=True, duplicate_messages=False),
            offline=dict(messages=self.selected["offline_messages"], samples=offline_samples,
                queued_latency=latency([row["queued_ms"] for row in offline_samples]),
                visible_from_restart_latency=latency([row["visible_from_restart_ms"] for row in offline_samples]),
                receiver_run_to_ready_ms=round((restart_ready-restart_started)/1e6, 3),
                scope="receiver fully stopped before offline sends; visibility timed from same-home restart call"),
            sender_run_to_ready_ms=round(sender_restart_ms, 3), restart_delivery_verified=True,
            verified_message_count=expected, quotas_before=quotas_before, quotas_after=quotas_after,
            quota_scope="reported logical storage/profile allowances, not measured sustainable capacity")
        self.phase = kind + ".shutdown"
        self.resources.sample(self.phase, True)
        receiver.stop()
        sender.stop()
        if mailbox is not None:
            self.resources.sample(self.phase, True)
            mailbox.stop()
        output["settled_task_disk"] = settled_disk(directory)
        self.outputs[kind] = output

    def close(self):
        clean = True
        for child in reversed(self.owned):
            try:
                child.stop()
            except BaseException:
                clean = False
        for child in reversed(self.mailboxes):
            try:
                child.stop()
            except BaseException:
                clean = False
        return clean and all(not child.forced for child in self.owned + self.mailboxes)


def run(binary, build_manifest, work, selected):
    binary = binary.resolve(strict=True)
    provenance = manifest(build_manifest, binary)
    work.mkdir(mode=0o700)
    work = work.resolve()
    config = dict(work=str(work), binary=str(binary), nonce=secrets.token_hex(32), relay=None, relay_only=False,
                  mode="local", role="host", **{key: provenance[key] for key in ("binary_sha256", "source_sha")})
    write_json(work / "config.json", config)
    measured = Measurement(config, selected)
    started = time.time()
    started_monotonic = time.monotonic()
    result = dict(schema=SCHEMA, build=provenance, workload=selected, started_unix=started,
        platform=dict(system=platform.system(), release=platform.release(), machine=platform.machine()),
        scope="single-host synthetic public then private workload using fresh native homes; direct loopback only",
        passed=False, cleanup_confirmed=False, independent_machines_qualified=False,
        external_relay_qualified=False, capacity_qualified=False, true_peak_rss_measured=False,
        cpu_scope="owned daemon/mailbox samples only; excludes CLI, harness and shutdown tail")
    try:
        for kind in ("public", "private"):
            require(public.controller.digest(binary) == provenance["binary_sha256"], "candidate changed before scenario")
            measured.scenario(kind)
        require(public.controller.digest(binary) == provenance["binary_sha256"], "candidate changed during measurement")
        result["resources"] = measured.resources.report()
        result["passed"] = True
    except Exception as failure:
        result.update(error_class=type(failure).__name__, failed_phase=measured.phase)
        write_json(work / "failure-private.json", dict(error_class=type(failure).__name__, message=str(failure)[:2048],
            detail=getattr(failure, "detail", None), operation=getattr(failure, "operation", None)))
    finally:
        handlers = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGTERM, signal.SIGINT)}
        try:
            result["cleanup_confirmed"] = measured.close()
            result["passed"] = result["passed"] and result["cleanup_confirmed"]
            if "resources" not in result:
                try:
                    result["resources"] = measured.resources.report()
                except Exception:
                    result["resource_report_incomplete"] = True
            result["scenarios"] = measured.outputs
            result["finished_unix"] = time.time()
            result["elapsed_seconds"] = round(time.monotonic()-started_monotonic, 3)
            require(len(json.dumps(result).encode()) <= MAX_RECEIPT, "sanitized receipt exceeds byte bound")
            write_json(work / "measurement-receipt.json", result)
        finally:
            for sig, handler in handlers.items():
                signal.signal(sig, handler)
    return result["passed"]


def main():
    os.umask(0o077)
    def interrupted(_sig, _frame):
        raise InterruptedError("measurement interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--messages", type=int, default=32)
    parser.add_argument("--message-bytes", type=int, default=256)
    parser.add_argument("--offline-messages", type=int, default=8)
    args = parser.parse_args()
    selected = workload(args.messages, args.message_bytes, args.offline_messages)
    return 0 if run(args.binary, args.manifest, args.work, selected) else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as failure:
        print(json.dumps(dict(passed=False, error_class=type(failure).__name__)), file=sys.stderr)
        raise SystemExit(1)
