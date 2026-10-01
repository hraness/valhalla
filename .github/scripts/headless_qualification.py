#!/usr/bin/env python3
"""Bounded public-room qualification through the actual headless CLI.

Two runner jobs use these commands, in this order within each job:
  host: host-start, upload descriptor, host-admit, host-offline,
        upload host-offline-ready, host-wait, always host-stop
  client: client-start, upload client-offer, client-offline,
          upload client-offline, client-wait, always client-stop

Upload ONLY the named JSON handoffs and *-receipt.json. Never upload the work
directory, homes, config, keys or logs. Artifact names are
headless-KIND-RUN_ID-RUN_ATTEMPT. Both jobs depend on the single build, not on
each other. A local command exercises the same journey on one machine; its
receipt explicitly does not qualify independent machines. Path evidence is
limited to open-path snapshots before requests and after authenticated replies.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import shutil
import signal
import socket
import subprocess
import sys
import time

import iroh_qualification as controller

SCHEMA = "valhalla.headless-public-independent-runners.v1"
SCRIPT = Path(__file__).resolve()
RELAY = "https://use1-1.relay.n0.iroh.link."
MAX_REPLY = 1024 * 1024
LIMITS = {"max_records": 2048, "max_record_bytes": 8 * 1024 * 1024}
CONTEXT = ("source_sha", "run_id", "run_attempt", "nonce", "binary_sha256", "lock_sha256")
HOST_CASES = ("owner_published", "explicit_writer_admission", "member_event_verified",
              "offline_send", "replacement_from_public_sync", "owner_stopped",
              "replacement_has_no_writer_authority", "owner_member_transport_checked",
              "replacement_transport_checked", "service_joined")
CLIENT_CASES = ("link_pin_verified", "wrong_pin_refused", "joined_without_writer_authority",
                "unadmitted_send_refused", "writer_admission_received", "owner_event_verified",
                "signed_send", "exact_retry", "offline_stopped", "same_home_restarted",
                "source_replaced", "offline_catch_up", "retained_exact_retry",
                "no_duplicate_event", "initial_transport_checked", "replacement_transport_checked",
                "service_joined")
TRANSPORT_STAGES = {
    "host": frozenset(("owner_to_member", "replacement_to_owner")),
    "client": frozenset(("member_to_owner", "member_to_replacement")),
}
PHASE_FIELDS = {
    "descriptor": {"link", "pin", "author", "peer"},
    "client-offer": {"link", "pin", "author", "peer", "host_machine"},
    "client-offline": {"pin", "host_machine"},
    "host-offline-ready": {"link", "pin", "author", "peer", "owner_stopped", "replaced_peer"},
}
PHASES = frozenset(("initialize", "publish", "join", "admission", "exchange", "offline",
                   "replacement", "restart", "catch_up", "shutdown", "complete"))
require = controller.require
read_json = controller.read_json
write_json = controller.write_json
_base_setup = controller.setup
_base_receipt = controller.receipt
_base_validate_client = controller.validate_client


def path_mode(config):
    if config.get("relay_only") is True:
        require(bool(config.get("relay")), "relay-only mode needs an explicit relay")
        return "relay_only"
    return "automatic" if config.get("relay") else "direct_only"


def validate_observation(value, mode):
    require(isinstance(value, dict) and set(value) == {"peer", "before", "after"},
            "unexpected transport observation fields")
    require(isinstance(value["peer"], str) and re.fullmatch(r"[a-f0-9]{64}", value["peer"]),
            "invalid observed peer")
    for when in ("before", "after"):
        snapshot = value[when]
        require(isinstance(snapshot, dict) and set(snapshot) == {"selected", "nonempty", "all_relay"},
                "unexpected path snapshot fields")
        require(snapshot["selected"] in ("direct", "relay", "unknown")
                and type(snapshot["nonempty"]) is bool and type(snapshot["all_relay"]) is bool,
                "invalid path snapshot")
        require(snapshot["nonempty"] or (snapshot["selected"] == "unknown" and not snapshot["all_relay"]),
                "empty path snapshot claims a route")
        require(not snapshot["all_relay"] or snapshot["selected"] != "direct",
                "relay-only snapshot claims a direct selection")
        if mode == "relay_only":
            require(snapshot["nonempty"] and snapshot["all_relay"], "relay-only paths were not observed")
        elif mode == "direct_only":
            require(snapshot["nonempty"] and snapshot["selected"] == "direct" and not snapshot["all_relay"],
                    "direct path was not observed")
    return value


def validate_transport(value, role, mode):
    require(mode in ("relay_only", "direct_only", "automatic"), "invalid configured path mode")
    require(isinstance(value, dict) and set(value) == TRANSPORT_STAGES[role],
            "incomplete or unexpected transport observations")
    for observation in value.values():
        validate_observation(observation, mode)
    return value


def path_claims(mode="unreported", observations=None):
    # Even matching snapshots do not establish which path carried every byte.
    snapshots = [value[when] for value in (observations or {}).values() for when in ("before", "after")]
    relay = bool(snapshots) and all(value["nonempty"] and value["all_relay"] for value in snapshots)
    direct = bool(snapshots) and all(value["nonempty"] and value["selected"] == "direct"
                                   and not value["all_relay"] for value in snapshots)
    observed = ("relay_only_snapshots" if relay else "direct_snapshots" if direct else
                "mixed_or_unknown_snapshots" if snapshots else "unreported")
    return dict(scope="public headless CLI processes", configured_path_mode=mode, observed_path=observed,
                path_observation_scope="open paths before request and after authenticated reply",
                forced_relay_qualified=mode == "relay_only" and relay,
                direct_path_qualified=mode == "direct_only" and direct, per_byte_path_qualified=False,
                independent_nat_qualified=False, private_qualified=False,
                browser_qualified=False)


def apply_transport_receipt(result, work, role):
    config = read_json(work / "config.json")
    mode = path_mode(config)
    observations = validate_transport(read_json(work / f"{role}-transport.json"), role, mode)
    result.update(path_claims(mode, observations), transport_observations=observations)


def artifact_name(kind):
    current = controller.context()
    return f"headless-{kind}-{current['run_id']}-{current['run_attempt']}"


def package(messages, out):
    candidates = []
    with messages.open() as source:
        for line in source:
            require(len(line) <= MAX_REPLY, "oversized Cargo record")
            value = json.loads(line)
            if (value.get("reason") == "compiler-artifact" and value.get("executable")
                    and value.get("target", {}).get("name") == "vhalla"
                    and value["target"].get("kind") == ["bin"]
                    and value.get("profile", {}).get("test") is False):
                candidates.append((Path(value["executable"]), value["profile"]))
    require(len(candidates) == 1, "expected exactly one actual vhalla CLI executable")
    executable, profile = candidates[0]
    require(profile.get("opt_level") == "3" and profile.get("debug_assertions") is False,
            "independent runners require the optimized release CLI")
    out.mkdir(mode=0o700)
    shutil.copyfile(executable, out / "fixture")
    (out / "fixture").chmod(0o700)
    write_json(out / "build.json", dict(controller.context(), schema=SCHEMA,
        binary_sha256=controller.digest(out / "fixture"),
        lock_sha256=controller.digest(Path("Cargo.lock")), nonce=secrets.token_hex(32),
        toolchain="1.98.1", features="headless", target="x86_64-unknown-linux-gnu",
        build_profile="release", cargo_profile=profile))


def setup(bundle, work, role):
    manifest, config = _base_setup(bundle, work, role)
    require(manifest.get("features") == "headless", "wrong candidate feature selection")
    for field in ("secret", "token", "namespace"):
        config.pop(field, None)
    config.update({key: manifest[key] for key in CONTEXT})
    config.update(binary=str((bundle / "fixture").resolve()), relay=RELAY, relay_only=True, mode="runners")
    write_json(work / "config.json", config)
    return manifest, config


def receipt(manifest, config, role):
    return dict(_base_receipt(manifest, config, role), **path_claims(path_mode(config)), relay_configured=True)


def fixture_command(_bundle, work):
    return [sys.executable, str(SCRIPT), "role", "--work", str(work.resolve())]


def configure():
    controller.SCHEMA = SCHEMA
    controller.CONTROLLER = SCRIPT
    controller.CLIENT_CASES = CLIENT_CASES
    controller.HOST_CASES = HOST_CASES
    controller.PHASES = PHASES
    controller.setup = setup
    controller.receipt = receipt
    controller.artifact_name = artifact_name
    controller.fixture_command = fixture_command
    controller.validate_client = validate_client


def public_packet(config, kind, **fields):
    value = {key: config[key] for key in CONTEXT}
    value.update(schema=SCHEMA, kind=kind, machine=config["machine"], **fields)
    validate_packet(value, kind, config, distinct=False)
    return value


def validate_packet(value, kind, expected, distinct=True):
    require(isinstance(value, dict) and kind in PHASE_FIELDS, "invalid public handoff")
    require(set(value) == set(CONTEXT) | {"schema", "kind", "machine"} | PHASE_FIELDS[kind],
            "unexpected public handoff fields")
    require(value["schema"] == SCHEMA and value["kind"] == kind
            and controller.matching(value, expected), "foreign public handoff")
    require(re.fullmatch(r"[a-f0-9]{64}", value["machine"] or ""), "invalid machine commitment")
    if distinct:
        require(value["machine"] != expected["machine"], "roles are not on distinct runners")
    for key in PHASE_FIELDS[kind] - {"link", "owner_stopped"}:
        require(isinstance(value[key], str) and re.fullmatch(r"[a-f0-9]{64}", value[key]),
                "invalid public commitment")
    if "link" in value:
        require(isinstance(value["link"], str) and len(value["link"]) <= 8192
                and value["link"].startswith("valhalla://public/1/"), "invalid public link")
    if "owner_stopped" in value:
        require(value["owner_stopped"] is True, "original owner is still running")
    if kind.startswith("client-"):
        require(value["host_machine"] == expected["machine"] or not distinct,
                "client selected another host")
    return value


def receive_remote(work, kind, timeout=180):
    expected = read_json(work / "config.json")
    packet = controller.poll_document(kind, f"{kind}.json", timeout)
    validate_packet(packet, kind, expected)
    write_json(work / f"{kind}.json", packet)
    return packet


def wait_file(work, filename, timeout=180):
    return controller.wait_local(work / filename, time.monotonic() + timeout,
                                 work / "supervisor.json")


def start_role(bundle, work, role):
    manifest, config = setup(bundle, work, role)
    write_json(work / f"{role}-receipt.json", receipt(manifest, config, role))
    if role == "client":
        receive_remote(work, "descriptor")
    with (work / "supervisor-private.log").open("wb") as log:
        subprocess.Popen([sys.executable, str(SCRIPT), "supervise", "--bundle", str(bundle.resolve()),
                          "--work", str(work.resolve())], stdin=subprocess.DEVNULL, stdout=log,
                         stderr=log, start_new_session=True)
    try:
        wait_file(work, "descriptor.json" if role == "host" else "client-offer.json", 90)
    except BaseException:
        (work / "stop").touch(mode=0o600)
        controller.wait_local(work / "supervisor.json", time.monotonic() + 75)
        raise


def validate_cases(cases, names, role):
    keys = set(names) | ({"host_machine"} if role == "client" else set())
    require(isinstance(cases, dict) and set(cases) == keys, "unexpected result fields")
    require(all(cases.get(key) is True for key in names), "incomplete public journey")
    if role == "client":
        require(re.fullmatch(r"[a-f0-9]{64}", cases["host_machine"] or ""), "invalid host commitment")
    return cases


def validate_client(value, expected):
    _base_validate_client(value, expected)
    validate_cases(value["cases"], CLIENT_CASES, "client")
    require(value["machine"] == expected.get("selected_client_machine"),
            "client receipt is not from the admitted runner")
    require(value.get("relay_configured") is True and expected.get("configured_path_mode") == "relay_only",
            "independent runners did not select relay-only mode")
    observations = validate_transport(value.get("transport_observations"), "client", "relay_only")
    for key, selected in path_claims("relay_only", observations).items():
        require(value.get(key) is selected if isinstance(selected, bool) else value.get(key) == selected,
                "unsupported route or scope claim")


def finish_client(work, wait):
    result = read_json(work / "client-receipt.json")
    try:
        if wait:
            receive_remote(work, "host-offline-ready")
        else:
            (work / "stop").touch(mode=0o600)
        supervisor = controller.wait_local(work / "supervisor.json", time.monotonic() + (180 if wait else 75))
        result["cleanup_confirmed"] = supervisor.get("child_reaped") is True and supervisor.get("group_cleared") is True
        result["fixture_exit_code"] = supervisor.get("exit_code")
        result["fixture_forced_cleanup"] = supervisor.get("forced")
        require(supervisor.get("exit_code") == 0 and supervisor.get("forced") is False
                and result["cleanup_confirmed"], "client process or cleanup failed")
        result["cases"] = validate_cases(read_json(work / "client-result.json"), CLIENT_CASES, "client")
        apply_transport_receipt(result, work, "client")
        result["passed"] = True
    except Exception as failure:
        result["passed"] = False
        result["error_class"] = type(failure).__name__
        result["failed_case"] = controller.safe_phase(work)
        (work / "stop").touch(mode=0o600)
        # Even an artifact error must finish owned cleanup before returning.
        if not (work / "supervisor.json").exists():
            try:
                supervisor = controller.wait_local(work / "supervisor.json", time.monotonic() + 75)
                result["cleanup_confirmed"] = supervisor.get("child_reaped") is True and supervisor.get("group_cleared") is True
            except Exception:
                result["cleanup_confirmed"] = False
    finally:
        result["finished_unix"] = int(time.time())
        write_json(work / "client-receipt.json", result)
    return result["passed"]


def finish_host(work, wait):
    controller.finish_host(work, wait)
    result = read_json(work / "host-receipt.json")
    try:
        validate_cases(result.get("cases"), HOST_CASES, "host")
        apply_transport_receipt(result, work, "host")
    except Exception as failure:
        result["passed"] = False
        result["error_class"] = type(failure).__name__
    write_json(work / "host-receipt.json", result)
    return result["passed"]


class CliRefusal(Exception):
    def __init__(self, code, operation=None, detail=None):
        super().__init__("CLI refused the selected operation")
        self.code = code
        self.operation = operation
        self.detail = detail


def exchange(argv, payload, env, timeout=35):
    """Bound every pipe, including stderr and input; never shell-interpolate JSON.

    CLI children inherit the fixture's dedicated process group. The external
    controller owns that group through fixture exit, including cancellation.
    """
    require(len(payload) <= controller.MAX_JSON, "oversized CLI input")
    child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=env)
    outputs = {"out": bytearray(), "err": bytearray()}
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selected:
            for stream, name in ((child.stdout, "out"), (child.stderr, "err")):
                os.set_blocking(stream.fileno(), False)
                selected.register(stream, selectors.EVENT_READ, name)
            if payload:
                os.set_blocking(child.stdin.fileno(), False)
                selected.register(child.stdin, selectors.EVENT_WRITE, "in")
            else:
                child.stdin.close()
            offset = 0
            while selected.get_map():
                require(time.monotonic() < deadline, "CLI pipe deadline")
                for key, _ in selected.select(min(0.1, max(0, deadline - time.monotonic()))):
                    if key.data == "in":
                        offset += os.write(key.fd, payload[offset:offset + 4096])
                        if offset == len(payload):
                            selected.unregister(key.fileobj)
                            key.fileobj.close()
                        continue
                    raw = os.read(key.fd, 65536)
                    if not raw:
                        selected.unregister(key.fileobj)
                        continue
                    outputs[key.data].extend(raw)
                    require(len(outputs[key.data]) <= (MAX_REPLY if key.data == "out" else 16384),
                            "CLI output exceeded bound")
        code = child.wait(timeout=max(0.01, deadline - time.monotonic()))
        return code, bytes(outputs["out"])
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
        for stream in (child.stdin, child.stdout, child.stderr):
            stream.close()


class Daemon:
    def __init__(self, config, name):
        self.config = config
        self.home = Path(config["work"]) / name
        self.argv = [config["binary"], "--no-update", "daemon"]
        self.env = controller.child_env(Path(config["work"]) / "config.json")
        self.child = None
        self.forced = False

    def invoke(self, action, request=None):
        payload = b"" if request is None else json.dumps(request, separators=(",", ":")).encode() + b"\n"
        code, raw = exchange(self.argv + [action, "--home", str(self.home)], payload, self.env)
        value = json.loads(raw)
        require(isinstance(value, dict), "invalid CLI reply")
        if value.get("ok") is False and code != 0:
            error = value.get("error", {})
            raise CliRefusal(error.get("code"), request.get("op") if request else action,
                             str(error.get("message", ""))[:1024])
        require(value.get("ok") is True and code == 0 and "result" in value, "CLI failed without a typed refusal")
        return value["result"]

    def call(self, op, **fields):
        return self.invoke("call", dict(op=op, **fields))

    def start(self, initialize=True):
        require(self.child is None, "daemon already selected")
        if initialize:
            require(self.invoke("init") == {"initialized": True}, "initialization failed")
        argv = self.argv + ["run", "--home", str(self.home), "--bind",
                            "0.0.0.0:0" if self.config["relay"] else "127.0.0.1:0"]
        if self.config["relay"]:
            argv += ["--relay-url", self.config["relay"]]
        if self.config.get("relay_only") is True:
            argv += ["--relay-only"]
        self.child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL, env=self.env)
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            require(self.child.poll() is None, "daemon exited before readiness")
            try:
                value = self.invoke("status")
                require(value.get("headless") is True and value.get("network", {}).get("listening") is True,
                        "daemon did not expose its actual headless peer")
                configured = value["network"].get("configured", {})
                require(configured.get("relay_only") is (self.config.get("relay_only") is True)
                        and configured.get("relay_url") == self.config["relay"],
                        "daemon transport mode differs from the selected configuration")
                return value
            except CliRefusal as failure:
                require(failure.code in ("owner-unavailable", "not-found"), "unexpected readiness refusal")
                time.sleep(0.2)
        raise TimeoutError("daemon readiness deadline")

    def stop(self):
        if self.child is None:
            return
        child = self.child
        try:
            require(child.poll() is None, "daemon exited unexpectedly")
            self.invoke("stop")
            require(child.wait(timeout=15) == 0, "daemon did not join cleanly")
        except BaseException:
            self.forced = True
            raise
        finally:
            if child.poll() is None:
                self.forced = True
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
            self.child = None


def operation(number):
    return f"{number:032x}"


class Journey:
    def __init__(self, config):
        self.config = config
        self.work = Path(config["work"])
        self.cases = {}
        self.transport = {}
        self.daemons = []
        self.deadline = time.monotonic() + 600

    def phase(self, name):
        require(name in PHASES, "unknown journey phase")
        write_json(self.work / "phase.json", name)

    def daemon(self, name):
        daemon = Daemon(self.config, name)
        self.daemons.append(daemon)
        return daemon

    def wait(self, probe, seconds=100):
        deadline = min(self.deadline, time.monotonic() + seconds)
        while time.monotonic() < deadline:
            if (self.work / "stop").exists():
                raise InterruptedError("journey stopped")
            value = probe()
            if value:
                return value
            time.sleep(0.25)
        raise TimeoutError("journey phase deadline")

    def incoming(self, kind):
        value = self.wait(lambda: read_json(self.work / f"{kind}.json")
                          if (self.work / f"{kind}.json").exists() else None, 210)
        return validate_packet(value, kind, self.config, self.config["mode"] == "runners")

    def publish_packet(self, kind, **fields):
        write_json(self.work / f"{kind}.json", public_packet(self.config, kind, **fields))

    def body(self, label):
        return f"headless qualification {self.config['nonce'][:16]} {label}"

    def descriptor(self, daemon, room):
        result = daemon.call("public.link", room=room)
        raw = result["link"].removeprefix("valhalla://public/1/")
        link = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
        if self.config["relay"]:
            # Do not upload private interface addresses. Only --relay-only,
            # checked at readiness, disables direct paths; a hint cannot do so.
            link["source"]["addresses"] = []
        encoded = base64.urlsafe_b64encode(json.dumps(link, separators=(",", ":")).encode()).decode().rstrip("=")
        value = "valhalla://public/1/" + encoded
        inspected = daemon.call("public.inspect_link", link=value)
        status = daemon.call("room.status", room=room)
        require(inspected["pin"] == result["pin"] == status["pin"], "public pin changed")
        require(inspected["source"]["relay_url"] == self.config["relay"], "unexpected relay selection")
        return dict(link=value, pin=status["pin"], author=status["author"],
                    peer=daemon.invoke("status")["network"]["peer"])

    def inspect(self, daemon, packet):
        value = daemon.call("public.inspect_link", link=packet["link"])
        require(value["pin"] == packet["pin"], "link differs from independent selected pin")
        require(value["source"]["relay_url"] == self.config["relay"], "foreign relay route")
        return value

    def seen(self, daemon, room, label, author):
        page = daemon.call("room.messages", room=room, after=0, limit=32)
        records = [record for record in page["records"] if record["body"] == self.body(label)]
        if not records:
            return None
        require(len(records) == 1 and records[0]["author"] == author
                and records[0]["visibility"] in ("provisional", "owner_sealed"),
                "message is duplicated, unauthenticated or from another author")
        return records[0]["event"]

    def send(self, daemon, room, number, label):
        return daemon.call("room.send", room=room, operation=operation(number), body=self.body(label))

    def observe(self, daemon, room, stage, peer):
        require(stage in TRANSPORT_STAGES[self.config["role"]] and stage not in self.transport,
                "unexpected or repeated transport stage")
        status = daemon.call("public.sync_status", room=room)
        selected = [source for source in status["selected_sources"] if source["peer"] == peer]
        require(len(selected) == 1, "observed peer is not the selected source")
        observation = selected[0].get("last_transport_observation")
        require(isinstance(observation, dict) and set(observation) == {"before", "after"},
                "selected source has no checked transport observation")
        self.transport[stage] = validate_observation(dict(peer=peer, **observation), path_mode(self.config))

    def host(self):
        self.phase("initialize")
        owner = self.daemon("a")
        owner.start()
        room = operation(1)
        created = owner.call("room.create", operation=room, kind="public", limits=LIMITS)
        require(created["created_here"] is True and created["can_send"] is True, "owner authority missing")
        self.phase("publish")
        owner.call("public.publish", room=room, operation=operation(2))
        descriptor = self.descriptor(owner, room)
        self.publish_packet("descriptor", **descriptor)
        self.cases["owner_published"] = True
        offer = self.incoming("client-offer")
        require(offer["pin"] == descriptor["pin"] and offer["author"] != created["author"], "foreign member")
        selected = self.inspect(owner, offer)
        self.phase("admission")
        owner.call("public.source", room=room, operation=operation(3), source=selected["source"])
        owner.call("public.set_writers", room=room, operation=operation(4),
                   # The immutable account owner and the room's local author
                   # can be different keys. A full replacement preserves both.
                   writers=sorted({created["owner"], created["author"], offer["author"]}))
        self.cases["explicit_writer_admission"] = True
        self.send(owner, room, 5, "owner-first")
        self.phase("exchange")
        self.wait(lambda: self.seen(owner, room, "member-first", offer["author"]))
        self.cases["member_event_verified"] = True
        self.observe(owner, room, "owner_to_member", offer["peer"])
        self.cases["owner_member_transport_checked"] = True
        self.send(owner, room, 6, "member-acknowledged")
        self.phase("offline")
        offline = self.incoming("client-offline")
        require(offline["pin"] == descriptor["pin"] and offline["machine"] == offer["machine"],
                "offline handoff selected another room or runner")
        self.send(owner, room, 7, "while-member-offline")
        self.cases["offline_send"] = True
        self.phase("replacement")
        replacement = self.daemon("r")
        replacement.start()
        inspected = self.inspect(replacement, descriptor)
        joined = replacement.call("room.join_public", operation=room, genesis=inspected["genesis"],
                                  pin=descriptor["pin"], limits=LIMITS)
        require(joined["created_here"] is False, "replacement acquired owner creation custody")
        replacement.call("public.publish", room=room, operation=operation(2))
        replacement.call("public.source", room=room, operation=operation(3), source=inspected["source"])
        for label, author in (("owner-first", created["author"]), ("member-first", offer["author"]),
                              ("member-acknowledged", created["author"]),
                              ("while-member-offline", created["author"])):
            self.wait(lambda label=label, author=author: self.seen(replacement, room, label, author))
        self.cases["replacement_from_public_sync"] = True
        self.observe(replacement, room, "replacement_to_owner", descriptor["peer"])
        self.cases["replacement_transport_checked"] = True
        require(replacement.call("room.status", room=room)["can_send"] is False,
                "replacement unexpectedly gained writer authority")
        self.cases["replacement_has_no_writer_authority"] = True
        changed = self.descriptor(replacement, room)
        require(changed["pin"] == descriptor["pin"] and changed["peer"] != descriptor["peer"],
                "replacement did not preserve pin and change transport identity")
        owner.stop()
        self.cases["owner_stopped"] = True
        self.publish_packet("host-offline-ready", **changed, owner_stopped=True, replaced_peer=descriptor["peer"])
        self.phase("shutdown")
        while not (self.work / "stop").exists():
            require(time.monotonic() < self.deadline, "host stop deadline")
            time.sleep(0.2)
        replacement.stop()

    def client(self):
        self.phase("initialize")
        member = self.daemon("b")
        member.start()
        descriptor = self.incoming("descriptor")
        self.cases["host_machine"] = descriptor["machine"]
        selected = self.inspect(member, descriptor)
        self.cases["link_pin_verified"] = True
        self.phase("join")
        wrong_pin = ("0" if descriptor["pin"][0] != "0" else "1") + descriptor["pin"][1:]
        try:
            member.call("room.join_public", operation=operation(99), genesis=selected["genesis"],
                        pin=wrong_pin, limits=LIMITS)
        except CliRefusal as failure:
            require(failure.code == "usage", "wrong-pin failure was not pin validation")
        else:
            raise ValueError("wrong genesis pin accepted")
        self.cases["wrong_pin_refused"] = True
        room = operation(1)
        joined = member.call("room.join_public", operation=room, genesis=selected["genesis"],
                             pin=descriptor["pin"], limits=LIMITS)
        require(joined["created_here"] is False and joined["can_send"] is False, "join granted writer rights")
        self.cases["joined_without_writer_authority"] = True
        try:
            self.send(member, room, 98, "unadmitted")
        except CliRefusal as failure:
            require(failure.code == "permission-denied", "unadmitted send failed for another reason")
        else:
            raise ValueError("unadmitted member wrote a message")
        self.cases["unadmitted_send_refused"] = True
        member.call("public.publish", room=room, operation=operation(2))
        member.call("public.source", room=room, operation=operation(3), source=selected["source"])
        self.publish_packet("client-offer", **self.descriptor(member, room), host_machine=descriptor["machine"])
        self.phase("admission")
        self.wait(lambda: member.call("room.status", room=room)["can_send"] is True)
        self.cases["writer_admission_received"] = True
        self.phase("exchange")
        self.wait(lambda: self.seen(member, room, "owner-first", descriptor["author"]))
        self.cases["owner_event_verified"] = True
        self.observe(member, room, "member_to_owner", descriptor["peer"])
        self.cases["initial_transport_checked"] = True
        first = self.send(member, room, 4, "member-first")
        require(first["exact_retry"] is False and first["queued_locally"] is True, "first send was not new")
        self.cases["signed_send"] = True
        retry = self.send(member, room, 4, "member-first")
        require(retry["exact_retry"] is True and retry["artifact"] == first["artifact"], "retry changed signed bytes")
        self.cases["exact_retry"] = True
        self.wait(lambda: self.seen(member, room, "member-acknowledged", descriptor["author"]))
        event = self.seen(member, room, "member-first", joined["author"])
        require(event is not None, "local sent event missing")
        self.phase("offline")
        member.stop()
        self.cases["offline_stopped"] = True
        self.publish_packet("client-offline", pin=descriptor["pin"], host_machine=descriptor["machine"])
        ready = self.incoming("host-offline-ready")
        require(ready["pin"] == descriptor["pin"] and ready["replaced_peer"] == descriptor["peer"]
                and ready["peer"] != descriptor["peer"] and ready["machine"] == descriptor["machine"],
                "wrong replacement peer or runner")
        self.phase("restart")
        member.start(initialize=False)
        status = member.call("room.status", room=room)
        require(status["pin"] == descriptor["pin"] and status["author"] == joined["author"],
                "restart changed native room custody")
        self.cases["same_home_restarted"] = True
        inspected = self.inspect(member, ready)
        member.call("public.disable_source", room=room, operation=operation(5), peer=descriptor["peer"])
        member.call("public.source", room=room, operation=operation(6), source=inspected["source"])
        self.cases["source_replaced"] = True
        self.phase("catch_up")
        self.wait(lambda: self.seen(member, room, "while-member-offline", descriptor["author"]))
        self.cases["offline_catch_up"] = True
        self.observe(member, room, "member_to_replacement", ready["peer"])
        self.cases["replacement_transport_checked"] = True
        retry = self.send(member, room, 4, "member-first")
        require(retry["exact_retry"] is True and retry["artifact"] == first["artifact"], "restart changed exact retry")
        self.cases["retained_exact_retry"] = True
        require(self.seen(member, room, "member-first", joined["author"]) == event, "event duplicated or changed")
        self.cases["no_duplicate_event"] = True
        self.phase("shutdown")
        member.stop()

    def run(self):
        try:
            (self.host if self.config["role"] == "host" else self.client)()
        finally:
            clean = True
            for daemon in reversed(self.daemons):
                try:
                    daemon.stop()
                except BaseException:
                    clean = False
            require(clean and all(not daemon.forced for daemon in self.daemons), "owned daemon cleanup failed")
        self.cases["service_joined"] = True
        role = self.config["role"]
        validate_cases(self.cases, HOST_CASES if role == "host" else CLIENT_CASES, role)
        validate_transport(self.transport, role, path_mode(self.config))
        write_json(self.work / f"{role}-transport.json", self.transport)
        write_json(self.work / f"{role}-result.json", self.cases)
        self.phase("complete")


def run_role(work):
    config = read_json(work / "config.json")
    require(config["role"] in ("host", "client") and Path(config["work"]) == work.resolve(), "wrong role home")
    binary = Path(config["binary"])
    require(binary.is_absolute() and binary.is_file()
            and controller.digest(binary) == config["binary_sha256"], "candidate binary changed")
    try:
        Journey(config).run()
    except Exception as failure:
        # Diagnostic only: never include this file in workflow artifacts.
        write_json(work / "failure-private.json", dict(error_class=type(failure).__name__,
            message=str(failure)[:2048], code=getattr(failure, "code", None),
            operation=getattr(failure, "operation", None), detail=getattr(failure, "detail", None),
            phase=controller.safe_phase(work)))
        raise


def local(binary, work, relay, relay_only=False):
    """Same-machine process baseline, with no source attestation or remote claim."""
    binary = binary.resolve(strict=True)
    require(not relay_only or relay, "relay-only mode needs an explicit relay")
    work.mkdir(mode=0o700)
    work = work.resolve()
    nonce = secrets.token_hex(32)
    context = dict(source_sha=None, run_id="local", run_attempt="1", nonce=nonce,
                   binary_sha256=controller.digest(binary), lock_sha256=None,
                   machine=hashlib.sha256((nonce + socket.gethostname()).encode()).hexdigest(),
                   binary=str(binary), relay=relay, relay_only=relay_only, mode="local")
    children = {}
    result = dict(schema=SCHEMA, **path_claims(path_mode(context)), binary_sha256=context["binary_sha256"],
                  source_sha=None, source_attested=False, placement="two roles on one local machine",
                  independent_machines_qualified=False, relay_configured=relay is not None,
                  passed=False, cleanup_confirmed=False)
    deadline = time.monotonic() + 660
    try:
        for role in ("host", "client"):
            home = work / role
            home.mkdir(mode=0o700)
            write_json(home / "config.json", dict(context, role=role, work=str(home)))
            with (home / "private.log").open("wb") as log:
                children[role] = subprocess.Popen([sys.executable, str(SCRIPT), "role", "--work", str(home)],
                    stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                    env=controller.child_env(home / "config.json"), start_new_session=True)
        for kind, source, target in (("descriptor", "host", "client"), ("client-offer", "client", "host"),
                                     ("client-offline", "client", "host"), ("host-offline-ready", "host", "client")):
            path = work / source / f"{kind}.json"
            while not path.exists():
                require(all(child.poll() is None for child in children.values()), "role exited before handoff")
                require(time.monotonic() < deadline, "local journey deadline")
                time.sleep(0.1)
            packet = validate_packet(read_json(path), kind, context, distinct=False)
            write_json(work / target / f"{kind}.json", packet)
        require(children["client"].wait(timeout=max(1, deadline - time.monotonic())) == 0, "client journey failed")
        (work / "host" / "stop").touch(mode=0o600)
        require(children["host"].wait(timeout=45) == 0, "host journey failed")
        result["client"] = validate_cases(read_json(work / "client" / "client-result.json"), CLIENT_CASES, "client")
        result["host"] = validate_cases(read_json(work / "host" / "host-result.json"), HOST_CASES, "host")
        observations = {}
        for role in ("host", "client"):
            observations.update(validate_transport(read_json(work / role / f"{role}-transport.json"),
                                                   role, path_mode(context)))
        result.update(path_claims(path_mode(context), observations), transport_observations=observations)
        result["passed"] = True
    except Exception as failure:
        result["error_class"] = type(failure).__name__
    finally:
        # Cleanup remains finite even when a role died with surviving children.
        previous = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGTERM, signal.SIGINT)}
        clean = True
        forced = False
        try:
            for role, child in children.items():
                (work / role / "stop").touch(mode=0o600)
                if child.poll() is None:
                    try:
                        child.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        forced = True
                extra, cleared = controller.clear_owned_group(child.pid)
                forced = forced or extra
                clean = clean and cleared
                child.wait(timeout=5)
            result["cleanup_confirmed"] = clean and len(children) == 2
            result["passed"] = result["passed"] and result["cleanup_confirmed"] and not forced
            write_json(work / "local-receipt.json", result)
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
    return result["passed"]


def main():
    os.umask(0o077)
    configure()
    def interrupted(_sig, _frame):
        raise InterruptedError("qualification interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("package", "supervise", "role", "local", "host-start",
        "host-admit", "host-offline", "host-wait", "host-stop", "client-start", "client-offline",
        "client-wait", "client-stop"))
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--work", type=Path)
    parser.add_argument("--cargo-messages", type=Path)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--relay-url", default=None, help="local mode only; default is loopback without relay")
    parser.add_argument("--relay-only", action="store_true", help="local mode only; requires --relay-url")
    args = parser.parse_args()
    command, work = args.command, args.work
    if work is not None:
        work = work.resolve()
    if command == "package":
        package(args.cargo_messages, args.bundle)
    elif command == "supervise":
        controller.supervise(args.bundle, work)
    elif command == "role":
        run_role(work)
    elif command == "local":
        return 0 if local(args.binary, work, args.relay_url, args.relay_only) else 1
    elif command in ("host-start", "client-start"):
        start_role(args.bundle, work, command.split("-")[0])
    elif command == "host-admit":
        offer = receive_remote(work, "client-offer")
        result = read_json(work / "host-receipt.json")
        result["selected_client_machine"] = offer["machine"]
        write_json(work / "host-receipt.json", result)
    elif command == "host-offline":
        receive_remote(work, "client-offline")
        wait_file(work, "host-offline-ready.json", 180)
    elif command == "client-offline":
        wait_file(work, "client-offline.json", 180)
    elif command in ("host-wait", "host-stop"):
        if command == "host-stop" and not work.exists():
            return 0
        return 0 if finish_host(work, command == "host-wait") else 1
    elif command in ("client-wait", "client-stop"):
        if command == "client-stop" and not work.exists():
            return 0
        return 0 if finish_client(work, command == "client-wait") else 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as failure:
        print(f"headless qualification failed: {type(failure).__name__}", file=sys.stderr)
        sys.exit(1)
