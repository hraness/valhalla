#!/usr/bin/env python3
"""Synthetic private MLS journey through the actual headless CLI on two VMs.

Host: host-start/upload descriptor; host-offers/upload host-offers;
host-admit/upload host-admission; host-offline/upload host-offline-ready;
host-remove; host-wait; always host-stop/upload host-receipt.
Client: client-start/upload client-hello; client-requests/upload client-requests;
client-offline/upload client-offline; client-restart/upload client-caught-up;
client-wait; always client-stop/upload client-receipt.

Use the existing public adapter's headless-bundle. Upload ONLY these named JSON
files, with artifact prefix headless-private-KIND-RUN_ID-RUN_ATTEMPT. Bootstrap
handoffs contain fresh synthetic credentials, never user custody. Tokens have
no expiry guarantee: their usable lifetime is bounded by the disposable host.
Never upload homes, keys, profiles, queues, config or logs. Local mode uses the
same processes on one machine and a direct loopback Iroh mailbox without relay.
Route evidence is limited to the last checked reply's before/after snapshots;
it never identifies which path carried every byte.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import subprocess
import sys
import time

import headless_qualification as public
import iroh_qualification as shared

SCHEMA = "valhalla.headless-private-independent-runners.v1"
SCRIPT = Path(__file__).resolve()
RELAY = public.RELAY
CONTEXT = public.CONTEXT
LIMITS = public.LIMITS
MAX_JSON = shared.MAX_JSON
HOST_CASES = ("mailbox_iroh_started", "explicit_member_admission", "current_roster_verified",
              "member_b_reply_verified", "member_c_reply_verified", "signed_acceptances_verified",
              "exact_retry", "offline_retained_without_b_acceptance", "offline_b_acceptance_verified",
              "removal_rekeyed", "surviving_member_after_rekey", "service_joined", "mailbox_joined")
CLIENT_CASES = ("owner_pin_verified", "preadmission_send_refused", "both_members_joined",
                "owner_message_verified", "signed_acceptances_verified", "exact_retry",
                "b_offline_stopped", "b_same_home_restarted", "offline_catch_up",
                "retained_exact_retry", "no_duplicate_event", "removed_member_refused",
                "surviving_member_received_new_epoch", "removed_state_persisted",
                "removed_member_no_new_epoch_message", "service_joined")
TRANSPORT_STAGES = {
    "host": frozenset(("owner_initial", "owner_offline", "owner_catchup", "owner_rekey")),
    "client": frozenset(("b_initial", "c_initial", "b_restarted", "c_rekey")),
}
PHASE_FIELDS = {
    "descriptor": {"owner", "endpoint", "namespace", "tokens", "validity"},
    "client-hello": {"host_machine", "accounts"},
    "host-offers": {"client_machine", "offers"},
    "client-requests": {"host_machine", "requests", "devices"},
    "host-admission": {"client_machine", "responses"},
    "client-offline": {"host_machine", "member_device"},
    "host-offline-ready": {"client_machine", "sequence"},
    "client-caught-up": {"host_machine", "member_device"},
}
PHASES = frozenset(("initialize", "bootstrap", "admission", "delivery", "exchange", "offline",
                   "restart", "catch_up", "removal", "rekey", "shutdown", "complete"))
require = shared.require
read_json = shared.read_json
write_json = shared.write_json
operation = public.operation


def artifact_name(kind):
    current = shared.context()
    return f"headless-private-{kind}-{current['run_id']}-{current['run_attempt']}"


def artifact_reader():
    # Isolate the shared controller's configuration. Importing or running this
    # adapter never changes public/controller globals used by test discovery.
    spec = importlib.util.spec_from_file_location("_private_artifact_reader", shared.__file__)
    reader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reader)
    reader.artifact_name = artifact_name
    return reader


def hex_value(value, size=64):
    require(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{" + str(size) + r"}", value),
            "invalid public or synthetic commitment")
    return value


def pair(value, artifacts=False):
    require(isinstance(value, dict) and set(value) == {"b", "c"}, "unexpected participant fields")
    for selected in value.values():
        if artifacts:
            require(isinstance(selected, str) and 0 < len(selected) <= 49152 and len(selected) % 2 == 0
                    and re.fullmatch(r"[a-f0-9]+", selected), "invalid bounded bootstrap artifact")
        else:
            hex_value(selected)


def validate_packet(value, kind, expected, distinct=True):
    require(isinstance(value, dict) and kind in PHASE_FIELDS, "invalid private handoff")
    require(set(value) == set(CONTEXT) | {"schema", "kind", "machine"} | PHASE_FIELDS[kind],
            "unexpected private handoff fields")
    require(value["schema"] == SCHEMA and value["kind"] == kind and shared.matching(value, expected),
            "foreign private handoff")
    require(len(json.dumps(value, separators=(",", ":")).encode()) <= MAX_JSON, "private handoff exceeds bound")
    hex_value(value["machine"])
    if distinct:
        require(value["machine"] != expected["machine"], "roles are not on distinct runners")
    for destination in ("host_machine", "client_machine"):
        if destination in value:
            hex_value(value[destination])
            if distinct:
                require(value[destination] == expected["machine"], "handoff selected another runner")
    if kind == "descriptor":
        owner = value["owner"]
        require(isinstance(owner, dict) and set(owner) == {"room", "anchor", "account", "device"},
                "unexpected owner context")
        for field in owner.values():
            hex_value(field)
        pair(value["tokens"])
        require(value["tokens"]["b"] != value["tokens"]["c"], "participants share a credential")
        hex_value(value["namespace"])
        endpoint = value["endpoint"]
        require(isinstance(endpoint, dict) and set(endpoint) == {"endpoint_id", "relay_url", "addresses"},
                "unexpected endpoint fields")
        hex_value(endpoint["endpoint_id"])
        require(endpoint["relay_url"] == expected.get("relay"), "unexpected private relay")
        if endpoint["relay_url"]:
            require(endpoint["addresses"] == [], "runner handoff contains private interface addresses")
        else:
            addresses = endpoint["addresses"]
            require(isinstance(addresses, list) and len(addresses) == 1
                    and isinstance(addresses[0], str) and re.fullmatch(r"127\.0\.0\.1:[1-9][0-9]{0,4}", addresses[0])
                    and int(addresses[0].split(":")[1]) <= 65535, "invalid local loopback route")
        validity = value["validity"]
        require(isinstance(validity, dict) and set(validity) == {"not_before", "expires_at"}
                and all(type(v) is int for v in validity.values())
                and 0 <= validity["not_before"] < validity["expires_at"]
                and validity["expires_at"] - validity["not_before"] <= 3600, "invalid synthetic validity")
    for name in ("accounts", "devices"):
        if name in value:
            pair(value[name])
            require(value[name]["b"] != value[name]["c"], "participants share an identity")
    for name in ("offers", "requests", "responses"):
        if name in value:
            pair(value[name], artifacts=True)
    if "member_device" in value:
        hex_value(value["member_device"])
    if "sequence" in value:
        require(type(value["sequence"]) is int and 0 < value["sequence"] < 2**64, "invalid outbox sequence")
    return value


def packet(config, kind, **fields):
    value = {key: config[key] for key in CONTEXT}
    value.update(schema=SCHEMA, kind=kind, machine=config["machine"], **fields)
    return validate_packet(value, kind, config, distinct=False)


def validate_observation(observation, config):
    mode = "relay_only" if config.get("relay") else "direct_only"
    require(isinstance(observation, dict) and set(observation) == {"peer", "operation", "before", "after"}
            and observation["operation"] in ("put", "page"), "unexpected private path evidence")
    public.validate_observation({key: observation[key] for key in ("peer", "before", "after")}, mode)
    expected = "relay" if config.get("relay") else "direct"
    require(all(observation[when]["selected"] == expected for when in ("before", "after")),
            "private selected path was not observed")
    return observation


def validate_transport(value, role, config):
    require(isinstance(value, dict) and set(value) == TRANSPORT_STAGES[role], "incomplete private path observations")
    for observation in value.values():
        validate_observation(observation, config)
    return value


def claims(config, passed=False, observations=None):
    observed = bool(observations)
    relay = bool(config.get("relay"))
    return dict(scope="private headless CLI processes",
                observed_path=("relay_only_snapshots" if relay else "direct_snapshots") if observed else "unreported",
                configured_path_mode="relay_only" if relay else "direct_only",
                relay_configured=relay, forced_relay_qualified=passed and relay and observed,
                direct_path_qualified=passed and not relay and observed, per_byte_path_qualified=False,
                independent_nat_qualified=False, browser_qualified=False,
                private_qualified=passed, independent_machines_qualified=passed and config["mode"] == "runners",
                path_observation_scope="last successful validated reply; snapshots, not per-byte routing",
                credential_lifetime="bounded by disposable host lifetime and cleanup; no token expiry")


def validate_result(value, role):
    names = HOST_CASES if role == "host" else CLIENT_CASES
    require(isinstance(value, dict) and set(value) == {"cases", "remote_machine"}, "unexpected role result")
    require(isinstance(value["cases"], dict) and set(value["cases"]) == set(names)
            and all(value["cases"][name] is True for name in names), "incomplete private journey")
    hex_value(value["remote_machine"])
    return value


def receipt(config):
    return dict({key: config[key] for key in CONTEXT}, schema=SCHEMA, role=config["role"],
                machine=config["machine"], **claims(config), passed=False, cleanup_confirmed=False,
                source_attested=config["mode"] == "runners",
                placement=("separate GitHub-hosted Ubuntu VMs; NAT diversity unmeasured"
                           if config["mode"] == "runners" else "both roles on one local machine"),
                started_unix=int(time.time()))


def setup(bundle, work, role):
    manifest = read_json(bundle / "build.json")
    require(manifest.get("schema") == public.SCHEMA and manifest.get("features") == "headless",
            "expected the existing current headless bundle")
    require(all(manifest.get(key) == value for key, value in shared.context().items()), "foreign bundle")
    require(manifest.get("binary_sha256") == shared.digest(bundle / "fixture")
            and manifest.get("lock_sha256") == shared.digest(Path("Cargo.lock")), "candidate digest changed")
    hex_value(manifest.get("nonce"))
    (bundle / "fixture").chmod(0o700)
    work.mkdir(mode=0o700)
    boot = Path("/proc/sys/kernel/random/boot_id").read_bytes()
    machine = hashlib.sha256(manifest["nonce"].encode() + boot + socket.gethostname().encode()).hexdigest()
    config = dict({key: manifest[key] for key in CONTEXT}, role=role, work=str(work.resolve()),
                  binary=str((bundle / "fixture").resolve()), machine=machine, relay=RELAY, mode="runners")
    write_json(work / "config.json", config)
    write_json(work / f"{role}-receipt.json", receipt(config))
    return config


def safe_phase(work):
    try:
        phase = read_json(work / "phase.json")
        return phase if isinstance(phase, str) and phase in PHASES else "unreported"
    except (OSError, ValueError):
        return "unreported"


def receive_remote(work, kind):
    config = read_json(work / "config.json")
    value = artifact_reader().poll_document(kind, f"{kind}.json", 240)
    validate_packet(value, kind, config)
    if kind != "descriptor":
        selected = read_json(work / ("client-hello.json" if config["role"] == "host" else "descriptor.json")) \
            if (work / ("client-hello.json" if config["role"] == "host" else "descriptor.json")).exists() else None
        if selected is not None:
            require(value["machine"] == selected["machine"], "later handoff changed the selected runner")
    write_json(work / f"{kind}.json", value)
    return value


def wait_file(work, name, timeout=240):
    return shared.wait_local(work / name, time.monotonic() + timeout, work / "supervisor.json")


def supervise(work):
    child = None
    result = dict(exit_code=None, forced=False, child_reaped=False, group_cleared=False)
    try:
        with (work / "private.log").open("wb") as log:
            child = subprocess.Popen([sys.executable, str(SCRIPT), "role", "--work", str(work.resolve())],
                stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                env=shared.child_env(work / "config.json"), start_new_session=True)
            deadline = time.monotonic() + 1080
            stopping = False
            while time.monotonic() < deadline:
                if (work / "stop").exists() and not stopping:
                    stopping = True
                    deadline = min(deadline, time.monotonic() + 90)
                try:
                    result["exit_code"] = child.wait(timeout=0.25)
                    break
                except subprocess.TimeoutExpired:
                    pass
            else:
                result["forced"] = True
    finally:
        previous = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGTERM, signal.SIGINT)}
        try:
            if child is not None:
                if child.poll() is None:
                    result["forced"] = True
                    try:
                        os.killpg(child.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    try:
                        child.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        os.killpg(child.pid, signal.SIGKILL)
                        child.wait(timeout=10)
                extra, result["group_cleared"] = shared.clear_owned_group(child.pid)
                result["forced"] = result["forced"] or extra
                result["child_reaped"] = child.poll() is not None
            write_json(work / "supervisor.json", result)
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)


def start_role(bundle, work, role):
    setup(bundle, work, role)
    if role == "client":
        receive_remote(work, "descriptor")
    with (work / "supervisor-private.log").open("wb") as log:
        subprocess.Popen([sys.executable, str(SCRIPT), "supervise", "--work", str(work.resolve())],
                         stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
    try:
        wait_file(work, "descriptor.json" if role == "host" else "client-hello.json", 120)
    except BaseException:
        (work / "stop").touch(mode=0o600)
        shared.wait_local(work / "supervisor.json", time.monotonic() + 150)
        raise


def validate_client(value, expected):
    require(isinstance(value, dict) and value.get("schema") == SCHEMA and value.get("role") == "client"
            and shared.matching(value, expected), "foreign private client receipt")
    require(value.get("passed") is True and value.get("cleanup_confirmed") is True,
            "private client journey or cleanup failed")
    require(value.get("source_attested") is True and type(value.get("fixture_exit_code")) is int
            and value["fixture_exit_code"] == 0 and value.get("fixture_forced_cleanup") is False,
            "private client lacks clean current-candidate process evidence")
    require(value.get("machine") == expected.get("selected_client_machine")
            and value.get("machine") != expected["machine"], "client receipt changed the admitted runner")
    validate_result(dict(cases=value.get("cases"), remote_machine=value.get("remote_machine")), "client")
    require(value["remote_machine"] == expected["machine"], "client selected another host")
    config = dict(mode="runners", relay=RELAY)
    observations = validate_transport(value.get("transport_observations"), "client", config)
    allowed = set(CONTEXT) | set(claims(config)) | {"schema", "role", "machine", "passed", "cleanup_confirmed",
        "source_attested", "placement", "started_unix", "finished_unix", "fixture_exit_code",
        "fixture_forced_cleanup", "cases", "remote_machine", "transport_observations"}
    require(set(value) <= allowed, "unexpected private receipt fields")
    for key, selected in claims(config, True, observations).items():
        require(value.get(key) is selected if isinstance(selected, bool) else value.get(key) == selected,
                "unsupported private path or scope claim")


def finish_role(work, role, wait):
    result = read_json(work / f"{role}-receipt.json")
    config = read_json(work / "config.json")
    try:
        if role == "host" and wait:
            hello = read_json(work / "client-hello.json")
            result["selected_client_machine"] = hello["machine"]
            client = artifact_reader().poll_document("client", "client-receipt.json", 360)
            validate_client(client, result)
            result["client_verified"] = True
        if role == "host" or not wait:
            (work / "stop").touch(mode=0o600)
        supervisor = shared.wait_local(work / "supervisor.json", time.monotonic() + (360 if wait else 150))
        result["cleanup_confirmed"] = supervisor.get("child_reaped") is True and supervisor.get("group_cleared") is True
        result["fixture_exit_code"] = supervisor.get("exit_code")
        result["fixture_forced_cleanup"] = supervisor.get("forced")
        require(result["cleanup_confirmed"] and supervisor.get("exit_code") == 0
                and supervisor.get("forced") is False, "private role cleanup failed")
        role_result = validate_result(read_json(work / f"{role}-result.json"), role)
        result.update(role_result)
        result["transport_observations"] = validate_transport(read_json(work / f"{role}-transport.json"), role, config)
        require(role != "host" or result.get("client_verified") is True, "remote client is not verified")
        result["passed"] = True
    except Exception as failure:
        result["passed"] = False
        result["error_class"] = type(failure).__name__
        result["failed_case"] = safe_phase(work)
        (work / "stop").touch(mode=0o600)
        try:
            supervisor = shared.wait_local(work / "supervisor.json", time.monotonic() + 150)
            result["cleanup_confirmed"] = supervisor.get("child_reaped") is True and supervisor.get("group_cleared") is True
        except Exception:
            result["cleanup_confirmed"] = False
    finally:
        result.update(claims(config, result["passed"], result.get("transport_observations")))
        result["finished_unix"] = int(time.time())
        write_json(work / f"{role}-receipt.json", result)
    return result["passed"]


class Mailbox:
    def __init__(self, config):
        self.config = config
        self.home = Path(config["work"]) / "mailbox-host"
        self.argv = [config["binary"], "--no-update", "private-host"]
        self.env = shared.child_env(Path(config["work"]) / "config.json")
        self.child = None
        self.log = None
        self.forced = False

    def invoke(self, action, *args):
        code, raw = public.exchange(self.argv + [action, str(self.home), *args], b"", self.env)
        require(code == 0, "private host command failed")
        value = json.loads(raw)
        require(isinstance(value, dict), "invalid private host reply")
        return value

    def start(self):
        bind = "0.0.0.0:0"
        if not self.config["relay"]:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.bind(("127.0.0.1", 0))
                bind = f"127.0.0.1:{probe.getsockname()[1]}"
        value = self.invoke("init", "--transport", "iroh", "--iroh-bind", bind,
                            "--relay-url", self.config["relay"] or "none", "--executable", self.config["binary"])
        require(value.get("status") == "initialized" and value.get("transport") == "iroh", "wrong mailbox transport")
        require(self.invoke("add-credential").get("credential_index") == 3, "third credential missing")
        self.log = (Path(self.config["work"]) / "mailbox-private.log").open("wb")
        self.child = subprocess.Popen(self.argv + ["serve", str(self.home)], stdin=subprocess.DEVNULL,
                                      stdout=self.log, stderr=self.log, env=self.env)
        deadline = time.monotonic() + 45
        path = Path(self.config["work"]) / "mailbox-private.log"
        while time.monotonic() < deadline:
            require(self.child.poll() is None, "mailbox exited before readiness")
            require(path.stat().st_size <= 16384, "mailbox readiness output exceeds bound")
            lines = path.read_bytes().splitlines()
            if lines:
                ready = json.loads(lines[0])
                require(ready.get("status") == "listening" and ready.get("transport") == "iroh",
                        "mailbox did not report Iroh readiness")
                connection = read_json(self.home / "connection.json")
                require(ready["endpoint"] == connection["endpoint"], "mailbox identity changed")
                return connection
            time.sleep(0.1)
        raise TimeoutError("mailbox readiness deadline")

    def stop(self):
        try:
            if self.child is not None:
                child = self.child
                try:
                    require(child.poll() is None, "mailbox exited unexpectedly")
                    child.terminate()
                    require(child.wait(timeout=30) == 0, "mailbox did not drain cleanly")
                except BaseException:
                    self.forced = True
                    raise
                finally:
                    if child.poll() is None:
                        self.forced = True
                        child.kill()
                    child.wait(timeout=10)
                    self.child = None
        finally:
            if self.log is not None:
                self.log.close()
                self.log = None


class Journey:
    def __init__(self, config):
        self.config = config
        self.work = Path(config["work"])
        self.cases = {}
        self.daemons = []
        self.mailbox = None
        self.remote_machine = None
        self.transport = {}
        self.endpoints = {}
        self.deadline = time.monotonic() + 960

    def phase(self, name):
        require(name in PHASES, "unexpected private phase")
        write_json(self.work / "phase.json", name)

    def wait(self, probe, seconds=150):
        deadline = min(self.deadline, time.monotonic() + seconds)
        while time.monotonic() < deadline:
            require(not (self.work / "stop").exists(), "private journey stopped")
            result = probe()
            if result:
                return result
            time.sleep(0.25)
        raise TimeoutError("private journey phase deadline")

    def incoming(self, kind):
        value = self.wait(lambda: read_json(self.work / f"{kind}.json")
                          if (self.work / f"{kind}.json").exists() else None, 300)
        validate_packet(value, kind, self.config, self.config["mode"] == "runners")
        if self.remote_machine is None:
            self.remote_machine = value["machine"]
        require(self.remote_machine == value["machine"], "handoff changed selected participant machine")
        return value

    def publish(self, kind, **fields):
        write_json(self.work / f"{kind}.json", packet(self.config, kind, **fields))

    def daemon(self, name):
        # This listener is independent of the private profile's Iroh mailbox.
        daemon = public.Daemon(dict(self.config, relay=None, relay_only=False), name)
        self.daemons.append(daemon)
        daemon.start()
        return daemon

    def body(self, label):
        return f"private qualification {self.config['nonce'][:16]} {label}"

    def status(self, daemon):
        return daemon.call("room.status", room=operation(1))

    def profile(self, daemon, descriptor, token):
        parent = daemon.home.parent / (daemon.home.name + "-delivery")
        parent.mkdir(mode=0o700)
        token_path = parent / "token.hex"
        token_path.write_text(hex_value(token))
        token_path.chmod(0o600)
        status = self.status(daemon)
        context = {key: status["context"][key] for key in ("room", "anchor", "account", "device")}
        require(all(context[key] == descriptor["owner"][key] for key in ("room", "anchor")), "foreign private room")
        value = dict(version=4, context=context, namespace=descriptor["namespace"],
                     transport=dict(kind="iroh", endpoint=descriptor["endpoint"], relay_only=bool(self.config["relay"])), token=str(token_path),
                     state=str(parent / "queue"), max_jobs=64, max_bytes=8388608, max_attempts=4,
                     initial_backoff_secs=1, max_backoff_secs=30, emit_acceptance=True,
                     initial_cursor=0, mailbox_polling="interactive")
        path = parent / "delivery.json"
        raw = json.dumps(value, separators=(",", ":")).encode()
        path.write_bytes(raw)
        path.chmod(0o600)
        digest = hashlib.sha256(raw).hexdigest()
        initialized = daemon.call("private.delivery_init", room=operation(1), profile=str(path), profile_hash=digest)
        require(initialized.get("initialized") is True and initialized.get("profile_hash") == digest,
                "private queue was not initialized")
        attached = daemon.call("private.delivery_attach", room=operation(1), operation=operation(10),
                               profile=str(path), profile_hash=digest)
        require(attached["current"]["state"] == "active", "private delivery was not attached")
        self.endpoints[daemon.home.name] = descriptor["endpoint"]["endpoint_id"]

    def observe(self, daemon, stage):
        require(stage in TRANSPORT_STAGES[self.config["role"]] and stage not in self.transport,
                "unexpected private transport stage")
        status = daemon.call("private.delivery_status", room=operation(1), after=0, limit=16)
        transport = status.get("transport", {})
        require(transport.get("kind") == "iroh" and transport.get("relay_only") is bool(self.config["relay"]),
                "private delivery selected another transport mode")
        observation = status.get("last_transport_observation")
        require(isinstance(observation, dict) and set(observation) == {"operation", "before", "after"},
                "no checked private reply path observation")
        value = dict(peer=self.endpoints[daemon.home.name], **observation)
        self.transport[stage] = validate_observation(value, self.config)

    def send(self, daemon, number, label, status=None):
        status = status or self.status(daemon)
        return daemon.call("room.send", room=operation(1), operation=operation(number),
                           body=self.body(label), epoch=status["epoch"], roster=status["roster"])

    def denied_send(self, daemon, number, label):
        try:
            self.send(daemon, number, label)
        except public.CliRefusal as failure:
            require(failure.code == "permission-denied", "membership refusal had another cause")
        else:
            raise ValueError("unadmitted or removed member sent a new message")

    def seen(self, daemon, label, sender):
        page = daemon.call("room.messages", room=operation(1), after=0, limit=16)
        records = [row for row in page["records"] if row["body"] == self.body(label)]
        if not records:
            return None
        require(len(records) == 1 and records[0]["sender"] == sender, "private message duplicated or wrong sender")
        return records[0]

    def outbox(self, daemon, sequence):
        page = daemon.call("room.outbox_status", room=operation(1), after=sequence-1, limit=1)
        require(len(page["records"]) == 1 and page["records"][0]["cursor"] == sequence,
                "retained application output disappeared")
        require(isinstance(page.get("acceptance_scope"), str), "acceptance scope missing")
        return page["records"][0]

    def accepted(self, daemon, sequence, recipients):
        row = self.outbox(daemon, sequence)
        observed = row["device_acceptances"]
        require(row["member_acceptance_count"] == len(observed), "acceptance count changed")
        actual = {claim["recipient"] for claim in observed}
        require(len(actual) == len(observed) and actual <= set(recipients), "unexpected recipient acceptance")
        for claim in observed:
            hex_value(claim["ciphertext"])
            require(type(claim["received_sequence"]) is int and claim["received_sequence"] > 0,
                    "invalid authenticated processing claim")
        return row if actual == set(recipients) else None

    def retained(self, daemon, number):
        def probe():
            status = daemon.call("private.delivery_status", room=operation(1), after=0, limit=16)
            require(status["state"] == "active", "private delivery stopped")
            # Queue sequence and native outbox sequence are separate domains.
            return any(row["operation"] == operation(number) and row["state"] == "retained"
                       for row in status.get("application", {}).get("records", []))
        self.wait(probe)

    def retry(self, daemon, number, label, original, status):
        retry = self.send(daemon, number, label, status)
        require(retry["exact_retry"] is True and retry["artifact"] == original["artifact"]
                and retry["sequence"] == original["sequence"], "exact private retry changed signed output")

    def host(self):
        self.phase("initialize")
        self.mailbox = Mailbox(self.config)
        connection = self.mailbox.start()
        self.cases["mailbox_iroh_started"] = True
        owner = self.daemon("a")
        validity = dict(not_before=int(time.time())-60, expires_at=int(time.time())+1800)
        initial = owner.call("room.create", operation=operation(1), kind="private", limits=LIMITS, validity=validity)
        descriptor = dict(owner={key: initial["context"][key] for key in ("room", "anchor", "account", "device")},
                          endpoint=connection["endpoint"], namespace=connection["namespace"], validity=validity,
                          tokens={name: (self.mailbox.home / f"client-{index}.token").read_text().strip()
                                  for name, index in (("b", 2), ("c", 3))})
        self.publish("descriptor", **descriptor)
        self.phase("bootstrap")
        hello = self.incoming("client-hello")
        offers = {name: owner.call("private.offer", room=operation(1), operation=operation(index),
                                  recipient=hello["accounts"][name], validity=validity)["offer"]
                  for name, index in (("b", 2), ("c", 3))}
        self.publish("host-offers", client_machine=self.remote_machine, offers=offers)
        requests = self.incoming("client-requests")
        self.phase("admission")
        responses = {name: owner.call("private.accept_contact", room=operation(1), operation=operation(index),
                                     request=requests["requests"][name], validity=validity)["artifact"]
                     for name, index in (("b", 4), ("c", 5))}
        self.cases["explicit_member_admission"] = True
        self.profile(owner, descriptor, (self.mailbox.home / "client-1.token").read_text().strip())
        self.publish("host-admission", client_machine=self.remote_machine, responses=responses)
        status = self.status(owner)
        members = {(row["account"], row["device"]) for row in status["recipients"]}
        require(all((hello["accounts"][name], requests["devices"][name]) in members for name in ("b", "c"))
                and status["members"] == 3, "owner admitted unexpected membership")
        self.cases["current_roster_verified"] = True
        self.phase("exchange")
        first = self.send(owner, 20, "owner-first", status)
        self.retry(owner, 20, "owner-first", first, status)
        self.cases["exact_retry"] = True
        for name in ("b", "c"):
            self.wait(lambda name=name: self.seen(owner, name + "-reply", requests["devices"][name]))
            self.cases[f"member_{name}_reply_verified"] = True
        self.wait(lambda: self.accepted(owner, first["sequence"], requests["devices"].values()))
        self.cases["signed_acceptances_verified"] = True
        self.observe(owner, "owner_initial")
        self.send(owner, 21, "exchange-complete")
        self.phase("offline")
        offline = self.incoming("client-offline")
        require(offline["member_device"] == requests["devices"]["b"], "another member went offline")
        sent_offline = self.send(owner, 22, "while-b-offline")
        self.retained(owner, 22)
        self.wait(lambda: self.accepted(owner, sent_offline["sequence"], [requests["devices"]["c"]]))
        self.cases["offline_retained_without_b_acceptance"] = True
        self.observe(owner, "owner_offline")
        self.publish("host-offline-ready", client_machine=self.remote_machine, sequence=sent_offline["sequence"])
        caught = self.incoming("client-caught-up")
        require(caught["member_device"] == requests["devices"]["b"], "another member restarted")
        self.wait(lambda: self.accepted(owner, sent_offline["sequence"], requests["devices"].values()))
        self.cases["offline_b_acceptance_verified"] = True
        self.observe(owner, "owner_catchup")
        self.phase("removal")
        before = self.status(owner)
        owner.call("private.remove", room=operation(1), operation=operation(30), device=requests["devices"]["b"])
        after = self.status(owner)
        require(after["epoch"] > before["epoch"] and after["roster"] != before["roster"]
                and after["members"] == 2 and all(row["device"] != requests["devices"]["b"]
                    for row in after["recipients"]), "removal did not advance MLS membership")
        self.cases["removal_rekeyed"] = True
        self.phase("rekey")
        post = self.send(owner, 31, "after-b-removal", after)
        self.wait(lambda: self.seen(owner, "c-after-removal", requests["devices"]["c"]))
        self.wait(lambda: self.accepted(owner, post["sequence"], [requests["devices"]["c"]]))
        self.cases["surviving_member_after_rekey"] = True
        self.observe(owner, "owner_rekey")
        self.send(owner, 32, "rekey-complete")
        self.phase("shutdown")
        while not (self.work / "stop").exists():
            require(time.monotonic() < self.deadline, "private host stop deadline")
            time.sleep(0.2)

    def client(self):
        self.phase("initialize")
        descriptor = self.incoming("descriptor")
        members = {name: self.daemon(name) for name in ("b", "c")}
        accounts = {name: daemon.call("service.status")["account"] for name, daemon in members.items()}
        self.publish("client-hello", host_machine=self.remote_machine, accounts=accounts)
        self.phase("bootstrap")
        offers = self.incoming("host-offers")
        joined = {}
        for name, daemon in members.items():
            joined[name] = daemon.call("room.join_private", operation=operation(1), offer=offers["offers"][name],
                expected_owner=descriptor["owner"]["account"], validity=descriptor["validity"], limits=LIMITS)
            status = joined[name]["status"]
            require(status["needs_owner_admission"] is True and status["can_send"] is False
                    and status["context"]["account"] == accounts[name]
                    and all(status["context"][key] == descriptor["owner"][key] for key in ("room", "anchor")),
                    "private offer did not bind expected membership")
            self.denied_send(daemon, 90, "before-admission")
        self.cases.update(owner_pin_verified=True, preadmission_send_refused=True)
        devices = {name: joined[name]["status"]["context"]["device"] for name in members}
        self.publish("client-requests", host_machine=self.remote_machine, devices=devices,
                     requests={name: joined[name]["request"] for name in members})
        self.phase("admission")
        admission = self.incoming("host-admission")
        for name, daemon in members.items():
            status = daemon.call("private.join_contact", room=operation(1), response=admission["responses"][name])
            require(status["phase"] == "member_joined" and status["can_send"] is True, "member admission incomplete")
            self.profile(daemon, descriptor, descriptor["tokens"][name])
        self.wait(lambda: self.status(members["b"])["roster"] == self.status(members["c"])["roster"]
                  and self.status(members["b"])["members"] == 3)
        self.cases["both_members_joined"] = True
        self.phase("exchange")
        first = {}
        bindings = {}
        for name, daemon in members.items():
            self.wait(lambda daemon=daemon: self.seen(daemon, "owner-first", descriptor["owner"]["device"]))
            bindings[name] = self.status(daemon)
            first[name] = self.send(daemon, 20, name + "-reply", bindings[name])
            self.retry(daemon, 20, name + "-reply", first[name], bindings[name])
        self.cases.update(owner_message_verified=True, exact_retry=True)
        for name, daemon in members.items():
            recipients = [descriptor["owner"]["device"], devices["c" if name == "b" else "b"]]
            self.wait(lambda daemon=daemon, name=name, recipients=recipients:
                      self.accepted(daemon, first[name]["sequence"], recipients))
            self.wait(lambda daemon=daemon: self.seen(daemon, "exchange-complete", descriptor["owner"]["device"]))
            self.observe(daemon, name + "_initial")
        self.cases["signed_acceptances_verified"] = True
        self.phase("offline")
        member = members["b"]
        member.stop()
        self.cases["b_offline_stopped"] = True
        self.publish("client-offline", host_machine=self.remote_machine, member_device=devices["b"])
        ready = self.incoming("host-offline-ready")
        self.phase("restart")
        member.start(initialize=False)
        status = self.status(member)
        require(status["context"] == bindings["b"]["context"], "restart changed private device identity")
        self.cases["b_same_home_restarted"] = True
        self.phase("catch_up")
        received = self.wait(lambda: self.seen(member, "while-b-offline", descriptor["owner"]["device"]))
        require(ready["sequence"] > 0, "offline source sequence missing")
        self.cases["offline_catch_up"] = True
        self.observe(member, "b_restarted")
        self.retry(member, 20, "b-reply", first["b"], bindings["b"])
        self.cases["retained_exact_retry"] = True
        require(self.seen(member, "while-b-offline", descriptor["owner"]["device"]) == received,
                "offline message duplicated after retry")
        self.cases["no_duplicate_event"] = True
        self.publish("client-caught-up", host_machine=self.remote_machine, member_device=devices["b"])
        self.phase("removal")
        self.wait(lambda: self.status(member)["phase"] == "removed")
        removed = self.status(member)
        require(removed["can_send"] is False, "removed member retained send authority")
        self.denied_send(member, 91, "removed-send")
        self.cases["removed_member_refused"] = True
        survivor = members["c"]
        self.phase("rekey")
        self.wait(lambda: self.seen(survivor, "after-b-removal", descriptor["owner"]["device"]))
        current = self.status(survivor)
        require(current["epoch"] > bindings["c"]["epoch"] and current["members"] == 2
                and all(row["device"] != devices["b"] for row in current["recipients"]),
                "surviving member did not advance membership")
        self.cases["surviving_member_received_new_epoch"] = True
        post = self.send(survivor, 31, "c-after-removal", current)
        self.wait(lambda: self.accepted(survivor, post["sequence"], [descriptor["owner"]["device"]]))
        self.wait(lambda: self.seen(survivor, "rekey-complete", descriptor["owner"]["device"]))
        self.observe(survivor, "c_rekey")
        member.stop()
        member.start(initialize=False)
        status = self.status(member)
        require(status["phase"] == "removed" and status["can_send"] is False
                and status["context"] == removed["context"], "removal did not survive restart")
        self.denied_send(member, 92, "removed-after-restart")
        self.cases["removed_state_persisted"] = True
        require(self.seen(member, "after-b-removal", descriptor["owner"]["device"]) is None,
                "removed member decrypted a new-epoch message")
        self.cases["removed_member_no_new_epoch_message"] = True
        self.phase("shutdown")

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
            if self.mailbox is not None:
                try:
                    self.mailbox.stop()
                except BaseException:
                    clean = False
            require(clean and all(not daemon.forced for daemon in self.daemons)
                    and (self.mailbox is None or not self.mailbox.forced), "private owned-process cleanup failed")
        self.cases["service_joined"] = True
        if self.mailbox is not None:
            self.cases["mailbox_joined"] = True
        result = validate_result(dict(cases=self.cases, remote_machine=self.remote_machine), self.config["role"])
        validate_transport(self.transport, self.config["role"], self.config)
        write_json(self.work / f"{self.config['role']}-transport.json", self.transport)
        write_json(self.work / f"{self.config['role']}-result.json", result)
        self.phase("complete")


def run_role(work):
    config = read_json(work / "config.json")
    require(config["role"] in ("host", "client") and Path(config["work"]) == work.resolve(), "foreign role home")
    binary = Path(config["binary"])
    require(binary.is_absolute() and binary.is_file()
            and shared.digest(binary) == config["binary_sha256"], "candidate executable changed")
    try:
        Journey(config).run()
    except Exception as failure:
        write_json(work / "failure-private.json", dict(error_class=type(failure).__name__,
            phase=safe_phase(work), message=str(failure)[:2048], code=getattr(failure, "code", None),
            operation=getattr(failure, "operation", None), detail=getattr(failure, "detail", None)))
        raise


def local(binary, work):
    binary = binary.resolve(strict=True)
    work.mkdir(mode=0o700)
    work = work.resolve()
    nonce = secrets.token_hex(32)
    context = dict(source_sha=None, run_id="local", run_attempt="1", nonce=nonce,
        binary_sha256=shared.digest(binary), lock_sha256=None, machine=hashlib.sha256(nonce.encode()).hexdigest(),
        binary=str(binary), relay=None, mode="local")
    result = dict(schema=SCHEMA, **claims(context), binary_sha256=context["binary_sha256"],
                  source_sha=None, source_attested=False, placement="both roles on one local machine",
                  passed=False, cleanup_confirmed=False)
    children = {}
    deadline = time.monotonic() + 1050
    try:
        for role in ("host", "client"):
            home = work / role
            home.mkdir(mode=0o700)
            write_json(home / "config.json", dict(context, role=role, work=str(home)))
            with (home / "private.log").open("wb") as log:
                children[role] = subprocess.Popen([sys.executable, str(SCRIPT), "role", "--work", str(home)],
                    stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                    env=shared.child_env(home / "config.json"), start_new_session=True)
        for kind, source, target in (("descriptor", "host", "client"), ("client-hello", "client", "host"),
            ("host-offers", "host", "client"), ("client-requests", "client", "host"),
            ("host-admission", "host", "client"), ("client-offline", "client", "host"),
            ("host-offline-ready", "host", "client"), ("client-caught-up", "client", "host")):
            path = work / source / f"{kind}.json"
            while not path.exists():
                require(all(child.poll() is None for child in children.values()), "role exited before handoff")
                require(time.monotonic() < deadline, "local private journey deadline")
                time.sleep(0.1)
            value = validate_packet(read_json(path), kind, context, distinct=False)
            write_json(work / target / f"{kind}.json", value)
        require(children["client"].wait(timeout=max(1, deadline-time.monotonic())) == 0, "client private journey failed")
        (work / "host" / "stop").touch(mode=0o600)
        require(children["host"].wait(timeout=90) == 0, "host private journey failed")
        observations = {}
        for role in ("host", "client"):
            result[role] = validate_result(read_json(work / role / f"{role}-result.json"), role)
            observations.update(validate_transport(read_json(work / role / f"{role}-transport.json"), role, context))
        result["transport_observations"] = observations
        result["passed"] = True
    except Exception as failure:
        result["error_class"] = type(failure).__name__
    finally:
        previous = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGTERM, signal.SIGINT)}
        clean = len(children) == 2
        try:
            for role, child in children.items():
                (work / role / "stop").touch(mode=0o600)
                try:
                    child.wait(timeout=90)
                    result["passed"] = result["passed"] and child.returncode == 0
                except Exception:
                    clean = False
                extra, cleared = shared.clear_owned_group(child.pid)
                clean = clean and cleared and not extra
                child.wait(timeout=10)
            result["cleanup_confirmed"] = clean
            result["passed"] = result["passed"] and clean
            result.update(claims(context, result["passed"], result.get("transport_observations")))
            write_json(work / "local-receipt.json", result)
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
    return result["passed"]


def main():
    os.umask(0o077)
    def interrupted(_sig, _frame):
        raise InterruptedError("private qualification interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("supervise", "role", "local", "host-start", "host-offers", "host-admit",
        "host-offline", "host-remove", "host-wait", "host-stop", "client-start", "client-requests",
        "client-offline", "client-restart", "client-wait", "client-stop"))
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    work, command = args.work.resolve(), args.command
    exchanges = {
        "host-offers": ("client-hello", "host-offers"),
        "host-admit": ("client-requests", "host-admission"),
        "host-offline": ("client-offline", "host-offline-ready"),
        "host-remove": ("client-caught-up", None),
        "client-requests": ("host-offers", "client-requests"),
        "client-offline": ("host-admission", "client-offline"),
        "client-restart": ("host-offline-ready", "client-caught-up"),
    }
    if command == "local":
        return 0 if local(args.binary, work) else 1
    if command == "role":
        run_role(work)
    elif command == "supervise":
        supervise(work)
    elif command in ("host-start", "client-start"):
        start_role(args.bundle.resolve(), work, command.split("-")[0])
    elif command in exchanges:
        incoming, outgoing = exchanges[command]
        receive_remote(work, incoming)
        if outgoing:
            wait_file(work, outgoing + ".json")
    else:
        role, action = command.split("-")
        if action == "stop" and not work.exists():
            return 0
        return 0 if finish_role(work, role, action == "wait") else 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as failure:
        print(json.dumps({"passed": False, "error_class": type(failure).__name__}), file=sys.stderr)
        sys.exit(1)
