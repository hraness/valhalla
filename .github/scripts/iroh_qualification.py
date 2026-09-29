#!/usr/bin/env python3
"""Bounded coordination for disposable iroh fixtures on separate GitHub runners.

Only the descriptor artifact contains a synthetic, short-lived mailbox token.
Receipts contain commitments and booleans; private config, logs and mailbox files
are never uploaded. Artifact selection is restricted to the current run/attempt.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

TEST = "relay::iroh::tests::qualification::independent_runner_transport_qualification"
SCHEMA = "valhalla.iroh-independent-runners.v1"
CLIENT_CASES = (
    "automatic_client_put_page", "exact_duplicate", "wrong_token_refused",
    "wrong_endpoint_refused", "wrong_namespace_refused", "fresh_client_reconnect",
    "raw_client_forced_relay_put_page", "forced_relay_paths_observed",
)
MAX_JSON = 65536
PHASES = frozenset(("descriptor", "automatic_put_page", "wrong_token", "wrong_endpoint",
                   "wrong_namespace", "fresh_client_reconnect", "forced_relay_put_page",
                   "host_identity", "host_storage", "host_service", "host_bind",
                   "host_ready", "host_shutdown", "host_retention"))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def read_json(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_JSON,
            "expected bounded regular JSON")
    return json.loads(path.read_bytes())


def write_json(path, value):
    temporary = path.with_suffix(".writing")
    temporary.write_text(json.dumps(value, sort_keys=True) + "\n")
    temporary.chmod(0o600)
    temporary.replace(path)


def safe_phase(work):
    try:
        phase = read_json(work / "phase.json")
        return phase if isinstance(phase, str) and phase in PHASES else "unreported"
    except (OSError, ValueError):
        return "unreported"


def context():
    value = {"source_sha": os.environ["GITHUB_SHA"], "run_id": os.environ["GITHUB_RUN_ID"],
             "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"]}
    require(re.fullmatch(r"[a-f0-9]{40}", value["source_sha"]), "invalid source selection")
    require(all(re.fullmatch(r"[1-9][0-9]*", value[k]) for k in ("run_id", "run_attempt")),
            "invalid run selection")
    return value


def artifact_name(kind):
    current = context()
    return f"iroh-{kind}-{current['run_id']}-{current['run_attempt']}"


def package(messages, out):
    candidates = []
    for line in messages.read_text().splitlines():
        value = json.loads(line)
        if (value.get("reason") == "compiler-artifact" and value.get("executable")
                and value.get("target", {}).get("name") == "vhalla_private_native"
                and value.get("profile", {}).get("test") is True
                and value["target"].get("kind") == ["lib"]):
            candidates.append(Path(value["executable"]))
    require(len(candidates) == 1, "expected exactly one compiled native unit-test executable")
    out.mkdir(mode=0o700)
    shutil.copyfile(candidates[0], out / "fixture")
    (out / "fixture").chmod(0o700)
    write_json(out / "build.json", dict(context(), schema=SCHEMA,
        binary_sha256=digest(out / "fixture"), lock_sha256=digest(Path("Cargo.lock")),
        nonce=secrets.token_hex(32), toolchain="1.98.1",
        features="agent-rpc,relay-iroh", target="x86_64-unknown-linux-gnu"))


def bundle_identity(bundle):
    manifest = read_json(bundle / "build.json")
    require(manifest.get("schema") == SCHEMA, "wrong fixture build schema")
    require(all(manifest.get(k) == v for k, v in context().items()), "foreign fixture build")
    require(manifest.get("binary_sha256") == digest(bundle / "fixture"), "fixture hash differs")
    require(manifest.get("lock_sha256") == digest(Path("Cargo.lock")), "lockfile differs")
    require(re.fullmatch(r"[a-f0-9]{64}", manifest.get("nonce", "")), "invalid run nonce")
    (bundle / "fixture").chmod(0o700)
    return manifest


def setup(bundle, work, role):
    manifest = bundle_identity(bundle)
    work.mkdir(mode=0o700)
    boot = Path("/proc/sys/kernel/random/boot_id").read_bytes()
    machine = hashlib.sha256(manifest["nonce"].encode() + boot + socket.gethostname().encode()).hexdigest()
    config = dict(context(), role=role, work=str(work.resolve()), nonce=manifest["nonce"],
                  machine=machine, secret=None, token=None, namespace=None)
    if role == "host":
        config.update(secret=list(secrets.token_bytes(32)), token=list(secrets.token_bytes(32)),
                      namespace=list(secrets.token_bytes(32)))
    write_json(work / "config.json", config)
    return manifest, config


def receipt(manifest, config, role):
    return dict(context(), schema=SCHEMA, role=role, passed=False, cleanup_confirmed=False,
                nonce=manifest["nonce"], machine=config["machine"],
                binary_sha256=manifest["binary_sha256"], lock_sha256=manifest["lock_sha256"],
                placement="separate GitHub-hosted Ubuntu job VMs; NAT diversity unmeasured",
                independent_nat_qualified=False, browser_qualified=False,
                started_unix=int(time.time()))


def child_env(config):
    # Do not hand Actions, repository or cloud credentials to the test process.
    selected = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "RUST_BACKTRACE": "0",
                "VHALLA_IROH_QUALIFICATION_CONFIG": str(config.resolve())}
    if "RUNNER_TRACKING_ID" in os.environ:
        # This is process ownership metadata, not an authentication credential.
        selected["RUNNER_TRACKING_ID"] = os.environ["RUNNER_TRACKING_ID"]
    return selected


def run_child(bundle, work, timeout, stop_path=None):
    child = None
    code = None
    forced = False
    interrupted = False
    try:
        with (work / "private.log").open("wb") as log:
            child = subprocess.Popen([str((bundle / "fixture").resolve()), TEST,
                                      "--exact", "--ignored", "--nocapture"],
                                     stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                     env=child_env(work / "config.json"), start_new_session=True)
            try:
                if stop_path is None:
                    code = child.wait(timeout=timeout)
                else:
                    deadline = time.monotonic() + timeout
                    stopping = None
                    while time.monotonic() < deadline:
                        if stop_path.exists() and stopping is None:
                            stopping = time.monotonic() + 20
                            deadline = min(deadline, stopping)
                        try:
                            code = child.wait(timeout=min(0.25, max(0.001, deadline - time.monotonic())))
                            break
                        except subprocess.TimeoutExpired:
                            continue
                    else:
                        forced = True
            except subprocess.TimeoutExpired:
                forced = True
            except InterruptedError:
                interrupted = True
                forced = True
    finally:
        # Repeated cancellation cannot interrupt the finite kill-and-reap path.
        handlers = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGTERM, signal.SIGINT)}
        try:
            if child is not None and child.poll() is None:
                forced = True
                try:
                    os.killpg(child.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    child.wait(timeout=10)
        finally:
            for sig, handler in handlers.items():
                signal.signal(sig, handler)
    return {"exit_code": code, "forced": forced,
            "interrupted": interrupted, "child_reaped": child is not None and child.poll() is not None}


def supervise(bundle, work):
    result = {"exit_code": None, "forced": True, "child_reaped": False}
    try:
        result = run_child(bundle, work, 660, stop_path=work / "stop")
    finally:
        handlers = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGTERM, signal.SIGINT)}
        try:
            write_json(work / "supervisor.json", result)
        finally:
            for sig, handler in handlers.items():
                signal.signal(sig, handler)


def wait_local(path, deadline, failure=None):
    while time.monotonic() < deadline:
        if path.exists():
            return read_json(path)
        if failure is not None and failure.exists():
            raise ValueError("fixture exited before publishing readiness")
        time.sleep(0.25)
    raise TimeoutError("fixture readiness or cleanup deadline")


def start_host(bundle, work):
    manifest, config = setup(bundle, work, "host")
    write_json(work / "host-receipt.json", receipt(manifest, config, "host"))
    with (work / "supervisor-private.log").open("wb") as log:
        subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "supervise",
                          "--bundle", str(bundle.resolve()), "--work", str(work.resolve())],
                         stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
    try:
        wait_local(work / "descriptor.json", time.monotonic() + 60, work / "supervisor.json")
    except BaseException:
        (work / "stop").touch(mode=0o600)
        wait_local(work / "supervisor.json", time.monotonic() + 45)
        raise


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def api_request(path, maximum=1024 * 1024):
    repository = os.environ["GITHUB_REPOSITORY"]
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository), "invalid repository")
    url = f"https://api.github.com/repos/{repository}/{path}"
    request = urllib.request.Request(url, headers={"Authorization": "Bearer " + os.environ["GH_TOKEN"],
        "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
    try:
        response = urllib.request.build_opener(NoRedirect()).open(request, timeout=15)
    except urllib.error.HTTPError as error:
        if error.code != 302:
            raise
        destination = error.headers["Location"]
        parsed = urllib.parse.urlsplit(destination)
        require(parsed.scheme == "https" and parsed.username is None and parsed.password is None,
                "unsafe artifact download redirect")
        require(parsed.hostname and any(parsed.hostname.endswith(suffix) for suffix in
                (".blob.core.windows.net", ".actions.githubusercontent.com", ".githubusercontent.com")),
                "unexpected artifact download host")
        # Never forward the repository token to the signed blob URL.
        response = urllib.request.urlopen(destination, timeout=15)
    with response:
        raw = response.read(maximum + 1)
    require(len(raw) <= maximum, "artifact response exceeded byte bound")
    return raw


def select_artifact(document, name):
    matches = [entry for entry in document.get("artifacts", []) if entry.get("name") == name
               and entry.get("expired") is False]
    require(len(matches) <= 1, "ambiguous matching artifacts")
    if not matches:
        return None
    selected = matches[0]
    require(type(selected.get("id")) is int and selected["id"] > 0, "invalid artifact identity")
    require(0 < selected.get("size_in_bytes", 0) <= 1024 * 1024, "artifact exceeds bound")
    return selected["id"]


def unpack_document(raw, filename):
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        files = archive.infolist()
        require(len(files) == 1 and files[0].filename == filename
                and 0 < files[0].file_size <= MAX_JSON, "artifact must contain one bounded exact file")
        return json.loads(archive.read(files[0]))


def poll_document(kind, filename, timeout):
    until = time.monotonic() + timeout
    name = artifact_name(kind)
    while time.monotonic() < until:
        try:
            found = []
            for page in range(1, 11):
                listing = json.loads(api_request(
                    f"actions/runs/{context()['run_id']}/artifacts?per_page=100&page={page}"))
                selected = select_artifact(listing, name)
                if selected is not None:
                    found.append(selected)
                if len(listing.get("artifacts", [])) < 100:
                    break
            require(len(found) <= 1, "duplicate run artifact name")
            if found:
                return unpack_document(api_request(f"actions/artifacts/{found[0]}/zip"), filename)
        except urllib.error.HTTPError as error:
            if error.code not in (404, 429, 500, 502, 503, 504):
                raise ValueError("artifact API refused request") from None
        except (urllib.error.URLError, TimeoutError):
            pass
        time.sleep(min(5, max(0, until - time.monotonic())))
    raise TimeoutError("matching run artifact did not arrive before deadline")


def matching(value, expected):
    return all(value.get(key) == expected.get(key) for key in
               ("source_sha", "run_id", "run_attempt", "nonce", "binary_sha256", "lock_sha256"))


def validate_client(value, expected):
    require(value.get("schema") == SCHEMA and value.get("role") == "client"
            and matching(value, expected), "foreign client receipt")
    require(value.get("passed") is True and value.get("cleanup_confirmed") is True,
            "client qualification or cleanup failed")
    require(re.fullmatch(r"[a-f0-9]{64}", value.get("machine", ""))
            and value["machine"] != expected["machine"], "runner identities are not distinct")
    cases = value.get("cases", {})
    require(all(cases.get(case) is True for case in CLIENT_CASES), "client evidence is incomplete")
    require(cases.get("host_machine") == expected["machine"], "client contacted another host")


def run_client(bundle, work):
    manifest, config = setup(bundle, work, "client")
    result = receipt(manifest, config, "client")
    try:
        descriptor = poll_document("descriptor", "descriptor.json", 360)
        require(all(descriptor.get(k) == config[k] for k in
                    ("source_sha", "run_id", "run_attempt", "nonce")), "foreign host descriptor")
        write_json(work / "descriptor.json", descriptor)
        child = run_child(bundle, work, 180)
        result["cleanup_confirmed"] = child["child_reaped"]
        result["fixture_exit_code"] = child["exit_code"]
        result["fixture_forced_cleanup"] = child["forced"]
        require(child["exit_code"] == 0 and not child["forced"], "client fixture failed")
        result["cases"] = read_json(work / "client-result.json")
        require(all(result["cases"].get(case) is True for case in CLIENT_CASES), "missing client case")
        result["passed"] = True
    except Exception as error:
        # No raw API, fixture assertion, token, namespace or URL in public evidence.
        result["error_class"] = type(error).__name__
        result["failed_case"] = safe_phase(work)
    finally:
        result["finished_unix"] = int(time.time())
        write_json(work / "client-receipt.json", result)
    return result["passed"]


def finish_host(work, wait):
    result = read_json(work / "host-receipt.json")
    try:
        if wait:
            client = poll_document("client", "client-receipt.json", 540)
            validate_client(client, result)
            result["client_machine"] = client["machine"]
            result["client_verified"] = True
    except Exception as error:
        result["error_class"] = type(error).__name__
    finally:
        (work / "stop").touch(mode=0o600)
        try:
            supervisor = wait_local(work / "supervisor.json", time.monotonic() + 45)
            result["cleanup_confirmed"] = supervisor.get("child_reaped") is True
            result["fixture_exit_code"] = supervisor.get("exit_code")
            result["fixture_forced_cleanup"] = supervisor.get("forced")
            host = read_json(work / "host-result.json")
            result["cases"] = host
            result["passed"] = (result.get("client_verified") is True
                and result["cleanup_confirmed"] and supervisor.get("exit_code") == 0
                and supervisor.get("forced") is False
                and all(host.get(k) is True for k in
                        ("stopped_on_request", "service_joined", "exact_durable_records")))
        except Exception as error:
            result["passed"] = False
            result["error_class"] = type(error).__name__
            result["failed_case"] = safe_phase(work)
        result["finished_unix"] = int(time.time())
        write_json(work / "host-receipt.json", result)
    return result["passed"]


def main():
    os.umask(0o077)
    def interrupted(_signal, _frame):
        raise InterruptedError("controller interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("package", "host-start", "supervise", "host-wait", "host-stop", "client"))
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--work", type=Path)
    parser.add_argument("--cargo-messages", type=Path)
    args = parser.parse_args()
    if args.command == "package":
        package(args.cargo_messages, args.bundle)
    elif args.command == "host-start":
        start_host(args.bundle, args.work)
    elif args.command == "supervise":
        supervise(args.bundle, args.work)
    elif args.command == "client":
        return 0 if run_client(args.bundle, args.work) else 1
    elif args.command in ("host-wait", "host-stop"):
        if args.command == "host-stop" and not args.work.exists():
            return 0
        return 0 if finish_host(args.work, args.command == "host-wait") else 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as failure:
        print(f"iroh qualification controller failed: {type(failure).__name__}", file=sys.stderr)
        sys.exit(1)
