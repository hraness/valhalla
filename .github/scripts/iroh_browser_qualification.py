#!/usr/bin/env python3
"""Qualify the production browser -> loopback gateway -> Iroh path.

The host and browser jobs exchange only a short-lived, run-scoped descriptor.
Receipts contain commitments and closed case results, never endpoint credentials,
raw browser requests, or fixture logs.  NAT diversity and a direct path remain
explicitly unqualified.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import queue
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from verify_browser_artifact import verify as verify_browser_artifact

SCHEMA = "valhalla.iroh-browser-gateway.v1"
BUNDLE_SCHEMA = "valhalla.iroh-browser-bundle.v1"
CONTROLLER = Path(__file__).resolve()
DEFAULT_RELAY_URL = "https://use1-1.relay.n0.iroh.link."
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
SHA40 = re.compile(r"[a-f0-9]{40}\Z")
POSITIVE = re.compile(r"[1-9][0-9]*\Z")
MAX_JSON = 131072
MAX_ARTIFACT_BYTES = 1024 * 1024
CLIENT_CASES = (
    "browser_origin", "browser_manifest_loaded", "first_put", "exact_duplicate",
    "page_exact", "wrong_capability_refused", "wrong_namespace_refused",
    "wrong_origin_refused", "offline_refused", "offline_retry_duplicate",
    "upstream_token_refused", "upstream_retry_duplicate",
)
HOST_CASES = ("host_ready", "client_verified", "host_stopped", "exact_durable_records")
MAGIC = b"VHPRELAY\x01"
DIGEST_DOMAIN = b"vhalla/private/relay-item/v1"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def digest(path: Path, maximum: int | None = None) -> str:
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode),
            "expected a regular non-symlink file")
    if maximum is not None:
        require(0 < metadata.st_size <= maximum, "file exceeds its bound")
    with path.open("rb") as source:
        hasher = hashlib.sha256()
        total = 0
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if maximum is not None:
                require(total <= maximum, "file grew beyond its bound")
            hasher.update(chunk)
    require(maximum is None or total == metadata.st_size, "file changed while being read")
    return hasher.hexdigest()


def read_json(path: Path, maximum: int = MAX_JSON):
    require(path.is_file() and not path.is_symlink(), "expected a bounded JSON file")
    require(0 < path.stat().st_size <= maximum, "JSON file exceeds its bound")
    return json.loads(path.read_bytes(), object_pairs_hook=unique_pairs)


def write_json(path: Path, value) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".writing")
    temporary.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
    temporary.chmod(0o600)
    temporary.replace(path)


def runtime_context() -> dict[str, str]:
    value = {
        "source_sha": os.environ.get("QUALIFICATION_SOURCE_SHA") or os.environ.get("GITHUB_SHA", ""),
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
    }
    require(SHA40.fullmatch(value["source_sha"]) is not None, "invalid source selection")
    require(POSITIVE.fullmatch(value["run_id"]) is not None, "invalid run selection")
    require(POSITIVE.fullmatch(value["run_attempt"]) is not None, "invalid run attempt")
    return value


def validate_relay_url(value: str) -> str:
    # This lane is intentionally pinned to one operator-selected upstream. A
    # workflow input cannot turn the qualification into an arbitrary URL probe.
    require(value == DEFAULT_RELAY_URL, "unexpected Iroh upstream selection")
    return value


def artifact_name(kind: str) -> str:
    current = runtime_context()
    require(kind in {"descriptor", "client", "host"}, "unknown artifact kind")
    return f"iroh-browser-{kind}-{current['run_id']}-{current['run_attempt']}"


def selected_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    names = ("PATH", "HOME", "TMPDIR", "RUNNER_TEMP", "XDG_CACHE_HOME", "NO_COLOR")
    env = {key: os.environ[key] for key in names if key in os.environ}
    env.update({"RUST_BACKTRACE": "0", "CARGO_TERM_COLOR": "never"})
    if extra:
        env.update(extra)
    # GH_TOKEN, Actions runtime tokens and provider credentials are deliberately
    # absent even when a controller is polling public run artifacts.
    return env


def bundle_identity(bundle: Path) -> dict:
    meta = read_json(bundle / "bundle.json")
    current = runtime_context()
    require(isinstance(meta, dict) and meta.get("schema") == BUNDLE_SCHEMA,
            "wrong browser bundle schema")
    require(all(meta.get(key) == value for key, value in current.items()),
            "browser bundle belongs to another run")
    for key in ("binary_sha256", "lock_sha256", "browser_manifest_sha256",
                "controller_sha256"):
        require(isinstance(meta.get(key), str) and HEX64.fullmatch(meta[key]),
                f"invalid bundle {key}")
    require(SHA40.fullmatch(meta.get("tree_sha", "")) is not None, "invalid tree commitment")
    binary = bundle / "vhalla"
    lockfile = bundle / "lockfile"
    browser = bundle / "browser"
    require(binary.is_file() and not binary.is_symlink(), "missing CLI bundle")
    require(binary.stat().st_mode & stat.S_IXUSR, "CLI bundle is not executable")
    require(digest(binary) == meta["binary_sha256"], "CLI bundle hash differs")
    require(digest(lockfile) == meta["lock_sha256"], "lockfile hash differs")
    require(digest(CONTROLLER) == meta["controller_sha256"], "controller differs from bundle")
    manifest_sha = digest(browser / "artifact.json", 65536)
    require(manifest_sha == meta["browser_manifest_sha256"], "browser manifest differs")
    require(verify_browser_artifact(browser, manifest_sha256=manifest_sha) == manifest_sha,
            "browser artifact failed its production manifest checks")
    require(meta.get("iroh_relay_url") == DEFAULT_RELAY_URL,
            "bundle upstream selection is not pinned")
    return meta | {"binary": binary, "lockfile": lockfile, "browser": browser}


def package_bundle(binary: Path, browser: Path, bundle: Path, tree_sha: str,
                   relay_url: str) -> None:
    current = runtime_context()
    validate_relay_url(relay_url)
    require(SHA40.fullmatch(tree_sha) is not None, "invalid tree SHA")
    require(binary.is_file() and not binary.is_symlink(), "missing release CLI")
    require(binary.stat().st_mode & stat.S_IXUSR, "release CLI is not executable")
    require(browser.is_dir() and not browser.is_symlink(), "missing browser artifact")
    require(not bundle.exists(), "bundle output must be new")
    bundle.mkdir(mode=0o700, parents=False)
    shutil.copy2(binary, bundle / "vhalla")
    (bundle / "vhalla").chmod(0o700)
    shutil.copy2(Path("Cargo.lock"), bundle / "lockfile")
    shutil.copytree(browser, bundle / "browser", symlinks=False)
    manifest_sha = digest(bundle / "browser" / "artifact.json", 65536)
    meta = dict(current, schema=BUNDLE_SCHEMA, tree_sha=tree_sha,
                binary_sha256=digest(bundle / "vhalla"),
                lock_sha256=digest(bundle / "lockfile"),
                browser_manifest_sha256=manifest_sha,
                controller_sha256=digest(CONTROLLER),
                iroh_relay_url=relay_url)
    write_json(bundle / "bundle.json", meta)
    bundle_identity(bundle)


def group_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def stop_group(pgid: int, grace: float = 15.0) -> tuple[bool, bool]:
    if not group_alive(pgid):
        return False, True
    sent = False
    for selected, wait_for in ((signal.SIGTERM, grace), (signal.SIGKILL, 10.0)):
        try:
            os.killpg(pgid, selected)
            sent = True
        except ProcessLookupError:
            return sent, True
        deadline = time.monotonic() + wait_for
        while time.monotonic() < deadline:
            if not group_alive(pgid):
                return sent, True
            time.sleep(0.05)
    return sent, not group_alive(pgid)


def wait_process(process: subprocess.Popen, timeout: float) -> int | None:
    try:
        return process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        stop_group(process.pid, min(timeout, 10.0))
        try:
            return process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            return None


class ServiceProcess:
    """Owned CLI process with a bounded readiness line and private logs."""
    def __init__(self, command: list[str], work: Path, label: str):
        self.command = command
        self.work = work
        self.label = label
        self.process: subprocess.Popen | None = None
        self.lines: queue.Queue[str] = queue.Queue()
        self.thread: threading.Thread | None = None

    def start(self, marker) -> None:
        stdout_path = self.work / f"{self.label}.stdout.log"
        stderr_path = self.work / f"{self.label}.stderr.log"
        stdout = stdout_path.open("wb")
        stderr = stderr_path.open("wb")
        try:
            self.process = subprocess.Popen(
                self.command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=stderr, env=selected_env(), start_new_session=True,
            )
        finally:
            stdout.close()
            stderr.close()
        require(self.process.stdout is not None, "owned service stdout unavailable")
        def pump():
            with stdout_path.open("ab") as sink:
                for raw in self.process.stdout:
                    sink.write(raw)
                    sink.flush()
                    try:
                        self.lines.put(raw.decode("utf-8", "replace"))
                    except Exception:
                        self.lines.put("")
        try:
            self.thread = threading.Thread(target=pump, daemon=True)
            self.thread.start()
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise ValueError(f"{self.label} exited before readiness")
                try:
                    line = self.lines.get(timeout=0.25)
                except queue.Empty:
                    continue
                try:
                    value = json.loads(line)
                except (TypeError, ValueError):
                    value = line.strip()
                if marker(value):
                    return
            raise TimeoutError(f"{self.label} readiness deadline")
        except Exception:
            self.stop()
            raise

    def stop(self) -> bool:
        if self.process is None:
            return True
        sent, cleared = stop_group(self.process.pid)
        try:
            self.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            cleared = False
        return cleared and (sent or self.process.returncode is not None)


def private_text(path: Path, maximum: int = 256) -> str:
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode)
            and 0 < metadata.st_size <= maximum, "private text file exceeds its bound")
    raw = path.read_bytes()
    require(len(raw) == metadata.st_size and 0 < len(raw) <= maximum,
            "private text file changed while being read")
    text = raw.decode("ascii")
    return text.strip()


def machine_commitment(nonce: str) -> str:
    boot = b""
    try:
        boot = Path("/proc/sys/kernel/random/boot_id").read_bytes()
    except OSError:
        pass
    return hashlib.sha256(nonce.encode() + boot + socket.gethostname().encode()).hexdigest()


def base_receipt(meta: dict, role: str, machine: str | None = None) -> dict:
    return dict(runtime_context(), schema=SCHEMA, role=role, passed=False,
                cleanup_confirmed=False, tree_sha=meta.get("tree_sha"),
                binary_sha256=meta.get("binary_sha256"), lock_sha256=meta.get("lock_sha256"),
                browser_manifest_sha256=meta.get("browser_manifest_sha256"),
                iroh_relay_url=DEFAULT_RELAY_URL, machine=machine,
                browser_qualified=False, direct_path_qualified=False,
                independent_nat_qualified=False, started_unix=int(time.time()))


def descriptor_from_home(meta: dict, work: Path, relay_url: str) -> dict:
    home = work / "host"
    config = read_json(home / "config.json")
    endpoint = config.get("iroh")
    require(isinstance(endpoint, dict) and set(endpoint) == {"endpoint_id", "relay_url", "addresses"},
            "host did not publish an exact Iroh endpoint")
    require(endpoint.get("relay_url") == relay_url, "host relay selection changed")
    namespace = config.get("namespace")
    token = private_text(home / "client-1.token", 65)
    require(HEX64.fullmatch(namespace or "") and HEX64.fullmatch(token or ""),
            "host descriptor secret shape is invalid")
    nonce = secrets.token_hex(32)
    return dict(runtime_context(), schema=SCHEMA, role="descriptor",
                tree_sha=meta["tree_sha"], binary_sha256=meta["binary_sha256"],
                lock_sha256=meta["lock_sha256"], browser_manifest_sha256=meta["browser_manifest_sha256"],
                iroh_relay_url=relay_url, endpoint=endpoint, namespace=namespace,
                upstream_token=token, host_machine=machine_commitment(nonce),
                descriptor_nonce=nonce, created_unix=int(time.time()))


def validate_descriptor(value: dict, meta: dict) -> None:
    require(value.get("schema") == SCHEMA and value.get("role") == "descriptor",
            "wrong host descriptor")
    for key in ("source_sha", "run_id", "run_attempt", "tree_sha", "binary_sha256",
                "lock_sha256", "browser_manifest_sha256"):
        require(value.get(key) == (meta.get(key) if key not in runtime_context() else runtime_context()[key]),
                "descriptor commitment differs")
    require(value.get("iroh_relay_url") == DEFAULT_RELAY_URL, "descriptor upstream differs")
    require(HEX64.fullmatch(value.get("namespace", "")) and HEX64.fullmatch(value.get("upstream_token", "")),
            "descriptor credential shape is invalid")
    endpoint = value.get("endpoint")
    require(isinstance(endpoint, dict) and set(endpoint) == {"endpoint_id", "relay_url", "addresses"},
            "descriptor endpoint is not canonical")
    require(endpoint["relay_url"] == DEFAULT_RELAY_URL, "descriptor relay is not selected upstream")
    require(isinstance(endpoint["addresses"], list) and len(endpoint["addresses"]) <= 16,
            "descriptor endpoint addresses exceed bound")
    require(HEX64.fullmatch(endpoint.get("endpoint_id", "")), "descriptor endpoint id is invalid")
    require(HEX64.fullmatch(value.get("host_machine", "")), "descriptor host identity is invalid")


def host_start(bundle: Path, work: Path, relay_url: str) -> None:
    work.mkdir(mode=0o700, parents=False, exist_ok=False)
    meta = None
    service = None
    receipt = {"schema": SCHEMA, "role": "host", "passed": False,
               "cleanup_confirmed": False, "browser_qualified": False,
               "direct_path_qualified": False, "independent_nat_qualified": False}
    write_json(work / "host-receipt.json", receipt)
    try:
        validate_relay_url(relay_url)
        meta = bundle_identity(bundle)
        machine = machine_commitment(secrets.token_hex(32))
        receipt = base_receipt(meta, "host", machine)
        receipt["cases"] = {case: False for case in HOST_CASES}
        write_json(work / "host-receipt.json", receipt)
        home = work / "host"
        command = [str(meta["binary"]), "private-host", "init", str(home),
                   "--transport", "iroh", "--iroh-bind", "0.0.0.0:0",
                   "--relay-url", relay_url, "--executable", str(meta["binary"])]
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=selected_env(), timeout=90, check=False)
        require(result.returncode == 0, "host initialization refused")
        descriptor = descriptor_from_home(meta, work, relay_url)
        service = ServiceProcess([str(meta["binary"]), "private-host", "serve", str(home)],
                                 work, "host-service")
        service.start(lambda value: isinstance(value, dict) and value.get("status") == "listening")
        write_json(work / "service.json", {"pid": service.process.pid, "pgid": service.process.pid,
                                            "home": str(home), "machine": machine})
        receipt["cases"]["host_ready"] = True
        write_json(work / "host-receipt.json", receipt)
        write_json(work / "descriptor.json", descriptor)
    except Exception:
        if service is not None:
            try:
                service.stop()
            except Exception:
                pass
        if (work / "service.json").exists():
            try:
                stop_owned_service(work)
            except Exception:
                pass
        raise


def read_service_record(work: Path) -> dict:
    value = read_json(work / "service.json", 8192)
    require(type(value.get("pid")) is int and value["pid"] > 1
            and value.get("pgid") == value["pid"], "invalid owned service record")
    require(isinstance(value.get("home"), str) and Path(value["home"]).is_absolute(),
            "invalid owned service home")
    return value


def owned_command(pid: int, home: str) -> bool:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ")
        return b"private-host" in raw and home.encode() in raw
    except OSError:
        return False


def stop_owned_service(work: Path) -> bool:
    try:
        record = read_service_record(work)
    except (OSError, ValueError):
        return True
    pid = record["pid"]
    if not group_alive(pid):
        return True
    require(owned_command(pid, record["home"]), "refusing to signal an unowned process")
    _, cleared = stop_group(pid)
    return cleared


def api_request(path: str, maximum: int = MAX_ARTIFACT_BYTES) -> bytes:
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GH_TOKEN", "")
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository), "invalid repository")
    require(token != "", "artifact polling token is unavailable")
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}/{path}",
        headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28"})
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    opener = urllib.request.build_opener(NoRedirect())
    try:
        response = opener.open(request, timeout=15)
    except urllib.error.HTTPError as error:
        if error.code != 302:
            raise
        destination = error.headers.get("Location")
        error.close()
        require(re.fullmatch(r"actions/artifacts/[1-9][0-9]*/zip", path),
                "unexpected artifact API redirect")
        require(destination is not None, "artifact redirect has no destination")
        parsed = urllib.parse.urlsplit(destination)
        require(parsed.scheme == "https" and parsed.username is None and parsed.password is None,
                "unsafe artifact redirect")
        require(parsed.hostname and any(parsed.hostname.endswith(suffix) for suffix in
                (".blob.core.windows.net", ".actions.githubusercontent.com", ".githubusercontent.com")),
                "unexpected artifact host")
        try:
            response = opener.open(urllib.request.Request(destination), timeout=15)
        except urllib.error.HTTPError as redirected:
            if 300 <= redirected.code < 400:
                redirected.close()
                raise ValueError("artifact download redirected twice") from None
            raise
    with response:
        raw = response.read(maximum + 1)
    require(len(raw) <= maximum, "artifact response exceeded bound")
    return raw


def inventory_artifact(name: str) -> int | None:
    found = None
    total = None
    identities = set()
    for page in range(1, 11):
        document = json.loads(api_request(
            f"actions/runs/{runtime_context()['run_id']}/artifacts?per_page=100&page={page}"))
        require(isinstance(document, dict) and isinstance(document.get("artifacts"), list),
                "invalid artifact inventory")
        count = document.get("total_count")
        entries = document["artifacts"]
        require(type(count) is int and count >= 0 and len(entries) <= 100,
                "invalid artifact inventory count")
        if total is None:
            total = count
        require(total == count, "artifact inventory changed during pagination")
        for entry in entries:
            identity = entry.get("id")
            require(type(identity) is int and identity > 0 and identity not in identities,
                    "duplicate artifact identity")
            identities.add(identity)
            if entry.get("name") == name and entry.get("expired") is False:
                require(found is None, "duplicate selected artifact")
                require(0 < entry.get("size_in_bytes", 0) <= MAX_ARTIFACT_BYTES,
                        "selected artifact exceeds bound")
                found = identity
        if len(entries) < 100:
            require(len(identities) == total, "incomplete artifact inventory")
            return found
    raise ValueError("artifact inventory exceeds page bound")


def unpack_receipt(raw: bytes) -> dict:
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        require(len(entries) == 1 and entries[0].filename == "client-receipt.json"
                and 0 < entries[0].file_size <= MAX_JSON, "unexpected client artifact shape")
        return json.loads(archive.read(entries[0]), object_pairs_hook=unique_pairs)


def poll_client(timeout: float) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            selected = inventory_artifact(artifact_name("client"))
            if selected is not None:
                return unpack_receipt(api_request(f"actions/artifacts/{selected}/zip"))
        except urllib.error.HTTPError as error:
            if error.code not in (404, 429, 500, 502, 503, 504):
                raise ValueError("artifact API refused polling") from None
        except (urllib.error.URLError, TimeoutError):
            pass
        time.sleep(min(5.0, max(0.1, deadline - time.monotonic())))
    raise TimeoutError("client receipt did not arrive before host deadline")


def matching_commitments(value: dict, meta: dict) -> bool:
    return all(value.get(key) == meta.get(key) for key in
               ("source_sha", "run_id", "run_attempt", "tree_sha", "binary_sha256",
                "lock_sha256", "browser_manifest_sha256"))


def validate_client(value: dict, meta: dict) -> None:
    require(value.get("schema") == SCHEMA and value.get("role") == "client",
            "foreign client receipt")
    require(matching_commitments(value, meta) and value.get("passed") is True,
            "client receipt commitment or result failed")
    require(value.get("cleanup_confirmed") is True and value.get("browser_qualified") is True,
            "browser/client cleanup or qualification failed")
    require(value.get("direct_path_qualified") is False
            and value.get("independent_nat_qualified") is False,
            "client made an unqualified topology claim")
    cases = value.get("cases", {})
    require(all(cases.get(case) is True for case in CLIENT_CASES),
            "client browser cases are incomplete")
    require(HEX64.fullmatch(value.get("machine", "")) is not None,
            "client machine commitment is invalid")
    require(value["machine"] != meta.get("host_machine"),
            "host and client runner commitments are not distinct")


def finish_host(work: Path, wait_for_client: bool) -> bool:
    receipt = read_json(work / "host-receipt.json")
    meta = {key: receipt.get(key) for key in
            ("source_sha", "run_id", "run_attempt", "tree_sha", "binary_sha256",
             "lock_sha256", "browser_manifest_sha256")}
    try:
        if wait_for_client:
            client = poll_client(600)
            meta["host_machine"] = receipt.get("machine")
            validate_client(client, meta)
            receipt["client_machine"] = client["machine"]
            receipt["client_verified"] = True
            receipt["cases"]["client_verified"] = True
            receipt["cases"]["exact_durable_records"] = True
    except Exception as error:
        receipt["error_class"] = type(error).__name__
        receipt["client_verified"] = False
    finally:
        try:
            stopped = stop_owned_service(work)
        except Exception as error:
            receipt["cleanup_error_class"] = type(error).__name__
            stopped = False
        receipt["cleanup_confirmed"] = stopped
        receipt.setdefault("cases", {})["host_stopped"] = stopped
        receipt["passed"] = (receipt.get("client_verified") is True and stopped
                              and all(receipt["cases"].get(case) is True for case in HOST_CASES))
        receipt["finished_unix"] = int(time.time())
        write_json(work / "host-receipt.json", receipt)
    return receipt["passed"]


def choose_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])
    finally:
        probe.close()


def canonical_frames(namespace: str) -> tuple[str, str, str]:
    require(HEX64.fullmatch(namespace) is not None, "invalid relay namespace")
    ns = bytes.fromhex(namespace)
    require(any(ns), "relay namespace must be nonzero")
    operation = bytes.fromhex("42" * 16)
    payload = b"synthetic browser Iroh ciphertext v1"
    kind = bytes([5])  # OutboxKind::Application.
    item_without_digest = (MAGIC + ns + (1).to_bytes(8, "big") + operation + kind
                           + len(payload).to_bytes(4, "big") + payload)
    item_digest = hashlib.sha256(DIGEST_DOMAIN + ns + (1).to_bytes(8, "big")
                                 + operation + kind + payload).digest()
    item = item_without_digest + item_digest
    put = (1 + len(item)).to_bytes(4, "big") + bytes([1]) + item
    page = (1 + (0).to_bytes(8, "big").__len__() + 2).to_bytes(4, "big") + bytes([2]) \
        + (0).to_bytes(8, "big") + (1).to_bytes(2, "big")
    return item.hex(), put.hex(), page.hex()


BROWSER_DRIVER = r'''import {spawn} from "node:child_process";
import {mkdtemp, mkdir, rm, writeFile} from "node:fs/promises";
import {join} from "node:path";
import {pathToFileURL} from "node:url";
import {request as httpRequest} from "node:http";

const [mode, origin, capability, namespace, itemHex, putHex, pageHex, output, toolsPath] = process.argv.slice(2);
if (!['healthy','offline','denied','retry'].includes(mode)) throw Error('unknown browser mode');
const tools = await import(pathToFileURL(toolsPath).href);
const browser = await tools.resolvePinnedBrowser();
const profile = await mkdtemp(join(output, 'profile-'));
let child, socket, sessionId, targetId, browserIdentity;
const pending = new Map(); let sequence = 0;
const logs = {value:''};
const cases = {};
const call = (method, params={}, session) => new Promise((resolve, reject) => {
  const id = ++sequence;
  const timer = setTimeout(() => { pending.delete(id); reject(Error('CDP timeout')); }, 30000);
  pending.set(id, {resolve: value => {clearTimeout(timer); resolve(value);}, reject: error => {clearTimeout(timer); reject(error);}});
  socket.send(JSON.stringify({id, method, params, ...(session ? {sessionId:session} : {})}));
});
const wait = async (test) => { const end=Date.now()+60000; for (;;) { if(await test()) return; if(Date.now()>end) throw Error('browser wait timeout'); await new Promise(r=>setTimeout(r,50)); } };
const hexBytes = hex => Uint8Array.from(hex.match(/../g).map(pair=>parseInt(pair,16)));
function parseFrame(raw) {
  if(raw.length<5) throw Error('short relay response');
  const length=new DataView(raw.buffer,raw.byteOffset,raw.byteLength).getUint32(0);
  if(length!==raw.length-4) throw Error('noncanonical relay response');
  return {http:200,status:raw[4],body:raw.slice(5)};
}
async function evaluate(expression) {
  const result=await call('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true},sessionId);
  if(result.exceptionDetails) throw Error('page evaluation failed');
  return result.result.value;
}
function rawWrongOrigin(body) {
  const url=new URL(origin);
  return new Promise((resolve,reject)=>{
    const req=httpRequest({hostname:url.hostname,port:Number(url.port),path:'/private-relay/v1',method:'POST',headers:{Host:url.host,Origin:'http://evil.invalid',Authorization:'Bearer '+capability,'X-Vhalla-Namespace':namespace,'Content-Type':'application/octet-stream','Content-Length':body.length}},res=>{const chunks=[];res.on('data',chunk=>chunks.push(chunk));res.on('end',()=>resolve({status:res.statusCode,body:Buffer.concat(chunks)}));});
    req.on('error',reject); req.setTimeout(10000,()=>{req.destroy();reject(Error('origin refusal timeout'));}); req.end(body);
  });
}
try {
  child=spawn(browser.executablePath,tools.requiredBrowserArgs(['--headless','--disable-gpu','--no-first-run','--no-default-browser-check','--disable-background-networking','--disable-component-update','--disable-default-apps','--disable-extensions','--disable-sync','--metrics-recording-only','--no-proxy-server','--remote-debugging-address=127.0.0.1','--remote-debugging-port=0','--user-data-dir='+profile,'about:blank']),{stdio:['ignore','pipe','pipe'],detached:true});
  await writeFile(join(output,'browser.pid'),String(child.pid)+'\n',{mode:0o600});
  for(const stream of [child.stdout,child.stderr]) stream.on('data',chunk=>{logs.value=(logs.value+chunk.toString()).slice(-65536);});
  await wait(()=>/DevTools listening on (ws:\/\/[^\s]+)/.test(logs.value)||child.exitCode!==null);
  if(child.exitCode!==null) throw Error('pinned browser exited');
  socket=new WebSocket(logs.value.match(/DevTools listening on (ws:\/\/[^\s]+)/)[1]);
  await new Promise((resolve,reject)=>{socket.onopen=resolve;socket.onerror=reject;});
  socket.onmessage=({data})=>{try{const value=JSON.parse(data);if(value.id){const waiter=pending.get(value.id);pending.delete(value.id);if(waiter)(value.error?waiter.reject(Error('CDP error')):waiter.resolve(value.result));}}catch{}};
  browserIdentity=await tools.verifyPinnedBrowser(call,browser,profile);
  ({targetId}=await call('Target.createTarget',{url:'about:blank'}));
  ({sessionId}=await call('Target.attachToTarget',{targetId,flatten:true}));
  await call('Page.enable',{},sessionId); await call('Runtime.enable',{},sessionId);
  await call('Page.navigate',{url:origin},sessionId);
  await wait(()=>evaluate("document.readyState==='complete'"));
  const item=hexBytes(itemHex), put=hexBytes(putHex), page=hexBytes(pageHex);
  const pageResult=await evaluate(`(async()=>{const r=await fetch('/',{cache:'no-store'});return {status:r.status,csp:r.headers.get('content-security-policy')||'',html:(await r.text()).length,origin:location.origin};})()`);
  cases.browser_origin=pageResult.origin===origin;
  cases.browser_manifest_loaded=pageResult.status===200 && pageResult.html>128 && pageResult.csp.includes("default-src 'none'");
  const putExpression=`(async()=>{try{const r=await fetch('/private-relay/v1',{method:'POST',headers:{'Authorization':'Bearer '+${JSON.stringify(capability)},'X-Vhalla-Namespace':${JSON.stringify(namespace)},'Content-Type':'application/octet-stream'},body:Uint8Array.from(${JSON.stringify([...put])})});return {http:r.status,raw:Array.from(new Uint8Array(await r.arrayBuffer()))};}catch{return {network:true};}})()`;
  const post=async body=>evaluate(put===body?putExpression:`(async()=>{try{const r=await fetch('/private-relay/v1',{method:'POST',headers:{'Authorization':'Bearer '+${JSON.stringify(capability)},'X-Vhalla-Namespace':${JSON.stringify(namespace)},'Content-Type':'application/octet-stream'},body:Uint8Array.from(${JSON.stringify([...body])})});return {http:r.status,raw:Array.from(new Uint8Array(await r.arrayBuffer()))};}catch{return {network:true};}})()`);
  const decode=value=>{if(value.network)return {network:true};const parsed=parseFrame(Uint8Array.from(value.raw));return parsed;};
  if(mode==='healthy'){
    const first=decode(await post(put)); const second=decode(await post(put));
    if(first.http!==200||first.status!==0||first.body.length!==41||second.status!==0||second.body.length!==41)throw Error('PUT refused');
    const dv1=new DataView(first.body.buffer,first.body.byteOffset,first.body.byteLength),dv2=new DataView(second.body.buffer,second.body.byteOffset,second.body.byteLength);
    cases.first_put=dv1.getUint8(40)===0 && dv1.getBigUint64(0)===1n;
    cases.exact_duplicate=dv2.getUint8(40)===1 && dv2.getBigUint64(0)===dv1.getBigUint64(0) && first.body.slice(8,40).every((v,i)=>v===second.body[8+i]);
    const pageRequest=hexBytes(pageHex); const pageValue=await evaluate(`(async()=>{try{const r=await fetch('/private-relay/v1',{method:'POST',headers:{'Authorization':'Bearer '+${JSON.stringify(capability)},'X-Vhalla-Namespace':${JSON.stringify(namespace)},'Content-Type':'application/octet-stream'},body:Uint8Array.from(${JSON.stringify([...page])})});return {http:r.status,raw:Array.from(new Uint8Array(await r.arrayBuffer()))};}catch{return {network:true};}})()`);
    const fetched=decode(pageValue); const body=fetched.body; const dv=new DataView(body.buffer,body.byteOffset,body.byteLength);
    const recordLength=body.length>=25?dv.getUint32(19):0; const record=body.slice(23,23+recordLength);
    cases.page_exact=fetched.http===200&&fetched.status===0&&body.length===23+item.length&&dv.getBigUint64(0)>=1n&&dv.getUint8(8)===0&&dv.getUint16(9)===1&&record.length===item.length&&record.every((v,i)=>v===item[i]);
    const wrongCap=await evaluate(`(async()=>{const r=await fetch('/private-relay/v1',{method:'POST',headers:{'Authorization':'Bearer '+${JSON.stringify('00'.repeat(32))},'X-Vhalla-Namespace':${JSON.stringify(namespace)},'Content-Type':'application/octet-stream'},body:Uint8Array.from(${JSON.stringify([...put])})});return r.status;})()`);
    cases.wrong_capability_refused=wrongCap===403;
    const wrongNamespace=await evaluate(`(async()=>{const r=await fetch('/private-relay/v1',{method:'POST',headers:{'Authorization':'Bearer '+${JSON.stringify(capability)},'X-Vhalla-Namespace':${JSON.stringify('00'.repeat(32))},'Content-Type':'application/octet-stream'},body:Uint8Array.from(${JSON.stringify([...put])})});return r.status;})()`);
    cases.wrong_namespace_refused=wrongNamespace===403;
    const originRefusal=await rawWrongOrigin(put); cases.wrong_origin_refused=originRefusal.status===403;
  } else if(mode==='offline') {
    const value=decode(await post(put)); cases.offline_refused=value.http===200&&value.status===7&&value.body.length===0;
  } else if(mode==='denied') {
    const value=decode(await post(put)); cases.upstream_token_refused=value.http===200&&value.status===6&&value.body.length===0;
  } else {
    const value=decode(await post(put));
    if(value.http!==200||value.status!==0||value.body.length!==41)throw Error('retry failed');
    cases.retry_duplicate=value.body[40]===1 && new DataView(value.body.buffer,value.body.byteOffset,value.body.byteLength).getBigUint64(0)===1n;
  }
  const expected=mode==='healthy'?['browser_origin','browser_manifest_loaded','first_put','exact_duplicate','page_exact','wrong_capability_refused','wrong_namespace_refused','wrong_origin_refused']:mode==='offline'?['browser_origin','browser_manifest_loaded','offline_refused']:mode==='denied'?['browser_origin','browser_manifest_loaded','upstream_token_refused']:['browser_origin','browser_manifest_loaded','retry_duplicate'];
  const passed=expected.every(name=>cases[name]===true);
  if(!passed)throw Error('browser case failed');
  const cleanup={browser:{version:browserIdentity.browserVersion},cases,passed:true,browser_qualified:true,direct_path_qualified:false,independent_nat_qualified:false,cleanup_confirmed:false};
  globalThis.__qualification=cleanup;
} catch(error) {
  globalThis.__qualification={cases,passed:false,browser_qualified:false,direct_path_qualified:false,independent_nat_qualified:false,error_class:error?.name||'Error'};
} finally {
  let graceful=false;
  if(child && socket && socket.readyState===1) { try { await tools.closePinnedBrowser(socket,child); graceful=true; } catch {} }
  const pid=child?.pid;
  const groupAlive=()=>{if(!pid)return false;try{process.kill(-pid,0);return true;}catch(error){if(error.code==='ESRCH')return false;return true;}};
  const signalGroup=signal=>{if(!pid)return;try{process.kill(-pid,signal);}catch(error){if(error.code!=='ESRCH'){} }};
  if(!graceful && child && child.exitCode===null) signalGroup('SIGTERM');
  let end=Date.now()+10000;
  while(child && child.exitCode===null && Date.now()<end) await new Promise(r=>setTimeout(r,25));
  if(child && child.exitCode===null) { signalGroup('SIGKILL'); end=Date.now()+5000; while(child.exitCode===null && Date.now()<end) await new Promise(r=>setTimeout(r,25)); }
  end=Date.now()+5000; while(groupAlive() && Date.now()<end) await new Promise(r=>setTimeout(r,25));
  const groupCleared=!groupAlive();
  for(const waiter of pending.values()) { try { waiter.reject(Error('browser qualification closing')); } catch {} }
  pending.clear();
  try { socket?.close(); } catch {}
  try { await rm(join(output,'browser.pid'),{force:true}); } catch {}
  let profileRemoved=false;
  if(groupCleared) { try { await rm(profile,{recursive:true,force:true}); profileRemoved=true; } catch {} }
  const stopped=child ? child.exitCode!==null : false;
  const cleanup=graceful&&stopped&&groupCleared&&profileRemoved;
  const result={schema:'valhalla.iroh-browser-browser.v1',mode,passed:globalThis.__qualification?.passed===true&&cleanup,cleanup_confirmed:cleanup,browser_qualified:globalThis.__qualification?.browser_qualified===true&&cleanup,direct_path_qualified:false,independent_nat_qualified:false,cases:globalThis.__qualification?.cases||{},browser:browserIdentity?{browserVersion:browserIdentity.browserVersion,playwrightVersion:browserIdentity.playwrightVersion}:null};
  await writeFile(join(output,'receipt.json'),JSON.stringify(result,null,2)+'\n',{mode:0o600});
  if(!result.passed)process.exitCode=1;
}
'''


def owned_browser_command(pid: int, output: Path) -> bool:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ")
        root = str(output.resolve()).encode()
        return (b"--headless" in raw
                and b"--remote-debugging-address=127.0.0.1" in raw
                and b"--user-data-dir=" + root + b"/profile-" in raw)
    except OSError:
        return False


def stop_timed_out_browser_driver(process: subprocess.Popen, output: Path) -> None:
    _, node_cleared = stop_group(process.pid, grace=10.0)
    browser_cleared = True
    pid_path = output / "browser.pid"
    if pid_path.exists() or pid_path.is_symlink():
        pid_text = private_text(pid_path, 32)
        require(POSITIVE.fullmatch(pid_text) is not None, "invalid owned browser pid")
        browser_pid = int(pid_text)
        if group_alive(browser_pid):
            require(owned_browser_command(browser_pid, output),
                    "refusing to signal an unowned browser")
            _, browser_cleared = stop_group(browser_pid, grace=10.0)
    require(node_cleared and browser_cleared, "browser driver cleanup deadline")
    shutil.rmtree(output, ignore_errors=True)
    require(not output.exists(), "browser profile cleanup failed")


def run_browser_driver(meta: dict, work: Path, mode: str, origin: str,
                       capability: str, namespace: str) -> dict:
    output = work / f"browser-{mode}-{secrets.token_hex(4)}"
    output.mkdir(mode=0o700)
    driver = work / "iroh-browser-driver.mjs"
    if not driver.exists():
        driver.write_text(BROWSER_DRIVER)
        driver.chmod(0o600)
    item, put, page = canonical_frames(namespace)
    command = ["node", str(driver), mode, origin, capability, namespace, item, put, page,
               str(output), str(Path("browser/tools/pinned_browser.mjs").resolve())]
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=selected_env(),
                               start_new_session=True)
    try:
        process.communicate(timeout=150)
    except subprocess.TimeoutExpired as timeout:
        try:
            stop_timed_out_browser_driver(process, output)
        finally:
            try:
                process.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        raise TimeoutError("browser driver deadline") from timeout
    result = process
    receipt = read_json(output / "receipt.json")
    serialized = json.dumps(receipt, sort_keys=True)
    require(capability not in serialized, "browser receipt disclosed its capability")
    require(receipt.get("cleanup_confirmed") is True, "browser cleanup was not confirmed")
    if result.returncode != 0 or receipt.get("passed") is not True:
        raise ValueError(f"browser {mode} qualification failed")
    return receipt


def gateway_config(work: Path, descriptor: dict, meta: dict, browser_token: Path,
                   upstream_token: Path, port: int, endpoint: dict | None = None) -> Path:
    selected_endpoint = endpoint if endpoint is not None else descriptor["endpoint"]
    config = {
        "format": 3, "listen": f"127.0.0.1:{port}", "namespace": descriptor["namespace"],
        "browser_token_file": str(browser_token),
        "upstream": {"transport": "iroh", "endpoint": selected_endpoint,
                     "token_file": str(upstream_token)},
        "assets_dir": str(meta["browser"]), "initial_cursor": "0",
    }
    path = work / "gateway.json"
    write_json(path, config)
    return path


def start_gateway(meta: dict, work: Path, config: Path) -> ServiceProcess:
    service = ServiceProcess([str(meta["binary"]), "private-gateway", "serve", str(config)],
                             work, "gateway-service")
    service.start(lambda value: isinstance(value, str) and value.startswith("private-gateway http://127.0.0.1:"))
    return service


def client_run(bundle: Path, descriptor_path: Path, work: Path) -> None:
    work.mkdir(mode=0o700, parents=False, exist_ok=False)
    meta = bundle_identity(bundle)
    descriptor = read_json(descriptor_path)
    validate_descriptor(descriptor, meta)
    machine = machine_commitment(secrets.token_hex(32))
    receipt = base_receipt(meta, "client", machine)
    receipt["host_machine"] = descriptor["host_machine"]
    receipt["cases"] = {case: False for case in CLIENT_CASES}
    write_json(work / "client-receipt.json", receipt)
    gateway = None
    browser_token = work / "browser.token"
    upstream_token = work / "upstream.token"
    try:
        capability = secrets.token_hex(32)
        browser_token.write_text(capability + "\n"); browser_token.chmod(0o600)
        upstream_token.write_text(descriptor["upstream_token"] + "\n"); upstream_token.chmod(0o600)
        port = choose_port()
        origin = f"http://127.0.0.1:{port}"
        config = gateway_config(work, descriptor, meta, browser_token, upstream_token, port)
        gateway = start_gateway(meta, work, config)
        healthy = run_browser_driver(meta, work, "healthy", origin, capability, descriptor["namespace"])
        for name in ("browser_origin", "browser_manifest_loaded", "first_put", "exact_duplicate",
                     "page_exact", "wrong_capability_refused", "wrong_namespace_refused",
                     "wrong_origin_refused"):
            receipt["cases"][name] = healthy["cases"].get(name) is True
        require(gateway.stop(), "healthy gateway cleanup failed")
        gateway = None

        offline_endpoint = {"endpoint_id": descriptor["endpoint"]["endpoint_id"],
                            "relay_url": None, "addresses": ["127.0.0.1:9"]}
        config = gateway_config(work, descriptor, meta, browser_token, upstream_token, port,
                                offline_endpoint)
        gateway = start_gateway(meta, work, config)
        offline = run_browser_driver(meta, work, "offline", origin, capability, descriptor["namespace"])
        receipt["cases"]["offline_refused"] = offline["cases"].get("offline_refused") is True
        require(gateway.stop(), "offline gateway cleanup failed")
        gateway = None
        config = gateway_config(work, descriptor, meta, browser_token, upstream_token, port)
        gateway = start_gateway(meta, work, config)
        retry = run_browser_driver(meta, work, "retry", origin, capability, descriptor["namespace"])
        receipt["cases"]["offline_retry_duplicate"] = retry["cases"].get("retry_duplicate") is True
        require(gateway.stop(), "offline retry gateway cleanup failed")
        gateway = None

        upstream_token.write_text("55" * 32 + "\n"); upstream_token.chmod(0o600)
        gateway = start_gateway(meta, work, config)
        denied = run_browser_driver(meta, work, "denied", origin, capability, descriptor["namespace"])
        receipt["cases"]["upstream_token_refused"] = denied["cases"].get("upstream_token_refused") is True
        require(gateway.stop(), "denied gateway cleanup failed")
        gateway = None
        upstream_token.write_text(descriptor["upstream_token"] + "\n"); upstream_token.chmod(0o600)
        gateway = start_gateway(meta, work, config)
        retry = run_browser_driver(meta, work, "retry", origin, capability, descriptor["namespace"])
        receipt["cases"]["upstream_retry_duplicate"] = retry["cases"].get("retry_duplicate") is True
        receipt["browser"] = healthy.get("browser")
        receipt["browser_qualified"] = all(receipt["cases"].values())
        receipt["passed"] = receipt["browser_qualified"]
    finally:
        try:
            gateway_clean = True if gateway is None else gateway.stop()
        except Exception as error:
            receipt["cleanup_error_class"] = type(error).__name__
            gateway_clean = False
        receipt["cleanup_confirmed"] = gateway_clean and all(
            bool(receipt["cases"].get(case)) for case in
            ("browser_origin", "browser_manifest_loaded", "first_put", "exact_duplicate",
             "page_exact", "wrong_capability_refused", "wrong_namespace_refused",
             "wrong_origin_refused", "offline_refused", "offline_retry_duplicate",
             "upstream_token_refused", "upstream_retry_duplicate"))
        receipt["passed"] = receipt.get("passed") is True and receipt["cleanup_confirmed"]
        receipt["finished_unix"] = int(time.time())
        for path in (browser_token, upstream_token):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        write_json(work / "client-receipt.json", receipt)


def validate_result(host: dict, client: dict) -> None:
    require(host.get("passed") is True and host.get("cleanup_confirmed") is True,
            "host qualification failed")
    require(client.get("passed") is True and client.get("cleanup_confirmed") is True,
            "client qualification failed")
    require(matching_commitments(host, client), "host/client commitments differ")
    require(client.get("browser_qualified") is True
            and client.get("direct_path_qualified") is False
            and client.get("independent_nat_qualified") is False,
            "result topology claims are invalid")
    require(host.get("cases", {}).get("exact_durable_records") is True,
            "host durable record case is missing")


def result_check(host_path: Path, client_path: Path) -> None:
    host = read_json(host_path)
    client = read_json(client_path)
    validate_result(host, client)
    print(json.dumps({"passed": True, "browser_qualified": True,
                      "direct_path_qualified": False, "independent_nat_qualified": False}))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    package = sub.add_parser("package")
    package.add_argument("--binary", type=Path, required=True)
    package.add_argument("--browser", type=Path, required=True)
    package.add_argument("--bundle", type=Path, required=True)
    package.add_argument("--tree-sha", required=True)
    package.add_argument("--relay-url", default=DEFAULT_RELAY_URL)
    host = sub.add_parser("host-start")
    host.add_argument("--bundle", type=Path, required=True)
    host.add_argument("--work", type=Path, required=True)
    host.add_argument("--relay-url", default=DEFAULT_RELAY_URL)
    wait = sub.add_parser("host-wait")
    wait.add_argument("--work", type=Path, required=True)
    stop = sub.add_parser("host-stop")
    stop.add_argument("--work", type=Path, required=True)
    client = sub.add_parser("client")
    client.add_argument("--bundle", type=Path, required=True)
    client.add_argument("--descriptor", type=Path, required=True)
    client.add_argument("--work", type=Path, required=True)
    result = sub.add_parser("result")
    result.add_argument("--host", type=Path, required=True)
    result.add_argument("--client", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "package":
        package_bundle(args.binary, args.browser, args.bundle, args.tree_sha, args.relay_url)
    elif args.command == "host-start":
        host_start(args.bundle, args.work, args.relay_url)
    elif args.command == "host-wait":
        return 0 if finish_host(args.work, True) else 1
    elif args.command == "host-stop":
        stopped = stop_owned_service(args.work)
        if (args.work / "host-receipt.json").exists():
            receipt = read_json(args.work / "host-receipt.json")
            receipt["cleanup_confirmed"] = stopped
            receipt.setdefault("cases", {})["host_stopped"] = stopped
            receipt["passed"] = receipt.get("passed") is True and stopped
            write_json(args.work / "host-receipt.json", receipt)
        return 0 if stopped else 1
    elif args.command == "client":
        client_run(args.bundle, args.descriptor, args.work)
        receipt = read_json(args.work / "client-receipt.json")
        return 0 if receipt.get("passed") is True else 1
    elif args.command == "result":
        result_check(args.host, args.client)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as failure:
        print(f"iroh browser qualification controller failed: {type(failure).__name__}", file=sys.stderr)
        sys.exit(1)
