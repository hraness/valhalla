#!/usr/bin/env python3
"""Bounded macOS managed-daemon qualification using one fresh synthetic home.

Run only through the repository's mac-native lane, with a supplied read-only
candidate binary. This script never builds, updates, or deletes a daemon home.
It installs only the label derived from its NEW home, and always attempts to
remove that exact job, including after a failure or SIGINT/SIGTERM. SIGKILL or
machine loss cannot be cleaned up by an in-process finally block.

Example (the parent directory must already exist):
  python3 .github/scripts/headless_managed_qualification.py \
    --binary /absolute/immutable/vhalla --binary-sha256 HEX64 \
    --source-sha HEX40 --work /private/tmp/vhm-UNIQUE

Retain the work directory privately. Only receipt.json is suitable for sharing;
home, ownership.json, diagnostic.json, keys, managed selection and supervisor logs are private.
No relay, external peer, existing daemon home, or unrelated launchd job is used.
"""

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import selectors
import signal
import stat
import subprocess
import sys
import time

SCHEMA = "valhalla.headless-managed-macos.v1"
MAX_OUTPUT = 65536
COMMAND_SECONDS = 40
JOURNEY_SECONDS = 240
CLEANUP_SECONDS = 60
BIND = "127.0.0.1:0"
CASES = ("fresh_home", "installed", "running", "clean_stop", "same_selection_restarted",
         "history_survived_restart", "uninstalled", "durable_files_retained",
         "configuration_and_identity_unchanged", "logs_retained")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def write_json(path, value):
    # Every output is newly created within the task's private work directory.
    temporary = path.with_suffix(".pending")
    with temporary.open("x", encoding="utf-8") as output:
        os.chmod(temporary, 0o600)
        json.dump(value, output, sort_keys=True, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(path)


def run_command(argv, payload, env, timeout):
    """Bound both output pipes and lifetime; own the transient command's group."""
    require(len(payload) <= MAX_OUTPUT, "command input exceeds bound")
    child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=env, start_new_session=True)
    deadline = time.monotonic() + timeout
    result = {"out": bytearray(), "err": bytearray()}
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
                if time.monotonic() >= deadline:
                    raise TimeoutError("command deadline")
                for key, _ in selected.select(min(0.1, max(0, deadline - time.monotonic()))):
                    if key.data == "in":
                        offset += os.write(key.fd, payload[offset:offset + 4096])
                        if offset == len(payload):
                            selected.unregister(key.fileobj)
                            key.fileobj.close()
                    else:
                        block = os.read(key.fd, 4096)
                        if not block:
                            selected.unregister(key.fileobj)
                        else:
                            result[key.data].extend(block)
                            require(len(result[key.data]) <= MAX_OUTPUT, "command output exceeds bound")
        code = child.wait(timeout=max(0.01, deadline - time.monotonic()))
        return code, bytes(result["out"]), bytes(result["err"])
    finally:
        # launchd jobs are not members of this group. Their separate exact-label
        # cleanup remains mandatory even when this short-lived command failed.
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait(timeout=5)
        for stream in (child.stdin, child.stdout, child.stderr):
            stream.close()


@contextmanager
def cleanup_signals():
    saved = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        yield
    finally:
        for sig, handler in saved.items():
            signal.signal(sig, handler)


class Refusal(ValueError):
    def __init__(self, code):
        super().__init__("daemon returned a typed refusal")
        self.code = code


class ManagedRun:
    def __init__(self, binary, expected_digest, work, source_sha, *, runner=run_command,
                 user_home=None, clock=time.monotonic, sleep=time.sleep, progress=lambda _phase: None):
        require(re.fullmatch(r"[a-f0-9]{64}", expected_digest), "invalid binary digest")
        require(re.fullmatch(r"[a-f0-9]{40}", source_sha), "invalid source revision")
        require(binary.is_absolute() and not binary.is_symlink(), "binary must be an absolute regular file")
        self.binary = binary.resolve(strict=True)
        info = self.binary.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and info.st_nlink == 1 and info.st_mode & 0o6222 == 0
                and info.st_mode & 0o111 != 0, "candidate must be owned, read-only, executable and non-set-ID")
        self.binary_stamp = stamp(info)
        self.binary_digest = expected_digest
        require(digest(self.binary) == expected_digest, "candidate binary digest differs")
        require(work.is_absolute() and work.name not in ("", ".", "..")
                and not work.exists() and not work.is_symlink(), "work must be a new absolute directory")
        self.work = work.parent.resolve(strict=True) / work.name
        self.home = self.work / "home"
        require(len(os.fsencode(self.home / "control/admin.sock")) < 104, "synthetic home exceeds macOS socket bound")
        self.work.mkdir(mode=0o700)
        self.user_home = (user_home or Path(os.environ["HOME"])).resolve(strict=True)
        self.env = {"HOME": str(self.user_home), "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "RUST_BACKTRACE": "0"}
        # HOME is the real user's unchanged home, never the synthetic daemon home.
        value = b"valhalla/headless/managed/v1\0" + len(b"label").to_bytes(8, "big") + b"label"
        encoded = str(self.home).encode("utf-8")
        value += len(encoded).to_bytes(8, "big") + encoded
        self.label = "me.vhalla.daemon." + hashlib.sha256(value).hexdigest()
        self.target = f"gui/{os.geteuid()}/{self.label}"
        self.plist = self.user_home / "Library/LaunchAgents" / f"{self.label}.plist"
        self.expected_plist = {
            "Label": self.label,
            "ProgramArguments": [str(self.binary), "daemon", "run", "--home", str(self.home), "--bind", BIND],
            "RunAtLoad": True, "KeepAlive": {"SuccessfulExit": False}, "ThrottleInterval": 30,
            "ExitTimeOut": 15, "Umask": 63, "ProcessType": "Background", "AbandonProcessGroup": False,
            "StandardOutPath": str(self.home / "supervisor.log"),
            "StandardErrorPath": str(self.home / "supervisor.log"),
        }
        self.runner, self.clock, self.sleep, self.progress = runner, clock, sleep, progress
        self.deadline = clock() + JOURNEY_SECONDS
        self.phase = "preflight"
        self.install_attempted = False
        self.baseline_clear = False
        self.plist_stamp = None
        self.plist_bytes = None
        self.home_stamp = None
        self.last_command = None
        self.launchd_before_reinstall = None
        self.result = dict(schema=SCHEMA, source_sha=source_sha, binary_sha256=expected_digest,
                           runner_sha256=digest(Path(__file__)), platform="macOS launchd",
                           scope="one fresh synthetic home; loopback only", passed=False,
                           cleanup_confirmed=False, cleanup_fallback_used=False,
                           started_unix=int(time.time()), cases={name: False for name in CASES})
        write_json(self.work / "ownership.json", dict(home=str(self.home), binary=str(self.binary),
                   label=self.label, launch_agent=str(self.plist), target=self.target))

    def transition(self, phase):
        self.phase = phase
        self.progress(phase)

    def check_candidate(self, full=False):
        require(stamp(self.binary.lstat()) == self.binary_stamp, "candidate file changed")
        if full:
            require(digest(self.binary) == self.binary_digest, "candidate bytes changed")

    def command(self, argv, payload=b""):
        remaining = self.deadline - self.clock()
        if remaining <= 0:
            raise TimeoutError("qualification deadline")
        # Never capture stdin: calls can carry message text or credentials. The
        # bounded result is retained only on failure, in a private local file.
        self.last_command = {"argv": argv, "phase": self.phase}
        code, out, err = self.runner(argv, payload, self.env, min(COMMAND_SECONDS, remaining))
        self.last_command.update(exit_code=code, stdout=out.decode("utf-8", errors="replace"),
                                 stderr=err.decode("utf-8", errors="replace"))
        return code, out, err

    def cli(self, *action, request=None):
        self.check_candidate()
        payload = b"" if request is None else json.dumps(request, separators=(",", ":")).encode() + b"\n"
        code, raw, _stderr = self.command([str(self.binary), "--no-update", "daemon", *action,
                                         "--home", str(self.home)], payload)
        value = json.loads(raw)
        require(isinstance(value, dict), "invalid daemon result")
        if value.get("ok") is False and code != 0:
            raise Refusal(value.get("error", {}).get("code"))
        require(code == 0 and value.get("ok") is True and isinstance(value.get("result"), dict),
                "daemon command failed without a typed result")
        return value["result"]

    def call(self, op, **fields):
        return self.cli("call", request=dict(op=op, **fields))

    def launch_state(self):
        code, out, err = self.command(["/bin/launchctl", "print", self.target])
        absent = f'Bad request.\nCould not find service "{self.label}" in domain for user gui: {os.geteuid()}\n'.encode()
        if code == 113 and out == b"" and err == absent:
            return None
        require(code == 0, "launchd absence or ownership could not be verified")
        return out.decode("utf-8")

    def capture_plist(self):
        # No symlink ancestry or foreign file may become fallback authority.
        for directory in (self.user_home, self.user_home / "Library", self.plist.parent):
            info = directory.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                    and info.st_mode & 0o022 == 0, "unsafe LaunchAgents ancestry")
        descriptor = os.open(self.plist, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                    and info.st_nlink == 1 and info.st_mode & 0o7777 == 0o600
                    and info.st_size <= MAX_OUTPUT, "unsafe owned LaunchAgent")
            with os.fdopen(os.dup(descriptor), "rb") as selected:
                raw = selected.read(MAX_OUTPUT + 1)
            require(len(raw) <= MAX_OUTPUT and stamp(os.fstat(descriptor)) == stamp(info)
                    and stamp(self.plist.lstat()) == stamp(info), "LaunchAgent changed while reading")
        finally:
            os.close(descriptor)
        require(plistlib.loads(raw) == self.expected_plist, "LaunchAgent does not select this exact candidate/home")
        if self.plist_stamp is not None:
            require(stamp(info) == self.plist_stamp and raw == self.plist_bytes, "captured LaunchAgent changed")
        self.plist_stamp, self.plist_bytes = stamp(info), raw

    def managed_status(self):
        value = self.cli("managed", "status")
        require(value.get("managed") is True and value.get("supported") is True
                and value.get("supervisor") == "launchd" and value.get("label") == self.label
                and value.get("home") == str(self.home) and value.get("executable") == str(self.binary),
                "managed selection differs")
        return value["service"]

    def wait(self, predicate, seconds=40):
        until = min(self.deadline, self.clock() + seconds)
        while self.clock() < until:
            value = predicate()
            if value:
                return value
            self.sleep(min(0.2, max(0, until - self.clock())))
        raise TimeoutError("managed state deadline")

    def running(self):
        service = self.managed_status()
        require(service.get("installed") is True and service.get("loaded") is True
                and service.get("launch_agent_current") is True, "managed service is not installed and loaded")
        if not (type(service.get("pid")) is int and service["pid"] > 0):
            return False
        try:
            status = self.cli("status")
        except Refusal as failure:
            require(failure.code in ("owner-unavailable", "not-found"), "unexpected readiness refusal")
            return False
        network = status.get("network", {})
        configured = network.get("configured", {})
        require(status.get("headless") is True and network.get("listening") is True
                and configured.get("bind") == BIND and configured.get("relay_url") is None
                and configured.get("relay_only") is False, "daemon did not use loopback/no-relay selection")
        return True

    def stopped(self):
        service = self.managed_status()
        require(service.get("installed") is True and service.get("loaded") is True,
                "successful stop unexpectedly unloaded the job")
        return (service.get("state") == "not running" and service.get("pid") is None
                and service.get("last_exit_code") == 0)

    def retained_files(self):
        result = set()
        for parent, directories, files in os.walk(self.home, followlinks=False):
            relative = Path(parent).relative_to(self.home)
            if relative == Path("."):
                directories[:] = [name for name in directories if name != "control"]
            for name in directories:
                require(not (Path(parent) / name).is_symlink(), "unexpected retained directory symlink")
            for name in files:
                path = Path(parent) / name
                info = path.lstat()
                require(stat.S_ISREG(info.st_mode), "unexpected retained special file")
                if not name.startswith("supervisor.log") and not name.endswith(("-journal", "-wal", "-shm")):
                    result.add(str(path.relative_to(self.home)))
        return result

    def journey(self):
        require(not self.plist.exists() and not self.plist.is_symlink(), "selected label already has a plist")
        require(self.launch_state() is None, "selected label is already loaded")
        self.baseline_clear = True
        require(self.cli("init") == {"initialized": True}, "fresh initialization failed")
        self.home_stamp = (self.home.stat().st_dev, self.home.stat().st_ino)
        self.result["cases"]["fresh_home"] = True
        sentinel = self.home / "qualification-retained.txt"
        sentinel.write_bytes(b"synthetic retained user data\n")
        sentinel.chmod(0o600)
        self.transition("install")
        self.install_attempted = True  # A failing command can still have installed its job.
        self.cli("managed", "install", "--bind", BIND)
        self.capture_plist()
        self.result["cases"]["installed"] = True
        self.wait(self.running)
        self.result["cases"]["running"] = True
        room = "11" * 16
        self.call("room.create", operation=room, kind="public",
                  limits={"max_records": 2048, "max_record_bytes": 8 * 1024 * 1024})
        self.call("room.send", room=room, operation="22" * 16, body="synthetic managed lifecycle message")
        messages = self.call("room.messages", room=room, after=0, limit=8)
        exact = {name: digest(self.home / name) for name in
                 ("account/identity", "managed-service.json", sentinel.name)}
        self.transition("stop")
        self.cli("stop")
        self.wait(self.stopped)
        self.result["cases"]["clean_stop"] = True
        retained = self.retained_files()
        self.launchd_before_reinstall = self.launch_state()
        self.transition("reinstall")
        self.cli("managed", "install", "--bind", BIND)
        self.capture_plist()
        self.wait(self.running)
        require(digest(self.home / "managed-service.json") == exact["managed-service.json"],
                "reinstall changed the retained selection")
        self.result["cases"]["same_selection_restarted"] = True
        require(self.call("room.messages", room=room, after=0, limit=8) == messages,
                "reinstall changed retained room history")
        self.result["cases"]["history_survived_restart"] = True
        log = self.home / "supervisor.log"
        require(log.is_file() and not log.is_symlink() and log.stat().st_size <= MAX_OUTPUT,
                "expected bounded synthetic supervisor log")
        log_prefix = log.read_bytes()
        self.transition("uninstall")
        removed = self.cli("managed", "uninstall")
        require(all(removed.get(name) is True for name in
                    ("home_preserved", "configuration_preserved", "logs_preserved")),
                "uninstall did not report preservation")
        require(self.launch_state() is None and not self.plist.exists(), "uninstall left its job or plist")
        self.result["cases"]["uninstalled"] = True
        require((self.home.stat().st_dev, self.home.stat().st_ino) == self.home_stamp,
                "uninstall replaced the home")
        require(retained <= self.retained_files(), "uninstall removed durable files")
        self.result["cases"]["durable_files_retained"] = True
        require(all(digest(self.home / name) == checksum for name, checksum in exact.items()),
                "uninstall changed the identity, configuration or sentinel")
        self.result["cases"]["configuration_and_identity_unchanged"] = True
        require(log.is_file() and not log.is_symlink() and log.read_bytes().startswith(log_prefix),
                "uninstall removed prior supervisor log content")
        self.result["cases"]["logs_retained"] = True
        self.check_candidate(full=True)

    def cleanup(self):
        if not self.install_attempted:
            return True  # No supervisor mutation was attempted, including a foreign-label refusal.
        require(self.baseline_clear, "cleanup lacks an initially absent label")
        try:
            if self.launch_state() is None and not self.plist.exists() and not self.plist.is_symlink():
                return True
            self.cli("managed", "uninstall")
        except Exception:
            pass
        if self.launch_state() is None and not self.plist.exists() and not self.plist.is_symlink():
            return True
        self.result["cleanup_fallback_used"] = True
        # Fallback is for a partial install or a failed CLI, never a foreign or
        # changed plist. Revalidate immediately before each destructive action.
        self.capture_plist()
        observed = self.launch_state()
        if observed is not None:
            require(f"path = {self.plist}" in [line.strip() for line in observed.splitlines()],
                    "loaded job does not identify the exact owned plist")
            self.capture_plist()
            code, _out, _err = self.command(["/bin/launchctl", "bootout", self.target])
            require(code == 0, "exact owned job did not stop")
            self.wait(lambda: self.launch_state() is None, seconds=20)
        self.capture_plist()
        directory = os.open(self.plist.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            require((os.fstat(directory).st_dev, os.fstat(directory).st_ino)
                    == (self.plist.parent.lstat().st_dev, self.plist.parent.lstat().st_ino),
                    "LaunchAgents directory changed")
            require(stamp(os.stat(self.plist.name, dir_fd=directory, follow_symlinks=False)) == self.plist_stamp,
                    "captured LaunchAgent was replaced before removal")
            os.unlink(self.plist.name, dir_fd=directory)
            os.fsync(directory)
        finally:
            os.close(directory)
        return self.launch_state() is None and not self.plist.exists()

    def run(self):
        try:
            self.journey()
        except BaseException as failure:
            self.result.update(error_class=type(failure).__name__, failed_phase=self.phase)
            try:
                write_json(self.work / "diagnostic.json", {
                    "schema": "valhalla.headless-managed-private-diagnostic.v1",
                    "phase": self.phase, "error_class": type(failure).__name__,
                    "error_code": failure.code if isinstance(failure, Refusal) else None,
                    "error": str(failure), "command": self.last_command,
                    "launchd_before_reinstall": self.launchd_before_reinstall,
                })
            except BaseException as diagnostic_failure:
                # Failure to retain optional diagnostics must never skip the
                # exact-label cleanup or replace the original failure.
                self.result["diagnostic_error_class"] = type(diagnostic_failure).__name__
        finally:
            with cleanup_signals():
                self.deadline = self.clock() + CLEANUP_SECONDS
                try:
                    self.result["cleanup_confirmed"] = self.cleanup()
                except BaseException as failure:
                    self.result["cleanup_error_class"] = type(failure).__name__
                self.result["passed"] = ("error_class" not in self.result
                                         and self.result["cleanup_confirmed"] is True
                                         and all(self.result["cases"].values()))
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
    require(sys.platform == "darwin" and os.geteuid() != 0, "requires the real macOS GUI user")
    def interrupted(_signal, _frame):
        raise InterruptedError("qualification interrupted")
    for selected in (signal.SIGINT, signal.SIGTERM):
        signal.signal(selected, interrupted)
    run = ManagedRun(args.binary, args.binary_sha256, args.work, args.source_sha,
                     progress=lambda phase: print(f"managed qualification: {phase}", flush=True))
    result = run.run()
    print(json.dumps({name: result[name] for name in ("passed", "cleanup_confirmed", "cleanup_fallback_used")}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as failure:
        print(f"managed qualification refused before execution: {type(failure).__name__}", file=sys.stderr)
        sys.exit(1)
