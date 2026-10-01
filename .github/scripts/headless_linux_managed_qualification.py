#!/usr/bin/env python3
"""Exercise one fresh headless daemon under the real Linux systemd user manager.

Reuse this workflow's optimized binary bundle; never build or use an existing
daemon home. Only receipt.json and cleanup-receipt.json may be uploaded. Keep
the home, ownership, diagnostics, selection, identity and logs private.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time

import headless_managed_qualification as common
import headless_qualification as public
import iroh_qualification as controller

SCHEMA = "valhalla.headless-managed-linux.v1"
OWNERSHIP = "valhalla.headless-managed-linux-ownership.v1"
FIELDS = ("LoadState", "ActiveState", "SubState", "MainPID", "ExecMainStatus",
          "NRestarts", "FragmentPath")
PROPERTIES = "--property=" + ",".join(FIELDS)
require, digest, stamp = common.require, common.digest, common.stamp


def bounded_file(path, *, private=False):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and info.st_nlink == 1 and info.st_size <= common.MAX_OUTPUT,
                "expected bounded owned regular file")
        if private:
            require(info.st_mode & 0o7777 == 0o600, "expected owner-only file")
        with os.fdopen(os.dup(descriptor), "rb") as source:
            raw = source.read(common.MAX_OUTPUT + 1)
        require(len(raw) <= common.MAX_OUTPUT and stamp(os.fstat(descriptor)) == stamp(info)
                and stamp(path.lstat()) == stamp(info), "file changed while reading")
        return raw, stamp(info)
    finally:
        os.close(descriptor)


def bundle_identity(bundle, *, seal, lockfile=Path("Cargo.lock")):
    require(bundle.is_absolute() and not bundle.is_symlink(), "bundle must be an absolute directory")
    bundle = bundle.resolve(strict=True)
    manifest = json.loads(bounded_file(bundle / "build.json")[0])
    require(manifest.get("schema") == public.SCHEMA
            and all(manifest.get(k) == v for k, v in controller.context().items()),
            "foreign candidate source or workflow")
    require(manifest.get("features") == "headless" and manifest.get("toolchain") == "1.98.1"
            and manifest.get("target") == "x86_64-unknown-linux-gnu"
            and manifest.get("build_profile") == "release", "wrong candidate selection")
    profile = manifest.get("cargo_profile", {})
    require(isinstance(profile, dict) and profile.get("opt_level") == "3"
            and profile.get("debug_assertions") is False and profile.get("test") is False,
            "candidate is not an optimized release executable")
    require(re.fullmatch(r"[a-f0-9]{64}", manifest.get("nonce", ""))
            and manifest.get("lock_sha256") == digest(lockfile), "candidate lock or nonce differs")
    binary = bundle / "fixture"
    info = binary.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
            and info.st_mode & 0o6022 == 0, "unsafe candidate executable")
    require(digest(binary) == manifest.get("binary_sha256"), "candidate binary digest differs")
    # Artifact download loses execute permission. Seal only this owned copy,
    # after provenance/hash checks, and never change its bytes or rebuild it.
    if seal and info.st_mode & 0o777 != 0o500:
        descriptor = os.open(binary, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            require(stamp(os.fstat(descriptor)) == stamp(info), "candidate changed before sealing")
            os.fchmod(descriptor, 0o500)
        finally:
            os.close(descriptor)
    info = binary.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_mode & 0o7777 == 0o500,
            "candidate must remain read-only and executable")
    return binary, manifest, stamp(info)


def process_identity(pid, binary, argv, *, proc=Path("/proc")):
    """Bind systemd's MainPID to this executable, argv, UID and start time."""
    require(type(pid) is int and pid > 0, "invalid service PID")
    root = proc / str(pid)
    require(root.stat().st_uid == os.geteuid(), "service PID belongs to another user")
    before = (root / "stat").read_bytes()
    require(len(before) <= common.MAX_OUTPUT, "oversized process stat")
    fields = before.rsplit(b") ", 1)[1].split()
    require(len(fields) >= 20 and fields[19].isdigit(), "invalid process start time")
    require(os.readlink(root / "exe") == str(binary), "service executable path differs")
    executable = (root / "exe").stat()
    expected = binary.stat()
    require((executable.st_dev, executable.st_ino) == (expected.st_dev, expected.st_ino),
            "service executable identity differs")
    with (root / "cmdline").open("rb") as source:
        command = source.read(common.MAX_OUTPUT + 1)
    require(command == b"\0".join(os.fsencode(value) for value in argv) + b"\0",
            "service arguments differ")
    after = (root / "stat").read_bytes()
    require(after.rsplit(b") ", 1)[1].split()[19] == fields[19],
            "service PID was reused")
    return pid, fields[19].decode("ascii")


class LinuxRun(common.ManagedRun):
    """Reuse the bounded JSON/RPC journey; replace every launchd-specific hook."""

    def __init__(self, bundle, work, *, restore=False, runner=common.run_command,
                 user_home=None, runtime=None, process_probe=process_identity,
                 clock=time.monotonic, sleep=time.sleep, progress=lambda _phase: None):
        self.binary, self.manifest, self.binary_stamp = bundle_identity(bundle, seal=not restore)
        self.binary_digest = self.manifest["binary_sha256"]
        require(work.is_absolute() and not work.is_symlink() and work.name not in ("", ".", ".."),
                "work must be an absolute private directory")
        self.work = work.parent.resolve(strict=True) / work.name
        if not restore:
            require(not self.work.exists(), "work must be new")
            self.work.mkdir(mode=0o700)
        info = self.work.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                and info.st_mode & 0o7777 == 0o700, "unsafe work directory")
        self.work_identity = (info.st_dev, info.st_ino)
        self.home = self.work / "home"
        require(len(os.fsencode(self.home / "control/admin.sock")) < 104, "synthetic socket path too long")
        selected_home = user_home or Path(os.environ["HOME"])
        require(selected_home.is_absolute() and not selected_home.is_symlink(), "unsafe user home")
        self.user_home = selected_home.resolve(strict=True)
        runtime = runtime or Path(f"/run/user/{os.geteuid()}")
        info = runtime.lstat()
        bus = runtime / "bus"
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                and info.st_mode & 0o7777 == 0o700 and stat.S_ISSOCK(bus.lstat().st_mode)
                and bus.lstat().st_uid == os.geteuid(), "real user manager bus is unavailable")
        self.env = {"HOME": str(self.user_home), "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                    "RUST_BACKTRACE": "0", "XDG_RUNTIME_DIR": str(runtime),
                    "DBUS_SESSION_BUS_ADDRESS": f"unix:path={bus}"}
        encoded = str(self.home).encode("utf-8")
        self.label = "me.vhalla.daemon." + hashlib.sha256(
            b"valhalla/headless/managed/v1\0" + (5).to_bytes(8, "big") + b"label"
            + len(encoded).to_bytes(8, "big") + encoded).hexdigest()
        self.target = self.label + ".service"
        self.unit = self.user_home / ".config/systemd/user" / self.target
        self.enable_link = self.unit.parent / "default.target.wants" / self.target
        # The shared journey calls its supervisor file "plist"; no launchctl
        # method is reachable here. The alias is this one exact Linux unit.
        self.plist = self.unit
        self.argv = [str(self.binary), "daemon", "run", "--home", str(self.home),
                     "--bind", common.BIND]
        require(all(value and not any(ord(c) <= 32 or ord(c) == 127 or c in "%\"'\\;$"
                                     for c in value) for value in self.argv),
                "systemd arguments need exact unescaped paths")
        self.expected_unit = (
            "[Unit]\nDescription=Valhalla headless daemon\n\n[Service]\nType=simple\n"
            f"ExecStart={' '.join(self.argv)}\nRestart=on-failure\nRestartSec=30\n"
            "TimeoutStopSec=15\nUMask=0077\n"
            f"StandardOutput=append:{self.home}/supervisor.log\n"
            f"StandardError=append:{self.home}/supervisor.log\n\n"
            "[Install]\nWantedBy=default.target\n").encode()
        self.systemctl = next((path for path in ("/usr/bin/systemctl", "/bin/systemctl")
                               if Path(path).is_file()), "/usr/bin/systemctl")
        self.runner, self.clock, self.sleep, self.progress = runner, clock, sleep, progress
        self.process_probe = process_probe
        self.deadline = clock() + common.JOURNEY_SECONDS
        self.phase = "preflight"
        self.install_attempted = self.baseline_clear = False
        self.plist_stamp = self.plist_bytes = self.home_stamp = None
        self.last_command = self.launchd_before_reinstall = self.initial_process = None
        self.result = dict(schema=SCHEMA, **{key: self.manifest[key] for key in public.CONTEXT},
                           build_profile="release", platform="Linux systemd user",
                           runner_sha256=digest(Path(__file__)),
                           common_runner_sha256=digest(Path(common.__file__)),
                           scope="one fresh synthetic home; loopback only",
                           passed=False, cleanup_confirmed=False, cleanup_fallback_used=False,
                           started_unix=int(time.time()), cases={name: False for name in
                               (*common.CASES, "initial_process_verified", "resumed_process_verified",
                                "enable_link_removed")})
        if restore:
            saved = json.loads(bounded_file(self.work / "linux-ownership.json", private=True)[0])
            expected = self.ownership()
            require(set(saved) == set(expected), "unexpected cleanup ownership fields")
            for key in set(expected) - {"initially_absent", "install_attempted", "unit_stamp", "home_stamp"}:
                require(saved[key] == expected[key], "cleanup ownership selection differs")
            require(type(saved["initially_absent"]) is bool and type(saved["install_attempted"]) is bool,
                    "invalid cleanup mutation record")
            self.baseline_clear, self.install_attempted = saved["initially_absent"], saved["install_attempted"]
            for key in ("unit_stamp", "home_stamp"):
                value = saved[key]
                require(value is None or (isinstance(value, list) and all(type(n) is int for n in value)
                        and len(value) == (8 if key == "unit_stamp" else 2)), "invalid retained identity")
            self.home_stamp = tuple(saved["home_stamp"]) if saved["home_stamp"] is not None else None
            self.plist_stamp = tuple(saved["unit_stamp"]) if saved["unit_stamp"] is not None else None
            self.plist_bytes = self.expected_unit if self.plist_stamp is not None else None
            if self.install_attempted:
                info = self.home.lstat()
                require(self.baseline_clear and stat.S_ISDIR(info.st_mode)
                        and (info.st_dev, info.st_ino) == self.home_stamp, "cleanup home identity differs")
        else:
            self.persist()

    def ownership(self):
        return dict(schema=OWNERSHIP, **{key: self.manifest[key] for key in public.CONTEXT},
                    uid=os.geteuid(), work_identity=list(self.work_identity),
                    binary=str(self.binary), binary_stamp=list(self.binary_stamp),
                    home=str(self.home), user_home=str(self.user_home), unit=str(self.unit), target=self.target,
                    initially_absent=self.baseline_clear, install_attempted=self.install_attempted,
                    unit_stamp=list(self.plist_stamp) if self.plist_stamp is not None else None,
                    home_stamp=list(self.home_stamp) if self.home_stamp is not None else None)

    def persist(self):
        common.write_json(self.work / "linux-ownership.json", self.ownership())

    def write_cleanup_receipt(self, result):
        # Use the validated directory descriptor, never an untrusted recovery
        # argument after its ownership check has failed.
        directory = os.open(self.work, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(directory)
            require((info.st_dev, info.st_ino) == self.work_identity and info.st_uid == os.geteuid()
                    and info.st_mode & 0o7777 == 0o700, "cleanup receipt directory changed")
            descriptor = os.open("cleanup-receipt.pending", os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                 | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(descriptor, "w") as output:
                json.dump(result, output, sort_keys=True)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace("cleanup-receipt.pending", "cleanup-receipt.json",
                       src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            os.close(directory)

    def cli(self, *action, request=None):
        if action[:2] == ("managed", "install"):
            # Persist intent before even starting a command which may partially
            # install. The always-cleanup step can recover after controller loss.
            self.install_attempted = True
            self.persist()
        return super().cli(*action, request=request)

    def launch_state(self):
        code, out, _err = self.command([self.systemctl, "--user", "show", PROPERTIES, self.target])
        require(code == 0, "systemd manager did not prove the selected unit state")
        fields = {}
        for line in out.decode("utf-8").splitlines():
            key, value = line.split("=", 1)
            require(key in FIELDS and key not in fields, "ambiguous systemd state")
            fields[key] = value
        require(set(fields) == set(FIELDS) and fields["LoadState"] in ("loaded", "not-found"),
                "unrecognized systemd state")
        require(all(re.fullmatch(r"0|[1-9][0-9]*", fields[key]) for key in
                    ("MainPID", "ExecMainStatus", "NRestarts")), "invalid systemd process state")
        if fields["LoadState"] == "not-found":
            require(fields["ActiveState"] == "inactive" and fields["SubState"] == "dead"
                    and fields["MainPID"] == "0" and fields["FragmentPath"] == "",
                    "systemd absence is unverified")
            return None
        return fields

    def capture_plist(self):
        for directory in (self.user_home, self.user_home / ".config",
                          self.user_home / ".config/systemd", self.unit.parent):
            info = directory.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                    and info.st_mode & 0o022 == 0, "unsafe systemd user directory")
        raw, observed = bounded_file(self.unit, private=True)
        require(raw == self.expected_unit, "unit does not select the exact candidate and home")
        if self.plist_stamp is not None:
            require(observed == self.plist_stamp and raw == self.plist_bytes, "captured unit changed")
        else:
            self.plist_stamp, self.plist_bytes = observed, raw
            self.persist()
        if self.enable_link.exists() or self.enable_link.is_symlink():
            info = self.enable_link.parent.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                    and info.st_mode & 0o022 == 0 and self.enable_link.is_symlink()
                    and self.enable_link.lstat().st_uid == os.geteuid()
                    and self.enable_link.resolve(strict=True) == self.unit, "foreign enable link")

    def managed_status(self):
        value = self.cli("managed", "status")
        require(value.get("managed") is True and value.get("supported") is True
                and value.get("supervisor") == "systemd" and value.get("label") == self.label
                and value.get("home") == str(self.home) and value.get("executable") == str(self.binary),
                "managed selection differs")
        service = value["service"]
        require(service.get("installed") is True and service.get("loaded") is True
                and service.get("unit_current") is True and service.get("unit_matches") is True
                and service.get("unit") == str(self.unit), "managed unit is not installed and loaded")
        return service

    def running(self):
        service = self.managed_status()
        observed = self.launch_state()
        require(observed is not None and observed["FragmentPath"] == str(self.unit),
                "manager loaded a foreign unit")
        if observed["ActiveState"] != "active" or observed["SubState"] != "running":
            return False
        pid = int(observed["MainPID"])
        require(type(service.get("pid")) is int and service["pid"] == pid
                and observed["NRestarts"] == "0", "service PID or restarts differ")
        self.capture_plist()
        self.check_candidate()
        before = self.process_probe(pid, self.binary, self.argv)
        try:
            status = self.cli("status")
        except common.Refusal as failure:
            require(failure.code in ("owner-unavailable", "not-found"), "unexpected readiness refusal")
            return False
        network = status.get("network", {})
        configured = network.get("configured", {})
        require(status.get("headless") is True and network.get("listening") is True
                and configured.get("bind") == common.BIND and configured.get("relay_url") is None
                and configured.get("relay_only") is False, "daemon did not use loopback/no-relay selection")
        after = self.launch_state()
        require(after == observed and self.process_probe(pid, self.binary, self.argv) == before,
                "service process changed during authenticated readiness")
        if self.phase == "install":
            self.initial_process = before
            self.result["cases"]["initial_process_verified"] = True
        else:
            require(before != self.initial_process, "reinstall did not resume a new process")
            self.result["cases"]["resumed_process_verified"] = True
        return True

    def stopped(self):
        service = self.managed_status()
        observed = self.launch_state()
        require(observed is not None and observed["FragmentPath"] == str(self.unit),
                "stopped manager selection differs")
        return (service.get("state") == "inactive/dead" and service.get("pid") is None
                and service.get("last_exit_code") == 0 and observed["ActiveState"] == "inactive"
                and observed["SubState"] == "dead" and observed["MainPID"] == "0"
                and observed["ExecMainStatus"] == "0")

    def journey(self):
        require(not self.enable_link.exists() and not self.enable_link.is_symlink(),
                "selected label already has an enable link")
        super().journey()
        require(not self.enable_link.exists() and not self.enable_link.is_symlink(),
                "uninstall retained an enable link")
        self.result["cases"]["enable_link_removed"] = True

    def absent(self):
        return (self.launch_state() is None and not self.unit.exists() and not self.unit.is_symlink()
                and not self.enable_link.exists() and not self.enable_link.is_symlink())

    def cleanup(self):
        if not self.install_attempted:
            return True
        require(self.baseline_clear, "cleanup lacks an initially absent unit")
        if self.absent():
            return True
        # Do not even invoke the production remover on a replaced/foreign file.
        self.capture_plist()
        observed = self.launch_state()
        require(observed is None or observed["FragmentPath"] == str(self.unit),
                "cleanup refuses a foreign loaded fragment")
        try:
            self.cli("managed", "uninstall")
        except Exception:
            pass
        if self.absent():
            return True
        self.result["cleanup_fallback_used"] = True
        self.capture_plist()
        observed = self.launch_state()
        require(observed is None or observed["FragmentPath"] == str(self.unit),
                "fallback refuses a foreign loaded fragment")
        self.capture_plist()
        code, _out, _err = self.command([self.systemctl, "--user", "disable", "--now", self.target])
        require(code == 0, "exact owned unit did not disable")
        def stopped():
            value = self.launch_state()
            return value is None or (value["FragmentPath"] == str(self.unit)
                and value["ActiveState"] in ("inactive", "failed") and value["MainPID"] == "0")
        self.wait(stopped, seconds=20)
        require(not self.enable_link.exists() and not self.enable_link.is_symlink(), "enable link remains")
        self.capture_plist()
        directory = os.open(self.unit.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            require((os.fstat(directory).st_dev, os.fstat(directory).st_ino)
                    == (self.unit.parent.lstat().st_dev, self.unit.parent.lstat().st_ino),
                    "systemd user directory changed")
            require(stamp(os.stat(self.unit.name, dir_fd=directory, follow_symlinks=False)) == self.plist_stamp,
                    "captured unit was replaced before removal")
            os.unlink(self.unit.name, dir_fd=directory)
            os.fsync(directory)
        finally:
            os.close(directory)
        code, _out, _err = self.command([self.systemctl, "--user", "daemon-reload"])
        require(code == 0, "exact unit removal was not reloaded")
        return self.absent()


def recover(bundle, work, **options):
    result = dict(schema=SCHEMA, **controller.context(), cleanup_confirmed=False)
    with common.cleanup_signals():
        if not work.exists() and not work.is_symlink():
            return dict(result, cleanup_confirmed=True, no_install_attempted=True)
        run = None
        try:
            run = LinuxRun(bundle, work, restore=True, **options)
            run.deadline = run.clock() + common.CLEANUP_SECONDS
            result["cleanup_confirmed"] = run.cleanup()
            result["cleanup_fallback_used"] = run.result["cleanup_fallback_used"]
        except BaseException as failure:
            result["error_class"] = type(failure).__name__
        # No writes at all if the supplied directory/record could not be
        # validated. Recovery never changes or upgrades journey evidence.
        if run is not None:
            try:
                run.write_cleanup_receipt(result)
            except BaseException as failure:
                result.update(cleanup_confirmed=False, receipt_error_class=type(failure).__name__)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("run", "cleanup"))
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    require(sys.platform == "linux" and os.geteuid() != 0, "requires a non-root Linux user manager")
    def interrupted(_signal, _frame):
        raise InterruptedError("qualification interrupted")
    for selected in (signal.SIGINT, signal.SIGTERM):
        signal.signal(selected, interrupted)
    if args.action == "run":
        run = LinuxRun(args.bundle, args.work,
                       progress=lambda phase: print(f"Linux managed qualification: {phase}", flush=True))
        result = run.run()
        passed = result["passed"]
    else:
        result = recover(args.bundle, args.work)
        passed = result["cleanup_confirmed"]
    print(json.dumps({key: result[key] for key in ("passed", "cleanup_confirmed", "cleanup_fallback_used")
                      if key in result}))
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as failure:
        print(f"Linux managed qualification refused: {type(failure).__name__}", file=sys.stderr)
        sys.exit(1)
