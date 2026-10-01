"""Linux lifecycle and recovery contracts; never starts a real supervisor."""

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import headless_linux_managed_qualification as qualification


class FakeManager:
    def __init__(self):
        self.run = None
        self.loaded = self.active = False
        self.pid = 0
        self.starts = 0
        self.calls, self.probes = [], []
        self.fail_after_install = self.fail_uninstall = False
        self.foreign_fragment = self.unavailable = False
        self.drop_data = self.drop_log = self.change_config = False
        self.change_process = False
        self.messages = {"records": [{"body": "synthetic managed lifecycle message"}]}

    @staticmethod
    def reply(value):
        return 0, json.dumps({"ok": True, "result": value}).encode(), b""

    @staticmethod
    def refusal():
        return 1, b'{"ok":false,"error":{"code":"owner-unavailable"}}', b""

    def process(self, pid, binary, argv):
        assert binary == self.run.binary and argv == self.run.argv
        self.probes.append(pid)
        return pid, str(pid + len(self.probes) if self.change_process else pid)

    def service(self):
        return dict(installed=self.run.unit.exists(), loaded=self.loaded, unit_current=True,
                    unit_matches=True, unit=str(self.run.unit),
                    state="active/running" if self.active else "inactive/dead",
                    pid=self.pid if self.active else None, last_exit_code=0)

    def managed(self, **fields):
        return dict(managed=True, supported=True, supervisor="systemd", label=self.run.label,
                    home=str(self.run.home), executable=str(self.run.binary), service=self.service(), **fields)

    def __call__(self, argv, payload, env, timeout):
        self.calls.append(argv)
        assert 0 < timeout <= qualification.common.COMMAND_SECONDS
        if argv[0] == self.run.systemctl:
            assert argv[1] == "--user"
            action = argv[2]
            if action == "show":
                assert argv[3:] == [qualification.PROPERTIES, self.run.target]
                if self.unavailable:
                    return 1, b"", b"user manager is unavailable"
                fragment = "/foreign.service" if self.foreign_fragment else str(self.run.unit)
                fields = dict(LoadState="loaded" if self.loaded else "not-found",
                    ActiveState="active" if self.active else "inactive",
                    SubState="running" if self.active else "dead", MainPID=str(self.pid if self.active else 0),
                    ExecMainStatus="0", NRestarts="0", FragmentPath=fragment if self.loaded else "")
                return 0, "".join(f"{key}={value}\n" for key, value in fields.items()).encode(), b""
            if action == "disable":
                assert argv[3:] == ["--now", self.run.target]
                self.active = False
                self.run.enable_link.unlink(missing_ok=True)
            else:
                assert argv[2:] == ["daemon-reload"]
                self.loaded = self.run.unit.exists()
            return 0, b"", b""
        assert argv[:3] == [str(self.run.binary), "--no-update", "daemon"]
        assert argv[-2:] == ["--home", str(self.run.home)]
        action = argv[3]
        if action == "init":
            (self.run.home / "account").mkdir(parents=True, mode=0o700)
            (self.run.home / "account/identity").write_bytes(b"synthetic identity")
            return self.reply({"initialized": True})
        if action == "managed":
            selected = argv[4]
            if selected == "status":
                return self.reply(self.managed())
            if selected == "install":
                self.run.unit.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                if not self.run.unit.exists():
                    self.run.unit.write_bytes(self.run.expected_unit)
                    self.run.unit.chmod(0o600)
                self.run.enable_link.parent.mkdir(mode=0o700, exist_ok=True)
                if not self.run.enable_link.exists():
                    self.run.enable_link.symlink_to(self.run.unit)
                config = self.run.home / "managed-service.json"
                if not config.exists():
                    config.write_bytes(b"synthetic exact selection")
                elif self.change_config:
                    config.write_bytes(b"changed selection")
                (self.run.home / "supervisor.log").touch()
                self.starts += 1
                self.pid = 600 + self.starts
                self.loaded = self.active = True
                if self.fail_after_install:
                    raise InterruptedError("interrupted after unit enable")
                return self.reply(self.managed())
            assert selected == "uninstall"
            if self.fail_uninstall:
                return self.refusal()
            self.loaded = self.active = False
            self.run.enable_link.unlink(missing_ok=True)
            self.run.unit.unlink(missing_ok=True)
            if self.drop_data:
                (self.run.home / "retained-room-history").unlink(missing_ok=True)
            if self.drop_log:
                (self.run.home / "supervisor.log").unlink(missing_ok=True)
            return self.reply(self.managed(home_preserved=True, configuration_preserved=True,
                                           logs_preserved=True))
        if action == "status":
            return self.reply({"headless": True, "network": {"listening": True, "configured": {
                "bind": qualification.common.BIND, "relay_url": None, "relay_only": False}}})
        if action == "stop":
            self.active = False
            return self.reply({"stopping": True})
        assert action == "call"
        value = json.loads(payload)
        if value["op"] == "room.messages":
            return self.reply(self.messages)
        if value["op"] == "room.send":
            (self.run.home / "retained-room-history").write_bytes(b"synthetic durable history")
        return self.reply({"room": "11" * 16})


class LinuxManagedQualificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir="/tmp")
        self.root = Path(self.temp.name).resolve()
        self.context = patch.dict(os.environ, GITHUB_SHA="a" * 40, GITHUB_RUN_ID="123",
                                  GITHUB_RUN_ATTEMPT="2", GH_TOKEN="private-provider-token")
        self.context.start()
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        self.binary = self.bundle / "fixture"
        self.binary.write_bytes(b"synthetic candidate, never executed")
        self.binary.chmod(0o644)
        self.manifest = dict(schema=qualification.public.SCHEMA, source_sha="a" * 40,
            run_id="123", run_attempt="2", nonce="b" * 64,
            binary_sha256=qualification.digest(self.binary),
            lock_sha256=qualification.digest(Path("Cargo.lock")), features="headless", toolchain="1.98.1",
            target="x86_64-unknown-linux-gnu", build_profile="release",
            cargo_profile=dict(opt_level="3", debug_assertions=False, test=False))
        self.write_manifest()
        self.user = self.root / "user"
        self.user.mkdir(mode=0o700)
        self.runtime = self.root / "runtime"
        self.runtime.mkdir(mode=0o700)
        # Only the runtime socket type is mocked; production checks ownership
        # and 0700 directory mode. No real sockets or supervisor are started.
        (self.runtime / "bus").touch()
        self.socket_type = patch.object(qualification.stat, "S_ISSOCK", return_value=True)
        self.socket_type.start()
        self.machine = FakeManager()
        self.run = self.new_run()
        self.machine.run = self.run

    def tearDown(self):
        self.socket_type.stop()
        self.context.stop()
        self.temp.cleanup()

    def write_manifest(self):
        (self.bundle / "build.json").write_text(json.dumps(self.manifest))

    def new_run(self, work="work", restore=False):
        return qualification.LinuxRun(self.bundle, self.root / work, restore=restore,
            runner=self.machine, process_probe=self.machine.process, user_home=self.user, runtime=self.runtime)

    def installed(self):
        self.run.baseline_clear = True
        self.run.cli("init")
        info = self.run.home.stat()
        self.run.home_stamp = (info.st_dev, info.st_ino)
        self.run.phase = "install"
        self.run.cli("managed", "install", "--bind", qualification.common.BIND)
        self.run.capture_plist()

    def test_complete_journey_verifies_both_real_process_probes_and_safe_receipt(self):
        result = self.run.run()
        self.assertTrue(result["passed"], result)
        self.assertTrue(result["cleanup_confirmed"])
        self.assertTrue(all(result["cases"].values()))
        self.assertEqual(self.machine.probes, [601, 601, 602, 602])
        self.assertFalse(self.run.unit.exists())
        self.assertFalse(self.run.enable_link.is_symlink())
        self.assertTrue((self.run.home / "account/identity").exists())
        self.assertTrue((self.run.home / "retained-room-history").exists())
        text = (self.run.work / "receipt.json").read_text()
        for private in (str(self.run.home), str(self.binary), self.run.label, "synthetic identity",
                        "synthetic exact selection", "private-provider-token"):
            self.assertNotIn(private, text)
        self.assertEqual(set(self.run.env),
                         {"HOME", "PATH", "RUST_BACKTRACE", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"})
        self.assertEqual(self.run.env["HOME"], str(self.user))
        self.assertFalse(any("launchctl" in call[0] for call in self.machine.calls))

    def test_partial_install_interruption_cleans_exact_unit_and_preserves_home(self):
        self.machine.fail_after_install = True
        result = self.run.run()
        self.assertFalse(result["passed"])
        self.assertEqual(result["error_class"], "InterruptedError")
        self.assertTrue(result["cleanup_confirmed"])
        self.assertFalse(self.run.unit.exists())
        self.assertTrue((self.run.home / "account/identity").exists())
        saved = json.loads((self.run.work / "linux-ownership.json").read_text())
        self.assertTrue(saved["install_attempted"])
        self.assertTrue(saved["initially_absent"])

    def test_cli_refusal_falls_back_to_only_exact_owned_unit(self):
        self.machine.fail_uninstall = True
        result = self.run.run()
        self.assertFalse(result["passed"])
        self.assertTrue(result["cleanup_confirmed"], result)
        self.assertTrue(result["cleanup_fallback_used"])
        mutations = [call for call in self.machine.calls if call[0] == self.run.systemctl and call[2] != "show"]
        self.assertEqual(mutations, [[self.run.systemctl, "--user", "disable", "--now", self.run.target],
                                     [self.run.systemctl, "--user", "daemon-reload"]])

    def test_foreign_fragment_prevents_cleanup_commands(self):
        self.machine.fail_after_install = self.machine.foreign_fragment = True
        result = self.run.run()
        self.assertFalse(result["cleanup_confirmed"])
        self.assertTrue(self.run.unit.exists())
        self.assertFalse(any(call[2] == "disable" or call[3:5] == ["managed", "uninstall"]
                             for call in self.machine.calls))

    def test_changed_unit_prevents_production_or_fallback_removal(self):
        self.installed()
        self.run.unit.write_bytes(b"foreign unit\n")
        count = len(self.machine.calls)
        with self.assertRaises(ValueError):
            self.run.cleanup()
        self.assertTrue(self.run.unit.exists())
        self.assertFalse(any(call[2] == "disable" or call[3:5] == ["managed", "uninstall"]
                             for call in self.machine.calls[count:]))

    def test_symlink_or_identical_replacement_never_becomes_captured_authority(self):
        self.installed()
        retained = self.run.unit.with_suffix(".retained")
        self.run.unit.rename(retained)
        self.run.unit.symlink_to(retained)
        with self.assertRaises(OSError):
            self.run.cleanup()
        self.run.unit.unlink()
        self.run.unit.write_bytes(self.run.expected_unit)
        self.run.unit.chmod(0o600)
        with self.assertRaises(ValueError):
            self.run.cleanup()
        self.assertTrue(retained.exists())

    def test_existing_unit_is_not_adopted(self):
        self.run.unit.parent.mkdir(parents=True)
        self.run.unit.write_bytes(b"foreign")
        result = self.run.run()
        self.assertFalse(result["passed"])
        self.assertTrue(result["cleanup_confirmed"])
        self.assertEqual(self.run.unit.read_bytes(), b"foreign")
        self.assertFalse(self.machine.calls)

    def test_existing_dangling_enable_link_is_not_adopted(self):
        self.run.enable_link.parent.mkdir(parents=True)
        self.run.enable_link.symlink_to("/missing-foreign.service")
        result = self.run.run()
        self.assertFalse(result["passed"])
        self.assertTrue(self.run.enable_link.is_symlink())
        self.assertFalse(self.machine.calls)

    def test_unavailable_manager_never_means_absent(self):
        self.machine.unavailable = True
        result = self.run.run()
        self.assertFalse(result["passed"])
        self.assertFalse(self.run.install_attempted)
        self.assertFalse(self.run.home.exists())

    def test_ambiguous_or_incomplete_systemd_properties_refuse(self):
        for output in (b"LoadState=not-found\n", b"LoadState=not-found\nLoadState=not-found\n"):
            with self.subTest(output=output):
                self.run.runner = lambda *_args: (0, output, b"")
                with self.assertRaises(ValueError):
                    self.run.launch_state()

    def test_process_change_across_authenticated_rpc_fails(self):
        self.machine.change_process = True
        result = self.run.run()
        self.assertFalse(result["passed"])
        self.assertTrue(result["cleanup_confirmed"])
        self.assertFalse(result["cases"]["initial_process_verified"])

    def test_process_probe_failure_cannot_qualify(self):
        self.run.process_probe = lambda *_args: (_ for _ in ()).throw(ValueError("wrong executable"))
        result = self.run.run()
        self.assertFalse(result["passed"])
        self.assertTrue(result["cleanup_confirmed"])

    def test_missing_data_logs_or_changed_selection_fail(self):
        for field in ("drop_data", "drop_log", "change_config"):
            with self.subTest(field=field):
                self.machine = FakeManager()
                setattr(self.machine, field, True)
                self.run = self.new_run(work=field)
                self.machine.run = self.run
                result = self.run.run()
                self.assertFalse(result["passed"])
                self.assertTrue(result["cleanup_confirmed"], result)

    def test_bundle_provenance_profile_and_hash_refuse_before_work_mutation(self):
        original = dict(self.manifest)
        changes = dict(source_sha="c" * 40, run_id="456", run_attempt="1", lock_sha256="0" * 64,
                       binary_sha256="0" * 64, features="legacy", build_profile="debug",
                       cargo_profile={}, nonce="invalid")
        for key, value in changes.items():
            with self.subTest(key=key):
                self.manifest = original | {key: value}
                self.write_manifest()
                with self.assertRaises(ValueError):
                    self.new_run(work="refused")
                self.assertFalse((self.root / "refused").exists())

    def test_modified_candidate_is_never_executed(self):
        self.binary.chmod(0o700)
        with self.assertRaises(ValueError):
            self.run.cli("status")
        self.assertFalse(self.machine.calls)

    def test_durable_cleanup_restores_exact_ownership_without_upgrading_journey(self):
        self.installed()
        self.machine.fail_uninstall = True
        receipt = self.run.work / "receipt.json"
        qualification.common.write_json(receipt, {"passed": False, "interrupted": True})
        before = receipt.read_bytes()
        restored = self.new_run(restore=True)
        self.machine.run = restored
        self.assertTrue(restored.cleanup())
        self.assertFalse(restored.unit.exists())
        self.assertEqual(receipt.read_bytes(), before)
        self.assertTrue((restored.home / "account/identity").exists())

    def test_durable_record_cannot_redirect_cleanup(self):
        self.installed()
        path = self.run.work / "linux-ownership.json"
        saved = json.loads(path.read_text())
        for key, value in (("target", "unrelated.service"), ("home", "/foreign"),
                           ("binary_stamp", [0] * 8), ("work_identity", [0, 0])):
            with self.subTest(key=key):
                qualification.common.write_json(path, saved | {key: value})
                with self.assertRaises(ValueError):
                    self.new_run(restore=True)
        self.assertTrue(self.run.unit.exists())

    def test_failed_restore_never_writes_into_symlink_or_foreign_directory(self):
        foreign = self.root / "foreign"
        foreign.mkdir(mode=0o700)
        link = self.root / "linked-work"
        link.symlink_to(foreign)
        for path in (foreign, link):
            with self.subTest(path=path):
                result = qualification.recover(self.bundle, path, runner=self.machine,
                    process_probe=self.machine.process, user_home=self.user, runtime=self.runtime)
                self.assertFalse(result["cleanup_confirmed"])
                self.assertEqual(list(foreign.iterdir()), [])

    def test_receipt_write_revalidates_owned_directory(self):
        retained = self.root / "retained-work"
        self.run.work.rename(retained)
        self.run.work.mkdir(mode=0o700)
        with self.assertRaises(ValueError):
            self.run.write_cleanup_receipt({"cleanup_confirmed": True})
        self.assertEqual(list(self.run.work.iterdir()), [])

    def test_proc_reader_checks_exact_argv_executable_and_start_time(self):
        proc = self.root / "proc"
        process = proc / "99"
        process.mkdir(parents=True)
        (process / "exe").symlink_to(self.binary)
        (process / "stat").write_bytes(b"99 (test daemon) S " + b"0 " * 18 + b"12345 0\n")
        command = b"\0".join(os.fsencode(value) for value in self.run.argv) + b"\0"
        (process / "cmdline").write_bytes(command)
        self.assertEqual(qualification.process_identity(99, self.binary, self.run.argv, proc=proc), (99, "12345"))
        (process / "cmdline").write_bytes(command + b"--unexpected\0")
        with self.assertRaises(ValueError):
            qualification.process_identity(99, self.binary, self.run.argv, proc=proc)
        (process / "cmdline").write_bytes(command)
        (process / "exe").unlink()
        (process / "exe").symlink_to("/bin/sh")
        with self.assertRaises(ValueError):
            qualification.process_identity(99, self.binary, self.run.argv, proc=proc)


if __name__ == "__main__":
    unittest.main()
