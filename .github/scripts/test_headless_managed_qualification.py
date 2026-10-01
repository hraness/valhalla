"""Managed journey and exact-job failure cleanup; never invokes real launchd."""

import json
import os
from pathlib import Path
import plistlib
import signal
import sys
import tempfile
import unittest

import headless_managed_qualification as qualification


class FakeMachine:
    def __init__(self):
        self.run = None
        self.loaded = False
        self.running = False
        self.calls = []
        self.fail_after_install = False
        self.fail_uninstall = False
        self.change_config = False
        self.foreign_loaded_path = False
        self.last_exit = None
        self.messages = {"records": [{"body": "synthetic managed lifecycle message"}]}

    def reply(self, result):
        return 0, json.dumps({"ok": True, "result": result}).encode(), b""

    def refuse(self):
        return 1, b'{"ok":false,"error":{"code":"owner-unavailable"}}', b""

    def service(self):
        return dict(installed=self.run.plist.exists(), loaded=self.loaded, launch_agent_current=True,
                    state="running" if self.running else "not running", pid=765 if self.running else None,
                    last_exit_code=self.last_exit)

    def managed(self, **fields):
        return dict(managed=True, supported=True, supervisor="launchd", label=self.run.label,
                    home=str(self.run.home), executable=str(self.run.binary), service=self.service(), **fields)

    def __call__(self, argv, payload, env, timeout):
        self.calls.append(argv)
        if argv[0] == "/bin/launchctl":
            assert argv[2] == self.run.target
            if argv[1] == "bootout":
                self.loaded = self.running = False
                return 0, b"", b""
            assert argv[1] == "print"
            if self.loaded:
                path = "/foreign.plist" if self.foreign_loaded_path else str(self.run.plist)
                return 0, f"job = {{\n path = {path}\n}}\n".encode(), b""
            absent = f'Bad request.\nCould not find service "{self.run.label}" in domain for user gui: {os.geteuid()}\n'
            return 113, b"", absent.encode()
        assert argv[:3] == [str(self.run.binary), "--no-update", "daemon"]
        assert argv[-2:] == ["--home", str(self.run.home)]
        action = argv[3]
        if action == "init":
            self.run.home.mkdir(mode=0o700)
            (self.run.home / "account").mkdir(mode=0o700)
            (self.run.home / "account/identity").write_bytes(b"synthetic identity")
            return self.reply({"initialized": True})
        if action == "managed":
            selected = argv[4]
            if selected == "install":
                self.run.plist.parent.mkdir(parents=True, exist_ok=True)
                if not self.run.plist.exists():
                    self.run.plist.write_bytes(plistlib.dumps(self.run.expected_plist))
                    self.run.plist.chmod(0o600)
                config = self.run.home / "managed-service.json"
                if not config.exists():
                    config.write_bytes(b"synthetic exact selection")
                elif self.change_config:
                    config.write_bytes(b"changed selection")
                (self.run.home / "supervisor.log").touch()
                self.loaded = self.running = True
                if self.fail_after_install:
                    raise InterruptedError("synthetic interruption after bootstrap")
                return self.reply(self.managed())
            if selected == "status":
                return self.reply(self.managed())
            assert selected == "uninstall"
            if self.fail_uninstall:
                return self.refuse()
            self.loaded = self.running = False
            self.run.plist.unlink(missing_ok=True)
            return self.reply(self.managed(home_preserved=True, configuration_preserved=True, logs_preserved=True))
        if action == "status":
            return self.reply({"headless": True, "network": {"listening": True, "configured": {
                "bind": qualification.BIND, "relay_url": None, "relay_only": False}}})
        if action == "stop":
            self.running = False
            self.last_exit = 0
            return self.reply({"stopping": True})
        assert action == "call"
        value = json.loads(payload)
        if value["op"] == "room.messages":
            return self.reply(self.messages)
        if value["op"] == "room.send":
            (self.run.home / "retained-room-history").write_bytes(b"synthetic durable history")
        return self.reply({"room": "11" * 16})


class ManagedQualificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir="/tmp")
        self.root = Path(self.temp.name).resolve()
        self.binary = self.root / "vhalla"
        self.binary.write_bytes(b"synthetic candidate, never executed")
        self.binary.chmod(0o500)
        self.user = self.root / "user"
        self.user.mkdir(mode=0o700)
        self.machine = FakeMachine()
        self.run = qualification.ManagedRun(self.binary, qualification.digest(self.binary),
            self.root / "work", "a" * 40, runner=self.machine, user_home=self.user)
        self.machine.run = self.run

    def tearDown(self):
        self.temp.cleanup()

    def test_complete_journey_preserves_files_and_emits_only_safe_receipt(self):
        result = self.run.run()
        self.assertTrue(result["passed"], result)
        self.assertTrue(result["cleanup_confirmed"])
        self.assertFalse(result["cleanup_fallback_used"])
        self.assertTrue(all(result["cases"].values()))
        self.assertFalse(self.machine.loaded)
        self.assertFalse(self.run.plist.exists())
        self.assertEqual((self.run.home / "retained-room-history").read_bytes(), b"synthetic durable history")
        self.assertTrue((self.run.home / "managed-service.json").exists())
        text = (self.run.work / "receipt.json").read_text()
        for private in (str(self.run.home), str(self.binary), self.run.label, "synthetic identity", "synthetic exact selection"):
            self.assertNotIn(private, text)
        self.assertEqual(self.run.env["HOME"], str(self.user))
        self.assertEqual(set(self.run.env), {"HOME", "PATH", "RUST_BACKTRACE"})

    def test_interrupted_partial_install_still_uninstalls_exact_job(self):
        self.machine.fail_after_install = True
        result = self.run.run()
        self.assertFalse(result["passed"])
        self.assertEqual(result["failed_phase"], "install")
        self.assertEqual(result["error_class"], "InterruptedError")
        self.assertTrue(result["cleanup_confirmed"])
        self.assertFalse(self.machine.loaded)
        self.assertFalse(self.run.plist.exists())
        self.assertTrue((self.run.home / "account/identity").exists())

    def test_failed_cli_uninstall_uses_only_exact_owned_bootout(self):
        self.machine.fail_uninstall = True
        result = self.run.run()
        self.assertFalse(result["passed"])
        self.assertTrue(result["cleanup_confirmed"])
        self.assertTrue(result["cleanup_fallback_used"])
        bootouts = [value for value in self.machine.calls if value[:2] == ["/bin/launchctl", "bootout"]]
        self.assertEqual(bootouts, [["/bin/launchctl", "bootout", self.run.target]])
        self.assertFalse(self.run.plist.exists())

    def test_foreign_loaded_path_prevents_fallback_bootout(self):
        self.machine.fail_after_install = self.machine.fail_uninstall = True
        self.machine.foreign_loaded_path = True
        result = self.run.run()
        self.assertFalse(result["passed"])
        self.assertFalse(result["cleanup_confirmed"])
        self.assertTrue(self.run.plist.exists())
        self.assertFalse(any(call[1] == "bootout" for call in self.machine.calls))

    def test_changed_captured_plist_prevents_fallback(self):
        self.run.baseline_clear = self.run.install_attempted = True
        self.run.plist.parent.mkdir(parents=True)
        self.run.plist.write_bytes(plistlib.dumps(self.run.expected_plist))
        self.run.plist.chmod(0o600)
        self.run.capture_plist()
        self.run.plist.write_bytes(plistlib.dumps(self.run.expected_plist | {"RunAtLoad": False}))
        self.machine.loaded = self.machine.fail_uninstall = True
        with self.assertRaises(ValueError):
            self.run.cleanup()
        self.assertTrue(self.run.plist.exists())
        self.assertFalse(any(call[1] == "bootout" for call in self.machine.calls))

    def test_existing_plist_is_never_adopted_or_removed(self):
        self.run.plist.parent.mkdir(parents=True)
        self.run.plist.write_bytes(b"foreign")
        result = self.run.run()
        self.assertFalse(result["passed"])
        self.assertTrue(result["cleanup_confirmed"])
        self.assertEqual(self.run.plist.read_bytes(), b"foreign")
        self.assertFalse(self.machine.calls)

    def test_symlinked_or_replaced_identical_plist_is_not_cleanup_authority(self):
        self.run.plist.parent.mkdir(parents=True)
        raw = plistlib.dumps(self.run.expected_plist)
        self.run.plist.write_bytes(raw)
        self.run.plist.chmod(0o600)
        self.run.capture_plist()
        retained = self.run.plist.with_suffix(".retained")
        self.run.plist.rename(retained)
        self.run.plist.symlink_to(retained)
        with self.assertRaises(OSError):
            self.run.capture_plist()
        self.run.plist.unlink()
        self.run.plist.write_bytes(raw)
        self.run.plist.chmod(0o600)
        with self.assertRaises(ValueError):
            self.run.capture_plist()
        self.assertEqual(retained.read_bytes(), raw)

    def test_selection_change_on_reinstall_fails_but_cleans_job(self):
        self.machine.change_config = True
        result = self.run.run()
        self.assertFalse(result["passed"])
        self.assertEqual(result["failed_phase"], "reinstall")
        self.assertTrue(result["cleanup_confirmed"])

    def test_modified_candidate_is_never_executed(self):
        self.binary.chmod(0o700)
        with self.assertRaises(ValueError):
            self.run.cli("status")
        self.assertFalse(self.machine.calls)

    def test_launchd_unavailable_is_not_mistaken_for_absent(self):
        self.run.runner = lambda *_args: (113, b"", b"domain unavailable")
        with self.assertRaises(ValueError):
            self.run.launch_state()

    def test_pending_command_timeout_and_large_output_are_bounded(self):
        environment = {"PATH": "/usr/bin:/bin"}
        for source, deadline in (("import time; time.sleep(10)", 0.1),
                                 ("import sys; sys.stdout.write('x'*70000)", 5),
                                 ("import sys; sys.stderr.write('x'*70000)", 5)):
            with self.subTest(source=source), self.assertRaises((ValueError, TimeoutError)):
                qualification.run_command([sys.executable, "-c", source], b"", environment, deadline)

    def test_cleanup_temporarily_defers_interrupt_signals(self):
        before = signal.getsignal(signal.SIGTERM)
        with qualification.cleanup_signals():
            self.assertEqual(signal.getsignal(signal.SIGTERM), signal.SIG_IGN)
        self.assertEqual(signal.getsignal(signal.SIGTERM), before)


if __name__ == "__main__":
    unittest.main()
