"""MCP process adapter invariants; actual candidate execution is a separate run."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import headless_mcp_qualification as qualification


class FakeChild:
    pid = 987654321

    def __init__(self):
        self.returncode = None

    def poll(self):
        return self.returncode

    def wait(self, timeout):
        if self.returncode is None:
            raise subprocess.TimeoutExpired("synthetic daemon", timeout)
        return self.returncode


class FakeMachine:
    def __init__(self):
        self.child = FakeChild()
        self.run = None
        self.calls = []
        self.uses = 0
        self.leak = False
        self.duplicate = False
        self.no_stop = False
        self.bad_initialize = False
        self.room = {"room": "01" * 16, "pin": "02" * 32, "author": "03" * 32,
                     "policy": {"id": "04" * 32, "revision": 0}}
        self.grant = {"token": "05" * 32, "generation": "06" * 32}

    def start(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        return self.child

    def __call__(self, argv, payload, env, timeout):
        self.calls.append((argv, payload))
        if argv[1:] == ["--version"]:
            return 0, b"vhalla 0.3.0 features=[experimental-private]\n", b""
        action = argv[3]
        result = {}
        if action == "init":
            self.run.home.mkdir(mode=0o700)
            result = {"initialized": True}
        elif action == "status":
            result = {"headless": True, "network": {"listening": True,
                       "configured": {"relay_url": None, "relay_only": False}}}
        elif action == "stop":
            if not self.no_stop:
                self.child.returncode = 0
            result = {"stopping": True}
        elif action == "call":
            request = json.loads(payload)
            if request["op"] == "room.create":
                result = self.room
            elif request["op"] == "grant.issue":
                result = self.grant
            elif request["op"] == "room.messages":
                result = {"records": [{"body": qualification.MESSAGE}]}
        elif action == "mcp":
            output = []
            for line in payload.splitlines():
                request = json.loads(line)
                if request["method"] == "notifications/initialized":
                    continue
                if request["method"] == "initialize":
                    result = {"protocolVersion": qualification.INITIALIZE_PROTOCOL, "capabilities": {"tools": {}},
                              "serverInfo": {"name": "valhalla", "version": "wrong" if self.bad_initialize else "0.3.0"}}
                elif request["method"] == "tools/list":
                    result = {"tools": [{"name": name, "inputSchema": {
                        "additionalProperties": False, "properties": {}}} for name in qualification.TOOLS]}
                else:
                    self.uses += 1
                    data = {"room": self.room["room"]}
                    name = request["params"]["name"]
                    if self.uses > 5:
                        result = {"isError": True, "structuredContent": {"code": "permission-denied"}}
                    else:
                        if name == "agent.send":
                            data.update(operation=f"{3:032x}", frame_hash="07" * 32,
                                        exact_retry=self.uses == 3)
                        elif name == "agent.messages":
                            data["records"] = [{"text": qualification.MESSAGE}] * (2 if self.duplicate else 1)
                        elif name == "agent.outbox_status":
                            data["operations"] = [{"operation": f"{3:032x}", "frame_hash": "07" * 32}]
                        if self.leak:
                            data["leaked"] = self.grant["token"]
                        result = {"isError": False, "structuredContent": data}
                output.append(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}).encode() + b"\n")
            return 0, b"".join(output), b""
        return 0, json.dumps({"ok": True, "result": result}).encode(), b""


class McpQualificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir="/tmp")
        self.root = Path(self.temp.name).resolve()
        self.binary = self.root / "vhalla"
        self.binary.write_bytes(b"synthetic immutable candidate")
        self.binary.chmod(0o500)
        self.machine = FakeMachine()
        self.run = qualification.McpRun(self.binary, qualification.digest(self.binary),
            self.root / "work", "a" * 40, runner=self.machine, popen=self.machine.start)
        self.machine.run = self.run

    def tearDown(self):
        self.temp.cleanup()

    def test_complete_journey_joins_real_command_shape_and_sanitizes_receipt(self):
        result = self.run.run()
        self.assertTrue(result["passed"], result)
        self.assertTrue(result["cleanup_confirmed"])
        self.assertTrue(all(result["cases"].values()))
        self.assertEqual(self.machine.child.poll(), 0)
        commands = [argv for argv, _ in self.machine.calls if argv[1:] != ["--version"]]
        self.assertEqual(sum(argv[3] == "mcp" for argv in commands), 2)
        self.assertTrue(all(argv[:3] == [str(self.binary), "--no-update", "daemon"] for argv in commands))
        for argv, payload in self.machine.calls:
            if len(argv) > 3 and argv[3] == "mcp":
                frames = [json.loads(line) for line in payload.splitlines()]
                self.assertEqual([value["method"] for value in frames[:2]],
                                 ["initialize", "notifications/initialized"])
        text = (self.run.work / "receipt.json").read_text()
        for private in (str(self.run.home), str(self.binary), qualification.MESSAGE,
                        self.machine.grant["token"], self.machine.grant["generation"]):
            self.assertNotIn(private, text)
        self.assertEqual(self.run.grant_file.stat().st_mode & 0o777, 0o600)
        self.assertFalse((self.run.work / "diagnostic.json").exists())

    def test_credential_leak_fails_and_still_joins_daemon(self):
        self.machine.leak = True
        result = self.run.run()
        self.assertFalse(result["passed"])
        self.assertEqual(result["failed_phase"], "mcp_tools")
        self.assertTrue(result["cleanup_confirmed"])
        self.assertEqual(self.machine.child.poll(), 0)
        self.assertNotIn(self.machine.grant["token"], (self.run.work / "receipt.json").read_text())
        self.assertEqual((self.run.work / "diagnostic.json").stat().st_mode & 0o777, 0o600)

    def test_initialize_version_must_match_the_actual_candidate(self):
        self.machine.bad_initialize = True
        result = self.run.run()
        self.assertFalse(result["passed"])
        self.assertFalse(result["cases"]["initialize_handshake"])
        self.assertEqual(result["failed_phase"], "mcp_tools")
        self.assertTrue(result["cleanup_confirmed"])

    def test_duplicate_message_fails_actual_journey_validation(self):
        self.machine.duplicate = True
        result = self.run.run()
        self.assertFalse(result["passed"])
        self.assertTrue(result["cleanup_confirmed"])
        self.assertFalse(result["cases"]["granted_read"])

    def test_diagnostic_failure_cannot_skip_cleanup(self):
        self.machine.leak = True
        (self.run.work / "diagnostic.pending").write_bytes(b"preserved")
        result = self.run.run()
        self.assertFalse(result["passed"])
        self.assertEqual(result["diagnostic_error_class"], "FileExistsError")
        self.assertTrue(result["cleanup_confirmed"])
        self.assertEqual(self.machine.child.poll(), 0)

    def test_forced_cleanup_is_reported_and_never_counts_as_pass(self):
        self.machine.no_stop = True
        def stop(pid, _signal):
            self.assertEqual(pid, self.machine.child.pid)
            self.machine.child.returncode = -15
        with mock.patch.object(qualification.os, "killpg", side_effect=stop):
            result = self.run.run()
        self.assertFalse(result["passed"])
        self.assertTrue(result["cleanup_confirmed"])
        self.assertTrue(result["cleanup_fallback_used"])

    def test_changed_candidate_refuses_before_starting_any_process(self):
        self.binary.chmod(0o700)
        result = self.run.run()
        self.assertFalse(result["passed"])
        self.assertTrue(result["cleanup_confirmed"])
        self.assertEqual(self.machine.calls, [])

    def test_existing_work_directory_is_preserved_and_refused(self):
        with self.assertRaises(ValueError):
            qualification.McpRun(self.binary, qualification.digest(self.binary), self.run.work, "a" * 40)
        self.assertTrue(self.run.work.is_dir())

    def test_protocol_parser_rejects_noise_wrong_ids_and_unterminated_output(self):
        request = qualification.frame(1, "tools/list")
        good = b'{"jsonrpc":"2.0","id":1,"result":{}}\n'
        self.assertEqual(qualification.replies(good, [request]), [{}])
        for bad in (good.rstrip(), b"debug\n" + good, good.replace(b'"id":1', b'"id":2'),
                    good.replace(b'"result":{}', b'"error":{}')):
            with self.subTest(raw=bad), self.assertRaises(ValueError):
                qualification.replies(bad, [request])


if __name__ == "__main__":
    unittest.main()
