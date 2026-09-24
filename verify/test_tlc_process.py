"""Black-box checks for the evidence runner; no Java/downloads are required."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


RUNNER = Path(__file__).with_name("run_tlc.py")
SUCCESS = """Model checking completed. No error has been found.
2 states generated, 2 distinct states found, 0 states left on queue.
Finished in 00s at (2026-09-23 00:00:00)
"""


class RunnerProcessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="valhalla-tlc-runner-")
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name)
        self.verify = self.repo / "verify"
        suite = self.verify / "probe"
        suite.mkdir(parents=True)
        shutil.copyfile(RUNNER, self.verify / "run_tlc.py")
        (suite / "Probe.tla").write_text(
            "---- MODULE Probe ----\nVARIABLE x\nInit == x = 0\n"
            "Next == x' = x\nSpec == Init /\\ [][Next]_x\nSafe == x = 0\n====\n"
        )
        (suite / "normal.cfg").write_text("SPECIFICATION Spec\nINVARIANT Safe\n")
        self.source = self.repo / "source.rs"
        self.source.write_text("fn admission() {}\n")
        manifest = {
            "schema_version": 1,
            "suites": [{
                "id": "probe", "module": "verify/probe/Probe.tla",
                "claim": "controlled runner boundary", "status": "implementation-correspondence",
                "bounds": "one variable", "assumptions": ["synthetic subprocess output"],
                "sources": [{"path": "source.rs", "symbols": ["admission"], "role": "production"}],
                "cases": [{"id": "normal", "config": "verify/probe/normal.cfg",
                           "expected": {"kind": "success"}}],
            }],
        }
        (self.verify / "cases.json").write_text(json.dumps(manifest))
        self.jar = self.repo / "fake.jar"
        self.jar.write_bytes(b"synthetic checker fixture, never executable Java\n")
        tools = {"tlc": {"version": "fixture", "sha256": hashlib.sha256(self.jar.read_bytes()).hexdigest()}}
        (self.verify / "tools.json").write_text(json.dumps(tools))
        self.java = self.repo / "fake-java"
        self.java.write_text(
            f"#!{sys.executable}\n"
            "from pathlib import Path\nimport sys, time\n"
            "root = Path(__file__).parent\n"
            "if sys.argv[1:] == ['-version']:\n"
            "    print('synthetic Java for runner tests')\n    sys.exit(0)\n"
            "mode = (root / 'mode').read_text()\n"
            "model = Path(sys.argv[-1])\n"
            "assert 'inputs' in model.parts, 'checker must consume copied inputs'\n"
            "if mode == 'source-drift':\n"
            "    (root / 'source.rs').write_text('fn changed_during_check() {}\\n')\n"
            "if mode == 'model-drift':\n"
            "    (root / 'verify/probe/Probe.tla').write_text(model.read_text() + '\\* changed\\n')\n"
            "if mode == 'copied-model-drift':\n"
            "    model.chmod(0o600)\n"
            "    model.write_text(model.read_text() + '\\* changed after copy\\n')\n"
            "if mode == 'runner-drift':\n"
            "    runner = root / 'verify/run_tlc.py'\n"
            "    runner.write_text(runner.read_text() + '# changed while checking\\n')\n"
            f"print({SUCCESS!r}, end='', flush=True)\n"
            "if mode == 'timeout':\n    time.sleep(10)\n"
        )
        self.java.chmod(0o700)
        (self.repo / "mode").write_text("success")
        self.out = self.repo / "evidence"

    def run_cli(self, mode="success", **overrides):
        (self.repo / "mode").write_text(mode)
        options = {"java": str(self.java), "jar": str(self.jar), "out": str(self.out), "timeout": "1"}
        options.update(overrides)
        command = [sys.executable, str(self.verify / "run_tlc.py")]
        for key, value in options.items():
            command.extend([f"--{key}", value])
        return subprocess.run(command, capture_output=True, text=True, timeout=20, check=False)

    def receipt(self):
        return json.loads((self.out / "receipt.json").read_text())

    def test_success_attests_consumed_inputs_command_and_log(self):
        result = self.run_cli()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        receipt = self.receipt()
        self.assertTrue(receipt["complete"])
        self.assertEqual(receipt["verdict"], "pass")
        self.assertEqual(receipt["inputs_sha256"], receipt["inputs_after_sha256"])
        for name in ("verify/run_tlc.py", "verify/cases.json", "verify/tools.json", "source.rs"):
            self.assertEqual(receipt["inputs_sha256"][name], hashlib.sha256((self.repo / name).read_bytes()).hexdigest())
        self.assertEqual(receipt["expected_cases"], 1)
        case, = receipt["cases"]
        self.assertEqual(case["command"][case["command"].index("-workers") + 1], "1")
        self.assertGreaterEqual(case["elapsed_seconds"], 0)
        log = self.out / "probe/normal/tlc.log"
        self.assertEqual(case["log_sha256"], hashlib.sha256(log.read_bytes()).hexdigest())
        self.assertEqual((self.out / "inputs/verify/probe/Probe.tla").read_bytes(),
                         (self.verify / "probe/Probe.tla").read_bytes())

    def test_timeout_cannot_reuse_success_text_printed_before_hang(self):
        result = self.run_cli("timeout")
        self.assertNotEqual(result.returncode, 0)
        receipt = self.receipt()
        self.assertFalse(receipt["complete"])
        self.assertEqual(receipt["verdict"], "fail")
        self.assertEqual(receipt["cases"][0]["verdict"], "inconclusive")
        self.assertIn("Model checking completed.", (self.out / "probe/normal/tlc.log").read_text())

    def test_missing_runtime_retains_incomplete_receipt(self):
        result = self.run_cli(java=str(self.repo / "not-installed"))
        self.assertNotEqual(result.returncode, 0)
        receipt = self.receipt()
        self.assertFalse(receipt["complete"])
        self.assertEqual(receipt["verdict"], "fail")
        self.assertEqual(receipt["cases"], [])
        self.assertTrue(receipt["error"])

    def test_wrong_checker_digest_is_rejected_before_execution(self):
        self.jar.write_bytes(b"changed fixture")
        result = self.run_cli()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("digest", result.stderr)
        self.assertFalse(self.out.exists())

    def test_existing_evidence_is_never_overwritten(self):
        self.out.mkdir()
        marker = self.out / "receipt.json"
        marker.write_text("retained previous evidence\n")
        result = self.run_cli()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(marker.read_text(), "retained previous evidence\n")

    def test_changed_production_source_invalidates_an_otherwise_successful_run(self):
        result = self.run_cli("source-drift")
        self.assertNotEqual(result.returncode, 0)
        receipt = self.receipt()
        self.assertEqual(receipt["cases"][0]["verdict"], "pass")
        self.assertFalse(receipt["complete"])
        self.assertEqual(receipt["verdict"], "fail")
        self.assertIn("changed", receipt["error"])

    def test_changed_model_is_rejected_but_consumed_snapshot_survives(self):
        before = (self.verify / "probe/Probe.tla").read_bytes()
        result = self.run_cli("model-drift")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.receipt()["complete"])
        self.assertEqual((self.out / "inputs/verify/probe/Probe.tla").read_bytes(), before)

    def test_changed_runner_invalidates_its_receipt(self):
        result = self.run_cli("runner-drift")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.receipt()["complete"])
        self.assertIn("changed", self.receipt()["error"])

    def test_changed_consumed_model_copy_invalidates_its_receipt(self):
        original = (self.verify / "probe/Probe.tla").read_bytes()
        result = self.run_cli("copied-model-drift")
        self.assertNotEqual(result.returncode, 0)
        receipt = self.receipt()
        self.assertFalse(receipt["complete"])
        self.assertEqual(receipt["verdict"], "fail")
        self.assertEqual((self.verify / "probe/Probe.tla").read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
