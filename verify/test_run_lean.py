"""Admission regressions independent of installed Lean; real controls run in CI."""
import copy
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from run_lean import (
    CONTROLS, ROOT, EvidenceError, audit_result, check_snapshot, command, diagnostics,
    load_inputs, require_corpus, require_rejection, require_success, require_version, run_checks, select_archive,
)
from run_tlc import digest


def message(data, severity="information", **extra):
    return json.dumps({"severity": severity, "data": data, **extra}) + "\n"


def audit(**changes):
    result = {"module": "Quorum", "namespace": "Valhalla.Quorum", "declarations_audited": 12,
              "theorems": [{"name": "Valhalla.Quorum.checked", "axioms": ["propext", "Quot.sound"]}]}
    result.update(changes)
    return message("LEAN_AUDIT_OK " + json.dumps(result))


class LeanEvidenceTests(unittest.TestCase):
    def assess(self, output, code=0):
        return audit_result(code, output, "Quorum", "Valhalla.Quorum", ["checked"])

    def test_success_needs_completed_exact_inventory_and_allowed_axioms(self):
        self.assertEqual(self.assess(audit())["declarations_audited"], 12)
        for output, code in (
            (audit(), 1), (audit(), -9), ("", 0), (audit() + audit(), 0),
            (audit(theorems=[]), 0), (audit(module="Other"), 0),
            (audit(namespace="Other"), 0), (audit(declarations_audited=0), 0),
            (audit() + message("declaration uses `sorry`", "warning"), 0),
            (audit() + message("unexpected token", "error"), 0),
        ):
            with self.subTest(code=code, output=output), self.assertRaises(EvidenceError):
                self.assess(output, code)

    def test_sorry_custom_and_native_axioms_are_not_admitted(self):
        for axiom in ("sorryAx", "customAxiom", "checked._native.native_decide.ax_1", "Lean.trustCompiler"):
            with self.subTest(axiom=axiom), self.assertRaises(EvidenceError):
                self.assess(audit(theorems=[{"name": "Valhalla.Quorum.checked", "axioms": [axiom]}]))

    def test_duplicate_or_replaced_claims_and_axioms_are_rejected(self):
        for theorems in (
            [{"name": "Valhalla.Quorum.other", "axioms": []}],
            [{"name": "Valhalla.Quorum.checked", "axioms": []}] * 2,
            [{"name": "Valhalla.Quorum.checked", "axioms": ["propext", "propext"]}],
            [{"name": "Valhalla.Quorum.checked", "axioms": "propext"}],
        ):
            with self.subTest(theorems=theorems), self.assertRaises(EvidenceError):
                self.assess(audit(theorems=theorems))

    def test_nonzero_exit_and_diagnostic_errors_cannot_hide_behind_success_text(self):
        for code, output in ((1, ""), (-15, ""), (0, message("problem", "warning")),
                             (0, message("problem", "error")), (0, "good proof\n")):
            with self.subTest(code=code, output=output), self.assertRaises(EvidenceError):
                require_success(code, output)

    def test_malformed_or_duplicate_json_is_rejected(self):
        for output in ("[]\n", "null\n", '{"severity":"information","data":3}\n',
                       '{"severity":"information","severity":"error","data":"x"}\n'):
            with self.subTest(output=output), self.assertRaises(EvidenceError):
                diagnostics(output)

    def test_parser_error_is_not_wrong_proof_evidence(self):
        reason = CONTROLS["false-proof"][1]
        intended = "Tactic `decide` proved that the proposition\n  3 > 3\nis false"
        require_rejection(1, message(intended, "error"), reason)
        for code, output in ((0, message(intended, "error")), (-9, message(intended, "error")),
                             (1, message("unexpected token ':='; expected term", "error")),
                             (1, message(intended, "error") + message("other failure", "error")),
                             (1, message(intended, "error") + message("incomplete", "warning"))):
            with self.subTest(code=code, output=output), self.assertRaises(EvidenceError):
                require_rejection(code, output, reason)

    def test_wrong_negative_axiom_and_missing_claim_fail_for_named_reason(self):
        require_rejection(1, message("LEAN_AUDIT_FORBIDDEN_AXIOM sorryAx", "error"), CONTROLS["sorry"][1])
        require_rejection(1, message("LEAN_AUDIT_MISSING_THEOREM Valhalla.LeanControl.witness", "error"),
                          CONTROLS["missing-theorem"][1])
        with self.assertRaises(EvidenceError):
            require_rejection(1, message("LEAN_AUDIT_FORBIDDEN_AXIOM custom", "error"), CONTROLS["sorry"][1])

    def test_tool_version_commit_and_release_identity_are_checked(self):
        tools = {"version": "4.34.0", "commit": "a" * 40}
        version = "Lean (version 4.34.0, linux, commit " + "a" * 40 + ", Release)\n"
        require_version(0, version, tools)
        for code, reported in ((1, version), (0, version.replace("4.34.0", "4.33.0")),
                               (0, version.replace("a" * 40, "b" * 40)),
                               (0, version.replace("Release", "Debug"))):
            with self.subTest(code=code, reported=reported), self.assertRaises(EvidenceError):
                require_version(code, reported, tools)

    def test_fixture_mismatch_cannot_be_reused_as_current_proof_evidence(self):
        original = b'{"version":1,"cases":[{"accept":true}]}\n'
        require_corpus(original, original)
        for changed in (original.replace(b"true", b"false"), original + b"\n", b""):
            with self.subTest(changed=changed), self.assertRaisesRegex(EvidenceError, "fixture"):
                require_corpus(changed, original)


class LeanInputTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="valhalla-lean-test-")
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name)
        _, _, snapshot = load_inputs(ROOT)
        for name, data in snapshot.items():
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.snapshot = snapshot
        self.tools_path = self.repo / "verify/lean/tools.json"
        self.claims_path = self.repo / "verify/lean/claims.json"

    def test_unchanged_snapshot_has_every_proof_and_correspondence_input(self):
        _, _, snapshot = load_inputs(self.repo)
        self.assertEqual(snapshot, self.snapshot)
        for name in ("verify/lean/claims.json", "verify/lean/lean-toolchain", "verify/run_lean.py",
                     "crates/vhalla-rooms-node/src/cert.rs", "crates/vhalla-rooms-node/src/context/lean_quorum_tests.rs"):
            self.assertIn(name, snapshot)
        check_snapshot(self.repo, snapshot)

    def test_source_and_copied_source_drift_are_rejected(self):
        path = self.repo / "verify/lean/Quorum.lean"
        path.write_text(path.read_text() + "\n-- drift\n")
        with self.assertRaisesRegex(EvidenceError, "changed"):
            check_snapshot(self.repo, self.snapshot)

    def test_extra_lean_source_cannot_escape_inventory(self):
        (self.repo / "verify/lean/Unlisted.lean").write_text("import Std\n")
        with self.assertRaisesRegex(EvidenceError, "unlisted"):
            load_inputs(self.repo)

    def test_duplicate_and_missing_claim_inventory_is_rejected(self):
        claims = json.loads(self.claims_path.read_text())
        for names in ([], ["checked", "checked"], ["checked; malicious"], [True]):
            claims["theorems"] = names
            self.claims_path.write_text(json.dumps(claims))
            with self.subTest(names=names), self.assertRaises(EvidenceError):
                load_inputs(self.repo)

    def test_editor_toolchain_mismatch_is_rejected(self):
        (self.repo / "verify/lean/lean-toolchain").write_text("leanprover/lean4:v4.33.0\n")
        with self.assertRaisesRegex(EvidenceError, "lean-toolchain"):
            load_inputs(self.repo)

    def test_symlink_input_is_rejected(self):
        path = self.repo / "verify/lean/corpus.json"
        retained = self.repo / "outside.json"
        path.rename(retained)
        path.symlink_to(retained)
        with self.assertRaisesRegex(EvidenceError, "symlink"):
            load_inputs(self.repo)

    def test_wrong_archive_is_rejected_before_any_tool_execution_and_leaves_failure_receipt(self):
        archive = self.repo / "wrong.tar.zst"
        archive.write_bytes(b"not the pinned Lean archive")
        out = self.repo / "evidence"
        with patch("run_lean.subprocess.Popen") as run, redirect_stdout(io.StringIO()):
            self.assertEqual(run_checks(self.repo, archive, out), 1)
            run.assert_not_called()
        receipt = json.loads((out / "receipt.json").read_text())
        self.assertFalse(receipt["complete"])
        self.assertIn("digest", receipt["error"])

    def test_existing_evidence_is_never_overwritten(self):
        out = self.repo / "evidence"
        out.mkdir()
        marker = out / "receipt.json"
        marker.write_text("retain prior evidence\n")
        with self.assertRaises(FileExistsError):
            run_checks(self.repo, self.repo / "missing", out)
        self.assertEqual(marker.read_text(), "retain prior evidence\n")

    def test_unknown_platform_and_wrong_digest_cannot_admit_tool(self):
        tools = json.loads(self.tools_path.read_text())
        archive = self.repo / "wrong.tar.zst"
        archive.write_bytes(b"wrong")
        with self.assertRaisesRegex(EvidenceError, "unsupported"):
            select_archive(tools, archive, "alien", "machine")
        bad_pin = copy.deepcopy(tools)
        bad_pin["platforms"]["linux-x86_64"]["bytes"] = archive.stat().st_size
        with self.assertRaisesRegex(EvidenceError, "digest"):
            select_archive(bad_pin, archive, "Linux", "x86_64")


class LeanProcessTests(unittest.TestCase):
    def test_timeout_preserves_partial_log_and_cannot_count_as_completion(self):
        with tempfile.TemporaryDirectory(prefix="valhalla-lean-timeout-") as folder:
            root = Path(folder)
            log = root / "timeout.log"
            entry, output = command([sys.executable, "-u", "-c",
                "import time; print('partial evidence', flush=True); time.sleep(5)"], root, None, 1, log)
            self.assertIsNone(entry["exit_code"])
            self.assertEqual(entry["error"], "timeout")
            self.assertEqual(output, "partial evidence\n")
            self.assertEqual(entry["log_sha256"], digest(log))

    def test_timeout_terminates_the_owned_child_group(self):
        with tempfile.TemporaryDirectory(prefix="valhalla-lean-child-timeout-") as folder:
            root = Path(folder)
            script = ("import subprocess,sys,time; "
                      "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)']); "
                      "print(child.pid, flush=True); time.sleep(20)")
            started = time.monotonic()
            entry, output = command([sys.executable, "-u", "-c", script], root, None, 1, root / "child.log")
            self.assertLess(time.monotonic() - started, 5)
            self.assertEqual(entry["error"], "timeout")
            child = int(output.strip())

            def child_is_running():
                try:
                    os.kill(child, 0)
                except ProcessLookupError:
                    return False
                # Linux can briefly retain a killed grandchild as a zombie
                # until the container's init reaps it; it no longer executes.
                status = Path(f"/proc/{child}/stat")
                if status.exists():
                    return status.read_text().split(")", 1)[1].split()[0] != "Z"
                return True

            deadline = time.monotonic() + 2
            while child_is_running() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertFalse(child_is_running(), "timed-out decompressor analogue is still executing")


if __name__ == "__main__":
    unittest.main()
