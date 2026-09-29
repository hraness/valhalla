"""Fail-closed artifact selection, evidence and cleanup for iroh runner tests."""
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch
import warnings
import zipfile

import iroh_qualification as qualification


class QualificationTests(unittest.TestCase):
    def expected(self):
        return dict(source_sha="a" * 40, run_id="100", run_attempt="2", nonce="b" * 64,
                    binary_sha256="c" * 64, lock_sha256="d" * 64, machine="e" * 64)

    def client(self):
        value = self.expected() | dict(schema=qualification.SCHEMA, role="client", passed=True,
                                      cleanup_confirmed=True, machine="f" * 64)
        value["cases"] = {case: True for case in qualification.CLIENT_CASES}
        value["cases"]["host_machine"] = self.expected()["machine"]
        return value

    def test_only_matching_complete_distinct_runner_receipts_pass(self):
        qualification.validate_client(self.client(), self.expected())
        for change in ({"source_sha": "1" * 40}, {"run_attempt": "1"}, {"nonce": "2" * 64},
                       {"binary_sha256": "3" * 64}, {"lock_sha256": "4" * 64},
                       {"machine": "e" * 64}, {"machine": "not-a-hash"},
                       {"passed": 1}, {"cleanup_confirmed": False}, {"role": "host"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                qualification.validate_client(self.client() | change, self.expected())
        for case in qualification.CLIENT_CASES + ("host_machine",):
            value = self.client()
            del value["cases"][case]
            with self.subTest(missing=case), self.assertRaises(ValueError):
                qualification.validate_client(value, self.expected())

    def test_selection_refuses_duplicate_expired_or_oversized_artifacts(self):
        entry = dict(name="selected", id=17, expired=False, size_in_bytes=512)
        self.assertEqual(qualification.select_artifact({"artifacts": [entry]}, "selected"), 17)
        self.assertIsNone(qualification.select_artifact({"artifacts": [entry]}, "other"))
        self.assertIsNone(qualification.select_artifact({"artifacts": [entry | {"expired": True}]}, "selected"))
        for entries in ([entry, entry], [entry | {"id": True}],
                        [entry | {"size_in_bytes": 2 * 1024 * 1024}]):
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                qualification.select_artifact({"artifacts": entries}, "selected")

    def archive(self, entries):
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, value in entries:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    archive.writestr(name, value)
        return data.getvalue()

    def test_download_never_extracts_unselected_paths_or_unbounded_documents(self):
        raw = self.archive([("descriptor.json", '{"synthetic":true}')])
        self.assertEqual(qualification.unpack_document(raw, "descriptor.json"), {"synthetic": True})
        for entries in ([('../descriptor.json', '{}')], [('descriptor.json', '{}'), ('extra', '{}')],
                        [('descriptor.json', ' ' * (qualification.MAX_JSON + 1))],
                        [('descriptor.json', '{}'), ('descriptor.json', '{}')]):
            with self.subTest(entries=[e[0] for e in entries]), self.assertRaises(ValueError):
                qualification.unpack_document(self.archive(entries), "descriptor.json")

    def test_test_process_receives_no_repository_or_runtime_tokens(self):
        with patch.dict(os.environ, {"GH_TOKEN": "private", "ACTIONS_RUNTIME_TOKEN": "private",
                                    "GITHUB_TOKEN": "private", "PROVIDER_SECRET": "private",
                                    "RUNNER_TRACKING_ID": "ownership-metadata"}):
            env = qualification.child_env(Path("fixture.json"))
        self.assertEqual(set(env), {"PATH", "RUST_BACKTRACE", "VHALLA_IROH_QUALIFICATION_CONFIG", "RUNNER_TRACKING_ID"})
        self.assertNotIn("private", env.values())

    def test_deadline_terminates_and_reaps_only_its_own_child_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            child = Mock(pid=9876)
            child.wait.side_effect = [subprocess.TimeoutExpired("fixture", 1), 143]
            child.poll.side_effect = [None, 143]
            with patch.object(qualification.subprocess, "Popen", return_value=child), \
                    patch.object(qualification.os, "killpg") as terminate:
                result = qualification.run_child(work, work, 1)
            self.assertTrue(result["forced"])
            self.assertTrue(result["child_reaped"])
            self.assertIsNone(result["exit_code"])
            terminate.assert_called_once_with(9876, qualification.signal.SIGTERM)
            self.assertEqual(child.wait.call_count, 2)

    def test_interrupted_controller_reaps_child_and_cannot_report_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            child = Mock(pid=6789)
            child.wait.side_effect = [InterruptedError("cancelled"), 143]
            child.poll.side_effect = [None, 143]
            with patch.object(qualification.subprocess, "Popen", return_value=child), \
                    patch.object(qualification.os, "killpg") as terminate:
                result = qualification.run_child(work, work, 180)
            self.assertTrue(result["interrupted"])
            self.assertTrue(result["forced"])
            self.assertTrue(result["child_reaped"])
            self.assertIsNone(result["exit_code"])
            terminate.assert_called_once_with(6789, qualification.signal.SIGTERM)

    def test_host_stop_has_short_grace_independent_of_fixture_lifetime(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            stop = work / "stop"
            stop.touch()
            child = Mock(pid=4567)
            child.wait.side_effect = [subprocess.TimeoutExpired("fixture", .25), 143]
            child.poll.side_effect = [None, 143]
            # The first wait crosses the 20s graceful bound, not the 660s total.
            with patch.object(qualification.subprocess, "Popen", return_value=child), \
                    patch.object(qualification.time, "monotonic", side_effect=[0, 0, 0, 0, 21]), \
                    patch.object(qualification.os, "killpg") as terminate:
                result = qualification.run_child(work, work, 660, stop_path=stop)
            self.assertTrue(result["forced"])
            self.assertTrue(result["child_reaped"])
            terminate.assert_called_once_with(4567, qualification.signal.SIGTERM)

    def test_failed_client_receipt_still_stops_and_checks_host_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            host = self.expected() | dict(schema=qualification.SCHEMA, role="host", passed=False)
            qualification.write_json(work / "host-receipt.json", host)
            qualification.write_json(work / "host-result.json", {
                "stopped_on_request": True, "service_joined": True, "exact_durable_records": True,
            })
            with patch.object(qualification, "poll_document", return_value=self.client() | {"passed": False}), \
                    patch.object(qualification, "wait_local", return_value={
                        "child_reaped": True, "exit_code": 0, "forced": False}):
                self.assertFalse(qualification.finish_host(work, True))
            self.assertTrue((work / "stop").exists())
            evidence = qualification.read_json(work / "host-receipt.json")
            self.assertTrue(evidence["cleanup_confirmed"])
            self.assertFalse(evidence["passed"])

    def test_uncertain_or_forced_host_cleanup_cannot_pass(self):
        for supervisor in ({"child_reaped": False, "exit_code": 0, "forced": False},
                           {"child_reaped": True, "exit_code": None, "forced": True},
                           {"child_reaped": True, "exit_code": 101, "forced": False}):
            with self.subTest(supervisor=supervisor), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                qualification.write_json(work / "host-receipt.json", self.expected())
                qualification.write_json(work / "host-result.json", {
                    "stopped_on_request": True, "service_joined": True, "exact_durable_records": True,
                })
                with patch.object(qualification, "poll_document", return_value=self.client()), \
                        patch.object(qualification, "wait_local", return_value=supervisor):
                    self.assertFalse(qualification.finish_host(work, True))

    def test_artifact_names_bind_current_run_attempt(self):
        with patch.dict(os.environ, {"GITHUB_SHA": "a" * 40, "GITHUB_RUN_ID": "100", "GITHUB_RUN_ATTEMPT": "2"}):
            self.assertEqual(qualification.artifact_name("descriptor"), "iroh-descriptor-100-2")


if __name__ == "__main__":
    unittest.main()
