"""Runner contract tests; no Valhalla build, network or private-room fixture."""

import asyncio
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("measurement", Path(__file__).with_name("measure_private_runtime.py"))
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class ContractTests(unittest.TestCase):
    def test_fixed_payloads_are_unique_exact_utf8_128_bytes(self):
        bodies = [m.body_for(i).encode() for i in range(100)]
        self.assertEqual(len(set(bodies)), 100)
        self.assertEqual({len(body) for body in bodies}, {128})

    def test_nearest_rank_percentiles_include_tail(self):
        self.assertIsNone(m.percentiles([]))
        self.assertEqual(m.percentiles([9]), {"p50": 9, "p95": 9, "p99": 9})
        self.assertEqual(m.percentiles(range(1, 101)), {"p50": 50, "p95": 95, "p99": 99})

    def test_filtered_raw_cursor_advances_without_visible_records(self):
        self.assertEqual(m.next_cursor({"head": "12", "next": "8", "records": []}, 4), 8)
        self.assertEqual(m.next_cursor({"head": "12", "next": None, "records": []}, 8), 12)
        with self.assertRaises(m.MeasurementError):
            m.next_cursor({"head": "2", "next": None}, 3)

    def test_exact_inbox_rejects_duplicates_wrong_sender_and_unknown_body(self):
        body = m.body_for(0).encode()
        record = {"sequence": "1", "sender": "A", "body_hex": body.hex()}
        seen = {}
        m.check_inbox([record], {body}, "A", seen)
        self.assertEqual(seen, {1: body})
        for altered in (record, {**record, "sequence": "2"}, {**record, "sender": "B"},
                        {**record, "body_hex": b"unexpected".hex()}):
            with self.subTest(altered=altered), self.assertRaises(m.MeasurementError):
                m.check_inbox([altered], {body}, "A", dict(seen))

    def test_fresh_budget_fits_load_without_topup(self):
        self.assertGreaterEqual(m.GRANT["max-messages"], m.SCENARIOS["load"])
        self.assertGreaterEqual(m.GRANT["max-preparations"], m.SCENARIOS["load"])
        self.assertGreaterEqual(m.GRANT["max-body-bytes"], 128 * m.SCENARIOS["load"])
        self.assertLessEqual(m.GRANT["max-read-records"], 4096)
        self.assertEqual(m.WINDOW, 16)
        self.assertEqual(m.DRAIN_SECONDS, 120)

    def test_footprint_does_not_follow_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").write_bytes(b"abc")
            (root / "link").symlink_to(root / "data")
            (root / "cycle").symlink_to(root, target_is_directory=True)
            result = m.footprint(root)
            self.assertEqual(result["regular_files"], 1)
            self.assertEqual(result["logical_bytes"], 3)

    def test_candidate_requires_exact_clean_source_and_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary, proof = root / "vhalla", root / "proof.json"
            binary.write_bytes(b"candidate")
            binary.chmod(0o700)
            (root / "Cargo.lock").write_bytes(b"lock")
            valid = {"passed": True, "source_clean_at_build": True, "source_commit": "head",
                     "source_tree": "tree", "lockfile_sha256": m.sha256(root / "Cargo.lock"),
                     "artifact": {"sha256": m.sha256(binary)}}
            with patch.object(m, "git", side_effect=lambda source, *args: "tree" if args[-1] == "HEAD^{tree}" else "head"), \
                    patch.object(m, "native_fingerprint", return_value="inputs"):
                m.write_json(proof, valid)
                self.assertEqual(m.admit_candidate(binary, proof, root)["native_inputs_sha256"], "inputs")
                for key, value in (("passed", False), ("source_clean_at_build", False),
                                   ("source_commit", "old"), ("source_tree", "old"),
                                   ("lockfile_sha256", "wrong"), ("artifact", {"sha256": "wrong"})):
                    m.write_json(proof, {**valid, key: value})
                    with self.subTest(key=key), self.assertRaises(m.MeasurementError):
                        m.admit_candidate(binary, proof, root)

    def test_log_bound_preserves_prior_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            log = m.Log(path)
            log.add({"first": True})
            with patch.object(m, "MAX_LOG", 30), self.assertRaises(m.MeasurementError):
                log.add({"oversized": "x" * 40})
            log.close()
            self.assertEqual([json.loads(line) for line in path.read_text().splitlines()], [{"first": True}])


class AsyncContractTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.fixture = m.Fixture(Path(sys.executable), Path(self.directory.name) / "smoke", "smoke")

    async def asyncTearDown(self):
        await self.fixture.shutdown()
        self.fixture.log.close()
        self.directory.cleanup()

    async def test_private_import_keeps_room_positional_and_room_flag(self):
        args = self.fixture.private_args("import", "b", room="scope", anchor="anchor")
        self.assertEqual(args[3], str(self.fixture.root / "b" / "room"))
        self.assertEqual(args[4:], ["--room", "scope", "--anchor", "anchor"])
        args = self.fixture.private_args("offer-inspect", "b", False, offer="path")
        self.assertEqual(args[3:], ["--offer", "path"])

    async def test_owned_stdio_child_is_closed_reaped_and_retained(self):
        child = await self.fixture.spawn("pipe-child", ["-c", "import sys; print('{\"ready\":true}', flush=True); sys.stdin.read()"])
        self.assertEqual(await child.line(), {"ready": True})
        await child.close()
        self.assertEqual(child.process.returncode, 0)
        self.assertFalse(child.forced)
        self.assertIn("pipe-child", (self.fixture.root / "events.jsonl").read_text())

    async def test_command_failure_is_not_success_and_process_is_reaped(self):
        with self.assertRaises(m.MeasurementError):
            await self.fixture.command(["-c", "import sys; print('failure'); sys.exit(3)"])
        child = self.fixture.children[-1]
        self.assertEqual(child.process.returncode, 3)
        # The failure is already asserted; remove only the test's closed handle
        # so teardown does not re-raise the expected refusal.
        self.fixture.children.remove(child)

    async def test_mcp_response_id_mismatch_refuses(self):
        code = "import sys,json; q=json.loads(sys.stdin.readline()); print(json.dumps({'id':q['id']+1,'result':{}}),flush=True); sys.stdin.read()"
        child = await self.fixture.spawn("wrong-id", ["-c", code])
        agent = m.Agent(child, {"grant_id": "g"}, {})
        with self.assertRaisesRegex(m.MeasurementError, "ID mismatch"):
            await agent.ask("tools/list", {})

    async def test_missing_observations_are_explicit_in_failed_metrics(self):
        self.fixture.messages[1] = {"index": 0, "scheduled_ns": 1, "prepare_request_ns": 2,
                                    "queue_request_ns": 3, "queue_reply_ns": 4}
        metrics = self.fixture.metrics()
        self.assertEqual(metrics["queue_to_receiver_observation_ms"]["observed_count"], 0)
        self.assertFalse(metrics["receiver_p95_under_5s"])
        self.assertFalse(self.fixture.complete())

    async def test_offline_retention_is_observed_past_first_sixteen_without_claims(self):
        calls = []
        class Sender:
            async def call(sender, name, **args):
                self.assertEqual(name, "private_outbox_status")
                after = int(args["after"])
                calls.append(after)
                end = min(after + args["limit"], 32)
                return {"head": "32", "next": str(end) if end < 32 else None,
                        "records": [{"sequence": str(n), "relay": {"state": "retained", "uncertain": False,
                                    "position": str(n)}, "member_acceptances": []} for n in range(after + 1, end + 1)]}
        self.fixture.agents["a"] = Sender()
        self.fixture.messages = {n: {} for n in range(1, 33)}
        try:
            await self.fixture.observe()
            self.assertEqual(calls, [0, 16])
            self.assertTrue(all("retained_observed_ns" in value for value in self.fixture.messages.values()))
            self.assertTrue(all("claim_observed_ns" not in value for value in self.fixture.messages.values()))
        finally:
            self.fixture.agents.clear()

    async def test_acceptance_before_retention_does_not_strand_observation(self):
        calls = []
        class Sender:
            async def call(sender, name, **args):
                calls.append(args)
                relay = ({"state": "pending"} if len(calls) == 1 else
                         {"state": "retained", "uncertain": False, "position": "1"})
                return {"head": "1", "next": None, "records": [{"sequence": "1", "relay": relay,
                        "member_acceptances": [{"recipient": "B", "received_sequence": "1"}]}]}
        self.fixture.contexts["b"] = {"device": "B"}
        self.fixture.agents["a"] = Sender()
        self.fixture.messages = {1: {}}
        try:
            await self.fixture.observe()
            self.assertIn("claim_observed_ns", self.fixture.messages[1])
            self.assertNotIn("retained_observed_ns", self.fixture.messages[1])
            await self.fixture.observe()
            self.assertIn("retained_observed_ns", self.fixture.messages[1])
            self.assertEqual(len(calls), 2)
        finally:
            self.fixture.agents.clear()

    async def test_cleanup_deadline_forces_and_reaps_only_owned_child(self):
        child = await self.fixture.spawn("cleanup-child", ["-c", "import sys; sys.stdin.read()"])
        async def stalled_shutdown():
            await asyncio.sleep(10)
        with patch.object(self.fixture, "_shutdown", stalled_shutdown), patch.object(m, "CLEANUP_SECONDS", 0.02):
            with self.assertRaisesRegex(m.MeasurementError, "forced cleanup"):
                await self.fixture.shutdown()
        self.assertIsNotNone(child.process.returncode)
        self.assertTrue(child.forced)
        self.assertEqual(self.fixture.cleanup[0]["pid"], child.process.pid)
        self.fixture.children.clear()  # expected forced failure already asserted

    async def test_acceptance_target_and_censored_counts_do_not_hide_receiver_only_success(self):
        self.fixture.messages[1] = {"index": 0, "scheduled_ns": 0, "prepare_request_ns": 1,
            "queue_request_ns": 2, "queue_reply_ns": 3, "receiver_observed_ns": 4,
            "retained_observed_ns": 4}
        result = self.fixture.metrics()
        self.assertEqual(result["counts"]["receiver_observed"], 1)
        self.assertEqual(result["counts"]["member_acceptance_observed"], 0)
        self.assertFalse(result["acceptance_p95_under_5s"])
        self.assertEqual(result["censored"][0]["missing"], ["claim_observed_ns"])
        self.assertIsNone(result["censored"][0]["observed_until_ns"])

    async def test_failed_scenario_preserves_receipt_and_home(self):
        destination = Path(self.directory.name) / "failed"
        async def fail_setup(fixture):
            fixture.log.add({"event": "before-failure"})
            raise m.MeasurementError("synthetic setup failure")
        with patch.object(m.Fixture, "setup", fail_setup):
            result = await m.run_scenario(Path(sys.executable), destination, "smoke")
        self.assertFalse(result["correctness_passed"])
        self.assertTrue((destination / "receipt.json").is_file())
        self.assertIn("before-failure", (destination / "events.jsonl").read_text())


if __name__ == "__main__":
    unittest.main()
