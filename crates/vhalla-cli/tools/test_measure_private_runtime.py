"""Runner contract tests; no Valhalla build, network or private-room fixture."""

import asyncio
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

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

    def test_frozen_candidate_checks_all_files_and_labels_modified_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "Cargo.lock").write_bytes(b"lock")
            (source / "input.rs").write_bytes(b"source")
            binary, proof = root / "vhalla", root / "proof.json"
            binary.write_bytes(b"candidate")
            binary.chmod(0o700)
            valid = {"kind": "frozen-source-v1", "passed": True, "source_clean_at_build": False,
                     "source_commit": "a" * 40, "source_tree": "b" * 40, "source_patch_sha256": "c" * 64,
                     "source_inputs": {path.name: m.sha256(path) for path in source.iterdir()},
                     "lockfile_sha256": m.sha256(source / "Cargo.lock"), "artifact": {"sha256": m.sha256(binary)}}
            m.write_json(proof, valid)
            result = m.admit_candidate(binary, proof, source)
            self.assertFalse(result["source_clean_at_build"])
            self.assertEqual(result["source_patch_sha256"], "c" * 64)
            self.assertIn("base commit/tree", result["source_identity_scope"])
            m.write_json(proof, {**valid, "source_patch_sha256": ""})
            with self.assertRaisesRegex(m.MeasurementError, "patch identity"):
                m.admit_candidate(binary, proof, source)
            m.write_json(proof, valid)
            (source / "unexpected.rs").write_bytes(b"extra")
            with self.assertRaisesRegex(m.MeasurementError, "captured inputs"):
                m.admit_candidate(binary, proof, source)
            (source / "unexpected.rs").unlink()
            (source / "input.rs").write_bytes(b"changed")
            with self.assertRaisesRegex(m.MeasurementError, "captured inputs"):
                m.admit_candidate(binary, proof, source)

    def test_repeated_quiet_distribution_requires_every_expected_sample(self):
        def result(milliseconds, passed=True):
            return {"correctness_passed": passed, "messages": [{"queue_request_ns": 0,
                     "claim_observed_ns": milliseconds * 1_000_000}]}
        partial = m.quiet_summary([result(1)], 20)
        self.assertFalse(partial["acceptance_p95_under_5s"])
        complete = m.quiet_summary([result(n) for n in range(1000, 1020)], 20)
        self.assertEqual(complete["percentiles_ms"]["p95"], 1018)
        self.assertTrue(complete["acceptance_p95_under_5s"])
        self.assertFalse(m.quiet_summary([result(1000, False)], 1)["acceptance_p95_under_5s"])
        self.assertFalse(m.quiet_summary([result(5000)], 1)["acceptance_p95_under_5s"])

    def test_log_bound_preserves_prior_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            log = m.Log(path)
            log.add({"first": True})
            with patch.object(m, "MAX_LOG", 30), self.assertRaises(m.MeasurementError):
                log.add({"oversized": "x" * 40})
            log.close()
            self.assertEqual([json.loads(line) for line in path.read_text().splitlines()], [{"first": True}])

    def test_invalid_polling_selection_creates_no_fixture_or_log(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "invalid"
            for selection in (None, "unknown", 1):
                with self.subTest(selection=selection), self.assertRaises(m.MeasurementError):
                    m.Fixture(Path(sys.executable), destination, "quiet", selection)
                self.assertFalse(destination.exists())

    def test_cpu_time_parses_platform_displays_without_float_roundoff(self):
        for text, nanoseconds, resolution in (
                ("0:00.01", 10_000_000, 10_000_000),
                ("125:30.99", 7_530_990_000_000, 10_000_000),
                ("01:02:03", 3_723_000_000_000, 1_000_000_000),
                ("2-03:04:05", 183_845_000_000_000, 1_000_000_000),
                ("00:00.123456789", 123_456_789, 1)):
            with self.subTest(text=text):
                self.assertEqual(m.parse_cpu_time(text), (nanoseconds, resolution))
        for invalid in ("", "nan", "-1:00.00", "0:60.00", "1-00:01", "1-24:00:00",
                        "00:00.1234567890", "0:00 trailing", "x" * 33):
            with self.subTest(invalid=invalid), self.assertRaises(m.MeasurementError):
                m.parse_cpu_time(invalid)

    def test_resource_row_retains_start_identity_and_rss_with_cpu(self):
        self.assertEqual(m.parse_process_sample(" 2243 Thu Sep 24 10:53:52 2026 1392 0:00.01"),
                         ("2243", "Thu Sep 24 10:53:52 2026", 1_425_408, 10_000_000, 10_000_000))
        for invalid in ("2243 Thu Sep 24 10:53:52 2026 1392",
                        "2243 Thu Sep 24 10:53:52 2026 -1 0:00.01",
                        "-2 Thu Sep 24 10:53:52 2026 1392 0:00.01"):
            with self.subTest(invalid=invalid), self.assertRaises(m.MeasurementError):
                m.parse_process_sample(invalid)


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

    async def test_transparent_meter_counts_both_directions_and_cleans_ownership(self):
        class Reader:
            def __init__(self, body):
                self.parts = [body, b""]
            async def read(self, size):
                return self.parts.pop(0)
        class Writer:
            def __init__(self):
                self.body = bytearray()
                self.closed = False
                self.eof = False
            def write(self, body):
                self.body.extend(body)
            async def drain(self):
                pass
            def can_write_eof(self):
                return True
            def write_eof(self):
                self.eof = True
            def close(self):
                self.closed = True
            async def wait_closed(self):
                pass
        downstream, upstream = Writer(), Writer()
        async def connect(*args):
            return Reader(b"encrypted reply"), upstream
        meter = m.TrafficMeter(("127.0.0.1", 1))
        with patch.object(m.asyncio, "open_connection", connect):
            await meter.accept(Reader(b"encrypted request"), downstream)
        self.assertEqual(upstream.body, b"encrypted request")
        self.assertEqual(downstream.body, b"encrypted reply")
        self.assertEqual(meter.counts, {"connections": 1, "completed": 1, "failed": 0, "refused": 0,
                         "upstream_bytes": 17, "downstream_bytes": 15})
        self.assertFalse(meter.tasks)
        self.assertTrue(downstream.closed and upstream.closed and downstream.eof and upstream.eof)

        cancelled = asyncio.Event()
        class BrokenReader:
            async def read(self, size):
                raise OSError("synthetic forwarding failure")
        class BlockedReader:
            async def read(self, size):
                try:
                    await asyncio.Event().wait()
                finally:
                    cancelled.set()
        downstream, upstream = Writer(), Writer()
        async def broken_connect(*args):
            return BlockedReader(), upstream
        with patch.object(m.asyncio, "open_connection", broken_connect):
            await asyncio.wait_for(meter.accept(BrokenReader(), downstream), 1)
        self.assertTrue(cancelled.is_set(), "opposite forwarding task must be collected")
        self.assertEqual(meter.counts["failed"], 1)
        self.assertFalse(meter.tasks)
        self.assertTrue(downstream.closed and upstream.closed)

    async def test_polling_selection_changes_no_retry_or_authority_fields(self):
        self.fixture.contexts["a"] = {"room": "r", "anchor": "a", "account": "k", "device": "d"}
        self.fixture.connection = {"namespace": "n"}
        self.fixture.addr = "127.0.0.1:12345"
        adaptive = self.fixture.delivery_profile("a")
        self.assertNotIn("mailbox_polling", adaptive, "default must remain compatible with old candidates")
        self.fixture.mailbox_polling = "interactive"
        interactive = self.fixture.delivery_profile("a")
        self.assertEqual(interactive.pop("mailbox_polling"), "interactive")
        self.assertEqual(interactive, adaptive)
        self.assertEqual(interactive["initial_backoff_secs"], 5)
        self.assertEqual(interactive["max_backoff_secs"], 300)
        result = self.fixture.metrics()
        self.assertEqual(result["mailbox_polling"], "interactive")
        self.assertIsNone(result["page_tls_exchange_count"])

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

    async def test_resource_failure_cannot_be_ignored_until_after_measurement(self):
        async def failure():
            raise m.MeasurementError("synthetic sampler deadline")
        task = asyncio.create_task(failure())
        self.fixture.resource_task = task
        await asyncio.sleep(0)
        with self.assertRaisesRegex(m.MeasurementError, "sampler deadline"):
            self.fixture.monitor_check()
        self.fixture.resource_task = None

    async def test_idle_cost_uses_elapsed_window_and_one_process_identity(self):
        before = {"monotonic_ns": 0, "inflight": 0, **m.TrafficMeter(("", 0)).counts}
        after = {**before, "monotonic_ns": 30_000_000_000, "connections": 30}
        self.fixture.idle_start, self.fixture.idle_end = {"a": before}, {"a": after}
        self.fixture.idle_observer_cpu_start, self.fixture.idle_observer_cpu_end = 1, 1.1
        self.fixture.samples = [
            {"monotonic_ns": 1_000_000_000, "cpu_time_ns": {"host": 100_000_000}, "rss_bytes": {"host": 1024},
             "process_start_identity": {"host": {"pid": 1, "lstart": "same"}}},
            {"monotonic_ns": 29_000_000_000, "cpu_time_ns": {"host": 400_000_000}, "rss_bytes": {"host": 2048},
             "process_start_identity": {"host": {"pid": 1, "lstart": "same"}}}]
        window = self.fixture.metrics()["idle_window"]
        self.assertEqual(window["clients"]["a"]["connections_per_minute"], 60)
        self.assertEqual(window["processes"]["host"]["cpu_time_ns"], 300_000_000)
        self.assertAlmostEqual(window["processes"]["host"]["cpu_seconds"], 0.3)
        self.assertEqual(window["processes"]["host"]["sample_span_seconds"], 28)
        self.assertEqual(window["processes"]["host"]["rss_max_bytes"], 2048)
        self.fixture.samples[-1]["process_start_identity"]["host"]["pid"] = 2
        with self.assertRaisesRegex(m.MeasurementError, "different process identities"):
            self.fixture.metrics()

    async def test_cpu_metrics_keep_process_generations_separate(self):
        self.fixture.samples = [
            {"rss_bytes": {}, "cpu_time_ns": {"agent-a-1": 10_000_000}},
            {"rss_bytes": {}, "cpu_time_ns": {"agent-a-1": 30_000_000, "agent-a-2": 20_000_000}}]
        self.assertEqual(self.fixture.metrics()["observed_cpu_time_ns_by_process"],
                         {"agent-a-1": 30_000_000, "agent-a-2": 20_000_000})

    async def test_resource_sampler_checks_live_pid_start_identity_and_cpu_progress(self):
        identity = "Thu Sep 24 10:53:52 2026"
        child = SimpleNamespace(process=SimpleNamespace(pid=2243, returncode=None), label="agent-a-1",
                                sampled_start_identity=None, sampled_cpu_time_ns=None)
        self.fixture.children.append(child)
        async def sample(row):
            process = SimpleNamespace(returncode=0, communicate=AsyncMock(return_value=(row.encode(), b"")))
            with patch.object(m.asyncio, "create_subprocess_exec", AsyncMock(return_value=process)), \
                    patch.object(m.asyncio, "sleep", AsyncMock(side_effect=asyncio.CancelledError)):
                await self.fixture.sample_resources()
        try:
            with self.assertRaises(asyncio.CancelledError):
                await sample(f"2243 {identity} 1392 0:00.02")
            saved = self.fixture.samples[0]
            self.assertEqual(saved["cpu_time_ns"], {"agent-a-1": 20_000_000})
            self.assertEqual(saved["cpu_time_display_resolution_ns"], {"agent-a-1": 10_000_000})
            self.assertEqual(saved["process_start_identity"]["agent-a-1"], {"pid": 2243, "lstart": identity})
            for row, reason in ((f"2243 {identity} 1392 0:00.01", "CPU clock regressed"),
                                ("2243 Thu Sep 24 10:53:53 2026 1392 0:00.03", "start identity changed"),
                                (f"2244 {identity} 1392 0:00.03", "unowned PID")):
                with self.subTest(row=row), self.assertRaisesRegex(m.MeasurementError, reason):
                    await sample(row)
            self.assertEqual(len(self.fixture.samples), 1, "refused samples must not be reported")
        finally:
            self.fixture.children.clear()

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

    async def test_meter_drain_shares_cleanup_deadline_and_forced_cleanup_collects_it(self):
        class SlowMeter:
            forced = False
            async def close(meter, force=False):
                if force:
                    meter.forced = True
                else:
                    await asyncio.sleep(10)
        meter = SlowMeter()
        self.fixture.meters["synthetic"] = meter
        with patch.object(m, "CLEANUP_SECONDS", 0.02):
            with self.assertRaisesRegex(m.MeasurementError, "graceful cleanup"):
                await asyncio.wait_for(self.fixture.shutdown(), 1)
        self.assertTrue(meter.forced)
        self.fixture.meters.clear()

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
            result = await m.run_scenario(Path(sys.executable), destination, "smoke", "interactive")
        self.assertFalse(result["correctness_passed"])
        self.assertEqual(result["mailbox_polling"], "interactive")
        self.assertEqual(json.loads((destination / "receipt.json").read_text())["mailbox_polling"], "interactive")
        self.assertTrue((destination / "receipt.json").is_file())
        self.assertIn("before-failure", (destination / "events.jsonl").read_text())


if __name__ == "__main__":
    unittest.main()
