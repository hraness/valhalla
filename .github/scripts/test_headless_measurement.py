"""Measurement semantics and evidence bounds; no native journey is launched."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import headless_measurement as measurement


class MeasurementTests(unittest.TestCase):
    def config(self, directory="/tmp/measurement"):
        return dict(work=directory, binary="/absolute/vhalla", nonce="a" * 64, relay=None,
                    mode="local", role="host", relay_only=False)

    def build(self, root, dirty=False):
        binary = root / "candidate"
        binary.write_bytes(b"immutable synthetic candidate bytes")
        value = dict(binary_sha256=measurement.public.controller.digest(binary), source_sha="b" * 40,
                     dirty_source=dirty, toolchain="rustc 1.98.1 (provided by build owner)",
                     build_profile="release")
        path = root / "build.json"
        measurement.write_json(path, value)
        return binary, path, value

    def test_manifest_binds_binary_without_checkout_or_cli_inference(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary, path, expected = self.build(root)
            with patch.object(measurement.public, "exchange") as command:
                result = measurement.manifest(path, binary)
            command.assert_not_called()
            self.assertEqual(result["source_sha"], expected["source_sha"])
            self.assertEqual(result["toolchain"], expected["toolchain"])
            self.assertEqual(result["build_profile"], "release")
            self.assertTrue(result["exact_committed_source"])
            self.assertEqual(result["manifest_sha256"], measurement.public.controller.digest(path))
            binary.write_bytes(b"another candidate")
            with self.assertRaises(ValueError):
                measurement.manifest(path, binary)

    def test_manifest_profile_is_explicit_and_historical_manifests_remain_unspecified(self):
        with tempfile.TemporaryDirectory() as directory:
            binary, path, value = self.build(Path(directory))
            for profile in ("dev", "release"):
                measurement.write_json(path, value | {"build_profile": profile})
                self.assertEqual(measurement.manifest(path, binary)["build_profile"], profile)
            historical = {key: item for key, item in value.items() if key != "build_profile"}
            measurement.write_json(path, historical)
            self.assertEqual(measurement.manifest(path, binary)["build_profile"], "unspecified")
            for profile in (None, False, 1, "", "debug", "release\n", "unspecified", []):
                measurement.write_json(path, value | {"build_profile": profile})
                with self.subTest(profile=profile), self.assertRaises(ValueError):
                    measurement.manifest(path, binary)

    def test_dirty_source_is_explicit_and_never_attested_as_exact_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            binary, path, value = self.build(Path(directory), dirty=True)
            result = measurement.manifest(path, binary)
            self.assertFalse(result["exact_committed_source"])
            self.assertIn("exact source not attested", result["source_scope"])
            for changed in ({key: item for key, item in value.items() if key != "dirty_source"},
                            value | {"dirty_source": 0}, value | {"toolchain": "bad\nsecret"},
                            value | {"token": "secret"}, value | {"source_sha": "HEAD"}):
                measurement.write_json(path, changed)
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    measurement.manifest(path, binary)

    def test_payloads_have_exact_utf8_size_and_distinct_identity(self):
        values = [measurement.body("a" * 64, kind, index, 256)
                  for kind in ("public", "private") for index in (0, 1, 1001, 2000)]
        self.assertEqual(len(set(values)), len(values))
        self.assertTrue(all(len(value.encode("utf-8")) == 256 for value in values))
        self.assertEqual(measurement.workload(32, 256, 8)["message_bytes"], 256)
        for values in ((0, 256, 8), (32, 0, 8), (48, 256, 16), (32, 4097, 8), (32, 256, False)):
            with self.subTest(values=values), self.assertRaises(ValueError):
                measurement.workload(*values)

    def test_quantiles_report_counts_and_nearest_rank_without_thresholds(self):
        result = measurement.latency(list(range(32)))
        self.assertEqual((result["samples"], result["p50"], result["p95"], result["p99"]), (32, 15, 30, 31))
        self.assertEqual(measurement.latency([2])["p99"], 2)
        self.assertNotIn("pass", result)
        self.assertFalse(measurement.workload(32, 256, 8)["capacity_claim"])
        for values in ([], [float("inf")], [-1], [float("nan")], [True]):
            with self.subTest(values=values), self.assertRaises(ValueError):
                measurement.latency(values)

    def test_ps_cpu_formats_preserve_cumulative_seconds(self):
        expected = {"0:01.23": 1.23, "00:00:02": 2, "90:01.5": 5401.5,
                    "1-02:03:04.50": 93784.5, "02:00:01": 7201}
        for text, seconds in expected.items():
            with self.subTest(text=text):
                self.assertEqual(measurement.cpu_seconds(text), seconds)
        for text in ("", "secret", "00:99", "00:60:00", "-01:00", "1:2", "NaN", "1:01\nsecret"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                measurement.cpu_seconds(text)

    def test_resource_samples_select_only_owned_pids_and_label_observed_maxima(self):
        resources = measurement.Resources(self.config())
        sender, receiver = Mock(pid=11), Mock(pid=12)
        sender.poll.return_value = receiver.poll.return_value = None
        resources.register("public.sender.1", sender)
        resources.register("public.receiver.1", receiver)
        with patch.object(measurement.public, "exchange", side_effect=[
            (0, b"11 2048 0:01.50\n12 1024 00:00:02\n"),
            (0, b"11 4096 0:01.75\n12 2048 00:00:03\n")]) as command:
            resources.sample("public.sequential", True)
            resources.sample("public.shutdown", True)
        argv, payload, env = command.call_args.args
        self.assertEqual(argv, ["/bin/ps", "-p", "11,12", "-o", "pid=", "-o", "rss=", "-o", "time="])
        self.assertEqual(payload, b"")
        self.assertNotIn("GH_TOKEN", env)
        result = resources.report()
        self.assertEqual(result["sample_count"], 4)
        self.assertEqual(result["process_count"], 2)
        self.assertEqual(result["processes"][0]["maximum_observed_rss_bytes"], 4096 * 1024)
        self.assertEqual(result["processes"][0]["last_observed_cpu_seconds"], 1.75)
        self.assertIn("not true peak", result["rss_scope"])
        self.assertIn("excludes short-lived CLI", result["cpu_scope"])
        self.assertTrue(all(row["interval_end_ms"] >= row["interval_start_ms"] for row in result["samples"]))

    def test_resource_samples_refuse_missing_foreign_or_reused_subjects(self):
        for raw in (b"12 123 0:00.01\n", b"11 123 0:00.01\n11 123 0:00.01\n", b""):
            resources = measurement.Resources(self.config())
            child = Mock(pid=11)
            child.poll.return_value = None
            resources.register("private.sender.1", child)
            with patch.object(measurement.public, "exchange", return_value=(0, raw)), self.assertRaises(ValueError):
                resources.sample("private.sequential", True)
        child = Mock(pid=11)
        child.poll.return_value = 0
        with self.assertRaises(ValueError):
            measurement.Resources(self.config()).register("private.sender.1", child)

    def test_resource_incarnations_remain_separate_after_restart(self):
        resources = measurement.Resources(self.config())
        first, second = Mock(pid=11), Mock(pid=22)
        first.poll.return_value = second.poll.return_value = None
        resources.register("public.receiver.1", first)
        with patch.object(measurement.public, "exchange", return_value=(0, b"11 1000 0:10.00\n")):
            resources.sample("public.offline", True)
        first.poll.return_value = 0
        resources.register("public.receiver.2", second)
        with patch.object(measurement.public, "exchange", return_value=(0, b"22 900 0:00.05\n")) as command:
            resources.sample("public.receiver_restart", True)
        self.assertEqual(command.call_args.args[0][2], "22")
        self.assertEqual([row["samples"] for row in resources.report()["processes"]], [1, 1])

    def test_accounting_strips_secret_and_path_fields(self):
        raw = dict(records=1, bytes=2, max_records=3, max_record_bytes=4, token="secret", profile="/secret")
        self.assertEqual(measurement.usage(raw), dict(records=1, bytes=2, max_records=3, max_record_bytes=4))
        with self.assertRaises(ValueError):
            measurement.usage(raw | {"bytes": True})
        raw = dict(jobs=1, bytes=2, max_jobs=3, max_bytes=4, state="/private/home")
        self.assertNotIn("state", measurement.queue_usage(raw))
        profile = dict(max_jobs=64, max_bytes=8388608, max_attempts=4, initial_backoff_secs=1,
            max_backoff_secs=30, initial_cursor=0, emit_acceptance=True, mailbox_polling="interactive",
            token="/secret/token", context={"account": "secret"})
        self.assertNotIn("token", measurement.profile_limits(profile))
        self.assertNotIn("context", measurement.profile_limits(profile))
        for change in ({"max_jobs": "secret"}, {"mailbox_polling": "/secret"}, {"emit_acceptance": 1}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                measurement.profile_limits(profile | change)

    def test_settled_disk_counts_hardlinks_once_and_never_follows_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = root / "data"
            data.mkdir()
            first = data / "one"
            first.write_bytes(b"retained" * 32)
            os.link(first, data / "two")
            result = measurement.disk_usage(data)
            self.assertEqual(result["logical_file_bytes"], 256)
            self.assertEqual(result["regular_files"], 1)
            with patch.object(measurement.time, "sleep"):
                settled = measurement.settled_disk(data)
            self.assertTrue(settled["settled"])
            self.assertIn("clone sharing is not deduplicated", settled["allocation_note"])
            (data / "symlink").symlink_to(root / "outside")
            with self.assertRaises(ValueError):
                measurement.disk_usage(data)

    def test_unsettled_disk_is_not_reported_as_settled(self):
        with patch.object(measurement, "disk_usage", side_effect=[dict(bytes=index) for index in range(6)]), \
             patch.object(measurement.time, "sleep"), self.assertRaises(ValueError):
            measurement.settled_disk(Path("/unused"))

    def test_inbox_paginates_and_ignores_nonmeasurement_receipt_content(self):
        nonce = "a" * 64
        text = measurement.body(nonce, "private", 1, 256)
        reader = measurement.Inbox("private", "b" * 64, nonce)
        daemon = Mock()
        daemon.call.side_effect = [
            dict(coverage="local", head=3, next=2, records=[dict(cursor=1, body=None), dict(cursor=2, body="receipt")]),
            dict(coverage="local", head=3, next=None, records=[dict(cursor=3, body=text, sender="b" * 64)])]
        self.assertIsNone(reader.poll(daemon, text))
        self.assertEqual(reader.cursor, 2)
        self.assertEqual(reader.poll(daemon, text), 3)
        self.assertEqual(daemon.call.call_args.kwargs["after"], 2)
        self.assertEqual(reader.cursor, 3)

    def test_offline_batch_retains_first_visibility_time_without_repolling_cached_rows(self):
        nonce = "a" * 64
        texts = [measurement.body(nonce, "private", number, 256) for number in (1, 2)]
        reader = measurement.Inbox("private", "b" * 64, nonce)
        daemon = Mock()
        daemon.call.return_value = dict(coverage="local", head=2, next=None,
            records=[dict(cursor=index, body=text, sender="b" * 64) for index, text in enumerate(texts, 1)])
        with patch.object(measurement.time, "perf_counter_ns", return_value=123456789):
            self.assertEqual(reader.poll(daemon, texts[0]), 1)
        self.assertEqual(reader.poll(daemon, texts[1]), 2)
        self.assertEqual(set(reader.observed_ns.values()), {123456789})
        daemon.call.assert_called_once()

    def test_public_visibility_requires_expected_authenticated_author_and_no_duplicates(self):
        nonce = "a" * 64
        text = measurement.body(nonce, "public", 1, 256)
        row = dict(cursor=1, body=text, author="b" * 64, event="c" * 64, visibility="provisional")
        for change in ({"author": "d" * 64}, {"visibility": "incomplete"}, {"event": "invalid"}):
            reader = measurement.Inbox("public", "b" * 64, nonce)
            daemon = Mock()
            daemon.call.return_value = dict(coverage="local", head=1, next=None, records=[row | change])
            with self.subTest(change=change), self.assertRaises(ValueError):
                reader.poll(daemon, text)
        reader = measurement.Inbox("public", "b" * 64, nonce)
        daemon = Mock()
        daemon.call.side_effect = [dict(coverage="local", head=1, next=None, records=[row]),
                                  dict(coverage="local", head=2, next=None, records=[row | {"cursor": 2}])]
        reader.poll(daemon, text)
        with self.assertRaises(ValueError):
            reader.poll(daemon, "not yet seen")

    def test_exact_retry_requires_retained_artifact_and_sequence(self):
        runner = measurement.Measurement(self.config(), measurement.workload(32, 256, 8))
        daemon = Mock()
        original = dict(artifact="ab", sequence=7)
        daemon.call.return_value = dict(exact_retry=True, **original)
        self.assertGreaterEqual(runner.retry(daemon, 101, "text", {}, original), 0)
        for value in (dict(exact_retry=False, **original), dict(exact_retry=True, artifact="cd", sequence=7),
                      dict(exact_retry=True, artifact="ab", sequence=8)):
            daemon.call.return_value = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                runner.retry(daemon, 101, "text", {}, original)

    def test_cleanup_attempts_only_owned_helpers_even_after_one_failure(self):
        runner = measurement.Measurement(self.config(), measurement.workload(32, 256, 8))
        first, second, mailbox = Mock(forced=False), Mock(forced=False), Mock(forced=False)
        second.stop.side_effect = ValueError("owned process failed")
        runner.owned = [first, second]
        runner.mailboxes = [mailbox]
        self.assertFalse(runner.close())
        first.stop.assert_called_once()
        second.stop.assert_called_once()
        mailbox.stop.assert_called_once()

    def test_failed_measurement_preserves_private_diagnostics_without_receipt_leak(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary, path, _ = self.build(root, dirty=True)
            runner = Mock(phase="private.sequential", outputs={})
            runner.scenario.side_effect = ValueError("sensitive diagnostic text")
            runner.close.return_value = True
            runner.resources.report.return_value = dict(process_count=0, sample_count=0, samples=[])
            work = root / "work"
            with patch.object(measurement, "Measurement", return_value=runner):
                self.assertFalse(measurement.run(binary, path, work, measurement.workload(32, 256, 8)))
            receipt = json.loads((work / "measurement-receipt.json").read_bytes())
            self.assertFalse(receipt["passed"] or receipt["capacity_qualified"] or receipt["true_peak_rss_measured"])
            self.assertFalse(receipt["build"]["exact_committed_source"])
            self.assertEqual(receipt["build"]["build_profile"], "release")
            self.assertTrue(receipt["cleanup_confirmed"])
            self.assertNotIn("sensitive diagnostic text", json.dumps(receipt))
            self.assertTrue((work / "failure-private.json").is_file())
            self.assertTrue((work / "config.json").is_file())
            runner.close.assert_called_once()

    def test_existing_work_directory_is_not_reused_or_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary, path, _ = self.build(root)
            work = root / "work"
            work.mkdir()
            sentinel = work / "retained"
            sentinel.write_text("preserve")
            with patch.object(measurement, "Measurement") as runner, self.assertRaises(FileExistsError):
                measurement.run(binary, path, work, measurement.workload(32, 256, 8))
            runner.assert_not_called()
            self.assertEqual(sentinel.read_text(), "preserve")


if __name__ == "__main__":
    unittest.main()
