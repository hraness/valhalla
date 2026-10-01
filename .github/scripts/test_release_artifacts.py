"""Offline behavioral coverage of exact cross-attempt release artifact reuse."""
import copy
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch
import warnings
import zipfile

import release_artifacts as artifacts


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = (ROOT / ".github/workflows/release.yml").read_text()
RUST = (ROOT / ".github/workflows/rust.yml").read_text()


def bundle(entries):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return output.getvalue()


class ReleaseArtifactTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="vhalla-artifact-retry-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.environment = {"GITHUB_REPOSITORY": "hraness/valhalla", "GITHUB_SHA": "a" * 40,
                            "GITHUB_RUN_ID": "42", "GITHUB_RUN_ATTEMPT": "2",
                            "GITHUB_REF": "refs/tags/v0.2.11", "GITHUB_REF_NAME": "v0.2.11"}
        active = patch.dict(os.environ, self.environment)
        active.start()
        self.addCleanup(active.stop)
        self.replies = {}
        self.calls = []
        active = patch.object(artifacts, "api_bytes", self.api)
        active.start()
        self.addCleanup(active.stop)

    def api(self, path, maximum):
        self.calls.append(path)
        reply = self.replies[path]
        self.assertLessEqual(len(reply), maximum)
        return reply

    def producer(self, name="vhalla-unsigned", attempt=1, identity=17, data=None, prefix=""):
        data = data or bundle([("archive", b"payload")])
        digest = hashlib.sha256(data).hexdigest()
        key = prefix + "_" if prefix else ""
        os.environ[key + "ARTIFACT_ID"] = str(identity)
        os.environ[key + "ARTIFACT_DIGEST"] = digest
        metadata = {"id": identity, "digest": "sha256:" + digest, "name": f"{name}-{attempt}",
                    "expired": False, "size_in_bytes": len(data),
                    "workflow_run": {"id": 42, "head_sha": "a" * 40}}
        self.replies[f"actions/artifacts/{identity}"] = json.dumps(metadata).encode()
        self.replies[f"actions/artifacts/{identity}/zip"] = data
        return metadata, data

    def test_failed_consumer_reuses_exact_prior_successful_producer(self):
        for name in ("vhalla-unsigned", "release-cli-aarch64-apple-darwin", "vhalla-browser", "release-browser"):
            with self.subTest(name=name):
                _, expected = self.producer(name)
                self.assertEqual(artifacts.fetch(name), expected)
        self.assertEqual(self.calls, ["actions/artifacts/17", "actions/artifacts/17/zip"] * 4)

    def test_current_attempt_is_accepted_without_artifact_listing(self):
        _, expected = self.producer(attempt=2)
        self.assertEqual(artifacts.fetch("vhalla-unsigned"), expected)
        self.assertEqual(self.calls, ["actions/artifacts/17", "actions/artifacts/17/zip"])

    def test_foreign_future_expired_and_malformed_metadata_fail_before_download(self):
        original, _ = self.producer()
        changes = [
            {"id": 18}, {"id": True}, {"digest": "sha256:" + "0" * 64},
            {"workflow_run": {"id": 43, "head_sha": "a" * 40}},
            {"workflow_run": {"id": 42, "head_sha": "b" * 40}}, {"workflow_run": None},
            {"name": "vhalla-unsigned-3"}, {"name": "vhalla-unsigned-0"},
            {"name": "vhalla-unsigned-01"}, {"name": "vhalla-unsigned-1-extra"},
            {"name": "foreign-1"}, {"name": []}, {"expired": True},
            {"size_in_bytes": 0}, {"size_in_bytes": artifacts.MAX_BYTES + 1}, {"size_in_bytes": True},
        ]
        for change in changes:
            with self.subTest(change=change):
                metadata = {**copy.deepcopy(original), **change}
                self.replies["actions/artifacts/17"] = json.dumps(metadata).encode()
                self.calls.clear()
                with self.assertRaises(ValueError):
                    artifacts.fetch("vhalla-unsigned")
                self.assertEqual(self.calls, ["actions/artifacts/17"])

    def test_missing_or_malformed_producer_outputs_fail_without_api(self):
        self.producer()
        for key, value in (("ARTIFACT_ID", ""), ("ARTIFACT_ID", "17/zip"), ("ARTIFACT_DIGEST", ""),
                           ("GITHUB_RUN_ATTEMPT", "0"), ("GITHUB_REPOSITORY", "elsewhere/valhalla")):
            with self.subTest(key=key, value=value), patch.dict(os.environ, {key: value}):
                with self.assertRaises(ValueError):
                    artifacts.fetch("vhalla-unsigned")
        self.assertFalse(self.calls)

    def test_downloaded_bytes_must_match_exact_producer_digest_and_size(self):
        _, data = self.producer()
        self.replies["actions/artifacts/17/zip"] = data[:-1] + bytes([data[-1] ^ 1])
        with self.assertRaisesRegex(ValueError, "ZIP digest or size"):
            artifacts.fetch("vhalla-unsigned")

    def test_mixed_attempt_native_outputs_stage_exact_five_pairs(self):
        expected = {}
        for identity, (key, target) in enumerate(artifacts.RELEASE_TARGETS.items(), 100):
            extension = ".zip" if key == "WINDOWS" else ".tar.gz"
            name = f"valhalla-v0.2.11-{target}{extension}"
            pair = [(name, target.encode()), (name + ".sha256", b"checksum")]
            expected.update(pair)
            self.producer("release-cli-" + target, 1 + identity % 2, identity, bundle(pair), key)
        name = "valhalla-browser-v0.2.11.tar.gz"
        pair = [(name, b"browser"), (name + ".sha256", b"checksum")]
        # A stale browser producer cannot add an unrequested release asset.
        self.producer("release-browser", 1, 105, bundle(pair), "BROWSER")
        destination = self.root / "assets"
        artifacts.fetch_release(destination)
        self.assertEqual({path.name: path.read_bytes() for path in destination.iterdir()}, expected)
        self.assertEqual(len(expected), 10)
        self.assertEqual(self.calls, [path for identity in range(100, 105)
                                     for path in (f"actions/artifacts/{identity}", f"actions/artifacts/{identity}/zip")])

    def test_zip_inventory_rejects_duplicate_traversal_symlink_and_existing_output(self):
        link = zipfile.ZipInfo("linked")
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            for entries in ([('../escape', b"bad")], [("/absolute", b"bad")], [(link, b"target")],
                            [("same", b"one"), ("same", b"two")]):
                with self.subTest(entries=entries), self.assertRaises(ValueError):
                    artifacts.unpack(bundle(entries), self.root / "bad")
                self.assertFalse((self.root / "bad").exists())
        destination = self.root / "good"
        artifacts.unpack(bundle([("member", b"original")]), destination, {"member"})
        with self.assertRaisesRegex(ValueError, "already contains"):
            artifacts.unpack(bundle([("member", b"replacement")]), destination, {"member"})
        self.assertEqual((destination / "member").read_bytes(), b"original")
        with self.assertRaisesRegex(ValueError, "inventory"):
            artifacts.unpack(bundle([("extra", b"unqualified")]), self.root / "bad", {"member"})

    def test_zip_expansion_and_destination_symlink_are_rejected(self):
        with patch.object(artifacts, "MAX_BYTES", 10), self.assertRaises(ValueError):
            artifacts.unpack(bundle([("a", b"123456"), ("b", b"123456")]), self.root / "expanded")
        self.assertFalse((self.root / "expanded").exists())
        (self.root / "link").symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "real directory"):
            artifacts.unpack(bundle([("a", b"data")]), self.root / "link")
        self.assertFalse((self.root / "a").exists())


class DownloadByteBoundTests(unittest.TestCase):
    def test_real_downloader_cannot_write_beyond_response_bound(self):
        with tempfile.TemporaryDirectory(prefix="vhalla-api-byte-limit-") as directory:
            executable = Path(directory) / "gh"
            executable.write_text(f"#!{sys.executable}\nimport os\nos.write(1, b'x' * 8192)\nos.write(1, b'y')\n")
            executable.chmod(0o700)
            sizes = []
            original = tempfile.TemporaryFile
            @contextmanager
            def tracked_output():
                with original() as output:
                    try:
                        yield output
                    finally:
                        sizes.append(os.fstat(output.fileno()).st_size)
            with patch.dict(os.environ, {"PATH": directory + os.pathsep + os.environ["PATH"]}), \
                 patch.object(artifacts.tempfile, "TemporaryFile", tracked_output):
                with self.assertRaisesRegex(ValueError, "API failed or exceeded"):
                    artifacts.api_bytes("actions/artifacts/17", 1024)
            self.assertEqual(sizes, [1024])


class WorkflowBindingsTests(unittest.TestCase):
    def test_native_matrix_emits_only_its_own_distinct_output_names(self):
        step = WORKFLOW.split("      - name: Preserve this target's immutable producer identity\n", 1)[1]
        script = textwrap.dedent(step.split("        run: |\n", 1)[1].split("\n\n  macos_build:", 1)[0])
        with tempfile.TemporaryDirectory() as directory:
            for key, target in artifacts.RELEASE_TARGETS.items():
                if key == "MACOS":
                    continue
                output = Path(directory) / key
                result = subprocess.run(["bash", "-c", script], env={**os.environ, "TARGET": target,
                    "ARTIFACT_ID": "42", "ARTIFACT_DIGEST": "a" * 64, "GITHUB_OUTPUT": str(output)},
                    capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(output.read_text(), f"{key.lower()}_artifact_id=42\n{key.lower()}_artifact_digest={'a' * 64}\n")
                for field in ("id", "digest"):
                    self.assertIn(f"{key.lower()}_artifact_{field}: ${{{{ steps.producer.outputs.{key.lower()}_artifact_{field} }}}}", WORKFLOW)
                    self.assertIn(f"{key}_ARTIFACT_{field.upper()}: ${{{{ needs.cli.outputs.{key.lower()}_artifact_{field} }}}}", WORKFLOW)

    def test_all_upload_names_are_attempt_scoped_and_consumers_never_select_by_name(self):
        for workflow in (WORKFLOW, RUST):
            uploads = re.findall(r"uses: actions/upload-artifact@[^\n]+\n(?:(?:        id: [^\n]+\n)?|)        with:\n          name: ([^\n]+)", workflow)
            self.assertTrue(uploads)
            self.assertTrue(all(name.endswith("-${{ github.run_attempt }}") for name in uploads), uploads)
            self.assertNotIn("overwrite:", workflow)
        self.assertNotIn("actions/download-artifact", WORKFLOW)
        self.assertIn("release_artifacts.py fetch-release release-assets", WORKFLOW)
        self.assertIn("release_artifacts.py fetch-zip release-cli-aarch64-apple-darwin", WORKFLOW)

    def test_optional_browser_outputs_keep_manifest_binding_without_release_dependency(self):
        for field in ("id", "digest"):
            self.assertIn(f"value: ${{{{ jobs.browser-artifact.outputs.artifact_{field} }}}}", RUST)
            self.assertIn(f"artifact_{field}: ${{{{ steps.browser-upload.outputs.artifact-{field} }}}}", RUST)
            self.assertNotIn(f"BROWSER_ARTIFACT_{field.upper()}", WORKFLOW)
        self.assertIn('verify_browser_artifact.py browser/dist --receipt "$RUNNER_TEMP/vhalla-private-delivery-results/receipt.json"', RUST)
        self.assertIn("value: ${{ jobs.browser-artifact.outputs.manifest_sha256 }}", RUST)
        self.assertNotIn("\n  browser:", WORKFLOW)
        self.assertNotIn("valhalla-browser-", WORKFLOW)
        self.assertNotIn("needs.validate.outputs.browser_", WORKFLOW)

    def test_native_release_still_requires_validation_signing_and_fresh_runner_smoke(self):
        self.assertIn("uses: ./.github/workflows/rust.yml", WORKFLOW)
        self.assertIn("needs: [validate, cli, macos_sign, macos_smoke]", WORKFLOW)
        self.assertIn("needs: [validate, macos_build]", WORKFLOW)
        self.assertIn("needs: macos_sign", WORKFLOW)
        self.assertEqual(WORKFLOW.count("uses: actions/attest-build-provenance@"), 2)

    def test_native_release_uses_headless_features_and_preserves_windows_member_tools(self):
        self.assertIn("matrix.features || 'headless'", WORKFLOW)
        self.assertIn("--features headless --target aarch64-apple-darwin", WORKFLOW)
        self.assertIn("features: experimental-private", WORKFLOW)
        self.assertNotIn("experimental-network,experimental-sync,experimental-rooms-tui", WORKFLOW)
        self.assertIn("for command in daemon private private-host private-gateway", WORKFLOW)


class HeadlessValidationPolicyTests(unittest.TestCase):
    @staticmethod
    def job(name):
        return re.search(rf"^  {name}:\n(.*?)(?=^  \S|\Z)", RUST,
                         re.MULTILINE | re.DOTALL).group(1)

    @staticmethod
    def script(step):
        return textwrap.dedent(step.split("        run: |\n", 1)[1])

    def test_browser_input_defaults_off_for_dispatch_and_reuse(self):
        header = RUST.split("\npermissions:\n", 1)[0]
        for event in ("workflow_dispatch", "workflow_call"):
            block = re.search(rf"^  {event}:\n(.*?)(?=^  \S|\Z)", header,
                              re.MULTILINE | re.DOTALL).group(1)
            declaration = block.split("      legacy_browser:\n", 1)[1].split("\n    outputs:", 1)[0]
            self.assertIn("type: boolean", declaration)
            self.assertIn("default: false", declaration)
        self.assertIn("browser: ${{ steps.legacy-browser.outputs.selected }}", self.job("changes"))

    def test_browser_is_selected_only_for_an_explicit_relevant_run(self):
        selector = self.job("changes").split("      - name: Select legacy browser verification\n", 1)[1]
        script = self.script(selector)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "outputs"
            for requested in ("", "false", "true"):
                for rust in ("false", "true"):
                    for browser in ("false", "true"):
                        with self.subTest(requested=requested, rust=rust, browser=browser):
                            output.write_text("")
                            result = subprocess.run(["bash", "-c", script], env={**os.environ,
                                "LEGACY_BROWSER": requested, "RUST_CHANGED": rust, "BROWSER_CHANGED": browser,
                                "GITHUB_OUTPUT": str(output), "GITHUB_STEP_SUMMARY": str(Path(directory) / "summary")},
                                capture_output=True, text=True, timeout=10)
                            self.assertEqual(result.returncode, 0, result.stderr)
                            selected = requested == rust == browser == "true"
                            self.assertEqual(output.read_text(), f"selected={str(selected).lower()}\n")

    def required(self, **changes):
        states = {name: "success" for name in (
            "CHANGES", "QUALITY", "WORKSPACE_TESTS", "WINDOWS_PORTABLE", "WORKSPACE_AUX",
            "PROTOTYPES", "KANI", "DESKTOP", "SITE", "SECURITY", "FORMAL", "MAIN_POLICY",
        )}
        states.update({name: "skipped" for name in (
            "BROWSER", "BROWSER_WORKER", "BROWSER_STORAGE", "BROWSER_PUBLIC",
        )})
        states.update(RUST_CHANGED="true", FORMAL_CHANGED="true", KANI_SELECTED="true",
                      PROTOTYPE_LIST='["prototypes/fixture/Cargo.toml"]', BROWSER_SELECTED="false")
        return subprocess.run(["bash", "-c", self.script(self.job("required"))],
                              env={**os.environ, **states, **changes},
                              capture_output=True, text=True, timeout=10)

    def test_headless_required_accepts_unrequested_browser_but_keeps_all_native_gates(self):
        result = self.required()
        self.assertEqual(result.returncode, 0, result.stderr)
        for gate in ("CHANGES", "QUALITY", "WORKSPACE_TESTS", "WINDOWS_PORTABLE", "WORKSPACE_AUX",
                     "PROTOTYPES", "KANI", "DESKTOP", "SITE", "SECURITY", "FORMAL", "MAIN_POLICY"):
            for state in ("skipped", "failure", "cancelled"):
                with self.subTest(gate=gate, state=state):
                    self.assertNotEqual(self.required(**{gate: state}).returncode, 0)

    def test_requested_browser_jobs_must_all_succeed(self):
        states = {name: "success" for name in (
            "BROWSER", "BROWSER_WORKER", "BROWSER_STORAGE", "BROWSER_PUBLIC",
        )}
        self.assertEqual(self.required(BROWSER_SELECTED="true", **states).returncode, 0)
        for gate in states:
            for state in ("skipped", "failure", "cancelled"):
                with self.subTest(gate=gate, state=state):
                    self.assertNotEqual(self.required(BROWSER_SELECTED="true",
                                                     **{**states, gate: state}).returncode, 0)


if __name__ == "__main__":
    unittest.main()
