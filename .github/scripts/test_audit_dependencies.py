import copy
import contextlib
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from audit_dependencies import ARCHIVE, MANIFESTS, active_packages, resolved_packages, audit, classify, discover_manifests, validate_report, verify_archive


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.metadata = {
            "version": 1,
            "packages": [{"id": "root", "name": "application", "version": "1.0.0"},
                         {"id": "safe", "name": "hickory-proto", "version": "0.26.3"},
                         {"id": "old", "name": "hickory-proto", "version": "0.25.2"}],
            "workspace_members": ["root"],
            "resolve": {"nodes": [{"id": "root", "dependencies": ["safe"]},
                                    {"id": "safe", "dependencies": []}]},
        }
        self.finding = {"package": {"name": "hickory-proto", "version": "0.25.2"},
                        "advisory": {"id": "RUSTSEC-2026-0119", "title": "CPU exhaustion"}}
        self.report = {
            "settings": {"ignore": [], "target_arch": [], "target_os": [], "severity": None,
                         "informational_warnings": ["unmaintained", "unsound", "notice"]},
            "database": {"advisory-count": 1251},
            "vulnerabilities": {"found": True, "count": 1, "list": [self.finding]},
            "warnings": {"unsound": [{"warning": "retained"}]},
        }

    def test_inactive_optional_dependency_retains_its_finding(self):
        # Metadata can include a weak optional dependency absent from the
        # feature-enabled tree. Keep its raw advisory without claiming activation.
        self.metadata["resolve"]["nodes"].append({"id": "old", "dependencies": []})
        active = active_packages(self.metadata, "application v1.0.0\nhickory-proto v0.26.3\n")
        result = classify(self.report, 1, active)
        self.assertEqual(result, [(self.finding, False)])
        self.assertEqual(self.report["warnings"], {"unsound": [{"warning": "retained"}]})

    def test_future_mdns_activation_fails_even_with_safe_version_also_present(self):
        self.metadata["resolve"]["nodes"][0]["dependencies"].append("old")
        self.metadata["resolve"]["nodes"].append({"id": "old", "dependencies": []})
        active = active_packages(self.metadata, "application v1.0.0\nhickory-proto v0.26.3\nhickory-proto v0.25.2\n")
        self.assertTrue(classify(self.report, 1, active)[0][1])

    def test_tree_annotations_are_checked_and_duplicates_preserve_packages(self):
        tree = ("application v1.0.0 (/local workspace/application)\n"
                "[build-dependencies]\nhickory-proto v0.26.3 (proc-macro)\n"
                "[dev-dependencies]\nhickory-proto v0.26.3 (https://example.com/repo?rev=abc#abc) (*)\n\n")
        self.assertEqual(active_packages(self.metadata, tree),
                         {("application", "1.0.0"), ("hickory-proto", "0.26.3")})

    def test_malformed_truncated_or_unknown_tree_fails_closed(self):
        for tree in ("", "application v1.0.0\n...\n", "application v1.0.0 (unrecognized)\n",
                     "application v1.0.0\nhickory-proto v0.26\n", "application v1.0.0 (**)\n",
                     "hickory-proto v0.26.3\n", "application v1.0.0\nhidden v1.0.0\n",
                     "application v1.0.0\n[features]\n"):
            with self.subTest(tree=tree), self.assertRaises(ValueError):
                active_packages(self.metadata, tree)

    def test_all_resolved_targets_are_checked_without_host_filtering(self):
        self.metadata["resolve"]["nodes"].append({"id": "old", "dependencies": []})
        self.assertIn(("hickory-proto", "0.25.2"), resolved_packages(self.metadata))

    def test_unknown_node_duplicate_or_broken_edge_is_rejected(self):
        for change in ("unknown", "duplicate", "edge", "missing_root"):
            with self.subTest(change=change):
                data = copy.deepcopy(self.metadata)
                if change == "unknown":
                    data["resolve"]["nodes"].append({"id": "missing", "dependencies": []})
                elif change == "duplicate":
                    data["packages"].append(data["packages"][0])
                elif change == "edge":
                    data["resolve"]["nodes"][0]["dependencies"].append("missing")
                else:
                    data["workspace_members"] = ["missing"]
                with self.assertRaises(ValueError):
                    resolved_packages(data)

    def test_hidden_advisories_or_targets_are_rejected(self):
        for field, value in [("ignore", ["RUSTSEC-2026-0119"]), ("target_os", ["linux"]),
                             ("target_arch", ["x86_64"]), ("severity", "high"),
                             ("informational_warnings", [])]:
            with self.subTest(field=field):
                data = copy.deepcopy(self.report)
                data["settings"][field] = value
                with self.assertRaises(ValueError):
                    validate_report(data, 1)

    def test_tool_failure_or_inconsistent_result_fails_closed(self):
        for code in (0, 2, -9):
            with self.subTest(code=code), self.assertRaises(ValueError):
                validate_report(self.report, code)
        self.report["vulnerabilities"]["count"] = 0
        with self.assertRaises(ValueError):
            validate_report(self.report, 1)

    def test_missing_report_schema_fails_closed(self):
        del self.report["vulnerabilities"]["list"]
        with self.assertRaises(KeyError):
            validate_report(self.report, 1)

    def test_clean_report_requires_successful_tool_exit(self):
        self.report["vulnerabilities"] = {"list": [], "count": 0, "found": False}
        self.assertEqual(validate_report(self.report, 0), [])
        with self.assertRaises(ValueError):
            validate_report(self.report, 1)

    def test_gate_preserves_every_report_and_blocks_future_activation(self):
        self.metadata["resolve"]["nodes"].append({"id": "old", "dependencies": []})
        report = copy.deepcopy(self.report)
        report["warnings"] = {}
        calls = []

        def fake_run(args, cwd):
            calls.append(args)
            metadata = args[:2] == ["cargo", "metadata"]
            if args[:2] == ["cargo", "tree"]:
                return subprocess.CompletedProcess(args, 0, "application v1.0.0\nhickory-proto v0.26.3\nhickory-proto v0.25.2\n", "")
            return subprocess.CompletedProcess(args, 0 if metadata else 1,
                                               json.dumps(self.metadata if metadata else report), "")

        with tempfile.TemporaryDirectory() as temporary, patch("audit_dependencies.run", fake_run), \
                patch("audit_dependencies.discover_manifests", return_value=MANIFESTS), \
                patch("audit_dependencies.verify_archive"), contextlib.redirect_stdout(io.StringIO()) as log:
            output = Path(temporary) / "reports"
            with self.assertRaisesRegex(ValueError, "active dependency vulnerabilities"):
                audit(Path(temporary), output)
            self.assertEqual(len(list(output.glob("*.audit.json"))), len(MANIFESTS) + 1)
            self.assertIn("ACTIVE VULNERABILITY", log.getvalue())
            self.assertIn("ARCHIVED VULNERABILITY", log.getvalue())
        metadata_calls = [args for args in calls if args[:2] == ["cargo", "metadata"]]
        self.assertEqual(len(metadata_calls), len(MANIFESTS))
        for args in metadata_calls:
            self.assertIn("--all-features", args)
            self.assertIn("--locked", args)
            self.assertNotIn("--filter-platform", args)
        tree_calls = [args for args in calls if args[:2] == ["cargo", "tree"]]
        self.assertEqual(len(tree_calls), len(MANIFESTS))
        for args in tree_calls:
            self.assertEqual(args[4:], ["--workspace", "--all-features", "--target", "all",
                                       "--locked", "--color", "never", "--edges", "normal,build,dev",
                                       "--prefix", "none", "--format", "{p}"])

    def test_metadata_or_tree_tool_failure_blocks_gate(self):
        report = copy.deepcopy(self.report)
        report["warnings"] = {}
        for failed in ("metadata", "tree"):
            def fake_run(args, cwd):
                if args[:2] == ["cargo", failed]:
                    return subprocess.CompletedProcess(args, 101, "", "tool failed")
                return subprocess.CompletedProcess(args, 0 if args[0] == "cargo" else 1,
                                                   json.dumps(self.metadata if args[0] == "cargo" else report), "")
            with self.subTest(tool=failed), tempfile.TemporaryDirectory() as temporary, \
                    patch("audit_dependencies.run", fake_run), \
                    patch("audit_dependencies.discover_manifests", return_value=MANIFESTS), \
                    contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(ValueError, f"Cargo {failed} failed"):
                    audit(Path(temporary), Path(temporary) / "reports")

    def test_real_cargo_weak_optional_feature_and_later_activation(self):
        cargo = shutil.which("cargo")
        self.assertIsNotNone(cargo, "Cargo is required for the offline feature-graph regression")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Cargo.toml").write_text(
                '[workspace]\nresolver = "2"\nmembers = ["application"]\nexclude = ["bridge", "leaf"]\n')
            manifests = {
                "application": '[dependencies]\nbridge = { path = "../bridge", features = ["runtime"] }\n',
                "bridge": ('[dependencies]\nleaf = { path = "../leaf", optional = true }\n'
                           '[features]\nruntime = ["leaf?/runtime"]\n'),
                "leaf": '[features]\nruntime = []\n',
            }
            for name, extra in manifests.items():
                path = root / name
                (path / "src").mkdir(parents=True)
                (path / "src/lib.rs").write_text("")
                (path / "Cargo.toml").write_text(
                    f'[package]\nname = "{name}"\nversion = "1.0.0"\nedition = "2021"\n' + extra)

            def checked(*args):
                result = subprocess.run([cargo, *args], cwd=root, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                return result.stdout

            checked("generate-lockfile", "--offline")
            for enabled in (False, True):
                if enabled:
                    with (root / "application/Cargo.toml").open("a") as manifest:
                        manifest.write('[features]\nnetwork = ["bridge/leaf"]\n')
                metadata = json.loads(checked("metadata", "--all-features", "--locked", "--offline", "--format-version", "1"))
                tree = checked("tree", "--workspace", "--all-features", "--target", "all",
                               "--locked", "--offline", "--color", "never", "--edges", "normal,build,dev",
                               "--prefix", "none", "--format", "{p}")
                active = active_packages(metadata, tree)
                self.assertEqual(("leaf", "1.0.0") in active, enabled)
                report = copy.deepcopy(self.report)
                report["vulnerabilities"]["list"][0]["package"] = {"name": "leaf", "version": "1.0.0"}
                self.assertEqual(classify(report, 1, active)[0][1], enabled)

    def test_archive_exception_requires_unchanged_lockfile(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / ARCHIVE
            archive.mkdir(parents=True)
            (archive / "Cargo.lock").write_bytes(b"historical")
            (archive / "SHA256SUMS").write_text(
                f"{hashlib.sha256(b'historical').hexdigest()}  Cargo.lock\n")
            verify_archive(root)
            (archive / "Cargo.lock").write_bytes(b"modified")
            with self.assertRaises(ValueError):
                verify_archive(root)

    def test_new_nested_prototype_lock_is_discovered_but_generated_and_archive_are_not(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            additions = ("prototypes/new-one/Cargo.toml", "prototypes/nested/demo/Cargo.toml")
            omitted = ("prototypes/new-one/target/generated/Cargo.toml", str(ARCHIVE / "Cargo.toml"))
            for manifest in (*MANIFESTS, *additions, *omitted):
                path = root / manifest
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("[package]\n")
                path.with_name("Cargo.lock").write_text("version = 4\n")
            self.assertEqual(set(discover_manifests(root)), set(MANIFESTS) | set(additions))


if __name__ == "__main__":
    unittest.main()
