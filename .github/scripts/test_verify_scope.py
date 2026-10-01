"""The verification selector narrows only when it can prove the narrower scope."""
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import re
import tempfile
import textwrap
import unittest

import verify_scope
from verify_scope import main, select

REPO = Path(__file__).resolve().parents[2]
PR = ("pull_request", "refs/pull/1/merge")
ALL_PROTOTYPES = sorted(p.relative_to(REPO).as_posix() for p in (REPO / "prototypes").glob("*/Cargo.toml"))


def pr(*paths, repo=REPO):
    return select(repo, *PR, list(paths))


class RealRepositoryTests(unittest.TestCase):
    def assert_full(self, selection):
        self.assertTrue(selection.full, selection.reasons)
        self.assertEqual(selection.prototypes, ALL_PROTOTYPES)
        self.assertTrue(selection.kani and selection.browser and selection.formal)

    def test_touched_prototype_runs_only_that_prototype(self):
        selection = pr("prototypes/room-registry/src/lib.rs")
        self.assertFalse(selection.full)
        self.assertEqual(selection.prototypes, ["prototypes/room-registry/Cargo.toml"])
        self.assertFalse(selection.kani or selection.browser or selection.formal)

    def test_shared_crate_selects_every_dependent_prototype_and_group(self):
        selection = pr("crates/vhalla-core/src/lib.rs")
        self.assertFalse(selection.full)
        for manifest in ("checkpoint-ledger", "social-retrieval", "discovery-parity", "relay-tls"):
            self.assertIn(f"prototypes/{manifest}/Cargo.toml", selection.prototypes)
        self.assertNotIn("prototypes/room-registry/Cargo.toml", selection.prototypes)
        self.assertTrue(selection.kani)
        self.assertTrue(selection.browser)
        self.assertFalse(selection.formal)

    def test_transitive_dependency_selects_kani(self):
        # vhalla-native -> vhalla-identity -> vhalla-crypto
        self.assertTrue(pr("crates/vhalla-crypto/src/lib.rs").kani)

    def test_crate_outside_scoped_closures_selects_nothing(self):
        selection = pr("crates/vhalla-policy/src/lib.rs")
        self.assertFalse(selection.full)
        self.assertEqual(selection.prototypes, [])
        self.assertFalse(selection.kani or selection.browser or selection.formal)

    def test_ledger_selects_its_prototype_but_not_kani_or_browser(self):
        selection = pr("crates/vhalla-ledger/src/lib.rs")
        self.assertEqual(selection.prototypes, ["prototypes/checkpoint-ledger/Cargo.toml"])
        self.assertFalse(selection.kani or selection.browser)

    def test_browser_sources_select_browser(self):
        selection = pr("browser/src/ui.rs")
        self.assertTrue(selection.browser)
        self.assertFalse(selection.kani)

    def test_relative_file_reads_are_inputs(self):
        # vhalla-browser-storage's recovery example includes these files.
        self.assertTrue(pr("prototypes/browser-archive-recovery/journey.rs").browser)
        # vhalla-cli (built by the browser artifact job) includes the Lean corpus.
        selection = pr("verify/lean/corpus.json")
        self.assertTrue(selection.browser)
        self.assertTrue(selection.formal)
        self.assertTrue(pr(".github/scripts/verify_browser_artifact.py").browser)
        # vhalla-cli's tests run the seed recipe's entry point; the rest of deploy/ is docs and images.
        self.assertTrue(pr("deploy/rooms-seed/start.sh").browser)
        selection = pr("deploy/rooms-seed/README.md", "deploy/rooms-seed/Dockerfile")
        self.assertFalse(selection.full or selection.browser or selection.prototypes)

    def test_formal_inputs(self):
        self.assertTrue(pr("verify/relay-quota/quota.rs").formal)
        self.assertTrue(pr("docs/private-rotation-contract.md").formal)
        self.assertTrue(pr("crates/vhalla-private-kernel/src/engine.rs").formal)
        self.assertFalse(pr("docs/release-readiness.md").formal)
        self.assertFalse(pr("crates/vhalla-policy/src/lib.rs").formal)

    def test_unrelated_changes_skip_every_group(self):
        selection = pr("site/index.html", "kb/notes/x.md", "README.md", "package.json", ".github/dependabot.yml",
                       "prototypes/agent-compartment/broker.py")
        self.assertFalse(selection.full)
        self.assertEqual(selection.prototypes, [])
        self.assertFalse(selection.kani or selection.browser or selection.formal)

    def test_retired_prototypes_are_manual_only(self):
        self.assertNotIn("prototypes/retired/botcaptcha/Cargo.toml", ALL_PROTOTYPES)
        self.assertTrue((REPO / "prototypes/retired/botcaptcha/Cargo.toml").is_file())
        self.assertTrue((REPO / "prototypes/retired/README.md").is_file())
        selection = pr("prototypes/retired/botcaptcha/src/lib.rs")
        self.assertFalse(selection.full)
        self.assertEqual(selection.prototypes, [])

    def test_global_inputs_run_everything(self):
        for path in ("Cargo.lock", "Cargo.toml", ".github/workflows/rust.yml", ".github/workflows/verification.yml",
                     ".github/scripts/verify_scope.py", ".github/scripts/test_verify_scope.py",
                     "vendor/libp2p-dns/src/lib.rs", "vectors/witness-v1.json", "rust-toolchain.toml"):
            with self.subTest(path=path):
                self.assert_full(pr("site/index.html", path))

    def test_unmapped_paths_run_everything(self):
        for path in ("newdir/file.rs", "crates/vhalla-gone/src/lib.rs", ".gitattributes",
                     "prototypes/new-top-level-file.rs", "crates/../Cargo.lock", "/etc/passwd"):
            with self.subTest(path=path):
                self.assert_full(pr(path))

    def test_missing_or_empty_change_lists_run_everything(self):
        self.assert_full(select(REPO, *PR, None))
        self.assert_full(select(REPO, *PR, []))
        self.assert_full(select(REPO, *PR, ["", "  "]))

    def test_only_pull_requests_and_main_pushes_are_scoped(self):
        self.assertFalse(select(REPO, "push", "refs/heads/main", ["site/x"]).full)
        for event, ref in (("schedule", "refs/heads/main"), ("workflow_dispatch", "refs/heads/main"),
                           ("push", "refs/tags/v0.3.0"), ("push", "refs/heads/other"), ("merge_group", "x")):
            with self.subTest(event=event, ref=ref):
                self.assert_full(select(REPO, event, ref, ["site/x"]))

    def test_non_rust_filter_clears_rust_groups_but_keeps_formal(self):
        selection = select(REPO, *PR, ["docs/private-rotation-contract.md"], rust=False)
        self.assertEqual(selection.prototypes, [])
        self.assertFalse(selection.kani or selection.browser)
        self.assertTrue(selection.formal)

    def test_cli_writes_github_outputs(self):
        with tempfile.TemporaryDirectory() as temp:
            changed = Path(temp) / "changed.txt"
            changed.write_text("prototypes/room-registry/src/lib.rs\n")
            output = Path(temp) / "out"
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--event", "pull_request", "--ref", "r", "--changed-files", str(changed),
                                       "--output", str(output)]), 0)
            values = dict(line.split("=", 1) for line in output.read_text().splitlines())
            self.assertEqual(values["scope"], "scoped")
            self.assertEqual(json.loads(values["prototypes"]), ["prototypes/room-registry/Cargo.toml"])
            self.assertEqual(values["kani"], "false")
            with redirect_stdout(io.StringIO()):
                main(["--event", "pull_request", "--ref", "r", "--changed-files", str(Path(temp) / "missing"),
                      "--output", str(output)])
            values = dict(line.split("=", 1) for line in output.read_text().splitlines())
            self.assertEqual(values["scope"], "full")


class SyntheticRepositoryTests(unittest.TestCase):
    """Closure rules on a small repository independent of today's crates."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name)
        self.write("Cargo.toml", """
            [workspace]
            members = ["crates/*"]
            exclude = ["prototypes/*"]
            [workspace.dependencies]
            shared = { path = "crates/shared" }
        """)
        self.write("crates/shared/Cargo.toml", "[package]\nname = 'shared'\n")
        self.write("crates/shared/src/lib.rs", "")
        self.write("crates/leaf/Cargo.toml", "[package]\nname = 'leaf'\n")
        self.write("crates/leaf/src/lib.rs", 'const X: &str = include_str!("../../../fixtures/leaf.json");\n'
                   'const Y: &str = "../..";\n')
        self.write("crates/vhalla-native/Cargo.toml", """
            [package]
            name = "vhalla-native"
            [dependencies]
            shared = { workspace = true }
            [target.'cfg(unix)'.dev-dependencies]
            leaf = { path = "../leaf" }
        """)
        self.write("crates/vhalla-native/src/lib.rs", "")
        self.write("prototypes/alpha/Cargo.toml", """
            [package]
            name = "alpha"
            [build-dependencies]
            leaf = { path = "../../crates/leaf" }
        """)
        self.write("prototypes/alpha/src/lib.rs", "")
        self.write("prototypes/beta/Cargo.toml", "[package]\nname = 'beta'\n")
        self.write("prototypes/beta/src/lib.rs", "")
        for package in verify_scope.BROWSER_PACKAGES:
            self.write(f"{package}/Cargo.toml", f"[package]\nname = '{package.replace('/', '-')}'\n")
        self.write("verify/cases.json", json.dumps({"suites": [{"sources": [{"path": "docs/contract.md"}]}]}))
        self.write("verify/lean/claims.json", json.dumps({"correspondence_sources": ["crates/shared/src/lib.rs"]}))

    def tearDown(self):
        self.temp.cleanup()

    def write(self, path, text):
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(textwrap.dedent(text))

    def test_workspace_target_and_build_dependencies_are_followed(self):
        selection = pr("crates/leaf/src/lib.rs", repo=self.repo)
        self.assertEqual(selection.prototypes, ["prototypes/alpha/Cargo.toml"])
        self.assertTrue(selection.kani)
        self.assertTrue(pr("crates/shared/src/lib.rs", repo=self.repo).kani)
        self.assertTrue(pr("crates/shared/src/lib.rs", repo=self.repo).formal)
        self.assertEqual(pr("prototypes/beta/src/lib.rs", repo=self.repo).prototypes, ["prototypes/beta/Cargo.toml"])

    def test_relative_reads_extend_the_closure_without_ancestors(self):
        selection = pr("fixtures/leaf.json", repo=self.repo)
        self.assertFalse(selection.full)
        self.assertEqual(selection.prototypes, ["prototypes/alpha/Cargo.toml"])
        self.assertTrue(selection.kani)
        references = verify_scope.Graph(self.repo).referenced_files("crates/leaf")
        self.assertEqual(references, {"fixtures/leaf.json"})

    def test_docs_correspondence_selects_formal(self):
        self.assertTrue(pr("docs/contract.md", repo=self.repo).formal)
        self.assertFalse(pr("docs/other.md", repo=self.repo).formal)

    def test_broken_manifest_runs_everything(self):
        self.write("crates/leaf/Cargo.toml", "[package\n")
        selection = pr("prototypes/beta/src/lib.rs", repo=self.repo)
        self.assertTrue(selection.full)
        self.assertIn("selector error", selection.reasons[0])
        self.assertEqual(selection.prototypes, sorted(p.relative_to(self.repo).as_posix()
                                                   for p in self.repo.glob("prototypes/*/Cargo.toml")))

    def test_dependency_outside_repository_runs_everything(self):
        self.write("prototypes/beta/Cargo.toml", "[package]\nname='beta'\n[dependencies]\nx = { path = '../../../x' }\n")
        self.assertTrue(pr("prototypes/beta/src/lib.rs", repo=self.repo).full)

    def test_missing_formal_manifest_runs_everything(self):
        (self.repo / "verify/cases.json").unlink()
        self.assertTrue(pr("prototypes/beta/src/lib.rs", repo=self.repo).full)


class WorkflowWiringTests(unittest.TestCase):
    """The workflow must consume every selector output and keep Required fail-closed."""

    def setUp(self):
        self.rust = (REPO / ".github/workflows/rust.yml").read_text()

    def test_scoped_jobs_use_selector_outputs(self):
        self.assertIn("fromJSON(needs.changes.outputs.prototypes)", self.rust)
        self.assertIn("python3 .github/scripts/verify_scope.py", self.rust)
        for job in ("kani-spent", "browser-artifact", "browser-worker", "browser-storage", "browser-public"):
            block = re.search(rf"^  {job}:\n(.*?)(?=^  \S)", self.rust, re.MULTILINE | re.DOTALL).group(1)
            output = "kani" if job == "kani-spent" else "browser"
            self.assertIn(f"needs.changes.outputs.{output} == 'true'", block, job)

    def test_required_checks_each_scoped_group(self):
        required = re.search(r"^  required:\n(.*?)(?=^  \S)", self.rust, re.MULTILINE | re.DOTALL).group(1)
        for line in ('filtered prototype-checks "$PROTOTYPES" "$PROTOTYPES_SELECTED"',
                     'filtered kani-spent "$KANI" "$KANI_SELECTED"',
                     'filtered browser-artifact "$BROWSER" "$BROWSER_SELECTED"',
                     'filtered formal "$FORMAL" "$FORMAL_CHANGED"'):
            self.assertIn(line, required)

    def test_nightly_runs_the_full_gate_and_reports_failures(self):
        nightly = (REPO / ".github/workflows/nightly.yml").read_text()
        self.assertIn("schedule:", nightly)
        self.assertIn("uses: ./.github/workflows/rust.yml", nightly)
        self.assertIn("issues: write", nightly)
        self.assertIn("cancel-in-progress: false", nightly)
        dispatch = nightly.split("  workflow_dispatch:", 1)[1].split("\npermissions:", 1)[0]
        self.assertIn("legacy_browser:", dispatch)
        self.assertIn("type: boolean", dispatch)
        self.assertIn("default: false", dispatch)
        self.assertIn(
            "legacy_browser: ${{ github.event_name == 'workflow_dispatch' && inputs.legacy_browser }}",
            nightly,
        )


if __name__ == "__main__":
    unittest.main()
