"""Release signing must use exact tagged main source on isolated runners."""
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = (ROOT / ".github/workflows/release.yml").read_text()
SIGNER = WORKFLOW.split("\n  macos_sign:", 1)[1].split("\n  macos_smoke:", 1)[0]
ADMISSION = textwrap.dedent(SIGNER.split("      - name: Require the exact version tag at verified main source\n", 1)[1]
                           .split("        run: |\n", 1)[1].split("      - name: Download exact", 1)[0])


class SigningSourceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="vhalla-signing-source-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.environment = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                            "GIT_AUTHOR_NAME": "Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                            "GIT_COMMITTER_NAME": "Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid"}
        self.git("init", "-q", "-b", "main", cwd=self.source)
        (self.source / "content").write_text("version one")
        self.git("add", "content", cwd=self.source)
        self.git("commit", "-qm", "source", cwd=self.source)
        self.sha = self.git("rev-parse", "HEAD", cwd=self.source)
        self.git("tag", "v0.2.11", cwd=self.source)
        self.checkout = self.root / "checkout"
        self.git("clone", "--no-local", "--quiet", str(self.source), str(self.checkout), cwd=self.root)

    def git(self, *arguments, cwd):
        return subprocess.run(["git", *arguments], cwd=cwd, env=self.environment,
                              check=True, capture_output=True, text=True, timeout=15).stdout.strip()

    def admit(self, ref="refs/tags/v0.2.11", sha=None):
        return subprocess.run(["bash", "-c", ADMISSION], cwd=self.checkout,
                              env={**self.environment, "GITHUB_REF": ref, "GITHUB_REF_NAME": "v0.2.11",
                                   "GITHUB_SHA": sha or self.sha}, capture_output=True, text=True, timeout=30)

    def test_exact_tag_on_main_passes(self):
        result = self.admit()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_branch_and_other_event_source_fail(self):
        self.assertNotEqual(self.admit(ref="refs/heads/main").returncode, 0)
        self.assertNotEqual(self.admit(sha="0" * 40).returncode, 0)

    def test_moved_main_or_tag_fails(self):
        (self.source / "content").write_text("version two")
        self.git("commit", "-qam", "advance", cwd=self.source)
        self.assertNotEqual(self.admit().returncode, 0)
        self.git("tag", "-f", "v0.2.11", cwd=self.source)
        self.git("reset", "--hard", self.sha, cwd=self.source)
        self.assertNotEqual(self.admit().returncode, 0)

    def test_signer_has_no_build_or_payload_execution(self):
        self.assertIn("environment: hraness-apple-release", SIGNER)
        for forbidden in ("cargo", '"$cli"', "--help", "--version"):
            self.assertNotIn(forbidden, SIGNER)
        self.assertIn("if: always()", SIGNER)
        self.assertIn("release_artifacts.py fetch-zip vhalla-unsigned", SIGNER)
        smoke = WORKFLOW.split("\n  macos_smoke:", 1)[1].split("\n  publish:", 1)[0]
        self.assertNotIn("secrets.", smoke)
        self.assertNotIn("environment:", smoke)
        self.assertIn("extract-signed", smoke)
        self.assertIn("MACOS_ARCHIVE_SHA256: ${{ needs.macos_sign.outputs.archive_sha256 }}", WORKFLOW)


if __name__ == "__main__":
    unittest.main()
