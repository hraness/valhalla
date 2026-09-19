"""Failure paths must leave public releases untouched."""

import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from publish_release import CODEQL_CHECKS, asset_names, publish


TAG = "v0.1.7"
SHA = "a" * 40
REPO = "hraness/valhalla"


class FakeGitHub:
    def __init__(self, assets):
        self.assets = assets
        self.calls = []
        self.main = SHA
        self.tag = {"type": "commit", "sha": SHA}
        self.annotated = None
        self.release = None
        self.upload_fails = False
        self.corrupt_download = False
        self.advance_main_after_upload = False
        self.checks = [dict(id=index, name=name, head_sha=SHA, status="completed",
                            conclusion="success", app={"slug": "github-actions"})
                       for index, name in enumerate(sorted(CODEQL_CHECKS), 1)]

    def __call__(self, *args):
        self.calls.append(args)
        if args[0] == "api":
            path = args[1].removeprefix(f"repos/{REPO}/")
            if path == "git/ref/heads/main":
                return json.dumps({"object": {"sha": self.main}})
            if path == f"git/ref/tags/{TAG}":
                return json.dumps({"object": self.tag})
            if path.startswith("git/tags/"):
                return json.dumps({"object": self.annotated})
            if path.startswith("commits/"):
                # Required checks span pages, as on an actual busy CI commit.
                return json.dumps([{"check_runs": self.checks[:2]}, {"check_runs": self.checks[2:]}])
            if path == "releases?per_page=100":
                return json.dumps([[self.release] if self.release else []])
            raise AssertionError(f"unexpected API request: {args}")
        if args[:2] == ("release", "upload"):
            if self.upload_fails:
                raise subprocess.CalledProcessError(1, args)
            if self.advance_main_after_upload:
                self.main = "b" * 40
        elif args[:2] == ("release", "download"):
            destination = Path(args[args.index("--dir") + 1])
            for path in self.assets.iterdir():
                shutil.copy2(path, destination / path.name)
            if self.corrupt_download:
                next(destination.glob("*.tar.gz")).write_bytes(b"incomplete upload")
        return ""

    def mutations(self):
        return [args[1] for args in self.calls
                if args[0] == "release" and args[1] in {"create", "upload", "edit"}]


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.assets = Path(self.temporary.name)
        for name in asset_names(TAG):
            if name.endswith(".tar.gz"):
                content = name.encode()
                (self.assets / name).write_bytes(content)
                (self.assets / (name + ".sha256")).write_text(
                    f"{hashlib.sha256(content).hexdigest()}  {name}\n")
        self.gh = FakeGitHub(self.assets)

    def run_publish(self):
        with contextlib.redirect_stdout(io.StringIO()):
            publish(self.assets, TAG, SHA, REPO, self.gh)

    def test_complete_release_is_verified_before_publication(self):
        self.run_publish()
        self.assertEqual(self.gh.mutations(), ["create", "upload", "edit"])
        commands = [args[:2] for args in self.gh.calls]
        self.assertLess(commands.index(("release", "download")), commands.index(("release", "edit")))
        self.assertIn("--draft", next(args for args in self.gh.calls if args[:2] == ("release", "create")))

    def test_missing_artifact_blocks_all_network_access(self):
        next(self.assets.glob("*.tar.gz")).unlink()
        with self.assertRaises(ValueError):
            self.run_publish()
        self.assertEqual(self.gh.calls, [])

    def test_checksum_mismatch_blocks_all_network_access(self):
        next(self.assets.glob("*.tar.gz")).write_bytes(b"corrupt")
        with self.assertRaises(ValueError):
            self.run_publish()
        self.assertEqual(self.gh.calls, [])

    def test_non_main_or_moved_tag_blocks_mutations(self):
        for field in ("main", "tag"):
            with self.subTest(field=field):
                gh = FakeGitHub(self.assets)
                setattr(gh, field, "b" * 40 if field == "main" else {"type": "commit", "sha": "b" * 40})
                with self.assertRaises(ValueError):
                    publish(self.assets, TAG, SHA, REPO, gh)
                self.assertEqual(gh.mutations(), [])

    def test_annotated_tag_is_peeled(self):
        self.gh.tag = {"type": "tag", "sha": "b" * 40}
        self.gh.annotated = {"type": "commit", "sha": SHA}
        self.run_publish()
        self.assertEqual(self.gh.mutations()[-1], "edit")

    def test_missing_failed_foreign_stale_or_pending_codeql_blocks_mutations(self):
        for change in ("missing", "failure", "foreign", "stale", "pending"):
            with self.subTest(change=change):
                gh = FakeGitHub(self.assets)
                check = gh.checks[0]
                if change == "missing":
                    gh.checks.pop(0)
                elif change == "failure":
                    check["conclusion"] = "failure"
                elif change == "foreign":
                    check["app"]["slug"] = "third-party"
                elif change == "stale":
                    check["head_sha"] = "b" * 40
                else:
                    check["status"] = "in_progress"
                with self.assertRaises(ValueError):
                    publish(self.assets, TAG, SHA, REPO, gh)
                self.assertEqual(gh.mutations(), [])

    def test_new_failed_codeql_retry_overrides_older_success(self):
        newer = copy.deepcopy(self.gh.checks[0])
        newer.update(id=100, conclusion="failure")
        self.gh.checks.insert(0, newer)
        with self.assertRaises(ValueError):
            self.run_publish()
        self.assertEqual(self.gh.mutations(), [])

    def test_partial_upload_never_publishes(self):
        self.gh.upload_fails = True
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_publish()
        self.assertEqual(self.gh.mutations(), ["create", "upload"])

    def test_corrupt_download_never_publishes(self):
        self.gh.corrupt_download = True
        with self.assertRaises(ValueError):
            self.run_publish()
        self.assertNotIn("edit", self.gh.mutations())

    def test_main_moving_during_upload_leaves_draft(self):
        self.gh.advance_main_after_upload = True
        with self.assertRaises(ValueError):
            self.run_publish()
        self.assertEqual(self.gh.mutations(), ["create", "upload"])

    def test_existing_draft_is_completed(self):
        self.gh.release = {"tag_name": TAG, "draft": True}
        self.run_publish()
        self.assertEqual(self.gh.mutations(), ["upload", "edit"])

    def test_published_release_retry_is_read_only(self):
        self.gh.release = {"tag_name": TAG, "draft": False}
        self.run_publish()
        self.assertEqual(self.gh.mutations(), [])

    def test_published_release_with_different_bytes_is_never_overwritten(self):
        self.gh.release = {"tag_name": TAG, "draft": False}
        self.gh.corrupt_download = True
        with self.assertRaises(ValueError):
            self.run_publish()
        self.assertEqual(self.gh.mutations(), [])


if __name__ == "__main__":
    unittest.main()
