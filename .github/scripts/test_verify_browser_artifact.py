"""The release must retain the exact bytes from successful browser qualification."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from verify_browser_artifact import MAX_FILE_BYTES, verify


class BrowserArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.artifact = self.root / "production"
        self.artifact.mkdir()
        self.receipt = self.root / "receipt.json"
        self.body = b"qualified production application"
        (self.artifact / "index.html").write_bytes(self.body)
        self.manifest = {"format": 1, "purpose": "production", "assets": {
            "index.html": {"bytes": len(self.body),
                           "sha256": hashlib.sha256(self.body).hexdigest()},
        }}
        self.commit()

    def commit(self):
        raw = json.dumps(self.manifest).encode()
        (self.artifact / "artifact.json").write_bytes(raw)
        self.digest = hashlib.sha256(raw).hexdigest()
        self.receipt.write_text(json.dumps({
            "passed": True, "artifactManifestSha256": self.digest,
        }))

    def test_qualified_receipt_binds_download_verification_without_rebuilding(self):
        expected = verify(self.artifact, receipt=self.receipt)
        self.assertEqual(expected, self.digest)
        self.assertEqual(verify(self.artifact, manifest_sha256=expected), expected)
        self.assertEqual((self.artifact / "index.html").read_bytes(), self.body)

    def test_changed_asset_cannot_be_repackaged_with_a_fresh_outer_checksum(self):
        changed = b"x" * len(self.body)
        (self.artifact / "index.html").write_bytes(changed)
        with self.assertRaises(ValueError):
            verify(self.artifact, manifest_sha256=self.digest)
        self.assertEqual((self.artifact / "index.html").read_bytes(), changed)

    def test_changed_manifest_cannot_substitute_its_own_new_digest(self):
        old_digest = self.digest
        old_receipt = self.receipt.read_bytes()
        changed = b"unqualified replacement"
        (self.artifact / "index.html").write_bytes(changed)
        self.manifest["assets"]["index.html"] = {
            "bytes": len(changed), "sha256": hashlib.sha256(changed).hexdigest(),
        }
        self.commit()
        self.receipt.write_bytes(old_receipt)
        for selection in ({"receipt": self.receipt}, {"manifest_sha256": old_digest}):
            with self.subTest(selection=selection), self.assertRaises(ValueError):
                verify(self.artifact, **selection)

    def test_foreign_artifact_and_unsuccessful_or_missing_receipt_refuse(self):
        for purpose in ("local-qualification", "other"):
            self.manifest["purpose"] = purpose
            self.commit()
            with self.assertRaises(ValueError):
                verify(self.artifact, receipt=self.receipt)
        self.manifest["purpose"] = "production"
        self.commit()
        for evidence in ({}, {"passed": False, "artifactManifestSha256": self.digest},
                         {"passed": 1, "artifactManifestSha256": self.digest},
                         {"passed": True, "artifactManifestSha256": ""}):
            self.receipt.write_text(json.dumps(evidence))
            with self.subTest(evidence=evidence), self.assertRaises(ValueError):
                verify(self.artifact, receipt=self.receipt)
        self.receipt.unlink()
        with self.assertRaises(OSError):
            verify(self.artifact, receipt=self.receipt)

    def test_extra_file_or_nested_directory_cannot_enter_the_archive(self):
        for kind in ("file", "directory"):
            extra = self.artifact / "extra"
            if kind == "file":
                extra.write_bytes(b"not exercised")
            else:
                extra.mkdir()
            with self.assertRaises(ValueError):
                verify(self.artifact, manifest_sha256=self.digest)
            extra.unlink() if kind == "file" else extra.rmdir()

    def test_symlink_assets_manifests_receipts_and_root_refuse(self):
        for target in (self.artifact / "index.html", self.artifact / "artifact.json", self.receipt):
            retained = self.root / "retained"
            target.rename(retained)
            target.symlink_to(retained)
            with self.subTest(target=target), self.assertRaises(ValueError):
                verify(self.artifact, receipt=self.receipt)
            target.unlink()
            retained.rename(target)
        link = self.root / "linked-artifact"
        link.symlink_to(self.artifact, target_is_directory=True)
        with self.assertRaises(ValueError):
            verify(link, manifest_sha256=self.digest)

    def test_bounded_flat_manifest_refuses_ambiguous_or_impossible_entries(self):
        original = self.manifest["assets"]["index.html"].copy()
        for change in ({"bytes": True}, {"bytes": MAX_FILE_BYTES + 1},
                       {"sha256": "A" * 64}, {"unqualified": True}):
            self.manifest["assets"]["index.html"] = original | change
            self.commit()
            with self.subTest(change=change), self.assertRaises(ValueError):
                verify(self.artifact, receipt=self.receipt)
        raw = b'{"format":1,"format":1,"purpose":"production","assets":{}}'
        (self.artifact / "artifact.json").write_bytes(raw)
        with self.assertRaises(ValueError):
            verify(self.artifact, manifest_sha256=hashlib.sha256(raw).hexdigest())


if __name__ == "__main__":
    unittest.main()
