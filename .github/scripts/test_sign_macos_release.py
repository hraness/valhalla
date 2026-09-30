#!/usr/bin/env python3
"""Behavioral tests use mocked Apple tools; no credentials or signing service."""
import base64
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

SPEC = importlib.util.spec_from_file_location("signing", Path(__file__).with_name("sign_macos_release.py"))
signing = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(signing)
TEAM = "A1B2C3D4E5"
VERSION = "0.2.11"
UUID = "12345678-1234-1234-1234-123456789abc"


class SigningTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="vhalla-signing-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.work = self.root / "vhalla-apple-signing"
        self.output = self.root / "signed-artifacts"
        self.archive = self.root / signing.archive_name(VERSION, unsigned=True)
        self.binary = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 0, 0, 0, 0) + b"not executable"
        self.native_archive()
        self.calls = []
        self.status = "Accepted"
        self.wait_id = UUID
        self.metadata = ("Identifier=dev.hraness.vhalla\nTeamIdentifier=" + TEAM + "\n"
                         "CodeDirectory v=20500 size=100 flags=0x10000(runtime) hashes=2+7 location=embedded\n"
                         "Timestamp=Sep 30, 2026 at 2:00:00 AM\n")
        self.identity_team = TEAM
        self.tool_failure = None
        self.environment = {
            "RUNNER_TEMP": str(self.root), "HOME": str(self.root),
            "APPLE_DEVELOPER_ID_P12_BASE64": base64.b64encode(b"fake private p12").decode(),
            "APPLE_DEVELOPER_ID_P12_PASSWORD": "never-print-me",
            "APPLE_NOTARY_KEY_P8_BASE64": base64.b64encode(b"fake private p8").decode(),
            "APPLE_NOTARY_KEY_ID": "ABCDE12345", "APPLE_NOTARY_ISSUER_ID": UUID,
        }
        for active in (patch.dict(os.environ, self.environment), patch.object(signing, "TEAM_ID", TEAM),
                       patch.object(signing.sys, "platform", "darwin"), patch.object(signing, "run", self.tool)):
            active.start()
            self.addCleanup(active.stop)

    def native_archive(self, extra=False, symlink=False):
        with tarfile.open(self.archive, "w:gz", format=tarfile.USTAR_FORMAT) as archive:
            member = tarfile.TarInfo("vhalla")
            member.size = len(self.binary)
            member.mode = 0o755
            if symlink:
                member.type = tarfile.SYMTYPE
                member.linkname = "/bin/sh"
                member.size = 0
            archive.addfile(member, None if symlink else io.BytesIO(self.binary))
            if extra:
                archive.addfile(tarfile.TarInfo("extra"))
        Path(str(self.archive) + ".sha256").write_text(signing.digest(self.archive.read_bytes()) + "\n")

    def tool(self, args, timeout=60):
        args = [str(arg) for arg in args]
        self.calls.append(args)
        self.assertFalse(any(name in os.environ for name in signing.SECRET_NAMES))
        if self.tool_failure and self.tool_failure in args:
            raise signing.SigningError("mock Apple rejection")
        if "create-keychain" in args:
            Path(args[-1]).touch(mode=0o600)
            for path in (self.work / "credentials").iterdir():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        if "find-identity" in args:
            return f'  1) {"A" * 40} "Developer ID Application: Example ({self.identity_team})"\n'
        if "--display" in args:
            return self.metadata
        if "notarytool" in args:
            if "submit" in args:
                self.assertEqual(timeout, 180)
                self.assertNotIn("--wait", args)
                return json.dumps({"id": UUID})
            self.assertEqual(timeout, 960)
            self.assertIn("15m", args)
            self.assertIn("wait", args)
            self.assertEqual(args[3], UUID)
            return json.dumps({"status": self.status, "id": self.wait_id})
        return ""

    def sign(self):
        signing.sign(self.archive, VERSION, self.output, self.work)

    def test_final_archive_is_signed_then_notarized_and_keychain_is_removed(self):
        self.sign()
        final = self.output / signing.archive_name(VERSION)
        self.assertTrue(final.is_file())
        self.assertEqual(Path(str(final) + ".sha256").read_text().strip(), signing.digest(final.read_bytes()) + "  " + final.name)
        with tarfile.open(final) as archive:
            self.assertEqual([entry.name for entry in archive], [f"valhalla-v{VERSION}-aarch64-apple-darwin/vhalla"])
            self.assertEqual(archive.extractfile(f"valhalla-v{VERSION}-aarch64-apple-darwin/vhalla").read(), self.binary)
        codesign = next(args for args in self.calls if "--sign" in args)
        self.assertIn("runtime", codesign)
        self.assertIn("--timestamp", codesign)
        self.assertIn("dev.hraness.vhalla", codesign)
        self.assertIn("certificate leaf[field.1.2.840.113635.100.6.1.13] exists", codesign[-2])
        notarized = next(i for i, args in enumerate(self.calls) if "--check-notarization" in args)
        removed = next(i for i, args in enumerate(self.calls) if "delete-keychain" in args)
        self.assertLess(notarized, removed)
        self.assertFalse(self.work.exists())
        self.assertTrue(all(args[0] in ("/usr/bin/security", "/usr/bin/codesign", "/usr/bin/xcrun") for args in self.calls))
        receipt = json.loads((self.root / "vhalla-apple-notarization.json").read_text())
        self.assertEqual(receipt["submissionId"], UUID)
        self.assertEqual(receipt["status"], "Accepted")
        self.assertEqual(receipt["state"], "verified")
        self.assertEqual(receipt["signedBinarySha256"], signing.digest(self.binary))

    def test_notary_rejection_removes_credentials_and_never_creates_release(self):
        self.status = "Invalid"
        with self.assertRaisesRegex(signing.SigningError, "not Accepted"):
            self.sign()
        self.assertFalse(self.output.exists())
        self.assertFalse(self.work.exists())
        self.assertTrue(any("delete-keychain" in args for args in self.calls))
        receipt = json.loads((self.root / "vhalla-apple-notarization.json").read_text())
        self.assertEqual(receipt["submissionId"], UUID)
        self.assertEqual(receipt["status"], "Invalid")

    def test_incomplete_notary_status_is_not_success(self):
        self.status = "In Progress"
        with self.assertRaisesRegex(signing.SigningError, "not Accepted"):
            self.sign()
        self.assertFalse(self.output.exists())

    def test_wait_timeout_preserves_submission_and_exact_hashes_without_retry(self):
        def timed_out(args, timeout=60):
            if "wait" in args:
                self.calls.append([str(arg) for arg in args])
                raise RuntimeError("Apple tool failed or timed out: xcrun")
            return self.tool(args, timeout)
        with patch.object(signing, "run", timed_out):
            with self.assertRaisesRegex(RuntimeError, "timed out"):
                self.sign()
        self.assertFalse(self.output.exists())
        self.assertFalse(self.work.exists())
        receipt_text = (self.root / "vhalla-apple-notarization.json").read_text()
        receipt = json.loads(receipt_text)
        self.assertEqual(receipt["submissionId"], UUID)
        self.assertEqual(receipt["state"], "wait-incomplete")
        self.assertIsNone(receipt["status"])
        self.assertEqual(receipt["signedBinarySha256"], signing.digest(self.binary))
        self.assertEqual(receipt["unsignedArchiveSha256"], signing.digest(self.archive.read_bytes()))
        self.assertRegex(receipt["submissionZipSha256"], "^[0-9a-f]{64}$")
        self.assertEqual(sum("submit" in args for args in self.calls), 1)
        self.assertEqual(sum("wait" in args for args in self.calls), 1)
        for private in ("fake private p12", "fake private p8", "never-print-me", str(self.work)):
            self.assertNotIn(private, receipt_text)

    def test_wait_cannot_accept_a_different_submission(self):
        self.wait_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        with self.assertRaisesRegex(signing.SigningError, "another submission"):
            self.sign()
        self.assertFalse(self.output.exists())
        receipt = json.loads((self.root / "vhalla-apple-notarization.json").read_text())
        self.assertEqual(receipt["submissionId"], UUID)
        self.assertEqual(receipt["state"], "wait-incomplete")
        self.assertIsNone(receipt["status"])

    def test_submit_failure_retains_hashes_and_never_retries_an_unknown_submission(self):
        self.tool_failure = "submit"
        with self.assertRaisesRegex(signing.SigningError, "mock Apple rejection"):
            self.sign()
        self.assertFalse(self.output.exists())
        self.assertFalse(self.work.exists())
        receipt = json.loads((self.root / "vhalla-apple-notarization.json").read_text())
        self.assertIsNone(receipt["submissionId"])
        self.assertEqual(receipt["state"], "submission-started")
        self.assertEqual(receipt["signedBinarySha256"], signing.digest(self.binary))
        self.assertEqual(sum("submit" in args for args in self.calls), 1)
        self.assertFalse(any("wait" in args for args in self.calls))

    def test_arbitrary_service_status_is_not_retained_in_diagnostics(self):
        self.status = "unexpected secret echoed by service"
        with self.assertRaisesRegex(signing.SigningError, "not Accepted"):
            self.sign()
        receipt_text = (self.root / "vhalla-apple-notarization.json").read_text()
        self.assertNotIn(self.status, receipt_text)
        self.assertEqual(json.loads(receipt_text)["status"], "Unrecognized")

    def test_wrong_certificate_team_is_rejected_before_signing(self):
        self.identity_team = "Z9Y8X7W6V5"
        with self.assertRaisesRegex(signing.SigningError, "expected Developer ID"):
            self.sign()
        self.assertFalse(any("--sign" in args for args in self.calls))
        self.assertFalse(self.work.exists())

    def test_hardened_runtime_and_timestamp_are_required(self):
        self.metadata = self.metadata.replace("(runtime)", "(none)")
        with self.assertRaisesRegex(signing.SigningError, "hardened runtime"):
            self.sign()
        self.assertFalse(any("notarytool" in args for args in self.calls))

    def test_missing_secure_timestamp_is_rejected(self):
        self.metadata = "\n".join(line for line in self.metadata.splitlines() if not line.startswith("Timestamp="))
        with self.assertRaisesRegex(signing.SigningError, "secure timestamp"):
            self.sign()
        self.assertFalse(any("notarytool" in args for args in self.calls))

    def test_actual_signed_metadata_must_match_expected_team(self):
        self.metadata = self.metadata.replace("TeamIdentifier=" + TEAM, "TeamIdentifier=Z9Y8X7W6V5")
        with self.assertRaisesRegex(signing.SigningError, "identity mismatch"):
            self.sign()
        self.assertFalse(self.output.exists())

    def test_term_interruption_unwinds_and_removes_credentials(self):
        def interrupted(args, timeout=60):
            if "notarytool" in args:
                # The installed SIGTERM handler raises SystemExit(143).
                raise SystemExit(143)
            return self.tool(args, timeout)
        with patch.object(signing, "run", interrupted):
            with self.assertRaises(SystemExit) as stopped:
                self.sign()
        self.assertEqual(stopped.exception.code, 143)
        self.assertFalse(self.output.exists())
        self.assertFalse(self.work.exists())
        self.assertTrue(any("delete-keychain" in args for args in self.calls))

    def test_post_notarization_verification_failure_blocks_publication(self):
        self.tool_failure = "--check-notarization"
        with self.assertRaisesRegex(signing.SigningError, "mock Apple rejection"):
            self.sign()
        self.assertFalse(self.output.exists())
        self.assertFalse(self.work.exists())

    def test_keychain_cleanup_failure_blocks_publication_and_removes_private_files(self):
        self.tool_failure = "delete-keychain"
        with self.assertRaisesRegex(signing.SigningError, "mock Apple rejection"):
            self.sign()
        self.assertFalse(self.output.exists())
        self.assertFalse(self.work.exists())

    def test_extra_tar_member_rejected_before_apple_tools(self):
        self.native_archive(extra=True)
        with self.assertRaisesRegex(signing.SigningError, "extra members"):
            self.sign()
        self.assertFalse(self.calls)
        self.assertFalse(self.work.exists())

    def test_symlink_payload_rejected_before_apple_tools(self):
        self.native_archive(symlink=True)
        with self.assertRaisesRegex(signing.SigningError, "regular vhalla"):
            self.sign()
        self.assertFalse(self.calls)

    def test_payload_checksum_rejected_before_apple_tools(self):
        Path(str(self.archive) + ".sha256").write_text("0" * 64)
        with self.assertRaisesRegex(signing.SigningError, "checksum mismatch"):
            self.sign()
        self.assertFalse(self.calls)

    def test_payload_must_be_arm64_macho_before_apple_tools(self):
        self.binary = b"#!/bin/sh\necho payload must never run\n"
        self.native_archive()
        with self.assertRaisesRegex(signing.SigningError, "arm64 Mach-O"):
            self.sign()
        self.assertFalse(self.calls)

    def test_macho_must_be_an_executable_not_a_dylib(self):
        self.binary = self.binary[:12] + struct.pack("<I", 6) + self.binary[16:]
        self.native_archive()
        with self.assertRaisesRegex(signing.SigningError, "arm64 Mach-O executable"):
            self.sign()
        self.assertFalse(self.calls)

    def test_team_placeholder_fails_closed(self):
        with patch.object(signing, "TEAM_ID", "__XCB_APPLE_TEAM_ID__"):
            with self.assertRaisesRegex(signing.SigningError, "not configured"):
                self.sign()
        self.assertFalse(self.calls)

    def artifact_zip(self, extra=None):
        path = self.root / "artifact.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.write(self.archive, self.archive.name)
            archive.write(Path(str(self.archive) + ".sha256"), self.archive.name + ".sha256")
            if extra:
                archive.writestr(extra, b"unexpected")
        return path

    def test_exact_artifact_zip_digest_and_two_file_inventory_are_verified(self):
        archive = self.artifact_zip()
        destination = self.root / "extracted"
        signing.unpack_artifact(archive, signing.digest(archive.read_bytes()), VERSION, destination)
        self.assertEqual((destination / self.archive.name).read_bytes(), self.archive.read_bytes())

    def test_wrong_artifact_zip_digest_is_a_hard_failure(self):
        archive = self.artifact_zip()
        destination = self.root / "extracted"
        with self.assertRaisesRegex(signing.SigningError, "ZIP digest mismatch"):
            signing.unpack_artifact(archive, "0" * 64, VERSION, destination)
        self.assertFalse(destination.exists())

    def test_extra_or_traversal_zip_member_is_rejected(self):
        archive = self.artifact_zip("../escaped")
        with self.assertRaisesRegex(signing.SigningError, "exactly the unsigned archive"):
            signing.unpack_artifact(archive, signing.digest(archive.read_bytes()), VERSION, self.root / "extracted")
        self.assertFalse((self.root / "extracted").exists())

    def test_cleanup_rejects_unowned_path(self):
        with self.assertRaisesRegex(signing.SigningError, "dedicated runner"):
            signing.cleanup(self.root)
        self.assertTrue(self.root.exists())


class ToolBoundaryTests(unittest.TestCase):
    def test_subprocess_receives_no_apple_or_provider_credentials(self):
        result = subprocess.CompletedProcess([], 0, stdout="ok", stderr="")
        with patch.dict(os.environ, {"APPLE_DEVELOPER_ID_P12_PASSWORD": "private", "OPENAI_API_KEY": "private"}), \
             patch.object(signing.subprocess, "run", return_value=result) as child:
            self.assertEqual(signing.run(["/usr/bin/security", "test"]), "ok")
        self.assertEqual(set(child.call_args.kwargs["env"]), {"PATH", "HOME", "LC_ALL"})

    def test_tool_errors_do_not_echo_secret_arguments_or_output(self):
        result = subprocess.CompletedProcess([], 1, stdout="private", stderr="private")
        with patch.object(signing.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(signing.SigningError, "^Apple tool failed: security$"):
                signing.run(["/usr/bin/security", "-p", "private"])


if __name__ == "__main__":
    unittest.main()
