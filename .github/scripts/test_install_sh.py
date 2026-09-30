"""The real shell installer rejects a new unsigned Mac release before execution."""
import hashlib
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="vhalla-install-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.fakebin = self.root / "tools"
        self.fakebin.mkdir()
        self.install = self.root / "installed"
        self.install.mkdir()
        (self.install / "vhalla").write_bytes(b"previous executable")
        self.marker = self.root / "executed"
        self.payload = b'#!/bin/sh\nprintf executed > "$EXECUTED"\nexit 0\n'
        self.command("uname", '#!/bin/sh\ncase "$1" in -s) echo "$TEST_OS";; -m) echo "$TEST_ARCH";; esac\n')
        self.command("curl", '#!/bin/sh\nurl=$2\ncp "$FIXTURES/${url##*/}" "$4"\n')
        self.command("ldd", '#!/bin/sh\necho glibc\n')

    def command(self, name, text):
        path = self.fakebin / name
        path.write_text(text)
        path.chmod(0o755)

    def run_install(self, version="v0.2.11", os_name="Darwin", corrupt=False, link=False):
        target = "aarch64-apple-darwin" if os_name == "Darwin" else "x86_64-unknown-linux-gnu"
        prefix = f"valhalla-{version}-{target}"
        archive = self.root / f"{prefix}.tar.gz"
        with tarfile.open(archive, "w:gz", format=tarfile.USTAR_FORMAT) as output:
            member = tarfile.TarInfo(prefix + "/vhalla")
            member.mode = 0o755
            member.size = len(self.payload)
            if link:
                member.type = tarfile.SYMTYPE
                member.linkname = "/bin/sh"
                member.size = 0
            output.addfile(member, None if link else io.BytesIO(self.payload))
        digest = "0" * 64 if corrupt else hashlib.sha256(archive.read_bytes()).hexdigest()
        Path(str(archive) + ".sha256").write_text(f"{digest}  {archive.name}\n")
        environment = {**os.environ, "PATH": str(self.fakebin) + os.pathsep + os.environ["PATH"],
                       "VHALLA_VERSION": version, "VHALLA_INSTALL_DIR": str(self.install),
                       "TEST_OS": os_name, "TEST_ARCH": "arm64" if os_name == "Darwin" else "x86_64",
                       "EXECUTED": str(self.marker), "FIXTURES": str(self.root)}
        return subprocess.run(["sh", str(ROOT / "site/install.sh")], env=environment,
                              capture_output=True, text=True, timeout=30)

    def test_new_unsigned_mac_release_never_executes_or_replaces_existing(self):
        result = self.run_install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Developer ID", result.stderr)
        self.assertFalse(self.marker.exists())
        self.assertEqual((self.install / "vhalla").read_bytes(), b"previous executable")

    def test_explicit_historical_mac_release_keeps_checksum_install(self):
        result = self.run_install(version="v0.2.10")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.marker.exists())
        self.assertEqual((self.install / "vhalla").read_bytes(), self.payload)

    def test_linux_install_is_unchanged(self):
        result = self.run_install(os_name="Linux")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.marker.exists())

    def test_bad_checksum_and_archive_links_never_execute(self):
        for options in ({"corrupt": True}, {"link": True}):
            with self.subTest(options=options):
                result = self.run_install(version="v0.2.10", **options)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.marker.exists())
                self.assertEqual((self.install / "vhalla").read_bytes(), b"previous executable")


if __name__ == "__main__":
    unittest.main()
