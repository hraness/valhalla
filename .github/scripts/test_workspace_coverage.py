"""Keep every maintained package in the sharded native test matrix."""
from pathlib import Path
import re
import shlex
import tomllib
import unittest


REPO = Path(__file__).resolve().parents[2]


class WorkspaceCoverageTests(unittest.TestCase):
    def test_every_workspace_package_has_a_native_test_lane(self):
        workspace = tomllib.loads((REPO / "Cargo.toml").read_text())["workspace"]
        expected = set()
        for member in workspace["members"]:
            manifests = sorted(REPO.glob(member + "/Cargo.toml"))
            self.assertTrue(manifests, f"workspace member has no manifest: {member}")
            for manifest in manifests:
                expected.add(tomllib.loads(manifest.read_text())["package"]["name"])

        workflow = (REPO / ".github/workflows/rust.yml").read_text()
        lanes = re.findall(r"^ +packages: (.+)$", workflow, re.MULTILINE)
        self.assertTrue(lanes, "native test matrix package lists disappeared")
        covered = set()
        for lane in lanes:
            arguments = shlex.split(lane)
            self.assertEqual(len(arguments) % 2, 0, f"unexpected package list: {lane}")
            for flag, package in zip(arguments[::2], arguments[1::2]):
                self.assertEqual(flag, "-p", f"unsupported matrix selector: {lane}")
                covered.add(package)
        self.assertEqual(expected - covered, set(), "workspace packages omitted from native CI")
        self.assertEqual(covered - expected, set(), "CI packages absent from workspace")


if __name__ == "__main__":
    unittest.main()
