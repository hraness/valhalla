"""Contract tests for the ALGAL wrapper; networking is qualified by the workflow."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import habitat_link_qualification as link


class HabitatLinkControllerTests(unittest.TestCase):
    def test_fixture_gets_only_the_config_and_probe_not_provider_credentials(self):
        with patch.object(link, "algal_source", return_value=Path("/fixture/algal")), \
                patch.object(link.shutil, "which", return_value="/tools/bun"), \
                patch.dict(os.environ, {"GH_TOKEN": "private", "TENANT_TOKEN": "private"}):
            command = link.fixture_command(Path("/bundle"), Path("/work"))
            self.assertEqual(command, ["/tools/bun", "/fixture/algal/scripts/habitat-link-iroh-qualification.ts"])
            environment = link.child_env(Path("/work/config.json"))
            self.assertEqual(environment["ALGAL_IROH_PROBE"], "/bundle/fixture")
            self.assertEqual(environment["VHALLA_IROH_QUALIFICATION_CONFIG"], "/work/config.json")
            self.assertNotIn("GH_TOKEN", environment)
            self.assertNotIn("TENANT_TOKEN", environment)

    def test_host_config_has_no_unused_mailbox_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            config = {"machine": "m", "secret": [1], "token": [2], "namespace": [3]}
            with patch.object(link, "_original_setup", return_value=({}, config)):
                _, actual = link.setup(Path("/bundle"), work, "host")
                self.assertEqual(actual, {"machine": "m"})
                self.assertEqual(link.controller.read_json(work / "config.json"), actual)

    def test_source_must_be_exact_selected_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            (root / "scripts/habitat-link-iroh-qualification.ts").touch()
            with patch.dict(os.environ, {"ALGAL_SOURCE": directory, "ALGAL_REF": "a" * 40}), \
                    patch.object(link.subprocess, "check_output", return_value="b" * 40):
                with self.assertRaises(ValueError):
                    link.algal_source()
            with patch.dict(os.environ, {"ALGAL_SOURCE": directory, "ALGAL_REF": "main"}):
                with self.assertRaises(ValueError):
                    link.algal_source()

    def test_client_receipt_binds_both_repository_versions(self):
        with patch.object(link, "_original_validate_client"):
            expected = {"algal_sha": "a" * 40, "algal_lock_sha256": "b" * 64}
            link.validate_client(dict(expected), expected)
            with self.assertRaises(ValueError):
                link.validate_client(dict(expected, algal_sha="c" * 40), expected)


if __name__ == "__main__":
    unittest.main()
