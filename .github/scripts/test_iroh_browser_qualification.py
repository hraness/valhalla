"""Focused contracts for the separate-job browser/Iroh qualification lane."""
import inspect
import os
import unittest
from unittest.mock import patch

import iroh_browser_qualification as qualification


class BrowserQualificationTests(unittest.TestCase):
    def setUp(self):
        self.env = {
            "GITHUB_SHA": "a" * 40,
            "GITHUB_RUN_ID": "100",
            "GITHUB_RUN_ATTEMPT": "2",
            "QUALIFICATION_SOURCE_SHA": "a" * 40,
        }
        self.context = {
            "source_sha": self.env["GITHUB_SHA"],
            "run_id": self.env["GITHUB_RUN_ID"],
            "run_attempt": self.env["GITHUB_RUN_ATTEMPT"],
        }

    def meta(self):
        return {
            "source_sha": "a" * 40,
            "run_id": "100",
            "run_attempt": "2",
            "tree_sha": "b" * 40,
            "binary_sha256": "c" * 64,
            "lock_sha256": "d" * 64,
            "browser_manifest_sha256": "e" * 64,
            "controller_sha256": "f" * 64,
            "host_machine": "1" * 64,
        }

    def descriptor(self):
        return {
            "source_sha": "a" * 40,
            "run_id": "100",
            "run_attempt": "2",
            "schema": qualification.SCHEMA,
            "role": "descriptor",
            "tree_sha": "b" * 40,
            "binary_sha256": "c" * 64,
            "lock_sha256": "d" * 64,
            "browser_manifest_sha256": "e" * 64,
            "iroh_relay_url": qualification.DEFAULT_RELAY_URL,
            "endpoint": {"endpoint_id": "2" * 64,
                         "relay_url": qualification.DEFAULT_RELAY_URL,
                         "addresses": []},
            "namespace": "3" * 64,
            "upstream_token": "4" * 64,
            "host_machine": "1" * 64,
            "descriptor_nonce": "5" * 64,
        }

    def client(self):
        value = {
            "source_sha": "a" * 40,
            "run_id": "100",
            "run_attempt": "2",
            "schema": qualification.SCHEMA,
            "role": "client",
            "tree_sha": "b" * 40,
            "binary_sha256": "c" * 64,
            "lock_sha256": "d" * 64,
            "browser_manifest_sha256": "e" * 64,
            "iroh_relay_url": qualification.DEFAULT_RELAY_URL,
            "machine": "6" * 64,
            "host_machine": "1" * 64,
            "passed": True,
            "cleanup_confirmed": True,
            "browser_qualified": True,
            "direct_path_qualified": False,
            "independent_nat_qualified": False,
        }
        value["cases"] = {case: True for case in qualification.CLIENT_CASES}
        return value

    def test_runtime_context_requires_exact_source_and_positive_run(self):
        with patch.dict(os.environ, self.env, clear=False):
            self.assertEqual(qualification.runtime_context(), self.context)
        for key, value in (("GITHUB_SHA", "not-a-sha"),
                           ("GITHUB_RUN_ID", "0"),
                           ("GITHUB_RUN_ATTEMPT", "-1")):
            changed = self.env | {key: value}
            if key == "GITHUB_SHA":
                changed["QUALIFICATION_SOURCE_SHA"] = ""
            with self.subTest(key=key), patch.dict(os.environ, changed, clear=False):
                with self.assertRaises(ValueError):
                    qualification.runtime_context()

    def test_runtime_context_prefers_explicit_workflow_source_commit(self):
        explicit = self.env | {"QUALIFICATION_SOURCE_SHA": "b" * 40}
        with patch.dict(os.environ, explicit, clear=False):
            self.assertEqual(qualification.runtime_context()["source_sha"], "b" * 40)

    def test_upstream_is_explicitly_pinned_and_not_an_arbitrary_probe(self):
        self.assertEqual(qualification.validate_relay_url(qualification.DEFAULT_RELAY_URL),
                         qualification.DEFAULT_RELAY_URL)
        for value in ("https://evil.example/", "http://use1-1.relay.n0.iroh.link.",
                      qualification.DEFAULT_RELAY_URL + "?redirect=evil"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                qualification.validate_relay_url(value)

    def test_canonical_browser_frames_are_length_prefixed_and_namespaced(self):
        item, put, page = qualification.canonical_frames("3" * 64)
        item_bytes = bytes.fromhex(item)
        put_bytes = bytes.fromhex(put)
        page_bytes = bytes.fromhex(page)
        self.assertEqual(item_bytes[:len(qualification.MAGIC)], qualification.MAGIC)
        self.assertEqual(put_bytes[4], 1)
        self.assertEqual(int.from_bytes(put_bytes[:4], "big"), len(put_bytes) - 4)
        self.assertEqual(page_bytes[4], 2)
        self.assertEqual(int.from_bytes(page_bytes[:4], "big"), len(page_bytes) - 4)
        self.assertEqual(len(page_bytes), 15)

    def test_descriptor_requires_same_tree_artifacts_endpoint_and_private_token_shape(self):
        with patch.dict(os.environ, self.env, clear=False):
            qualification.validate_descriptor(self.descriptor(), self.meta())
        for field, replacement in (
            ("source_sha", "9" * 40),
            ("tree_sha", "9" * 40),
            ("browser_manifest_sha256", "9" * 64),
            ("upstream_token", "not-secret-shaped"),
        ):
            value = self.descriptor() | {field: replacement}
            with self.subTest(field=field), patch.dict(os.environ, self.env, clear=False), \
                    self.assertRaises(ValueError):
                qualification.validate_descriptor(value, self.meta())
        wrong_endpoint = self.descriptor()
        wrong_endpoint["endpoint"] = {**wrong_endpoint["endpoint"], "relay_url": "https://evil.example/"}
        with patch.dict(os.environ, self.env, clear=False), self.assertRaises(ValueError):
            qualification.validate_descriptor(wrong_endpoint, self.meta())

    def test_client_receipt_requires_every_case_and_keeps_topology_unqualified(self):
        with patch.dict(os.environ, self.env, clear=False):
            qualification.validate_client(self.client(), self.meta())
        for case in qualification.CLIENT_CASES:
            value = self.client()
            del value["cases"][case]
            with self.subTest(case=case), patch.dict(os.environ, self.env, clear=False), \
                    self.assertRaises(ValueError):
                qualification.validate_client(value, self.meta())
        for change in ({"direct_path_qualified": True},
                       {"independent_nat_qualified": True},
                       {"browser_qualified": False},
                       {"machine": "1" * 64},
                       {"cleanup_confirmed": False}):
            with self.subTest(change=change), patch.dict(os.environ, self.env, clear=False), \
                    self.assertRaises(ValueError):
                qualification.validate_client(self.client() | change, self.meta())

    def test_result_rejects_missing_host_durability_or_topology_claims(self):
        host = {
            "passed": True, "cleanup_confirmed": True,
            "cases": {case: True for case in qualification.HOST_CASES},
        } | self.meta()
        client = self.client()
        qualification.validate_result(host, client)
        for change in (
            {"cleanup_confirmed": False},
            {"cases": {case: True for case in qualification.HOST_CASES[:-1]}},
            {"passed": False},
        ):
            broken = host | change
            with self.subTest(change=change), self.assertRaises(ValueError):
                qualification.validate_result(broken, client)

    def test_child_environment_does_not_forward_repository_or_gateway_credentials(self):
        with patch.dict(os.environ, {**self.env, "GH_TOKEN": "secret", "ACTIONS_RUNTIME_TOKEN": "secret",
                                     "BROWSER_CAPABILITY": "secret", "RUNNER_TRACKING_ID": "owner"}, clear=False):
            selected = qualification.selected_env()
        self.assertNotIn("GH_TOKEN", selected)
        self.assertNotIn("ACTIONS_RUNTIME_TOKEN", selected)
        self.assertNotIn("BROWSER_CAPABILITY", selected)
        self.assertEqual(selected.get("RUST_BACKTRACE"), "0")

    def test_browser_driver_receipt_source_contains_no_network_topology_claim(self):
        self.assertIn("independent_nat_qualified:false", qualification.BROWSER_DRIVER)
        self.assertIn("direct_path_qualified:false", qualification.BROWSER_DRIVER)
        self.assertIn("cleanup_confirmed", qualification.BROWSER_DRIVER)
        self.assertNotIn("upstream_token:", qualification.BROWSER_DRIVER)

    def test_browser_driver_timeout_reaps_only_its_owned_processes(self):
        source = inspect.getsource(qualification.run_browser_driver)
        self.assertIn("start_new_session=True", source)
        self.assertIn("stop_timed_out_browser_driver", source)
        self.assertIn("browser.pid", qualification.BROWSER_DRIVER)
        self.assertIn("detached:true", qualification.BROWSER_DRIVER)
        self.assertIn(
            "refusing to signal an unowned browser",
            inspect.getsource(qualification.stop_timed_out_browser_driver),
        )


if __name__ == "__main__":
    unittest.main()
