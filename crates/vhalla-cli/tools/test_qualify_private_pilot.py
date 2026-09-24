"""Qualification oracle tests; no model, relay, compiler or room fixture."""

import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent))
import qualify_private_pilot as p


class PilotContractTests(unittest.TestCase):
    def test_work_has_exact_dependencies_and_computed_result(self):
        prior = None
        bodies = []
        for index in range(4):
            body = p.stage_body(index, prior)
            value = json.loads(body)
            self.assertEqual(value["stage"], p.STAGES[index])
            self.assertLess(len(body.encode()), 1024)
            if prior:
                self.assertEqual(value["previous_sha256"], p.digest(prior))
            bodies.append(body)
            prior = body
        self.assertEqual(json.loads(bodies[1])["result"], {"count": 4, "sum": 40, "min": 3, "max": 19})
        self.assertTrue(json.loads(bodies[2])["accepted"])
        self.assertTrue(json.loads(bodies[3])["completed_after_restart"])
        for index in range(1, 4):
            previous = json.loads(bodies[index - 1])
            for changed in ({**previous, "stage": "other"}, {**previous, "task": "other"},
                            {**previous, "extra": "not reviewed"}):
                with self.subTest(index=index), self.assertRaises(p.runtime.MeasurementError):
                    p.stage_body(index, p.encode(changed))

    def test_receiver_checks_content_sender_and_uniqueness(self):
        body = p.stage_body(0)
        record = {"sequence": "2", "sender": "A", "body_hex": body.encode().hex()}
        seen = {}
        self.assertEqual(p.accept_record(record, body, "A", seen), 2)
        for change in ({}, {"sequence": "3"}, {"sender": "B"}, {"body_hex": b"wrong".hex()}, {"sequence": "0"}):
            with self.subTest(change=change), self.assertRaises(p.runtime.MeasurementError):
                p.accept_record({**record, **change}, body, "A", dict(seen))

    def test_acceptance_requires_both_exact_device_claim_and_relay_retention(self):
        sent = {"outbox_sequence": 4, "inbox_sequence": 7, "operation": "operation"}
        record = {"sequence": "4", "operation": "operation", "kind": "application",
                  "relay": {"state": "retained", "uncertain": False, "position": "9"},
                  "member_acceptances": [{"recipient": "B", "received_sequence": "7"}]}
        self.assertTrue(p.retained_acceptance(record, sent, "B"))
        self.assertEqual(sent["relay_position"], 9)
        self.assertFalse(p.retained_acceptance({**record, "member_acceptances": []}, sent, "B"))
        self.assertFalse(p.retained_acceptance({**record, "relay": {"state": "queued"}}, sent, "B"))
        for field, value in (("recipient", "C"), ("received_sequence", "8")):
            changed = copy.deepcopy(record)
            changed["member_acceptances"][0][field] = value
            with self.subTest(field=field), self.assertRaises(p.runtime.MeasurementError):
                p.retained_acceptance(changed, sent, "B")
        for relay in ({"state": "uncertain"}, {"state": "stopped"},
                      {"state": "retained", "uncertain": True, "position": "9"},
                      {"state": "retained", "uncertain": False, "position": "0"}):
            with self.subTest(relay=relay), self.assertRaises(p.runtime.MeasurementError):
                p.retained_acceptance({**record, "relay": relay}, sent, "B")
        with self.assertRaises(p.runtime.MeasurementError):
            p.retained_acceptance({**record, "sequence": "5"}, sent, "B")
        for change in ({"operation": "foreign"}, {"kind": "control"}):
            with self.assertRaises(p.runtime.MeasurementError):
                p.retained_acceptance({**record, **change}, sent, "B")
        with self.assertRaises(p.runtime.MeasurementError):
            p.retained_acceptance({**record, "member_acceptances": record["member_acceptances"] * 2}, sent, "B")

    def test_no_partial_or_status_only_run_passes(self):
        receipt = {"cases": dict.fromkeys(p.CASES, "PASS")}
        self.assertTrue(p.passed(receipt))
        for case in p.CASES:
            for result in (None, "NOT_RUN", "BLOCKED", "FAIL"):
                changed = copy.deepcopy(receipt)
                changed["cases"][case] = result
                self.assertFalse(p.passed(changed))
            changed = copy.deepcopy(receipt)
            del changed["cases"][case]
            self.assertFalse(p.passed(changed))
        self.assertFalse(p.passed({"cases": {"launcher": "PASS"}}))

    def test_public_identity_uses_allowlist_and_omits_paths(self):
        selected = ("source_commit", "source_tree", "cli_sha256", "provenance_sha256", "lockfile_sha256",
                    "native_inputs_sha256", "source_kind", "source_clean_at_build", "source_patch_sha256",
                    "source_identity_scope", "runner_sha256", "python", "platform", "machine")
        candidate = dict.fromkeys(selected, "public")
        candidate.update(cli="SECRET_PATH", provenance="SECRET_PATH", private_context="SECRET_CONTEXT",
                         token="SECRET_TOKEN", raw_rpc={"body": "SECRET_BODY"})
        actual = p.public_identity(candidate)
        self.assertEqual(set(actual), set(selected))
        self.assertNotIn("SECRET", json.dumps(actual))

    def test_claim_binds_exact_grant_bytes_and_full_scope(self):
        grant = {"grant_id": "id", "context": {"room": "room", "anchor": "anchor", "account": "account", "device": "device"},
                 "epoch": "1", "roster": "roster", "expires_at": 100}
        claim = {**grant, "format": "vhalla-agent-launch-claim-v1", "grant_sha256": "hash"}
        p.validate_claim(claim, grant, "hash")
        for key in claim:
            changed = copy.deepcopy(claim)
            changed[key] = "foreign"
            with self.subTest(key=key), self.assertRaises(p.runtime.MeasurementError):
                p.validate_claim(changed, grant, "hash")

    def test_remaining_allowance_is_selected_and_nonnegative(self):
        values = dict.fromkeys(("preparations", "messages", "body_bytes", "read_records", "read_bytes"), "4")
        self.assertEqual(set(p.remaining({"remaining": {**values, "secret": "omit"}})), set(values))
        with self.assertRaises(p.runtime.MeasurementError):
            p.remaining({"remaining": {**values, "messages": "-1"}})

    def test_launch_limits_are_finite_and_allow_registration_work_and_reopen(self):
        self.assertEqual(p.POLICY["max_launches"], 4)
        self.assertEqual(p.POLICY["lifetime"], 900)
        self.assertEqual(p.POLICY["disclosure"]["provider"], "none")
        self.assertLessEqual(p.POLICY["max_read_records"], 4096)
        self.assertGreaterEqual(p.POLICY["max_messages"], p.SENDERS.count("a"))


if __name__ == "__main__":
    unittest.main()
