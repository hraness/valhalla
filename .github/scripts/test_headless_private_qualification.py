"""Bounded synthetic handoffs, production CLI contracts and honest evidence."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import headless_private_qualification as qualification


class PrivateQualificationTests(unittest.TestCase):
    def config(self, machine="e", role="host", relay=qualification.RELAY):
        return dict(source_sha="a" * 40, run_id="100", run_attempt="2", nonce="b" * 64,
                    binary_sha256="c" * 64, lock_sha256="d" * 64, machine=machine * 64,
                    relay=relay, mode="runners", role=role, work="/tmp/synthetic", binary="/absolute/vhalla")

    def descriptor(self):
        return qualification.packet(self.config("f"), "descriptor",
            owner={key: str(index) * 64 for index, key in enumerate(("room", "anchor", "account", "device"), 1)},
            endpoint=dict(endpoint_id="5" * 64, relay_url=qualification.RELAY, addresses=[]),
            namespace="6" * 64, tokens=dict(b="7" * 64, c="8" * 64),
            validity=dict(not_before=1000, expires_at=2000))

    def observation(self, selected="relay"):
        return dict(peer="5" * 64, operation="page",
                    **{when: dict(selected=selected, nonempty=True, all_relay=selected == "relay")
                       for when in ("before", "after")})

    def transport(self, role="client", selected="relay"):
        return {stage: self.observation(selected) for stage in qualification.TRANSPORT_STAGES[role]}

    def client_receipt(self):
        config = self.config("f", "client")
        value = qualification.receipt(config)
        value.update(passed=True, cleanup_confirmed=True, remote_machine="e" * 64,
                     fixture_exit_code=0, fixture_forced_cleanup=False,
                     cases={name: True for name in qualification.CLIENT_CASES},
                     transport_observations=self.transport())
        value.update(qualification.claims(config, True, value["transport_observations"]))
        return value

    def test_import_and_artifact_reader_do_not_mutate_other_adapters(self):
        shared = qualification.shared
        public = qualification.public
        before = (shared.SCHEMA, shared.CONTROLLER, shared.artifact_name, shared.fixture_command,
                  shared.HOST_CASES, shared.CLIENT_CASES, public.SCHEMA, public.path_claims)
        spec = importlib.util.spec_from_file_location("isolated_private_test", qualification.SCRIPT)
        isolated = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(isolated)
        reader = isolated.artifact_reader()
        self.assertIsNot(reader, shared)
        self.assertEqual(before, (shared.SCHEMA, shared.CONTROLLER, shared.artifact_name, shared.fixture_command,
                                 shared.HOST_CASES, shared.CLIENT_CASES, public.SCHEMA, public.path_claims))
        with patch.dict(os.environ, {"GITHUB_SHA": "a" * 40, "GITHUB_RUN_ID": "100", "GITHUB_RUN_ATTEMPT": "2"}):
            self.assertEqual(reader.artifact_name("client"), "headless-private-client-100-2")

    def test_descriptor_accepts_only_exact_candidate_and_distinct_machine(self):
        packet = self.descriptor()
        qualification.validate_packet(packet, "descriptor", self.config())
        for field, value in (("source_sha", "0" * 40), ("run_attempt", "9"), ("nonce", "0" * 64),
                             ("binary_sha256", "0" * 64), ("lock_sha256", "0" * 64),
                             ("machine", "e" * 64), ("kind", "host-offers")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                qualification.validate_packet(packet | {field: value}, "descriptor", self.config())

    def test_bootstrap_allowlist_rejects_homes_keys_profiles_and_logs(self):
        for field in ("home", "endpoint_key", "private_key", "profile", "log", "account_backup"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                qualification.validate_packet(self.descriptor() | {field: "forbidden"}, "descriptor", self.config())
        for field in ("tokens", "owner", "endpoint", "validity"):
            value = self.descriptor()
            value[field]["secret"] = "forbidden"
            with self.subTest(field=field), self.assertRaises(ValueError):
                qualification.validate_packet(value, "descriptor", self.config())

    def test_synthetic_tokens_are_separate_bounded_and_not_claimed_to_expire(self):
        for token in ("7" * 63, "A" * 64, "7" * 65, None):
            value = self.descriptor()
            value["tokens"]["b"] = token
            with self.subTest(token=token), self.assertRaises(ValueError):
                qualification.validate_packet(value, "descriptor", self.config())
        value = self.descriptor()
        value["tokens"]["c"] = value["tokens"]["b"]
        with self.assertRaises(ValueError):
            qualification.validate_packet(value, "descriptor", self.config())
        self.assertIn("no token expiry", qualification.claims(self.config())["credential_lifetime"])

    def test_runner_endpoint_cannot_export_interface_addresses_or_change_relay(self):
        for change in ({"addresses": ["10.0.0.2:1234"]}, {"relay_url": "https://foreign.example/"},
                       {"endpoint_id": "not-a-key"}):
            value = self.descriptor()
            value["endpoint"].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                qualification.validate_packet(value, "descriptor", self.config())
        value = self.descriptor()
        value["endpoint"].update(relay_url=None, addresses=["127.0.0.1:1234"])
        qualification.validate_packet(value, "descriptor", self.config(relay=None))
        for address in ("0.0.0.0:1234", "127.0.0.1:0", "127.0.0.1:65536", "host.invalid:1234"):
            value["endpoint"]["addresses"] = [address]
            with self.subTest(address=address), self.assertRaises(ValueError):
                qualification.validate_packet(value, "descriptor", self.config(relay=None))

    def test_later_packets_pin_destination_and_reject_unbounded_artifacts(self):
        value = qualification.packet(self.config("f", "client"), "client-requests",
            host_machine="e" * 64, requests=dict(b="ab" * 10, c="cd" * 10), devices=dict(b="1" * 64, c="2" * 64))
        qualification.validate_packet(value, "client-requests", self.config())
        with self.assertRaises(ValueError):
            qualification.validate_packet(value | {"host_machine": "9" * 64}, "client-requests", self.config())
        for artifact in ("", "a", "AB", "ab" * 24577):
            changed = value | {"requests": dict(b=artifact, c="ab")}
            with self.subTest(artifact_size=len(artifact)), self.assertRaises(ValueError):
                qualification.validate_packet(changed, "client-requests", self.config())
        changed = value | {"requests": dict(b="ab" * 24576, c="cd" * 24576)}
        with self.assertRaises(ValueError):
            qualification.validate_packet(changed, "client-requests", self.config())

    def test_result_requires_every_assertion_and_contains_no_artifacts(self):
        value = dict(cases={name: True for name in qualification.CLIENT_CASES}, remote_machine="f" * 64)
        qualification.validate_result(value, "client")
        for change in ({"exact_retry": 1}, {"removed_state_persisted": False}, {"token": "secret"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                qualification.validate_result(value | {"cases": value["cases"] | change}, "client")
        with self.assertRaises(ValueError):
            qualification.validate_result(value | {"profile": "secret"}, "client")

    def test_snapshot_claims_require_observations_and_successful_cleanup(self):
        for mode in (self.config(), self.config(relay=None) | {"mode": "local"}):
            claims = qualification.claims(mode)
            self.assertEqual(claims["observed_path"], "unreported")
            for key in ("forced_relay_qualified", "direct_path_qualified", "per_byte_path_qualified",
                        "private_qualified", "independent_machines_qualified", "independent_nat_qualified"):
                self.assertIs(claims[key], False)
        failed = qualification.claims(self.config(), False, self.transport())
        self.assertEqual(failed["observed_path"], "relay_only_snapshots")
        self.assertFalse(failed["forced_relay_qualified"])
        passed = qualification.claims(self.config(), True, self.transport())
        self.assertTrue(passed["forced_relay_qualified"] and passed["private_qualified"])
        self.assertFalse(passed["per_byte_path_qualified"] or passed["independent_nat_qualified"])
        local = qualification.claims(self.config(relay=None) | {"mode": "local"}, True, self.transport(selected="direct"))
        self.assertTrue(local["direct_path_qualified"])
        self.assertFalse(local["independent_machines_qualified"])

    def test_private_observation_requires_selected_relay_in_both_snapshots(self):
        qualification.validate_transport(self.transport(), "client", self.config())
        for when in ("before", "after"):
            for change in ({"selected": "unknown"}, {"selected": "direct"}, {"nonempty": False},
                           {"all_relay": False}, {"nonempty": 1}, {"address": "private"}):
                value = self.transport()
                value["b_initial"][when].update(change)
                with self.subTest(when=when, change=change), self.assertRaises(ValueError):
                    qualification.validate_transport(value, "client", self.config())
        for change in ({"operation": "watch"}, {"peer": "foreign"}, {"token": "secret"}):
            value = self.transport()
            value["b_initial"].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                qualification.validate_transport(value, "client", self.config())
        with self.assertRaises(ValueError):
            qualification.validate_transport({}, "client", self.config())

    def test_receipt_matches_admitted_client_and_refuses_private_payload_or_inflated_claim(self):
        expected = self.config() | {"selected_client_machine": "f" * 64}
        value = self.client_receipt()
        qualification.validate_client(value, expected)
        for change in ({"machine": "9" * 64}, {"remote_machine": "9" * 64}, {"source_sha": "9" * 40},
                       {"cleanup_confirmed": False}, {"per_byte_path_qualified": True},
                       {"fixture_exit_code": False}, {"fixture_exit_code": 1}, {"fixture_forced_cleanup": True},
                       {"source_attested": False},
                       {"independent_nat_qualified": True}, {"transport_observations": {}},
                       {"profile": "secret"}, {"token": "secret"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                qualification.validate_client(value | change, expected)

    def test_profile_uses_authenticated_context_and_exact_v4_iroh_shape(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            config = self.config() | {"work": str(root)}
            journey = qualification.Journey(config)
            daemon = Mock()
            daemon.home = root / "a"
            context = self.descriptor()["owner"]
            def call(op, **fields):
                self.assertEqual(fields["room"], qualification.operation(1))
                if op == "room.status":
                    return {"context": dict(kind="private", **context)}
                if op == "private.delivery_init":
                    raw = Path(fields["profile"]).read_bytes()
                    self.assertEqual(qualification.hashlib.sha256(raw).hexdigest(), fields["profile_hash"])
                    return dict(initialized=True, profile_hash=fields["profile_hash"])
                if op == "private.delivery_attach":
                    self.assertEqual(fields["operation"], qualification.operation(10))
                    return {"current": {"state": "active"}}
                self.fail(op)
            daemon.call.side_effect = call
            journey.profile(daemon, self.descriptor(), "7" * 64)
            path = root / "a-delivery" / "delivery.json"
            value = json.loads(path.read_bytes())
            self.assertEqual(value["version"], 4)
            self.assertEqual(value["context"], context)
            self.assertEqual(value["transport"], dict(kind="iroh", endpoint=self.descriptor()["endpoint"], relay_only=True))
            self.assertTrue(value["emit_acceptance"])
            self.assertEqual(value["mailbox_polling"], "interactive")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            self.assertNotIn("ca", value)
            self.assertNotIn("tls_name", value)

    def test_shared_mailbox_accepts_actor_local_counters_and_exact_retries(self):
        journey = qualification.Journey(self.config())
        status = dict(epoch=2, roster="1" * 64)
        retained = {}
        rooms = {}
        sequences = {}

        def factory(config, name):
            daemon = Mock(home=Path(config["work"]) / name)
            def call(op, **fields):
                self.assertEqual(fields["room"], rooms[name])
                if op == "room.status":
                    return status
                self.assertEqual(op, "room.send")
                key = fields["operation"]
                intent = (name, fields["body"], fields["epoch"], fields["roster"])
                if key in retained:
                    prior, output = retained[key]
                    if prior != intent:
                        raise ValueError("shared namespace operation collision")
                    return output | {"exact_retry": True}
                sequences[name] = sequences.get(name, 0) + 1
                output = dict(exact_retry=False, artifact=key, sequence=sequences[name])
                retained[key] = (intent, output)
                return output
            daemon.call.side_effect = call
            return daemon

        with patch.object(qualification.public, "Daemon", side_effect=factory):
            actors = {name: journey.daemon(name) for name in ("a", "b", "c")}
        rooms.update({name: journey.room(daemon) for name, daemon in actors.items()})
        # Join operations become local room slots and also enter the shared
        # mailbox. A new home does not make another actor's ID reusable there.
        self.assertEqual(len(set(rooms.values())), 3)
        for name, daemon in actors.items():
            first = journey.send(daemon, 20, name + "-first", status)
            journey.retry(daemon, 20, name + "-first", first, status)
            daemon.stop()
            daemon.start(initialize=False)
            journey.retry(daemon, 20, name + "-first", first, status)
            # Owner and surviving member both use this step after the rekey.
            journey.send(daemon, 31, name + "-after-removal", status)
        self.assertEqual(len(retained), 6)
        self.assertTrue(set(rooms.values()).isdisjoint(retained))
        self.assertEqual(sequences, dict(a=2, b=2, c=2))

    def test_removed_member_attempt_does_not_reuse_another_actors_operation(self):
        journey = qualification.Journey(self.config())
        daemons = [Mock(home=Path("/tmp/synthetic") / name) for name in ("a", "b", "c")]
        with patch.object(qualification.public, "Daemon", side_effect=daemons):
            owner, member, survivor = [journey.daemon(name) for name in ("a", "b", "c")]
        attempted = {}
        def refused(op, **fields):
            if op == "room.status":
                return dict(epoch=3, roster="1" * 64)
            self.assertEqual(op, "room.send")
            attempted.update(fields)
            raise qualification.public.CliRefusal("permission-denied")
        member.call.side_effect = refused
        journey.denied_send(member, 31, "removed-new-send")
        self.assertEqual(attempted["room"], journey.room(member))
        self.assertNotIn(attempted["operation"], {
            journey.operation(owner, 31), journey.operation(survivor, 31), journey.operation(member, 20)})

    def test_private_observer_checks_actual_profile_mode_and_checked_reply(self):
        config = self.config("f", "client")
        journey = qualification.Journey(config)
        daemon = Mock(home=Path("/tmp/synthetic/b"))
        journey.endpoints["b"] = "5" * 64
        observation = self.observation()
        response = dict(transport=dict(kind="iroh", relay_only=True),
                        last_transport_observation={key: observation[key] for key in ("operation", "before", "after")})
        daemon.call.return_value = response
        journey.observe(daemon, "b_initial")
        self.assertEqual(journey.transport["b_initial"], observation)
        with self.assertRaises(ValueError):
            journey.observe(daemon, "b_initial")
        response["transport"]["relay_only"] = False
        with self.assertRaises(ValueError):
            journey.observe(daemon, "b_restarted")
        response["transport"]["relay_only"] = True
        response["last_transport_observation"] = None
        with self.assertRaises(ValueError):
            journey.observe(daemon, "b_restarted")

    def test_fresh_membership_denial_does_not_accept_an_unrelated_error(self):
        journey = qualification.Journey(self.config())
        for code in ("permission-denied", "usage", "owner-unavailable"):
            with patch.object(journey, "send", side_effect=qualification.public.CliRefusal(code)):
                if code == "permission-denied":
                    journey.denied_send(Mock(), 90, "denied")
                else:
                    with self.assertRaises(ValueError):
                        journey.denied_send(Mock(), 90, "denied")

    def test_recipient_receipts_are_separate_from_retention_and_match_expected_devices(self):
        journey = qualification.Journey(self.config())
        claim = dict(recipient="1" * 64, ciphertext="2" * 64, received_sequence=3)
        with patch.object(journey, "outbox", return_value=dict(member_acceptance_count=0, device_acceptances=[])):
            self.assertIsNone(journey.accepted(Mock(), 1, ["1" * 64]))
        with patch.object(journey, "outbox", return_value=dict(member_acceptance_count=1, device_acceptances=[claim])):
            self.assertIsNotNone(journey.accepted(Mock(), 1, ["1" * 64]))
            with self.assertRaises(ValueError):
                journey.accepted(Mock(), 1, ["9" * 64])
        with patch.object(journey, "outbox", return_value=dict(member_acceptance_count=2, device_acceptances=[claim, claim])):
            with self.assertRaises(ValueError):
                journey.accepted(Mock(), 1, ["1" * 64])

    def test_retention_binds_operation_instead_of_unrelated_queue_sequence(self):
        with tempfile.TemporaryDirectory() as directory:
            journey = qualification.Journey(self.config() | {"work": directory})
            daemon = Mock()
            daemon.call.return_value = dict(state="active", application=dict(records=[
                dict(sequence=4, operation=qualification.operation(22), state="retained")]))
            journey.retained(daemon, 22)
            daemon.call.assert_called_once()

    def test_mailbox_commands_disable_updates_and_do_not_leak_cli_credentials(self):
        mailbox = qualification.Mailbox(self.config())
        with patch.object(qualification.public, "exchange", return_value=(0, b'{"status":"initialized"}')) as exchanged:
            mailbox.invoke("init", "--transport", "iroh")
        argv, payload, env = exchanged.call_args.args
        self.assertEqual(argv, ["/absolute/vhalla", "--no-update", "private-host", "init",
                                "/tmp/synthetic/mailbox-host", "--transport", "iroh"])
        self.assertEqual(payload, b"")
        self.assertNotIn("GH_TOKEN", env)
        self.assertNotIn("HOME", env)

    def test_mailbox_stop_waits_for_graceful_exit_and_marks_forced_cleanup(self):
        mailbox = qualification.Mailbox(self.config())
        child = Mock()
        child.poll.side_effect = [None, 0]
        child.wait.return_value = 0
        mailbox.child = child
        mailbox.stop()
        child.terminate.assert_called_once()
        child.kill.assert_not_called()
        self.assertIsNone(mailbox.child)
        self.assertFalse(mailbox.forced)
        child = Mock()
        child.poll.return_value = 1
        child.wait.return_value = 1
        mailbox.child = child
        with self.assertRaises(ValueError):
            mailbox.stop()
        self.assertTrue(mailbox.forced)

    def test_candidate_mismatch_is_refused_before_launching_a_role(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory).resolve()
            binary = work / "binary"
            binary.write_bytes(b"not the candidate")
            qualification.write_json(work / "config.json", self.config() | {"work": str(work), "binary": str(binary)})
            with patch.object(qualification, "Journey") as journey:
                with self.assertRaises(ValueError):
                    qualification.run_role(work)
                journey.assert_not_called()

    def test_failed_local_role_preserves_diagnostics_and_reports_clean_unqualified_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            binary = root / "refuse"
            binary.write_text(f"#!{sys.executable}\nimport sys\nprint('{{}}')\nsys.exit(2)\n")
            binary.chmod(0o700)
            work = root / "work"
            self.assertFalse(qualification.local(binary, work))
            result = qualification.read_json(work / "local-receipt.json")
            self.assertFalse(result["passed"] or result["private_qualified"] or result["independent_machines_qualified"])
            self.assertTrue(result["cleanup_confirmed"])
            self.assertEqual(result["observed_path"], "unreported")
            self.assertTrue((work / "host" / "failure-private.json").is_file())
            self.assertTrue((work / "host" / "config.json").is_file())

    def test_workflow_uses_exact_artifact_allowlist_and_shared_bundle(self):
        path = qualification.SCRIPT.parent.parent / "workflows" / "headless-qualification.yml"
        text = path.read_text()
        private = text[text.index("  private-host:"):]
        for command in ("host-start", "host-offers", "host-admit", "host-offline", "host-remove", "host-wait", "host-stop",
                        "client-start", "client-requests", "client-offline", "client-restart", "client-wait", "client-stop"):
            self.assertIn("headless_private_qualification.py " + command, private)
        self.assertIn("name: headless-binary-${{ github.run_id }}-${{ github.run_attempt }}", private)
        expected = set(qualification.PHASE_FIELDS) | {"host-receipt", "client-receipt"}
        uploaded = set()
        for line in private.splitlines():
            if "path:" in line and "headless-private-" in line:
                name = line.strip().split("/")[-1]
                if name.endswith(".json"):
                    uploaded.add(name[:-5])
                else:
                    self.fail("private work directory or non-allowlisted artifact is uploaded: " + line)
        self.assertEqual(uploaded, expected)


if __name__ == "__main__":
    unittest.main()
