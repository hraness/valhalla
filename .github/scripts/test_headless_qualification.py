"""Process bounds, public-only handoffs and honest headless evidence."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

import headless_qualification as qualification


class QualificationTests(unittest.TestCase):
    def expected(self, machine="e"):
        return dict(source_sha="a" * 40, run_id="100", run_attempt="2", nonce="b" * 64,
                    binary_sha256="c" * 64, lock_sha256="d" * 64, machine=machine * 64)

    def descriptor(self):
        return qualification.public_packet(self.expected("f"), "descriptor",
            link="valhalla://public/1/placeholder", pin="1" * 64, author="2" * 64, peer="3" * 64)

    def observation(self, selected="relay", peer="3" * 64):
        return dict(peer=peer, **{when: dict(selected=selected, nonempty=True, all_relay=selected == "relay")
                                for when in ("before", "after")})

    def transport(self, role="client", selected="relay"):
        return {stage: self.observation(selected) for stage in qualification.TRANSPORT_STAGES[role]}

    def test_public_handoff_rejects_foreign_or_same_machine_evidence(self):
        expected = self.expected()
        packet = self.descriptor()
        self.assertEqual(qualification.validate_packet(packet, "descriptor", expected), packet)
        for field, value in (("source_sha", "9" * 40), ("run_attempt", "1"), ("nonce", "9" * 64),
                             ("binary_sha256", "9" * 64), ("lock_sha256", "9" * 64),
                             ("machine", expected["machine"]), ("kind", "client-offer")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                qualification.validate_packet(packet | {field: value}, "descriptor", expected)

    def test_public_handoff_does_not_accept_private_or_unknown_fields(self):
        for field in ("token", "secret", "namespace", "native_home", "private_offer", "log", "cap"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                qualification.validate_packet(self.descriptor() | {field: "secret-value"},
                                              "descriptor", self.expected())
        with self.assertRaises(ValueError):
            qualification.validate_packet(self.descriptor() | {"link": "x" * 8193}, "descriptor", self.expected())
        with self.assertRaises(ValueError):
            qualification.validate_packet(self.descriptor() | {"pin": "not-a-pin"}, "descriptor", self.expected())

    def test_client_handoff_must_select_this_host(self):
        packet = qualification.public_packet(self.expected("f"), "client-offline",
                                               pin="1" * 64, host_machine="e" * 64)
        qualification.validate_packet(packet, "client-offline", self.expected())
        with self.assertRaises(ValueError):
            qualification.validate_packet(packet | {"host_machine": "0" * 64}, "client-offline", self.expected())

    def test_replacement_requires_actual_owner_stop_boolean(self):
        fields = dict(link="valhalla://public/1/placeholder", pin="1" * 64, author="2" * 64,
                      peer="3" * 64, replaced_peer="4" * 64)
        for value in (False, 1, None, "true"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                qualification.public_packet(self.expected(), "host-offline-ready", **fields, owner_stopped=value)

    def test_result_whitelist_requires_every_case_and_no_extra_payload(self):
        cases = {key: True for key in qualification.CLIENT_CASES}
        cases["host_machine"] = "f" * 64
        qualification.validate_cases(cases, qualification.CLIENT_CASES, "client")
        for modification in ({"exact_retry": 1}, {"service_joined": False}, {"log": "private"}):
            with self.subTest(modification=modification), self.assertRaises(ValueError):
                qualification.validate_cases(cases | modification, qualification.CLIENT_CASES, "client")

    def test_path_claims_do_not_infer_observation_from_configuration(self):
        for mode in ("unreported", "relay_only", "direct_only", "automatic"):
            claims = qualification.path_claims(mode)
            self.assertEqual(claims["observed_path"], "unreported")
            for key in ("forced_relay_qualified", "direct_path_qualified", "independent_nat_qualified",
                        "private_qualified", "browser_qualified", "per_byte_path_qualified"):
                self.assertIs(claims[key], False)

    def test_path_claims_distinguish_automatic_routing_and_point_in_time_evidence(self):
        relay = qualification.path_claims("relay_only", self.transport())
        self.assertEqual(relay["observed_path"], "relay_only_snapshots")
        self.assertTrue(relay["forced_relay_qualified"])
        self.assertFalse(relay["per_byte_path_qualified"])
        automatic = qualification.path_claims("automatic", self.transport())
        self.assertEqual(automatic["observed_path"], "relay_only_snapshots")
        self.assertFalse(automatic["forced_relay_qualified"])
        direct = qualification.path_claims("direct_only", self.transport(selected="direct"))
        self.assertEqual(direct["observed_path"], "direct_snapshots")
        self.assertTrue(direct["direct_path_qualified"])
        self.assertFalse(direct["independent_nat_qualified"])

    def test_transport_requires_complete_nonempty_before_and_after_relay_snapshots(self):
        qualification.validate_transport(self.transport(), "client", "relay_only")
        stage = "member_to_owner"
        for when in ("before", "after"):
            for change in ({"nonempty": False}, {"all_relay": False}, {"selected": "direct"},
                           {"all_relay": 1}, {"nonempty": "true"}, {"addresses": ["private"]}):
                value = self.transport()
                value[stage][when].update(change)
                with self.subTest(when=when, change=change), self.assertRaises(ValueError):
                    qualification.validate_transport(value, "client", "relay_only")
        for value in ({}, self.transport() | {"unexpected": self.observation()},
                      {stage: self.observation() | {"address": "private"}},
                      {stage: self.observation()}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                qualification.validate_transport(value, "client", "relay_only")
        value = self.transport()
        value[stage]["after"]["selected"] = "unknown"
        qualification.validate_transport(value, "client", "relay_only")

    def test_direct_baseline_requires_actual_direct_selected_snapshots(self):
        qualification.validate_transport(self.transport(selected="direct"), "client", "direct_only")
        for selected in ("relay", "unknown"):
            with self.assertRaises(ValueError):
                qualification.validate_transport(self.transport(selected=selected), "client", "direct_only")

    def test_observations_are_taken_only_from_the_matching_selected_source(self):
        config = dict(work="/tmp/synthetic", role="client", relay=qualification.RELAY, relay_only=True)
        journey = qualification.Journey(config)
        observed = self.observation()
        snapshots = {key: observed[key] for key in ("before", "after")}
        daemon = Mock()
        daemon.call.return_value = dict(selected_sources=[dict(peer="3" * 64,
                                                               last_transport_observation=snapshots)])
        journey.observe(daemon, "1" * 32, "member_to_owner", "3" * 64)
        self.assertEqual(journey.transport["member_to_owner"], observed)
        with self.assertRaises(ValueError):
            journey.observe(daemon, "1" * 32, "member_to_owner", "3" * 64)
        with self.assertRaises(ValueError):
            journey.observe(daemon, "1" * 32, "member_to_replacement", "4" * 64)
        daemon.call.return_value["selected_sources"][0]["last_transport_observation"] = None
        with self.assertRaises(ValueError):
            journey.observe(daemon, "1" * 32, "member_to_replacement", "3" * 64)

    def test_final_receipt_binds_the_admitted_client_and_honest_scope(self):
        expected = self.expected() | {"selected_client_machine": "f" * 64, "configured_path_mode": "relay_only"}
        observations = self.transport()
        value = self.expected("f") | qualification.path_claims("relay_only", observations) | dict(
            schema=qualification.SCHEMA, role="client", passed=True, cleanup_confirmed=True,
            transport_observations=observations, relay_configured=True,
            cases={key: True for key in qualification.CLIENT_CASES} | {"host_machine": "e" * 64})
        with patch.multiple(qualification.controller, SCHEMA=qualification.SCHEMA,
                            CLIENT_CASES=qualification.CLIENT_CASES):
            qualification.validate_client(value, expected)
            for change in ({"machine": "1" * 64}, {"observed_path": "relay"},
                           {"forced_relay_qualified": False}, {"private_qualified": True},
                           {"per_byte_path_qualified": True}, {"transport_observations": {}},
                           {"relay_configured": False}, {"configured_path_mode": "automatic"}):
                with self.subTest(change=change), self.assertRaises(ValueError):
                    qualification.validate_client(value | change, expected)

    def test_daemon_selects_relay_only_and_checks_the_reported_configuration(self):
        for relay_only in (False, True):
            config = dict(work="/tmp/synthetic", binary="/absolute/vhalla", relay=qualification.RELAY,
                          relay_only=relay_only)
            daemon = qualification.Daemon(config, "b")
            status = dict(headless=True, network=dict(listening=True,
                configured=dict(relay_url=qualification.RELAY, relay_only=relay_only)))
            child = Mock()
            child.poll.return_value = None
            with patch.object(daemon, "invoke", return_value=status), \
                    patch.object(qualification.subprocess, "Popen", return_value=child) as spawned:
                daemon.start(initialize=False)
                self.assertEqual("--relay-only" in spawned.call_args.args[0], relay_only)
            daemon = qualification.Daemon(config, "b")
            status["network"]["configured"]["relay_only"] = not relay_only
            with patch.object(daemon, "invoke", return_value=status), \
                    patch.object(qualification.subprocess, "Popen", return_value=child):
                with self.assertRaises(ValueError):
                    daemon.start(initialize=False)

    def test_json_input_and_output_are_real_pipes_and_credentials_are_stripped(self):
        script = ("import json,os,stat,sys; value=json.load(sys.stdin); "
                  "print(json.dumps({'input':value,'stdin_pipe':stat.S_ISFIFO(os.fstat(0).st_mode),"
                  "'stdout_pipe':stat.S_ISFIFO(os.fstat(1).st_mode),'keys':sorted(os.environ)}))")
        with patch.dict(os.environ, {"GH_TOKEN": "secret", "ACTIONS_RUNTIME_TOKEN": "secret",
                                    "PROVIDER_SECRET": "secret", "HOME": "/private/session"}):
            env = qualification.controller.child_env(Path("synthetic-config.json"))
            code, raw = qualification.exchange([sys.executable, "-c", script], b'{"op":"example"}', env)
        value = json.loads(raw)
        self.assertEqual(code, 0)
        self.assertEqual(value["input"], {"op": "example"})
        self.assertTrue(value["stdin_pipe"] and value["stdout_pipe"])
        for key in ("GH_TOKEN", "ACTIONS_RUNTIME_TOKEN", "PROVIDER_SECRET", "HOME"):
            self.assertNotIn(key, value["keys"])

    def test_timeout_reaps_the_exact_process_even_with_blocked_stdin(self):
        children = []
        original = subprocess.Popen
        def tracked(*args, **kwargs):
            child = original(*args, **kwargs)
            children.append(child)
            return child
        started = time.monotonic()
        with patch.object(qualification.subprocess, "Popen", side_effect=tracked):
            with self.assertRaises(ValueError):
                qualification.exchange([sys.executable, "-c", "import time;time.sleep(30)"],
                    b"x" * qualification.controller.MAX_JSON, {}, timeout=0.15)
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].poll())

    def test_oversized_stdout_and_stderr_are_refused_and_reaped(self):
        for stream, count in (("stdout", qualification.MAX_REPLY + 1), ("stderr", 16385)):
            with self.subTest(stream=stream), self.assertRaises(ValueError):
                qualification.exchange([sys.executable, "-c",
                    f"import sys;sys.{stream}.buffer.write(b'x'*{count})"], b"", {}, timeout=5)

    def test_typed_refusal_does_not_count_as_success(self):
        config = dict(work="/tmp/synthetic", binary="/absolute/vhalla")
        daemon = qualification.Daemon(config, "b")
        with patch.object(qualification, "exchange", return_value=(1, b'{"ok":false,"error":{"code":"permission-denied"}}')):
            with self.assertRaises(qualification.CliRefusal) as raised:
                daemon.call("room.send", room="0" * 32)
        self.assertEqual(raised.exception.code, "permission-denied")
        for result in ((0, b'{"ok":false,"error":{"code":"permission-denied"}}'),
                       (1, b'{"ok":true,"result":{}}'), (0, b'{"ok":true}')):
            with self.subTest(result=result), patch.object(qualification, "exchange", return_value=result):
                with self.assertRaises(ValueError):
                    daemon.invoke("status")

    def test_cli_calls_disable_updates_and_use_json_stdin_not_arguments(self):
        config = dict(work="/tmp/synthetic", binary="/absolute/vhalla")
        request = {"op": "room.send", "body": "literal `text` $(text)\nwith newline"}
        with patch.object(qualification, "exchange", return_value=(0, b'{"ok":true,"result":{}}')) as exchanged:
            qualification.Daemon(config, "b").invoke("call", request)
        argv, payload, env = exchanged.call_args.args
        self.assertEqual(argv, ["/absolute/vhalla", "--no-update", "daemon", "call", "--home", "/tmp/synthetic/b"])
        self.assertEqual(json.loads(payload), request)
        self.assertNotIn(request["body"], argv)
        self.assertNotIn("HOME", env)

    def test_candidate_hash_mismatch_refuses_before_running_any_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory).resolve()
            binary = work / "binary"
            binary.write_bytes(b"not the candidate")
            qualification.write_json(work / "config.json", dict(role="host", work=str(work),
                binary=str(binary), binary_sha256="0" * 64))
            with patch.object(qualification, "Journey") as journey:
                with self.assertRaises(ValueError):
                    qualification.run_role(work)
                journey.assert_not_called()

    def test_local_failure_keeps_state_and_reports_no_remote_qualification(self):
        # A tiny deliberately refusing executable tests actual role supervision,
        # not the public protocol. The real journey requires a candidate build.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            binary = root / "refuse"
            binary.write_text(f"#!{sys.executable}\nimport sys\n"
                              "print('{\"ok\":false,\"error\":{\"code\":\"usage\"}}')\nsys.exit(2)\n")
            binary.chmod(0o700)
            work = root / "work"
            self.assertFalse(qualification.local(binary, work, None))
            receipt = qualification.read_json(work / "local-receipt.json")
            self.assertFalse(receipt["passed"])
            self.assertTrue(receipt["cleanup_confirmed"])
            self.assertFalse(receipt["independent_machines_qualified"])
            self.assertFalse(receipt["source_attested"])
            self.assertTrue((work / "host/config.json").is_file())
            self.assertTrue((work / "client/config.json").is_file())


if __name__ == "__main__":
    unittest.main()
