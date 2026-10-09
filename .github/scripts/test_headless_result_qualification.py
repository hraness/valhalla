"""Exact-artifact aggregate tests; no network, daemon, or credentials."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import headless_result_qualification as result
import headless_linux_managed_qualification as linux
import headless_managed_qualification as managed
import headless_mcp_qualification as mcp
import headless_private_qualification as private
import headless_qualification as public

SHA = "a" * 40
NOW = 1800000000
RUN = "73"
ATTEMPT = "2"


def write(path, value):
    path.write_text(json.dumps(value) + "\n")


def read(path):
    return json.loads(path.read_text())


def hash_bytes(value):
    return hashlib.sha256(value).hexdigest()


def observations(stages, *, operation=False):
    snapshot = {"selected": "relay", "nonempty": True, "all_relay": True}
    return {stage: dict(peer=hash_bytes(stage.encode()), before=snapshot, after=snapshot,
                        **({"operation": "put"} if operation else {})) for stage in stages}


class HeadlessResultTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.root = base / "artifacts"
        self.root.mkdir()
        self.lock = base / "Cargo.lock"
        self.lock.write_bytes(b"locked candidate\n")
        self.files = {}
        for directory, names in {
            "binary": ("build.json", "fixture"),
            "public-host": ("host-receipt.json",), "public-client": ("client-receipt.json",),
            "private-host": ("host-receipt.json",), "private-client": ("client-receipt.json",),
            "linux-managed": ("receipt.json", "cleanup-receipt.json"), "mcp": ("receipt.json",),
        }.items():
            folder = self.root / directory
            folder.mkdir()
            for name in names:
                self.files[directory, name] = folder / name
        self.files["binary", "fixture"].write_bytes(b"release executable bytes")
        self.expected = dict(source_sha=SHA, run_id=RUN, run_attempt=ATTEMPT,
                             nonce="b" * 64, binary_sha256=hash_bytes(b"release executable bytes"),
                             lock_sha256=result.digest(self.lock, 1000))
        write(self.files["binary", "build.json"], dict(self.expected, schema=public.SCHEMA,
              features="headless", toolchain="1.98.1", target="x86_64-unknown-linux-gnu",
              build_profile="release", cargo_profile={"opt_level": "3", "test": False,
                                                        "debug_assertions": False}))
        for kind, module in (("public", public), ("private", private)):
            host_machine, client_machine = hash_bytes(kind.encode()), hash_bytes((kind + "-client").encode())
            for role, machine, other in (("host", host_machine, client_machine),
                                         ("client", client_machine, host_machine)):
                obs = observations(module.TRANSPORT_STAGES[role], operation=kind == "private")
                if kind == "public":
                    doc = dict(self.expected, schema=module.SCHEMA, role=role, machine=machine,
                               passed=True, cleanup_confirmed=True, fixture_exit_code=0,
                               fixture_forced_cleanup=False, started_unix=NOW - 20,
                               finished_unix=NOW - 1, relay_configured=True,
                               placement="separate GitHub-hosted Ubuntu job VMs; NAT diversity unmeasured",
                               cases={key: True for key in (module.HOST_CASES if role == "host" else module.CLIENT_CASES)},
                               transport_observations=obs, **module.path_claims("relay_only", obs))
                    if role == "client":
                        doc["cases"]["host_machine"] = other
                else:
                    doc = dict(self.expected, schema=module.SCHEMA, role=role, machine=machine,
                               passed=True, cleanup_confirmed=True, fixture_exit_code=0,
                               fixture_forced_cleanup=False, started_unix=NOW - 20,
                               finished_unix=NOW - 1, source_attested=True,
                               placement="separate GitHub-hosted Ubuntu VMs; NAT diversity unmeasured",
                               cases={key: True for key in (module.HOST_CASES if role == "host" else module.CLIENT_CASES)},
                               remote_machine=other, transport_observations=obs,
                               **module.claims({"relay": module.RELAY, "mode": "runners"}, True, obs))
                if role == "host":
                    doc.update(client_verified=True, selected_client_machine=other)
                    if kind == "public":
                        doc["client_machine"] = other
                write(self.files[kind + "-" + role, role + "-receipt.json"], doc)
        cases = {*managed.CASES, "initial_process_verified", "resumed_process_verified", "enable_link_removed"}
        write(self.files["linux-managed", "receipt.json"], dict(self.expected, schema=linux.SCHEMA,
              passed=True, cleanup_confirmed=True, cleanup_fallback_used=False,
              started_unix=NOW-20, finished_unix=NOW-1, build_profile="release",
              platform="Linux systemd user", scope="one fresh synthetic home; loopback only",
              runner_sha256=result.digest(result.SCRIPTS / "headless_linux_managed_qualification.py", 1024*1024),
              common_runner_sha256=result.digest(result.SCRIPTS / "headless_managed_qualification.py", 1024*1024),
              cases={name: True for name in cases}))
        write(self.files["linux-managed", "cleanup-receipt.json"], dict(
              schema=linux.SCHEMA, source_sha=SHA, run_id=RUN, run_attempt=ATTEMPT,
              cleanup_confirmed=True, cleanup_fallback_used=False))
        write(self.files["mcp", "receipt.json"], dict(schema=mcp.SCHEMA,
              source_sha=SHA, binary_sha256=self.expected["binary_sha256"], passed=True,
              cleanup_confirmed=True, cleanup_fallback_used=False, started_unix=NOW-20,
              finished_unix=NOW-1, runner_sha256=result.digest(result.SCRIPTS / "headless_mcp_qualification.py", 1024*1024),
              platform="linux", scope="one fresh public room; actual foreground daemon and MCP pipes; no network peer",
              cases={name: True for name in mcp.CASES}))

    def verify(self):
        result.verify(self.root, SHA, RUN, ATTEMPT, self.lock, now=NOW)

    def mutate(self, selected, field, value):
        path = self.files[selected]
        doc = read(path)
        doc[field] = value
        write(path, doc)

    def test_complete_receipts_with_mcp_emitted_fields_only(self):
        self.verify()
        self.assertNotIn("run_id", read(self.files["mcp", "receipt.json"]))
        self.assertNotIn("lock_sha256", read(self.files["mcp", "receipt.json"]))
        self.assertNotIn("client_machine", read(self.files["private-host", "host-receipt.json"]))

    def test_missing_and_unexpected_artifact_rejected(self):
        self.files["mcp", "receipt.json"].unlink()
        with self.assertRaises((OSError, ValueError)):
            self.verify()

    def test_malformed_and_duplicate_json_rejected(self):
        path = self.files["mcp", "receipt.json"]
        path.write_text('{"passed":true,"passed":true}')
        with self.assertRaises(ValueError):
            self.verify()

    def test_failed_cleanup_rejected_even_if_journey_passed(self):
        for selected, field, value in (
            (("linux-managed", "cleanup-receipt.json"), "cleanup_confirmed", False),
            (("linux-managed", "receipt.json"), "cleanup_fallback_used", True),
            (("mcp", "receipt.json"), "cleanup_confirmed", False),
            (("public-host", "host-receipt.json"), "fixture_forced_cleanup", True),
        ):
            with self.subTest(selected=selected):
                path = self.files[selected]
                original = path.read_text()
                self.mutate(selected, field, value)
                with self.assertRaises(ValueError):
                    self.verify()
                path.write_text(original)

    def test_stale_future_and_cross_run_receipts_rejected(self):
        for selected, field, value in (
            (("public-client", "client-receipt.json"), "finished_unix", NOW - result.MAX_AGE - 1),
            (("private-host", "host-receipt.json"), "started_unix", NOW + result.SKEW + 1),
            (("public-host", "host-receipt.json"), "run_attempt", "1"),
            (("private-client", "client-receipt.json"), "nonce", "c" * 64),
            (("linux-managed", "cleanup-receipt.json"), "run_id", "72"),
            (("mcp", "receipt.json"), "source_sha", "c" * 40),
            (("mcp", "receipt.json"), "binary_sha256", "c" * 64),
        ):
            with self.subTest(selected=selected, field=field):
                path = self.files[selected]
                original = path.read_text()
                self.mutate(selected, field, value)
                with self.assertRaises(ValueError):
                    self.verify()
                path.write_text(original)

    def test_binary_and_lock_bytes_bound(self):
        path = self.files["binary", "fixture"]
        path.write_bytes(b"other executable")
        with self.assertRaises(ValueError):
            self.verify()
        path.write_bytes(b"release executable bytes")
        self.lock.write_bytes(b"different lock")
        with self.assertRaises(ValueError):
            self.verify()

    def test_missing_case_or_unsupported_claim_rejected(self):
        for selected, field, value in (
            (("private-client", "client-receipt.json"), "direct_path_qualified", True),
            (("private-host", "host-receipt.json"), "browser_qualified", True),
            (("public-client", "client-receipt.json"), "independent_nat_qualified", True),
            (("public-host", "host-receipt.json"), "per_byte_path_qualified", True),
            (("mcp", "receipt.json"), "scope", "internet qualified"),
        ):
            with self.subTest(selected=selected, field=field):
                path = self.files[selected]
                original = path.read_text()
                self.mutate(selected, field, value)
                with self.assertRaises(ValueError):
                    self.verify()
                path.write_text(original)
        selected = ("mcp", "receipt.json")
        doc = read(self.files[selected])
        doc["cases"].pop(next(iter(mcp.CASES)))
        write(self.files[selected], doc)
        with self.assertRaises(ValueError):
            self.verify()

    def test_changed_runner_or_peer_selection_rejected(self):
        for selected, field, value in (
            (("linux-managed", "receipt.json"), "runner_sha256", "0" * 64),
            (("private-host", "host-receipt.json"), "remote_machine", "0" * 64),
            (("public-client", "client-receipt.json"), "machine", "0" * 64),
        ):
            with self.subTest(selected=selected):
                path = self.files[selected]
                original = path.read_text()
                self.mutate(selected, field, value)
                with self.assertRaises(ValueError):
                    self.verify()
                path.write_text(original)


if __name__ == "__main__":
    unittest.main()
