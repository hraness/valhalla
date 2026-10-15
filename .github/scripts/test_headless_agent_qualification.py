"""Deterministic contract tests for the scoped MCP fixture seam; no network pass."""

import json
from pathlib import Path
import stat
import tempfile
import unittest

from headless_agent_qualification import (AgentRefusal, BUDGET, PERMISSIONS,
    ScopedAgent, fixed_public_scope, private_grant)
from headless_mcp_qualification import INITIALIZE_PROTOCOL

ROOM, PIN, AUTHOR, POLICY = "1" * 32, "2" * 64, "3" * 64, "4" * 64
GENERATION, TOKEN, HASH = "5" * 64, "6" * 64, "7" * 64


def frame(number, result=None, error=None):
    value = {"jsonrpc": "2.0", "id": number}
    value["error" if error is not None else "result"] = error if error is not None else result
    return value


def reply(data, *, refused=False, error=None):
    initialized = frame("initialize", {"protocolVersion": INITIALIZE_PROTOCOL,
                                       "serverInfo": {"name": "valhalla"}})
    called = frame(1, {"isError": refused, "structuredContent": data}, error=error)
    return b"".join(json.dumps(value).encode() + b"\n" for value in (initialized, called))


class FakeDaemon:
    def __init__(self, work):
        self.config = {"work": str(work)}
        self.home = work / "home"
        self.argv = ["/immutable/fixture", "--no-update", "daemon"]
        self.env = {"PATH": "/usr/bin:/bin"}
        self.status = {"room": ROOM, "kind": "public", "pin": PIN, "author": AUTHOR,
                       "policy": {"id": POLICY, "revision": 1}}
        self.calls = []
        self.revoke = True
        self.issued_override = None

    def call(self, op, **fields):
        self.calls.append((op, fields))
        if op == "room.status":
            return self.status
        if op == "grant.issue":
            if self.issued_override is not None:
                return self.issued_override
            return {"generation": GENERATION, "token": TOKEN, "room": ROOM,
                    "scope": fields["grant"]["scope"], "permissions": PERMISSIONS,
                    "expires_at": fields["grant"]["expires_at"], "allowance": "retained"}
        if op == "grant.revoke":
            return {"revoked": self.revoke}
        raise AssertionError("agent data was routed to owner-admin: " + op)


class ScopedAgentTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.work = Path(temp.name) / "role"
        self.work.mkdir(mode=0o700)
        self.daemon = FakeDaemon(self.work)
        self.responses = []
        self.launches = []
        self.agent = ScopedAgent(self.daemon, ROOM, PIN, self.work / "grant.json",
                                 transport=self.transport, clock=lambda: 2_000_000_000)

    def transport(self, argv, payload, env, timeout):
        self.launches.append((argv, payload, env, timeout))
        return 0, self.responses.pop(0)

    def issue(self):
        return self.agent.issue("8" * 32)

    def test_issue_is_fixed_room_finite_and_file_only_contains_credentials(self):
        summary = self.issue()
        self.assertEqual(summary["scope"], {"kind": "public", "pin": PIN, "author": AUTHOR,
                                             "policy": POLICY, "revision": 1})
        self.assertEqual(summary["budget"], BUDGET)
        self.assertNotIn("token", json.dumps(summary))
        self.assertEqual(json.loads(self.agent.grant_path.read_text()),
                         {"generation": GENERATION, "token": TOKEN})
        self.assertEqual(stat.S_IMODE(self.agent.grant_path.stat().st_mode), 0o600)
        self.assertEqual(self.daemon.calls[1][1]["grant"]["expires_at"], 2_000_000_600)
        with self.assertRaisesRegex(ValueError, "already issued"):
            self.issue()
        self.agent.close()
        self.assertFalse(self.agent.grant_path.exists())
        self.assertEqual([name for name, _ in self.daemon.calls],
                         ["room.status", "grant.issue", "grant.revoke"])

    def test_foreign_pin_policy_and_nonpublic_room_never_mint_grant(self):
        for field, value in (("pin", "a" * 64), ("kind", "private"),
                             ("policy", {"id": POLICY, "revision": True})):
            status = self.daemon.status.copy()
            status[field] = value
            with self.assertRaises(ValueError):
                fixed_public_scope(status, PIN)
        self.daemon.status["pin"] = "a" * 64
        with self.assertRaises(ValueError):
            self.issue()
        self.assertEqual([name for name, _ in self.daemon.calls], ["room.status"])

    def test_mismatched_issued_grant_is_revoked_before_launch(self):
        self.daemon.issued_override = {"generation": GENERATION, "token": TOKEN,
                                       "room": ROOM, "scope": {"kind": "private"},
                                       "permissions": PERMISSIONS, "expires_at": 2_000_000_600}
        with self.assertRaisesRegex(ValueError, "differs from selected scope"):
            self.issue()
        self.assertEqual([name for name, _ in self.daemon.calls],
                         ["room.status", "grant.issue", "grant.revoke"])
        self.assertEqual(self.daemon.calls[-1][1],
                         {"generation": GENERATION, "token": TOKEN})
        self.assertIsNone(self.agent.grant)
        self.assertFalse(self.agent.grant_path.exists())
        self.assertEqual(self.launches, [])

    def test_missing_issued_credentials_leave_explicit_uncertainty(self):
        self.daemon.issued_override = {"room": ROOM, "scope": {"kind": "private"}}
        with self.assertRaisesRegex(ValueError, "revocation unconfirmed"):
            self.issue()
        self.assertEqual([name for name, _ in self.daemon.calls], ["room.status", "grant.issue"])
        self.assertFalse(self.agent.grant_path.exists())
        self.assertEqual(self.launches, [])

    def test_existing_grant_file_and_link_are_refused(self):
        path = self.agent.grant_path
        path.write_text("existing")
        with self.assertRaises(ValueError):
            private_grant(path, {"generation": GENERATION, "token": TOKEN})
        path.unlink()
        path.symlink_to(self.work / "other")
        with self.assertRaises(ValueError):
            private_grant(path, {"generation": GENERATION, "token": TOKEN})
        self.assertTrue(path.is_symlink())

    def test_mcp_send_retry_and_read_are_scoped_and_not_delivery_claims(self):
        self.issue()
        sent = {"room": ROOM, "operation": "9" * 32, "frame_hash": HASH,
                "exact_retry": False, "delivery": "not asserted"}
        self.responses = [reply(sent), reply({**sent, "exact_retry": True}),
                          reply({"room": ROOM, "records": [{"text": "inert",
                              "trust": "inert untrusted room content"}]})]
        self.assertFalse(self.agent.send("9" * 32, "inert")["exact_retry"])
        self.assertTrue(self.agent.send("9" * 32, "inert")["exact_retry"])
        self.assertEqual(self.agent.messages()[0]["text"], "inert")
        self.assertEqual(len(self.launches), 3)
        for argv, payload, _env, timeout in self.launches:
            self.assertEqual(argv[-2:], ["--grant", str(self.agent.grant_path)])
            self.assertEqual(timeout, 35)
            frames = [json.loads(line) for line in payload.splitlines()]
            self.assertEqual([row["method"] for row in frames],
                             ["initialize", "notifications/initialized", "tools/call"])
            self.assertNotIn(TOKEN.encode(), payload)
        self.assertEqual([name for name, _ in self.daemon.calls], ["room.status", "grant.issue"])

    def test_cross_room_and_exhausted_grant_refuse_by_typed_codes(self):
        self.issue()
        self.responses = [reply(None, error={"code": -32602, "message": "Invalid tool arguments"}),
                          reply({"status": "refused", "code": "permission-denied"}, refused=True)]
        with self.assertRaises(AgentRefusal) as cross:
            self.agent.call("agent.status", room="another")
        self.assertEqual(cross.exception.code, -32602)
        with self.assertRaises(AgentRefusal) as exhausted:
            self.agent.status()
        self.assertEqual(exhausted.exception.code, "permission-denied")

    def test_wrong_room_and_untrusted_page_fail_closed(self):
        self.issue()
        self.responses = [reply({"room": "a" * 32, "kind": "public", "author": AUTHOR}),
                          reply({"room": ROOM, "records": [{"text": "secret"}]})]
        with self.assertRaisesRegex(ValueError, "escaped"):
            self.agent.status()
        with self.assertRaisesRegex(ValueError, "inert"):
            self.agent.messages()

    def test_credential_echo_and_unsupported_delivery_are_refused(self):
        self.issue()
        self.responses = [reply({"room": ROOM, "secret": TOKEN}),
                          reply({"room": ROOM, "operation": "9" * 32, "frame_hash": HASH,
                                 "exact_retry": False, "delivery": "delivered"})]
        with self.assertRaisesRegex(ValueError, "exposed"):
            self.agent.status()
        with self.assertRaisesRegex(ValueError, "unsupported delivery"):
            self.agent.send("9" * 32, "inert")

    def test_failed_revoke_is_not_reported_as_cleanup(self):
        self.issue()
        self.daemon.revoke = False
        with self.assertRaisesRegex(ValueError, "unconfirmed"):
            self.agent.close()
        self.assertFalse(self.agent.grant_path.exists())
        self.assertIsNotNone(self.agent.grant)


if __name__ == "__main__":
    unittest.main()
