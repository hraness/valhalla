"""Deterministic contract tests for the scoped MCP fixture seam; no network pass."""

import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
from types import SimpleNamespace
import unittest

import headless_qualification as public
from headless_agent_qualification import (AgentRefusal, BUDGET, MAX_OUTBOX_PAGES, PERMISSIONS,
    ScopedAgent, fixed_public_scope, issue_agent_pair, private_grant)
from headless_managed_qualification import digest
from headless_mcp_qualification import INITIALIZE_PROTOCOL, McpRun

ROOM, PIN, AUTHOR, POLICY = "1" * 32, "2" * 64, "3" * 64, "4" * 64
GENERATION, TOKEN, HASH = "5" * 64, "6" * 64, "7" * 64
PEER, EVENT = "a" * 64, "b" * 64


def frame(number, result=None, error=None):
    value = {"jsonrpc": "2.0", "id": number}
    value["error" if error is not None else "result"] = error if error is not None else result
    return value


def reply(data, *, refused=False, error=None):
    initialized = frame("initialize", {"protocolVersion": INITIALIZE_PROTOCOL,
                                       "serverInfo": {"name": "valhalla"}})
    called = frame(1, {"isError": refused, "structuredContent": data}, error=error)
    return b"".join(json.dumps(value).encode() + b"\n" for value in (initialized, called))


def completion(operation, cursor, frame_hash=HASH):
    return {"cursor": cursor, "operation": operation, "kind": "Event", "frame_hash": frame_hash}


def outbox(rows, head=40, next_cursor=None):
    return reply({"room": ROOM, "kind": "public", "head": head, "next": next_cursor,
                  "operations": rows, "delivery": "not asserted"})


def message(cursor=31, text="synthetic", author=PEER, visibility="Provisional"):
    return {"cursor": cursor, "event": EVENT, "author": author, "sequence": 1,
            "policy": POLICY, "text": text, "visibility": visibility,
            "trust": "inert untrusted room content"}


def inbox(rows, head=40, next_cursor=None):
    return reply({"room": ROOM, "kind": "public", "head": head, "next": next_cursor,
                  "records": rows})


class FakeDaemon:
    def __init__(self, work, *, room=ROOM, author=AUTHOR,
                 generation=GENERATION, token=TOKEN):
        self.config = {"work": str(work)}
        self.home = work / "home"
        self.argv = ["/immutable/fixture", "--no-update", "daemon"]
        self.env = {"PATH": "/usr/bin:/bin"}
        self.status = {"room": room, "kind": "public", "pin": PIN, "author": author,
                       "policy": {"id": POLICY, "revision": 1}}
        self.generation, self.token = generation, token
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
            return {"generation": self.generation, "token": self.token,
                    "room": self.status["room"],
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
        with self.assertRaisesRegex(ValueError, "already attempted or issued"):
            self.issue()
        self.agent.close()
        self.assertFalse(self.agent.grant_path.exists())
        self.assertEqual([name for name, _ in self.daemon.calls],
                         ["room.status", "grant.issue", "grant.revoke"])
        with self.assertRaisesRegex(ValueError, "already attempted or issued"):
            self.agent.issue("9" * 32)
        self.assertEqual(len(self.daemon.calls), 3)

    def test_confirmed_direct_revoke_still_removes_private_file_on_close(self):
        self.issue()
        self.agent.revoke()
        self.assertIsNone(self.agent.grant)
        self.assertTrue(self.agent.grant_path.is_file())
        self.agent.close()
        self.assertFalse(self.agent.grant_path.exists())
        self.assertFalse(self.agent.owns_file)
        self.agent.close()  # Idempotent local cleanup, not another owner write.
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

    def test_wrong_room_status_refuses_before_grant_mint(self):
        self.daemon.status["room"] = "a" * 32
        with self.assertRaisesRegex(ValueError, "differs from selected room"):
            self.issue()
        self.assertEqual([name for name, _ in self.daemon.calls], ["room.status"])
        self.assertFalse(self.agent.grant_path.exists())
        self.assertEqual(self.launches, [])

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
        with self.assertRaisesRegex(ValueError, "already attempted or issued"):
            self.agent.issue("9" * 32)
        self.assertEqual(len(self.daemon.calls), 3)

    def test_missing_issued_credentials_leave_explicit_uncertainty(self):
        self.daemon.issued_override = {"room": ROOM, "scope": {"kind": "private"}}
        with self.assertRaisesRegex(ValueError, "revocation unconfirmed"):
            self.issue()
        self.assertEqual([name for name, _ in self.daemon.calls], ["room.status", "grant.issue"])
        self.assertFalse(self.agent.grant_path.exists())
        self.assertEqual(self.launches, [])
        with self.assertRaisesRegex(ValueError, "already attempted or issued"):
            self.agent.issue("9" * 32)
        self.assertEqual([name for name, _ in self.daemon.calls], ["room.status", "grant.issue"])

    def test_owner_issue_lost_reply_is_never_retried(self):
        def lost(op, **fields):
            if op == "grant.issue":
                self.daemon.calls.append((op, fields))
                raise TimeoutError("owner reply lost")
            return FakeDaemon.call(self.daemon, op, **fields)
        self.daemon.call = lost
        with self.assertRaises(TimeoutError):
            self.issue()
        with self.assertRaisesRegex(ValueError, "already attempted or issued"):
            self.agent.issue("9" * 32)
        self.assertEqual([name for name, _ in self.daemon.calls], ["room.status", "grant.issue"])
        self.assertFalse(self.agent.grant_path.exists())

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

    def test_status_requires_pinned_policy_and_finite_authenticated_allowance(self):
        self.issue()
        status = {"room": ROOM, "kind": "public", "author": AUTHOR, "policy": POLICY,
                  "revision": 1, "remaining": {**BUDGET, "calls": BUDGET["calls"] - 1},
                  "freshness": "local authenticated state"}
        self.responses = [reply(status)]
        self.assertEqual(self.agent.status()["remaining"]["calls"], BUDGET["calls"] - 1)
        cases = [({"policy": "a" * 64}, "pinned public scope"),
                 ({"revision": 2}, "pinned public scope"),
                 ({"revision": True}, "pinned public scope"),
                 ({"freshness": "unverified"}, "finite authenticated allowance"),
                 ({"remaining": {**BUDGET, "calls": BUDGET["calls"] + 1}},
                  "finite authenticated allowance"),
                 ({"remaining": {**BUDGET, "send_attempts": True}},
                  "finite authenticated allowance"),
                 ({"remaining": {**BUDGET, "read_bytes": -1}},
                  "finite authenticated allowance"),
                 ({"remaining": {"calls": 1}}, "finite authenticated allowance")]
        for changed, reason in cases:
            with self.subTest(changed=changed):
                self.responses = [reply({**status, **changed})]
                with self.assertRaisesRegex(ValueError, reason):
                    self.agent.status()
        self.assertEqual(len(self.launches), len(cases) + 1)
        self.assertEqual([name for name, _ in self.daemon.calls], ["room.status", "grant.issue"])

    def test_duplicate_scoped_mcp_json_field_refuses_before_status_admission(self):
        self.issue()
        status = {"room": ROOM, "kind": "public", "author": AUTHOR, "policy": POLICY,
                  "revision": 1, "remaining": BUDGET,
                  "freshness": "local authenticated state"}
        good = reply(status)
        key = f'"room": "{ROOM}"'.encode()
        self.assertEqual(good.count(key), 1)
        self.responses = [good.replace(key, key + b', "room": "' + b'a' * 32 + b'"')]
        with self.assertRaisesRegex(ValueError, "duplicate MCP JSON field"):
            self.agent.status()
        self.assertEqual(len(self.launches), 1)
        self.assertEqual([name for name, _ in self.daemon.calls], ["room.status", "grant.issue"])

    def test_peer_event_scans_stable_pages_and_returns_body_free_local_evidence(self):
        self.issue()
        self.responses = [inbox([message(12, "unrelated", AUTHOR)], next_cursor=20),
                          inbox([message()])]
        summary = self.agent.peer_event(PEER, "synthetic")
        self.assertEqual(summary, {"event": EVENT, "author": PEER, "sequence": 1,
                                   "visibility": "Provisional", "local_signed_event_once": True,
                                   "delivery": "not asserted"})
        self.assertNotIn("synthetic", json.dumps(summary))
        self.assertNotIn(TOKEN, json.dumps(summary))
        self.assertEqual([json.loads(launch[1].splitlines()[-1])["params"]["arguments"]
                          for launch in self.launches],
                         [{"after": 0, "limit": 16}, {"after": 20, "limit": 16}])
        self.assertEqual([name for name, _ in self.daemon.calls], ["room.status", "grant.issue"])

    def test_peer_event_refuses_foreign_author_policy_unadmitted_and_duplicate(self):
        self.issue()
        cases = [inbox([message(author=AUTHOR)]),
                 inbox([message() | {"policy": "c" * 64}]),
                 inbox([message(visibility="Incomplete")]),
                 inbox([message(visibility="ContinuityOnly")]),
                 inbox([message(12), message(31)])]
        for page in cases:
            with self.subTest(page=page):
                self.responses = [page]
                with self.assertRaises(ValueError):
                    self.agent.peer_event(PEER, "synthetic")
        self.assertEqual(len(self.launches), len(cases))

    def test_peer_event_refuses_moving_or_malformed_page_and_absent_peer(self):
        self.issue()
        cases = ([inbox([], next_cursor=20), inbox([message()], head=41)],
                 [reply({"room": ROOM, "kind": "public", "head": 40, "records": [message()]})],
                 [inbox([message() | {"cursor": True}])],
                 [inbox([message() | {"trust": "verified by prompt"}])],
                 [inbox([message() | {"event": "not-an-event"}])],
                 [inbox([message()], next_cursor=30)],
                 [inbox([])])
        for pages in cases:
            with self.subTest(pages=pages):
                self.responses = list(pages)
                with self.assertRaises(ValueError):
                    self.agent.peer_event(PEER, "synthetic")

    def test_peer_event_refuses_non_u64_metadata(self):
        self.issue()
        # The daemon's head, cursor and author sequence are unsigned 64-bit values.
        # Python's JSON decoder accepts wider integers; they must not become evidence.
        cases = ([inbox([message()], head=1 << 64)],
                 [inbox([message() | {"sequence": 1 << 64}])])
        for pages in cases:
            with self.subTest(pages=pages):
                self.responses = list(pages)
                with self.assertRaises(ValueError):
                    self.agent.peer_event(PEER, "synthetic")

    def test_peer_event_refuses_invalid_intent_and_bounded_incomplete_scan(self):
        self.issue()
        for peer, text in ((AUTHOR, "synthetic"), ("not-a-peer", "synthetic"),
                           (PEER, ""), (PEER, "a" * 4097)):
            with self.subTest(peer=peer, size=len(text)):
                with self.assertRaisesRegex(ValueError, "invalid pinned peer event intent"):
                    self.agent.peer_event(peer, text)
        self.assertEqual(self.launches, [])
        self.responses = [*(inbox([], next_cursor=after + 1)
                            for after in range(16))]
        with self.assertRaisesRegex(ValueError, "exceeded peer scan bound"):
            self.agent.peer_event(PEER, "synthetic")
        self.assertEqual(len(self.launches), 16)

    def test_exact_local_retry_scans_completed_outbox_without_delivery_claim(self):
        self.issue()
        operation, text = "9" * 32, "private message body"
        sent = {"room": ROOM, "operation": operation, "frame_hash": HASH,
                "state": "Provisional", "exact_retry": False, "delivery": "not asserted"}
        self.responses = [reply(sent), reply({**sent, "exact_retry": True}),
                          outbox([completion("a" * 32, 12)], next_cursor=20),
                          outbox([completion(operation, 31)])]
        summary = self.agent.exact_local_retry(operation, text)
        self.assertEqual(summary, {"frame_hash": HASH, "local_completion_once": True,
                                   "delivery": "not asserted"})
        self.assertNotIn(text, json.dumps(summary))
        self.assertNotIn(TOKEN, json.dumps(summary))
        self.assertEqual(len(self.launches), 4)
        self.assertEqual([json.loads(launch[1].splitlines()[-1])["params"]["name"]
                          for launch in self.launches],
                         ["agent.send", "agent.send", "agent.outbox_status", "agent.outbox_status"])
        self.assertEqual(json.loads(self.launches[-1][1].splitlines()[-1])["params"]["arguments"],
                         {"after": 20, "limit": 16})
        self.assertEqual([name for name, _ in self.daemon.calls], ["room.status", "grant.issue"])

    def test_outbox_refuses_metadata_beyond_daemon_u64_range(self):
        self.issue()
        with self.assertRaisesRegex(ValueError, "invalid bounded outbox page"):
            self.agent.outbox_status(after=1 << 64)
        self.assertEqual(self.launches, [])
        self.responses = [outbox([completion("9" * 32, 31)], head=1 << 64)]
        with self.assertRaisesRegex(ValueError, "local outbox page is incomplete"):
            self.agent.outbox_status()
        self.assertEqual(len(self.launches), 1)

    def test_retry_refuses_bad_intent_before_any_mcp_launch(self):
        self.issue()
        for operation, text in (("0" * 32, "message"), ("9" * 32, "a" * 2049),
                                ("9" * 32, ""), ("not-an-operation", "message")):
            with self.subTest(operation=operation, size=len(text)):
                with self.assertRaisesRegex(ValueError, "bounded retry intent"):
                    self.agent.exact_local_retry(operation, text)
        self.assertEqual(self.launches, [])

    def test_retry_refuses_replayed_first_send_or_changed_signed_frame(self):
        self.issue()
        operation = "9" * 32
        sent = {"room": ROOM, "operation": operation, "frame_hash": HASH,
                "state": "Provisional", "exact_retry": False, "delivery": "not asserted"}
        self.responses = [reply({**sent, "exact_retry": True})]
        with self.assertRaisesRegex(ValueError, "already an exact retry"):
            self.agent.exact_local_retry(operation, "message")
        self.responses = [reply(sent), reply({**sent, "exact_retry": True, "frame_hash": "b" * 64})]
        with self.assertRaisesRegex(ValueError, "changed signed frame"):
            self.agent.exact_local_retry(operation, "message")
        self.assertEqual(len(self.launches), 3)

    def test_retry_refuses_unadmitted_signed_frame_without_overclaiming_completion(self):
        self.issue()
        operation = "9" * 32
        sent = {"room": ROOM, "operation": operation, "frame_hash": HASH,
                "state": "Provisional", "exact_retry": False, "delivery": "not asserted"}
        self.responses = [reply({**sent, "state": "PendingHistory"})]
        with self.assertRaisesRegex(ValueError, "first send is not locally admitted"):
            self.agent.exact_local_retry(operation, "message")
        self.assertEqual(len(self.launches), 1)  # Never retry after an unadmitted result.
        self.responses = [reply(sent), reply({**sent, "state": "NeedsRepost",
                                               "exact_retry": True})]
        with self.assertRaisesRegex(ValueError, "exact retry is not locally admitted"):
            self.agent.exact_local_retry(operation, "message")
        self.assertEqual(len(self.launches), 3)

    def test_retry_refuses_duplicate_completion_and_moving_outbox(self):
        self.issue()
        operation = "9" * 32
        sent = {"room": ROOM, "operation": operation, "frame_hash": HASH,
                "state": "Provisional", "exact_retry": False, "delivery": "not asserted"}
        self.responses = [reply(sent), reply({**sent, "exact_retry": True}),
                          outbox([completion(operation, 12)], next_cursor=20),
                          outbox([completion(operation, 31)])]
        with self.assertRaisesRegex(ValueError, "no unique local signed completion"):
            self.agent.exact_local_retry(operation, "message")
        self.responses = [reply(sent), reply({**sent, "exact_retry": True}),
                          outbox([], next_cursor=20), outbox([completion(operation, 31)], head=41)]
        with self.assertRaisesRegex(ValueError, "changed during retry check"):
            self.agent.exact_local_retry(operation, "message")

    def test_retry_refuses_incomplete_or_forged_outbox(self):
        self.issue()
        operation = "9" * 32
        sent = {"room": ROOM, "operation": operation, "frame_hash": HASH,
                "state": "Provisional", "exact_retry": False, "delivery": "not asserted"}
        cases = [outbox([completion(operation, 31, "b" * 64)]),
                 outbox([completion(operation, 31)], next_cursor=0),
                 outbox([completion(operation, 31)], next_cursor=30),
                 outbox([completion(operation, 31, HASH) | {"kind": "Policy"}]),
                 reply({"room": ROOM, "kind": "public", "head": 40,
                        "operations": [completion(operation, 31)], "delivery": "not asserted"})]
        for page in cases:
            with self.subTest(page=page):
                self.responses = [reply(sent), reply({**sent, "exact_retry": True}), page]
                with self.assertRaises(ValueError):
                    self.agent.exact_local_retry(operation, "message")

    def test_retry_refuses_scan_beyond_finite_page_budget(self):
        self.issue()
        operation = "9" * 32
        sent = {"room": ROOM, "operation": operation, "frame_hash": HASH,
                "state": "Provisional", "exact_retry": False, "delivery": "not asserted"}
        self.responses = [reply(sent), reply({**sent, "exact_retry": True}),
                          *(outbox([], head=40, next_cursor=after + 1) for after in range(16))]
        with self.assertRaisesRegex(ValueError, "exceeded retry scan bound"):
            self.agent.exact_local_retry(operation, "message")
        self.assertEqual(len(self.launches), 18)

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
        with self.assertRaisesRegex(ValueError, "do not retry"):
            self.agent.close()
        self.assertEqual([name for name, _ in self.daemon.calls].count("grant.revoke"), 1)

    def test_lost_revoke_reply_does_not_trigger_a_second_write(self):
        self.issue()
        def lost(op, **fields):
            if op == "grant.revoke":
                self.daemon.calls.append((op, fields))
                raise TimeoutError("revoke reply lost")
            return FakeDaemon.call(self.daemon, op, **fields)
        self.daemon.call = lost
        with self.assertRaises(TimeoutError):
            self.agent.close()
        with self.assertRaisesRegex(ValueError, "do not retry"):
            self.agent.close()
        self.assertEqual([name for name, _ in self.daemon.calls],
                         ["room.status", "grant.issue", "grant.revoke"])
        self.assertFalse(self.agent.grant_path.exists())
        self.assertIsNotNone(self.agent.grant)


class PairedAgentTests(unittest.TestCase):
    """Two fake local issuers; never evidence of separate physical machines."""

    def setUp(self):
        ScopedAgentTests.setUp(self)
        other = self.work.parent / "peer-role"
        other.mkdir(mode=0o700)
        self.second_daemon = FakeDaemon(other, room="a" * 32, author=PEER,
                                        generation="c" * 64, token="d" * 64)
        self.second = ScopedAgent(self.second_daemon, "a" * 32, PIN,
                                  other / "grant.json", clock=lambda: 2_000_000_000)
        self.machines = ("e" * 64, "f" * 64)
        self.operations = ("8" * 32, "9" * 32)

    def transport(self, argv, payload, env, timeout):
        return ScopedAgentTests.transport(self, argv, payload, env, timeout)

    def paired_issue(self):
        return issue_agent_pair(self.agent, self.second, self.operations, self.machines)

    def test_two_scopes_grants_and_summary_remain_separate_and_body_free(self):
        result = self.paired_issue()
        self.assertEqual([entry["scope"]["author"] for entry in result["agents"]],
                         [AUTHOR, PEER])
        self.assertEqual([entry["declared_machine_id"] for entry in result["agents"]],
                         list(self.machines))
        self.assertEqual([entry["budget"] for entry in result["agents"]], [BUDGET, BUDGET])
        self.assertEqual(result["delivery"], "not asserted")
        self.assertIn("unverified", result["machine_identity"])
        self.assertNotIn(TOKEN, json.dumps(result))
        self.assertNotIn(self.second_daemon.token, json.dumps(result))
        self.assertNotIn("grant.json", json.dumps(result))
        self.assertEqual([name for name, _ in self.daemon.calls],
                         ["room.status", "room.status", "grant.issue"])
        self.assertEqual([name for name, _ in self.second_daemon.calls],
                         ["room.status", "room.status", "grant.issue"])
        self.assertEqual(json.loads(self.agent.grant_path.read_text()),
                         {"generation": GENERATION, "token": TOKEN})
        self.assertEqual(json.loads(self.second.grant_path.read_text()),
                         {"generation": "c" * 64, "token": "d" * 64})
        self.assertEqual(self.launches, [])
        self.second.close()
        self.agent.close()
        self.assertFalse(self.agent.grant_path.exists())
        self.assertFalse(self.second.grant_path.exists())
        with self.assertRaisesRegex(ValueError, "separate homes and private work"):
            self.paired_issue()
        self.assertEqual(len(self.daemon.calls), 4)
        self.assertEqual(len(self.second_daemon.calls), 4)

    def test_separate_objects_with_shared_home_or_work_refuse_before_any_mint(self):
        # Distinct daemon wrappers and declared machine IDs do not isolate custody.
        original_home = self.second_daemon.home
        self.second_daemon.home = self.daemon.home
        with self.assertRaisesRegex(ValueError, "separate homes and private work"):
            self.paired_issue()
        self.second_daemon.home = original_home
        shared = FakeDaemon(self.work, room=self.second.room, author=PEER,
                            generation="c" * 64, token="d" * 64)
        shared.home = original_home
        collocated = ScopedAgent(shared, self.second.room, PIN,
                                 self.work / "other-grant.json", clock=lambda: 2_000_000_000)
        with self.assertRaisesRegex(ValueError, "separate homes and private work"):
            issue_agent_pair(self.agent, collocated, self.operations, self.machines)
        self.assertEqual(self.daemon.calls, [])
        self.assertEqual(self.second_daemon.calls, [])
        self.assertEqual(shared.calls, [])
        self.assertFalse(self.agent.grant_path.exists())
        self.assertFalse(collocated.grant_path.exists())

    def test_duplicate_machine_role_and_operation_refuse_before_any_mint(self):
        with self.assertRaisesRegex(ValueError, "machine identifiers"):
            issue_agent_pair(self.agent, self.second, self.operations,
                             (self.machines[0], self.machines[0]))
        with self.assertRaisesRegex(ValueError, "grant operations"):
            issue_agent_pair(self.agent, self.second, (self.operations[0],) * 2, self.machines)
        with self.assertRaisesRegex(ValueError, "separate homes and private work"):
            issue_agent_pair(self.agent, self.agent, self.operations, self.machines)
        self.assertEqual(self.daemon.calls, [])
        self.assertEqual(self.second_daemon.calls, [])

    def test_wrong_pin_policy_or_same_author_refuses_without_mint(self):
        for changed, value in (("pin", "b" * 64),
                               ("policy", {"id": "b" * 64, "revision": 1}),
                               ("author", AUTHOR)):
            with self.subTest(changed=changed):
                old = self.second_daemon.status[changed]
                self.second_daemon.status[changed] = value
                with self.assertRaises(ValueError):
                    self.paired_issue()
                self.second_daemon.status[changed] = old
        self.assertFalse(self.agent.grant_path.exists())
        self.assertFalse(self.second.grant_path.exists())
        self.assertNotIn("grant.issue", [name for name, _ in self.daemon.calls])
        self.assertNotIn("grant.issue", [name for name, _ in self.second_daemon.calls])

    def test_second_issuance_mismatch_rolls_back_first_and_never_launches(self):
        self.second_daemon.issued_override = {"generation": "c" * 64, "token": "d" * 64,
            "room": self.second.room, "scope": {"kind": "private"},
            "permissions": PERMISSIONS, "expires_at": 2_000_000_600}
        with self.assertRaisesRegex(ValueError, "differs from selected scope"):
            self.paired_issue()
        self.assertEqual([name for name, _ in self.daemon.calls][-2:],
                         ["grant.issue", "grant.revoke"])
        self.assertEqual([name for name, _ in self.second_daemon.calls][-2:],
                         ["grant.issue", "grant.revoke"])
        self.assertFalse(self.agent.grant_path.exists())
        self.assertFalse(self.second.grant_path.exists())
        self.assertIsNone(self.agent.grant)
        self.assertIsNone(self.second.grant)
        self.assertEqual(self.launches, [])

    def test_credential_reuse_refuses_and_revokes_both(self):
        self.second_daemon.generation, self.second_daemon.token = GENERATION, TOKEN
        with self.assertRaisesRegex(ValueError, "reused credentials"):
            self.paired_issue()
        self.assertFalse(self.agent.grant_path.exists())
        self.assertFalse(self.second.grant_path.exists())
        self.assertEqual([name for name, _ in self.daemon.calls].count("grant.revoke"), 1)
        self.assertEqual([name for name, _ in self.second_daemon.calls].count("grant.revoke"), 1)

    def test_second_issuance_cleanup_uncertainty_is_explicit(self):
        self.second_daemon.issued_override = {"generation": "c" * 64, "token": "d" * 64,
            "room": self.second.room, "scope": {"kind": "private"},
            "permissions": PERMISSIONS, "expires_at": 2_000_000_600}
        self.daemon.revoke = False
        with self.assertRaisesRegex(ValueError, "cleanup unconfirmed"):
            self.paired_issue()
        self.assertFalse(self.agent.grant_path.exists())
        self.assertFalse(self.second.grant_path.exists())
        self.assertIsNotNone(self.agent.grant)
        self.assertEqual(self.launches, [])
        with self.assertRaisesRegex(ValueError, "do not retry"):
            self.agent.close()
        self.assertEqual([name for name, _ in self.daemon.calls].count("grant.revoke"), 1)


class RealProcessGrantTests(unittest.TestCase):
    """Opt-in single-machine daemon/MCP regression, never two-agent evidence."""

    @unittest.skipUnless(os.environ.get("HEADLESS_AGENT_TEST_BINARY"),
                         "set HEADLESS_AGENT_TEST_BINARY to an owned built vhalla CLI")
    def test_fresh_mcp_launches_share_one_finite_grant_and_paginated_outbox(self):
        source = Path(os.environ["HEADLESS_AGENT_TEST_BINARY"])
        self.assertTrue(source.is_absolute() and source.is_file() and not source.is_symlink())
        # Use a short, owned private directory for macOS's Unix socket bound.
        # The dummy SHA is never emitted as a receipt or interpreted as a source attestation.
        scratch = Path(os.environ.get("HEADLESS_AGENT_TEST_WORKDIR", ".")).absolute()
        self.assertTrue(scratch.is_dir() and scratch.resolve() == scratch
                        and scratch.stat().st_uid == os.geteuid(),
                        "choose an owned HEADLESS_AGENT_TEST_WORKDIR inside the workspace")
        self.assertLess(len(os.fsencode(scratch / "aq-XXXXXXXX" / "r" / "home"
                                      / "control" / "admin.sock")), 104,
                        "choose a shorter HEADLESS_AGENT_TEST_WORKDIR inside the workspace")
        with tempfile.TemporaryDirectory(prefix="aq-", dir=scratch) as temp:
            root = Path(temp).resolve()
            candidate = root / "candidate"
            shutil.copyfile(source, candidate)
            candidate.chmod(0o500)
            process = McpRun(candidate, digest(candidate), root / "r", "0" * 40)
            admin_calls = []
            launches = []

            def admin_call(op, **fields):
                admin_calls.append(op)
                return process.call(op, **fields)

            def scoped_launch(argv, payload, env, timeout):
                launches.append(argv[-4])  # action only; never record the private payload/grant
                return public.exchange(argv, payload, env, timeout)

            daemon = SimpleNamespace(config={"work": str(process.work)}, home=process.home,
                                     argv=[str(candidate), "--no-update", "daemon"],
                                     env=process.env, call=admin_call)
            agent = None
            try:
                process.start()
                created = process.call("room.create", operation=f"{1:032x}", kind="public",
                                       limits={"max_records": 128, "max_record_bytes": 1048576})
                agent = ScopedAgent(daemon, created["room"], created["pin"],
                                    process.work / "agent-grant.json", transport=scoped_launch)
                agent.issue(f"{2:032x}")
                before = agent.status()
                self.assertEqual(before["remaining"]["send_attempts"], BUDGET["send_attempts"])
                operation, text = f"{100:032x}", "synthetic finite-grant retry"
                first = agent.send(operation, text)
                self.assertFalse(first["exact_retry"])
                retried = agent.send(operation, text)
                self.assertTrue(retried["exact_retry"])
                self.assertEqual(retried["frame_hash"], first["frame_hash"])
                for number in range(1, BUDGET["send_attempts"] - 1):
                    sent = agent.send(f"{100 + number:032x}", f"synthetic finite-grant {number}")
                    self.assertFalse(sent["exact_retry"])
                after = agent.status()
                self.assertEqual(after["remaining"]["send_attempts"], 0)
                self.assertLess(after["remaining"]["calls"], before["remaining"]["calls"])

                cursor, head, rows = 0, None, []
                for _ in range(MAX_OUTBOX_PAGES):
                    page = agent.outbox_status(after=cursor, limit=1)
                    self.assertEqual(page["head"], head if head is not None else page["head"])
                    head = page["head"]
                    rows.extend(page["operations"])
                    if page["next"] is None:
                        break
                    cursor = page["next"]
                else:
                    self.fail("local outbox exceeded finite page bound")
                self.assertGreater(len(rows), 1)  # Actual pagination, not a single-page stub.
                matched = [row for row in rows if row["operation"] == operation]
                self.assertEqual(len(matched), 1)
                self.assertEqual(matched[0]["kind"], "Event")
                self.assertEqual(matched[0]["frame_hash"], first["frame_hash"])
                messages = agent.messages(after=0, limit=16)
                self.assertEqual(sum(row["text"] == text for row in messages), 1)
                with self.assertRaises(AgentRefusal) as refused:
                    agent.send(f"{999:032x}", "synthetic exhausted-grant refusal")
                self.assertEqual(refused.exception.code, "permission-denied")
                self.assertEqual(agent.status()["remaining"]["send_attempts"], 0)
                self.assertEqual(admin_calls, ["room.status", "grant.issue"])
                self.assertGreaterEqual(len(launches), BUDGET["send_attempts"] + 5)
            finally:
                try:
                    if agent is not None:
                        agent.close()
                finally:
                    self.assertTrue(process.cleanup())
                    self.assertFalse(process.result["cleanup_fallback_used"])
            self.assertFalse(agent.grant_path.exists())
            self.assertEqual(admin_calls, ["room.status", "grant.issue", "grant.revoke"])


if __name__ == "__main__":
    unittest.main()
