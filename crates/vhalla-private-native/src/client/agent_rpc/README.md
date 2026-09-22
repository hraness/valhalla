# Fixed-room cooperating-host MCP

This production adapter connects existing CLI agent hosts to an already-created
private room. It exposes `private_status`, `private_inbox`, `private_prepare`,
`private_queue`, and `private_outbox_status`. The native custodian retains keys,
the account lock, ratchets, and store ownership. Tools cannot select another
room, path, grant, provider, relay, signing operation, or membership operation.

This is an API authority boundary. A Codex/Devin process with its own filesystem,
network, tools, memory, or inference service remains privileged outside it.
Provider/model/processing-policy fields are explicit declarations by the trusted
operator; neither MCP client metadata nor the `session` argument authenticates or
constrains that remote provider. A host that cannot be trusted with the selected
plaintext must not receive an inbox grant. The separate sandbox prototype is
not this adapter's containment backend.

## Trusted launch

Use the trusted CLI `private agent-grant` command to prepare a version 1 private
JSON file from authenticated room status, with explicit host/provider disclosure,
mode, lifetime, selected inbox range, quotas and a fresh receipt path. That
command is not an MCP tool. `private agent-serve ID STORE --grant FILE` reads this
bounded 0600 file from a 0700 directory before serving MCP over pipes.

The grant pins the full room, anchor, account, device, epoch and roster. Inbox
selection is an exclusive `after` and inclusive `through` sequence range.
`follow:false` grants only already-retained records. Explicit `follow:true` may
include future records up to a fixed ceiling at most 4096 above the startup
head; the same finite read budget and roster still apply. It does not renew or
follow membership changes. Request cursors outside the selected range refuse.

Startup creates the selected claim with `create_new`, writes its grant digest
and context, and syncs both the file and its directory **before** narrowing the
room and releasing any RPC data. The entire allowance is consumed once. An
existing, partial, or uncertain receipt refuses, including after a clean exit
that used no budget. Preserve receipts: changing/deleting one to make automatic
restart work is not recovery. A trusted operator must reconcile retained local
operations and explicitly authorize a fresh grant, with a new identifier and
receipt. This relies on the existing cooperating-owner filesystem boundary;
it does not detect an owner rolling back all grant files.

## Wire and lifecycle

The adapter implements primary MCP specifications:

- [2026-07-28 base protocol](https://modelcontextprotocol.io/specification/2026-07-28/basic):
  every modern request carries `protocolVersion` and `clientCapabilities` in the
  reserved `_meta` keys. Replies include `resultType`. `server/discover` is
  supported, and unknown revisions receive `UnsupportedProtocolVersion`.
- [Versioning and compatibility](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning)
  and [2025-11-25 lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle):
  established CLI hosts may use `initialize` / `notifications/initialized`.
- [stdio transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio):
  one JSON-RPC message per UTF-8 line; stdout contains protocol messages only.
  No logging, identity, message body, password, or provider credential is printed
  outside the explicitly authorized tool result.

Generated tool schemas include the exact application `session` identifier on
every call; it references the launch grant, not a conversation inferred from a
connection. The integer `limit` is 1..16. Cursors, retained draft identifiers,
epoch and sequence outputs use canonical decimal strings to preserve all u64
values across JavaScript hosts. Queue requires a full nonzero 16-byte operation
ID encoded as 32 lowercase hex digits. Prepared bodies are exact bounded UTF-8;
inbox records contain exact `body_hex`, optional UTF-8 `text`, and an explicit
inert-content marker. Tool errors contain stable codes without raw input/paths.

Each request is at most 64 KiB, each encoded result at most 1 MiB, and a launch
accepts at most 4096 protocol messages. Nonblocking pipes bound partial frames,
reply backpressure and cancellation scans. A partial frame and each operation /
reply have a 30-second bound; idle waiting also stops at the grant deadline.
Native filesystem barriers may finish within a synchronous Rust poll, so a
deadline/cancellation can withhold their result after the effect committed.
The native host must still be able to terminate a stuck process. No automatic
retry is authorized. A partial reply may already have disclosed a prefix;
expiry or cancellation cannot retract it.

EOF, cancellation, transport failure and expired authority close custody. A
single cancellation conservatively ends the whole launch. Failed/canceled
native data operations remain latched. Room content never becomes a grant or
control instruction. The host must check `RpcSession::check_release` immediately
before emitting output and revoke on transport uncertainty.

## Trusted delivery facet

`RoomSession::into_agent_host` constructs `AgentHostSession` before narrowing.
Its `agent()` borrow exposes the same five operations. Separate typed `outbox`,
`receive`, `apply_control` and `issue_acceptance` methods allow the trusted controller to deliver
ciphertext while retaining the single account/room custody owner. They are not
registered tools and grant no network destination. Relay eligibility and a
durable delivery policy belong to the trusted controller.

`issue_acceptance` signs only a claim for ciphertext already durable in the
receiver's inbox. It refuses acknowledgments of acknowledgments and retains
the exact signed/encrypted output for retries. The receipt signature binds the
room, anchor, original sender, recipient device, ciphertext commitment and
recipient-local inbox sequence. It authenticates a device's claim; it does not
prove honest physical storage, human reading or continued membership.

The host-only `update_delivery(namespace, status)` reloads the original local
artifact and checks its canonical relay digest, operation and namespace before
adding metadata. `record_member_acceptance(sequence, proof)` accepts only the
typed result of signature verification and rechecks its original/context.
The view holds at most 4096 jobs and at most 16 distinct recipient claims per
job, refuses contradictory/regressing updates, and retains no ciphertext.
`private_outbox_status` includes optional `relay` and `member_acceptances` fields
for those checked records. Relay retention and member claims remain distinct;
the client never converts either into human-read or current-member assertions.
These updates are not RPC methods and do not broaden the agent's grant.

Same-roster application delivery can populate an explicitly followed inbox.
An authenticated control changing epoch, roster or lifecycle revokes the grant
and discards its draft before further agent output. The host may reconcile
already-retained delivery first, then end the session and obtain a new explicit
grant. Native refusals remain conservative: kernel checks after `begin_live`
can require reopen even when a peer packet is malformed. An enum error is not
proof that continuing the cached kernel is safe. Exact own-sender relay echoes
and structurally ineligible envelopes should be filtered before kernel input.

Queue results assert durable local outbox state only. Relay retention is not
recipient acceptance. This adapter itself performs no external inference or
arbitrary external action; such effects still require independently bound
selected-content/destination authorization and durable reconciliation.

## Focused evidence

The native `client::agent_rpc::tests` suite uses real MLS/account/SQLite custody
for grant binding, one-use restart refusal, current/legacy protocol handling,
exact inert inbox selection, queue metadata, host delivery and membership-change
revocation. CLI `private_agent` integration tests generate grants with the real
command, exchange bounded messages with a real stdio subprocess, verify queued
state after reopen, and cover restart refusal, read-only permissions,
cancellation and oversized frames. No external provider call is needed.

```sh
cargo test --locked -p vhalla-private-native --features agent-rpc client::agent_rpc::tests
cargo test --locked -p vhalla-cli --features experimental-private --test private_agent
```

Use the repository's host scheduler for builds and the selected exact Rust
toolchain. Root integration owns combined delivery/release qualification.
