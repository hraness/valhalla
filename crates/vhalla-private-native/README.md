# Native private-room storage

This workspace crate provides native persistence, a fixed-room agent interface,
an opaque relay-item protocol, and an optional trusted private-room session. It
does not install a network transport or a CLI. See [release boundaries](../../docs/private-rooms.md).
The `private_rooms` backend accepts only opaque stored images and records, with
no key or plaintext API. An opaque byte constructor is not proof of encryption.
The kernel supplies MLS and authenticated encryption. The separate optional
`client` interface may return private metadata, plaintext inbox and retained
artifacts to trusted local code; it must not be exposed wholesale as agent tools.

The API is `NativePrivateStore::{create_new,open,load,read,publish}` with a full 128-byte `Context` (room, signed anchor, account, device), immutable `Limits`, and closed `RecordKey::{Outbox,Inbox,Operation,Received,Control}`. Images are at most 4 MiB +40 bytes; immutable records at most266,280 bytes, at most3 per transaction. The kernel adapter supplies canonical key fields, maps the four failure classes, and authenticates reloaded state/records before releasing anything.

A single SQLite database contains one encrypted current image and an immutable primary-key-indexed records table. This makes indexed absence a database result; no separate missing record file is mistaken for an unused operation ID. The adapter has no delete/update-record/reset/import API and no lifetime in-memory map. `expected=None` requires the exact empty state and no record rows. Existing FORMAT plus a missing, partial or incompatible database is an error, never permission to create a replacement.

A fresh private0700 directory has a lifetime0600 custody lock. The selected existing parent is resolved once (including macOS /var aliases), while the final store leaf and database retain no-follow checks. SQLite opens the exact0600 regular/nlink1 database with NOFOLLOW, no URI/CREATE on reopen, no shared cache/extensions, bounded SQL/blob/page/cache resources, defensive configuration and untrusted-schema checks. A checksummed immutable full-context/limits FORMAT must match before SQLite can recover. Creation publishes FORMAT last, only after the initialized schema/database is durable; interrupted initialization stays preserved and refuses reopen rather than silently restarting. Exact schema, application_id and user_version are checked. Reads use bounded indexed queries, not full integrity/history scans.

Publication runs an immediate transaction, compares the exact current image, preflights every offered record collision and budget, inserts new immutable ciphertext rows and changes the image together. It uses DELETE journals with synchronous=EXTRA, fullfsync and explicit post-COMMIT file/directory sync, then exact bounded readback before success. Every offered already-published key is a conflict, even when its bytes match. Kernel operation retries read the retained result and never republish a record with a new state image. A conflict or capacity refusal is reported only after successful rollback with no mutations. Any uncertain transaction/commit/sync/readback poisons the handle. Explicit open performs SQLite recovery and resyncs before returning; load/read never repair and refuse poisoned handles.

SQLite documents that [EXTRA adds rollback-journal directory durability](https://www.sqlite.org/pragma.html#pragma_synchronous) and [fullfsync selects the stronger macOS sync](https://www.sqlite.org/pragma.html#pragma_fullfsync). Its [atomic commit/recovery contract](https://www.sqlite.org/atomiccommit.html) replaces a new custom intent and growing index implementation. The dependency is pinned rusqlite0.40.2 with bundled SQLite3.53.2 and limits features, default features disabled; the promoted dependency graph passed scoped and complete-workspace security auditing, with retained findings described below.

Limits: checksums and kernel AEAD do not detect a coherent rollback or valid malicious SQL edits that delete a whole indexed row, nor a cloned live custody key or storage that falsely reports durability. The local OS owner/cooperating-writer boundary applies. There is no O(history) integrity scan on every open/read; physical corruption is rejected by SQLite page checks and exact stored bindings when accessed. The kernel still owns authorization, cryptographic authentication, replay rules and current owner/clock checks. This native module is not a browser IndexedDB qualification.

Qualification covers exact CAS/immutable collisions, bounds/capacity, separate
contexts, custody/mode/symlink/schema/corruption refusal, injected pre/post-COMMIT
failures and five real SIGKILL boundaries with forced page spills. SIGKILL is not
proof of disk power-loss durability or every VFS failure. Tests create fresh
synthetic stores and never reset existing histories. Full dependency auditing
retains the inactive `cfg(hax)` RUSTSEC-2026-0173 maintenance warning; no advisory
is suppressed. Enabling that configuration requires renewed review.

## Kernel bridge

`bridge::KernelStore::{create_new,open}` accepts the kernel's typed full context and implements its encrypted `Store` contract. The backend stays independent of MLS; the bridge maps exactly room, anchor, account, device, all five index variants and the four persistence failure classes. Compile-time equality keeps both atomic-record ceilings aligned. `Control(n)` uses tag5 plus the nonzero big-endian u64. The group kernel emits these immutable records for membership changes. Its versioned group image does not automatically migrate the earlier two-device image; the older qualification receipts remain historical evidence.

The trait methods complete one bounded synchronous native operation in one poll and do not spawn work or invoke callbacks. Run them on an appropriate native worker; they may block on SQLite and filesystem sync and are not a browser/UI event-loop adapter. Explicit physical reopen is separate from read-only load/read. The kernel owns the wrapping key and re-authenticates exact published state and records before exposing prepared MLS output or admitted plaintext.

`tests/journey.rs` uses real owner/account signatures, OS-generated MLS device keys, explicit signed invitations and actual native stores. The journeys cover bidirectional messages and removal; exact retained ciphertext after reopen; no returned plaintext/ciphertext after uncertain publication; cancellation after actual SQL commit; stale logical writers under one physical custody lock; and capacity/scope refusal. Fault wrappers are test-only and run actual SQLite publication before injecting an uncertain or canceled completion. The production bridge is not cloneable. Synthetic account/wrapping keys are never written in plaintext; encrypted device state is deliberately persisted.

These are private native API journeys, not a CLI, transport or activation. The
optional trusted session below adds account custody and access to retained
artifacts. Histories have explicit caps; no quota failure grants permission to
reset a device. The browser adapter and every changed integration require their
own qualification.

## Opaque relay items

The `relay` module is the transport boundary for private delivery. A caller
selects a fresh nonzero `RelayNamespace` out of band, converts an ordinary
`CommittedOutbox` artifact with `RelayItem::from_artifact`, and gives the item to
an adapter implementing its own HTTP, QUIC or file transport. `RelayItem::encode`
and `decode` provide a bounded canonical wire format; the digest binds the
namespace, sender sequence, operation, artifact kind and exact ciphertext.

`relay::Store` is a small in-process reference implementation for tests and local
development. One mailbox serves every sender in its namespace: it assigns each
retained item an increasing mailbox `position`, so pages, cursors and fetches
order by that position while `RelayItem::sequence` stays committed sender-local
metadata. It enforces item and byte quotas, rejects cross-namespace writes and
conflicting operation reuse, refuses confidential offer metadata,
and makes exact retries idempotent. Its `RelayReceipt` means only that this
relay kept
the opaque bytes. It is never a member acknowledgment, a delivery guarantee or
an authorization decision. The receiving session still passes only the item
payload to `RoomSession::receive`, which performs normal MLS scope, membership,
replay and durable-inbox checks. No relay API receives room IDs, anchors,
accounts, device keys, plaintext or secret offers.

`relay::FileStore` is the same mailbox bound to a durable 0700 directory. It
keeps one SQLite database in rollback-journal mode behind a lifetime exclusive
lock, re-verifies every retained item and quota on open, syncs each accepted
mutation before issuing a receipt, and never prunes or rewrites retained items.
A directory is created once with an immutable namespace and quota; reopening
requires the same namespace and fails while another handle holds the lock. It is
still a local mailbox, not a delivery service: scheduling, authentication and
recipient acceptance belong to a real adapter.

## Optional trusted native session

Enable `client` to use `client::{RoomCreation, RoomSession}`. The feature is off
by default and enables `vhalla-identity/private-storage`. It retains the existing
account's exclusive custodian and derives an opaque storage key through the
kernel's fixed HKDF-SHA256 contract. No seed getter, generic signer, storage-key
getter, kernel getter or clone is exposed. The feature does not add networking.

For a new owner, call `RoomCreation::owner(identity, validity)`. For a genuinely
fresh member, use `RoomCreation::member` with the independently selected full
scope, signed anchor and owner enrollment. Inspect and retain `context()` before
consuming `commit(path, limits)`; keep anchor and enrollment metadata private.
Creation uses a never-existing destination and commits a fresh device before
returning a session. It is not account-key restoration of an old device.

If creation fails, is interrupted or reports uncertainty, preserve its exact path
and context. `RoomSession::open(identity, path, context)` recovers only an existing
store and authenticates its retained image. A wrong account is rejected before
the backend is opened. A missing image or incomplete namespace remains an error;
there is no fallback initialization, reset or implicit migration. The underlying
native calls finish synchronously within one poll, so async cancellation cannot
interrupt one in-progress native call; process death and uncertain I/O still need
explicit recovery. Run this work away from a UI event loop.

A `RoomSession` owns the kernel before the account in drop order. `lock()` or drop
destroys room key/state/store custody and then releases account custody. A live
kernel cannot survive an account-only lock through this API. An outstanding
borrowed operation must be dropped before lock; callers must also clear their own
previously returned plaintext and draft buffers. Reopening the same account path
or store while that session owns it refuses. This currently serializes sessions
using one native identity directory; do not copy credentials to bypass that lock.

`membership()` reauthenticates the locally retained anchor, owner/local
enrollments and complete roster for recipient display. The view includes private
full account/device keys and validity periods; it is not global freshness or
permission to send after removal/quarantine. `prepare_message` binds exact
content to the full context, epoch and roster. `send` rechecks those values before
committing. Renewal or membership change needs new explicit consent. Local
publication and a returned artifact are not remote receipt or member acceptance.

The session exposes bounded inbox/outbox, key-package preparation, explicit
invite/join, targeted removal, encrypted control acceptance/catch-up and same-device
owner renewal. Renewal signs only the typed replacement through its retained
account custodian. Retain its exact operation ID and validity for retry. System
wall time is checked internally; there is no peer-supplied clock or automatic
renewal. `succeed` composes the same account custodian into an account-signed
succession grant: it hands owner authority to an already-enrolled same-account
device through one predecessor-signed control, demotes the predecessor to
ordinary membership, and retains the grant as bounded evidence. The predecessor
must be live to commit the handoff; safe live-custody transfer remains
unimplemented.

Trusted host code can consume a live `RoomSession` with `into_agent(LocalGrant)`
when it intentionally delegates the same fixed room. Conversion refuses locked,
uncertain or mismatched custody and moves the kernel into an
`client::agent::OwnedAgentRoomSession` whose field order releases room state before
the account lock. The adapter exposes only the five methods listed below and has
no conversion back, signer, key, store, ciphertext or relay API. `lock()` drops
both custodians; it does not retract plaintext already returned to the host.

Existing-member catch-up uses `encrypted_controls` and `apply_control` with exact
retained predecessor-epoch envelopes. Legacy manual KeyPackage and invitation
outbox artifacts contain private bootstrap metadata and require an
independently confidential transfer channel. Generic outbox output must not be
sent to public discovery/activity or assumed safe for an untrusted relay.

Derivation can reopen complete existing encrypted state after the same account
is unlocked. Password re-encryption does not change that key; account-key rotation
does. A restored account alone cannot recover missing ratchets, histories or
membership, prevent coherent rollback, or authorize two live copies. Existing
stores encrypted under explicit keys are not automatically converted.

`tests/client.rs` contains actual account/SQLite/MLS cases for joint lock/drop,
exact reopen and ciphertext retry, complete membership inspection, stale consent
after renewal/removal, wrong-account rejection and absent-image preservation.
`tests/derived_custody.rs` checks account-derived custody against a reopened real
SQLite store. These cases passed in the custody/control checkpoint. Each later protocol
candidate still needs its current integration gate; source presence alone is not
a passing result.

## Trusted confidential invitation flow

`RoomSession::create_contact_offer` returns the committed secret file through an
explicit confidential-export type. `RoomCreation::from_contact` verifies it using
the independently selected owner account and actual unlocked recipient account,
then prepares a fresh device. Inspect and retain its exact context before commit.
`contact_request`, `accept_contact` and `join_contact` wrap the complete encrypted
exchange with the session's trusted clock and joint account/kernel custody.
They open no network connection and provide no agent invitation capability.

Ordinary outbox pages contain `OutboxEntry`; callers must explicitly select an
ordinary artifact through `artifact()`. Secret issuance returns metadata only.
The agent's `QueuedStatus::artifact_bytes` is `None` for that metadata and `Some`
for ordinary artifacts. It never returns secret offers or ciphertext. Exact
offer recovery is available only through the trusted session's issuance retry.

The native contact integration test covers full-file owner/recipient pinning,
real SQLite create/reopen/join, encrypted message exchange, redacted paging,
exact admission retry and refusal to reactivate consumed authority. Together
with the kernel/backend/agent suites, 87 tests and compile-fail examples passed
for this candidate. Browser/runtime and final aggregate checks remain separate.

## Fixed-room agent session

`agent::AgentRoomSession` owns one kernel and one host-created `LocalGrant`. The host exposes only `status`, `inbox`, `prepare`, `queue`, and `outbox_status` as agent tools. The trusted constructor binds the full room/anchor/account/device, exact epoch and roster, explicit permissions and finite process budgets. The host keeps the sole `RevocationHandle`: dropping or revoking it blocks further output. A monotonic deadline of at most one day is checked before and after storage calls; kernel validity checks separately use trusted system wall time. There is no agent-supplied clock, grant renewal, room selection, membership change or kernel accessor.

One `MessageDraft` is retained at a time; a new successful preparation invalidates the previous opaque reference. The same standing grant can authorize repeated explicit messages without repeated prompts, within its limits. A changed roster requires separate trusted authorization and a fresh agent context. Draft preparations, message/body totals and requested bounded read pages consume finite allowances. Charges and an unusable-session latch precede the first await. Cancellation, failed storage, or authority loss during the operation never refunds allowance or returns plaintext, ciphertext or confirmation. Trusted recovery can reopen the exact store and retain the original ciphertext; that does not grant the old agent permission to export it.

Queue results and outbox pages contain metadata only, with no ciphertext or delivery claim. Inbox bodies are already committed authenticated content, but are still untrusted text. The interface never interprets instructions, loads paths, reads environment values, invokes tools, signs arbitrary data or sends network requests. This is a cooperating-host API boundary, not an operating-system sandbox or universal secret detector. Exposing inbox contents to a remote inference provider is itself an egress decision. An agent with independent host access can bypass this surface; restarting or constructing another grant can reset process quotas, so these are not durable account-wide limits.


## Earlier renewal qualification

The earlier owner-renewal source, before the state-v3 confidential controls and
optional trusted session, passed 21 native backend/agent tests plus six actual
MLS/SQLite journeys and strict all-target lint. The added journey recovers owner
renewal after a real commit with uncertain completion, cancels member acceptance
after commit, reopens exact retained state, rejects old roster consent and
exchanges current-epoch traffic. Workspace CI requalifies the promoted source;
prior source-specific receipts remain historical evidence.


## Account-owned read-only archives

The optional `client` feature exposes `archive::ArchiveExporter`, `ArchiveInput`,
`ArchiveReceiver` and `ArchiveSession`. Each owns account custody together with its
opaque kernel operation; lock/drop releases the archive before the account. Source
prefix authentication precedes destination creation, and final-seal authentication
precedes opening an existing archive. No wrapper returns a live kernel or storage
key. Native open retains SQLite recovery/sync effects; archive reads do not publish.

The [native CLI archive runbook](../vhalla-cli/README.md#native-private-archives-experimental-private)
covers bounded encrypted files and exact interrupted-import resume. Archives are
read-only historical recovery, with secret offers redacted from ordinary outbox
views. They do not establish freshness, absence of clones, owner succession or
safe live-device transfer.
