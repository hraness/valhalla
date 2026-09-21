# Bounded browser storage

This crate contains a portable opaque-image codec and a Rust/WASM IndexedDB
adapter. It is adapted from
`c407159^:prototypes/dioxus-services/src/browser.rs`; no Dioxus dependency,
renderer, controller, authored JavaScript or TypeScript is included.

## API and trust boundary

The application supplies a locally selected 32-byte `Namespace`. Its database
name is derived under a fixed prefix; neither a network record nor a route may
select another profile. Namespace selection is a host responsibility and is
not authentication by this crate.

Three fixed `Slot` values are independent: `Vault`, `Checkpoint` and `Outbox`.
An `Image` contains bounded length-prefixed opaque records. Each image is at
most 2 MiB, at most 256 records, and at most 1 MiB per record. These are
per-publication limits, **not a lifetime social-history limit**. There is no
requirement to store an entire archive in an image or preserve every historical
record in the next checkpoint. Segmented history and proof/range synchronization
belong to a separate domain/storage layer.

Only `Vault` checks a domain format: exactly one 125-byte encrypted
`vhalla-browser-vault::Envelope`. This is structural checking, not password
authentication. Checkpoint/outbox bytes are deliberately opaque. The domain
controller must verify signatures, trusted genesis and validator changes,
monotonic frontier/anti-rollback policy, source dependencies, and submitted
operations before using or publishing them. No method calls these bytes
"verified" or lets successful storage substitute for admission.

Keep only encrypted vaults and signed public evidence/submissions in these
slots. Never give this adapter a plaintext private key or password. The codec
cannot identify secrets hidden inside arbitrary opaque checkpoint/outbox bytes;
the typed domain controller must maintain that invariant. Images and errors
have no automatic content logging.

On WASM, `browser::IndexedStorage` provides:

- `open(namespace)`: create missing schema only; never initialize or repair data.
- `load(slot)`: return an exact image or explicit `None` for absent/evicted data,
  after the read transaction completes. The caller decides what absence means.
- `compare_exchange(expected, next)`: compare exact prior bytes inside one
  readwrite transaction and queue one replacement. `expected: None` succeeds
  only if the slot is absent. An exact previous vault allows an explicitly
  authorized password/identity replacement; storage does not prohibit rotation.
- `needs_reopen()`: after failed/canceled publication or schema invalidation,
  drop the handle, reopen and load the actual surviving image before proceeding.

Application writes request IndexedDB `durability: "strict"` and check the returned
transaction mode before queuing a mutation. Browsers that ignore or reject it
refuse writes; unchanged identity unlock remains read-only. This durability hint
is not protection against eviction, coherent rollback or dishonest storage.

Slots do not form an atomic multi-slot transaction. A workflow that needs
evidence and outbox changes to commit together must put its bounded publication
unit in one image or introduce a separately reviewed journal/transaction API.
Do not infer cross-slot durability from separate successful calls.

The identity-specific methods below provide a reviewed vault/provenance pair
transaction. Browser identity controllers must use that API, including normal
unlock, instead of treating a generic vault CAS as a creation receipt.

## Publication and cancellation

Prepare and validate the next image before starting the transaction. The read
success callback performs only bounded exact-byte comparison and a synchronous
`put`; there is no asynchronous cryptographic validation inside an auto-commit
window. A queued or successful put request is never reported as publication.
Only the transaction's `complete` event can return success.

The handle becomes unavailable before a write transaction starts. A failure
returns `PublishError::ReopenRequired(cause)` and keeps it unavailable. Dropping
an already-polled write future also leaves it unavailable and asks IndexedDB
to abort. Cancellation may race a completed transaction: never claim rollback
or automatically retry from an assumed prior image. Reload what survived.
Invalid slot input or an already unavailable handle returns `Rejected` without
starting a new transaction. A stale CAS is conservatively reopen-required even
though that transaction did not replace the winning tab's state.

Transaction request errors explicitly request abort and keep callbacks until a
terminal abort/complete event. Guards detach handlers and abort unfinished
transactions on cancellation and early setup errors. Schema version changes
close the connection and invalidate the handle; a late completion cannot make
that handle ready again. Dropping a handle closes its connection.

IndexedDB open requests cannot be canceled. At most four pending opens retain
their own callbacks until a terminal event. A blocked open reports `Blocked`
but keeps its slot; late success closes the connection, and a canceled upgrade
aborts. A successful result waiting in an unpolled channel also owns a closing
guard. A blocker that never releases keeps a slot indefinitely, bounding orphan
state instead of accumulating invisible connections. The host must also bound
successful live handles and concurrent tasks; image ceilings are not a global
memory bound. Individual handles permit only one mutable operation at a time.

## Canonical framing and limits

The bytes are `VHBI 00 00 00 01`, a one-byte slot tag (`1` vault, `2` checkpoint,
`3` outbox), a big-endian u16 record count, then each big-endian u32 length and
its exact bytes. There is no padding, optional field or trailing data. Wrong
version/slot, excess counts/lengths and truncation fail before copying a complete
image. Empty checkpoint/outbox images are representable but require domain
authorization; a vault always contains one encrypted envelope.

This layer does not supply authenticity for private application metadata,
rollback resistance, remote replication, browser-eviction immunity, or a promise
that transaction completion survived power loss. Same-origin hostile code can
read/modify/delete browser storage. Vault encryption is a separate password
boundary, not XSS isolation. The browser controller must expose quota, missing
data and recovery states instead of silently minting another identity.

## Local creation and author recovery

`IndexedStorage::load_identity()` reads the vault and local birth metadata in one
transaction. `IdentitySnapshot` retains their exact bytes. Its `local_creation`
method requires the independently authenticated public key and fails closed if
the metadata is absent or does not match. Imported and older vaults without birth
remain usable for unlock and encrypted backup, but cannot authorize a fresh
activity sequence. A missing vault with present birth, malformed metadata, or a
different public key is corruption; no method repairs it implicitly.

`create_local_identity(next)` is reserved for a genuine CSPRNG new-key path. It
requires an absent pair and atomically adds the encrypted vault plus a canonical
40-byte `VHBBTH01` record containing its public key under the fixed key
`identity/v1/local-birth`. `replace_identity(expected, next)` compares the exact
pair, permits only the same existing key, and preserves the birth record or its
absence. Importing a backup into an empty profile never manufactures provenance.
Same-key password changes preserve provenance. An unchanged normal unlock calls
`revalidate_identity(expected)`: one readonly transaction rereads and compares
the exact encrypted vault and provenance pair before acknowledging the worker
identity. It performs no `put` or `add`, keeping unlock and author-state export
available when storage reads succeed but writes fail. Missing, changed or
malformed state fails closed. Cancellation or failed completion requires reopen;
no cached identity is substituted. New identities and changed backup imports
still require their write CAS. This removes an unnecessary write dependency;
actual browser quota failures and export remain a separate qualification gate.

`IndexedOutbox::initialize_locally_created_author(scope, expected)` checks the
exact saved pair and matching author in the same transaction that requires an
entirely absent author namespace and adds its initial floor. It returns an
already-persisted `AuthorHead`; do not initialize it a second time. Existing
floors, signed records and pending reservations must be loaded, never reset.
Cancellation or uncertain publication requires reopening and reading the
surviving pair/floor, including when a transaction committed before cancellation.

Birth metadata records only this browser profile's creation path under trusted
same-origin code. It is not cryptographic attestation or protection from storage
rollback, eviction, hostile code, or signing on another device. Use a key on one
authoring device. An encrypted key backup restores possession, **not** the local
sequence floor, unpublished signed events, or pending reservations. Key-only
restore into a new profile stays read-only for activity until a separate author
history recovery flow can establish and preserve that state. Do not infer an
unused sequence from an empty profile or a peer's asserted head.

## Append-only certified history

`history` provides bounded opaque `HistoryHead`/`HistoryRecord` frames and
`browser::history::IndexedHistory` retains them under an exact profile, network
identifier and independently selected bootstrap pin. It uses disjoint fixed
`history/v1/NETWORK/PIN/` keys in the same schema; heights are 16-digit lowercase
hex strings, preserving every u64 value without JavaScript number conversion.

`initialize` atomically creates the exact bootstrap bytes and height-zero head.
An exact existing genesis/bootstrap pair is idempotent only when no height
records exist. Different or advanced state and orphan partial scopes fail;
load existing history instead of resetting it. Bootstrap storage allows up to
40 MiB, while the controller must enforce `Bootstrap::decode`'s tighter domain
limits and compare the independently selected pin before publication or use.

`append(expected, record)` compares the complete prior head inside one readwrite
transaction, adds an immutable next-height record, and writes its next head.
An existing height is never overwritten, even with equal bytes. Only transaction
completion acknowledges publication. Failed or canceled writes require
drop/open/replay; retrying from an assumed old head is unsafe. The caller must
prepare a `CertifiedClient` candidate before append and call
`commit_after_persist` only after successful publication.

`read_page(start, limit, byte_budget)` reads the head and contiguous records in
one read transaction, stops at that observed head, and returns at most 16 records
and 2 MiB. It checks JavaScript byte lengths before copying values into Rust.
Published gaps, wrong scope/height, broken in-page predecessor metadata,
malformed/trailing frames and a final record inconsistent with the observed head
fail. A budget unable to fit one record fails instead of claiming an empty page.
Each bundle is limited to the current journal ceiling (384 KiB + 148 bytes).
There is no lifetime record-count cap or implicit pruning; the controller owns
bounded replay work, quota handling and storage-pressure recovery.

Storage framing is not a certificate or content-hash check. Well-framed altered
payload bytes still require the controller's certificate/application replay;
compare the prepared candidate's complete frontier and bundle ID to the retained
metadata before using it. Retained bootstrap/head bytes are never their own trust
anchor. This API adds no rollback resistance, storage-eviction protection,
cross-slot atomicity or absolute physical-durability guarantee.

## Author reservations and local outbox

`outbox` and `browser::outbox::IndexedOutbox` separate authoring from delivery.
Their fixed namespace contains the full immutable network, realm, directory,
room genesis and author public key. It deliberately excludes the mutable
bootstrap pin: validator rotations must not reset an author's sequence.

The controller may call `initialize_fresh_author` only for an explicitly
authorized, genuinely never-used room/key scope. The browser controller uses the
atomic `initialize_locally_created_author` path above. An absent database, a restored
key, or a peer's asserted head is insufficient. Existing scope keys refuse
initialization. Key backups recover private keys, **not** author sequence state;
new-device author-history recovery remains a separate required integration.

Before dispatching the worker, the controller admits the draft against its
certified room policy and calls `reserve` with exact typed unsigned bytes.
One transaction checks the current full author head, the selected certified
history head in the same profile database, and any pending draft. It adds an
absent pending intent or accepts only the identical retained intent. A different
draft at that sequence is refused before any signature request should be sent.

The worker signs only the canonical typed activity and its exact claimed author.
`finalize` requires a strictly verified signature with the reserved content ID
and claims. One transaction checks the same author, pending and policy basis,
adds immutable signed event and local outbox records, advances the author head,
and removes the pending intent. Only completion permits reporting locally queued.
This does not mean any serving peer accepted the event or that its policy is
globally current. No server-write, delivered-status, pending-abort, sequence-reset
or history-pruning API is provided here.

Cancellation can race signing or commit. Uncertain writes require reopen and
inspection; they never make a sequence available for different bytes.
`rebase_reservation(old, new)` handles an unrelated certified-history advance:
the controller first admits the unchanged request under its freshly replayed
registry, then constructs `new` with the exact same author base and unsigned
bytes, the same bootstrap scope, and a strictly higher history head. One
transaction compares the current author floor, old pending intent, and exact
new certified head before changing only pending policy metadata. An exact new
pending image is also accepted after an uncertain successful rebase; no other
pending content is ever overwritten.

This is not permission to change the policy revision signed into the event.
A revoked or changed room policy still quarantines the possibly signed intent;
recovery of revoked pending ancestors remains a separate protocol/product gap.
It must never cause that sequence to be reset or reused for different bytes.

`read_page` returns at most 16 events/128 KiB under one observed author head;
it checks byte lengths before copying, then verifies signatures and in-page
chain continuity after the read transaction. Missing published entries fail.
Outbox events are retained for explicit retries without a lifetime image cap.
No storage frame is a remotely certified author floor or freshness proof.

## Native custody and peer sessions

`native::NativeOutbox` uses the same typed reservation, signed-event and delivery
checks under an exclusive lock in a private directory. Creation is explicit;
opening missing or corrupt state never creates a fresh author. Reservations
become durable before signing; immutable signed events and receipts precede
their published heads. Retained history uses bounded direct-index pages and
explicit configured capacity, without automatic pruning.

`native::peers::NativePeerSession` is a separate, bounded store for one explicitly
selected full peer key and immutable HTTPS endpoint. Its scope binds both the
stable network ID and independently pinned bootstrap/configuration digest.
`create_new` requires a fresh signed advertisement with READ and that exact
endpoint. `open` checks the caller's full scope, key and endpoint before recovery
writes. Snapshot compare-and-swap operations durably checkpoint a nondecreasing
local clock and retain the latest signed advertisement sequence. Expired evidence
restores a sequence floor; it does not authorize activity. Valid newer route or
capability withdrawals are persisted before the caller decides whether the peer
is usable, preventing a later older advertisement from restoring withdrawn claims.
There is no reset, route replacement, automatic migration or network operation.

Both native stores stage future updates in private `INTENT.tmp`, sync it, then
atomically publish and sync authoritative `INTENT` before any transition effects.
Reopening promotes an exact complete staged transition. Only a structurally
incomplete unpublished scratch prefix bound to the exact retained state can be
removed, with guards against already-created transition effects. Malformed,
foreign or stale scratch and corrupt authoritative intents remain evidence and
fail closed. An uncertain write requires dropping and reopening the handle;
recovery resyncs retained evidence before acknowledging completion. This preserves
the existing outbox format and does not repair legacy partial authoritative
intents. Coherent disk rollback and hostile mutation by the same OS owner remain
outside this local custody boundary. Controllers still must verify certified
history, fresh peer proofs and current route/capability suitability; this API adds
no sending or public publishing command.

## Per-peer delivery evidence

`outbox::delivery::{DeliveryHead, DeliveryRecord}` retain a complete canonical
POST request, `ActivityResponseProof`, and exact `LocalReceipt` body. The request
includes its original challenge and the SHA-256 hash of the entire signed event.
The record verifies the exact network and full peer key, challenge, response
signature and receipt bytes. `check_event` verifies the author signature and
binds the complete network/realm/directory/room/key scope, sequence, content ID,
and POST body hash to the actual local outbox event. A receipt's room ID alone
cannot establish that complete scope.

`IndexedOutbox::load_delivery(scope, peer)` reauthenticates the retained latest
receipt and its signed local event before returning that peer's contiguous
author floor. `record_delivery(scope, peer, expected, request, proof, body)`
compares that exact floor, checks the current stored outbox bytes, and atomically
adds an immutable next-sequence receipt plus the new floor. The sequence must
be contiguous, its signed predecessor must match, and the peer's local cursor
must increase. Only transaction completion acknowledges publication. Failed or
canceled publication requires reopen/reconciliation, like other outbox writes.

An independently verified retry for the latest already-acknowledged exact event
returns the original retained head and preserves the original proof/body even
if the retry reports a different local cursor. It cannot roll back the cursor
or replace evidence. Different peers have independent namespaces containing
their full keys; no peer receipt deletes outbox events or marks them globally
delivered. Orphan receipts without their head fail closed. The namespace uses
fixed `delivery/FULL_PEER_KEY/receipt/016lowerhex` keys below the full author
scope, without JavaScript number conversion or lifetime history caps.

`load_delivery_receipt(scope, peer, sequence)` returns retained original evidence
for offline display up to the observed floor. Missing published receipts and
missing/mismatched signed local events fail. This is evidence that the named
peer made a local durable-storage statement; it is not independent proof that
the peer retained bytes, is still online, saw globally latest policy, or achieved
consensus. As with other local state, coherent rollback, eviction and malicious
same-origin rewriting are outside this storage boundary.

## Complete author-scope recovery

`outbox::recovery` and `IndexedOutbox` implement explicit paged export and
staged import of one complete room/key scope. `begin_export` captures its exact
author head, optional pending intent, and receipt mutation revision under the
independently selected network/bootstrap pin. `export_page` reads at most 16
recognized relative key/value pairs per transaction, checks value lengths
before JavaScript-to-Rust copying, verifies signed event chains and exact
event/outbox duplicates, and validates complete per-peer receipt prefixes and
their local signed byte bindings. There is no 4,096-event or lifetime cap.
`finish_export` rechecks the exact captured head **and pending intent and receipt
revision** before issuing the final authenticated frame. A concurrent signing,
rebase, or receipt write requires starting a new backup. Each accepted receipt
increments that revision in the same transaction as its immutable evidence.

The unlocked identity worker encrypts each typed page separately. All numbered
parts, including the final part, are required. An initialized sequence-zero
scope is explicit: its zero head is included, along with any reserved first
intent. A missing scope is never silently exported as unused. The browser
offers one bounded file per explicit action; it does not accumulate an entire
history in memory. Browser download initiation is not proof of file retention.

`begin_import` requires an authenticated matching identity snapshot, exact
independently selected scope/pin, and an entirely absent author namespace.
Only the identical interrupted backup can resume. `import_page` validates
canonical page order/hash chaining, signatures, sequence/predecessor chains,
pending/base equality, and delivery prefix completeness before adding immutable
records. The active author head is withheld; a persistent `recovery/stage`
record blocks fresh initialization even if the key has local birth metadata.
Every write compares the exact identity pair, retained import progress, and
head absence. Unknown outcomes require reopen/load; the exact latest part can
be retried without replacing data. Other content or an older active-state
backup cannot overwrite existing state.

After the authenticated final part, `verify_import_page` joins every original
peer request/proof/receipt to the actual staged signed outbox bytes in bounded
pages. Only then may `activate_import` publish the validated head and remove the
stage marker in one transaction. There is no destructive abort/reset API;
preserve incomplete data and resume its exact backup. Key-only import still
does not create local birth or authorize a used author sequence.

This procedure restores complete local state under the trusted-origin model.
It cannot prove a backup is globally latest, detect coherent rollback, replace
missing newer signatures, resolve two-device forks, or bypass revoked room
policy. The operator must stop the prior writer and select the latest complete
backup. Imports preserve exact pending intent even when current policy prevents
using it; recovery does not discard a possibly signed sequence.

## Validation and remaining browser gate

Native tests cover canonical parsing and bounds, two stale competing writers,
duplicate initialization, before/after-commit cancellation, abort/reopen,
schema invalidation and independent slots/vault replacement. The event model
shares the real CAS predicate and publication latch; it does **not** emulate
IndexedDB or prove callback cleanup in a browser.

After workspace/lock integration, run focused tests and Clippy, then compile
`vhalla-browser-storage` for `wasm32-unknown-unknown` with the matching Rust
1.98 standard library and locked wasm-bindgen 0.2.108/web-sys 0.3.85. That checks
Rust/browser API compatibility only. The integration owner still needs a real
browser fixture with isolated namespaces: competing tabs, abort after queued
put, close/reopen, missing/corrupt/oversized values, blocked and canceled opens,
late success buffered before polling, version changes, quota failure, and page
interruption. Use fresh test-owned namespaces and preserve any existing data.

The browser adapter resolves a typed IndexedDB factory in its current global
realm. A dedicated custody worker can own the same strict transactions without
sending decrypted state or database handles through the window. The synthetic
`qualify_storage.mjs` harness exercises both Window and dedicated-worker realms;
this does not by itself implement private-room storage or worker authorization.

## Public continuity receipts (separate from v1 authoring)

`outbox::continuity` frames one exact author/bootstrap/peer/endpoint session. It
has no key, signature-generation, network, policy-admission, pruning or author
reset API. A `Snapshot` prepares a move-only `Publication`; inspecting its
projected state is not a persistence receipt. Reserve the exact attempt before
HTTP and generate a new unpredictable nonce for each new exchange. An ambiguous
retry keeps the logical operation and signed content while replacing the nonce;
late replies cannot match the retained attempt. Immediate nonce reuse refuses;
entropy and avoiding older nonce reuse remain the controller's responsibility.

`Reply::Status` and `Reply::Staged` are hints only. `TerminalEvidence` records one
selected peer's admission assertion. It never acknowledges its ancestors. Only
strictly verified `Reply::Evidence` records whose canonical signed frames match
the actual immutable local outbox advance `RetentionHead`. The retained role and
transaction boundary are checked across page edges, including pages with distinct
original registry bases. Completion requires the selected terminal's role,
original cursor and registry to match both evidence types. No global completeness,
latest policy, peer availability or continued physical remote storage is proved.

A job fixes an existing local signed terminal. Explicit replacement can move to a
strictly later terminal with a new operation, preserving retained evidence and
all original response files. This slice does not implement the HTTP controller
or signing/recovering an old-policy reserved draft. Existing v1 `AuthorHead`,
`DeliveryHead`, reservations, delivery proofs and native directory bytes stay
unchanged. There is no conversion of a jumped terminal into a v1 delivery head.

Native `native::continuity::NativeContinuity::{create_new,open,snapshot,publish,
read_record}` uses a separately created private receipt directory and lifetime
custody lock. Every call also borrows the existing `NativeOutbox`; it never opens
a second author writer. FORMAT binds the exact complete scope/route and immutable
limits before recovery writes. Missing prior sessions refuse; use `create_new`
only for an explicitly new receipt session, never to repair a lost one. Reads
reauthenticate a fixed maximum of three referenced proofs plus one pending body,
then compare the actual indexed author records. Older proofs are checked on direct
indexed reads; open is not an all-history file-integrity scan. Missing published
records fail when referenced/read, without reinitialization.

Future native operations publish `INTENT.tmp`, synchronize it, atomically rename
to INTENT and synchronize the directory before effects. Exact immutable proof
bytes precede atomic STATE and acknowledgement; INTENT removal is synchronized
last. Reopen first validates scope, quota, current state and source. A complete
canonical staged intent can finish its exact prior operation. An incomplete
unpublished frame is removed only with exact current-before framing and no
successor/temporary effects. Full malformed or authoritative partial intents stay
untouched. Initial never-completed FORMAT/STATE creation remains fail closed.
Any ambiguous write poisons the handle; no success is reported before explicit
reconciliation. The model assumes a cooperating private-directory owner; coherent
hostile local rollback is outside its guarantee.

IndexedDB `IndexedOutbox::{create_continuity,load_continuity,publish_continuity,
continuity_record}` stores a new `continuity/v1` prefix inside the existing
profile database. Strict transaction completion is the success boundary. The
same transaction rechecks source author/history, exact source event keys and
receipt STATE before adding immutable evidence and the next state. Access latches
before await; cancellation, abort or uncertainty requires drop/open/load. An
existing prefix cannot be recreated and missing state is not a fresh author.

Each wire mutation contains at most33 frames and Evidence at most32. A candidate
rechecks at most40 source checks; fixed referenced proofs plus a pending attempt
use at most136 checks. Publication performs both (at most176 checks), independent
of lifetime history. A response record is at
most `MAX_REPLY_BYTES+8192`; state is at most `MAX_BODY_BYTES+8192`. Native bounded
intent/temp/control overhead is separate from retained response quotas (under
one MiB total), not the v1 64KiB allowance. Explicit quotas are one to one million
response records and at most8GiB retained response bytes. Exhaustion preserves
all evidence and refuses the new operation. These are storage bounds, not
throughput or production capacity recommendations. Server 4096 staging and lease
limits remain unchanged.
