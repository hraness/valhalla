# Private rooms: implementation and release boundaries

Valhalla's private room core is implemented in the workspace. It is not yet a
private-room end-user release. An optional trusted native session now joins
account and room custody under one lock lifetime. The optional Unix CLI supports
explicit local file exchange. The optional browser worker now joins account and
room custody. A bounded read-only archive core and native encrypted-file archive workflow are
implemented. The optional browser interface has passed its two-account file-exchange journey and now shares the
same `.vharchive` export, interruption-safe import and read-only archive inspection as the native CLI. Owner-authorized
same-account fresh-device rejoin is implemented and exercised end-to-end; live custody transfer, owner-device succession
and automatic confidential delivery remain unfinished. Public discovery and public author
backups must never carry private state or private invitations.

## Components and default dependencies

- `vhalla-private-protocol`: bounded, canonical signed account/device/owner
  records. A verified signature establishes its source, not permission to act.
- `vhalla-private-kernel`: OpenMLS 0.9 with the RFC 9420
  X25519/AES128GCM/SHA256/Ed25519 suite. It checks pinned owner policy, actual MLS
  credentials and proposals, then commits encrypted state and output together.
- `vhalla-private-native`: bounded SQLite persistence, exclusive private-file
  custody and a host-controlled fixed-room agent interface. Optional feature
  `client` adds `RoomCreation` and `RoomSession` for a trusted native controller;
  it is off by default and does not add a CLI or network transport.
- `vhalla-browser-storage`, feature `private-rooms`: the same kernel Store
  contract over strict IndexedDB transactions. This optional feature is off by
  default; the public browser does not acquire MLS dependencies by using storage.
- `vhalla-identity` and `vhalla-browser-vault`, feature `private-rooms`: typed
  account signing for exact room anchors and device enrollments. Neither exposes
  a seed getter or a generic signing oracle. These features require only the
  private protocol, not the MLS implementation. Their separate optional
  `private-storage` features add the shared typed HKDF storage-key derivation
  and require the kernel. These features are also off by default.

The CLI's optional `experimental-private` feature exposes create, signed offer
inspection/import, encrypted contact request/response, message send/receive,
exact retry/export, membership inspection, removal, owner renewal, signed
control-proof export, owner-control observation and fork-evidence reporting. Its
[command guide](../crates/vhalla-cli/README.md#local-encrypted-private-room-files-experimental-private)
includes the full two-account file exchange. It opens existing identity custody,
uses only explicit local stores, and has explicit canonical relay-item export and
apply commands but no listener or automatic transport. Input is a
bounded pipe or owner-private file; outputs are exclusive-create, synced private
files. Fresh send checks authenticated membership, validity and the exact selected
epoch/roster before reading text. Output failure preserves the state and partial
file; retry exact inputs to a fresh output path or export retained ciphertext.
The FORMAT locator is an unauthenticated hint; the selected account and complete
private image authenticate before display or action. Six actual CLI process
journeys and the read-only locator regression pass; strict enabled-target CLI
and full-feature native lints also pass.

There is no dependency on Platonik. Clankdar puzzle bytes are inert application
content; solve evidence never changes membership, file access, or tool authority.

## Lifecycle and consent

The owner account signs a fresh random room anchor and initial device enrollment.
The anchor fixes the owner device. Accounts and devices have separate full keys;
several devices may use one account without gaining owner powers. There are at
most 16 active devices, including the owner, rather than a lifetime invite limit.

A trusted controller retains the complete room/anchor/account/device context
before consuming an owner or member draft. The native `client` derives its opaque
storage key from the existing account custodian and that exact context. Lower-level
callers may instead retain explicit storage-key custody. Initialization commits
the fresh device before releasing any MLS artifact. A pending member generates a
one-use KeyPackage, sends it through an independently confidential invitation
channel, and accepts only the pinned owner's matching Welcome and signed roster
checkpoint. The checkpoint is checked against the real resulting MLS roster and
GroupContext. Existing members process the exact next ordered encrypted control;
they cannot jump to a new joiner's checkpoint.

`membership()` reauthenticates the complete locally accepted anchor, owner, local
enrollment and roster before display. Account/device keys and validity intervals
are private metadata. A pending, removed or quarantined snapshot is an inspection
result, not permission to send or evidence of global freshness.

Message drafts bind exact room, author, epoch and roster. Membership changes and
owner renewal invalidate those drafts. The application must show the current
destination and recipients before preparing a replacement. It must not silently
copy an old message into a new roster. A retry of an already committed operation
returns the original retained ciphertext, never a new encryption for new members.
That recovery result alone is not authority to export it again.

Removal preserves already accepted local history while refusing new participation.
Fresh-device rejoin requires a new explicit owner invitation; it does not restore
or clone an old ratchet. Delayed old-epoch messages may be refused after a control
change. Removing someone cannot retract plaintext or keys they previously copied.

`owner_renewal_request` and `renew_owner` accept a current account-signed enrollment
for the exact same anchored owner device. The replacement extends its expiration
and must not move its start backwards. A narrow path permits the previous owner
certificate to be expired; ordinary operations retain their time checks, and an
expired member cannot use the renewal control to reactivate itself. The MLS
self-update is checked to contain only the intended credential update, with no
hidden membership, PSK or extension proposals. It advances the epoch, control
floor and roster digest atomically and supports exact retained retries.

Owner-device succession is not implemented. Losing every copy of that device's
current custody can leave a room unable to administer membership. An account key
alone cannot recover MLS state. A future succession policy must be explicitly
authorized by the original anchor and retain a common accepted control floor;
no current anchor is implicitly upgraded. Member renewal currently means an
owner-authorized fresh-device rejoin, not a reset or clone of existing state.

## Custody and confidential artifacts

`Identity::private_storage_key` and `UnlockedIdentity::private_storage_key` share
one fixed HKDF-SHA256 contract over the secret account seed and full private
context. They check the actual account key and return only an opaque zeroizing
`StorageKey`. Password re-encryption of the same account preserves access;
account-key replacement does not. Account compromise exposes all its retained
derived stores. Derivation neither creates membership nor reconstructs lost MLS
ratchets. Existing explicit-key stores are not silently converted.

The native `RoomSession` holds both exclusive account custody and kernel/store
custody. `lock()` or drop ends both. Its creation API consumes a fresh draft;
retain the exact context before `commit`. A failed or uncertain creation is
reconciled only by opening that context and existing store. Missing state refuses;
there is no delete-and-recreate fallback. Native storage operations run on a
suitable worker because SQLite and filesystem barriers block within one poll.
The optional browser controller uses the existing identity worker for both
custodians. Private entry prevents public signing/export for the lifetime of that
worker, including busy and failed states. Each operation revalidates the retained
account image; cancellation requires exact-context reopen. Creation separates
locator preparation, explicit retention acknowledgment and commit. The real
worker journey exercises these boundaries; a complete product interface and
private backup/import workflow remain separate work.

Existing-member control catch-up now uses an authenticated encrypted envelope.
Its key comes from the predecessor MLS epoch exporter and binds full room/anchor,
control floor, epoch, roster and fixed owner device. The original envelope commits
with the next state before release and is retained for exact retry. Applying it
still requires the inner pinned-owner signature, exact next floor and MLS checks;
being able to encrypt as a member grants no owner authority. The header reveals
control kind, epoch/sequence and length, so this is not traffic-analysis privacy.

`encrypted_controls` returns only retained encrypted envelopes. A fresh joiner
starts at its joining floor and cannot supply older encrypted controls. `controls`
returns local signed proof records, not catch-up packets safe for public sharing.
An altered old ciphertext is refused, not treated as proof of an owner fork;
quarantine requires authenticated signed evidence at a known retained floor.

Both maintained clients expose the inspection half of that boundary. The CLI's
`control-proof` exports the next signed owner-control proof at an exact floor
cursor, `observe` compares one signed proof against retained history and reports
`retained`, `unknown-history`, `below-retained-base` or
`conflicting-fork-quarantined`, and `fork-evidence` exports the first durably
retained contradiction. The browser panel reads the same bounded proof pages,
downloads exact `.vhproof` files, and applies the same observation verdicts;
a proven conflict still ends its worker after the durable quarantine write, and
the reopened panel shows quarantine status plus the retained evidence — the DOM
journey exercises this by observing a divergent control that a
local-qualification-only phase has the owner device re-sign at a retained floor.
The same journey covers the expired-envelope edge: a real next-floor control
applied under a caller clock past the local enrollment validity is refused by
the ordinary time check — nothing is published or quarantined — and the
identical envelope applies under a valid clock after reopen. An observed proof
is never adopted as state, never grants membership or owner succession, and
proves nothing about floors the device has not retained — comparison is
against local history only, not a global freshness claim.

## Confidential recipient bootstrap

`create_contact_offer` produces one 713-byte secret file bound to a full recipient
account. It contains the signed anchor and current owner enrollment, a separate
random offer ID, expiry, and two independently random direction keys. The anchored
owner device signs the entire canonical file, including those keys. An attacker
cannot copy legitimate bootstrap records and substitute its own encryption keys.
The file still requires confidential transfer; signing does not make it public.

`ContactBootstrap::inspect` checks the complete offer against independently
selected owner and recipient account keys and current time. Its metadata getters
are enough to initialize a fresh member device. `contact_request` commits a fully
encrypted KeyPackage request. `accept_contact` consumes the unused offer together
with membership state, encrypted invitation, operation record and existing-member
control in the same transaction, still at most three immutable records.
`join_contact` requires the exact retained request hash as well as the existing
owner, recipient, MLS Welcome and roster checks.

There are at most 64 outstanding offers. Each lasts at most 24 hours from issuance
and no later than the owner enrollment's expiry. Owner renewal invalidates the old
enrollment's offers. Exact creation retry returns the original secret without
reactivating consumed, expired or invalidated authority; exact admission retry
returns the original encrypted response. If a committed pending request expires
or is invalidated before admission, retain its evidence and explicitly prepare a
fresh device for another attempt. Never silently replace the old KeyPackage.

`OutboxEntry` is a closed choice between an ordinary artifact and confidential
issuance metadata. Its `artifact()` returns `None` for secret offers; normal
outbox export cannot retrieve their keys. A dedicated exact offer retry can
recover the secret from encrypted storage. Archived bootstrap secrets therefore
do not have a forward-secrecy guarantee against later storage-custody compromise.
The wire exposes direction, random offer ID, request/response correlation, nonce,
length and network timing/endpoints. It exposes no caller operation ID or room,
account, device or roster field in the clear header. It does not provide anonymity.

The earlier `key_package`/`invite` methods remain explicit local artifact APIs;
their plaintext metadata must not be uploaded through a generic relay path.
Contact encryption does not discover a relay, grant network authority or prove
that a remote member received anything. The maintained native client now exposes
an opaque `RelayItem` protocol for ordinary encrypted outbox artifacts: its
canonical bytes bind an out-of-band namespace, sender sequence, operation, kind
and ciphertext, while bounded in-process and durable file-backed mailboxes
provide idempotent retries and retention-only receipts. It refuses confidential
offer metadata and never
exposes room, anchor, account, device or plaintext fields to the relay. This is
the transport boundary, not a deployed relay or delivery acknowledgment; the CLI
can export and explicitly apply the canonical envelope for local adapter
integration, while an HTTP/QUIC/file adapter and live failure-domain
qualification remain required.

## Durable state and limits

The kernel publishes one encrypted current image and at most three new immutable
records under exact whole-image compare-and-swap. Owner changes append control,
outbox and operation records together. Records are never replaced, including
equal-byte collisions; retries read their previously accepted record. Plaintext
inbox delivery and outbound ciphertext are withheld until durable completion.
Uncertainty or cancellation latches the custodian until an explicit reopen of
the exact retained context. Missing published state never means “start again.”

SQLite uses a private directory, lifetime exclusive lock, fixed FORMAT/context,
bounded indexed tables, rollback journals, EXTRA synchronization, macOS fullfsync
and explicit file/directory synchronization plus readback. IndexedDB requires the
browser's strict durability mode and transaction-complete event. These are local
storage contracts, not a proof against lying hardware, coherent rollback,
origin eviction, a malicious host or cloned live custody.

The current bounds are 4 MiB plaintext state, 256 provider entries, 128 KiB MLS
frames, 4,096-byte message bodies, 16 records/512 KiB per history page and a
4,096-byte roster checkpoint. Stores have explicit retained-record/byte capacity.
There is no automatic history pruning or unlimited storage claim. A valid owner
fork at a known retained floor quarantines the device and preserves bounded proof
if publication succeeds. If storage cannot write, the pending proof must be
preserved separately; observing it in memory does not make it durable.

Current state uses `VHPKSTATE\x04`; invitation packets use `VHPKINVITE\x02`.
State versions 1, 2 and 3 are not automatically migrated. Opening an old, incomplete
or inconsistent store refuses; it does not overwrite, migrate or silently
regenerate it. Retain compatible source and complete custody when inspecting
older experimental artifacts.

## Agent boundary

Trusted host code creates `LocalGrant` from an authenticated local status and
retains its sole revocation handle. A grant fixes the complete context, exact
epoch/roster, allowed methods, finite process quotas and a monotonic deadline of
at most one day. The agent gets only status, bounded inbox, prepare, queue and
outbox metadata. It cannot choose another room, edit grants, change membership,
retrieve raw keys/ciphertext, open files, execute code or contact a network through
this interface. Revocation, expiry and storage uncertainty are checked across
awaits before output. Canceled/uncertain work consumes its allowance conservatively.

Room messages remain untrusted text. Instructions or successful puzzles do not
grant execution authority. Sharing inbox content with an external model provider
is itself a separate host egress decision. The same standing grant can cover
repeated coordination within its exact room and limits; a changed roster needs a
new grant and fresh agent context. Process quotas are not durable global quotas.

This API does not sandbox an independently privileged agent process. A product
controller still needs room-lifetime file/process/network compartments, explicit
input/provider grants and exact-content/destination authorization for intentional
export. No classifier or prompt can guarantee that an unrestricted agent never
copies a secret.

## Qualified behavior and unfinished release work

The earlier promoted group/renewal checkpoint, before state-v3 confidential
controls and native account-derived sessions, passed 155 tests across five packages,
including 30 kernel tests, one kernel compile-fail example, 21 native backend/agent
tests and six real MLS/SQLite journeys. Full-workspace strict lint and explicit
WASM lint/build passed. The 53-lock security gate found no active vulnerabilities;
inactive/archive findings and 14 warnings remain in its reports without
suppression. Actual Chromium Window and worker journeys against the workspace
artifact each performed 66 strict writes and 374 reads, covering three
devices, bidirectional messages, exact reopen, removal, owner renewal, wrong
scope/key, stale writers, quotas and faults after actual commits. A monolithic
debug fixture originally exhausted the standard WASM stack; splitting it into
bounded async phases fixed the defect without increasing stack or time budgets.
CI repeats the native and actual browser coverage for each integration candidate.
Those counts describe that earlier source, not a result for the changes described
in this guide. Current native-session tests cover custody lock/reopen, exact retries,
recipient inspection, stale consent after renewal, wrong-account refusal and
missing-state preservation. Current confidential-control and custody tests are
also present in source. The combined custody/control/continuity candidate passed
214 tests across six packages, full-workspace/all-target/all-feature strict Clippy,
WASM library Clippy with all features, the separate production-feature WASM
Clippy configuration, and the real private-room browser fixture build. The actual Window and worker runtime each passed with 66 strict writes and 374
reads. The fresh 53-lock dependency audit found no active vulnerabilities; three
inactive/archive findings and 14 warnings remain recorded without suppression.
The current state-v4 confidential contact candidate passed 87 kernel/native/client/
agent tests and compile-fail examples. Its actual Window and dedicated-worker
group journeys each performed 74 strict writes and 447 reads, including the
owner-signed one-use contact exchange and refusal of a modified offer. A separate
real account-derived custody fixture passed in both contexts, each with six
strict writes and 57 reads: saved-vault authentication, joint account/kernel drop,
exact image reopen and ciphertext retry, password re-encryption parity,
wrong-account preservation and missing-image refusal. Both retained the standard
WASM stack, 20-second worker/45-second outer deadlines and full Argon2 parameters.
The complete harnesses took 9.126 and 11.361 seconds respectively on the measured
Chromium 153/macOS host; these are fixture timings, not throughput guarantees.
Full-workspace strict Clippy, all-feature and production-feature WASM Clippy,
both browser fixture builds and a fresh 53-lock security audit also passed.
The public continuity store's 39 tests and strict lint passed separately.
These checks do not establish a complete private-room UI or live relay delivery.

Before a private-room release, finish and qualify:

1. Browser worker/session integration around the maintained custody and storage
   primitives, plus complete-state backup and clean-device recovery in both
   clients. Key-only restoration must not restart an old device or clone custody.
2. Usable room creation, recipient-bound invitation, member/device inspection,
   catch-up, removal, renewal and explicit recovery UX in both clients.
3. Usable delivery of the implemented confidential bootstrap and encrypted
   controls. Keep secret offers, legacy plaintext bootstrap and local proof
   artifacts out of public relay uploads.
4. Integrate the maintained bounded opaque relay-item protocol with an actual
   interchangeable transport, offline retry, congestion/quota behavior and
   strict separation between relay retention and member acceptance.
5. Enforced agent compartments and inference-provider grants, with fresh contexts
   across rooms and explicit intentional export.
6. Owner-device succession policy, overload/storage-full behavior, full worker
   termination recovery, independent-peer operation and relevant live acceptance.

The public site's readiness page remains the end-user status. This document
describes implemented foundations and does not advertise a live private network.


## Archive recovery boundary

The kernel now exports complete authenticated room state and retained evidence in
bounded encrypted pages. Import uses an explicit fresh namespace and exact source
context/archive ID, checks source-key possession before writes, preserves exact
progress across uncertain writes, and publishes only after a complete final seal.
The destination remains a read-only archive: it cannot send, sign or reopen as a
live MLS device. Secret offer issuance remains redacted in normal history views.
See the [archive contract](../crates/vhalla-private-kernel/README.md#encrypted-read-only-archives).

The optional native CLI supplies bounded `.vharchive` export, fresh-destination
import, exact receiving-state resume, and membership/inbox/redacted-outbox
inspection. Its three account-custody tests, three process journeys and interrupted
file-framing test passed locally. See the [native archive runbook](../crates/vhalla-cli/README.md#native-private-archives-experimental-private)
for private file permissions, immutable quotas and recovery after uncertainty.
Archive inspection authenticates the completed destination and final file seal;
it does not freshly verify every middle page of an already imported file.

The optional browser interface supplies the same `.vharchive` container. An open
room streams bounded authenticated pages into one file; a selected file decodes
its unauthenticated header, refuses foreign accounts before any worker call, and
imports pages one at a time into a separate read-only IndexedDB namespace with a
durable receiving cursor that resumes exactly after interruption — committed
pages are re-fed once so the worker validates the exact retry rather than
re-importing them. A completed archive opens read-only membership, inbox and
redacted-outbox views and explicit ciphertext re-export under the same secret-
offer exclusion. Archive selection never coincides with a live room or prepared
creation, an explicit close is required before another selection, and a foreign
or absent archive destination fails the session rather than fabricating state.

Same-account fresh-device rejoin is implemented and exercised end-to-end: the
account backup restores the same public key to fresh custody, the owner admits
it through the ordinary confidential offer/request/response flow addressed to
its own account, and the new device enrolls as a distinct member starting at its
joining checkpoint with no access to earlier history. Kernel, CLI-process and
real-browser DOM journeys all cover the path, including post-join bidirectional
exchange and exact retained retries. It is a new enrollment, never a ratchet
restore — account backup alone cannot reconstruct MLS state, and a copied store
is never a safe second sender. Historical archive
inspection never authorizes resuming an old device. Retain all encrypted parts
and the full locator; never silently clone a ratchet. Owner-device succession and
safe live-custody transfer remain unimplemented.
