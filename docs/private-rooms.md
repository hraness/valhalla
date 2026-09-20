# Private rooms: implementation and release boundaries

Valhalla's private room core is implemented in the workspace. It is not yet a
private-room end-user release. The native CLI and browser UI still need custody,
invitation, recovery and confidential delivery workflows. Public discovery and
public author backups must never carry private state or private invitations.

## Components and default dependencies

- `vhalla-private-protocol`: bounded, canonical signed account/device/owner
  records. A verified signature establishes its source, not permission to act.
- `vhalla-private-kernel`: OpenMLS 0.9 with the RFC 9420
  X25519/AES128GCM/SHA256/Ed25519 suite. It checks pinned owner policy, actual MLS
  credentials and proposals, then commits encrypted state and output together.
- `vhalla-private-native`: bounded SQLite persistence, exclusive private-file
  custody and a host-controlled fixed-room agent interface.
- `vhalla-browser-storage`, feature `private-rooms`: the same kernel Store
  contract over strict IndexedDB transactions. This optional feature is off by
  default; the public browser does not acquire MLS dependencies by using storage.
- `vhalla-identity` and `vhalla-browser-vault`, feature `private-rooms`: typed
  account signing for exact room anchors and device enrollments. Neither exposes
  a seed getter or a generic signing oracle. These features require only the
  private protocol, not the MLS implementation.

There is no dependency on Platonik. Clankdar puzzle bytes are inert application
content; solve evidence never changes membership, file access, or tool authority.

## Lifecycle and consent

The owner account signs a fresh random room anchor and initial device enrollment.
The anchor fixes the owner device. Accounts and devices have separate full keys;
several devices may use one account without gaining owner powers. There are at
most 16 active devices, including the owner, rather than a lifetime invite limit.

A trusted controller retains the complete room/anchor/account/device context and
storage secret before consuming an owner or member draft. Initialization commits
the fresh device before releasing any MLS artifact. A pending member generates a
one-use KeyPackage, sends it through an independently confidential invitation
channel, and accepts only the pinned owner's matching Welcome and signed roster
checkpoint. The checkpoint is checked against the real resulting MLS roster and
GroupContext. Existing members process the exact next ordered control; they
cannot jump to a new joiner's checkpoint.

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

The experimental group state and invite encodings are explicitly versioned.
Opening an old, incomplete or inconsistent store refuses; it does not overwrite,
migrate or silently regenerate it. Retain compatible source and complete custody
when inspecting older experimental artifacts.

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

The promoted workspace passed 155 tests across its five changed packages,
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

Before a private-room release, finish and qualify:

1. Maintained native/browser storage-secret custody, lock/unlock, complete-state
   backup and clean-device recovery. Key-only restoration must not start an old
   device's counters again or clone current custody.
2. Usable room creation, recipient-bound invitation, member/device inspection,
   catch-up, removal, renewal and explicit recovery UX in both clients.
3. Confidential invite and control transport. Current local control packets
   contain owner/enrollment/roster metadata around MLS artifacts; uploading them
   unchanged to an untrusted public relay would expose that metadata.
4. Bounded interchangeable encrypted relays, offline retry, congestion/quota
   behavior and strict separation between relay retention and member acceptance.
5. Enforced agent compartments and inference-provider grants, with fresh contexts
   across rooms and explicit intentional export.
6. Owner-device succession policy, overload/storage-full behavior, full worker
   termination recovery, independent-peer operation and relevant live acceptance.

The public site's readiness page remains the end-user status. This document
describes implemented foundations and does not advertise a live private network.
