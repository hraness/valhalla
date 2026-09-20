# Public room activity

This portable `no_std + alloc` crate defines version-1 signed public text and
local admission under an independently verified room registry. Activity does
not enter the bounded social `Archive` or consume a room-control revision per
post. The room owner must first commit `SetPublicActivityPolicy` through the
existing consensus/control path. Rooms without that policy remain closed.

A signature identifies the complete application public key. It does not prove
a human identity, room ownership, validator membership, reputation, payment,
host execution authority, or confidentiality. Text is inert untrusted text;
renderers must escape it and never execute it.

## Canonical version-1 wire

All integers are unsigned big-endian; all identifiers retain their full width.
No field is optional and trailing bytes are rejected. The complete frame is at
most 4,392 bytes, checked before parsing or allocation.

| Field | Bytes |
| --- | ---: |
| Magic `VHRA`, version `1` | 5 |
| Stable pinned network ID | 32 |
| Realm | 16 |
| Directory ID | 32 |
| Full room genesis ID | 32 |
| Exact owner-signed policy record ID | 32 |
| Author Ed25519 public key | 32 |
| Sequence, at least 1 | 8 |
| Previous event ID, zero if and only if sequence is 1 | 32 |
| Author-claimed creation time | 8 |
| Content kind `0` (text) | 1 |
| Exact UTF-8 text length | 2 |
| Nonempty text | 1–4096 |
| Ed25519 signature | 64 |

No Unicode normalization is performed. Unicode control characters are rejected
except newline and tab. The content ID is SHA-256 over
`vhalla/room-activity/content-id/v1\0` followed by the exact frame excluding the
signature. The signature covers `vhalla/room-activity/signature/v1\0` followed
by the full content ID. Ed25519 decoding rejects weak keys and verification
uses `verify_strict`. No alternate protocol version or signature fallback is
accepted.

Use a stable network ID pinned independently of peer advertisements. The
mutable node configuration fingerprint is not an activity network ID.

## Verification and durable publication

`SignedEvent::decode` establishes bounded canonical framing only.
`SignedEvent::verify` returns a private `VerifiedEvent` wrapper that attributes
the bytes to the author key. Admission remains separate:

1. Obtain the current local registry through the application's certified replay
   path. A decoded snapshot or a gateway's claimed digest is insufficient.
2. Create an `AdmissionContext` for that immutable view and pinned network. It
   caches the registry digest once per view. This is a local certified frontier,
   not proof that no newer state exists elsewhere.
3. `AuthorChain::prepare_next` checks exact scope, current open policy, and the
   full author sequence/predecessor. It returns a move-only `PendingAdmission`
   without advancing the chain.
4. Atomically persist the signed event, outbox entry, and next author head,
   comparing both the candidate's author base and registry digest against
   current durable state. Serialize policy advancement with this transaction.
   Dropping a candidate after a refused or failed transaction advances nothing.
5. Only after durability succeeds, call `commit_after_persist` with the candidate
   and the current `AdmissionContext`. It rechecks the author base, network and
   exact registry digest and current policy before advancing the local head.
   On any uncertain transaction or stale-base result, reconcile durable state
   before signing another event. A failed in-memory commit does not undo I/O.

The portable crate cannot perform or attest to I/O. `AdmittedEvent` is a local
receipt after the caller reports persistence, not a signed authorization receipt,
quorum certificate, proof of delivery, or proof of current policy.

Chains are scoped by network, realm, directory, full room genesis, and full
author key. Policy changes do not reset them. A changed application key starts
a different chain; no ownership or continuity link is inferred. The caller must
restore the actual durable latest head and must never treat a peer's advertised
high sequence as a trusted floor. `from_receipt` accepts a local committed
receipt; it does not choose the latest receipt or authenticate external storage.
For restart, `restore_local_admitted_head` is an explicit trusted local storage
boundary: the storage owner must tie the exact verified event to its own prior
published admission log/index and actual durable latest head. A signed remote
event alone does not establish that condition. The method checks the expected
full scope/key and restores chain state without minting a new admission receipt
or re-admitting historical policy under today's registry. It cannot prove that
the caller's disk index is complete, current or unmodified.

## History and limits

Store signed activity in separate append-only disk history, with bounded query
pages, pending gaps, outboxes and physical storage admission. This crate owns one
bounded author head and no global archive. Persistence and paging are integration
work outside this crate; cryptographic validity does not entitle a peer to consume
unlimited disk, authors, or pending entries. Refuse new writes explicitly when a
storage budget is exhausted rather than silently discarding history.

Duplicate heads, gaps, competing predecessors and same-position forks are
refused. Older sequences require consulting retained signed history: the bounded
head alone cannot distinguish every old duplicate from an old fork. Use
`VerifiedEvent::conflicts_with` to retain evidence of competing signed events;
arrival order and claimed timestamps never choose a winner. Paging cursors and
local receipts establish neither global history completeness nor finality.

Closed or archived rooms reject new admission. Reopening requires the exact new
policy ID while retaining the same author-chain identity. Historical signatures
remain verifiable after revocation, but neither their claimed time nor an old
local receipt proves that they were globally admitted before the policy changed.
There is no work-execution, reward, moderation, or reputation protocol in this
first text-only version.
