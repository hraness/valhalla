# Direct public rooms

This crate verifies owner-authorized public rooms independently of the legacy
social-credit and consensus directory. It is a protocol library under development;
it does not provide a daemon, storage, delivery, or a supported end-user workflow.

Room links pin the full signed genesis commitment. Read access is public. The
immutable owner names up to 64 explicit writers, including itself. Display names
and host routes are separate metadata. Messages carry inert UTF-8 text up to
4,096 bytes, with per-author sequence and predecessor commitments. An author’s
timestamp supplies display metadata only.

## Canonical records

Integers are unsigned big-endian. Public keys and IDs are 32 bytes. Lists have a
`u16` count; text has a `u32` byte length. Writers and seal tables are strictly
sorted by full author key, with no duplicates. Signature bytes follow the complete
unsigned frame. The decoder rejects trailing bytes, weak keys, unsupported versions,
oversized lengths, invalid UTF-8, and controls other than newline and tab.

| Record | Magic | Fields after magic |
| --- | --- | --- |
| Genesis | `VHDG\x01` | owner key, nonzero random nonce, writer list |
| Policy | `VHDP\x01` | room ID, owner key, revision, previous policy ID, writer list, seal table |
| Event | `VHDE\x01` | room ID, policy ID, author key, sequence, previous event ID, claimed Unix time, text |

A seal-table entry is `(author key, sequence, event ID)`. Its sequence is positive.
The three signing domains are `vhalla/direct-room/genesis/v1\0`,
`vhalla/direct-room/policy/v1\0`, and `vhalla/direct-room/event/v1\0`.
Each Ed25519 signature covers `domain || unsigned frame`; its content ID is
SHA-256 of the same transcript. Signature representations are excluded from IDs.
The genesis ID is the room ID. The initial policy ID is
`SHA256("vhalla/direct-room/policy-root/v1\0" || room ID)`.

The redundant owner key in a policy is checked against the pinned genesis.
`verify()` establishes a signature; `verify_pin()` additionally establishes the
genesis match and returns the opaque `PinnedGenesis` required by `PolicyState`.

Frozen Rust/Node-compatible vectors are in `vectors/direct-room-v1.txt`. Check the
independent encoder with `bun crates/vhalla-direct-room/tools/vectors.mjs --check`.
Updating those bytes requires an explicit wire-compatibility review.

## Owner policies and history

A policy update replaces the writer list and closes the immediately preceding
policy. It identifies the exact author-chain terminals the owner observed. An
omitted author has no endorsed messages under that closed policy. Earlier seals
remain immutable. An old-policy message beyond its seal stays available as signed
continuity evidence; a later policy cannot turn it into an admitted historical post.

Each declared seal must advance beyond that author’s earlier verified seal and
extend its exact hash ancestry. `PreparedPolicy::push_seal` verifies bounded pages
of additional frames. The terminal must name the policy being closed. Incomplete
proofs prevent policy commit. The current policy state retains at most 4,096 author
anchors, including removed writers; reaching the bound refuses new anchors and
preserves existing history. It does not keep the lifetime policy journal in memory.

On receiving an authenticated newer owner update, the storage controller first
retains it and calls `observe_after_persist`. This blocks fresh admissions while
policy or seal history is missing, including updates received across a gap. A
timeout cannot restore old writer authority. Observations and authenticated fork
evidence must survive restart. `observe_retained_after_persist` fences conflicts
at older retained revisions. Owner forks require operator recovery; this library
does not select a branch automatically.

Unresolved observations retain every revision commitment, including revisions
below the newest observed update. The in-memory budget is 256 unresolved revisions.
Overflow permanently fences that replica until storage rebuilds against all retained
policy evidence; replaying only the remembered subset cannot clear the fence.
Fresh author admission must extend the exact last verified seal. Continuity replay
checks the anchor against the current policy; a chain already beyond a newly learned
seal needs replay to prove that ancestry. This replay never resets local signing state.

Once every declared seal has been verified and persisted, committing the prepared
policy produces an opaque `ClosedPolicy`. Its historical verifier requires the
exact candidate on a contiguous verified chain ending at the owner’s terminal.
A sequence below a numeric cutoff is insufficient. Proof pages are atomic and
contain at most 32 frames. Message ancestry spanning other policies grants only
continuity for those other frames.

Messages under the current policy are provisional. A later owner transition may
exclude concurrent/offline messages absent from its view. Clients retain those
bytes, report `needs-repost` where applicable, and require an explicit new send
under a valid policy. Hosts acknowledge retention; that does not promise owner
finalization or recipient processing.

## Storage integration requirements

The pure state machine cannot attest to filesystem writes. Its caller must:

1. Retain the chosen room pin, every signed policy, author frames, pending updates,
   exact operation reservations, fork evidence and selected-host cursors.
2. Reserve the exact unsigned author bytes durably before signing. Signing new
   text at an uncertain existing sequence is forbidden.
3. Atomically persist signed bytes, the outbox and author head before committing
   the prepared transition. Recheck both author and policy bases under one writer.
4. Import old frames through continuity checks and classify their visibility under
   their own policy. Missing policy or message history remains incomplete.
5. Restore pending-policy fences and all sealed anchors through verified replay.
   A key-only restore never initializes a new sequence-zero author under an old key.

Native storage, authenticated peer snapshots, backup/restore and the headless
runtime must implement these rules before this protocol is enabled for users.
