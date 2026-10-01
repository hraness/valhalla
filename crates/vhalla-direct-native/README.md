# Direct native room controller

This crate provides local, custodied direct public rooms. It is a protocol/storage
foundation, not a launched daemon or a network service. It has no transport,
archive activation, account-key recovery, or authenticated peer snapshot protocol.

`RoomSession::create` creates a new pinned genesis and a fresh room author.
`join` verifies an independently chosen full room pin and creates a different new
author. The owner must explicitly add that key before it can post. Ordinary
messages always use the room author; the shared account key signs owner policies
only for a room with intact locally created controller state. Joining with the
owner's account key does not confer that capability.

An absent private home is created with `lock`, `author/`, and `store/`. The room,
author and account custody locks remain held for the session. Open never creates
missing keys or repairs incomplete controller state. The underlying store performs
explicit SQLite recovery on open; ordinary reads do not repair anything.

## Durable operations

Every send and policy change has a nonzero 16-byte operation ID. The controller
durably reserves exact unsigned bytes before calling the typed signer. Retrying
the same intent preserves the original timestamp, sequence and policy; changing
text or writers under an existing operation ID is refused. Each stream allows
one unfinished reservation. Signed bytes, immutable indices and completion are
published atomically. Uncertain writes require reopening the same intact home.

Reconciliation completes exact reservations, including an old-policy event that
must remain continuity-only and be reported as `NeedsRepost`. It never silently
rewrites that text under a new policy. A contradictory owner transition does not
permit rebasing an owner-policy reservation.

Policy observations are retained before another fresh send. Every revision is
compared with the first retained observation, including old and future revisions.
Raw fork evidence remains immutable. Missing seal ancestry preserves the pending
policy fence. Incoming signatures from the local author without matching local
operation history expose lost/cloned custody and disable local authoring. The
corresponding owner-controller anomaly disables owner policy signing.

## History and capacity

Opening a room verifies its complete journal, policy ancestry and active author
chains. While the room is open, sends and incoming records update the verified
state after publication. The controller caches at most 65 author chains: the
current writers and its own author. Removing a nonlocal writer removes its cache.

Each reconciliation pass reads at most 128 signed ancestry frames and commits at
most eight policies. Proof progress survives between calls in memory. Check
`Status::reconciliation_pending` and repeat `reconcile()`; missing frames must be
received before a stalled proof can finish. A policy change can require checking
an existing author's suffix against a newly learned seal or finding its latest
message for that policy. Those checks use the same per-call allowance. Restarting
reconstructs all proofs from the saved records.

Historical message classification checks the original and closing policies and
the exact candidate and terminal IDs through immutable indices. It reuses the
ancestry verified when that closing policy was committed. It does not replay the
room from genesis for each message. These algorithmic limits do not establish
latency or storage performance at the maximum supported history size.

Messages are classified as provisional, owner-sealed, continuity-only or
incomplete. Local retention never means host retention, recipient processing or
global completeness. No peer cursor is implemented here.

Ordinary data leaves 64 records and 256 KiB available for controls and faults.
New sends preflight the complete intent, signed frame, indices and completion
using the actual message size before reserving or signing. `can_send` checks
authority and capacity for a minimum-size message; larger inputs can still exceed
their exact byte allowance.
At the hard store quota, an empty-record publication retains the triggering
authenticated frame in the bounded state image and sets a sticky capacity fence.
Reads and completed exact retries remain available. `expand_limits()` increases
the store allowance in place. It publishes the emergency frame with its indices
and any fork or lost-key evidence before clearing the emergency slot. If the new
allowance is insufficient, that slot stays occupied. Expansion preserves earlier
fork, observation-overflow and lost-key restrictions. Physical storage failure
can still produce an uncertain outcome;
there is no destructive reset or pruning escape hatch.

`records()` is trusted local inspection: it contains unsent reservation text and
operation metadata. Never expose it directly over a network. `replicated_records()`
filters only authenticated signed genesis, policies and events. Its cursor and tip
remain local source positions, and its pages are not signed peer snapshots.
Filtered pages accept an output limit of one to 32 records and scan at most 128
source entries. Continue from `next` even when the filtered result is empty.

## Recovery boundary

Opening retained intact state is supported. An archive, account key, remote
numeric high-water mark, or copied stale controller snapshot cannot establish
safe resumed signing. Archive imports must remain inert; a new live join uses a
fresh author and explicit owner admission. Losing owner-controller state requires
a new pinned room unless a complete exclusive-custody transfer is established.
This crate provides neither transfer nor archive activation. File checksums and
exclusive locks do not detect coherent rollback or a copied signing key.
