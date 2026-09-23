# Activity append-log prototype (E-2 spike)

A bounded, standalone design model for performance-review recommendation E-2:
replace the v1 room-activity store's per-record `records/` files, per-author
`authors/<author>/<seq>` heads, and `HEAD`/`intent.tmp` lifecycle with one
fixed-name append-only log plus a double-slot head. It is a measured spike,
not production code — it proves the barrier count, the recovery cases, and
the bounded page read that a full port requires, and it documents the gaps
that keep E-2 out of the shipped store for now.

Run it:

```sh
cargo test --offline                          # protocol and recovery tests
cargo run --release --bin bench -- /tmp/vaal-N 1000
```

## Layout

All names are fixed at creation; nothing is created, renamed, or removed
afterward, so no directory barrier is ever needed in steady state.

| File     | Role |
|----------|------|
| `format` | 8-byte marker (`VAAL\x02`); foreign markers are refused like the consensus WAL `VRW2` marker. |
| `lock`   | Lifetime exclusive lock (`File::try_lock`), writers only. |
| `log`    | Append-only entry file. |
| `index`  | Derived ordinal→offset table, 16 bytes/entry; never synced, never authority, rebuilt and re-verified at open. |
| `HEAD`   | One 8 KiB file, two 4 KiB slots written by `pwrite` at 4 KiB alignment. |

Entry framing:

```
[u32 body_len][kind=1][ordinal u64][author 32B][sequence u64]
[expected_count u64][expected_tail 32B][cumulative_bytes u64]
[payload_len u32][payload][sha256(body)]
```

Head slot (4096 bytes, hash-verified):

```
[generation u64][count u64][bytes u64][tail 32B][log_len u64]
[author_count u16][author table: (author 32B, seq u64, ordinal u64) xN]
[zero pad to 4064][sha256(slot[..4064])]
```

The writer alternates slots by generation parity; the reader takes the
highest-generation slot whose hash verifies, so a torn slot write can only
produce the old or the new complete head. With no valid slot the head falls
back to genesis — safe because genesis can never contradict committed state:
the committed entries simply re-present as retained intents and re-complete
idempotently. (A production port could instead surface `Corrupt` on nonzero
invalid slots and retain the evidence for an explicit decision; both
behaviors are defensible and the spike picks the self-healing one.)

## Barrier ledger

Steady-state append is two `F_FULLFSYNC`-equivalent calls:

1. write log entry → `sync(log)` — the intent-before-effect boundary;
2. write index entry (no barrier — derived cache), `pwrite` head slot →
   `sync(HEAD)` — the acknowledgement boundary.

versus the shipped v1 path's twelve after E-1 (intent file, directory,
record file, record directory, author head file, author directory, global
head, root directory, plus retained-intent re-syncs on recovery). The bench
prints `sync_calls`, which the tests pin at exactly 2 per append.

## Intent-before-effect

An entry durable past `HEAD.log_len` *is* the retained intent — the same
role `intent.tmp` plays in v1, without a rename. Open classifies the tail
once: a complete hash-valid frame continuing the head is pending intent
(complete it or leave it, never rewrite it); a non-parseable tail is torn
evidence that refuses appends and reads until `recover()` resolves it —
the spike truncates it on explicit recover, the documented analogue of v1
discarding a torn `intent.tmp`. Only the first valid tail frame is claimed;
further frames become pending on the next open, in order.

A same-admission retry while an intent is pending completes it exactly
once and returns the same receipt; a different admission refuses
`RecoveryRequired`. `(author, sequence)` retries reconcile against the
retained record and conflict on different bytes.

## Bounded reads

`read_page(after, limit)` serves at most `MAX_PAGE` (64) records by ordinal
through the rebuilt index — `pread` at the recorded offset, frame decoded,
hash re-verified, tail cross-checked — never a lifetime enumeration. The
index file is never synced: it is rebuilt from the authoritative log prefix
at every open, which is `O(history)` — the production gap below.

## What the spike proves

- 2 barriers per append steady state (pinned by
  `steady_state_append_is_two_barriers`).
- Retained intent completes once; exact retry idempotent
  (`retained_intent_completes_once_and_exact_retry_is_idempotent`).
- Different intent refused and preserved
  (`different_intent_is_refused_and_preserved`).
- Torn tail retained until explicit recovery
  (`torn_tail_is_retained_then_discarded_by_explicit_recovery`).
- Torn live slot falls back to the previous complete head
  (`torn_live_slot_falls_back_to_previous_complete_head`).
- Both slots lost → genesis fallback, intents re-complete
  (`both_slots_lost_fall_back_to_genesis_and_intents_recomplete`).
- Foreign format marker refused; gap/dedup/page bounds hold.

## Why production adoption stays deferred

The spike deliberately excludes the parts of the v1 contract that make a
format change expensive:

- **Signed records.** v1 stores canonical signed record envelopes and
  verifies once per record (E-18). The spike carries raw payloads; a port
  must embed the signed envelope in the frame (or add a signature segment
  to the entry) without re-verifying on the hot path.
- **`O(history)` open.** Every open re-scans the log prefix the head names.
  Production needs a checkpoint or a trusted index epoch so open stays
  bounded; alternatively the index file gains its own hash chain and is
  trusted after a spot audit.
- **Author table bound.** `MAX_AUTHORS` = 71 fits the slot; beyond it the
  review's fallback is per-author slot files (one extra barrier each). The
  real store must decide whether rooms can exceed that bound and what the
  overflow path costs.
- **Bounded-history retention.** v1 keeps bounded history via cleanup
  steps after head commit. An append-only log needs a compaction/checkpoint
  protocol — new head naming a truncation point, a second log generation,
  and a directory barrier — none of which the spike implements.
- **Migration.** The production store must read-or-refuse existing v1
  homes, keep retained v1 intents completable, and never destroy evidence
  during an upgrade. That is a one-way format gate, not covered here.
- **Full crash matrix.** The production `Step` table plus Hegel command
  sequences must be ported to the new protocol points (`EntryWritten`,
  `EntrySynced`, `IndexWritten`, `HeadSlotWritten`, `HeadSlotSynced`)
  before any adoption; the spike's six unit tests are the shape of that
  matrix, not the matrix itself.
- **Reader semantics.** v1 readers never repair; `read_page` here already
  refuses during recovery, but the shared-reader hold and verified
  snapshot contract must be preserved in the port.

Given the remaining surface, E-2 lands as this spike only; the production
append path keeps the E-1-optimized v1 layout at 12 barriers.
