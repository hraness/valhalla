# Rooms held reply boundary

`RoomsHeldReply.tla` checks one operating rooms host and its sequential
connector. The small configuration contains two distinct request rounds at one
undecided height, one batch that may arrive late or never, and capacity for one
durable proposal-metadata record. The second round can therefore encounter a
full budget while the original evidence remains retained.

The model separates reply custody, selection, durable preparation, adapter
admission, successful reply and network publication. Retained exact bytes may
outlive an adapter pending-map entry: committing earlier heights can prune a
future batch. Preparation must validate and restore its admission before a
local live reply. The model starts with absent confirmed admission at the
current frontier; a real three-height test exercises the preceding pruning.
A selected live value takes precedence over a
deadline that has already passed, matching the implementation. A valueless
expired request or metadata refusal instead returns a reply-only tombstone.
An entire finite, paced parts stream is represented by one `Publish` action;
the host cannot accept the next queued request until that stream drains.

## Source correspondence

Paths below are relative to `crates/vhalla-rooms-node/src/`.

| Action or property | Production boundary | Exercised correspondence |
| --- | --- | --- |
| `Request`, `ReplyCustody` | `unix.rs` `run` / `AppMsg::GetValue`; `HeldReply` retains the oneshot | `formal_held_reply::deadline_unparks_connector_without_another_message` exercises the real loop and subsequent connector progress. |
| `Arrival` | Retained bytes from `App::submit`, `App::register_batch` / `persist_batch`, still available after possible earlier-frontier pruning | `formal_held_reply::late_submit_is_durable_before_reply_and_network_drain` submits after the request is held; the three-height regression retains a future candidate through earlier decisions. |
| `Expire`, `Resolve` | Intake tick; `App::drain_answerable_held` | The deadline test lets an empty request resolve without another consensus message. |
| `Prepare`, `DurableBeforeReply` | `prepare_local_parts` / `App::record_seen`, before successful `reply.send` in `flush_held` or `GetValue` | The late-submit test observes retained batch/seen bytes when the receiver resumes with a backpressured network; `seen_tests::seen_failed_preparation_cannot_release_direct_or_held_reply` separately rejects early send by forcing preparation failure. |
| `Prepare`, `AdmittedBeforeReply` | `prepare_local_parts` checks exact retained identity/bytes and the current frontier, then restores the adapter hold after successful metadata admission | `formal_finalized::local_proposal_restores_exact_candidate_after_earlier_frontier_pruning` commits three planned heights without self-gossip; `refused_local_metadata_does_not_readmit_a_pruned_candidate` checks that metadata refusal cannot add a pending candidate. |
| Capacity refusal | `prepare_local_parts` returns `None`; callers reply with `App::tombstone` | `formal_held_reply::full_metadata_answers_locally_without_publishing` uses the production metadata limit. Model capacity one represents a saturated budget, not a proposed production limit. |
| `Reply`, `Publish`, `TombstonesStayLocal` | `flush_held` and `GetValue` send the reply before `send_part_stream`; only real prepared parts reach the network | Deadline and capacity tests check that the network has no tombstone output; the live test observes real proposal publication. |

The focused Rust tests live in `unix/formal_held_reply.rs` and
`unix/formal_finalized.rs`. They exercise
corresponding schedules in production functions; they are independently
maintained tests, not extracted TLA+ executions or a refinement proof.

## Properties and environmental assumptions

- `ReplyCustody`: every accepted request is owned by the host or successfully
  answered, with no double ownership. The `lost` mutant state exposes a dropped
  empty-queue reply directly.
- `DurableBeforeReply`: every real-value reply follows durable batch retention
  and exact metadata preparation. The model assumes each durable write succeeds
  atomically; it does not establish filesystem durability or crash recovery.
- `AdmittedBeforeReply`: every real-value reply has confirmed adapter admission
  for its valid retained candidate. Durable retention alone is insufficient.
  Within this one-height abstraction admission remains held; this is not a
  claim that committed candidates remain in memory forever.
- `TombstonesStayLocal`: no tombstone has a parts stream published.
- `MetadataBound`: preparation cannot exceed the configured metadata budget.
- `AllRequestsAnswered`: all finitely offered requests eventually receive a
  reply under the stated weak fairness assumptions.

Liveness requires a running host, open reply receivers, eventual deadline
passage, fair request/poll/preparation scheduling, successful storage, a valid
retained candidate when one is selected, and an
eventually draining network consumer for each finite real-value stream. There
is **no fairness assumption on `Arrival`**: a producer need never submit a
batch. The deadline is an eligibility threshold for a later poll, not a proven
wall-clock response bound. Network closure or storage failure terminates the
actual loop; closed receivers can make `reply.send` fail. Those stopped or
cancelled executions are outside the successful operating-host contract.

The model does not cover multiple simultaneous held requests, committed-history
reads, metadata pruning after a decision, exact duplicate metadata retries,
WAL/lock recovery, packet validity or tombstone hash uniqueness. The successful
live preparation step abstracts validation; it does not prove the validator.
Existing tests
for those boundaries remain required. No BFT safety claim follows from this
host-boundary model.

## Mutations and checked examples

| Config | Expected failure | Counterexample prefix |
| --- | --- | --- |
| `mutant-drop.cfg` | Invariant `ReplyCustody` | Accept an empty request and discard its reply. |
| `mutant-early.cfg` | Invariant `DurableBeforeReply` | Accept, receive a batch, select it, reply before preparation. |
| `mutant-tombstone.cfg` | Invariant `TombstonesStayLocal` | Accept, expire, prepare/reply with a tombstone, publish its parts. |
| `mutant-deadline.cfg` | Temporal property `AllRequestsAnswered` | Accept, expire without a batch, then stutter forever while ignoring the deadline. |
| `mutant-unadmitted.cfg` | Invariant `AdmittedBeforeReply` | Retain a valid batch and its metadata, then reply without restoring its adapter hold. |

TLC 1.7.4 reports the four invariant failures with exit 12. The temporal
failure exits 13 and prints `Temporal properties were violated.` without the
property name. `mutant-deadline.cfg` intentionally configures exactly one
temporal property, so its result can be attributed to `AllRequestsAnswered`.
The saved JSON examples retain the original textual states, including the
temporal stuttering step, and bind model/config/tool hashes. They are examples,
not substitutes for freshly executing the required checker cases.

The initial pinned, one-worker run on 23 September 2026 completed the normal
configuration with 58 generated / 46 distinct states, depth 13, all invariants
and conditional liveness passing (exit 0). The drop, early, tombstone and
deadline mutants respectively explored 2/2, 14/11, 25/20 and 25/22
generated/distinct states before their expected completed failures. The normal
run's reported optimistic fingerprint-collision estimate was `3.0E-17`.
After separating admission on 23 September, all six cases completed with the
same normal state counts; `mutant-unadmitted` failed `AdmittedBeforeReply` at
17 generated / 14 distinct states. The saved mutant traces were refreshed for
the changed model and config hashes.

Run focused implementation correspondence from the repository root:

```console
cargo test -p vhalla-rooms-node --all-features --locked formal_held_reply
cargo test -p vhalla-rooms-node --all-features --locked formal_finalized
```

The shared formal runner owns current checker receipts and required case
registration. Never accept a parser error, interrupted run, missing trace or
different property failure as a successful mutation check.
