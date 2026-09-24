# Rooms durable frontier

This finite safety model separates the decided journal, durable social and
rooms snapshots, the complete application frontier, acknowledgment, and the
host's finalization response. It models two committed heights with two possible
value identities, two process interruptions, and a roster change at height 2.
Snapshot roots may repeat across heights. Height, value, agreed time and control
remain part of the full frontier even when both roots stay unchanged.

## Production correspondence

| Model boundary | Production boundary | Real regression evidence |
| --- | --- | --- |
| `JournalCommit`, `PublishSocial`, `PublishRooms`, `Apply` | `Adapter::decide`, `publish`, `reconcile_committed` in `crates/vhalla-rooms-consensus/src/lib.rs` | `formal_recovery_changed_snapshots_redeliver_from_each_publication_cut` publishes actual canonical journal bytes and zero, one or both snapshot stores. |
| `Redeliver`, `AckHasFullFrontier` | `committed_at`, `reconcile_committed`, `Application::apply_locally` | `formal_recovery_empty_clock_batch_redelivery_applies_full_frontier` crosses a control expiry without changing either root; `formal_recovery_game_batch_redelivery_preserves_order_and_identity` checks the same frontier rule for game-only batches. Both exercise exact retries and committed-identity conflicts. |
| `CompatiblePrefix`, `LoadPrefix`, `RecoveryReady` | `Adapter::open_with` selects a joint snapshot prefix, replays every remaining height, and checks the journal's final frontier commitment | `formal_recovery_reopen_accepts_social_only_publication_cuts` and `formal_recovery_reopen_accepts_changed_and_root_preserving_history` exercise ambiguous root matches and repeated reopen. |
| `PublicationOrder` | `Adapter::publish` commits social before rooms | `formal_recovery_reopen_refuses_rooms_ahead_of_social` rejects the opposite snapshot order. `formal_recovery_reopen_refuses_snapshots_ahead_of_empty_journal` additionally checks foreign snapshots at genesis; corrupt input admission is outside this model's honest-cut state space. |
| `HostFailure`, `EngineRestart`, `FailedFinalizationKeepsWal` | `AppMsg::Finalized` in rooms-node `unix.rs`; pinned Malachite maps `Next::Restart` through `RestartHeight` to a WAL reset | `unix::tests::formal_finalized` sends actual host messages with real signed certificates and requires failed `Decided`/`Finalized` reply channels to close without a start or restart request. The modeled engine consequence is a source-traced assumption, not a Malachite proof. |
| `HostSuccess`, `NextRoster` | Successful `Finalized` replies with `Next::Start(height + 1, height_params(set_for(height + 1)))` | `withheld_finalization_preserves_frontier_and_retries_with_next_roster` and `rejected_finalization_preserves_frontier_and_retries_with_next_roster` repair/admit the fixture, retry and verify the next-height roster and exact retained decision. |

Adapter tests live in `crates/vhalla-rooms-consensus/src/formal_recovery.rs`.
Host tests live in `crates/vhalla-rooms-node/src/unix/formal_finalized.rs`. The
host's withheld fixture is an actual journal read failure before commit; the
adapter tests provide the separate post-publication cuts. Neither simulates a
physical power failure.

`Cargo.lock` binds both external crates to Malachite revision
`72143f6c99a98452b587e1c392bdb80944eb2232`. At that revision, the
[application connector](https://github.com/circlefin/malachite/blob/72143f6c99a98452b587e1c392bdb80944eb2232/code/crates/app-channel/src/connector.rs#L196)
waits for decided and finalized replies in separate tasks; a missing decided
reply does not prevent a later finalized request. The
[engine response mapping](https://github.com/circlefin/malachite/blob/72143f6c99a98452b587e1c392bdb80944eb2232/code/crates/engine/src/consensus.rs#L1604)
turns `Next::Restart` into `RestartHeight`, whose
[restart branch](https://github.com/circlefin/malachite/blob/72143f6c99a98452b587e1c392bdb80944eb2232/code/crates/engine/src/consensus.rs#L482)
resets the WAL and starts with empty replay entries. These are the exact source
assumptions behind `EngineRestart`.

## Cases and counterexamples

| Config | Expected result | Meaning |
| --- | --- | --- |
| `normal.cfg` | All invariants pass | Height 1 changes both roots; height 2 preserves both. |
| `root-preserving.cfg` | All invariants pass | Both committed heights preserve both roots. |
| `social-only.cfg` | All invariants pass | Height 1 changes only social; height 2 preserves both. |
| `two-changing.cfg` | All invariants pass | Both heights change both roots, exercising distinct second-height publication and historical acknowledgments. |
| `mutant-roots-only.cfg` | `AckHasFullFrontier` fails | Commit an empty batch, fail before application, redeliver it, and acknowledge by roots alone while the full frontier remains stale. |
| `mutant-early-ack.cfg` | `AckAfterDurability` fails | Acknowledge a selected decision before journal publication. |
| `mutant-identity.cfg` | `CommittedIdentity` fails | A conflicting redelivery overwrites a previously committed value identity. |
| `mutant-failed-restart.cfg` | `FailedFinalizationKeepsWal` fails | Return `Next::Restart` after a withheld decision; the modeled engine consumes it and resets still-required height-1 vote/lock evidence. |
| `mutant-next-roster.cfg` | `NextRoster` fails | A successful height-1 finalization starts height 2 with height 1's roster. |
| `mutant-publication-order.cfg` | `PublicationOrder` fails | Publish changed rooms state before the corresponding social evidence. |
| `mutant-independent-roots.cfg` | `HonestRecovery` fails | After a social-only journal commit and interruption, unchanged rooms root appears to be height 1 while unchanged social is height 0; independent latest-match inference refuses the honest cut despite compatible joint prefix 0. |

The roots-only acknowledgment and independent-root recovery mutations reproduce
the ordering mistakes repaired by the corresponding Rust regressions. The
failed-finalization mutation models the source-traced effect of the previous
host response. The other mutations are deliberate protections against future
regressions, not claims that those defects were found in production.

`HonestRecovery` checks the state *before* the `RecoveryReady` equality guard:
every reachable `recovery-check` state must already contain the full journal
frontier and matching snapshots, and no honest cut may enter `blocked`. This
prevents a stuck or refused recovery from passing merely because it never
records a successful reopen. There is no scheduling liveness claim.

## Assumptions and limits

- A journal commit atomically and durably binds the exact ordered batch and
  certificate identity. Successful individual snapshot publications are atomic
  and durable. The model does not prove journal recovery, filesystem barriers,
  physical power-loss behavior or snapshot-store internals.
- Upstream cryptographic certificate checking and deterministic batch replay
  are assumed. Value/root symbols stand for exact identities; neither hash
  injectivity nor full Byzantine consensus is established here.
- The root labels can repeat when state is unchanged. Changed roots are fresh
  in these configurations; a later transition returning to an older distinct
  snapshot root is outside the bound. The whole frontier includes additional
  metadata rather than treating root equality as height equality.
- `LoadPrefix` nondeterministically considers every compatible joint prefix;
  production searches from the newest prefix downward. This explores more
  choices but does not prove the Rust search or replay implementation.
- Interruptions discard memory and preserve previously durable boundaries.
  There is one sequential adapter owner and at most one in-flight decision
  ahead of its applied frontier before interruption. Interrupted memory resets
  to genesis, so recovery may reconstruct both retained heights. There is no
  concurrent mutation of committed history.
- WAL custody concerns one retained height-1 vote/lock set. Successful
  application acknowledgment may release it; a failed finalization may not.
  The model does not implement Malachite, WAL replay, vote locks or later-height
  anti-equivocation. The next-height roster check concerns the host reply.
- A receipt from TLC establishes only these bounded transitions and
  invariants. Production correspondence comes from source review and the real
  Rust regressions, not a machine-checked refinement relation.

## Validation

On 23 September 2026, the focused development run explored 9,349 distinct states
for `normal`, 11,313 for `root-preserving`, 11,415 for `social-only`, and 16,289
for `two-changing`. All seven mutants exited 12 and violated exactly their named
invariant. Each case took less than three seconds with one worker, a 512 MiB
heap, fingerprint index 0 and seed 1. These counts describe this checked
model/configuration, not future runs.

The checked-in `counterexamples/` JSON files retain full ordered current-run
state traces and model/config/tool hashes. They are explanatory artifacts;
the complete repository runner must produce fresh evidence for the entire
manifest and never uses these files as a current verdict.

Run the repository's pinned inventory runner as documented in
[`../README.md`](../README.md). Relevant Rust checks are:

```console
cargo test --locked --all-features -p vhalla-rooms-consensus formal_recovery
cargo test --locked --all-features -p vhalla-rooms-node formal_finalized
```
