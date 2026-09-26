# Assurance ledger

Each entry identifies a claim and its limits. Passing one layer does not imply
the deployed system meets the claim of another layer. Tool download hashes live
in `tools.json` and the CI workflow; complete model logs and counterexamples are
retained as CI artifacts. The original private-room evidence is recorded in
`docs/production-formal-plan-2026-09-23.md`; the subsequent tool comparison and
new boundaries are tracked in `kb/plans/valhalla-formal-rigor.md`. Additional
shipping protocols are covered by the
[protocol expansion](../kb/plans/valhalla-protocol-formal-expansion.md).
The [Lean trial](../kb/plans/valhalla-lean-assurance-trial.md) connects
weighted-certificate theorems to signed Rust conformance cases.

| Claim | Production correspondence | Evidence | Limits |
| --- | --- | --- | --- |
| Spent-nonce decisions fail closed | `crates/vhalla-native/src/spent.rs` validator, serializer and admission | Kani 0.68.0 in the required Rust gate; full-capacity and restart tests | Symbolic length/admission inputs and entry-byte partitions; codec rounds at 0–2 entries. No BTreeSet/concurrency/filesystem theorem. |
| Linear ledger admission preserves invariants | `vhalla-ledger::Ledger::append` and its caches | `ledger.rs` Verus theorem; sampled `crates/vhalla-ledger/tests/model_conformance.rs` compares vector projection against production maps and snapshot reopen | Verus IDs are abstract; hashing is outside the model. The independently maintained executable projection is testing, not a refinement proof or automatically extracted model. |
| Distinct weighted quorums share an honest signer; certificates in one signing context agree under honest non-equivocation | `RoomValidatorSet::validate`, both certificate verifiers in rooms-node `cert.rs`, and CLI `quorum` | [Lean weighted-certificate proofs](lean/README.md), audited theorem inventory, generated corpus consumed by both authenticated Rust verifiers | Unbounded mathematics on one fixed roster; assumes authenticated signatures, at most one-third faulty weight and honest non-equivocation in the same context. Rust correspondence is finite testing. Cross-round locking, rotation and cryptography remain separate obligations. |
| Fetched retryable traffic remains recoverable | Browser `Engine` strict image+retained-item publication, `deferred` metadata and kernel receive/control paths; native staged scan and applied markers | `private-delivery/PrivateDelivery.tla`, positive safety/liveness and capacity-only configs; `browser/tests/private_delivery_engine.rs` future/control/restart regression; `private-delivery/delivery.rs` inductive Verus proof of all six safety invariants with proved counterexamples for each mutant and a completion witness | Two clients, three identities, finite crash budget. Assumes valid authority, successful atomic storage, eventual transport and sufficient capacity for liveness. No crypto or physical-fsync proof. The Verus proof strengthens the *model* claims to induction over the instance; production correspondence still rests on the named tests. |
| Duplicate replay cannot repeat an application effect | Kernel exact receive and retained artifact identity | `ExactlyOnce`, mutant-duplicate, kernel and delivery regression tests | The model abstracts exact identity as an integer; byte/signature binding needs real-code tests. |
| A new acceptance cannot let a local membership control overtake older output | Native monotone outbox capture and sender-local control merge | `private-egress/PrivateEgress.tla`, tail-shortcut counterexample and real TLS bounded-backlog regression; `private-egress/egress.rs` inductive Verus proof of `OldBeforeControl` over the same transition system, with a proved mutant counterexample and completion witness | Three already-committed local artifacts, one control and capacity one. Checks staging/egress order; does not prove source artifact creation, global delivery order or remote epoch availability. The Verus proof strengthens the *model* claim from finite enumeration to induction; production correspondence still rests on the named tests, not refinement. |
| Drained generation cutover preserves pending work, spend and receipt scope | Proposed contract in `docs/private-rotation-contract.md` | `private-rotation/PrivateRotation.tla`, two jobs/two generations, separate durable retention/receipt, frozen predecessor head and three counterexamples; `private-rotation/rotation.rs` inductive Verus proof of all six invariants with proved counterexamples for each mutant and a completion witness | Design evidence only until native/browser/host transition implementation is qualified. Does not model distributed global drain discovery, malicious peers, credential revocation or offline-member availability. The Verus proof strengthens the *model* claims to induction over the instance; implementation correspondence remains open as noted. |
| Every selected controller drains generated acceptance output before a conditional mailbox fence and durable successor selection | Transition contract in `docs/private-rotation-contract.md` | `private-generation/PrivateGeneration.tla`, two controllers, one application and acceptance each, an admitted old-writer race, durable intent and crash/reopen; `private-generation/generation.rs` inductive Verus proof of all eight checked invariants over `normal.cfg`, strengthened by six auxiliaries, with each mutant proved to reach a violation and a completion witness | Design model while implementation is being joined. Assumes a trusted complete controller inventory and atomic storage; safety only, with no offline availability or physical durability claim. The Verus proof strengthens the *model* claims to induction over the instance; production-correspondence obligations are unchanged. |
| Release follows confirmed publication and a final local grant check; drafts retain their roster | `AgentSession::queue`, `authority`, kernel send and storage CAS | `private-publication/PrivatePublication.tla`; existing `agent_pending_cancellation_and_uncertain_commit_conserve_charges`, `agent_authority_expires_or_is_revoked_while_publication_is_pending`, kernel competing-custody tests; `private-publication/publication.rs` inductive Verus proof of all three invariants with proved counterexamples for each mutant and a completion witness | Two sessions, one exact operation per session, one roster change, irreversible local revocation. Atomic storage is assumed. Release linearizes at its final grant check; this does not prevent bytes already authorized from arriving later or provide remote instantaneous revocation. No liveness claim. The Verus proof strengthens the *model* claims to induction over the instance; production correspondence still rests on the named tests. |
| An operating rooms host preserves reply custody, durably prepares and admits live candidates, and resolves empty requests | `drain_answerable_held`, `prepare_local_parts`, `flush_held`, `run` in rooms-node `unix.rs` | [Held reply model](rooms-held-reply/README.md); real host-loop tests, forced preparation failure, and a three-height candidate-pruning regression | Two requests at one height, one retained valid batch and one metadata slot. Prior-height pruning is abstracted as absent adapter admission. Progress assumes advancing deadlines, fair host polling, live receiver and eventual network drain. No hard wall-clock deadline, shutdown custody, hash-injectivity, Malachite or filesystem theorem. |
| Sealed host recovery preserves its rollback evidence across repeated interruptions | `recover_seal`, `restore_seal_backups_with`, `remove_seal_scratch` and `load` in private-host `config.rs` | [Host recovery model](host-recovery/README.md), including a counterexample to the former absent-marker cleanup; `formal_host_recovery_*` regressions; `host-recovery/recovery.rs` inductive Verus proof of all six checked invariants over `normal.cfg` and `uncertain.cfg`, with proved counterexamples for each mutant and a completion witness | Two data files plus config/completion, two interruptions, atomic durable replacement assumed. Separates process-visible unlink from durable absence. No physical APFS power-cut proof, mailbox migration or simultaneous-writer theorem. The Verus proof strengthens the *model* claims to induction over the instance; production correspondence still rests on the named regressions. |
| Rooms acknowledgments follow the complete durable frontier; failed finalization preserves WAL custody | `Adapter::open_with`, `reconcile_committed`, `decide`, snapshot `publish` and the rooms-node `Finalized` response | [Rooms frontier model](rooms-frontier/README.md); seven adapter recovery regressions and two real host-loop finalization regressions | Two heights/values, two interruptions, four root-change schedules, one height-1 WAL obligation and one roster transition. Atomic publication and verified replay are assumed; the pinned engine's restart/reset mapping is source-reviewed, not proved. No physical persistence or whole-consensus theorem. |
| Native retries retain exact transport identity, uncertainty and attempt evidence | `DeliveryStore::tick`, outcome publication, `resume` and reopen | [Native delivery model](native-delivery/README.md); existing delivery tests and the real TLS lost-receipt/resume regression | One exact job, two attempts per allowance, one explicit resume, bounded outages/crashes and one precommit outcome refusal. Atomic local publication is assumed; postcommit barrier/readback failure, delivery liveness, cancellation and re-encryption are outside this model. |
| Relay retention and quota charges publish together; exact retries preserve position and original charge ownership | Relay store PUT transaction, TLS service storage quotas and stable credential ID | [Relay quota model](relay-quota/README.md); the compound TLS regression reopens both stores, replaces a token and reconciles the original mailbox position | Two items, two credential IDs, four requests and two interruptions. Process restart and SQLite atomicity are modeled; no physical power-loss, concurrent writers or rate-window theorem. |
| Owner handoffs retain historical authority and uncertain fork publication preserves quarantine custody | Kernel `owner_device_at`, succession checks, control observation, storage publication and reopen | [Private control model](private-control/README.md); real A→B→A and storage-fault succession tests | Two devices, four control slots, two handoffs and bounded new-process reopens; ordinary and late-join histories. Valid signatures and atomic storage are assumed. No MLS, disconnected-replica agreement, dead-owner recovery or observation persistence after a refused write and process loss. |
| Confirmed contact admission uses one unchanged worker review and rejects stale custody | Browser `Admission::review`, `before`, `confirm`, Session dispatch and kernel storage CAS | [Retained-admission model](private-admission/README.md), eight safety mutants, successful-publication witness and production Admission/Kernel regressions; `private-admission/admission.rs` inductive Verus proof of all seven checked invariants with proved violation traces for each mutant and a completion witness | Two worker lifetimes and reviews, two items, one membership change and rival publication. Atomic storage and authenticated decoding assumed. Expiry is checked at the captured confirmation time; no physical publication deadline, cryptographic proof or liveness claim. The Verus proof strengthens the *model* claims to induction over the instance; production correspondence still rests on the named regressions. |

## Running and interpreting finite-model checks

```console
python3 verify/run_tlc.py --jar /absolute/tla2tools.jar --java /absolute/java --out /new/owned/evidence-directory
```

The versioned [`cases.json`](cases.json) inventory declares every model/config,
expected result, claim, bounds, assumptions and production/contract sources.
An unlisted model or config, duplicate registration, escaping/symlink path or
undeclared expected property fails before checking. Source-symbol descriptions
are review aids, not a mechanically checked refinement relation.

The runner checks the pinned JAR digest before execution, uses one worker and
fixed fingerprint/seed settings, and runs copied model/config bytes. Receipts
bind runner, manifest, tool metadata, models, configurations and listed source
files; they retain actual commands, elapsed times, state counts and full log
hashes. A changed input or inventory invalidates the run. A successful receipt
requires every declared case to complete as expected. Historical saved traces
are documentation and can never substitute for a missing current trace.

Positive cases require successful completion and state statistics. Invariant
mutants require the **named invariant**, exit 12 and a structurally complete
counterexample. TLC 1.7.4 does not name a violated temporal property, so temporal
mutants must declare exactly one property and return exit 13 with the temporal
diagnostic and a stuttering/cycle witness. A syntax failure, missing Java,
wrong JAR, malformed trace, timeout or killed run is not success. TLC uses
fingerprints, so its reported collision-probability estimate remains part of
the evidence. Run the runner's boundary tests without downloading tools:

```console
python3 -m unittest discover -s verify -p 'test_*.py'
```

The normal delivery run on 23 September explored 1,444 distinct states and
checked conditional eventual resolution. Capacity one explored eight states
with safety only; exhaustion can prevent progress without losing custody.
The proposed rotation contract explored 61 distinct states. Publication explored
688 distinct states. Bounded sender egress explored seven distinct states. Ten mutations
failed as expected. Generated state traces are retained under each model's
`counterexamples/` directory. Their `tlc_text` preserves the original checker
state representation: TLC 1.7.4 does not provide the newer JSON trace option.

The delivery counterexample's Fetch→PublishFetch-with-drop sequence maps to
the old browser future-epoch `Skip`. The real regression extends that prefix
with restart and the missing owner control, then verifies one exact receive
and retained acceptance. Replaying the mathematical trace does not itself
execute MLS or IndexedDB; the real-adapter tests remain independently required.

The egress counterexample sends old item 1, stages a new-epoch receipt directly
into the freed queue slot, then sends the control while old item 2 remains
uncaptured. The real TLS regression uses a longer precommitted backlog and a
one-job queue. Receipt issuance now records durable kernel output; only monotone
catch-up stages that output for transport. This model assumes those source
artifacts already exist; the integration test supplies that correspondence.

The held reply model adds a liveness counterexample: with deadline resolution
disabled, the connector can stutter forever awaiting its reply even though no
producer supplies a batch. The other mutants drop custody, reply before
retaining exact metadata, omit adapter admission, and publish a tombstone. Production regressions drive
actual `run`/oneshot/network channels with a late submission, deadline-only
resolution and a full metadata budget. The live-value test observes retained
data when its receiver resumes; the independent forced-write-failure test is
what rejects sending before synchronous persistence. These tests and source
review establish correspondence evidence, not automatic trace extraction or
a Rust refinement proof.

Broader rooms validation exposed a separate gap between durable retention and
decision readiness. Committing earlier heights pruned a future batch from the
adapter, while its bytes remained available for a local proposal. Because
self-gossip does not run through remote admission, that proposer could reject
its own later decision. Local preparation now validates and restores the exact
candidate after metadata admission. The three-height regression reproduces the
failure without network timing; a full-budget case checks that refused
preparation cannot add a hold. The held-reply model's separate admission state
and mutant preserve this distinction.

The host model distinguishes process interruption from power loss. It exposed
the former cleanup sequence: unlink marker, stop before the directory fence,
retry with no visible marker, delete a backup, then lose power while the marker
can still reappear. Cleanup now fences the directory even when the marker is
already absent. A deterministic sync-failure regression checks that this fence
must succeed before any backup is deleted. The counterexample demonstrates a
missing ordering guarantee under conservative metadata persistence assumptions;
it is not a reproduction of physical disk loss. Additional schedules cover
interrupted restoration, corrupt evidence and whole-snapshot admission.

The rooms frontier expansion reproduced three adapter defects with real
canonical journal and snapshot writes: root-preserving batches could be
acknowledged before their full frontier advanced, independently inferred
snapshot heights could refuse an honest social-only interruption, and changed
snapshots could be admitted beneath an empty journal. Recovery now selects a
jointly compatible prefix and applies each remaining full frontier. Separate
host-loop tests reproduced failed finalization requesting a same-height engine
restart, which resets the WAL in the pinned engine. Failure now withholds that
response; successful finalization uses the actual next height's validator set.
The model's `HonestRecovery` property checks recovery state before successful
admission, so a stuck or incorrectly refused honest recovery cannot hide behind
the final equality guard. Its source map and mutants distinguish these repaired
defects from deliberately introduced future-regression checks.

Native sender attempts and relay storage charges have different meanings. An
attempt intent becomes durable before transport; a durably classified outage
restores its attempt charge while retaining uncertainty and outage evidence.
Explicit resume grants a new allowance while accumulating previous spend.
At the relay, an exact duplicate keeps its original position and charge owner,
even after a token changes under the same stable credential ID. The compound
TLS trace crosses both boundaries: it loses a successful PUT completion,
reopens, exhausts and resumes the sender, then receives the original position
without renewed relay quota. The two models keep these accounting rules
separate.

The private-control model derives the signer for a control sequence from
accepted handoff history, including the predecessor signature on the carrying
handoff itself. Observation compares evidence and cannot advance accepted
authority. Unknown precheckpoint history cannot establish a fork, while a
known conflicting historical proof can. Interrupted fork publication blocks
live work until recovery; once quarantine is durable, reopening retains it.
The runtime tests distinguish a refused write whose volatile observation is
lost with the process from a committed fault whose completion was lost.

## Lean comparison decision

Lean has a maintained trial for weighted certificates, alongside TLA+ for
protocol interleavings and recovery. The
[initial assessment](../kb/plans/valhalla-formal-rigor.md) kept its small Lean
experiment optional. The [subsequent trial](lean/README.md) adds an identity-aware
proof, authenticated Rust conformance tests and a required CI check so its
usefulness and upkeep can be evaluated in the repository.

| Approach | Best fit here | Evidence and upkeep | Decision |
| --- | --- | --- | --- |
| TLA+/TLC | Reply custody, protocol ordering, interrupted recovery, conditional progress | Finite-state exploration with operational counterexamples; maintain abstraction, bounds, fairness and production regressions | Expand the existing required gate. |
| Lean | Unbounded mathematical statements about weighted signers and certificate agreement in one context | Kernel-checked theorems, audited assumptions and generated cases tested against Rust; separate toolchain and correspondence upkeep | Maintain the narrow weighted-certificate trial in required CI. |
| Verus | Unbounded Rust-shaped admission invariants | Existing ledger model and sampled production correspondence; reference-model abstraction still needs review | Retain; compare the same theorem here before claiming Lean superiority. |
| Kani plus Hegel/property tests | Symbolic production decisions and real storage/restart sequences | Kani has tractability and input bounds; tests sample histories and exercise actual adapters | Preserve as complementary evidence. |

The identity-list proof connects the sum over known, distinct signer identities
to the sum selected from a unique weighted roster. It supports an honest common
signer theorem and certificate value equality when both certificates use the
same context and honest signers sign only one value there. Concrete witnesses
show why the quorum, fault and signing assumptions are needed. The source map,
tool pins, measured costs and reproduction commands live with the
[proofs](lean/README.md).

This trial establishes a use for Lean in Valhalla without comparing its cost to
an equivalent Verus implementation. TLA+, Verus and Kani keep their existing
claims. The Lean result and the finite Rust comparisons remain distinct evidence;
neither establishes an end-to-end consensus proof.

Tool semantics are documented by the [TLA+ tools reference](https://lamport.azurewebsites.net/tla/tools.html),
[Lean proof validation](https://lean-lang.org/doc/reference/latest/ValidatingProofs/)
and [Verus guide](https://verus-lang.github.io/verus/guide/). The recommendation
above is a repository-specific assessment, not a claim that one tool is
universally stronger.

## Remaining trust boundaries

The TLA+ actions abstract storage transactions as atomic; interruption tests
must justify that abstraction for native SQLite and real IndexedDB. Models do
not replace authority checks, packet codecs, MLS/signature review, actual
grant-revocation boundaries, migration compatibility, OS isolation or physical
host qualification. Fair scheduling is not guaranteed availability during
permanent partition, missing control, exhausted storage, expired authority or
unbounded hostile traffic. Archived ratchets remain read-only.

The formal workflow is called by the complete Rust gate and required by its
aggregate, including release validation. Consequently production changes rerun
the models even when no proof file was edited. A model that still passes after
production changes can still be stale: review the correspondence table and run
the adapter/conformance tests, and add a counterexample for each newly found
failure mode.
