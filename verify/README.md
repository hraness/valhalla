# Assurance ledger

Each entry identifies a claim and its limits. Passing one layer does not imply
the deployed system meets the claim of another layer. Tool download hashes live
in `tools.json` and the CI workflow; complete model logs and counterexamples are
retained as CI artifacts. Local evidence for this continuation is recorded in
`docs/production-formal-plan-2026-09-23.md` as the implementation converges.

| Claim | Production correspondence | Evidence | Limits |
| --- | --- | --- | --- |
| Spent-nonce decisions fail closed | `crates/vhalla-native/src/spent.rs` validator, serializer and admission | Kani 0.68.0 in the required Rust gate; full-capacity and restart tests | Symbolic length/admission inputs and entry-byte partitions; codec rounds at 0–2 entries. No BTreeSet/concurrency/filesystem theorem. |
| Linear ledger admission preserves invariants | `vhalla-ledger::Ledger::append` and its caches | `ledger.rs` Verus theorem; sampled `crates/vhalla-ledger/tests/model_conformance.rs` compares vector projection against production maps and snapshot reopen | Verus IDs are abstract; hashing is outside the model. The independently maintained executable projection is testing, not a refinement proof or automatically extracted model. |
| Fetched retryable traffic remains recoverable | Browser `Engine` strict image+retained-item publication, `deferred` metadata and kernel receive/control paths; native staged scan and applied markers | `private-delivery/PrivateDelivery.tla`, positive safety/liveness and capacity-only configs; `browser/tests/private_delivery_engine.rs` future/control/restart regression | Two clients, three identities, finite crash budget. Assumes valid authority, successful atomic storage, eventual transport and sufficient capacity for liveness. No crypto or physical-fsync proof. |
| Duplicate replay cannot repeat an application effect | Kernel exact receive and retained artifact identity | `ExactlyOnce`, mutant-duplicate, kernel and delivery regression tests | The model abstracts exact identity as an integer; byte/signature binding needs real-code tests. |
| A new acceptance cannot let a local membership control overtake older output | Native monotone outbox capture and sender-local control merge | `private-egress/PrivateEgress.tla`, tail-shortcut counterexample and real TLS bounded-backlog regression | Three already-committed local artifacts, one control and capacity one. Checks staging/egress order; does not prove source artifact creation, global delivery order or remote epoch availability. |
| Drained generation cutover preserves pending work, spend and receipt scope | Proposed contract in `docs/private-rotation-contract.md` | `private-rotation/PrivateRotation.tla`, two jobs/two generations, separate durable retention/receipt, frozen predecessor head and three counterexamples | Design evidence only until native/browser/host transition implementation is qualified. Does not model distributed global drain discovery, malicious peers, credential revocation or offline-member availability. |
| Release follows confirmed publication and a final local grant check; drafts retain their roster | `AgentSession::queue`, `authority`, kernel send and storage CAS | `private-publication/PrivatePublication.tla`; existing `agent_pending_cancellation_and_uncertain_commit_conserve_charges`, `agent_authority_expires_or_is_revoked_while_publication_is_pending`, kernel competing-custody tests | Two sessions, one exact operation per session, one roster change, irreversible local revocation. Atomic storage is assumed. Release linearizes at its final grant check; this does not prevent bytes already authorized from arriving later or provide remote instantaneous revocation. No liveness claim. |

## Running and interpreting finite-model checks

```console
python3 verify/run_tlc.py --jar /absolute/tla2tools.jar --java /absolute/java --out /new/owned/evidence-directory
```

The runner checks the pinned JAR digest before execution, uses one worker and
fixed fingerprint/seed settings, and records model/config hashes. It requires
TLC's successful completion for positive cases and the **named invariant**
violation plus a counterexample for mutants. A syntax failure, missing Java,
wrong JAR, timeout or killed run is not success. TLC uses fingerprints, so its
reported collision-probability estimate remains part of the evidence.

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

## Lean comparison decision

The selected near-term targets are concurrency and recovery, for which TLC can
produce short operational counterexamples, plus existing Rust admission checks.
A Lean statement for scalar budget conservation or context preservation would
duplicate an elementary theorem already expressible in Verus while adding a
second correspondence problem to Rust. Defer a maintained Lean toolchain for
this increment. No Lean proof was run or claimed. Reopen the bounded comparison
when there is a stable target requiring mathematical structure or proof reuse
that is materially awkward in the existing stack. Require pinned dependencies,
audited theorem statements/axioms and no `sorry` before accepting Lean evidence.

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
