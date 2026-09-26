# Formal verification

Valhalla combines production Rust checks, a verified reference model, finite
protocol models and real-adapter tests. Each supports a named claim; none
establishes that the complete deployed system is verified. The maintained
[assurance ledger](../verify/README.md) maps claims to production code,
assumptions, regressions and evidence boundaries.

## Kani bounded model checking

`#[cfg(kani)]` harnesses live next to the code they check. They prove
properties over *every* symbolic input within an unwind bound — stronger than
property tests, which sample, but bounded: nothing is claimed beyond the
bounds written in each harness.

| Crate | Harnesses | Properties proven |
| --- | --- | --- |
| `vhalla-journal` | `mod proofs` in `src/lib.rs` | `Bundle::decode` rejects inputs past the scratch bound without panicking |
| `vhalla-native` | `src/spent.rs` | Symbolic length/admission decisions, byte validation over lengths 0–68 via partitions, and codec round trips for 0–2 nonzero sorted entries |

Ledger admission invariants (tip advance, atomicity, per-actor monotonicity, duplicate and capacity rejection) are handled in the unbounded Verus model below. The journal Kani proof checks that the bundle decoder rejects oversized inputs without panicking. Bounded Kani harnesses on the production `BTreeMap<EventDigest, Event>` implementation proved intractable on this toolchain: CBMC unwinds the standard-library `find_key_index` and node-scan loops far beyond a useful bound even for one- or two-element maps, so the trade-off favors the Verus abstraction for admission logic and a small, fast Kani check for the self-contained codec.

The journal Kani harness is intentionally not run in CI: CBMC is too slow and
resource-hungry to complete on GitHub's free runners within an acceptable
PR gate. Run it locally when the decoder surface changes:

```console
cargo install kani-verifier --locked   # once; then cargo kani setup
cargo kani -p vhalla-journal -j --output-format terse
```

The separate spent-nonce pilot **is required by CI** and pins Kani 0.68.0:

```console
cargo kani -p vhalla-native --output-format terse -Z unstable-options --harness-timeout 300s
```

Its production capacity stays 1,024. Admission accepts membership as an input;
this does not verify BTreeSet membership, a 1,024-entry codec execution,
concurrent redemption or filesystem durability. Full-capacity tests and Hegel
restart/fault tests remain required. Timeout or unsatisfied cover is not success.

## Verus functional verification

`verify/ledger.rs` is a self-contained verified model of the ledger admission
machine — ids are `u64` stand-ins for digests and the retained event set is a
vector (the production `BTreeMap`s are caches over it), while the transition
function applies the same checks in the same order as `Ledger::append` and
fails closed. It is a reference artifact: the production code stays idiomatic
and the model stays provable.

Proven with no bounds assumed: append-only growth, linear parent chain,
distinct ids (no double admission), strictly increasing per-actor sequences,
capacity, and atomic rejection — `13 verified, 0 errors`.

Run (needs rustup with toolchain `1.98.1`, then the matching Verus release):

```console
verus --crate-type=lib verify/ledger.rs
```

The pinned binary is `verus 0.2026.09.13.671956e` (release tag
`release/0.2026.09.13.671956e`, bundles `verus-…-arm64-macos.zip` /
`verus-…-x86-linux.zip`) on rustup toolchain `1.98.1`.

CI verifies the tool's release-asset SHA-256 before executing it. The formal
workflow is now part of the complete Rust aggregate, including tag-release
validation, so a production-only edit cannot bypass it. The sampled
`model_conformance` ledger tests compare the model's vector admission discipline
with production maps and snapshot reopening; this is not a general equivalence
proof and remains a separately maintained executable projection.

A second Verus use translates an existing TLA+ model rather than production
code: `verify/private-egress/egress.rs` re-states `PrivateEgress.tla` as a
transition system and proves the safety invariant inductively, with machine-
checked mutant counterexample and reachability witnesses. Unlike the ledger
model it proves a *specification*, so it adds nothing about implementation
correspondence; what it buys is that the finite-instance model-checking claim
becomes a proof over every execution of that instance.

```console
verus --crate-type=lib verify/private-egress/egress.rs
```

## TLA+ finite protocol checks

`verify/private-delivery` explores durable deferred items, out-of-order control
dependencies, duplicate retries and interrupted fetch/publication. Its normal
configuration includes two clients, three items and one crash per client;
conditional liveness assumes available storage/transport, sufficient deferral
capacity, valid authority and fair scheduling. The capacity-one configuration
checks safety only: bounded storage can prevent reaching a missing dependency.

`verify/private-rotation` checks a proposed drained cutover contract. This is
design evidence; it does not claim the current host/client implementation
already supports that transition. Its mutations expose orphaned pending jobs,
reset spent accounting and receipts relabeled to another namespace.

The same transition system is proved in Verus in
`verify/private-rotation/rotation.rs`: all six checked invariants
(`TypeOK`, `NoOrphans`, `PreservedSpend`, `BoundReceipts`, `Conservation`,
`FrozenHead`) are inductive over `normal.cfg`'s `Next`, strengthened by three
auxiliaries (preparation implies drained and fenced, and no job carries a
future generation). Each mutant configuration is proved to reach a violation
of the invariant TLC reports for it, and a completion witness reaches the
post-cutover state with both jobs retained. This remains design evidence for
the contract; it strengthens the model claims from finite enumeration to
induction but says nothing new about implementation correspondence.

`verify/private-generation` covers the staged generation transition separately:
complete controller inventory, a common drained head, durable pause, conditional
fencing, durable successor intent, retained history and cumulative spending. Six
mutations omit a controller, ignore a changed head, skip generated acceptance
work, select without an intent, reset spending and discard the archive. It checks
finite safety; actual storage fault tests and native/browser journeys are
required to connect it to production behavior. It does not establish that an
offline participant becomes available or that a physical inventory is complete.

`verify/private-publication` explores two competing sessions, a roster-bound
draft, cancellation before/after commit, exact retained recovery, readback and
local revocation. Release linearizes at the final successful authority check;
it does not promise that previously authorized bytes cannot arrive later.
The three mutations release before confirmation, retarget a stale draft and
ignore revocation. Native pending-publication and competing-custody regressions
remain necessary to justify the model's atomic-publication abstraction.

The same transition system is proved in Verus in
`verify/private-publication/publication.rs`: `ConfirmedOutput`,
`DraftBinding` and `AuthorizedOutput` are inductive over `normal.cfg`'s
`Next`, strengthened by four auxiliaries (ready/done implies confirmed,
released implies done, revision equals stored count plus roster, and a stored
session never re-enters a pre-publication phase). Each mutant is proved to
reach its recorded violation — early release breaks `ConfirmedOutput`,
retarget breaks `DraftBinding`, revocation-breaking release breaks
`AuthorizedOutput` — and a completion witness runs the full safe lifecycle.
This strengthens the model claims from finite enumeration to induction; it
changes nothing about the production-correspondence obligations above.

`verify/private-egress` checks sender-local order with three committed artifacts,
one membership control and one queue slot. Its mutation stages a new receipt
past the monotone capture frontier, allowing the control to overtake an older
application. The real TLS backlog regression exercises that defect in native
delivery. The model assumes source artifacts exist and does not establish
global message order, remote availability or source-publication correctness.

The same transition system is also proved in Verus in
`verify/private-egress/egress.rs`: `OldBeforeControl` is inductive over the
normal configuration's `Next` once two auxiliary invariants are added
(nothing staged or retained exceeds the capture count; a captured item is
never dropped before retention). The proof additionally checks that the
`TailFastPath` mutant genuinely reaches a violation and that the safe model
reaches the completed cutover — the proof-side analogue of the suite's
counterexample and reachability controls. This lifts the safety claim for
this model from finite enumeration to induction; the correspondence to
production is unchanged and still rests on the named regression tests.

`verify/rooms-held-reply` checks the rooms node's sequential connector boundary:
preserved oneshot custody, durable preparation and confirmed candidate admission
before a real reply, reply-only
tombstones, bounded metadata admission and eventual deadline resolution under
explicit scheduling/network assumptions. Its deliberate failures include a
temporal counterexample that leaves an empty request waiting forever. The
real host-loop tests use actual channels and synthetic stores, and the existing
forced-persistence-failure regression checks the send ordering. A three-height
regression exercises a retained future batch pruned from the pending adapter;
local preparation must restore it before replying. A separate mutant omits
that admission while preserving durable metadata. This is not a
hard real-time guarantee or a proof of Malachite consensus.

`verify/host-recovery` checks sealed maintenance and repeated recovery with
process interruption distinguished from power loss. The model found that a
retry after an unsynced marker unlink could skip the pre-cleanup fence; the
implementation now syncs before deleting backups even when no marker is visible.
Its regression injects a failed directory sync and requires every backup to
remain. Other cases challenge consumed backups, premature cleanup and admission
using only matching config/completion files. Atomic durable replacement remains
an assumption; these checks do not simulate physical filesystem power loss.

The same transition system is proved in Verus in
`verify/host-recovery/recovery.rs`: `TypeOK`, `RestoreEvidence`,
`RestartEvidence`, `SealedAdmission`, `CompletedSnapshot` and
`RefusalKeepsEvidence` are inductive over `normal.cfg`'s `Next`, strengthened
by nine auxiliaries (a non-`none` marker, visible or durable, always stands
next to the full backup set; the files/sync/cleanup phases pin the marker
values their entries establish; and the post-commit window plus the written
files carry the whole snapshot into `done`). The same invariant is also proved
inductive over `uncertain.cfg`'s `AllowCorruption` faults, matching that
configuration's positive TLC result. Each mutant is proved to reach its
recorded violation — consuming a backup breaks `RestoreEvidence`, cleanup
before sync and skipping the absent-marker barrier both break
`RestartEvidence`, and pair-only admission breaks `SealedAdmission` — and a
completion witness runs a seal through one interrupted recovery to `done`.
This strengthens the model claims from finite enumeration to induction; it
changes nothing about the production-correspondence obligations above.

`verify/rooms-frontier` separates journal commitment, the two snapshot stores,
the full application frontier and finalization replies. Four positive root
schedules include empty batches and changes to only one store. Seven mutants
challenge acknowledgment ordering, root equality as progress, independent
snapshot-height inference, committed identity, publication order, failed
finalization and next-height roster selection. Real adapter regressions cover
each publication cut and exact reopen/redelivery; real host messages reproduce
failed finalization with authenticated certificates. The repair preserves the
WAL by withholding failure responses instead of requesting an engine reset.
The model assumes atomic publication and verified replay, and source-binds the
external engine behavior to its pinned revision. It is not a consensus proof.

`verify/native-delivery` separates durable attempt intent, transport results,
outcome publication, uncertainty, budget exhaustion and explicit resume. It
checks exact destination/ciphertext binding, checked retention receipts and
conservation of spent attempts plus durably classified outages. Two attempts
per allowance, one resume and bounded failures keep the state space finite;
the split outcome-refusal action is limited to precommit failures. Failure
after SQL commit during barrier/readback and delivery liveness are outside this
model.

`verify/relay-quota` checks atomic item/charge publication, exact duplicate
position, stable credential ownership and durable retention before receipt.
Two items, two credential IDs, four requests and two interruptions cover item
and byte limits separately. A real TLS regression loses a successful PUT
completion, reopens both stores, replaces the token under the same credential
ID, exhausts/resumes the sender and recovers the original position with one
charge. SQLite atomicity and successful durability barriers remain assumptions.

`verify/private-control` checks sequence-bound owner attribution across two
handoffs, grants pinned to their carrying sequence, observation-only authority,
known-history fork evidence and quarantine across uncertain publication and
new-process reopen. Ordinary and late-join configurations use two devices and
four control slots. Real kernel tests exercise A→B→A and storage refusal,
lost completion and canceled completion. A precommit refusal can lose volatile
fork evidence when the process is lost; committed quarantine must survive.
The model assumes valid signatures and atomic publication and does not verify
MLS or agreement between disconnected replicas.

All use checksum-pinned TLC 1.7.4. The complete case inventory is required by the
runner: new configs cannot silently miss the gate. It requires complete positive
runs, named invariant failures or an unambiguously attributed temporal witness
for intentionally broken configurations. It preserves copied model inputs,
counterexamples, logs and source/tool/runner hashes; parse errors, input changes
or timeouts cannot count as finding the expected defect.

```console
python3 verify/run_tlc.py --jar /absolute/tla2tools.jar --java /absolute/java --out /new/evidence/directory
```

TLC explores arbitrary-length behaviors within the finite state space; it is
not proof over arbitrary process counts, cryptography, physical persistence,
all host failures or the deployed Rust program. Real-adapter regression tests
and independent deployment qualification remain necessary.

## What is not verified

The journal harness stubs hashing and Verus abstracts event identifiers;
the spent-nonce checks do not establish cryptographic or filesystem claims.
Signatures, MLS internals, consensus, physical persistence and operating-system
isolation remain outside these proofs. Kani results retain their input and
unwinding bounds; Verus proves reference transition discipline; TLC checks its
chosen finite protocol abstraction. Tests and live evidence cover different
parts of the argument and must not be relabeled as mathematical proofs.

## Lean weighted-certificate proofs

The [Lean trial](../verify/lean/README.md) proves weighted quorum intersection
for arbitrary finite rosters, connects distinct signer lists to roster
membership, and derives certificate value equality under honest
non-equivocation in one signing context. Lean 4.34.0 checks the `Std`-only
proofs; the runner verifies the distribution digest, theorem inventory and
transitive axioms before reporting success.

The [tool comparison](../verify/README.md#lean-comparison-decision) recommends
TLA+ for protocol interleavings, with Lean, Kani and Verus assigned their own
claims. The called formal workflow requires the Lean check. Generated Lean
cases also run through both Rust certificate verifiers with genuine signatures
and through the CLI threshold helper. This finite comparison tests their
correspondence; cryptography, cross-round locking and validator rotation need
separate evidence. See the proof README for commands, assumptions and costs.
