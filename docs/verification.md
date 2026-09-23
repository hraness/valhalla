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

`verify/private-publication` explores two competing sessions, a roster-bound
draft, cancellation before/after commit, exact retained recovery, readback and
local revocation. Release linearizes at the final successful authority check;
it does not promise that previously authorized bytes cannot arrive later.
The three mutations release before confirmation, retarget a stale draft and
ignore revocation. Native pending-publication and competing-custody regressions
remain necessary to justify the model's atomic-publication abstraction.

`verify/private-egress` checks sender-local order with three committed artifacts,
one membership control and one queue slot. Its mutation stages a new receipt
past the monotone capture frontier, allowing the control to overtake an older
application. The real TLS backlog regression exercises that defect in native
delivery. The model assumes source artifacts exist and does not establish
global message order, remote availability or source-publication correctness.

All use checksum-pinned TLC 1.7.4. The runner requires complete positive runs
and the specific expected invariant failure for each intentionally broken
configuration. It preserves counterexamples, logs and source/tool hashes; a
parse error or timeout cannot count as finding the expected defect.

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
