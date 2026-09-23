# Evaluated optional Lean quorum spike

This isolated experiment evaluates Lean against a real Valhalla mathematical
boundary. It is not a maintained production proof or a required CI toolchain.
It changes no Rust code, dependency, release gate or runtime behavior. The
current decision is to expand TLA+ for protocol interleavings and retain
Verus/Kani for their existing Rust claims. This experiment demonstrates that
Lean is viable; no equivalent Verus run was measured, so it does not establish
that Lean is faster or cheaper to maintain.

## Checked statements

`Quorum.lean` imports only `Std`, with no Lake project or external dependencies.
Each list entry represents one distinct validator, with a natural-number
weight and Boolean membership in two signer subsets and the Byzantine subset.

- `strict_quorums_have_honest_overlap`: for any finite weighted roster, if
  both signer subsets hold strictly more than two-thirds of the total weight
  and Byzantine weight is at most one-third, their intersection has positive
  honest weight. The supporting finite-sum bounds are proved by list induction.
- `threshold_exact`: `3 * signed > 2 * total` is equivalent to
  `signed >= floor(2 * total / 3) + 1` over natural numbers.
- `multiplication_safe`: `total <= (2^64 - 1) / 3` and `signed <= total`
  imply that `3 * signed` and `2 * total` fit within `2^64 - 1`.
- `nonstrict_threshold_admits_no_honest_overlap`: three unit-weight voters,
  including one Byzantine voter shared by two two-voter subsets, satisfy a
  non-strict two-thirds threshold but have no honest overlap.
- `excess_faults_admit_no_honest_overlap`: a shared Byzantine voter of weight
  two and two separate honest voters of weight one satisfy strict quorums
  without honest overlap when the Byzantine bound is removed.

The last two statements are concrete, checked witnesses showing why the
threshold and fault assumptions matter. They are not model-checker traces.

## Production correspondence and limits

| Mathematical boundary | Production source | Remaining obligation |
| --- | --- | --- |
| One canonical roster, positive weights and total at most `u64::MAX / 3` | `RoomValidatorSet::validate` in [`context.rs`](../../crates/vhalla-rooms-node/src/context.rs) | The Lean list represents admitted distinct identities; it does not execute the Rust validator. |
| Known distinct signers, authenticated votes and strict quorum | `verify_commit_certificate` and `verify_canonical_certificate` in [`cert.rs`](../../crates/vhalla-rooms-node/src/cert.rs) | Signature verification, byte encoding and duplicate rejection remain Rust/cryptographic obligations. |
| Minimum quorum weight | `quorum` in [`rooms_node.rs`](../../crates/vhalla-cli/src/rooms_node.rs) | The arithmetic theorem does not establish that every caller used a validated total. |
| Existing strict-boundary and large-power regression | `certificate_quorum_is_exact_at_large_power_and_invalid_sets_fail_closed` in [`context/tests.rs`](../../crates/vhalla-rooms-node/src/context/tests.rs) | This test is separately maintained evidence; it is not a refinement proof. |

The theorem uses one fixed roster and one weight assignment. It does not prove
agreement on a validator schedule, safe rotation, Malachite locking across
rounds, non-equivocation, cryptography, machine-integer semantics, storage
durability or end-to-end consensus safety. Honest quorum intersection alone
does not establish that two certificates from different rounds cannot decide
different values. Natural-number arithmetic is linked to Rust only by the
documented premises above, not by extraction or formal refinement.

Before promoting this into a maintained layer, require an owned production
correspondence boundary and a demonstrated advantage over the same-scope
Verus proof. Useful conformance tests would exercise both actual certificate
verifiers with genuine signatures, unequal weights, signer subsets, duplicate
and unknown signers, exact two-thirds boundaries and near-cap powers. Such
tests would still be tests, not a proof that Rust refines this model. Reopen
adoption for a stable unbounded theorem requiring reusable mathematical
structure; scalar arithmetic alone is insufficient justification.

## Reproduce

Use an independently obtained Lean **4.34.0** distribution. The
`lean-toolchain` file records the version; this directory installs nothing.
From the repository root, using that distribution's absolute executable:

```sh
/absolute/lean-4.34.0/bin/lean --version
/absolute/lean-4.34.0/bin/lean prototypes/lean-quorum/Quorum.lean
shasum -a 256 prototypes/lean-quorum/Quorum.lean
```

Successful checking must exit zero. The file prints each public result's
transitive axiom dependencies. Require only the audited standard axioms
below; reject `sorryAx`, custom axioms and native-evaluation axioms. A timeout,
compiler error or version mismatch is not successful evidence. No `lake
update`, mathlib acquisition or global toolchain change is needed.

## Recorded experiment

On 23 September 2026, the checked source was copied unchanged from an isolated
temporary probe. Its SHA-256 is
`741c17543a1384dc67b009a2262310853cf0a31bfe9f67da9c3c9d9e075af7fc`.

The initial three-result proof checked in 4.80 seconds. The installed, unpacked
macOS arm64 Lean distribution occupied 2.7 GiB; download/setup time and CI
cold-start cost were not measured. The final source includes both witnesses.
After copying that exact source into this directory, the fresh check exited
zero in 2.17 seconds wall time (`user 0.55`, `sys 0.70`) with:

```sh
/usr/bin/time -p /private/tmp/algal-verification-tools/lean-4.34.0-darwin_aarch64/bin/lean prototypes/lean-quorum/Quorum.lean
```

It reported Lean 4.34.0, `arm64-apple-darwin24.6.0`, commit
`293d5d0c0c3f3dded4688b3ccd6a33939ac5102b`, Release. The checked axiom output was:

```text
'strict_quorums_have_honest_overlap' depends on axioms: [propext, Quot.sound]
'threshold_exact' depends on axioms: [propext, Classical.choice, Quot.sound]
'multiplication_safe' depends on axioms: [propext, Classical.choice, Quot.sound]
'nonstrict_threshold_admits_no_honest_overlap' does not depend on any axioms
'excess_faults_admit_no_honest_overlap' does not depend on any axioms
```

This is local proof evidence, not a trusted distribution manifest or a receipt
for a later edited source. Recheck the file after changes.

Official references: [Lean 4.34.0 release](https://lean-lang.org/doc/reference/latest/releases/v4.34.0/),
[kernel-checked tactic proofs](https://lean-lang.org/doc/reference/latest/Tactic-Proofs/),
[axioms and their audit](https://lean-lang.org/doc/reference/latest/Axioms/),
[Verus scope](https://verus-lang.github.io/verus/guide/), and
[Verus trusted components](https://verus-lang.github.io/verus/guide/tcb.html).
