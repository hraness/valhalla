# Lean quorum experiment

The maintained proofs, Rust comparisons and reproduction commands are in
[`verify/lean`](../../verify/lean/README.md).

The original experiment on 23 September 2026 checked weighted quorum
intersection, threshold arithmetic and two assumption counterexamples using
Lean 4.34.0 and `Std`. Its final source hash was
`741c17543a1384dc67b009a2262310853cf0a31bfe9f67da9c3c9d9e075af7fc`;
that source is preserved in Git at commit `24381a6`. It checked in 2.17 seconds
locally. The distribution occupied 2.7 GiB; download and cold CI costs were not
measured for that experiment.

The [follow-up trial](../../kb/plans/valhalla-lean-assurance-trial.md) extends
the theorem to distinct signer identities and certificates in one signing
context, compares generated cases with Rust, and runs Lean in required CI.
Its results do not establish a cost advantage over an equivalent Verus proof.
