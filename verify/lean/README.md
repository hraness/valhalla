# Lean weighted-certificate proofs

Lean proves that two strict weighted two-thirds quorums on one fixed roster
share an honest signer when faulty weight is at most one-third. The proof
connects distinct signer lists to weighted roster membership, then derives
certificate value equality when honest signers sign only one value in the
same signing context: height and round for precommits. These statements hold
for arbitrary finite rosters.

This is a maintained trial using Lean 4.34.0 and its standard library. The
mathematical proof and the Rust comparison have different scopes: Lean checks
the theorem, while generated cases test the production certificate verifiers
with genuine signatures. The proof assumes authenticated signatures, an agreed
roster and honest non-equivocation. It does not establish cryptographic
soundness, agreement across rounds, safe validator rotation or Rust refinement.

## What connects the proof to Rust

| Mathematical statement | Production source | Correspondence evidence |
| --- | --- | --- |
| A unique signer list contained in a unique roster counts exactly the selected roster weight | `RoomValidatorSet::validate`, `verify_commit_certificate`, `verify_canonical_certificate` | Generated weighted rosters and signer lists run through both verifiers; duplicate and unknown signers are rejected. |
| Two strict quorums share a positive-weight honest signer under the fault bound | Fixed-roster certificate acceptance in rooms-node `cert.rs` | The Lean theorem has no roster-size bound; the Rust corpus exercises finite signer subsets and weighted thresholds. |
| Certificates in one signing context have equal values under honest non-equivocation | `vote_sign_bytes` binds height, round, value and signer; both verifiers rebuild the precommit | Signature tests change each field without signing again. Honest non-equivocation is a theorem premise, not a property proved about the consensus engine. |
| Strict two-thirds acceptance equals `floor(2 * total / 3) + 1` | CLI `quorum` | The CLI uses the same generated expected thresholds. |
| Validated totals and distinct signer power keep the engine's `u64` products in range | Validator-set total cap and CLI arithmetic | Near-cap corpus cases and the existing large-power certificate regression. Certificate verifiers themselves use `u128`. |

[`claims.json`](claims.json) lists every public theorem and the source files
included in checking records. [`Quorum.lean`](Quorum.lean) also contains
counterexamples showing why strict quorum, the fault bound, one context and
honest non-equivocation are necessary. A successful compilation alone is
insufficient: the runner checks the theorem inventory and the transitive axioms
of every declaration in the proof module.

The generated [`corpus.json`](corpus.json) contains 354 cases: all 340 signer
subsets across 30 rosters of one to four validators with powers one or two,
one initial example, and 13 boundary cases. It includes exact two-thirds,
near-cap totals, 64 validators, excessive signature counts, duplicate signers
and unknown signers. Of those cases, 94 are accepted and 260 rejected.
The Rust test also checks 315 ordered pairs of accepted small certificates
against 1,451 fault assignments within the theorem's weight bound.

This corpus is finite differential-test data. Its acceptance function is tied
to the mathematical predicate by a Lean theorem. Regenerating the file executes
Lean code, so the compiler/runtime and JSON transport participate in that test
comparison. This is separate from kernel checking the unbounded theorems. The
Rust verifier and CLI tests consume the recorded expected results directly
rather than repeat a second expected-quorum formula.

## Reproduce the check

Download the archive for your platform from the official URL in
[`tools.json`](tools.json). Supported trial platforms are Linux x86-64 and
macOS arm64. Python 3 and a `tar` capable of reading Zstandard archives are
required. The runner checks the archive digest before extracting or executing
it and verifies the Lean version and commit. It installs no global toolchain.

```console
python3 verify/run_lean.py --archive /absolute/lean-4.34.0-PLATFORM.tar.zst --out /new/owned/lean-evidence
python3 -m unittest discover -s verify -p 'test_*.py'
cargo test --locked -p vhalla-rooms-node --all-features lean_
cargo test --locked -p vhalla-cli --features experimental-rooms-node --bin vhalla lean_shared_quorum_corpus_matches_operator_threshold
```

The output directory must be new. It records the source and tool hashes,
commands, durations, diagnostics and theorem audit, plus a regenerated corpus.
Only `propext`, `Classical.choice` and `Quot.sound` are allowed as axioms.
Unfinished proofs, extra axioms, missing theorems, changed fixtures, compiler
errors and timeouts fail the check. Negative controls exercise these rejection
paths. The extracted distribution stays outside the uploaded evidence
directory; generated proof files and compiled modules remain with its inputs.

The `lean-quorum` job in the called formal workflow runs this check on each
candidate and participates in the required Rust aggregate. The Rust workspace
jobs separately execute the authenticated comparisons. Updating a production
source therefore reruns both, but reviewing the theorem-to-code relationship
remains necessary when that source changes.

## Trial result and costs

The first shared fixture passed Lean and both Rust certificate verifiers. The
comparison also reproduced a discrepancy at `Round::Some(u32::MAX)`: the engine
accepted the certificate while both canonical readers rejected its reserved
round encoding. The engine verifier rejects that sentinel before journal
commit; `u32::MAX - 1` remains accepted. The regression uses genuine signatures
and preserves the certificate format.

The trial supports keeping Lean for this mathematical component alongside
TLA+ protocol models. No equivalent Verus implementation was timed, so no
comparative cost or superiority claim follows. Checking time and distribution
setup are recorded separately in each run; CI includes the archive download.

In the fresh macOS arm64 run on 24 September 2026, unpacking the pinned archive
took 84.27 seconds and checking `Quorum.lean` took 4.68 seconds. All recorded
commands, including startup, audits, corpus generation and eight rejection
controls, totaled 135.86 seconds. The archive was already downloaded and other
Rust checks ran concurrently, so these figures describe that run rather than
an isolated performance benchmark. Its output contained 1.90 MB of evidence.

Lean's [proof validation guide](https://lean-lang.org/doc/reference/latest/ValidatingProofs/)
and [axiom reference](https://lean-lang.org/doc/reference/latest/Axioms/)
describe the trust assumptions of the checker. The
[implementation plan](../../kb/plans/valhalla-lean-assurance-trial.md) records
the trial's validation and review history.
