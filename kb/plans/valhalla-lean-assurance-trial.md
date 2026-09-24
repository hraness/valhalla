---
type: plan
area: formal-verification
status: completed
---

# Lean assurance trial for weighted certificates

## Outcome and context

Give Lean a maintained, bounded trial on a real Valhalla mathematical boundary.
The user explicitly reopened Lean after the completed
[[plans/valhalla-formal-rigor|formal-rigor assessment]] and
[[plans/valhalla-protocol-formal-expansion|protocol expansion]]. The existing
optional quorum spike demonstrates feasibility but does not exercise production
certificate verification or run in required CI. This trial connects checked
unbounded statements, concrete signed-certificate conformance, and reproducible
proof admission. It does not assume Lean must outperform Verus to be tried;
any claim of comparative superiority still requires comparative evidence.

## Scope and constraints

- Start from clean `main` at `24381a6e9db2f22e23c21906aabebf0d4c69b3a0`.
  Before validation, integrate the unrelated main updates through `339760a`;
  their files do not overlap the certificate or proof changes.
- Keep Lean 4.34.0 and `Std` only; no mathlib, global toolchain change or
  production dependency. Move the maintained boundary under `verify/lean` and
  preserve a navigation pointer at the historical prototype.
- Prove fixed-roster weighted intersection and a useful extension with explicit
  signing-context and honest-behavior premises; retain threshold, overflow and
  checked counterexample witnesses. Never claim full consensus safety,
  cryptographic soundness, cross-round locking, roster agreement or rotation.
- Exercise both real certificate verifiers with genuine signatures and common
  mathematical fixtures. Finite conformance remains testing, not Rust refinement
  or extraction. The verifier uses `u128`; distinguish its arithmetic from the
  engine/CLI's validated `u64` total contract.
- Admit only completed kernel-checked proofs with audited standard axioms.
  Reject missing claims, `sorry`, custom/native-evaluation axioms, malformed
  evidence, version mismatches and timeouts. Keep source, tool and result hashes.
- Preserve all existing TLC, Verus, Kani, Rust and security gates. Add Lean to
  the existing called formal workflow so the required Rust aggregate includes
  it. Check official distribution digests before executing downloaded tools.
- No release, deployment, service activation or data migration is required.
- A reproduced discrepancy in the certificate paths may receive a narrow
  correction with a failing regression first. Preserve certificate encodings,
  the accepted ordinary rounds, journal history and WAL recovery evidence.
- Workers never commit. The integration owner owns this plan, shared workflow,
  assurance documentation, KB catalog, branch and delivery. Worker file scopes
  are disjoint. There is one Cargo owner and one CI-wait owner.
- Use an installed host scheduler for heavyweight work when available. No
  `oompa-host-run` or `hra-host-run` currently resolves in PATH or the standard
  installed binary directories on this host; do not install a wrapper or bypass
  a denial. Use pinned Rust 1.98.1, four build jobs and the existing target cache.

## Phase map

| Phase | Deliverable | Depends on | Write owner | Parallel with |
| --- | --- | --- | --- | --- |
| 0 | Reviewed mathematical, implementation and tool contracts | None | Root: plan; three read-only spikes | Independent spike lanes |
| 1 | Existing proof reproduced and one shared fixture checked end to end | 0 | Proof worker: Lean source; Rust worker: test module; root: joining contract | Disjoint proof/test work |
| 2a | Unbounded theorem extension and assumption witnesses | 1 | Proof worker: `verify/lean/Quorum.lean`, generated shared fixture | 2b, 2c |
| 2b | Authenticated production correspondence suite | 1 | Rust worker: new certificate conformance test module, module registration, dev-dependency and CLI test | 2a, 2c |
| 2c | Fail-closed proof checker and evidence regressions | 1 | Tool worker: Lean audit support, Python runner/tests and tool manifest | 2a, 2b |
| 3 | Integrated CI, documentation, aggregate checks and independent review | 2a, 2b, 2c | Root: shared files; independent reviewer: bounded findings | Independent review slices |

## Phase 0: Trial contract

- **Status:** Done
- **Acceptance:** select explicit theorem statements and assumptions, fixture
  format, verifier callsites, tool/axiom admission rules and disjoint owners.
- **Validation:** source inspection and bounded temporary probes; record the
  decision without treating feasibility as completed implementation.

## Phase 1: Executable thread

- **Status:** Done
- **Acceptance:** the pinned Lean binary rechecks the original quorum proof;
  one common weighted-roster fixture is checked by Lean and consumed by both
  production verifiers with real signatures. Record commands and results.
- **Validation:** absolute Lean 4.34.0 invocation; focused `cargo test --locked
  -p vhalla-rooms-node --all-features lean_` under Rust 1.98.1.

## Phase 2a: Mathematical extension

- **Status:** Done
- **Acceptance:** unbounded theorem proves a useful conclusion beyond scalar
  quorum arithmetic, with a fixed roster and explicit signing context. Checked
  witnesses expose the need for strict quorum, fault bounds and any new honest
  behavior/context assumption. Every admitted theorem has an audited axiom set.
- **Validation:** pinned Lean proof runner; no unfinished or unaudited proof.

## Phase 2b: Rust correspondence

- **Status:** Done
- **Acceptance:** shared fixtures cover small unequal-weight rosters and signer
  subsets, exact thresholds and near-cap powers. Both verifiers reject duplicate
  and unknown signers and tampered signing context. Exercise actual production
  entry points and preserve expected outcomes in an independently checked corpus.
- **Validation:** focused conformance test, relevant existing certificate tests,
  and strict crate Clippy; report fixture and test-source hashes.

## Phase 2c: Checker admission

- **Status:** Done
- **Acceptance:** exact Lean/tool identity, theorem inventory and axiom audit;
  bounded execution and retained logs; source/tool/fixture hashes; intentional
  wrong-proof and incomplete-proof cases rejected for their intended reason.
  Official distribution URL/digest is pinned and CI installs locally.
- **Validation:** Python runner regressions and successful real Lean run,
  including negative controls. Parser failure alone is not mutation evidence.

## Phase 3: Integrated assurance boundary

- **Status:** Done
- **Acceptance:** existing formal workflow includes Lean; old optional-only
  guidance points to the maintained trial. Document theorem statements,
  implementation map, measured checking/setup cost and remaining assumptions.
  Independent review covers proofs, fixtures, actual verifiers and CI admission.
- **Validation:** focused evidence from workers, one converged proof run,
  `python3 -m unittest discover -s verify -p 'test_*.py'`, Rust formatting,
  Wordcell percolation/refresh/check, and current-candidate required PR gates.

## Delivery and recovery

Follow `docs/main-policy.md`: independent agent review, current-main candidate,
complete Rust aggregate, all five CodeQL analyses and the managed CodeQL
verdict from app 57789 must succeed before conditional merge. Root owns the
single CI wait and verifies the exact integrated tree. Record PR, candidate,
checks and merge evidence at closeout. A failed proof/tool download is a failed
gate; repair or remove the new trial through reviewed changes without weakening
existing checks. Proof tooling adds no runtime dependency. Any certificate
correction must fail before the durable commit and preserve the storage format;
reverting proof tooling needs no storage or operational rollback.

## Implementation log

- 24 September 2026, phase 0: three independent source/tool spikes selected an
  identity-list-to-membership weighted-sum bridge and same-height/same-round
  value uniqueness conditional on authenticated votes and honest
  non-equivocation. A temporary Std-only bridge proof checked in 3.1 seconds.
  Both actual verifiers already establish known distinct authenticated signers
  and strict `u128` quorum arithmetic; no product defect was observed. The
  shared version-1 JSON corpus contains case IDs, powers, signer identity
  indices, expected acceptance and minimum quorum power. Lean generates it from
  its proved admission function; the runner checks regeneration and Rust uses
  the expected results directly. Start with one checked fixture before
  expanding to all 340 small-roster subsets and named boundary cases.
- Phase 1 inspection found a possible certificate discrepancy: the engine
  verifier accepts `Round::Some(u32::MAX)`, whose `VC2` bytes use the same
  reserved sentinel that both canonical readers reject. The real-signature
  regression must reproduce this before a correction. The host calls engine
  verification before adapter/journal commit; replica and public-client
  consumers call the canonical verifier. The planned correction rejects that
  reserved round before persistence and preserves `u32::MAX - 1` acceptance.
- Phase 1 joined: the original proof rechecked in 0.60 seconds with Lean
  4.34.0, and the new weighted fixture (`[1, 2]`, both signers, quorum three)
  was checked by Lean and accepted by both authenticated Rust verifiers.
  `cargo test --offline --locked -j 4 -p vhalla-rooms-node --all-features lean_`
  under Rust 1.98.1 passed the fixture test and failed the intentional
  reserved-round regression: engine accepted round 4294967295 while canonical
  rejected it. Round 4294967294 passed both. The complete red log is
  `/private/tmp/valhalla-lean-steel-rust-red-20260924.log`; pre-repair `cert.rs`
  SHA-256 is `4ec3c7765fb06dbc0fe5ed40819fed0f4959b03fb95bf116427e4e8adc916651`.
  Authorize `CertError::ReservedRound` plus an early sentinel rejection, and
  expand proofs, correspondence and checker support in disjoint parallel work.
- Phases 2a/2b source review: independent agent `lean_independent_review`
  found no changes needed in the mathematical statements, corpus, certificate
  correction or Rust comparisons. It independently recomputed all 354 expected
  corpus results and the exhaustive 340 small subsets, and traced the host,
  replica and public-client consumers. The proof contains 24 theorems, including
  the identity-list bridge, a positive-weight honest common signer, indexed
  fixture correspondence and same-context value uniqueness. The source hash is
  `a75956b0e07248a9ee37d0056cf4dc0f26f3ad92cfd2686c509a161eaed939a3`;
  the 354-row corpus hash is
  `ccc71c7b6ff58c486b57fe77e00972de1e3e117accd6a1678918fe7fab82178d`.
  Lean checked source/emission in 3.21 seconds; regenerated corpus bytes match.
  The node's five conformance tests passed after the sentinel correction,
  including 315 accepted subset pairs and 1,451 fault assignments. Complete
  tool audit, pinned Rust/Clippy results and final integration remain pending.
- Phases 2a/2b/2c joined after complete independent source review. The final
  Rust receipt, `/private/tmp/valhalla-lean-pinned-receipt-20260924.json`, replaces
  earlier evidence with ambiguous Homebrew tool dispatch. It records absolute
  Rust 1.98.1 binaries, command-local PATH/RUSTC/RUSTDOC, binary hashes, an
  intended failing regression with the guard removed, restoration, 18 passing
  context tests, two passing CLI tests and strict node/CLI Clippy. Per-command
  input hashes stayed unchanged. Receipt SHA-256:
  `b7b4fd4e28b3be6feec31f4da9c2f0480c762c4355b6b98f6fe3e43a4145e017`.
- Phase 3 local integration: the archive-based Lean runner passed all 24
  theorem claims, audited all 177 module declarations and rejected eight
  controls for their intended reasons. Receipt
  `/private/tmp/valhalla-lean-final-20260924-a/receipt.json` has SHA-256
  `09872858edf777b568df66c6a9d9ccb71ab49973bf22dcea104cdfbea1cb51b6`.
  All 19 current and copied source hashes, 21 command-log hashes and regenerated
  corpus bytes were read back and matched. Commands totaled 135.857 seconds;
  extraction took 84.272 seconds and proof checking 4.676 seconds. No download
  time is included; this run overlapped independent Rust checks. The output
  contains 1,896,364 bytes, excluding the extracted toolchain. All 49 Python
  runner regressions, pinned Rust formatting and the full administrative
  checked-PR policy audit passed. The first TLC attempt failed before model
  exploration because the sandbox denied its local RMI socket; retain that
  incomplete result and rerun through the approved escalation boundary.
- The approved TLC rerun passed all 61 cases (18 positive, 42 invariant
  counterexamples and one temporal counterexample). Receipt
  `/private/tmp/valhalla-lean-tlc-final-20260924-b/receipt.json` has SHA-256
  `ae34612cf8215c02cdfa88f661d6a12faba0ff9f9789fc46b474f4e5036fc151`.
  The full Lean and pinned Rust evidence was independently read back by
  `lean_independent_review`, including current/copied source hashes, tool
  identities, all logs and intended rejection diagnostics, with no findings.
  Wordcell percolation returned no candidates for the changed concept or plan;
  refresh/check passed with 17 notes, 47 contextual links and a current catalog.
  Source and documentation were drafted by root and the named implementation
  agents and reviewed by the independent AI agent; no human review is claimed.
  Current-candidate CI and governed delivery remain pending.
- PR [#105](https://github.com/hraness/valhalla/pull/105) publishes implementation
  candidate `0607fe474133d62e5a3c56117fd274b2fff1ea92` on current main `339760a`.
  Its Linux Lean job passed in 39 seconds, including download and extraction.
  Artifact readback exposed a packaging omission: upload-artifact excluded the
  copied `.github/workflows/verification.yml` by default. Enable hidden-file
  upload for this explicitly enumerated source/evidence directory, then rerun
  required CI and verify all 19 copied inputs from the downloaded artifact.
  The omitted file contains workflow source, not credentials; the extracted
  distribution remains outside the uploaded directory.
- The corrected candidate `019282e6679f6c6aee37839ecad67299cec3531c`
  passed all 71 checks, including the complete Rust aggregate, all five CodeQL
  analyses and the managed CodeQL verdict from app 57789. The Linux Lean job
  in [run 35947888460](https://github.com/hraness/valhalla/actions/runs/35947888460)
  completed in 43 seconds, including download and extraction. Its receipt
  SHA-256 is
  `6c490740376bbe48e4303debb2597bad42d8f4eeb485cbb221d974ebabb0f500`.
  Independent AI reviewer `lean_independent_review` verified all 19 copied
  inputs, including the workflow, all 21 logs, 24 claims, 177 declarations,
  eight rejection controls and the regenerated corpus. The same review checked
  the CI TLC receipt
  `a085298f550af4e769277d413a9edb48848aec57ba9e27d4e38e5f031901eef0`,
  all 141 source inputs, 71 copies, 61 logs and 43 expected counterexamples.
  Both artifacts matched the candidate; neither review required changes.
- PR [#105](https://github.com/hraness/valhalla/pull/105) merged on
  24 September 2026 at 02:57:36 UTC as
  `dd5b72cc574d3f03efd67820ca0bcab36bbe2d20`. Conditional squash merge
  required the reviewed head and included current main. Readback confirmed the
  merged tree exactly matched candidate tree
  `2c6056a609816be9e467bb4ca0d43cc9237215cd`. The implementation branch is
  `codex/lean-assurance-trial-20260924`; this completion record is maintained
  on `codex/lean-assurance-closeout-20260924`. No release, deployment, service
  activation or data migration was needed.

## Result

All phases are complete. Lean checks 24 theorems in required CI, including
weighted signer-list correspondence, positive-power honest quorum overlap and
same-context certificate value equality under the stated authentication and
non-equivocation assumptions. The 354-case shared corpus exercises both Rust
certificate verifiers with signatures and the CLI quorum threshold. Production
correspondence inspection and a failing regression exposed the reserved-round
mismatch; engine verification now rejects it before persistence.

The measured Linux check cost supports keeping this trial alongside the existing
TLA+, Verus and Kani checks. Finite Rust conformance and the mathematical proof
remain distinct evidence. Broader adoption still depends on a useful theorem
and a clear implementation connection for each proposed target.

## Durable memory

The maintained [[notes/formal-assurance|formal-assurance note]] records the
division of work between protocol models, mathematical proofs and production
tests. [The Lean reference](../../verify/lean/README.md) owns the theorem map,
assumptions, Rust callsites, corpus, commands and measured costs;
[the verification guide](../../docs/verification.md) links the required checks.
The historical prototype points to this maintained implementation. No additional
follow-up plan is required for the completed trial.
