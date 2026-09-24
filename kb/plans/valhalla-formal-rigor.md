---
type: plan
area: formal-verification
status: completed
---

# Valhalla formal rigor: assessed tools, executable contracts

## Outcome and context

Assess TLA+ and Lean against Valhalla's actual risks, then ship an executable
steel thread and parallel, independently reviewed extensions. Start from
`ac0063f` (23 September 2026), which already contains four private-protocol TLC
models, a Verus ledger model with sampled Rust correspondence, and Kani spent
nonce checks. Preserve those investments and distinguish new evidence from
existing evidence. The user requested assessment, planning and implementation,
including parallel spikes and parallel expansion after an end-to-end thread.

The initial hypothesis is TLA+ for interleavings and recovery; existing
Verus/Kani for Rust invariants; Lean only if a real checked theorem demonstrates
enough additional mathematical value. Three independent read-only spikes
challenge that hypothesis before implementation. A proof assistant compiling
is not evidence of a useful theorem, and passing a model is not a Rust proof.

## Scope, constraints and decisions

- Keep production behavior and operational authority unchanged unless a new
  counterexample demonstrates a concrete defect requiring a bounded repair.
  No release activation, private-data migration, public deployment or new
  infrastructure is needed for verification support.
- Preserve all existing formal and Rust checks. Add bounded cases to the
  existing required formal workflow, which already participates in `check`.
- Use pinned TLC 1.7.4 with SHA-256 from `verify/tools.json`; an available Java
  21 runtime. Keep new models small enough for the existing ten-minute CI job.
- A maintained Lean layer needs checked statements, explicit assumptions,
  no `sorry`/unchecked axioms and a Rust correspondence story that warrants
  its installation and review costs. A successful isolated probe alone does
  not mandate adoption. Record an honest defer decision if that is the result.
- Root owns this plan, shared runner registrations/manifests, workflows,
  assurance documentation, tool pins, KB catalog and Git delivery. Workers own
  disjoint model/test files, run focused validation and never commit.
- Use the installed host scheduler for heavy commands when available. On this
  host neither `oompa-host-run` nor `hra-host-run` resolves in PATH or standard
  installed binary directories. Do not install or revive retired global
  wrappers. Keep model runs one-worker/512 MiB and Rust jobs bounded.
- Deliver a checked PR, independent agent review, resolved findings, current
  main ancestry, required `check` and all required CodeQL checks, including
  the managed `CodeQL` verdict. Never bypass `.github/main-ruleset.json`.
  Verification adoption is delivered in source and CI. No existing service is
  selected for operational activation; the bounded recovery fix follows the
  same checked-PR gates.

## Phase map

| Phase | Outcome | Depends on | Write scope | Parallel with |
| --- | --- | --- | --- | --- |
| 0 | Evidence-backed tool/target decision | none | Root plan; isolated temporary spikes | Three read-only reasoning lanes |
| 1 | Held reply steel thread: model, mutants, Rust regression, gate | 0 | Worker `verify/rooms-held-reply/`; root rooms-node test module and shared registration | Model and real-code test preparation |
| 2a | Fail-closed model inventory and evidence | 1 | Runner worker `verify/run_tlc.py`, `verify/test_run_tlc.py`, new manifest/tests | 2b; root assessment/docs |
| 2b | Interrupted sealed-host recovery model and regressions | 1 | Model worker `verify/host-recovery/`; separate host test ownership if needed | 2a; root assessment/docs |
| 3 | Integrated assurance and independent review | 2a, 2b | Root docs/KB/workflow integration; reviewer bounded fixes | Disjoint review slices |
| 4 | Checked PR merged with exact-head evidence | 3 | Root Git/PR only | CI lanes owned by root |

## Phase 0: Parallel decision spikes

- **Status:** Done
- **Depends on:** none
- **Objective:** select tools and targets using repository and official-source
  evidence, including an actually checked Lean experiment where feasible.
- **Scope:** TLA protocol gap spike; Lean weighted-quorum spike; checker and
  implementation-correspondence spike. Temporary experiments remain separate.
- **Acceptance criteria:** compare present stack, TLA+ and Lean over the same
  claims; record benefits, maintenance costs, limits and reversal conditions.
  Name precise invariants and Rust boundaries for each selected new model.
- **Validation:** source traces and official references; exact Lean command,
  version, theorem assumptions and outcome; no unsupported proof claim.

## Phase 1: Held reply steel thread

- **Status:** Done
- **Depends on:** 0
- **Objective:** detect failure modes at the rooms node's sequential connector
  boundary and connect the model to exercised production functions.
- **Scope:** `verify/rooms-held-reply/`, focused tests under
  `crates/vhalla-rooms-node/src/unix/`, root-owned runner registration.
- **Approach:** abstract request custody, late arrival, deadline expiry,
  metadata capacity, durable preparation, reply and publication. Match
  `drain_answerable_held`, `prepare_local_parts`, `flush_held` and `GetValue`.
- **Acceptance criteria:** normal finite safety and conditional liveness pass;
  mutants fail named properties for dropped custody, premature live reply,
  tombstone publication or forgotten deadline as appropriate. Real-code tests
  demonstrate deadline resolution, durable evidence before live reply,
  capacity refusal as a tombstone and no tombstone network publication.
  Preserve receiver-closed/network-failure and scheduler assumptions explicitly.
- **Validation:** one-worker pinned TLC on all new configs; exact focused
  `cargo test -p vhalla-rooms-node --all-features --locked formal_held_reply`;
  `cargo fmt --all -- --check`; independent model/test review.

## Phase 2a: Complete, attributable model evidence

- **Status:** Done
- **Depends on:** 1
- **Objective:** make a newly added but unexecuted model config fail the gate;
  reject malformed, incomplete or misattributed checker evidence.
- **Scope:** runner, runner tests and a versioned case/correspondence manifest.
- **Approach:** explicit inventory with unique cases, bounded relative paths,
  named expected failures and claim/source mapping; retain complete logs and
  structured traces with provenance. Include runner/manifest/source hashes,
  command, elapsed time and result in receipts. Preserve current CLI arguments.
- **Acceptance criteria:** all existing models remain checked; missing or extra
  configs/modules, duplicate entries and invalid paths fail closed; a checker
  error, timeout, signal, wrong property or malformed/empty trace cannot count
  as a mutant success. No stale checked-in trace masquerades as current evidence.
- **Validation:** `python3 -m unittest discover -s verify -p 'test_*.py'`, including
  bounded subprocess/fake-checker failure tests; full pinned TLC runner after
  root integrates every selected suite.

## Phase 2b: Recovery that survives another interruption

- **Status:** Done
- **Depends on:** 1
- **Objective:** explore sealed host maintenance, crash and repeated recovery
  at every abstract persistence boundary.
- **Scope:** `verify/host-recovery/` and narrowly assigned production regressions.
- **Approach:** source mapping to private-host config maintenance: backups before
  marker; selected files plus config/complete; non-consuming restore; durable
  marker removal before cleanup; exact sealed read admission. Model two files,
  bounded old/new versions and a bounded crash budget. Declare filesystem
  atomicity/durability assumptions rather than implying physical fsync proof.
- **Acceptance criteria:** recoverable interrupted states preserve evidence;
  admitted home is one complete committed version; capacity/failure refuses
  safely. Mutants expose consuming restore backups, premature backup cleanup,
  and admission based only on config/complete agreement. Existing or added Rust
  tests exercise the same boundaries and synthetic isolated homes only.
- **Validation:** pinned TLC normal and all named mutants; focused private-host
  config tests with exact names recorded in the log; independent source review.

## Phase 3: Convergence and assurance

- **Status:** Done
- **Depends on:** 2a, 2b
- **Objective:** one coherent claim-to-evidence ledger and reviewed result.
- **Scope:** `verify/README.md`, `docs/verification.md`, this plan, KB catalog,
  shared workflow wiring only when required.
- **Acceptance criteria:** compact TLA+/Lean/current-stack comparison, actually
  measured evidence and explicit non-claims; every model config is inventoried;
  workflow still runs from production-only edits; independent reviewers examine
  model validity, runner trust and Rust correspondence; all findings resolved.
- **Validation:** complete TLC suite; Python verification/policy tests;
  focused affected Rust tests and clippy; `git diff --check`;
  Wordcell percolate/refresh/check for the changed plan. Phase 4 runs the final
  aggregate via the repository's required current-head CI `check` before merge.

## Phase 4: Delivery

- **Status:** Done
- **Depends on:** 3
- **Objective:** integrate only task-owned changes through current branch policy.
- **Acceptance criteria:** source-policy audit, independent review, passing
  current-head complete `check`, required CodeQL analyses and managed verdict,
  conditional merge with no bypass, post-merge checks/readback and clean branch.
- **Validation:** record branch, commit, PR, exact checks, merge SHA and main
  readback. No existing host is selected for restart or operational deployment.

## Recovery

All probes and model evidence use new task-owned temporary directories. Runtime
tests use synthetic fixtures and never existing node/host homes. Revert task-owned
verification changes if necessary through ordinary Git review; retain failed
counterexamples and logs. Do not repair actual user stores or reset WALs.

## Implementation log

- 2026-09-23, phase 0: three independent read-only spikes converged on
  TLA+ for held reply custody and sealed host recovery; runner inventory and
  evidence gaps are concrete. Existing four models remain useful within their
  published assumptions. Lean 4.34.0 checked a Std-only weighted quorum theorem
  in 4.80 seconds: arbitrary finite weighted strict-two-thirds quorums share
  honest weight under at most one-third Byzantine weight. It also checked
  threshold equivalence and multiplication bounds. Only standard kernel axioms
  were reported. This is a reference theorem, not a Rust or BFT proof. Retain a
  reproducible isolated spike, defer a required Lean CI layer until a maintained
  Rust correspondence or extraction target justifies it. No Verus-vs-Lean
  performance comparison was measured. Phase 1 begins with disjoint model and
  real-code test ownership; existing runtime behavior is unchanged.
- 2026-09-23, phase 1: TLC normal completed (46 distinct states) with
  safety and conditional liveness; drop, early-reply and tombstone mutants
  produced named invariant counterexamples (exit 12), forgotten deadline
  produced a temporal stuttering counterexample (exit 13). Runtime tests:
  `CARGO_BUILD_JOBS=4 cargo test -p vhalla-rooms-node --all-features --locked
  --offline -- formal_held_reply seen_direct_and_held_replies_follow_durable_preparation
  seen_failed_preparation_cannot_release_direct_or_held_reply` passed all five.
  Fresh dependency fetch was required; no lockfile changed. Independent review
  accepted after distinguishing receiver-observed durability from exact send
  ordering, which the forced-persistence-failure regression separately checks.
  A harmless irrefutable-pattern warning was removed for final clippy. Root
  registered normal/safety cases; phase 2a now adds temporal attribution and
  complete manifest registration. Source-policy administrative audit passed:
  active reviewed ruleset, no bypass actors, app-bound required checks.
- 2026-09-23, phase 2 decision: the host-recovery source spike found a
  real missing ordering guarantee in `remove_seal_scratch`: retry after an
  unlink but before its directory fence sees no visible marker, so the old
  conditional fence lets backup deletion precede durable marker absence.
  Independent source review confirmed that ordinary recovery/load and the
  already-existing maintenance lock supply no intervening fence. Authorize the
  smallest production repair (always fence the directory before backup cleanup)
  with model counterexample and deterministic failure/order regression. The
  consequence is possible recovery refusal after another power loss, not a
  demonstrated APFS failure or a mailbox-data-loss claim. This is the plan's
  explicitly permitted counterexample-driven scope extension.
- 2026-09-23, independent Lean review: checked exact retained hash, theorem
  statements, axioms, witnesses and Rust source mapping; no blocking finding.
  Final new held-loop tests passed 3/3 after the warning repair; rooms-node
  all-target/all-feature clippy passed with `-D warnings`; source-policy Python
  tests passed 69/69. Full required aggregate still awaits converged-tree CI.
- 2026-09-23, phase 2b model/source review: normal explored 277 distinct
  states; explicit uncertain-evidence config explored 465; all four named
  mutants failed as intended. The former absent-marker behavior produced a
  16-state counterexample (675 generated/243 distinct). A separate reviewer
  traced each step to production and approved the unconditional directory fence
  plus deterministic sync-error/recovery tests. This extends source/CI assurance;
  it neither mutates nor restarts an existing private host.
- 2026-09-23, phase 2a parallel validation: root added a disjoint black-box
  CLI test lane (`verify/test_tlc_process.py`), passing 8/8. Tests cover copied
  input attribution, complete-looking output followed by timeout, missing
  runtime, wrong checker digest, output-directory preservation, and source,
  model and runner edits during checking. Runner worker owns config/inventory
  and trace-parser tests, and the converged Python gate. Root refreshed exact
  `refs/heads/main` without tags; base remains `ac0063f`.
- 2026-09-23, phase 2a gate: 25 Python runner tests pass, including root's
  eight independent black-box tests. Root's full pinned TLC integration run
  completed all 26 cases (eight positives, 17 expected invariant failures,
  one expected temporal failure) in 38.77 seconds. Receipt
  `/private/tmp/valhalla-formal-integrated-20260923-a/receipt.json` is complete,
  verdict pass, with all 60 attested inputs unchanged. The runner exercised
  actual TLC single-variable, multi-variable and stuttering trace formats.
  A fresh independent integrated reviewer is inspecting the complete diff.
- 2026-09-23, independent integrated review: required workflow/aggregate
  wiring, all 26 actual logs and source/model correspondence accepted. Review
  found two runner defects: consumed copies were not rehashed, and a malformed
  trace could put completion statistics before its state sequence. Reopened
  phase 2a for bounded repairs. Root added a black-box copied-input drift test
  and observed it fail against the prior runner (9 tests, one failure); the
  author is adding consumed-copy checks and strict terminal ordering. The
  previous passing TLC run remains valid historical evidence for its exact
  inputs; a new full run will bind the repaired runner.
- 2026-09-23, phase 2a final gate: the repaired runner checks consumed
  copies before every invocation and at closeout, and requires trace states
  before final statistics/completion while allowing earlier temporal progress.
  All 29 Python tests passed. The independent integrated reviewer replayed both
  defects, confirmed rejection and accepted all source/model claims with no
  unresolved finding. Root reran all 26 pinned TLC cases in 22.85 seconds:
  `/private/tmp/valhalla-formal-integrated-20260923-b/receipt.json` reports
  complete/pass, all 60 attested inputs and 32 consumed copies unchanged.
  This run supersedes the earlier aggregate for the final runner bytes.
- 2026-09-23, phases 2b/3 final local gates: Rust 1.98.1 passed all 13
  private-host config tests, including the five new recovery regressions, and
  CLI all-target/all-feature clippy with `-D warnings`. Both affected crates'
  focused checks, all 29 verification Python tests, all 69 policy tests, all
  26 TLC cases, source formatting, independent integrated review and the final
  Wordcell percolate/refresh/check passed. The final runtime source needed no
  repair after compilation. Phase 4 owns the complete current-head CI gate and
  checked merge; this source snapshot does not pre-claim those external results.
- 2026-09-23, staged-tree gate: staging newly added counterexample files
  exposed trailing blank lines that unstaged `git diff --check` cannot inspect.
  Removed those four whitespace-only lines. A fresh 26-case aggregate passed in
  18.01 seconds with all 60 attested inputs and 32 consumed copies unchanged:
  `/private/tmp/valhalla-formal-integrated-20260923-c/receipt.json`. The staged
  whitespace gate and final KB refresh/check are clean.
- 2026-09-23, phase 4 completion: [PR #98](https://github.com/hraness/valhalla/pull/98)
  merged reviewed candidate `9a4d06f3c64968e805c4d38b2ec077e3f880dda8`
  as `4066036902e0b20951acee79e8af8aa80a7e34c4`, without a branch-policy
  bypass. All 70 PR checks passed, including the complete aggregate, five
  CodeQL analyses and the managed verdict with no new alerts. Final independent
  whole-feature review passed without edits or unresolved findings. All 69
  post-merge checks passed in the [Rust run](https://github.com/hraness/valhalla/actions/runs/35919070042)
  and [CodeQL run](https://github.com/hraness/valhalla/actions/runs/35919068321).
  The merged tree exactly matched the reviewed candidate. Fresh merged-main
  formal evidence passed all 26 cases; all 60 attested source hashes, 32
  consumed-input hashes and 26 log hashes were independently verified.
  Local main and the remote main readback matched the merge commit, with a
  clean local working tree. All implementation and delivery phases are
  complete. Maintained Lean adoption remains deferred as decided in phase 0.

## Result

The assessment and implementation are complete. Expand TLA+ for protocol and
recovery behavior, preserve existing Kani/Verus checks, and retain the checked
Lean weighted-quorum theorem as an optional experiment. The held-reply steel
thread and recovery model connect bounded claims to actual Rust regressions.
The recovery model exposed and drove a repair for the absent-marker directory
fence. A complete inventory and checked evidence contract now cover all six
TLA+ suites. All phases were delivered through
[PR #98](https://github.com/hraness/valhalla/pull/98), with passing current-head
and post-merge checks recorded above. The PR retains the external delivery
record for branch `codex/formal-rigor-20260923` and merge `4066036`.

## Durable memory

[[notes/formal-assurance|Formal assurance with implementation correspondence]]
owns the reusable distinction between model results, production correspondence
and live qualification, including visible versus durable recovery state.
The [assurance ledger](../../verify/README.md) owns the tool decision and current
claims, bounds and assumptions; each model README owns its source mapping and
counterexamples. The [verification guide](../../docs/verification.md) owns the
maintained checker invocation and interpretation.
