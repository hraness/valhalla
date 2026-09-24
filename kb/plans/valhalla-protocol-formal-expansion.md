---
type: plan
area: formal-verification
status: completed
---

# Valhalla protocol formal coverage expansion

## Outcome and context

Expand the completed [[plans/valhalla-formal-rigor|formal-rigor program]] into
additional shipping protocols. The user explicitly selected expanded coverage
after the initial six-suite program and optional Lean assessment were delivered.
Start from `1cff4f5fc202b1a1a987d6ae52672188956774b0`. Parallel source spikes
select precise claims, then an executable rooms replay steel thread establishes
the model-to-Rust workflow before parallel relay and private-control expansion.

The intended result is four additional bounded models, deliberate failing
mutations, production regressions, a complete evidence inventory and a checked
PR. Correct a production defect only after a failing regression or independently
confirmed counterexample establishes it. Models do not prove the complete Rust
implementation, Malachite, MLS, signatures, SQLite or physical filesystem safety.

## Scope, constraints and decisions

| Target | Decision and reason | Boundary |
| --- | --- | --- |
| Rooms durable frontier | Steel thread: journal, snapshots, memory, acknowledgment and restart have distinct failure points | Preserve WAL and exact committed history; no consensus safety theorem |
| Native delivery custody | Adopt: durable attempt intent, uncertain outcomes, stop/reopen/resume and destination binding are absent from current models | Exact ciphertext retries; no automatic re-encryption, cancellation or liveness promise |
| Relay quota publication | Adopt as a separate small model: item/charge atomicity and stable credential identity differ from sender attempt budgets | Token replacement under one credential ID; no mailbox generation migration |
| Private-control authority | Adopt: handoffs, historical owner attribution and uncertain fork quarantine need combined coverage | Replica-local accepted history; no invented recovery or dead-owner authority |
| Additional Lean layer | Retain the earlier defer decision | This expansion concerns protocol state and implementation correspondence |

- Root owns this plan, shared registrations, assurance docs, KB catalog,
  workflows, Git and all external delivery waits. Workers own disjoint model,
  test and explicitly assigned production files. Workers never commit.
- Read repository instructions before edits. Preserve unrelated work, storage
  formats, protocol bytes, quotas, custody, rollback evidence and existing gates.
  All regression homes, credentials and traffic are synthetic and task-owned.
  No existing service, release, migration or deployment is selected.
- Use the installed host scheduler when available. Neither `oompa-host-run`
  nor `hra-host-run` exists in PATH or the standard installed binary directories
  on this host. Do not install a replacement. Raw focused TLC uses one worker
  and 512 MiB. One owner at a time runs Cargo against the shared target, with
  Rust 1.98.1 and `CARGO_BUILD_JOBS=4`; reasoning and disjoint editing continue.
- Use the existing digest-pinned TLC 1.7.4 and Java 21. Development runs are
  distinct from the final complete runner receipt. The runner must inventory
  every new module/config and retain named counterexamples for every mutant.
  Keep each case within its existing 120-second limit and the full CI job
  within ten minutes. Reduce dimensions explicitly rather than hiding bounds.
- Preserve checked-PR enforcement: independent source review, current main
  ancestry, complete `check`, all five CodeQL analyses and the separate managed
  `CodeQL` verdict. Conditional merge must not bypass branch policy.

## Phase map

| Phase | Outcome | Depends on | Write scope | Parallel with |
| --- | --- | --- | --- | --- |
| 0 | Selected targets and falsifiable source hypotheses | none | Root plan; read-only spikes | Three source investigations |
| 1 | Rooms model, reproducible regressions and bounded repairs | 0 | Separate model, rooms-consensus and rooms-node workers | Root integration; independent source/model review |
| 2a | Native delivery and relay quota models with real TLS compound trace | 1 model/targeted-regression join | Relay worker: `verify/native-delivery/`, `verify/relay-quota/`, native relay test modules | 2b; remaining phase-1 node diagnosis; root documentation |
| 2b | Handoff and fork-quarantine model with storage-fault traces | 1 model/targeted-regression join | Control worker: `verify/private-control/`, private-kernel succession tests | 2a; remaining phase-1 node diagnosis; root documentation |
| 3 | Complete inventory, assurance ledger and reviewed integration | completed 1, 2a, 2b | Root shared files; independent reviewers | Disjoint review slices |
| 4 | Exact-head checked delivery and main readback | 3 for merge; candidate CI may overlap final review | Root Git/PR and external evidence | CI lanes |

## Phase 0: Evidence-backed target selection

- **Status:** Done
- **Depends on:** none
- **Objective:** distinguish additional useful coverage from duplicate models.
- **Scope:** three read-only source/test investigations and root decision.
- **Out of scope:** whole-product proofs or adopting a required Lean toolchain.
- **Acceptance criteria:** each target has shipping symbols, bounded actions,
  properties, realistic mutants, concrete Rust correspondence and non-claims;
  distinguish confirmed defects from hypotheses and missing test coverage.
- **Validation:** independent source traces and review of existing six suites.

## Phase 1: Durable frontier steel thread

- **Status:** Done
- **Depends on:** 0
- **Objective:** acknowledgment implies the complete decided frontier is applied
  after durable journal/snapshot publication, including root-preserving batches.
- **Scope:** `verify/rooms-frontier/`, the existing `verify/rooms-held-reply/`
  admission boundary, `crates/vhalla-rooms-consensus/src/lib.rs`
  and its tests, `crates/vhalla-rooms-node/src/unix.rs` and focused host tests.
- **Out of scope:** changing consensus rules, deleting/resetting WAL, new store
  formats, or proof of the external engine's anti-equivocation implementation.
- **Approach:** separate journal, social/rooms snapshots, full memory frontier,
  ack and reopen. Include root-preserving transitions, exact redelivery and
  failures before/after publication. Reproduce the roots-equal shortcut hypothesis
  before repair. Independently trace the `Finalized` failure response: a local
  failed commit must not authorize an engine restart that resets retained WAL.
- **Acceptance criteria:** positive finite safety cases pass; deliberate early
  acknowledgment, roots-only reconciliation, unsafe failed-finalization restart,
  conflicting committed identity and wrong next-roster mutants violate their
  named properties. Real tests
  demonstrate exact full-frontier advancement and restart/readback, unchanged
  exact retries and rejection of mismatched decisions. Host-channel tests show
  only successful finalization advances to next-height parameters, while failed
  finalization emits neither a start nor a WAL-reset request. Repair only
  confirmed paths, retaining all recovery evidence. A local live proposal must
  retain current adapter admission after prior-height pruning; metadata refusal
  must not add a pending hold. Preserve the original held-reply contract.
- **Validation:** raw pinned TLC per new config; focused Rust regressions must
  fail before and pass after repairs; `cargo test --locked --all-features
  -p vhalla-rooms-consensus`; `cargo test --locked --all-features
  -p vhalla-rooms-node formal_finalized`; affected strict clippy and formatting;
  independent model/source review. Root registers and runs the complete runner
  once this steel thread converges before opening phase 2.

## Phase 2a: Exact retries and conserved quota evidence

- **Status:** Done
- **Depends on:** phase 1 model, targeted regression and source-review join;
  broader node qualification remains a required phase-3 convergence gate.
- **Objective:** connect sender attempt custody to real relay retention without
  conflating attempt allowances, transport quota and member acceptance.
- **Scope:** `verify/native-delivery/`, `verify/relay-quota/` and
  `crates/vhalla-private-native/src/relay/tls/tests.rs`; a focused delivery test
  sibling only if existing seams do not suffice. Root owns native README edits.
- **Out of scope:** generation migration, new cancellation/re-encryption APIs,
  quota resets, production transport hooks or delivery liveness claims.
- **Approach:** native model separates intent publication, transport outcome,
  local outcome commit, uncertainty, interruption/reopen, exhaustion and explicit
  resume. Count committed attempts minus durably classified outages. Relay model
  separates staged and durable item/charge state, stable credential ID, token
  replacement, exact duplicate position and receipt delivery.
- **Acceptance criteria:** positive cases and named mutants cover intent before
  transport, exact destination/bytes, preserved uncertainty, conserved spent
  attempts, checked receipts, atomic item/charge publication, duplicate charge
  refusal, stable-ID spend and durable retention before receipt. A real TLS
  trace loses an already-successful PUT response, reopens, replaces a token under
  the same ID, exhausts/rearms the sender budget and reconciles the same item at
  its original position with one charge. A new item still hits the original
  quota. Preserve the real endpoint identity across fixture restarts.
- **Validation:** worker-owned pinned TLC on all new cases; `cargo test --locked
  -p vhalla-private-native --features relay-tls,client formal_relay_`;
  `cargo test --locked -p vhalla-private-native --features relay-tls,client
  relay::delivery::tests::`; `cargo test --locked -p vhalla-private-native
  --features relay-tls,client relay::tls::tests::`; independent review.

## Phase 2b: Historical authority and durable quarantine

- **Status:** Done
- **Depends on:** phase 1 model, targeted regression and source-review join;
  broader node qualification remains a required phase-3 convergence gate.
- **Objective:** handoff preserves sequence-bound authority and uncertain fork
  publication never silently authorizes continued live work.
- **Scope:** `verify/private-control/` and
  `crates/vhalla-private-kernel/src/tests/succession.rs`.
- **Out of scope:** new owner-recovery authority, clearing quarantine, MLS proof
  or simultaneous agreement of disconnected replicas.
- **Approach:** two devices, bounded handoffs/controls, known history and a
  checkpoint case; exact/stale/future/foreign-owner observations; successful,
  refused and uncertain quarantine publication, reopen and live operation.
- **Acceptance criteria:** named mutants fail historical-generation attribution,
  pinned handoff, observation-only admission, unknown-history refusal, volatile
  fault custody and persistent quarantine properties. Real Kernel tests cross
  handoff with historical forks and `Before`, `After`, `HangAfter` storage faults;
  exact retries and precheckpoint/future proof observations retain their actual
  semantics. A precommit failure plus process loss may lose volatile observation
  evidence; neither model nor docs claim it was durably retained.
- **Validation:** worker-owned pinned TLC on all new cases; `cargo test --locked
  -p vhalla-private-kernel tests::succession`; focused existing `owner_fork`,
  `canceled_fork`, `missing_precheckpoint` and
  `observing_unsupported_owner_claim` filters; independent review.

## Phase 3: Complete reviewed assurance

- **Status:** Done
- **Depends on:** completed phase 1 node qualification, 2a, 2b
- **Objective:** every new claim has checked evidence and precise implementation
  correspondence in one maintained inventory.
- **Scope:** `verify/cases.json`, `verify/README.md`, `docs/verification.md`,
  native README drift, CLI recovery guidance, the formal-assurance note, this
  plan and KB catalog; workflow only if needed.
- **Acceptance criteria:** all existing and new configs are inventoried; all
  mutants fail the intended property, not a parser/runtime error; full receipt
  binds unchanged source/copy/log hashes. Independent reviewers inspect model
  validity, Rust transitions, failure reachability and non-claims. All findings
  resolved, including the expanded node-suite failures observed during phase 1.
  Existing required CI integration remains active for production edits.
- **Validation:** `python3 -m unittest discover -s verify -p 'test_*.py'`;
  complete `python3 verify/run_tlc.py --jar <pinned-jar> --java <java21>
  --out <new-owned-directory>`; focused affected tests and strict clippy;
  `cargo fmt --all -- --check`; `git diff --check`; Wordcell percolate, refresh
  and check. Root alone runs the final complete current-head CI aggregate.

## Phase 4: Repository delivery

- **Status:** Done
- **Depends on:** completed phase 3 for merge. After local aggregate checks,
  candidate PR CI may run alongside whole-feature review; neither gate is waived.
- **Objective:** integrate the reviewed expansion under the existing policy.
- **Acceptance criteria:** independent review, current-main ancestry, successful
  current-head complete aggregate and all required managed/security checks,
  conditional merge and exact merged-tree readback. No unrelated work submitted.
- **Validation:** retain branch, candidate SHA, PR, check conclusions, merge SHA
  and main readback; verify post-merge formal artifact attribution for the changed
  production paths. Release and service activation are not part of this scope.

## Recovery

All experiments and fixtures use fresh task-owned directories. Retain failed
traces and test logs. Revert task-owned source through normal review if needed;
never restore old user state, alter WAL markers or delete recovery evidence.

## Implementation log

- 2026-09-23, phase 0: three source spikes selected the four targets above.
  Existing six suites do not cover these boundaries. Rooms replay inspection
  found a roots-only acknowledgment hypothesis and traced a naturally reachable
  failed-finalization response to the pinned engine's WAL-reset operation.
  The adapter and host regressions must establish these before bounded repairs.
  Relay and control spikes found coverage gaps, not confirmed defects. The
  prior plan's documentation closeout merged as `1cff4f5` through PR #99 after
  all 70 current-head checks passed, including the managed CodeQL verdict.
  Phase 1 uses disjoint model, adapter and host-loop ownership; one Cargo owner
  at a time, with parallel reasoning/model checks.
- 2026-09-23, phase 1 regression gate: the real adapter tests failed before
  repair in three distinct cases: an acknowledged empty batch retained frontier
  height zero; a legitimate social-only journal publication could not reopen;
  non-genesis snapshots under an empty journal were admitted. The pinned,
  offline `formal_recovery` run returned exit 101 (three passed, three failed),
  retained in `/private/tmp/valhalla-rooms-formal-recovery-before.log`.
  Source review also confirmed that the pinned Malachite connector processes
  Decided and Finalized response waits independently and maps `Next::Restart`
  to a WAL reset. The bounded repairs remain under independent review.
- 2026-09-23, phase 1 functional join: independent model, adapter and host
  reviews passed. Seven adapter regressions pass within the full 31-pass suite
  (one existing diagnostic ignored), with strict clippy. Both host regressions
  failed their intended no-start/no-reset assertion before repair and pass
  after repair. The complete pinned runner passed all 37 cases in 62.55 seconds;
  all 84 attested inputs, 44 consumed copies and 37 log hashes were verified
  unchanged in `/private/tmp/valhalla-protocol-steel-20260923-a/receipt.json`.
  The independent review added an honest-recovery property and a fourth positive
  root schedule to avoid guarded-admission and second-height coverage gaps.
  The broader 87-test live-node run reported existing network-journey failures;
  its owner retains diagnosis and Cargo custody. Phase 1 remains in progress.
  Disjoint private-protocol model/test construction now proceeds after the
  functional join; these failures and final clippy remain required convergence
  work, with no delivery gate removed or weakened.
- 2026-09-23, phase 1 custody extension: the broader node run completed with
  76 passes and 11 timeouts. Failed-home inspection and a deterministic
  three-height host regression established a second host defect: earlier
  decisions prune future candidates from the adapter while their exact bytes
  remain retained, and local preparation did not restore the candidate. The
  regression failed at the third-height decision before repair. Preparation
  now validates the exact candidate against the current frontier and restores
  its hold only after durable metadata admission. A full-metadata negative
  test confirms refusal does not add a hold. The original held-reply model is
  extended with separate adapter admission and an omitted-admission mutant;
  retained bytes are no longer treated as proof of decision readiness. The
  four-validator journey now passes; full node qualification remains in flight.

- 2026-09-23, phase 1 convergence: the repaired full node suite passed all 89
  tests in 210.22 seconds, including all 11 previously failing journeys.
  Strict node clippy, the seven focused host tests, two forced-preparation
  tests and scoped formatting passed. The held-reply admission refinement
  passed independent source/model review; six checker cases completed, with
  the new `AdmittedBeforeReply` mutant failing at 17 generated / 14 distinct
  states. Its five retained counterexamples were refreshed against current
  model/config hashes. Full node evidence is retained in
  `/private/tmp/valhalla-formal-finalized-node-suite-green-raw-20260924.log`;
  focused model evidence is in
  `/private/tmp/valhalla-held-admission-20260924-a/receipt.json`.

- 2026-09-23, phase 2b join: both positive private-control configurations and
  all six named mutants passed their expected checker verdicts. The real
  succession suite passed 14 tests, including all four new handoff/fork-fault
  schedules; four existing historical-observation filters and strict clippy
  passed. The independent relay worker checked the source, copied inputs,
  all eight logs, six traces and Rust evidence without a blocking finding.
  Epoch/MLS state is explicitly outside the model, while the runtime tests
  assert unchanged epoch after observation. New-process reopen is distinguished
  from a latched live handle. Evidence is retained in
  `/private/tmp/valhalla-private-control-dev-20260924-b/receipt.json` and
  `/private/tmp/valhalla-private-control-rust-receipt-20260924.json`.

- 2026-09-23, phase 2a join: all 15 sender/relay model cases completed with
  expected verdicts, including an additional duplicate-position mutation.
  Source review narrowed the outcome-write action to precommit refusal:
  SQL COMMIT can precede a failed sync/readback, so retaining the old intent
  is not a generic write-failure guarantee. Postcommit barrier/readback failure
  is explicitly outside this model. Eight sender cases and their traces were
  refreshed after that clarification. Independent review checked all 15 logs
  and 11 retained traces against exact copied/current hashes. The compound
  real TLS test, all 16 delivery tests, all 17 TLS tests and strict native
  clippy passed; the only implementation adjustment was the new test fixture's
  page-record accessor. No private-protocol production defect was established.
  Evidence is retained in
  `/private/tmp/valhalla-relay-model-dev-20260924-d/receipt.json`,
  `/private/tmp/valhalla-relay-model-dev-20260923-c/receipt.json` and
  `/private/tmp/valhalla-formal-relay-rust-receipt-20260924.json`.

- 2026-09-23, phase 3 aggregate: all 61 registered cases across ten suites
  completed with their required positive or named-mutant verdicts. The root
  independently matched every source/input, copied-input and checker-log hash
  against the pre/post receipt. The complete evidence is retained in
  `/private/tmp/valhalla-protocol-expanded-20260923-final-a/receipt.json`.
  The 29 runner-boundary tests, whole-workspace formatting and full read-only
  administrative checked-PR policy audit also passed. No branch policy changed.
  Whole-feature independent review and KB finalization remain before delivery.

- 2026-09-23, candidate preparation: a fresh whole-feature reviewer owns final
  source/plan integration review. Its pass remains mandatory before merge.
  The root prepares the PR candidate after all local runtime/model gates so
  remote CI can run in parallel with that review. The full model run contained
  18 positive cases and 43 deliberate failures, totaling 65.19 seconds with
  no case above 5.69 seconds. All 141 attested inputs, 71 copied inputs and
  61 checker logs matched the final readback. No source/model changes are
  planned during review; any repair requires renewed affected evidence.

- 2026-09-23, current-main integration: the governed fetch found `aea7323`
  (site theme PR #100). Its eleven site/JavaScript files are disjoint from this
  expansion. The branch fast-forwarded to that main while retaining task edits;
  all 141 formal-attested inputs remained byte-identical. Candidate CI will
  run the complete required aggregate on the integrated tree. Wordcell
  percolation found no candidates; refresh and the normal catalog check passed.

- 2026-09-23, phases 3–4 complete: fresh independent whole-feature review
  passed without edits against `aea7323..be61ad7`, inspecting all 94 changed
  files and independently checking the complete formal and runtime evidence.
  [PR #102](https://github.com/hraness/valhalla/pull/102) passed all 70 checks
  on `be61ad72cdaef68ffca914c965b4bd80b6fba380`, including the complete Rust
  aggregate, all five analyses, and the separate managed CodeQL success
  from app 57789 with no new alerts. Conditional squash merge produced
  `ad317cad7bf2e7d747b1d0b4df556ae60e99a0b2` at 23:37:21 UTC. Its tree
  exactly matched the reviewed head; local main fast-forwarded cleanly.
  The fresh [post-merge formal job](https://github.com/hraness/valhalla/actions/runs/35934507800/job/107428401942)
  passed all 61 cases. All 141 source inputs, 71 consumed copies and 61 log
  hashes matched its pre/post receipt and merged source. The downloaded
  receipt SHA-256 is
  `c281cb4bca46b01d98d5705190616519540ddbfd07ad5b4d91984a465473a4bf`.

## Result

Delivered four additional bounded protocol models and strengthened the existing
held-reply admission model. The required inventory now checks ten suites with
18 positive cases and 43 deliberate failures. Real adapter, host-loop, TLS and
Kernel regressions connect the claims to production transitions; independent
phase and whole-feature reviews passed.

The rooms repairs preserve complete frontier advancement and compatible
snapshot recovery, withhold unsafe failed-finalization restart commands, and
restore exact local candidate admission after earlier-height pruning. The
private-protocol slices added coverage without production changes. Required
candidate CI and fresh post-merge formal evidence passed. Implementation branch
`codex/formal-protocol-expansion-20260923` was delivered through PR #102 as
`ad317ca`; the follow-up documentation records this completed state. No release,
service activation, data migration or production-data mutation was selected.

## Durable memory

- [[notes/formal-assurance|Formal assurance with implementation correspondence]]
  owns the reusable distinction between snapshot contents and full protocol
  progress, between durable retention and current admission, and between
  successful-admission checks and honest recovery reachability.
- The [assurance ledger](../../verify/README.md),
  [case inventory](../../verify/cases.json) and per-model source maps own the
  checked claims, bounds, mutations and implementation correspondence. These
  remain finite-model evidence, not a proof of the complete deployed Rust
  system. The evaluated Lean spike remains optional.
- The [rooms operator guide](../../crates/vhalla-cli/README.md) owns failed
  finalization and WAL-preserving recovery guidance. The
  [native relay guide](../../crates/vhalla-private-native/README.md) owns current
  outage, retry-budget, explicit-resume and quota behavior.
