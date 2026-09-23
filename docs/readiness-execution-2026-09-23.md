# Readiness execution record — 23 September 2026

Status: integration candidate on `codex/readiness-formal-plan-20260923`, based on
`ba00721c07078f5e5aca3bd879941287a417c0b7`, in the recovered
`/private/tmp/valhalla-steel-20260922` checkout. This records local validation
before required current-head CI; it is not a release or installed-service
promotion receipt. Focused results below were
obtained while the integration tree was evolving; final current-tree gates
remain required. Existing user custody and installed services are unchanged.

## Current lane outcomes

| Plan item | Implemented work and focused evidence | Remaining gate |
| --- | --- | --- |
| R1 browser retryable gaps | Bounded exact durable deferral, fetched/resolved frontiers, restart and missing/tampered-item refusal. Codec 11, model 10 and engine 17 tests pass, including 64-case stateful testing; both WASM binaries check cleanly. Production build/package, panel and delivery qualification pass. | Final integration. Finite deferral exhaustion may still prevent progress; no unbounded liveness claim. |
| R2 automatic controls | Separate encrypted-control transport tag 9 and native/browser streams, authenticated local history, exact retry, explicit native upgrade. Existing tags 1–8 retain meaning. Real browser-engine and production DOM third-member/causal-order journeys pass. Eleven native TLS cases pass, including 65 future messages, corrupted markers, partial-replay restart, bounded receipt staging, missing upgrade evidence and preserved legacy queue refusal. | Final aggregate remains pending. |
| R3 generation transition | Drained-transition ADR and finite model, including separate retention/receipt and frozen predecessor head. Ordinary host `rotate` now refuses before mutation. | Host fencing, controller migration, cumulative allowances, crash qualification and offline-device drain. No migration support or 10,000-message rollover claim. |
| R4/R5/R6/R13 host lifecycle | Persisted intended TTL; strict CA boundary; repeated recoverable sealed restoration; maintenance lock; revoke/replace preserving quota identity; version-2 selection. Final focused host unit 13/13 and process 10/10 pass, including rotation refusal. | Integrated gates and real-device lifecycle. Legacy v1 renewal requires explicit original lifetime. Credential change takes effect at service restart. |
| R7 browser receipts | Verified accepting-device/recipient-position UI, IPC v6 and bounded progress/refusal state; exact acceptance survives reopen in engine regression and passes the production DOM journey. | Lifetime attempt/byte continuation remains finite, with no automatic allowance reset. |
| R8 gateway | Connection-local unwind is isolated; upstream/shared-budget uncertainty stops admission and fails closed. 16/16 HTTP tests pass. | Actual CLI in-flight PUT, SIGTERM drain, restart and exact duplicate retention pass in the host process suite. Supervisor/independent-device lifecycle remains separate; no injected physical-fsync interruption claim. |
| R9 independent device | User selected a second Mac and received a setup handoff prompt; waiting for its machine/directory/SSH readiness report. | Exact candidate artifact, independent physical path, wrong identity/credentials, catch-up and sleep/wake/logout/reboot receipts. |
| R10 performance | Existing baseline and proposed workload targets retained. | Current-path latency/RSS/disk measurements and 24-hour soak. No new performance claim. |
| R11 formal foundations | Four TLA+ models, known-bad mutations, checksum-pinned tools and required reusable CI integration. Verus reports 13 verified, 0 errors. Ledger production/reference conformance passes 2 tests including 64 generated histories. | Final integration CI and continued model/code correspondence review. Lean deferred with rationale; no Lean proof claimed. |
| R12 checked-PR policy | Independently reviewed main-only ruleset 23889123 created; full administrative readback passes with no bypass actors. Read-only CI drift audit and four negative/positive tests added. | Current-branch CI execution; retain full admin readback because the public API hides bypass actors. |

The final native delivery suite passes 11/11 real TLS cases and 10/10 nested
delivery/recovery unit tests. Independent source review found no remaining
blocker after all three final regressions reproduced before repair. Formatting
and diff whitespace checks pass. The production browser delivery journey passes
all 13 receipt facts, including offline third-member admission, causal ordering
and verified acceptance in the DOM. Strict workspace Clippy passes with all
targets/features and warnings denied. The first aggregate attempt found an old
relay-kind match in the benchmark; the repaired application-only benchmark
retains its narrow scope. Marker comparison lint repairs preserve canonical
JSON strings, with 10/10 recovery units and the real TLS replay case passing
again. The complete current-head CI remains the final integration gate.

## Review findings incorporated during implementation

- Unconditional control-first transport can strand an older queued application
  after a membership epoch change. The real browser regression first failed on
  that ordering. Both clients now merge by epoch metadata from authenticated
  committed artifacts: older local applications, then their owner's control,
  then new-epoch applications. This is sender-local ordering; independent remote
  controls can still make previously unsent old-epoch work stale.
- Native control `Policy` refusals now halt rather than being marked terminal
  skipped, matching browser authority behavior.
- Native upgrade now atomically publishes a version-2 selected profile. Old
  binaries reject that profile before networking. Deliberately restoring an
  older profile or coherently rolling back custody is not protected by this
  selected-profile version barrier.
- Repeating an upgrade of an already selected v2 profile could recreate missing
  control evidence. It now validates the selected evidence and refuses if the
  control directory or activation marker is missing. Interrupted v1 activation
  can still recover before selecting v2.
- Newly issued receipts could bypass monotone outbox capture and let a control
  overtake an older application at small queue capacity. Receipt issuance now
  commits only to the kernel; ordinary catch-up stages every output in order.
  A real TLS regression and a separate TLA+ counterexample cover this defect.
- An upgraded v1 queue may already contain a receipt beyond its monotone scan
  frontier. The driver now refuses that preserved state before any network
  publication without changing attempts or custody. The regression also checks
  that a valid next-item enqueue interrupted before checkpoint publication
  still reconciles and progresses normally.
- Restored native applied markers were trusted by filename without rechecking
  their contents. Bounded exact-item and semantic revalidation now refuses corrupt markers and
  preserves the durable checkpoint during partial replay. The TLS regression
  confirms replay creates no new kernel inbox/outbox record.
- The rotation model initially permitted new storage after fencing. Separate
  `Store` and receipt `Retain` actions now permit only already-stored exact
  reconciliation after fencing, with a frozen-head invariant.
- The TLC runner originally accepted any nonzero mutant exit with matching
  text. It now requires the pinned checker's completed invariant-violation
  exit 12; signal/internal-error/partial-output tests pass 3/3.

## Formal evidence

The [assurance ledger](../verify/README.md) maps claims to production functions,
assumptions and implementation tests. These models do not verify cryptography,
physical persistence, arbitrary process counts or the complete Rust program.

The complete local model run at
`/private/tmp/valhalla-formal-models-20260923-8/receipt.json` completed 15 cases:
delivery normal 1,444 distinct states with conditional eventual resolution;
capacity-one 8 states with safety only; rotation 61 states; publication 688
states; sender egress 7 states; and ten expected named invariant violations
with exit 12. Saved
counterexamples are committed alongside model sources. Earlier parser/tool
failures remain in their evidence directories and are not successes. The
runner's strict completion classifier passes its three negative/positive tests.
A portable receipt copy is retained in [repository evidence](evidence/private-models-20260923.json).

Verus used release `0.2026.09.13.671956e` and the explicitly selected Rust 1.98.1
toolchain. TLC used digest-pinned 1.7.4 and a checksum-verified Java 21 runtime.
All new downloads are task-owned under `/private/tmp/valhalla-formal-tools`;
the runner itself performs no download. Lean is deferred because this
increment's main risks are concurrency/recovery and Rust correspondence, not a
missing mathematical theorem library.

## Join and delivery gates

Workers own focused evidence; one integration owner runs aggregate checks after
the tree converges. Cargo writers share one retained target serially. Heavy
work remains under the host scheduler; a queued check is not a failed check or
permission to bypass scheduling.

Next join: native/browser causal ordering, three-member offline catch-up,
version refusal, exact restored evidence, host rotation refusal and production
browser qualification. Then complete formatting, lint, workspace/feature/doc
tests, security/Kani/Verus/model checks, package/site/desktop gates and independent
integrated review through the required current-head CI. Experimental artifact
admission remains separate from a local or independent-device pilot. A 24-hour
soak and unavailable second-machine lifecycle evidence cannot be replaced by
model checking or simulated elapsed time.

The production browser package at
`/private/tmp/valhalla-browser-readiness-20260923-h8aq_6fa` contains ten assets
with manifest SHA-256
`31075ce2fa8be1d9dd64ebdca5dd64759ee9d7f1d4634b4045ab9072b6e0de00`.
Its production panel receipt (`panel-1/receipt.json`) records three synthetic
contexts, zero network writes and viewport checks at widths 390, 768 and 1280.
The exact packaged delivery journey (`delivery-1/receipt.json`) passes against
the repaired native CLI, with all owned Chrome/gateway/TLS children cleaned up.
The [portable browser evidence](evidence/private-browser-20260923.json) retains
the checks and exact receipt hashes without generated credential files.
The complete qualified package is preserved under `production-artifact/`;
tracked `browser/dist` was restored to its baseline because maintained CI
rebuilds, qualifies and uploads the production package from source.

Repository delivery/security Python regressions pass 69/69 with Homebrew Python
3.14.6. An initial invocation used Apple Python 3.9 and failed because the
existing suite requires `tomllib` and `hashlib.file_digest`; no production code
was changed to mask that toolchain mismatch. CI workflow YAML parses cleanly.
