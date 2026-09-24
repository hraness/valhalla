---
type: plan
area: private-rooms
status: in-progress
---

# Dependable private rooms and the first collaborative pilot

## Outcome

Deliver the private-room roadmap selected on 24 September 2026: responsive
delivery, recipient joining through the relay, useful agent/browser exchange,
safe mailbox maintenance, and understandable owner/device recovery. The shared
acceptance journey is two agents and a human completing work in one private
room across interruption and a membership change. Independent-device results
require a selected second machine and observed evidence; local results retain
their actual scope.

Start at clean main `269299003ef4547dc4af3c4d844a8fa7731fafcb`. The existing
foundation includes MLS, authenticated delivery and member receipts, native and
browser stores, owner request review, a reusable `agent-launch` command, device
succession, read-only archives, and maintained TLA+/Lean checks. Reuse those
paths. The latest published release observed at planning is v0.2.3; source,
release content, local tests and independent-device tests are separate statuses.

The longer vision adds structured work, public social discovery integration,
portable skills and supported contained execution. This plan establishes the
private-room prerequisite and records concrete follow-on contracts; it does not
silently turn room text into executable commands or revive cancelled Platonik
or Dioxus requirements.

## Constraints and ownership

- Preserve private keys, live ratchets, original ciphertext, historical records,
  receipt positions, grants, spent allowances and uncertain-operation evidence.
  Use fresh synthetic identities and homes for tests; never clone live custody,
  reset a quota by deleting data, or turn an archive into an active sender.
- Confidential offer bootstrap and transport authorization remain explicit.
  A relay cannot authorize admission, choose a new endpoint or advance a trusted
  starting cursor. Joining and roster changes require exact reviewed context.
- Keep finite work, request, queue, byte and lifetime limits. A latency improvement
  must measure idle overhead and cannot starve unrelated credentials or PUTs.
- Implement drained generation rollover first. Undrained offline migration is a
  different contract. Preserve the current refusal until implementation and
  crash/reopen evidence meet the transition contract.
- Existing CLI agents retain their ambient host/provider authority. Test their
  actual tool use separately from deterministic MCP fixtures. Neither proves OS
  containment, provider privacy or human reading.
- Root owns this plan, manifests/lockfiles, shared CI, verification registration,
  KB catalog, cross-cutting documentation, Git, releases and external waits.
  Workers own assigned disjoint files and never commit. One owner runs Cargo
  against the shared target at a time; root schedules browser/native checks.
- No installed `oompa-host-run` or `hra-host-run` resolves in PATH or the
  standard binary directories at start. Do not install a substitute or bypass a
  denial. Use absolute Rust 1.98.1 tools and four build jobs. If a scheduler
  becomes available, use its documented command and lane.
- Deliver through `docs/main-policy.md`: independent review, current-main
  ancestry, required Rust aggregate, five CodeQL analyses and successful managed
  CodeQL verdict from app 57789, then conditional merge and tree readback.
  Release only through the repository's exact-artifact publication workflow.
  External qualification is required for corresponding operational claims;
  it does not erase useful source delivery when a second device is unavailable.

## Phase map

| Phase | Outcome | Depends on | Write scope | Parallel with |
| --- | --- | --- | --- | --- |
| 0 | Frozen contracts, source baseline and acceptance measures | None | Root plan; bounded source/design spikes | Three independent spikes |
| 1a | Responsive native delivery with measured idle cost | 0 delivery contract | Delivery worker: agent delivery driver, focused tests and performance runner | 1b, 1c |
| 1b | Authenticated recipient review and relay joining | 0 | Admission worker: kernel contact APIs, browser admission/session/codec/delivery and focused tests | 1a, 1c |
| 1c | Reproducible agent pilot and current readiness inventory | 0 pilot contract | Root: new pilot driver/tests and readiness docs | 1a, 1b |
| 2 | Joined local native/browser/agent journey | 1a, 1b, 1c | Root integration; independent reviewer | Focused review slices |
| 3 | Safe drained mailbox rollover | 2 contract; independent spike may start sooner | Assigned runtime worker; root formal registration | Owner-lifecycle integration where disjoint |
| 4 | Coherent owner/device/recovery workflow | 2 | Assigned product worker; root shared docs | 3 |
| 5 | Delivered artifacts and independent-device evidence | Local phase gates; external target selected for remote cases | Root delivery/qualification | CI and independent review |

## Phase 0: Contracts and acceptance

- **Status:** Done
- **Objective:** freeze implementable scopes without duplicating shipped work.
- **Approach:** compare shorter idle polling against bounded authenticated wakeup;
  specify a nonmutating response inspection and exact consent boundary; define
  late-join cursor authority and recovery; select a useful finite pilot task.
- **Acceptance:** owned files, API/data contracts, limits, failure cases and
  measurable results are recorded before dependent writes. Root resolves shared
  contracts. The second device/access route is requested from the user, not
  inferred from SSH configuration or an old runbook.
- **Validation:** current source and existing tests, no production mutation.

## Phase 1a: Quiet-room delivery

- **Status:** Delivered by PR110 (merged to main as `6cec817`, absorbed into
  this branch). The pilot keeps the adaptive idle backoff as the profile
  default (five to thirty seconds, reset by staged or applied work); its
  unconditional one-second poll was reverted before delivery, and the pilot
  claims no quiet-arrival improvement of its own. PR110's opt-in
  `mailbox_polling: "interactive"` profile policy and its single-message
  comparison own that claim; this branch's runner additions (`--quiet-samples`,
  the 30-second idle window with per-client bytes/connections and per-process
  CPU/RSS) are the tooling for the repeated equal-duration comparison the
  acceptance below asks for, which has not been run yet.
- **Depends on:** phase 0 delivery contract.
- **Objective:** reduce the measured 28.667-second quiet-arrival acceptance delay.
- **Approach:** choose the smallest measured improvement preserving transport
  and grant boundaries. Record repeated quiet samples and idle work, not a
  single observation labeled as a distribution.
- **Acceptance:** proposed quiet-arrival acceptance p95 below five seconds under
  the defined local workload; unchanged exact outcomes after outage/reopen;
  explicit idle request/CPU/RSS evidence; no starvation or authority expansion.
- **Validation:** `cargo test --locked -p vhalla-cli --features experimental-private
  --test private_agent_delivery`; focused driver tests; Python runner contract
  tests; exact-binary real-process quiet/load/offline runs. Report actual results
  if the target is missed rather than weakening it.

## Phase 1b: Recipient relay admission

- **Status:** Done locally; rerun on `8047ffd` after the PR110 merge. The
  production browser delivery qualification on that head records the
  recipient publishing its exact request through prejoin sync, reviewing an
  authenticated invitation after multipage discovery, refusing stale consent
  after sync/reload, then joining with live replay at zero and preserved
  connection spend (sixteen facts, same-machine synthetic identities; all 32
  owned children stopped, Chrome's closure observed through its private log
  file). Independent-device evidence stays in phase 5.
- **Depends on:** 0.
- **Objective:** after confidential bootstrap, review and explicitly join from an
  encrypted retained response without manually transferring that response file.
- **Approach:** kernel authenticates inspection; prejoin transport has limited
  explicit authority; consent binds request/response bytes, recipient, owner,
  validity and worker lifetime. Normal delivery starts from a trusted boundary.
- **Acceptance:** late join into an active three-member room, no prejoin plaintext
  history, postjoin traffic works, exact interrupted retry; changed response,
  context, roster or expired consent refuses without partial admission. Crash
  between join and connection publication has a recoverable exact state.
- **Validation:** focused contact/kernel tests, codec and admission tests,
  `cargo test --locked -p vhalla-private-kernel`; maintained browser tests and
  strict WASM checks; actual production worker/DOM journey at integration.

## Phase 1c: Useful pilot and accurate operating instructions

- **Status:** Done locally; rerun on `8047ffd` after the PR110 merge. The
  deterministic `agent-launch` pilot passes all nine cases on that head (four
  stages at relay positions 4/6/8/10, 35 owned children, none forced) and its
  mixed browser-plus-two-native-agents variant passes too (the mixed run
  records request, result, verified, human-review and completion stages with
  exact digests, `realModel: NOT_RUN`, `externalDevice: DEFERRED`); the one
  installed Codex run remains a single retained sample.
- **Depends on:** phase 0 pilot contract.
- **Objective:** reproducibly exercise read, prepare, queue, delivery and
  authenticated acceptance with the existing stable launcher.
- **Approach:** finite synthetic work exchange with exact expected results,
  durable restart and fresh grant generation. Separate deterministic protocol
  checks from selected real-agent/provider observations.
- **Acceptance:** attributable request/result exchange, current-artifact hashes,
  grant use, revocation and cleanup recorded; no status-only call described as
  collaboration. Readiness distinguishes implemented, released, locally tested,
  independently tested and unfinished. Correct stale receipt/launcher/Lean claims.
- **Validation:** focused pilot contract tests and a real CLI-process run. Real
  agent calls use explicitly selected synthetic input/provider boundaries and
  finite budgets. No secrets or raw fixture custody enter shared evidence.

## Phase 2: Joined private-room journey

- **Status:** Done locally; rerun on `8047ffd` after the PR110 merge. The
  production-artifact mixed pilot joins one browser owner and two native MCP
  agents through confidential offers and exact encrypted admission files,
  completes the statistics task, removes the reviewer with one-use review,
  applies the authenticated control offline, reloads, and delivers the
  completion under a fresh scoped grant while the original ciphertext, grants
  and claims stay byte-identical (three facts; 44 owned children stopped,
  including the removed member's refused send judged at its declared exit 1
  and three `direct-child` MCP receipts).
- **Depends on:** 1a, 1b, 1c.
- **Objective:** the pieces work together through the real user entry points.
- **Acceptance:** create/admit, exchange work, go offline, reopen, catch up,
  change membership, review/regrant and continue; wrong scope, expired authority,
  stale ownership and uncertain storage preserve work and refuse safely.
- **Validation:** focused worker evidence, converged strict Clippy/formatting,
  real production browser/worker qualification and native pilot, relevant TLA+
  cases and runner regressions, independent cross-boundary review, required CI.

## Phase 3: Drained mailbox maintenance

- **Status:** Done locally; rerun on `8047ffd` after the PR110 merge. The
  joined `--generation-pilot` run (local only; CI runs the mixed pilot without
  it) drains one browser owner and two native controllers to a common head of
  18, pauses all three durably, fences and cuts over the host through
  check/prepare/fence/cutover/recover, and reaches generation 1 with encrypted
  room state preserved, incoming starting at zero, cumulative client and host
  spend preserved and no additional allowance (82 owned children stopped);
  `independentDevice: DEFERRED`.
- **Depends on:** joined delivery/admission contract from 2.
- **Objective:** allow a room to move beyond a mailbox generation's capacity.
- **Approach:** follow the reviewed drain/fence/intent/cutover contract in
  `docs/private-rotation-contract.md`, correcting its stale description of the
  currently refused CLI first. Preserve predecessor reads and exact retries.
- **Acceptance:** native/browser clients select one recoverable successor;
  unchanged MLS state/ciphertext and prior spend, no lost or duplicate accepted
  work, explicit refusals for offline undrained clients and unknown final PUTs.
- **Validation:** tiny-capacity integration, concurrent old writers, stale tabs,
  every publication crash point, exact reopen and successor-substitution refusal;
  corresponding model/mutations and focused production regressions.

## Phase 4: Owner and recovery experience

- **Status:** Done locally; rerun on `8047ffd` after the PR110 merge. The
  production panel qualification passes twelve facts including the ordered
  removal envelope under the real clock and the account-authorized succession
  to the enrolled same-account device through one distributed owner control
  (review captures at 1280 and 390 pixels); the mixed pilot exercises removal
  with one-use review and reopen under a fresh grant. Missing-owner custody
  still offers only the supported alternatives.
- **Depends on:** 2.
- **Objective:** expose existing device, agent and recovery mechanisms coherently.
- **Acceptance:** owner can inspect devices and agent authority, revoke or review
  changed membership, distinguish account restore from read-only history and
  fresh-device admission, and perform a live-predecessor owner handoff. Missing
  owner custody offers only supported alternatives. No ratchet cloning or new
  unilateral dead-owner recovery is introduced.
- **Validation:** real native/browser journeys with fresh synthetic custody,
  preserved original state, negative authority cases and independent review.

## Phase 5: Delivery and independent-device acceptance

- **Status:** In progress. PR #115 carries the branch and left draft at
  `e985a80`; every local gate and the four real-Chrome qualifications passed
  on `8047ffd`, again on `c84f585` after current main (PR112, PR117) was
  merged in, and the Chrome qualifications and native pilot again on
  `b51d60b` after PR119 and the CodeQL-driven driver conversion
  (implementation log). Delivery follows `docs/main-policy.md`
  (current-head required checks, independent agent review recorded in the PR
  body, CodeQL, conditional merge). The second-machine cases stay deferred by
  the owner until the connection is ready; sleep/logout/reboot and the sparse
  soak have no selected target or window and are not claimed.
- **Depends on:** applicable local implementation phases and reviewed candidate.
- **Objective:** ship the source/artifacts and prove the selected external route.
- **Acceptance:** exact-current-head required checks, independent review,
  conditional merge, clean main and artifact readback. Run the selected second
  machine through `docs/private-device-qualification.md`; retain PASS/FAIL/
  BLOCKED/NOT RUN per case. Sleep/logout/reboot need a selected target and window.
  Run a separately budgeted sparse soak; 24 hours at one Hz exceeds current caps.
- **Validation:** repository merge/release gates; hashes and feature readback;
  independent native/browser delivery, outage/reopen and membership evidence.
  State any unavailable external acceptance precisely, preserving delivered work.

## Implementation log

- 24 September 2026: created the plan on
  `codex/private-room-pilot-20260924` from clean main `2692990` and began
  parallel contract spikes. A second-machine target/access route is pending
  user input; source implementation and local verification can proceed.
- Delivery contract selected: test one-second successful-empty polling while
  preserving network-error backoff to 30 seconds. This avoids occupying the
  relay's finite connection slots with waiting requests. Measure five baseline
  quiet arrivals and 20 candidate arrivals, each after 90 seconds idle; retain
  raw samples and censoring, exact outcomes, idle connection/byte counts and
  process CPU/RSS. The predicted increase from about two to 60 idle PAGE requests
  per client per minute is a cost to measure, not free responsiveness. Root
  authorizes an isolated exact-source baseline and gives the delivery worker
  sole Cargo ownership while other workers continue contract work.
- Recipient contract proposed for independent review: prejoin connections require
  initial cursor zero. A separate bounded discovery cursor locates authenticated
  responses; normal delivery stays at zero and replays every mailbox item after
  explicit join, including postjoin applications retained before the response.
  Kernel inspection and join share complete isolated Welcome validation.
  Worker-held one-use consent binds full context and exact response. A durable
  connection intent reconciles a committed kernel join after interruption without
  reusing lost consent for an uncommitted join. No kernel/relay format change is
  needed; browser IPC and delivery image versioning require compatibility tests.
- Pilot contract selected: four inert application stages (request, computed
  result, owner review, post-restart completion) through the existing
  `agent-launch` command. The deterministic fixture checks exact authenticated
  inbox and member-acceptance relationships, distinct bounded grant generations,
  retained work and final explicit removal. It is separate from actual installed
  Codex/Devin invocation and from independent-device evidence. The new pilot
  driver/test own separate files; runtime helper interfaces are coordinated with
  the delivery worker. Shared receipts are constructed from allowed fields only.
- Independent AI reviewer `lean_independent_review` confirmed the contracts with
  two required refinements: v4 discovery staging/index invariants are separate
  from ordinary delivery cursor/admission invariants; legacy prejoin images may
  convert only from unambiguous zero progress, retaining counters and evidence.
  Otherwise they refuse. Discovery authenticates candidates for the exact pending
  request and respects finite response capacity. Inspection must preserve the
  durable KeyPackage, and recovery must query authenticated joined identity rather
  than call the mutating join as a probe. These are mandatory implementation and
  regression criteria. Phase 0 is complete with those refinements.
- The user is handling the second-machine connection and explicitly deferred it.
  Continue implementation, local verification and artifact delivery. Remote-device
  qualification remains deferred until that connection is ready; do not request
  a target again or infer permission for remote/power changes. Root takes the
  separate pilot driver files while the two implementation workers proceed.
- Independent AI review of the kernel inspection subset found no blocking
  issue: the preview hydrates an isolated MLS provider and cannot publish or
  consume the durable KeyPackage. The committed-response query reads the
  authenticated joined hash, including after removal. Runtime tests remain
  assigned to the admission worker.
- The deterministic pilot passed against the frozen baseline `2692990` binary
  `dd90c90e644be499f0cb22dc6337ba9e27a1dfece019a49759ca69ed25f2763a`.
  Its nine cases cover four work stages, exact sender/operation/receipt joins,
  final inbox uniqueness, restart, old ciphertext and grant preservation,
  explicit removal denial, artifact identity and cleanup of 35 owned children
  with zero forced exits. Eight focused Python tests pass. Independent AI review
  identified five evidence gaps, all fixed and rechecked before this run.
  Registration without delivery leaves its claim unused; a delivery-enabled
  process correctly claims before its first driver effect. Raw fixture state
  stays in `/private/tmp/valhalla-private-pilot-baseline-20260924-1`; only the
  selected receipt fields are suitable for sharing. This is a baseline local
  deterministic diagnostic, not the final integrated artifact or a model agent.
- The first quiet diagnostic reproduced 28.829 seconds to acceptance. The
  initial diagnostic batch overlapped a candidate build and later hit the
  bounded resource-sampler deadline; preserve it and exclude it from controlled
  before/after measurements. Complete builds and the browser journey before
  the delivery worker starts its controlled measurement window.
- Phase 3 storage prerequisites are independently writable. The selected
  transition first inventories every required controller privately, drains
  inbound applications and their generated acceptance output to one common
  head, then durably pauses client mutation. The host conditionally fences that
  exact head; a changed head refuses. The fence preserves reads and exact
  already-retained retries permanently. Unknown or offline controllers refuse
  the drained-only pilot. Native successor baselines must identify predecessor
  output/control heads without inventing successor jobs; browser retained keys
  and stale-handle checks must bind generation and preserve the gateway origin.
- Storage ownership: `lean_independent_review` implements relay generation
  metadata and TLS quota ledger, root owns host/gateway integration and formal
  registration, `private_runtime_next` will own native controller generations,
  and `private_product_next` will own browser selection after admission joins.
  Explicit format upgrades make transitioned stores unreadable to old writers.
  A successor carries all stable credential IDs, including revoked IDs, their
  prior spend and cumulative allowance; extra finite allowance requires an
  explicit operator value. No automatic reset or source-only activation.
- A separate installed Codex 0.156.1 run with the configured `gpt-6-astra`
  completed `private_inbox`, `private_prepare` and `private_queue` for one
  synthetic statistics request. A fresh native controller then delivered the
  exact computed result and verified the recipient's acceptance. The run used
  normal configured approval controls and a read-only shell sandbox; it does
  not claim enforced provider isolation. Four checks passed, Codex exited zero
  and all 20 fixture children exited cleanly. Retained private evidence is
  `/private/tmp/valhalla-model-pilot-20260924`; its selected receipt distinguishes
  requested model/provider declaration from independent provider attestation.
- Native contact tests passed 19/19. Initial browser focused checks passed
  12 codec, 12 model and 28 engine tests, including active three-member replay
  and four cross-store publication crash points. Root review found a consent
  expiry gap across awaited intent publication; the worker added a fresh clock
  check immediately before join and a delayed-publication regression. File
  fallback now refuses any existing durable prejoin connection before kernel
  mutation, including a reloaded worker without a live delivery handle.
- The delivery candidate passed 39 CLI unit tests and ten integration tests;
  the existing 65-message recovery case missed its unchanged 30-second bound
  twice (57/65 and 49/65). The runtime worker will compare the exact frozen
  baseline and candidate in isolation before attributing the result or accepting
  the cadence change. Controlled latency measurements remain pending.
- Root registered an additional design model for controller completeness,
  generated acceptance drain, changed-head fence refusal and durable successor
  intent/archive/spend preservation. Its six targeted mutations remain pending
  actual TLC validation and implementation correspondence review.
- The focused generation model completed 11,720 distinct normal states with all
  eight safety invariants intact. All six deliberately weakened variants produced
  their declared counterexamples; those traces are retained as documentation.
  Evidence is in `/private/tmp/valhalla-private-generation-focus-20260924-a/evidence-host`.
  The initial sandbox run could not open TLC's JVM management listener; the
  same bounded command passed after automatic approval of loopback access.
  This remains a design model pending implementation correspondence review.
- Root independently reviewed the relay fence and cumulative TLS ledger plus
  twelve focused tests without a blocking source finding. Rust execution is
  queued after the delivery diagnostic. Browser integration identified that
  legacy delivery keeps shared attempts/bytes, unlike native split queues;
  controller receipts will explicitly preserve that distinction instead of
  inventing historical per-queue spend or observation counters.
- After the interrupted workers stopped, root revalidated the active branch and
  task processes, then resumed three bounded owners for native runtime, browser
  product/storage and host transition. No task-owned build or fixture remained
  running. The gateway now has source support for up to sixteen explicit
  namespace routes at one browser origin, with shared admission limits and
  distinct browser capabilities. An independent source review found no blocker;
  focused Rust tests remain queued.
- Browser storage review identified a cross-store race: checking a pause only in
  the session cannot fence a kernel publication in another tab. The selected
  fix compares the generation selector and pause bit inside the kernel image's
  IndexedDB write transaction. Pause atomically checks both images and upgrades
  the store format so an older application cannot reopen it as a writer.
- Shared Cargo artifacts invalidated an initial baseline/candidate recovery
  comparison: dependency files pointed at the working tree. Those observations
  are excluded. Separate targets rebuilt the frozen sources and both passed the
  existing 65-message regression with its unchanged 30-second catch-up bound
  (49.09 and 34.65 seconds total test time). The diagnostic receipts are under
  `/private/tmp/valhalla-private-delivery-diagnostic-20260924`. Runtime audited
  the separate release receipts against all 1,217 input hashes and their
  compiler logs; controlled before/after measurements remain pending.
- The frozen phase-1b snapshot passed 12 delivery-model and 29 engine tests,
  including the final single-page bound. Its production WASM build remains in
  progress. Main-tree generation storage and product changes are separate from
  that snapshot and require their own checks.
- Root independently reviewed the host transition, configuration selection,
  retained services, seven unit tests and real TLS test without a blocking
  source finding. Host Rust execution is queued. Retained services use only
  their originally enrolled identities; a post-transition credential must not
  enroll in a fenced predecessor. All credentials revoked in a retained
  generation require an enrolled replacement before the combined host serves.
- Keep the shared lifetime byte ceiling at 1 GiB for this first transition.
  Namespace rollover preserves spend and cannot remove lifetime exhaustion.
  Browser attempts have a separately explicit cumulative ceiling of 65,536.
  Multi-generation remote forwarding remains outside the deferred connection
  work; the existing Tailcat template selects one port.
- Root added an optional mixed pilot to the production browser driver: one
  browser owner and two native MCP agents share a statistics task, verify and
  review the result, stop, remove one device, reopen with a fresh grant and
  complete the task. Three evidence-contract tests pass; the actual integrated
  run remains pending. The deterministic fixture does not invoke a model.
- Main advanced to `fe630c3` through README and shared-palette dependency updates.
  Root fast-forwarded this branch before the final browser snapshot. Earlier
  isolated snapshots retain their original identity; current-head checks and
  release evidence must use the integrated tree.
- The native host unit suite passed 26 tests including private receipt
  inspection, and earlier real TLS host tests passed the generation journey:
  unchanged predecessor items, exact retries, carried quota spending and
  exclusion of later-enrolled credentials from the predecessor. The one old
  all-credentials-revoked wording assertion was repaired and its targeted rerun
  passed. Four gateway tests, four receipt-codec tests and three successor
  creation tests passed, including seven creation fault boundaries and macOS
  parent-alias handling without accepting a symlinked store leaf.
- Main-tree Python measurement and pilot contracts passed 36 tests. The mixed
  JavaScript pilot and generation receipt observers passed six tests. The first
  phase-1b production DOM run reached recipient review, then failed on an
  outdated wording assertion; the driver now matches the visible expiry text.
  That run is not a passing qualification receipt.
- The full native agent-delivery suite exposed test-observation problems:
  reading an in-progress marker, trying to acquire a live writer's lock and
  assuming an automatically generated acceptance already existed. Those fixes
  are confined to observation and synchronization. Its 65-message catch-up
  missed the unchanged 30-second limit in a concurrent debug run; the next
  focused run must diagnose this separately from the earlier valid isolated
  baseline/candidate results. No deadline or acceptance criterion is waived.
- Browser generation selection now guards both the session's captured selector
  before mutation and the IndexedDB publication transaction across awaits.
  Explicit owner removal and live same-account handoff require one-use review
  of the current enrolled device and membership. Focused tests, the current
  production artifact, and the combined three-controller rollover are in
  progress. The [maintenance guide](../../docs/private-generations.md) owns the
  command sequence, private inventory and known recovery limits.
- Claude took over the branch after the Codex thread stopped on its usage cap
  and checkpointed the uncommitted work, then merged main `a47fe86` (#109)
  as `9ab2530`. `delivery-pause` refused every checkpoint member: it paged
  encrypted controls from `Status::history_base`, which sits below the
  kernel's encrypted base for a member joined at a trusted admission
  checkpoint, so the kernel refused the first page as missing. The pause now
  pages from the device's retained wire-history base through the new
  `encrypted_controls_from(None, ..)` native API, exactly as the delivery
  driver does; it never accepts a relay-supplied checkpoint or reads below
  the joining floor. `private_agent_delivery` passes 12/12 with the fix.
- The unconditional one-second idle poll was reverted to main's adaptive
  backoff so this branch stays orthogonal to PR110, which proposes an opt-in
  `polling::Policy` and conflicts with the pilot in nine files; whichever
  merges second resolves textual conflicts. Phase 1a is handed to PR110 and
  `docs/private-runtime-readiness.md` no longer claims a shorter interval.
- The first current-head CI run (36037035228) failed only the browser
  production artifact, the `vhalla-cli` lane (the pause refusal above) and
  the site test's outdated readiness phrase. The browser failure was the
  mixed pilot's 390-pixel owner-removal review capture: the secret label
  (`Only for account <64 hex> · operation ..`) could not wrap, so the review
  overflowed the viewport. `#private-panel p, h3 { overflow-wrap: anywhere }`
  fixes it without changing any text. On the fixed bundle the production
  delivery qualification passed locally with all sixteen facts, including the
  recipient prejoin relay join with live replay at zero.
- With the overflow fixed, the local mixed pilot reached the owner's removal
  control export and then timed out silently. The panel retains at most eight
  blob downloads for thirty seconds each and refuses a ninth; the pilot's owner
  exports nine files (locator, two offers, two admission responses, the first
  control, two messages, the removal control) in about ten seconds, so the
  ninth click was refused and the harness waited for a download that never
  began. A slower diagnostic run whose ninth export came 32 seconds after the
  first passed, which confirmed the mechanism. The driver now waits for that
  exact per-document slot window before clicking any export and fails loudly
  on a refused export; the product limit is unchanged.
- The first local `--generation-pilot` run (not part of CI) failed its common
  drain after 120 seconds while every native controller already reported
  `applied` at the relay head with nothing pending. The owner's browser was the
  holdout: both natives were admitted through the exact file path, so their
  relay-published contact requests stayed retained as two local admission
  copies awaiting an owner decision, and the product's `drained()` predicate
  correctly refuses a transition while any retained bootstrap item is
  unresolved. The pilot now has the owner discard each duplicate copy
  explicitly before the drain, as an operator must; the mailbox and the
  predicate are unchanged.
- With the duplicate copies discarded, the joined generation pilot passed:
  three controllers drained to head 18 and paused, the host fence bound the
  exact transition, namespaces and head, cutover and recovery selected the
  successor, and the successor started incoming at zero with cumulative client
  and host spend preserved and no additional allowance. Its receipts, plan and
  fence are retained under the qualification output directory; the run is
  same-machine evidence and `independentDevice` stays `DEFERRED`.
- PR110 merged to main (`6cec817`) while this branch's cargo gates were
  running, so the gates were stopped and main was merged as `4ba579b` with
  nine textual conflicts. Resolution: main's `polling::Policy`, admission
  model, process guardian and two-Mac evidence win wherever this branch
  equalled old main; the branch keeps the generation module and `lineage`
  profile field, the pause paging fix, the download-slot wait, the drain
  discards and the pilot flags. The qualification driver now runs fixture
  commands and services under main's guardian (`spawnOwned`); the mixed
  pilot's `agent-launch` children stay direct children because the guardian
  gives its leader no stdin or environment and MCP stdio needs both, so the
  cleanup receipt records them as `direct-child`. The runtime measurement
  tool keeps the transparent meters, repeated quiet samples, idle window and
  frozen-source admission on main's integer CPU sampling and polling
  selection (the idle window reports `cpu_time_ns` and derived seconds; the
  float parser and its test were dropped). `verify/cases.json` is the union of
  both registrations: 12 suites, 78 cases. The readiness inventory merges
  both Lean sentences, takes main's partial two-Mac status and admission
  replay, and records that the pilot drivers leave `mailbox_polling` at its
  adaptive default. Fast gates on the merged tree: rustfmt, the five Python
  suites (69/5/16/41/4), the Node lifecycle/guardian/pilot suites (35) and
  the verify evidence tests (49).
- Post-merge cargo gates passed on the merged tree once `polling::Policy`
  derived `Serialize`: clippy `-D warnings`, the `vhalla-cli` lane (247
  passed, 3 filtered), the workspace doc tests and the no-default-features
  identity (7) and social (1) tests. Those no-default-features steps overwrite
  `target/debug/vhalla` without `experimental-private`, so the feature CLI
  must be rebuilt before any qualification; the first post-merge qualification
  attempt was refused for exactly that reason.
- The post-merge mixed and generation pilots failed at the removed member's
  refused send. The driver runs fixture commands under PR110's guardian, whose
  exit status is its own cleanup verdict: it treated only exit 0 as a normal
  self-exit, so a command expected to exit 1 failed cleanup; declaring the
  expected status made the guardian exit 0, which the driver then read as the
  command's exit. `spawnOwned` now passes `expectedExit` to the guardian, the
  cleanup receipt records the leader's real exit, `stopOwned` waits briefly
  for a receipt that lands after the exit event, and the driver's command
  helper judges `receipt.guardian.leaderExit`, never the guardian's status.
- The mixed run's Chrome cleanup then failed with `owned child stdio closure
  was not observed before cleanup deadline` after twenty seconds. A pipe
  watcher showed `chrome_crashpad_handler` (its own session) and four
  `GoogleUpdater --wake-all` processes holding Chrome's inherited
  stdout/stderr outside the owned group after every group member was gone.
  Lengthening the closure bound was rejected as weaker evidence. The guardian
  gained an `outputPath` launch option: it creates the file exclusively at
  mode 0600, hands the leader that file as stdout/stderr and keeps no
  descriptor, so no escaped descendant can hold the parent's pipes. The
  delivery driver launches Chrome with it, the panel driver opens the same
  kind of file for its direct Chrome child, and the retained `chrome.log` is
  that file. A descriptor probe confirmed the leader inherits neither the
  guardian's pipes nor its IPC channel. Chrome's flags are unchanged because
  PR113/PR114 showed the crashpad and debugging-address flags break the
  Linux runner. Three guardian tests pin the exit semantics, the escaped
  descendant with and without the file, and option validation.
- Independent review ran in three slices on the merged tree: browser product
  and storage (no P0–P2; three P3 notes), tooling/formal/docs (one P1, the
  expected-exit-1 failure above; P2: pin post-merge pilot runs to a commit,
  record the traffic meters' bounds and health; seven P3 notes) and native
  runtime/host (no P0/P1; P2: commit the `Serialize` derive; six P3 notes).
  Load-bearing native checks were verified rather than read: relay join
  admission, fence idempotence, cutover crash safety, TLS spend carry,
  client transition, successor profile rewrite, merge exactness and
  bound/secret handling. Fixed in `8047ffd`: the measurement fixture checks
  its meters before shutdown (a refused or failed connection fails the
  scenario) and names the bounds and the declared-not-verified frozen base
  in its receipt scope; idle-window processes with fewer than two samples are
  listed, not dropped; the pilot keeps a journey failure's label beside a
  final-check failure; the generation fence refuses a predecessor config
  without its CA digest instead of panicking; the delivery driver's second
  tab attributes downloads to its own frame. Recorded follow-ups, none
  blocking: `private-host serve` accepts a fenced predecessor without
  `require_idle`; the revoked-credential refusal wording names no remedy;
  legacy config canonicalization deserves a note in the maintenance guide; a
  takeover-admitted member has no `delivery-pause` regression of its own; the
  generation pilot hard-codes `/usr/bin/sqlite3` (local-only mode); the
  `inspect_contact_response` refusal probe reads a field it does not check.
- Full local rerun on `8047ffd` (24 September 2026, 21:29–22:11 UTC), every
  step exit 0: `cargo fmt --check`; `clippy --workspace --all-targets
  --all-features -D warnings`; the five Python suites (42/69/5/16/4); the
  verify evidence tests (49); the CI Node step (38); the `vhalla-cli` lane with
  CI's three live-mesh skips (24 test binaries, 247 passed, 0 failed, 3
  filtered); the workspace doc tests; the no-default-features identity (7) and
  social (1) tests; the `experimental-private` CLI rebuilt afterwards
  (`7cf1e90c…`); then, on that binary and a locally built Trunk bundle
  (manifest `546ddef6…`), the production delivery qualification (16 facts, 32
  owned children stopped, no cleanup failures), `--mixed-pilot` (3 facts, 44
  owned children stopped: the removed member's refused send at its declared
  exit 1 and three `direct-child` MCP receipts among them),
  `--generation-pilot` (3 facts; generation 1 at head 18 across three
  controllers; 82 owned children stopped) and the panel `--production`
  qualification (12 facts). Every cleanup receipt records Chrome's closure
  observed through its private log file. The deterministic `agent-launch`
  pilot then passed all nine cases on the same binary from a git-checkout
  build receipt (source commit `8047ffd`, tree `301129b`, native inputs clean;
  35 owned children, none forced). The other crate lanes ran on the merged
  tree `4ba579b`; `8047ffd` changes only `vhalla-cli`, the browser tools and
  the Python tools. `docs/performance.md` now names the meter bounds and the
  unrecorded repeated comparison. PR #115 leaves draft on the docs commit
  carrying this entry.
- Main moved again while PR #115 was leaving draft: PR112 routes launchd
  supervisor output to `supervisor.log` and rotates it at startup, PR117
  updates retired scheduler references. Merged as `f9959f1` with one textual
  conflict in `private_host.rs`: the branch acquires every generation's store
  before binding any listener, so main's `events::bound_supervisor_output`
  call now runs after the generation-service loop and before the bind
  retries, where main placed it relative to the service and the bind loop.
  One semantic conflict followed: PR112's test-only `launchd::test_config`
  predates `retained_generations`, so the merged test target did not compile
  (CI `quality` failed at clippy on `f9959f1`); `c84f585` adds the empty
  field. Full local rerun on `c84f585` (22:17–22:29 UTC), every step exit 0:
  fmt; clippy `-D warnings`; the `vhalla-cli` lane (24 binaries, 252 passed,
  0 failed, 3 filtered); doc tests (43); identity (7) and social (1) without
  default features; the rebuilt `experimental-private` CLI (`34cadd40…`);
  delivery (16 facts, 32 owned children stopped), `--mixed-pilot` (3 facts,
  44 stopped, refused send at declared exit 1, three `direct-child`
  receipts), `--generation-pilot` (3 facts, generation 1 at head 18 across
  three controllers, 82 stopped) and panel `--production` (12 facts) on the
  same bundle (`546ddef6…`), Chrome's closure observed through its log file
  in each; the deterministic `agent-launch` pilot 9/9 from a git-checkout
  receipt for `c84f585` (35 owned children, none forced). The generation
  pilot is the local exercise of the resolved serve path with retained
  generations; CI's browser job ran delivery, mixed pilot and panel on the
  same head.
- Main moved a third time (PR119 records the native-only deployment
  decision, docs and plans only); merged clean as `3f1cf59`. CodeQL then
  held PR #115 on two "improper code sanitization" findings (alerts 459 and
  462) in the delivery driver: page code assembled as a string with
  `JSON.stringify`-interpolated values (the download button id and the
  snapshot key suffix). Every input at those sites is a driver constant, but
  the pattern is wrong and the drivers already carry an argument-passing
  helper over `Runtime.callFunctionOn`; `b51d60b` makes the three
  interpolating sites in the delivery driver and the two in the panel driver
  pass the button id, input id, key suffix and expected count as call
  arguments, so no page code is built from data. Rust inputs are unchanged
  since `c84f585`, so the cargo lanes stand; the Node suites (38) and the
  five Python suites passed on the converted drivers, and the four
  real-Chrome qualifications were rerun on them (22:53–22:58 UTC, every
  step exit 0, driver hash `6caf30cf…` as committed): delivery (16 facts, 32
  owned children stopped), `--mixed-pilot` (3 facts, 44 stopped, refused
  send at declared exit 1, three `direct-child` receipts),
  `--generation-pilot` (3 facts, generation 1 at head 18 across three
  controllers, 82 stopped) and panel `--production` (12 facts) on the same
  bundle and CLI (`546ddef6…`, `34cadd40…`), Chrome's closure observed
  through its log file in each. The deterministic `agent-launch` pilot
  passed 9/9 from a git-checkout receipt for `b51d60b` on the clean
  committed tree (35 owned children, none forced).
