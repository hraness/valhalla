# Private runtime readiness continuation

This continuation starts from `1cff4f5fc202b1a1a987d6ae52672188956774b0`.
Private rooms remain opt-in. Local qualification is not independent-device or
production activation evidence.

## Existing foundation

PR96 delivered bounded private delivery, encrypted membership-control forwarding,
recovery and browser qualification. PR98 added six maintained TLA+ suites with
26 cases and repaired a host recovery fence exposed by a counterexample. PR99
closed that formal plan. Kani checks production spent-nonce logic; Verus checks
a ledger reference implementation with sampled Rust correspondence. The Lean
weighted-certificate proofs now have a maintained required CI check and signed
Rust conformance cases. Their theorem applies to one fixed roster and signing
context under honest non-equivocation; it does not prove cross-round consensus.
See [formal rigor](../kb/plans/valhalla-formal-rigor.md) for exact claims and limits.

During this continuation, PR102 expanded the maintained inventory to ten TLA+
suites and 61 cases, including native delivery attempts, relay quota accounting,
private control admission and the rooms finalization frontier. Its production
repairs preserve rooms recovery custody and restore retained future candidates
before replying. This branch incorporates that main-line work; the earlier
`1cff4f5` measurement remains evidence for its original native build. See
[protocol formal expansion](../kb/plans/valhalla-protocol-formal-expansion.md).

These results do not prove operating-system durability, MLS cryptography, an
entire implementation refinement, or unbounded distributed liveness. Further
formal work should follow concrete protocol changes and failures, with an
independent production regression for each useful counterexample.

## Execution graph and ownership

1. **Complete — recover context and freeze contracts.** Resume from retained
   evidence and current main; preserve other active checkouts. No existing
   provider, identity, room or daemon state becomes a synthetic test fixture.
2. **Complete — parallel implementation.**
   - `private_rooms_audit`: browser private modules, admission codec and focused
     consent tests. Owner-side review of retained encrypted requests only.
   - `formal_strategy`: real-process Python performance runner, its unit tests
     and performance documentation. No production runtime changes.
   - Root integrator: production DOM journey, wire-version harness changes,
     build provenance, artifact qualification, review and final gates.
   These writers share one checkout with disjoint file ownership. Cargo writes
   and browser/native resource lanes have one owner at a time.
3. **Complete — local join and qualification.** Check codec/consent boundaries, production
   WASM build and real browser journey. Build an exact native candidate, run a
   small smoke fixture, then the bounded load, quiet and offline scenarios.
   Retain unsuccessful evidence as well as successful evidence.
4. **Complete — independent review and delivery.** PR101 merged as `4b08106`
   after its current-head checks passed. Its original browser and native
   component identities remain separate from subsequent source changes.
5. **Partial — independent-device qualification.** Two physical Macs completed
   native bidirectional delivery and stopped-member catch-up under a fresh
   grant. The [portable result](evidence/private-two-mac-native-20260924.json)
   binds the original native build and four exact application deliveries.
   A separate [production browser journey on Mac B](evidence/private-browser-mac-b-20260924.json)
   passed all 15 UI observations and confirmed owned process-group cleanup.
   Its browser identities and relay ran together on Mac B; cross-device browser
   transport, installed lifecycle and a real-duration soak remain open.

The next readiness change adds a retained-request admission model and real
cancellation and competing-publication regressions. Its [full model replay](evidence/private-admission-models-20260924.json)
passed all 71 cases across 11 suites. The new normal case explored 1,628,479
distinct states; eight deliberately broken variants produced their expected
counterexamples, and a separate witness demonstrated successful admission.
These are finite safety results under the documented assumptions, not a proof
of the complete implementation or production readiness.

## Frozen admission contract

IPC v7 adds retained-request review and separate confirmation. Review binds the
worker lifetime, exact retained position and ciphertext, complete room context,
epoch, roster and control floor, recipient account/device and bounded validity.
Confirmation rereads the retained item and checks the exact snapshot before
calling the existing admission operation. Consent is volatile and single-use;
every intervening request invalidates it. Rendering alone must not invalidate
the normal review-to-confirm path.

The panel shows full scope before confirmation. Wrong recipient, expired offer,
stale state and changed retained bytes must refuse without admission. No
automatic acceptance or broader relay authority is introduced. Recipient-side
prejoin transport needs a separate kernel inspection/transport contract and
continues through the explicit file flow in this slice.

## Runtime qualification

Use real CLI processes and fresh synthetic homes, distinct bounded credentials,
explicit grants, pinned loopback TLS and retained evidence. Do not substitute
the in-process benchmark for current controller behavior.

| Scenario | Workload | Required evidence |
| --- | --- | --- |
| Smoke | Two exact messages | Setup, delivery, acceptance and safe process cleanup |
| Scheduled load | 100 distinct 128-byte messages at 1 Hz; at most 16 outstanding; 120-second drain | Offered/admitted/accepted counts, missed schedules, censored samples and exact final set |
| Quiet arrival | Drained setup, 90 seconds idle, one message | Separate latency including adaptive polling |
| Offline/reopen | Recipient stopped, 32 retained messages, explicit fresh grant and reopen | Authenticated-ready/catchup bounds; exact committed set and acceptance after another reopen |

Record source, lockfile, harness and binary hashes, exact grant/quota bounds,
monotonic observations, sampled RSS and disk allocation. Observation timestamps
are bounds, not invented internal event times. An exploratory acceptance p95
under five seconds is distinct from correctness and may fail honestly.

## Remaining production decisions and gates

- Quiet-arrival latency remains a measured gap: after 90 seconds idle, one
  message took 28.67 seconds to observed acceptance. The 100-message 1 Hz run
  passed correctness with no missed slots and 4.27-second acceptance p95.
  Investigate wakeup or bounded long-polling before promising the same latency
  after idle; preserve explicit authority and resource limits.
- Native delivery and offline catch-up passed across two physical Macs on one
  LAN. The Tailcat path was not classified as direct or DERP; cross-device browser and
  separate transport-fault cases remain unrun.
- A sparse 24-hour soak requires a real elapsed run and explicit grant handoffs.
  A 24-hour 1 Hz run and 10,000-message single-mailbox run exceed current bounds.
- Mailbox/credential rotation is modeled and gated; seamless migration is not
  implemented. Preserve capacity refusals and retained recovery evidence.
- Recipient-side retained response review/prejoin delivery remains a separate
  scoped contract. Device transfer, rollback resistance and browser background
  persistence retain their documented limitations.
- Production activation needs relevant operational evidence and exact artifact
  identity; finite proofs and local passing tests alone do not establish it.

## Local join evidence

Six admission-focused tests (five new plus the existing third-member case), all
14 codec tests, both WASM binaries under strict Clippy, formatting and all 69
delivery/security policy tests passed. Independent review found no remaining
blocker after fixing observer pagination, cleanup bounds, censor timestamps and
complete owner-scope assertions.

The production-feature Mac browser journey passed 15 checks, including actual
worker consent invalidation after sync, explicit re-review, queued-message/control
ordering, authorization failures, reload and competing tabs. Its verified asset
manifest is `c37ab9ef3cb6ba6491ceef15097564b2b629d653fe4dac2c32f6e77f19d95b2a`.
This local pre-PR build is bound to retained source-input hashes; it is not a
clean-head release attestation. CI must qualify its own current-head artifact.

The real-process smoke passed 2/2 exact messages and clean subprocess shutdown.
The complete fixed workload passed 133/133 messages with no censored records;
all 63 owned CLI processes exited cleanly. Offline catch-up retained all 32
exact messages and authenticated acceptance claims across additional recipient
and sender reopens. All claims were observed within 12.00 seconds after the
first recipient reopen. The runner's 18 contract tests passed.
See [runtime measurements](performance.md#actual-private-cli-process-measurement)
for the frozen runner, candidate and completed workload results. Required
current-head CI, final delivery status and independent-device gates remain
separate from these local checks.
