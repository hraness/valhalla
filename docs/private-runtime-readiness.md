# Private runtime readiness continuation

This continuation started from `1cff4f5fc202b1a1a987d6ae52672188956774b0`
and merged in PR101 at `4b08106`. The implementation and local measurements
below describe that delivered change. The active follow-on work is the
[private-room pilot plan](../kb/plans/valhalla-private-room-pilot.md).
Independent-device qualification is deferred while the user prepares the
connection. Private rooms remain opt-in.

## Existing foundation

PR96 delivered bounded private delivery, encrypted membership-control forwarding,
recovery and browser qualification. PR98 added six maintained TLA+ suites with
26 cases and repaired a host recovery fence exposed by a counterexample. PR99
closed that formal plan. Kani checks production spent-nonce logic; Verus checks
a ledger reference implementation with sampled Rust correspondence. The Lean
weighted-certificate trial became a required CI check in PR105. It checks 24
theorems and a shared conformance corpus consumed by both Rust verifiers; it
does not prove their complete implementations. See the
[Lean trial](../kb/plans/valhalla-lean-assurance-trial.md).
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
4. **Complete — independent review and source delivery.** PR101 merged after
   its current-head checks and independent review. Release artifact identity
   and operational tests remain separate from source delivery.
5. **Pending external qualification.** Bind the second-Mac instructions to the
   qualified candidate. Run separate-machine pinned-relay/Tailcat and
   sleep/wake/reboot qualification when that machine is identified and ready.

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

## Follow-on work and remaining operating tests

- PR101 established the quiet-arrival baseline: after 90 seconds idle, one
  message took 28.67 seconds to observed acceptance. The 100-message 1 Hz run
  passed correctness with no missed slots and 4.27-second acceptance p95.
  The pilot implements a shorter idle polling interval. Its repeated comparison
  must include idle connections, bytes, CPU and memory before claiming an
  improvement; the original numbers remain evidence for the PR101 binary.
- Independent-device and remote-path qualification is not yet run.
- A sparse 24-hour soak requires a real elapsed run and explicit grant handoffs.
  A 24-hour 1 Hz run and 10,000-message single-mailbox run exceed current bounds.
- [Drained mailbox rollover](private-generations.md) is implemented in the active
  pilot. Joined browser/native testing and delivery are still tracked there.
  Offline undrained migration remains unsupported; preserve capacity refusals
  and all transition records.
- Recipient-side retained response review and prejoin transport are implemented
  in the pilot and awaiting its production browser journey. Device transfer,
  rollback resistance and browser background persistence retain their documented
  limitations.
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
current-head CI and source delivery completed in PR101. Published artifact
identity and independent-device results remain separate from these local checks.
