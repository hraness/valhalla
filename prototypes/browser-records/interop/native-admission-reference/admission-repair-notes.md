# Native WebRTC admission repair candidate

Disposable upstream fork only; no maintained adapter or public transport changes.
Candidate files: `work/native-webrtc-admission/src/tokio/{udp_mux,transport}.rs`.

The first candidate compiled and passed seven local tests on 2026-09-13. It
released all 96 declined source reservations plus four same-source retries;
recovered a full 32-entry table on owner drop; closed mux connections on owner
cancellation/expiry; rejected late get/register/remove calls against a new
same-key generation; retained a simulated promoted connection after releasing
its pending slot; invalidated held offers on listener close/drop; and yielded
after 32 polling cycles under a finite invalid-packet backlog.

The final candidate passed formatting, all 18 library tests (six existing plus
12 new), and strict library Clippy (`-D warnings`). Exact command, lockfile,
manifest, source, patch and toolchain identities are in
`admission-repair-results.json`; final source diff is `admission-repair.patch`.

Independent review of the initial candidate identified a promotion/reaper race,
a writer path that could send after cancellation/close, and source mixing before
ICE registration. The final candidate uses competing atomic CAS transitions,
scopes every writer to its current connection generation, validates queued writes
again immediately before UDP output, and checks the reserved source before ICE
buffer routing. Regression cases cover those boundaries plus current-generation
successful UDP output. The actual Incoming probe drops unpolled and polled
upgrade futures and successfully reoffers the same source afterward.

One intermediate transport test failed because its seven-byte synthetic ICE
password was too short for upstream validation; the corrected fixture uses a
32-byte credential and the actual upgrade remains pending until cancellation.
An intermediate strict Clippy run found a collapsible if; it was repaired before
the final gate. These are not suppressed failures. The final Clippy command
checks the library; the upstream standalone integration/smoke suite was not run.

Mechanism:

- At most 32 pending offers, 32 mux connections, 32 mapped addresses; ufrags
  must be nonempty and at most 256 bytes. These are experimental constants,
  not negotiated public protocol settings.
- Each incoming offer owns a non-clone Reservation. Its shared identity is an
  Arc allocation, and a shared atomic status marks Pending, Promoted or Cancelled.
  Sharing an ICE handle cannot prolong the owner: dropping the owner cancels
  Pending and wakes the mux. HashMap cleanup is bounded and happens on polling.
- An absolute ten-second deadline starts on the first reported packet. A timer
  wakes the listener to reap expiry, and the actual upgrade future races the
  same deadline. Replayed packets never extend it.
- A scoped ICE mux handle binds get/remove requests to the exact reservation
  allocation. Current connection identity is checked using Tokio watch receiver
  `same_channel`; a delayed old registration cannot mutate its replacement.
  A per-connection writer permit also travels with queued sends, rejects stale
  generations and closed listeners, and enforces the incoming reserved target.
  Copying each submitted UDP payload is capped at the existing 8192-byte MTU.
- ICE address registration alone does not authenticate anything. The incoming
  wrapper promotes its reservation only after the upstream Noise upgrade returns
  success, before the deadline. The success unit case models that boundary;
  it is not a real successful WebRTC handshake test.
- Cancellation/expiry retires only connections belonging to that reservation
  generation. Listener close clears pending state; dropping the mux invalidates
  held offers and closes its known mux connections.
- Mux polling has a 32-cycle budget and self-wakes on exhaustion. Closure is
  serviced first; all other command classes receive a turn each cycle.

Limits requiring further work/review:

1. No real successful browser/native exchange has run against this candidate.
   The active browser fixture continues using upstream native transport with
   its documented loopback-only restriction.
2. This bounds the inspected mux tables, not every buffer, queue, native task,
   ICE/DTLS/SCTP object or process RSS. `RTCPeerConnection` has asynchronous
   `close()` and no `Drop` implementation in the inspected webrtc 0.17.2 source.
   Cancelling upstream inbound futures may therefore need explicit lifecycle
   custody beyond reclaiming mux state. No task-leak or whole-process-memory
   claim is established by these tests.
3. The outbound path keeps its existing unscoped mux handle. Inbound generation
   tests do not prove same-ufrag late cleanup safety for locally initiated dials.
4. Pending expiry and success race on monotonic time/atomic state; this is a
   prototype with initial independent source review; it still needs repeated
   cancellation/close stress and a model/property test over interleavings.
5. Closing the shared listener is unavailable through a scoped inbound ICE
   handle; compatibility needs verification with all actual upstream teardown
   paths. This cannot be promoted as a transparent drop-in dependency fix yet.
6. A per-poll budget establishes cooperative yielding for the inspected loop,
   not an end-to-end latency bound. Saturated command queues, sustained mixed
   traffic, cap exhaustion, and authenticated workloads need joint evidence.

All packet probes use owned `127.0.0.1` UDP sockets, bounded finite sends and
one/five-second outer deadlines where appropriate; no Internet traffic. Test
manifests retain the previous offline diagnostic adjustments. Required heavy
validation runs through `/Users/bg/.bun/bin/hra-host-run`.
