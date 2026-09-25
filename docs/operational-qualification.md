# Local hosting and operational qualification

## The current setup

The development Mac can run native peers, isolated browser profiles and local
fault tests. `vhalla.com` is the existing Vercel static marketing/documentation
project: `vercel.json` builds `site/dist`. Neither the domain nor website
publication establishes that a Valhalla application peer or relay is running.

The selected first workflow runs on the user's Mac as a mostly persistent local
host. A dedicated service retains only opaque mailbox data; CLI agents and browser
workers retain their own custody. Tailcat can expose exact loopback service ports
using a saved key. Browser clients use a fixed forwarding port and stable origin.
No paid host or public DNS endpoint is required. Sleep, network loss and browser
suspension are expected outages, not authority to reset queues or custody.

Use synthetic accounts and rooms for qualification. Do not transfer the user's
real private stores, credentials, archives or browser profiles. Local process and
restart evidence qualifies this local use; remote Tailcat and independent-device
claims require separate measurements on that actual path.

Two machines can establish behavior when one participant disconnects. They do
not establish the four independent validator failure domains needed to qualify
a four-member Byzantine directory deployment. Record separately which machines
run clients, relays, publishing peers and validators; co-locating roles does not
create additional failure tolerance.

## Transport and persistence contracts

The public peer binds loopback behind an operator-owned TLS proxy and checks its
exact advertised HTTPS route and browser Origin. Preserve those restrictions.
The private relay has a maintained TLS service with scoped credentials and
durable quotas, plus a loopback-only reference socket and a directly accessed
mailbox directory. Use the dedicated `private-host` lifecycle for local hosting or the explicit
`relay-tls-serve` adapter for a separately operated listener. The TLS library
and fault tests do not establish a running public endpoint.

The maintained relay adapter establishes server identity before transmitting
credentials, binds the chosen namespace independently of a server response,
and bounds connection counts and total I/O time, enforcing per-credential and total
storage/work budgets. Credentials must have explicit scope and rotation rules.
It returns retention evidence only. A recipient's durable processing requires
separate authenticated acceptance evidence. Relay access never grants room
membership, plaintext access or authority to sign owner controls.

The durable delivery controller retains exact ciphertext and a durable job
identity before attempting transport. Retrying cannot invoke new encryption for
the same logical job. Backoff has finite work/time limits and cannot busy-loop
on malformed pages. A timeout leaves an uncertain delivery attempt, not proof
of refusal. Receiver acceptance, relay retention, locally queued output and
human reading must remain distinct statuses.

## Evidence packet

Every run should retain the following outside user stores. Avoid recording
tokens, private keys, message bodies, private room labels or membership in
ordinary operational logs.

| Evidence | What it establishes |
| --- | --- |
| Git commit, dirty-tree status, lockfile hashes, toolchain, build flags and artifact SHA-256 | The exact source and binaries exercised; a commit alone does not identify a dirty build |
| Host role, OS/browser version and pseudonymous machine identifier | Which participant performed an action; identifiers alone do not prove independent infrastructure |
| Separately reviewed provider/region/power/network placement | The actual failure assumptions; two processes on one host do not count as independent |
| Independently obtained bootstrap pin and full selected peer identity | The client's trust selection before dialing |
| DNS, certificate identity/expiry, HTTPS route and Origin/CORS observations | The deployed transport configuration actually exercised |
| Case start/end, exact fault boundary, observed durable state and cleanup outcome | Which operation was interrupted and what survived; a timeout alone is not a pass |
| File/packet commitments, monotone positions and authenticated receipts | Correlation without logging private contents; each receipt retains its actual claim |
| Peak disk/memory, byte counts, latency and configured bounds | Measured capacity for this run; do not extrapolate to arbitrary workloads |

Publish a success result only after assertions and owned-process cleanup pass.
Retain failed and interrupted results. Never repair a failed run by removing
anti-replay state, journals, WAL, retained intents or a used cursor.

## Qualification journeys

1. **Clean client:** start a new native account and fresh browser origin, select
   the independent bootstrap pin, discover and explicitly select a peer, post,
   and verify exact readback from the second machine. Repeat with the optional
   private client using a confidential invitation; public discovery must never
   receive its bootstrap or membership material.
2. **Offline catch-up:** stop the receiving client, retain traffic, restart with
   its original custody and catch up in bounded pages. Repeat with relay outage
   and a lost response after acceptance. Check exact retries and monotone
   cursor/evidence; do not claim recipient acceptance from retention alone.
3. **Process interruption:** terminate only a synthetic participant at selected
   pre-publication and post-publication/pre-reply boundaries. Reopen the exact
   state and verify either no commit or one exact retained commit. Include
   client, relay, native store and real browser worker/document lifetimes.
4. **Storage-full:** use an isolated bounded test volume or supported quota
   injection, never fill the shared development/production disk. Exercise write,
   sync and final-publication failures. Preserve last accepted state, ambiguous
   intent and exact retry output; uncertainty must stop further authoring.
5. **Partition and withdrawal:** make one synthetic path unavailable while
   another progresses, then heal. Record convergence or honest refusal under
   capacity/expiry constraints. For validator claims, separately test a real
   quorum/minority split with the required independent placements.
6. **Owner/device lifecycle:** exercise current successor handoff, removal,
   stale-control refusal, account-only restore and fresh-device rejoin. Restore
   history into a read-only archive; never reactivate its old ratchet. An
   unavailable predecessor must not be inferred dead from a timeout.
7. **Hostile transport:** wrong server, wrong namespace/token, oversized and
   malformed frames, nonprogressing pages, reordered/duplicated ciphertext,
   slow clients and quota exhaustion. Verify bounded resource use and that an
   authorized healthy client can still make the promised degree of progress.
8. **Different browser/device:** repeat account/archive recovery on another
   physical machine and browser implementation. A new Chromium profile on the
   same Mac remains a local fresh-origin test.

## Promotion decision

Use the repaired local implementation and focused tests to admit an experimental
artifact when its repository gates pass. Enable a deployed capability only
after its applicable journeys have current evidence. Keep failed or unrun
capabilities disabled and describe the exact missing result. A design model,
fake server, locally injected quota error, or verified website cannot substitute
for the corresponding independent deployed observation.

The selected first-use acceptance is existing CLI agents and browser sessions
using the local Mac host, durable private-room delivery and explicit bounded
synchronization. An independent machine is required for remote-path claims, not
for local artifact admission or first local use. Four independent validators are required only for the separate public
Byzantine-directory claim; a two-machine private workflow does not make that
claim. Likewise, existing CLI agents retain their ambient tools and configured
inference provider; their successful MCP use is not OS containment evidence.

The [22 September review](design-review-2026-09-22.md) tracks code repairs and
spikes. The [recovery policy experiment](../prototypes/device-recovery-policy/README.md)
records the dead-device authority constraint. The Mac is the selected first host.
Independent-host execution remains separate from the selected local-first scope.
A hosted browser gateway is not part of the product: the
[native-only plan](../kb/plans/valhalla-private-rooms-native-only.md) keeps every
relay and gateway on a participant's laptop or server.
