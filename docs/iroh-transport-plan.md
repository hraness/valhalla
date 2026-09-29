# Iroh for private rooms

Status: implemented in the source checkout, assessed 28 September 2026.

Iroh fits Valhalla's private-room transport. A stable endpoint public key and
QUIC connections with relay fallback replace manual IP selection, certificate
exchange and Tailcat forwarding for new private hosts. The owner still runs
the mailbox; its availability and storage limits remain the owner's concern.

## Decision

Make iroh the default for new private hosts. Keep explicitly selected TLS for
operators using direct TCP listeners and the existing generation-transition
tools. No compatibility migration is required for this work, and existing
private state is never reset or rewritten automatically.

Iroh carries the existing opaque mailbox requests. MLS room encryption,
membership, durable storage, token permissions, credential quotas, exact
ciphertext retries and recipient acceptance keep their existing semantics.
An iroh relay forwards encrypted transport traffic; it is separate from the
owner's Valhalla mailbox, which retains room ciphertext while members are away.

The public room directory uses Malachite's libp2p network for gossip,
discovery, validator proofs and consensus synchronization. Replacing that
stack requires a separate network implementation and consensus qualification.
The browser keeps its same-origin loopback gateway; its native upstream uses
iroh. Browser storage and origins do not change.

## Shared contract

- A strict endpoint record contains the pinned endpoint public key, one
  optional HTTPS relay URL and bounded direct address hints.
- Delivery identity binds endpoint key, mailbox namespace and protocol. A
  changed routing hint does not invalidate queued work; a changed identity
  cannot silently receive it.
- Credentials are transmitted only after the endpoint's authenticated
  handshake. Endpoint identity grants no mailbox or room authority.
- Both transports use one durable admission implementation. Its in-flight
  guard survives until the response write finishes.
- Global connections, per-peer connections, stream counts, frame sizes and
  deadlines have finite limits. Endpoint keys do not prevent Sybil attacks.
- Synchronous client calls use an owned runtime and work inside the CLI's
  asynchronous runtime. Construction validates selection without dialing.
- Direct-only tests disable relay use. Relayed tests must record the path
  exercised; local UDP success is not remote-network evidence.

## Execution and ownership

| Phase | Owner | Scope | State |
| --- | --- | --- | --- |
| Assessment and shared design | Root plus three research agents | Existing transports, iroh API, security and delivery gates | Done |
| Native transport | `/root/iroh_research` | `crates/vhalla-private-native`, shared service and client, transport tests | Implemented and tested |
| Host lifecycle | `/root/private_assessment` | `private_host.rs`, `private_host/`, host tests | Implemented and tested |
| Client integration | `/root/rooms_assessment` | Private commands, invite/join, durable agent delivery, gateway and client tests | Implemented and tested |
| Integration | Root | CLI manifest, lockfiles, documentation, journey checks | Joined and tested |
| Independent review and delivery | Root and independent reviewer | Complete diff, required CI, PR and merge evidence | AI review complete; GitHub enforces `Required` before merge |

Writers share one checkout on `codex/iroh-transport` and own disjoint paths.
The native API is fixed before integration. The root owns dependency resolution
and the final aggregate; focused commands have one owner and are not repeated
without changed inputs or missing evidence.

## Acceptance

1. A new host starts with iroh without issuing certificates or requiring a
   public listening address. Its private endpoint key survives restart.
2. Invite/join, queued agent delivery and the browser gateway select the same
   pinned endpoint and retain all room and credential checks.
3. Real local endpoints demonstrate PUT, PAGE, held-page wakeup, retries,
   shutdown/restart and wrong key, token and namespace refusal.
4. Persistent credential quotas survive reopen and token replacement. Invalid
   or oversized streams cannot bypass admission or allocate unbounded memory.
5. Existing TLS paths pass their focused regressions. Unsupported iroh
   generation-transition operations fail before changing state.
6. Formatting, Rust lint, affected tests and dependency audit pass. The
   repository's complete `Required` CI check admits the PR before merge.
7. Report source identity, checks and delivery evidence separately from any
   unperformed independent-machine or NAT qualification.

## Sources

- [Iroh documentation](https://docs.iroh.computer/): endpoint identity, direct
  connectivity and encrypted relay transport.
- [Iroh crate](https://docs.rs/iroh/1.2.0/iroh/): pinned version 1.2.0,
  endpoint and stream APIs. Its declared minimum Rust version is 1.91.
- [Minimal endpoint preset](https://docs.rs/iroh/1.2.0/iroh/endpoint/presets/struct.Minimal.html):
  selected to avoid public endpoint discovery. The configured relay is explicit.
- [Pinned relay defaults](https://github.com/n0-computer/iroh/blob/v1.2.0/iroh/src/defaults.rs):
  source of the default North America east relay URL.
- [Current transport contracts](operational-qualification.md) and
  [main delivery policy](main-policy.md): local acceptance and required CI.

## Local qualification, 28 September 2026

Rust 1.98.1 was used for the local checks. The complete CLI target set compiled.
Workspace formatting and Clippy (`--workspace --all-targets --all-features
--locked -- -D warnings`) passed. All 42 runtime measurement contracts passed
under Python 3.14.7. The TLS prototype's existing lockfile still resolves.
The affected CLI suites passed: 160 binary unit tests, 15 agent delivery tests,
13 host tests, two iroh lifecycle tests, 21 private-room tests and all three
two-agent journeys. The iroh journey exchanged messages and signed recipient
receipts, queued work during an outage, restarted the host, opened fresh agent
grants, recovered exact jobs and refused a wrong mailbox credential.

The native package passed 174 unit cases and 15 integration cases. The new
HTTP gateway test submitted and read exact ciphertext through a real iroh
connection, and refused a wrong browser capability before storing anything.
Raw malformed/oversized stream and stalled long-poll tests passed. The latter
caught a shutdown delay: an interrupted wait now gets five seconds to write
its response instead of retaining its original long-poll deadline.

The explicit public-relay test passed through Number 0's North America east
relay with client UDP disabled and every observed connection path checked as
relayed. It sent synthetic ciphertext between two endpoints on one machine.
This run establishes public-relay operation between local endpoints. It did
not test independent-machine or multi-NAT paths.

The default non-private CLI and public consensus transport do not activate
iroh. Adding the optional transport expands the private build's dependency
graph; the simpler host setup does not mean a smaller dependency tree. TLS
remains available for its existing generation-transition tools.

Drafted by Codex. Independently reviewed by Codex agent
`/root/integration_review` (AI), with reciprocal host/client/native reviews.
The review included implementation, operator documentation and test evidence;
it did not qualify independent networks or publish a new binary release.

## Robustness follow-up

The follow-up review found three failures around the transport and invitation
setup. A disconnected client or stopped response stream could retain a held
PAGE request's slot for its entire wait. A panic while holding the mailbox
mutex could deadlock the request guard during unwinding. Invalid invitation
setup arguments could fail after creating member state.

The transport cancels only the abandoned request's wait, wakes it without a
lost notification, and joins its storage worker before releasing resources.
The mutex guard drops before the request guard during unwinding. Invitation
joins validate their operation, paths and output destination before committing
member state. Final exclusive file creation still handles filesystem races;
later storage failures retain the existing recovery behavior.

Regression tests cover connection close and STOP_SENDING with a second reader
left waiting, subsequent PUT/PAGE requests, panic recovery in a child process
with a timeout, and corrected TLS and iroh invitation joins after invalid
setup attempts. The architecture continues to use iroh for connectivity, MLS
for room confidentiality and the durable mailbox for delivery. These findings
do not require another transport or replication protocol.

### Repeat independent-runner testing

The advisory [Iroh independent runners workflow](../.github/workflows/iroh-qualification.yml)
builds one native test executable and runs a temporary host and client in two
GitHub-hosted Ubuntu jobs. It runs on relevant pull requests and can be invoked
manually with `gh workflow run iroh-qualification.yml --ref main`.

The production client checks PUT, PAGE, exact duplicate submission, refusal of
wrong credentials, endpoint and namespace, and a fresh client connection.
A separate raw iroh client disables UDP and verifies that its PUT/PAGE paths
use the public relay. The host reopens its mailbox after shutdown and checks
the two expected records. Automatic routing and forced relay are reported as
separate cases.

Artifacts bind the source SHA, lockfile, executable, run, attempt and temporary
test identity. The two roles must report distinct machine hashes and completed
child cleanup. Only synthetic data and a short-lived credential for that test
mailbox are exchanged; no endpoint secret or production credential is uploaded.
The host has a finite lifetime and storage limit. Its public relay dependency
makes this an advisory network test, separate from the required local tests.

A successful run establishes connectivity between two hosted machines. Their
NAT diversity is not measured. Home/mobile networks, long-running relay
availability and comparative performance need separate measurements. The
hosted Railway service continues to use TLS, and this work does not publish
a binary release or move that service to iroh.

## Habitat Link profile

Valhalla now carries a small, opt-in framing adapter for `algal.habitat-link.v1`
in `vhalla-private-native::habitat_link`. It negotiates `algal/habitat/1`,
prefixes one bounded canonical JSON envelope with a four-byte network-order
length, and refuses truncation, trailing bytes, invalid UTF-8/JSON, unsupported
contracts, and malformed operation identities. `with_habitat_link_alpn` and
`configure_iroh_endpoint` add the ALPN only when a caller explicitly enables
a dedicated Habitat Link service; existing private-room listeners keep their
current ALPN list until that service has a handler.

The adapter is deliberately below authority. Iroh endpoint identity authenticates
the connection, while Habitat Link grants, durable acceptance, mailbox policy,
replay identity, and evidence remain habitat responsibilities. The feature is
compiled with `--features habitat-link` (which enables the Iroh dependency). It
does not turn a Valhalla room into an execution scheduler
or promise exactly-once external effects.

### Dedicated handler and client

`habitat_link::HabitatLinkService` is the dedicated handler for connections
negotiated on `algal/habitat/1`. Each request is one bidirectional QUIC stream:
the service reads the four-byte length prefix, refuses a declaration above
262,144 bytes before requesting any payload byte, reads exactly that many
bytes, refuses trailing bytes, validates the envelope with the shared frame
decoder, and hands the bytes to the habitat's `HabitatLinkHandler`
(`fn handle(&self, envelope: &[u8]) -> Result<Vec<u8>, HabitatLinkError>`).
The handler returns one reply envelope, which the service frames, writes and
finishes. A handler refusal or panic resets the stream without a reply frame.
The transport never reads the envelope's meaning.

Bounds are constants in `habitat_link`: four live request streams per
connection, 64 per service, 32 live connections per dedicated accept loop,
a four-second handshake, a ten-second request read, a ten-second reply write,
and a thirty-second idle close per connection. A connection whose ALPN is not
Habitat Link is closed with application code 1 before the handler is
consulted. Refused frames stop the request stream and reset the reply stream
with code 2 (frame), 3 (capacity) or 4 (read timeout); handler failures reset
with code 5. The Iroh endpoint key authenticates the peer's transport only and
grants no habitat authority; the grant inside the envelope does. The handler's
own running time is the habitat's bound.

Two ways to serve it exist. `HabitatLinkService::serve` is an accept loop for
an endpoint dedicated to Habitat Link, built with `habitat_link::endpoint_builder`
(no discovery, no datagrams, explicit relay only). `Service::serve_iroh_with_habitat_link_until`
serves the private-room mailbox and the Habitat Link service on one endpoint;
only that entry point adds the ALPN. The default `serve_iroh_until` remains
mailbox-only. A CLI built with `experimental-private` enables the bridge with
`vhalla private-host serve HOME --habitat-link-socket ABSOLUTE_SOCKET`. This
option requires an Iroh host and applies to this foreground process only;
`install` does not persist it. `send_envelope` and
`send_envelope_until` are the client side: connect with the ALPN, write one
frame, read one reply frame, close. A timeout after the frame was written
leaves the habitat's outcome uncertain; the envelope's operation identity is
what makes a retry safe.

`UnixHabitatLinkHandler` connects to a persistent ALGAL socket adapter. Keep
that socket in an owner-only directory. Each connection sends one length-prefixed
JSON envelope and keeps its write side open while reading one reply frame and
EOF. The adapter starts processing when the request frame is complete. The
entire exchange, including connect and EOF, has a ten-second deadline;
both frames retain the 262,144-byte limit. A timeout may follow acceptance, so
retry the same operation identity. Grant verification, process execution, and
result lookup belong to ALGAL's `LocalHabitatAcceptor`. The bridge sends no
ambient tenant credential or Iroh identity as habitat authority.

Invocations return acceptance records. An `algal.habitat-query.v1` envelope
carries `operationId`, `grant`, and `sender: {habitat, principal}` to retrieve
an authorized result. Messages return `algal.habitat-message-acceptance.v1`.
The socket adapter closes the connection on invalid records or denied grants;
the Iroh service resets that request stream.

For a local cross-repository check, start the ALGAL socket adapter and build
`cargo build -p vhalla-private-native --features habitat-link --example habitat-link-probe --locked`.
Run `target/debug/examples/habitat-link-probe ABSOLUTE_SOCKET`. Write one
canonical JSON envelope per stdin line and read one reply per stdout line.
Every exchange uses a direct loopback Iroh endpoint and the Unix bridge. EOF
stops the probe. This exercises the actual ALGAL adapter when it owns the
selected socket. In an ALGAL checkout, set `ALGAL_IROH_PROBE` to the absolute
probe path and run `bun test src/habitat-link-socket.test.ts` to include this
transport in the signed-grant process test.

On 2026-09-29 that cross-repository test passed all 20 assertions, including
caller suspension and wake-up. A same-machine run of ALGAL's qualification
fixture also passed every host/client case through the public relay, including
duplicate invocation and grant refusal. These establish local integration and
relay reachability; independent-machine evidence remains pending and NAT
traversal testing remains outstanding.

Loopback tests under `--features habitat-link` bind direct-only endpoints on
127.0.0.1 with no relay. They show an `algal.habitat-invocation.v1` envelope
answered by an `algal.habitat-acceptance.v1` reply from an echo handler,
an oversize declared length refused while the stream is still open and before
any payload is sent, a truncated frame reset without a reply, a foreign-ALPN
connection closed with code 1 and never reaching the handler, a handler
refusal reset without a reply frame, and the mailbox listener refusing the
ALPN at the handshake by default while serving both protocols on one endpoint
when the service is passed in. These tests do not exercise a relay, a second
machine, NAT traversal, or a real habitat; no live two-machine Habitat Link
qualification has been run.

The [Habitat Link independent runners workflow](../.github/workflows/habitat-link-qualification.yml)
adds a live check using ALGAL's `scripts/habitat-link-iroh-qualification.ts`.
Dispatch it with `gh workflow run habitat-link-qualification.yml --ref main -f algal_ref=FULL_ALGAL_COMMIT_SHA`.
For pre-merge qualification, the registered Iroh workflow also accepts
`gh workflow run iroh-qualification.yml --ref HABITAT_LINK_BRANCH -f algal_ref=FULL_ALGAL_COMMIT_SHA`.
That explicit input calls the same Habitat Link profile; omitting it keeps
the private-mailbox profile, including its existing pull-request checks.
It builds one probe, starts the ALGAL acceptor and Iroh service on one Ubuntu
runner, and resumes a caller on another. The client disables UDP and requires
every observed connection path to use the selected relay. It checks a signed
grant refusal, duplicate invocation, remote result, and caller wake-up. Receipts
bind both repository commits, both lockfiles, the probe executable, run and
attempt, and distinct machine identities. Both process groups must be stopped
and reaped before a run passes. Only a temporary grant and synthetic process
records are exchanged. The workflow measures separate hosted machines and a
relay path; their NAT diversity remains unmeasured. Record the successful run
and receipt hashes here before claiming live qualification.
