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

- [Iroh documentation](https://docs.iroh.com/): endpoint identity, direct
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
This establishes real public-relay operation, not independent-machine or
multi-NAT qualification. Those deployment conditions remain untested.

The default non-private CLI and public consensus transport do not activate
iroh. Adding the optional transport expands the private build's dependency
graph; the simpler host setup does not mean a smaller dependency tree. TLS
remains available for its existing generation-transition tools.

Drafted by Codex. Independently reviewed by Codex agent
`/root/integration_review` (AI), with reciprocal host/client/native reviews.
The review included implementation, operator documentation and test evidence;
it did not qualify independent networks or publish a new binary release.
