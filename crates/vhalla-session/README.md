# Valhalla paired chat sessions

Experimental pure Rust session layer for two **explicitly paired** peers. It is
in the test workspace and the optional loopback-only native CLI. Public rooms,
discovery and browser integration remain open; it has no host-effect connection.
Independent protocol review is still required before public network admission.

The local adapter pins both complete application keys, both observed transport
keys, realm, room, membership epoch and expiry. This configuration is trusted
input, not a remotely self-authorizing invitation. Transport must authenticate
the keys the adapter supplies.

The initiator signs Hello with a fresh 32-byte nonce. The responder verifies it
and signs a response binding both nonces. The initiator verifies the response
and signs confirmation; the responder must verify confirmation before accepting
chat. Role-specific packet kinds prevent reflection. The common session ID is
derived from both nonces and the complete pairing digest.

Each direction retains its own full-key replay window. The session only accepts
chat kind 1, rejects messages from old sessions, and permanently closes on local
revocation, expiry or observed clock rollback. Session establishment on one side
does not prove that the other side received confirmation. Strict sequence
high-water marks drop older reordered messages; this is not concurrent history
or lossless catch-up.

`prepare_chat` reserves a sequence and returns inert bytes for the local signing
custodian. `receive` verifies signed bytes and returns immutable chat evidence.
No policy or host crate is imported, and chat evidence cannot satisfy the policy
crate's typed effect-kind check.

The `Invitation` type is a separate fixed-width owner-signed claim for pairing
handoff. It binds the complete owner and invitee application keys, realm, room,
membership epoch, exclusive expiry and a nonzero 32-byte nonce under a versioned
domain. `decode` checks canonical size and key validity; `verify_for` additionally
requires the caller's expected owner key; `verify_at` applies the caller's clock.
An invitation does not authenticate a transport, open a room, or establish a
session, and the owner must retain spent-token state if it needs single-use
semantics.

`SpentInvitationNonces` provides the corresponding local replay guard. It is a
move-only, explicitly capacity-bounded set with atomic `consume`; duplicates
return `AlreadySpent`, and a full set returns `Capacity` without eviction or
mutation. It has no filesystem, clock or network behavior, so an adapter must
persist and recover its state before using it for durable single-use policy.
Scope one guard to the issuer and authorization domain that owns its nonce set;
callers spanning multiple issuers should derive a domain-separated spend key
from verified claims before consuming.

The caller must supply fresh unpredictable entropy on **every** handshake,
including after a crash. Reusing both nonces repeats the session and can reopen
replay; the nonzero check is only a default-value guard. Pending handshakes need
adapter-owned count limits and deadlines. Pairing persistence, real entropy,
invitation integration, key custody, restart integration, browser execution and
network delivery are separate admission gates. This module provides no durable
exactly-once effect, encrypted history or global membership consensus.

Run the focused tests and compiler boundary checks:

```console
cargo test -p vhalla-session --locked
cargo clippy -p vhalla-session --all-targets --locked -- -D warnings
```

The public API suite covers two-way chat, fresh-session replay rejection,
transport/application-key mismatches, changed pairing coordinates, reflected or
tampered handshakes, malformed lengths, timeout, revocation, clock rollback,
non-chat denial, maximum signed frames and generated nonce/bit-mutation cases.
The pairing digest has a separately calculated Python fixed-width vector.
