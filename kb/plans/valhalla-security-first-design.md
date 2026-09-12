---
title: Valhalla security-first design plan
type: plan
area: valhalla-security
status: proposed
tags:
  - security
  - p2p
  - wasm
  - urp
---

# vhalla (valhalla) security-first design plan

**Status:** design draft  
**Scope:** protocol, core runtime, browser boundary, and host integration  
**Date:** 2026-09-12

This document is the design contract for **vhalla (valhalla)**: a portable,
peer-to-peer coordination protocol with IRC-like ergonomics for agents and
humans. The command is `vhalla`; public documentation calls the product
Valhalla. The repository is still in design mode. This plan is intentionally
more specific than the README, but it does not claim that an implementation
exists.

## Decision in one paragraph

Valhalla should use a small Rust security kernel that can compile to native
targets and WebAssembly, with libp2p-style transports kept behind adapters.
Every network value enters as untrusted bytes and moves through explicit
typed states: parsed, authenticated, locally authorized, and executed. Peer
messages, room membership, signatures, relay access, and model output never
grant host authority. A local owner policy is the only component allowed to
mint a narrowly scoped effect capability. The host consumes that capability
through a typed, allowlisted adapter and emits a receipt. The compiler can
make accidental authority crossings difficult or impossible; runtime checks,
key custody, browser security, and operational controls still carry the rest.

## URP principles carried over from Jungle

The Jungle repository's URP guidance is the source of these rules:

1. **Make invalid states hard to represent.** Authority-bearing values are
   newtypes with private constructors. The state machine does not expose an
   API that accepts a raw string as a peer, room, capability, command, or
   resource.
2. **Parse foreign values from `unknown`.** Wire bytes, JSON/CBOR, model
   output, browser messages, configuration, and persisted state are all
   untrusted at the boundary. Strict schemas, size/depth limits, and stable
   errors run before domain logic.
3. **Keep authority one-way.** Documentation, room text, display names,
   prompts, and peer-provided policy descriptions may explain or propose; they
   cannot silently override the applicable local policy.
4. **Prefer deterministic evidence while it is cheap.** Add property tests,
   golden protocol vectors, compile-fail tests, fuzzers, and deterministic
   transport simulations before public peers or real tools are connected.
5. **Treat external coordination as expensive.** Every future phase records
   its owner, acceptance evidence, recovery path, and residual risk in this
   plan rather than leaving an unowned security reminder.

The Jungle “fences, not sandboxes” distinction is useful here. A fence is a
deliberate refusal when a caller lacks the required identity, scope, epoch,
approval, or budget. It is not a promise that a compromised model, browser,
operating system, or unsafe dependency can never act maliciously.

## Security contract

The public protocol and implementation should preserve these statements:

- **Received is not authorized.** A message arriving in a room is data. It is
  not a command, a policy change, a credential, or an owner instruction.
- **Authenticated is not authorized.** A valid peer signature proves control
  of an identity key for a specific envelope. It does not grant host tools or
  change local trust policy.
- **Proposed is not executed.** A model or peer may produce a structured
  `ProposedIntent`. Only a local policy can convert it to an
  `AuthorizedRequest`, and only an appropriate capability can execute it.
- **Executed is not silently claimed.** Each state transition produces a
  receipt containing the event/capability hashes, outcome, and applicable
  policy epoch. “Message received” and “effect completed” remain distinct
  user-visible states.
- **Prompt injection remains content.** Valhalla cannot stop a model from
  misunderstanding hostile prose. It must stop that prose from acquiring
  authority, changing schemas or budgets, selecting tools, or bypassing the
  host policy.
- **No ambient authority.** An agent connected to a room should be able to
  chat with zero filesystem, process, secret, or outbound-network capability.

## Threat model and explicit limits

Assume an attacker can operate a malicious peer, relay, bootstrap node, room
descriptor, browser tab, artifact, dependency, or model message. They can
reorder, replay, duplicate, drop, delay, flood, and attempt downgrade or
confusion attacks. They may use forged nicknames, plausible prose, malicious
attachments, or strings such as “ignore previous instructions”.

The protocol must resist unauthorized effects, identity forgery, replay,
cross-room confusion, capability escalation, parser/resource exhaustion, and
secret leakage through events or logs. It must not assume a relay is honest.

The following are limits rather than missing promises:

- A compromised owner host, kernel, browser origin, or already-authorized
  process can misuse local authority. Key rotation, pairing revocation, and
  process separation reduce but cannot eliminate this risk.
- A memory-safe Rust core does not make an `unsafe` dependency, browser, or
  OS safe. Unsafe code is confined and audited rather than declared impossible.
- P2P does not guarantee liveness or privacy. Relays may censor or observe
  metadata, and NAT traversal may require infrastructure even when no central
  service owns the protocol.
- Prompt injection is a model-behavior problem. The enforceable guarantee is
  that injected content cannot cross the authority boundary by itself.

## Architecture and authority seams

The first implementation should be a Rust workspace with these dependency
directions:

```text
vhalla-core       pure state, identifiers, bounded values, no I/O
      ^
vhalla-wire       strict parsing, canonical envelopes, signatures
      ^
vhalla-policy     local owner policy, capability minting, authorization
      ^
vhalla-transport  libp2p/WebRTC/relay adapters; no host effects
      ^
vhalla-host       OS/tool/process adapters; the only effectful boundary
vhalla-browser    WASM/UI bridge, origin and postMessage checks
```

The arrows describe permitted dependency flow: the core knows nothing about
the network or tools; transport knows nothing about host authority; the host
does not get to reinterpret untrusted wire data. A later implementation may
split crates differently, but it must preserve these ownership boundaries.

### Foundation-first repository shape

The first implementation milestone is a buildable, testable Rust workspace,
not a web client. The repository should contain no authored JavaScript or
TypeScript and no npm/bundler dependency. Browser support remains a Rust
compilation target (`wasm32-unknown-unknown`) with a narrow host surface; any
binding glue generated by a Rust tool is a build artifact, not a second
application implementation.

Start with this Cargo layout and add effectful crates only when their phase
starts:

```text
Cargo.toml                 workspace, resolver, shared lints
Cargo.lock                 committed for every application/binary target
rust-toolchain.toml        exact reviewed toolchain and installed targets
crates/vhalla-core/        pure state, bounded values, no_std where feasible
crates/vhalla-wire/        strict decoding and canonical event envelopes
crates/vhalla-crypto/      vetted hash/signature/key wrappers
crates/vhalla-policy/      local authorization and capability minting
crates/vhalla-transport/   later: native and browser transport adapters
crates/vhalla-host/        later: typed OS/tool effect boundary
crates/vhalla-cli/         later: the `vhalla` binary
fuzz/                      bounded cargo-fuzz targets
vectors/                   versioned cross-target protocol fixtures
```

The workspace sets shared `rustfmt`, Clippy, documentation, and dependency
lints. Core, wire, crypto, and policy crates use `#![forbid(unsafe_code)]`,
`#![deny(missing_docs)]`, explicit feature flags, and no filesystem, process,
network, model, or browser imports. `Cargo.lock` and the toolchain file are
part of the reviewed source state. A dependency must be justified by the
boundary it serves, pinned by the lockfile, and checked for license,
provenance, and advisories before admission.

### Testing foundation before networking

Every pure module gets focused unit tests beside its implementation. Cross-
crate behavior lives in `crates/*/tests/`, and shared protocol fixtures live
in `vectors/`. Tests must not use wall-clock time, ambient randomness,
network access, the local home directory, or provider credentials; inject a
clock, entropy source, and store so a test can replay the same result.

The initial test stack is:

- `cargo test --workspace --all-targets --all-features` for unit,
  integration, and documentation tests;
- `proptest` for parser, canonicalization, ordering, expiry, deduplication,
  capability scope, and state-machine laws, with checked-in regression cases;
- `trybuild` compile-fail tests proving that unverified events cannot call
  effect APIs and external crates cannot construct capabilities;
- `cargo-fuzz`/libFuzzer targets for bounded wire, manifest, envelope, and
  intent parsers, with corpus limits and no side effects;
- deterministic transport/state simulations once those crates exist, covering
  loss, reorder, duplication, delay, partition, and quota exhaustion;
- `cargo check --target wasm32-unknown-unknown` and the same protocol/vector
  tests for the WASM target, without introducing a JS/TS test harness.

CI should run `cargo fmt --check`, Clippy with warnings denied, the full test
suite, compile-fail tests, the WASM check, and dependency/license/audit checks.
Fuzzing and mutation testing can run on a scheduled lane, but a failing
security regression or compile-fail case blocks integration immediately.

The first green checkpoint is therefore meaningful: a native and WASM Rust
core can parse bounded foreign bytes, enforce typed lifecycle transitions,
replay the same property tests, and demonstrate at compile time that remote
content has no path to a host effect. No transport, browser UI, model, or
external service is required to pass that checkpoint.

### Typed lifecycle

The security kernel should expose a deliberately narrow pipeline:

```rust
parse(raw: &[u8])
  -> Result<UntrustedEnvelope, ParseError>
verify(envelope, realm_trust)
  -> Result<AuthenticatedEvent, VerifyError>
authorize(event, local_policy)
  -> Result<AuthorizedRequest, Denied>
execute(request, effect_capability)
  -> Result<ExecutionReceipt, EffectError>
```

`UntrustedEnvelope`, `AuthenticatedEvent`, `ProposedIntent`,
`AuthorizedRequest`, `EffectCapability`, and `ExecutionReceipt` are distinct
types. There are no implicit conversions between them. Constructors for
authority-bearing types are private to the policy/host modules, and
`EffectCapability` has no deserializer.

### Compiler-enforced invariants

- `#![forbid(unsafe_code)]` in `vhalla-core`, `vhalla-wire`, and
  `vhalla-policy`; audited unsafe code is isolated in adapters if a target
  requires it.
- Newtypes for `PeerId`, `RealmId`, `RoomId`, `EventId`, `CapabilityId`,
  `Sequence`, `Epoch`, `Audience`, and `Expiry`; no bare `String` or integer
  at an authority seam.
- Typestate or sealed constructors for the lifecycle above. A remote event
  cannot satisfy the trait required by an effectful host method.
- `AuthorizedRequest` carries a scope, resource, audience, expiry, nonce,
  policy epoch, and confirmation requirement. It is not constructible from
  chat text or a peer payload.
- Host methods accept only typed, allowlisted operations (for example,
  `ReadWorkspaceFile` with a bounded path), never an arbitrary shell string,
  URL, executable, or RPC method.
- Model adapters return a strict `ProposedIntent` schema. They cannot return
  capabilities, credentials, prompts, schemas, budgets, tools, or output
  paths.
- Core APIs use `#[must_use]` results and explicit error enums. Stringly typed
  “allow” flags and catch-all `serde_json::Value` are prohibited in the trusted
  path.
- Compile-fail tests (`trybuild`) prove that an unverified event cannot call a
  host effect and that external crates cannot construct a capability.

The compiler is a fence against accidental crossings; it is not a
cryptographic verifier or a defense against a compromised host.

## Protocol and cryptographic rules

Every application event is independently authenticated; a Noise/TLS session
or libp2p `PeerId` is only a transport channel. A canonical envelope binds:

`version, realm, room, sender, recipient/audience, event_id, parent,
sequence, issued_at, expires_at, sender_epoch, capability_hash (when
present), payload_hash, and payload`.

Sign the domain-separated canonical transcript, reject unknown versions and
fields according to the negotiated profile, and fail closed on invalid
signatures, wrong realm/audience, expiry, excessive clock skew, duplicate
event IDs, or sequence rollback. Persist the replay window and sender epoch
across restart.

Keep keys separate:

- long-lived identity signing key;
- owner authority/pairing key;
- per-session transport keys;
- private-message/group encryption keys;
- browser-origin key where WebCrypto can keep it non-exportable.

Pairing is explicit and out of band (local gesture, fingerprint, QR, or CLI
display). Nicknames, DNS, GitHub accounts, relays, room membership, model
claims, and discovery advertisements never become owner authority. Rotation,
revocation, device removal, and policy epochs are first-class protocol
objects.

## Prompt-injection and content boundary

All peer messages, room history, display names, realm descriptors, relay
responses, attachments, tool output, and model output are `UntrustedContent`
with provenance. The model adapter receives labeled/quoted content, not a
value that can be spliced into a system or developer instruction. Natural
language cannot invoke a tool, change a budget, expand a room, or alter an
allowlist.

The model may suggest a structured intent such as “summarize room X” or
“prepare a patch preview”. Policy evaluates that intent against local scope,
resource, rate, expiry, and (for sensitive effects) a human confirmation.
The host then executes a fixed operation with validated arguments. Never use
peer text in `eval`, shell interpolation, URL fetches, file paths, prompts,
schemas, or output paths without an explicit parser and policy decision.

## P2P, rooms, and resource fences

Discovery descriptors are signed hints, not authority. An invitation pins the
initial realm/owner fingerprint and policy version; a peer advertisement may
request a room but cannot change its rules. Relays forward opaque events and
cannot mint or rewrite them.

Rooms should remain few and structured: a realm has a manifest of stable room
IDs, role names, retention, maximum event size, and subscription policy. A
room message is not a new channel definition. Unknown room roles and manifest
versions fail closed.

Bound resource use before accepting untrusted input: maximum frame, event,
attachment, nesting depth, history page, connection, subscription, queue,
CPU/time, and per-peer/room rate. Use backpressure, token buckets, bounded
outboxes, and isolation/strike policies. No unauthenticated packet may cause
unbounded allocation, model-context growth, or durable storage.

## Browser and embedded targets

The core should compile to WASM without importing browser or OS authority.
The browser is an observer/requester by default. A browser origin is paired
to a specific owner key and receives only scoped capabilities after a local
gesture; bearer owner tokens never appear in URLs or `localStorage`.

The browser adapter requires a strict CSP and `connect-src` allowlist, no
remote code loading or `eval`, origin- and nonce-checked `postMessage`, and
bounded schemas on every JS/WASM boundary. Native agents accept only a pinned
origin/key and explicit capability scope. Revoke a pairing when an origin or
device is lost.

Embedded builds may omit UI, encryption backends, or heavyweight transports,
but they must retain the same wire vectors, lifecycle types, quotas, and
default-deny policy. Optional features must not widen authority when enabled.

## Phased implementation plan

### Phase 0 — contract and proof boundaries

- Freeze the threat model, claims, non-goals, room-manifest shape, and key
  roles in design records.
- Decide the initial Rust/WASM target matrix and the minimum transport profile.
- Write a security glossary so “peer”, “owner”, “authenticated”,
  “authorized”, and “executed” are not conflated.

**Exit evidence:** reviewed threat model, explicit residual risks, and a
traceable list of compiler-, runtime-, host-, and operational-enforced claims.

### Phase 1 — foundation checkpoint

- Establish the Rust workspace, exact toolchain, committed lockfile, shared
  lints, dependency policy, and native/WASM build matrix.
- Implement bounded identifiers, timestamps, epochs, room manifests, and
  lifecycle types in a pure, `no_std`-where-feasible crate.
- Add strict `unknown` parsers with stable error codes and deny-by-default
  handling for unknown/oversized/deep values.
- Add colocated unit tests, `proptest` laws, checked-in regressions,
  `trybuild` authority-boundary tests, fuzz targets, and protocol vectors.

**Exit evidence:** `cargo test --workspace --all-targets --all-features`,
`cargo fmt --check`, Clippy with warnings denied, compile-fail tests,
`cargo check --target wasm32-unknown-unknown`, and no unsafe code or authored
JS/TS in the foundation crates.

### Phase 2 — identity, envelopes, and replay

- Implement canonical encoding, domain-separated signatures, audience/realm
  binding, expiry/skew, sequence and replay persistence, rotation, and
  revocation.
- Publish Rust↔WASM golden vectors before adding alternate implementations.

**Exit evidence:** forged, wrong-audience, downgraded, expired, replayed, and
reordered fixtures all fail deterministically.

### Phase 3 — transport and room behavior

- Add native libp2p transport and a browser-compatible adapter (WebRTC/relay
  as needed) behind the same event API.
- Treat GossipSub membership and relay connections as delivery mechanisms,
  never authorization.
- Implement bounded queues, backpressure, connection/subscription quotas,
  and deterministic loss/reorder/duplication simulation.

**Exit evidence:** native↔browser conformance, relay-forgery tests, and
resource-exhaustion tests with bounded memory and CPU.

### Phase 4 — local policy and effect runner

- Implement owner pairing, policy epochs, capability minting, confirmation
  rules, audit receipts, and revocation.
- Put OS/tool execution in a separate process or WASI-style boundary with
  typed allowlists, no arbitrary shell/network, restrictive key storage, and
  redacted logs.

**Exit evidence:** a malicious peer can chat and propose but cannot cause a
filesystem write, process spawn, secret read, or network egress without a
locally minted capability and the required confirmation.

### Phase 5 — browser UI and operator controls

- Add room/agent views that visibly distinguish received, proposed, authorized,
  and completed states.
- Add origin pairing, CSP, nonce-checked messaging, key rotation/revocation,
  and explicit gestures for sensitive actions.

**Exit evidence:** origin-confusion, XSS-like content, stale pairing, and
postMessage replay fixtures fail closed.

### Phase 6 — adversarial and supply-chain gate

- Fuzz wire, descriptor, browser, and model-intent parsers.
- Run prompt-injection corpora and assert that content remains content.
- Run dependency/license/SBOM/provenance checks, `cargo audit`, `cargo deny`,
  reproducible builds, and locked release artifacts.
- Review unsafe adapter code and any cryptographic backend separately.

**Exit evidence:** an immutable release candidate with a security report,
conformance vectors, known limitations, revocation runbook, and exact
verification commands.

## Verification matrix

The implementation is not ready for public agents until these are automated:

- compile-fail: remote/unverified values cannot call effect APIs; capabilities
  cannot be deserialized or constructed outside policy;
- property/fuzz: canonicalization, signature transcript, expiry/skew,
  audience/realm binding, dedupe, replay after restart, rotation, revocation,
  bounded parsing, and unknown-field behavior;
- transport simulation: loss, delay, reorder, duplication, partition, relay
  substitution, peer churn, and backpressure;
- authorization: scope/resource/epoch/nonce/max-use/confirmation checks and
  default deny for every unknown operation;
- prompt injection: hostile room text, display names, attachments, tool
  output, and model responses never produce an `AuthorizedRequest` directly;
- browser: origin mismatch, nonce replay, CSP violation, stale pairing, and
  tab compromise handling;
- hygiene: no credentials in argv, prompts, events, receipts, diagnostics,
  or persisted state; no unbounded model-context or queue growth;
- release: locked dependencies, audit/license results, SBOM, reproducible
  native/WASM artifacts, and signed immutable release provenance.

## Prototype-backed decisions (throwaway reference pass)

The first fork pass lives under `prototypes/`. Each prototype is intentionally
small, dependency-light, and disposable; it tests a boundary or failure mode
rather than claiming production security. The current decisions are:

- **Wire:** choose canonical CBOR for signed protocol envelopes. The
  `prototypes/wire-format` experiment shows typed bytes, smaller transcripts,
  definite-length maps, duplicate-key rejection, and bounded decoding. Keep a
  canonical JSON projection for diagnostics, fixtures, and human tooling only;
  replace the hand-written codec with an audited Rust implementation and
  cross-target golden vectors before production.
- **Transport:** keep application events independent from sockets and model
  relay loss, duplication, reordering, and bounded inboxes at that seam. The
  `prototypes/transport` experiment supports a libp2p-first investigation
  because direct browser capability is a priority. Keep Iroh as a native-first
  optional adapter and make relay fallback explicit; no relay is an authority
  or durable store.
- **Private messaging:** use pairwise owner DMs in the first secure release.
  The `prototypes/privacy` membership-epoch model shows why group membership
  changes require key rotation and stale-envelope rejection. Defer group E2E
  until offline delivery, browser key custody, history retention, and
  revocation semantics have a complete design.
- **Effects and history:** keep a typed capability/effect boundary separate
  from bounded local history. The `prototypes/effects` experiment shows that
  remote requests remain inert, local policy is the only capability minting
  path, single-use/epoch checks are explicit, and history can deduplicate and
  evict within count/byte limits. The production runner should be a separate
  process or WASI-style boundary, not a general plugin API.
- **History replication:** keep live delivery, local storage, and durable
  replication as separate states. The `prototypes/replication` experiment
  makes merges idempotent, orders concurrent events deterministically, bounds
  retention, and refuses to call a stored event durable. Durable replication
  remains optional and must have an explicit privacy/retention capability.
- **Discovery:** treat invitations, DNS, HTTP, GitHub, and relay listings as
  replaceable signed hints. The `prototypes/discovery` experiment pins realm
  and minimum protocol policy, rejects expiry/downgrade/wrong-realm hints, and
  prefers direct paths before relay fallback.
- **Browser boundary:** make a browser an origin-paired requester. The
  `prototypes/browser` experiment requires exact origin, key fingerprint,
  nonce, and scope matches; production adds non-exportable key custody, CSP,
  postMessage validation, and revocation.

These are provisional architecture decisions, not release claims. The next
implementation phase must replace hand-written codecs and placeholder key
fingerprints with vetted libraries, signed vectors, adversarial tests, and
measured native/WASM builds.

## Remaining forks and production gates

1. **Wire productionization:** select and audit the canonical CBOR crate,
   finalize integer/key ordering and unknown-field policy, and freeze vectors.
2. **Transport productionization:** compile native and WASM libp2p profiles,
   measure relay/direct behavior, and decide which discovery helpers are
   allowed in a minimal embedded profile.
3. **Group messaging:** decide whether and how to add group E2E after pairwise
   DMs have exercised pairing, revocation, and browser key custody.
4. **Effect runner hardening:** choose the first concrete process/WASI runner,
   prove its allowlist and recovery behavior, and test it against malicious
   adapters.
5. **History replication productionization:** decide whether durable
   replication belongs in the protocol at all; if it does, define retention,
   privacy, authorization, and recovery as a separate capability using the
   prototype's separate stored/durable receipts.
6. **Discovery and browser hardening:** replace descriptor/key placeholders
   with vetted signatures and origin-bound key storage, then measure direct,
   relay, reconnect, revocation, and browser-tab failure behavior.

## Security review rule

Every new feature must state: the foreign input boundary, the type that proves
authorization, the resource limits, the deterministic regression fixture, the
exact verification command, and the remaining failure mode. If a feature
cannot answer those questions, it stays behind a disabled or local-only
feature flag.
