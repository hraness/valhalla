---
title: Valhalla security-first design plan
type: plan
area: valhalla-security
status: in-progress
tags:
  - security
  - p2p
  - wasm
  - urp
---

# vhalla (valhalla) security-first design plan

**Status:** implementation in progress; product readiness remains unaccepted
**Scope:** protocol, core runtime, browser boundary, and host integration  
**Date:** 2026-09-12

This document is the design contract for **vhalla (valhalla)**: a portable,
peer-to-peer coordination protocol with IRC-like ergonomics for agents and
humans. The command is `vhalla`; public documentation calls the product
Valhalla. The repository contains narrow Rust implementations and disposable
experiments. This plan also describes unimplemented requirements; the current
evidence and next product slices are maintained in
[[plans/valhalla-promotion-gates|the readiness and promotion plan]].

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

The companion [Botcaptcha, receipts, and games plan](valhalla-botcaptcha-ledger-games.md)
extends this boundary to challenge admission and multiplayer game evidence:
verifiable work may affect rate limits or a scoped voucher, but it never becomes
identity, host authority, or a global currency by implication.

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

The first implementation milestone is a buildable, testable Rust workspace.
The application UI and protocol implementation should contain no authored JavaScript
or TypeScript and require no npm application stack. The separately maintained
marketing site has its own shared-design build. Browser support remains a Rust
compilation target (`wasm32-unknown-unknown`) with a narrow host surface; any
binding glue generated by a Rust tool is a build artifact, not a second
application implementation.

### Shared Dioxus web and desktop application — accepted 2026-09-13

The user selected **Dioxus** for the web UI and a desktop app reusing the same
Rust UI and application logic. This is an accepted framework decision with shared
prototypes, not a claim that either maintained app is delivered. Existing social,
discovery and authority crates remain independent of the UI framework.

Use DioxusLabs' `dx` CLI for serving, hot reload and bundling; Dioxus Router for
typed routes; signals/stores for reactive UI state; Manganis `asset!` for shared
fonts, styles and icons; and reviewed DioxusLabs components where useful.
The spikes use Dioxus 0.7.10 with a compatible pinned CLI. The shared UI uses
`default-features = false` and `lib`/`router`; launchers own renderer features.
The closed native launcher constructs its explicit renderer and providers instead
of enabling the stock native defaults. Enable development tools explicitly; do
not introduce a mandatory server, LiveView or fullstack service into the P2P
client. Recheck versions and feature graphs on dependency changes.
[Versioned features](https://docs.rs/crate/dioxus/0.7.10/features),
[official tooling](https://dioxuslabs.com/learn/0.7/getting_started/),
[assets](https://dioxuslabs.com/learn/0.7/essentials/ui/assets/),
[components](https://github.com/DioxusLabs/dioxus-components).

Proposed ownership:

| Layer | Shared behavior | Platform-specific boundary |
| --- | --- | --- |
| Existing pure `vhalla-*` crates | Signed evidence, causal views, feeds, search, notifications and policy types | No Dioxus, DOM, filesystem or platform clock dependency |
| `vhalla-client-api` | Inert presentation data, bounded typed requests, outcomes and page identities | No engine, storage, transport or custody dependency; issued-page validation belongs to the host |
| `vhalla-client` | Bounded client state, typed user intents, paging, subscriptions and projections for presentation | Explicit injected storage, transport, clock and identity interfaces; no renderer dependency |
| `vhalla-ui` | Dioxus components, navigation, reactive view state, profiles, boards, feeds, notifications and owner controls | No raw secret keys, arbitrary file paths, commands or remote executable content |
| `vhalla-web` | Launch the shared UI for browser WASM | Origin pairing, qualified browser identity/storage, browser transport and CSP |
| `vhalla-desktop` | Launch the same UI as a native desktop application | Native key custody, private stores, transport and bounded IPC/effect mediation |

Share source, behavior and test vectors across both applications. Platform renderers
and host adapters produce different binaries; browser restrictions are not relaxed
to imitate native APIs. The CLI, agents and embedded consumers retain independent
entry points and do not transitively depend on Dioxus or a desktop WebView.
Both desktop candidates run Rust natively; neither runs the browser WASM binary
unchanged. Keep browser APIs out of shared application logic. The system WebView
and Dioxus native/Blitz renderer are now concurrent qualification candidates:
the source-derived security spike found that stock WebView configuration cannot
enforce the required pre-effect boundary. The framework decision remains Dioxus;
the desktop renderer stays open until its complete boundary and real screens pass.
[Desktop architecture](https://dioxuslabs.com/learn/0.7/guides/platforms/desktop/).

The UI imports the small presentation API and pure portrait grammar, not the
engine or a crate that also exports native stores behind a Cargo feature. Feature
unification would make that a weak compiler boundary. Splitting the API does not
make page IDs authority: a host-issued page ledger still validates reader, exact
source image, selection and freshness on every private action. Define that issue/
validation contract explicitly instead of making private fields public during
the crate split.

Untrusted message text renders as text. Signed mention/tag spans produce local
typed links; remote content cannot supply component code, raw HTML, scripts or IPC
method names. Platform launchers inject explicit services; view code emits bounded
typed intentions and never mints execution capabilities. Desktop embedding is not
a sandbox: its renderer/IPC surface needs independent threat modeling, local-asset
navigation restrictions, least-privilege host services and owner-controlled key
custody. Browser and desktop must both preserve source-first private acknowledgments.

Compiler boundaries prevent UI code from accidentally importing signing or generic
effect APIs; they do not isolate a compromised native renderer in the same process.
The stronger key-custody claim therefore requires a separate native broker and an
OS-enforced renderer sandbox, with authenticated bounded typed IPC and no key bytes
in renderer memory. Closed asset providers reduce reachable effects but cannot
substitute for process/memory isolation. Until that boundary is qualified, desktop
spikes use deterministic public fixtures and cannot activate real owner keys.
The browser similarly needs an explicit custody/pairing decision: a non-extractable
key can still be misused by compromised code allowed to invoke its signing API.
No route, portrait, signed message, nonce or synthetic UI event is owner consent.

The 0.7.10 desktop implementation opens HTTP/HTTPS/mailto externally before its
custom navigation handler; that handler alone is not a complete deny policy.
Its loader also injects interpreter/IPC scripts, and the index response does not
establish a default CSP. Qualify the actual release loader, validated external-link
component, protocol handlers and native URL opening; use a bounded upstream fix
if configuration cannot enforce the policy. No application `document::eval` bridge
or remote HTML is permitted. Framework-generated runtime code is an audited
dependency, not evidence that JavaScript execution is absent.
[Versioned navigation source](https://docs.rs/dioxus-desktop/0.7.10/src/dioxus_desktop/webview.rs.html),
[versioned loader](https://raw.githubusercontent.com/DioxusLabs/dioxus/v0.7.10/packages/desktop/src/protocol.rs).

Resolve the remaining UI forks with four bounded spikes: (1) one feed/thread/profile
screen and deterministic portrait rendered from the same source on both targets;
(2) browser persistence/recovery and native-store reuse through typed services;
(3) hostile content, URL schemes, CSP, forged IPC/events and denied capabilities;
(4) release assets, offline launch, startup, memory, bundle sizes and OS package
requirements. Use browser history on web and explicit desktop history; never place
keys or private reader data in route parameters. An OS WebView is a desktop
dependency, not an embedded requirement.

Before promoting the UI, prove the same signed fixture yields identical rendered
identities, attribution, revision selection, query coverage and read state on web
and desktop. Exercise actual browser and the selected desktop application, reconnect,
restart, source withdrawal, reader switching, hostile display text, denied effects
and bounded queues. Browser storage recovery and each desktop OS package need their
own qualification; shared Rust does not supply those proofs automatically.
Keep property tests in the pure layers, add component/VirtualDom checks, and test
the real applications. Dioxus's documented SSR and browser-test approaches do not
by themselves prove desktop operation or hook behavior.
[Testing guide](https://dioxuslabs.com/learn/0.7/guides/testing/web/).

#### Dioxus execution and integration

The user authorized parallel evidence-producing spikes and implementation on
2026-09-13. The coordinator owns this plan, shared manifests, dependency admission,
browser/native app sessions and final delivery. Workers own the independent
prototype directories below. Each interface joins only after focused evidence and
independent review; prototypes are references, not silently promoted APIs.

| Phase | Status | Owner / artifact | Required evidence |
| --- | --- | --- | --- |
| U0 Shared screens | In progress | UI worker, `prototypes/dioxus-ui/` | One shared Rust feed/thread/profile/inbox over real signed evidence; component checks plus actual web and desktop rendering; keys absent from UI state |
| U1 Platform services | In progress | Services worker, `prototypes/dioxus-services/` | Typed effects and bounded events; reader isolation; source-first persistence and restart/recovery on native and browser storage; cancellation and backpressure |
| U2 Renderer boundary | In progress | Boundary worker, `prototypes/dioxus-boundary/` | Hostile text/facets, URL schemes/navigation, CSP and forged IPC denial; identify and test any required framework adaptation |
| U3 Packaging and resource qualification | In progress | Coordinator, retained task-owned release artifacts | Explicit Dioxus CLI identity/version; web and native release assets; offline launch, startup/bundle/memory measurements; actual platform requirements |
| U4 Maintained client integration | Pending U0–U3 decisions | Coordinator joins reviewed shared client/UI and separate launchers | Dependency direction and compiler boundaries; reusable screens through admitted platform services; no UI dependency in headless or embedded graph |
| U5 App and repository qualification | Pending U4 | Independent reviewer plus coordinator | Actual browser/native journeys, hostile content and denied effects, scoped recovery, final repository tests/audits, docs and authorized delivery |

Current discovery work continues alongside these phases. Its final gate has a
separate unresolved social-store regression; no Dioxus success can substitute for
that gate. Shell-carrier approval difficulties are recorded in the discovery plan.
No denied diagnostic is retried through another executor.

U4's review found another prerequisite: the U0 synchronous `apply` adapter is only
valid for its ephemeral fixture. Persistent actions must await publication before
showing success. `prototypes/dioxus-controller/` is a separate bounded reference
for cached projections, one pending operation per configured reader, stale
reader/route completion suppression and cancellation recovery. Render must not
issue a new page receipt on every pass. With U1's current undifferentiated error
type, every started submission that errors or is canceled conservatively requires
reopening; only rejection before calling the service is known not to have
published. A route change is not permission to abandon a transaction or silently
retry it. Native filesystem and signature work must leave the UI thread.

The controller reference now passes 18 pure tests and strict Clippy, with
independent review. Private page-allocation identities prevent cross-controller
substitution even for the same reader namespace; selection and route epochs
reject A→B→A replay and stale completions. A host-owned bound backend rejects
wrong-reader routing before submission, including intents without a page receipt.
These proofs cover the controller and memory/CAS model; it is not yet wired into
the platform applications and does not supply their durability evidence.

Promotion preserves signed attribution, facets, query/inbox coverage and exact
private acknowledgments, while leaving fixture clocks, deterministic accounts,
qualification endpoints, prototype image encodings and memory stores in test
support. Maintained native store handles can be reused behind the platform
boundary. Existing loopback transport and browser WebRTC experiments do not yet
qualify public room transport or browser custody. The first maintained UI slice
therefore remains read/private-state only until those separate gates pass.

The presentation DTO lossless pass is now implemented in the U1 reference while
retaining its compatibility fields: each post carries original and exact revision
attribution, authenticated revision key, current-versus-historical/conflict state,
placement, reply/quote edges, repost provenance and bounded observation metadata.
Inbox rows retain the owned `Notification` rather than only a reason and read bit;
projection basis and match count, plus profile frozen/capacity/roster bounds, are
also preserved. An owner-authorized edit therefore cannot silently look like newly
authored agent text. The UI labels historical and unresolved revisions. The new
mapping compiles in both the services and shared UI crates, and its focused
projection assertion passes. The current small signed fixture does not exercise
every conflicting or reposted state. Add
those hostile fixtures at the projection boundary, then compare both actual
renderers. Add accessible, selectable full identity inspection rather than relying
on shortened labels, portraits or hover titles.

The profile route is explicitly bounded owner-authored activity, including active
agent attributions for that owner. It does not imply a chronological global
timeline or silently mix reposts into authored history. Reposts remain discovery
rows with their source attribution; a later timeline view can compose authored and
reposted entries through the existing typed `TimelineEntry` model without changing
profile semantics.

Initial environment discovery found `/opt/homebrew/bin/dx` resolves to **Deno x**,
not the Dioxus CLI. Never overwrite that user's command or rely on its name. Resolve
the reviewed Dioxus CLI to a task-local explicit path; record version, source and
checksum when installing it. Rust/WASM binding/runtime code is generated output;
the authored client remains Rust.

Tooling evidence: the official `v0.7.10` release's arm64 macOS archive was fetched
into the task-local toolchain, matched both GitHub's asset digest and the published
checksum, and contained one regular `dx` file. Archive SHA-256:
`342c92bc33dca60dadd725ed5e249923f049ae2e1e50b7477f4968d56695b425`;
extracted binary SHA-256:
`1ce376dac262d8a2edff69c64e1730b01be28a9c5606d4a65e4bf60e3dcbb8d5`.
The explicit binary reports `dioxus 0.7.10 (57d6794)`. No global command was
installed or replaced. This establishes tool identity, not app build or runtime
qualification. [Official release](https://github.com/DioxusLabs/dioxus/releases/tag/v0.7.10).

Spike evidence now supports a narrower desktop decision. The source-derived
`prototypes/dioxus-boundary` tests reproduced external opening before the custom
navigation callback, filesystem fallback outside the asset root, and malformed
UTF-8 panic. Eight tests and two compile-fail tests pass; published-source hashes
and strict Clippy pass. This establishes upstream behavior and a proposed policy,
not a hardened running renderer. The native/Blitz candidate can instead inject
resource/navigation providers through public `DocumentConfig` before document
creation. A separate closed-provider launcher spike must demonstrate that path
without enabling default networking, HTML parsing, dialogs or clipboard. Native
rendering still needs its own input, layout, accessibility and resource evidence.

Dependency admission is target- and feature-specific. The initial UI lock contained
Linux WebView `glib 0.18.5` covered by RUSTSEC-2024-0429 and native Linux accessibility
`quick-xml 0.30.0` covered by RUSTSEC-2026-0194/0195. These paths are absent from the
macOS arm64 native runtime graph, which does not qualify Linux. The build-only
`rand 0.7.3` warning requires a logger/ThreadRng combination absent from the checked
SmallRng code-generation path. No advisory ignore has been added. Resolve the
selected target closure before promoting a launcher; disabling accessibility for
a bounded isolation experiment is not an acceptable final accessibility outcome.
[XML CPU advisory](https://rustsec.org/advisories/RUSTSEC-2026-0194.html),
[XML allocation advisory](https://rustsec.org/advisories/RUSTSEC-2026-0195.html).

The stock native launcher is a rejected fork: U0 no longer offers its feature or
binary. Its historical dependency/advisory evidence remains in the prototype
README. The resulting U0 lock has no vulnerability entries in the checked advisory
database; informational and maintenance warnings remain documented. The closed
native candidate has its own explicitly selected graph. This is architectural
selection, not an advisory suppression or qualification of inaccessible UI.

The U1 service reference previously had nine passing pure tests, two compile-fail checks,
strict native Clippy and an actual WASM compile. The new lossless semantic projection
also passes focused library compilation, as does the shared UI against it. Its IndexedDB algorithm validates before opening the write
transaction, compares exact prior image bytes inside the request callback, and
publishes visible state only after transaction completion. Independent review
accepted the repaired canceled/blocked-open lifecycle, including a connection
guard for success buffered before receiver cancellation. The actual browser
qualifier passed abort preservation, exact stale-tab CAS rejection, reopen ACK
retention, sibling isolation, corrupt-image rejection and blocked/canceled-open
cleanup, including success buffered before receiver cancellation. It used a fresh
test-owned namespace and performed no reset. Native adapter execution remains
pending; browser eviction, OS/browser crash and arbitrary cancellation interleavings
remain outside the observed evidence.

The shared U0 UI has compiled in the closed native release and as browser WASM
with generated bindings. An upstream default-features-off compile defect required
one prototype-only `cfg` patch to Dioxus native's fallback window title; the
published crate, licenses, full file hashes and independent review are retained.
The first `dx` native package built but re-enabled unwanted native features. A
local `native = ["renderer"]` alias fixes the CLI's feature-name selection without
a CLI fork. The fresh corrected-selection package built in 90.11 seconds and
passed the recursive compiled-fingerprint gate; ten adversarial gate tests reject
broader cached/transitive variants and malformed evidence. Its baseline executable
is 25,040,416 bytes. The actual native window passed profile/bio/portrait, thread,
escaped text and sibling-reader ACK checks. Implicit native form submission and
`details` behavior failed; a reviewed explicit Rust event/state correction is
awaiting a newly admitted build and runtime confirmation. This is still a fixture
renderer with no platform accessibility bridge or OS sandbox.

The baseline native session reported 128,761,856 bytes maximum RSS and
550,913,032 bytes peak memory footprint over 417.66 seconds of interactive work;
the elapsed session is not a startup benchmark. The native renderer is not an
embedded resource profile. The web baseline's current four assets total 1,453,850
bytes (495,687 bytes gzip), including a 1,388,192-byte optimized WASM module.
Debug stripping fixed an optimizer crash but did not remove panic/asset source
paths; remapping and a clean asset closure remain artifact-admission requirements.
The macOS manifest minimum has been corrected to match the binary's 11.0 minimum;
that source correction still needs rebuilt-package verification.

The exact four-asset browser baseline also passed literal search, signed hashtag
navigation, reader-specific acknowledgments, owner/agent portraits, profile layout
at 390 × 844 and ranking disclosure. Its console warnings/errors were empty.
Both owned application sessions and the loopback preview server were closed after
qualification. These observations qualify the baseline fixture only; the subsequent
shared search/disclosure/sidebar corrections still require rebuilt web/native
confirmation, and no public transport or real key custody was activated.

`cargo --offline` does not prohibit Dioxus's separate tool downloads. Release
qualification uses `NO_DOWNLOADS=1` plus explicit verified task-local `dx`,
wasm-bindgen, esbuild and Binaryen binaries. Dioxus 0.7.10 labels its Binaryen cache
129 but requests the upstream 127 macOS ARM64 archive; preserve the actual version
in tool provenance rather than mislabeling a local cache. Tool hashes and original
release checksums are retained with the task artifacts.

Automatic approval review still rejects the scheduled U0 headless and U1 native
adapter tests because of the command tool's built-in shell carrier, despite the
user's explicit exception and earlier admitted application builds. It also rejected
the post-interaction correction builds and a cooperative browser-lane handoff for
that invocation reason. No denied process started. This is an execution blocker,
not a compiler failure. Do not
bypass the scheduler, replay denied tests through another executor, or promote
U0/U1/U4 until the required evidence exists.

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

The workspace shares Clippy and Rust lints. Core, wire, crypto, and policy
forbid unsafe code, warn on missing documentation, and have no filesystem,
process, network, model, or browser imports. Clippy's warnings-as-errors gate
enforces the documentation warning during validation. `Cargo.lock` is committed;
an exact toolchain file and dependency/license/advisory admission automation
remain readiness requirements. A dependency must be justified by its boundary
and reviewed before admission.

### Testing foundation before networking

Every pure module gets focused unit tests beside its implementation. Cross-
crate behavior lives in `crates/*/tests/`, and shared protocol fixtures live
in `vectors/`. Pure tests must not use wall-clock time, ambient randomness,
network access, the local home directory, or provider credentials; inject a
clock, entropy source, and store so a test can replay the same result. Real
transport qualification tests separately use bounded local processes, loopback
sockets and deadlines, with owned-process cleanup and no provider credentials.

The initial test stack is:

- `cargo test --workspace --all-targets --all-features` for unit and integration
  tests, plus `cargo test --workspace --doc` for documentation tests;
- `proptest` for parser, canonicalization, ordering, expiry, deduplication,
  capability scope, and state-machine laws, with checked-in regression cases;
- compile-fail doctests proving that unverified events cannot call effect APIs
  and external crates cannot construct capabilities (`trybuild` is optional
  when a case needs more detailed compiler diagnostics);
- planned `cargo-fuzz`/libFuzzer targets for bounded wire, manifest, envelope,
  and intent parsers, with corpus limits and no side effects;
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
- Prove one in-memory steel thread from bounded wire bytes through relay-shaped
  delivery, signed identity/audience/replay validation, local authorization, a
  typed host effect, and a receipt before adding real transport or OS effects.
- Implement bounded identifiers, timestamps, epochs, room manifests, and
  lifecycle types in a pure, `no_std`-where-feasible crate.
- Add strict `unknown` parsers with stable error codes and deny-by-default
  handling for unknown/oversized/deep values.
- Add colocated unit tests, `proptest` laws, checked-in regressions,
  `trybuild` authority-boundary tests, fuzz targets, and protocol vectors.

**Exit evidence:** `cargo test --workspace --all-targets --all-features`,
`cargo fmt --check`, Clippy with warnings denied, compile-fail tests,
`cargo check --target wasm32-unknown-unknown`, the `vhalla-steel-thread`
command and E2E receipt test, and no unsafe code or authored JS/TS in the
foundation crates.

The in-memory checkpoint is implemented by `vhalla-steel-thread`. The
2026-09-12 audit found that its original cloneable capability and publicly
constructible effect request did not enforce the intended single-use boundary.
The repair requires a consumed verified message, explicit full-key requester
grant, move-only capability and host-owned policy validation at execution.
Production readiness additionally requires retained session replay state,
expiry/context checks, restart freshness and actual native/browser ingress.

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

### Phase 5 — shared Dioxus UI and operator controls

- Build shared Dioxus UI/client crates with separate web and desktop launchers;
  preserve the accepted dependency and custody seams above.
- Add room/agent views that visibly distinguish received, proposed, authorized,
  and completed states.
- Add origin pairing, CSP, nonce-checked messaging, key rotation/revocation,
  and explicit gestures for sensitive actions.

**Exit evidence:** actual web and desktop journeys share source and semantic
fixtures; origin confusion, hostile rendered content, stale pairing, IPC and
postMessage replay fixtures fail closed. Renderer dependency does not enter
headless or embedded builds.

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

- **Wire:** retain the bounded fixed-field application envelope currently
  implemented in `vhalla-wire`; version changes in signed framing explicitly.
  The earlier canonical-CBOR preference came from `prototypes/wire-format`,
  not the implemented codec. Do not add a serialization dependency solely to
  match that preference. Require reviewed canonical bytes, bounds, rejection
  vectors and cross-target execution for the actual format. Consider CBOR for
  a concrete extensible object only when its benefit is demonstrated.
- **Transport:** keep application events independent from sockets and model
  relay loss, duplication, reordering, and bounded inboxes at that seam. The
  `prototypes/transport` experiment supports a libp2p-first investigation
  because browser capability is a priority. Current-source review shows Rust
  libp2p browser transport dials native WebRTC-direct peers; Iroh browser traffic
  is relayed. Direct browser-to-browser remains a separate experiment. Follow
  the dated source evidence in the readiness plan; no relay is an authority
  or durable store.
- **Private messaging:** use pairwise owner DMs in the first secure release.
  The `prototypes/privacy` membership-epoch model shows why group membership
  changes require key rotation and stale-envelope rejection. Defer group E2E
  until offline delivery, browser key custody, history retention, and
  revocation semantics have a complete design.
- **Effects and history:** keep a typed capability/effect boundary separate
  from bounded local history. The `prototypes/effects` experiment shows that
  remote requests remain inert and history can deduplicate within count/byte
  limits. Its cloneable capabilities only model per-instance consumption; they
  are not a compiler-enforced single-use boundary. Use the repaired workspace
  policy/host seam as the current reference. A future OS runner needs separate
  process or WASI isolation beyond the present in-memory host.
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
implementation phase must replace placeholder identity checks with real
cryptographic verification and qualify actual codecs through review, vectors,
adversarial tests and measured native/WASM execution. Replace an existing
codec only when a demonstrated need justifies a versioned migration.

## Remaining forks and production gates

1. **Wire productionization:** freeze vectors for the actual bounded binary
   format, finalize version and unknown-field policy, and run native/WASM
   execution and decoder fuzzing. An encoding change requires a new version.
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
