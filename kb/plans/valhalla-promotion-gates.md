---
title: Valhalla readiness and promotion gates
type: plan
area: valhalla-promotion
status: in-progress
tags:
  - architecture
  - security
  - verification
  - provenance
  - checkpoints
  - wasm
---

# Valhalla readiness and promotion gates

**Status:** in progress; narrow primitives exist, integration gates remain open
**Date:** 2026-09-12  
**Scope:** a usable native/browser agent room, its security and operational
evidence, and selective promotion of reference code into `vhalla-*` crates

This plan turns the prototype hardening wave into a reviewable promotion path.
The prototypes are useful models, but their passing tests do not automatically
make their data structures, cryptography, persistence, or distributed claims
safe for production. Promotion is allowed only when the production crate that
owns an invariant can enforce it at its boundary and the steel thread proves
the invariant survives transport, policy, and host integration.

Related design documents:

- [Valhalla security-first design](valhalla-security-first-design.md) defines
  the authority seams, URP principles, and compiler-enforced boundaries.
- [Valhalla eukaryotic transition](valhalla-eukaryotic-transition.md) records
  the disposable prototype wave and its remaining promotion risks.
- [Valhalla blockchain architecture](valhalla-blockchain-architecture.md)
  separates signed evidence and realm checkpoints from any future global
  settlement chain.
- [Botcaptcha, receipts, and games](valhalla-botcaptcha-ledger-games.md)
  defines work receipts, game evidence, and their limits as authority.
- [[plans/valhalla-room-directory|Shared rooms and creation allowance]] defines
  the selected public slug namespace, owner creation authority and admission
  gates; the isolated model is not a deployed directory.

## Outcome

The promotion result should be a small, portable Rust protocol core in which:

1. canonical bytes and domain-separated hashes are defined once;
2. authenticated provenance binds identity, content, policy scope, epoch,
   expiry, and revocation without treating authentication as authorization;
3. checkpoint roots are derived from bounded canonical history rather than
   accepted as caller-supplied claims;
4. replay, queues, receipts, and lifecycle retention have explicit bounds and
   fail closed when those bounds are exhausted;
5. property and state-machine tests exercise adversarial schedules, not only
   happy-path examples; and
6. the end-to-end steel thread demonstrates that remote data cannot mint or
   widen a host capability.

The event and receipt layer is a prerequisite, not the whole product. The
standing implementation objective also includes a usable `vhalla` command,
browser participation, autonomous discovery, and a real game consumer. Do not
declare readiness after completing only the reference models below.

## Product acceptance and implementation order

The source audit at `c373c71` found no socket transport, browser application,
installed CLI, persisted network identity, signed invitation parser, room
membership protocol, or connection lifecycle. The in-memory transport,
browser pairing, and discovery experiments are models. In particular, browser
pairing uses equality checks, replication retains an unbounded seen-ID set,
and the game-session model uses unauthenticated integer approvers and toy
hashes. None may be imported as a production security boundary.

| Slice | Required observable result | Status and admission evidence |
| --- | --- | --- |
| 1. Authority and message sessions | A message crosses bounded decoding, strict signature and full-key/context checks, retained replay state, explicit requester policy, and host-owned execution context | Repair first: baseline authorization was cloneable and its public effect request bypassed policy. Require exploit regressions, compile-fail boundaries, expiry and rotation tests, and no effect on denial. Only the in-memory read exists; OS effects stay absent. |
| 2. Actual native peers | Two separate `vhalla` processes exchange signed chat in an explicitly invited room using persisted identities | The maintained loopback steel thread now has persisted identities, explicit full-key invitations, actual child-process restart evidence, and a versioned bounded JSON-lines output interface. A fixed-width owner-signed invitation claim now binds owner/invitee keys, room scope, epoch, expiry and nonce without granting transport authority. Product admission still requires non-loopback transport qualification, malformed-frame/queue/loss/reconnect evidence, resource measurements, and reviewed invitation integration. |
| 3. Shared web/desktop participation | Dioxus web and desktop applications reuse Rust screens/client logic, join the same room, display foreign text safely, and send authenticated messages | Execute actual browser and selected desktop renderer journeys, not only `cargo check`. Verify separate identity/storage/transport adapters, resource/navigation authority, applicable origin/CSP/IPC, restart, explicit owner pairing, denial paths and direct versus relay routing. Generated binding glue is allowed; no authored JS/TS application or protocol implementation. Headless/embedded crates must not depend on Dioxus. |
| 4. Resilient rooms and discovery | Three peers converge on bounded chat history, survive one peer/relay loss, and bootstrap through interchangeable signed hints; owner-authorized agents register and find rooms in the shared public directory | Separate delivered, locally stored, replicated and executed states. Define concurrent ordering and retention without abusing the linear checkpoint ledger as multiwriter consensus. Qualify two replaceable bootstrap/relay choices, identity rotation and recovery without silently resetting replay state. Public registration also requires the room plan's atomic slug/owner-slot/allowance transition, partition and recovery evidence, authenticated awards, durable manifests and actual CLI/Dioxus journeys. |
| 5. A real game | Platonik runs through an optional Valhalla session adapter and a receiver independently verifies the result | Preserve exact versioned inner artifacts, charge verification budgets, request large traces separately, and test tampering, duplication, wrong ruleset/case, pause/resume and failed exchange evidence. Keep game authority explicit; multiplayer does not imply permissionless finality. |
| 6. Usable distribution | A clean machine can install, initialize, invite, join, recover and remove Valhalla using documented commands | Admit locked dependency/license/advisory/provenance evidence, bounded decoder fuzzing, native/WASM execution vectors, exact toolchain and release artifacts, real target builds, restore drills and performance budgets based on measurements. Check `vh` availability before offering it as an optional alias; never overwrite another command. |

Each slice needs a named implementation owner, independent review, current-tree
repository gates, and a reproducible user journey. Record limitations alongside
evidence. The coordinator owns final integration and delivery. Tests are not a
security audit, and availability cannot be guaranteed across partitions or
without reachable peers. Persisted owner identity and session freshness are
required before advertising unattended network agents.

Checkpoint rotation, protected pins, settlement and botcaptcha remain useful
parallel investigations. They do not block chat-only slices unless those slices
actually depend on their guarantees. There is no default remote shell/tool
execution, token issuance, or autonomous value transfer in the first room.

### Transport decision after current-source review

As of 2026-09-12, retain **libp2p as a candidate**, subject to execution evidence.
The released Rust `libp2p` 0.57.0 requires Rust 1.88; its native WebRTC adapter
0.10.0-alpha is still alpha. The browser adapter 0.5.0 dials WebRTC-direct peers
but rejects listening. It does not establish direct browser-to-browser support.
See the [published manifest](https://docs.rs/crate/libp2p/0.57.0/source/Cargo.toml)
and [browser transport source](https://docs.rs/crate/libp2p-webrtc-websys/0.5.0/source/src/transport.rs).

The first disposable native spike uses QUIC, explicit expected transport peer
identity, a bounded binary codec, and no discovery service. Browser-to-native
WebRTC follows independently. Cap connections, concurrent requests, stream and
receive windows, frame bytes, queues and deadlines inside the adapter. Keep
transport identity separate from the application signing key and local policy.
Relay admission later requires explicit reservation, circuit, duration, byte
and rate limits, with two interchangeable relay processes.

The executable reference now lives in `prototypes/native-quic`, excluded from
the workspace. It exchanges 17-byte and full 65,536-byte payloads between
separate native processes and rejects a substituted transport PeerId. The first
reconnect attempt exposed a lingering connection slot; the repaired sender
disconnects and the test waits for the listener's close event before reuse.
Fixture keys are public and sockets are loopback-only. Passing this test is
transport interoperability evidence, not application authentication, private
identity custody, Internet reachability or browser support. Its native graph
contains 195 normal/build dependencies; the unoptimized arm64 binary measured
about 19.7 MB with debug information disabled. This supports keeping the stack
in an optional host adapter rather than the portable core. Build RSS and test
duration in its README are not idle-memory or latency benchmarks.

Iroh 1.2.0 is an alternative when browser relay traffic is acceptable. Its
[browser documentation](https://docs.iroh.computer/languages/wasm-browser)
states that browser connections are relayed. Use explicit custom relays and a
minimal preset for an experiment; provider DNS and public bootstrap defaults
must not become protocol dependencies. Neither library alone currently closes
the direct browser-to-browser requirement.

For that fork, a bounded two-browser WebRTC experiment must inspect the selected
ICE path, continue after signaling stops, reconnect through another signaling
service, and fail clearly when a direct path is unavailable. The Rust
[Matchbox implementation](https://github.com/johanhelsing/matchbox) can serve as
an interoperability oracle, but its 0.14.0 socket code has unbounded internal
queues and public STUN defaults. An outer frame bound does not fix those queues;
do not admit it unchanged. All authored application code can remain Rust, but
browser bindings need generated JavaScript and transport TLS dependencies may
include C/assembly. Embedded/no-`std` claims apply only to separately verified
small core profiles, not the complete native network stack.

### Platonik boundary after inspection of the latest engine

Reviewed Platonik commit
[`76ea2db`](https://github.com/hraness/platonik/tree/76ea2db82abf0e146f1a2abb9d89b5848289e0f6).
The active checkout also contains another task's uncommitted exchange-capacity
work; that work is preserved and is not treated as released evidence.

| Option | Benefit | Cost | Decision |
| --- | --- | --- | --- |
| Move the complete core into the base platform | Immediate access to all current experiments | Couples networking and security to game rules, graders, fixtures, `std` and JSON | Do not make this the default platform dependency |
| Extract a shared deterministic kernel immediately | Could unify metering and replay | Extraction can change canonical bytes, fuel semantics, historical results and charged work | Require parity evidence before moving semantics |
| Optional game adapter, then proven shared pieces | Reuses the actual engine while keeping the portable platform small | Requires bounded artifacts, evaluator budgets and target qualification | Start here |

The current Rust engine is a finite rule machine with typed game actions, not
the Lisp imagined in the original botcaptcha proposal. Its useful foundations
are bounded input, a pinned ruleset, deterministic execution, cumulative work
accounting, replay and independently checked outcomes. Platonik's
`check::verify_receipt` reruns the experiment; a hash or a remotely supplied
verification report does not replace that check. Introduce private immutable
`VerifiedRun` evidence only after the adapter has verified locally.

Preserve exact Serde JSON receipt hashes and protocol versions: canonical input
bytes are charged work, and fuel failure rolls back staged effects while
retaining consumed work. A naive serializer change or replacement fuel counter
could change the economics. Keep habitat types, interpreter semantics, grades,
fixtures and economy in the adapter. The smallest candidate shared contract is
versioned session input, ruleset identity, explicit work allowance, ordered
replay inputs, checkpoint identity and checked-result evidence. Its game-facing
API must not expose files, networks, wall clock, signing keys or host commands.

The next cross-repository spike uses the exact committed engine in a disposable
Rust harness: send ruleset digest, case ID and bounded experiment identity;
independently execute and verify at the receiving peer; compare unchanged
hashes, traces, costs and exchange grades across reference worlds and failure
controls; then test tampered/rehashed receipts, wrong model/case, duplicate and
stale sessions, oversized input and pause/resume without resetting fuel.
Measure verification count, memory and artifact sizes before choosing chunk
defaults, and run the same engine under WASM before claiming portability.

`bloom_exchange` supplies a useful request → custody → provenance-bearing
acknowledgment → service model and rejects contradictory failed attempts too.
Its simulator provenance is not peer authentication. Committed Bloom receipts
already reach roughly 1.25 MB, so traces belong in explicitly requested bounded
artifacts, not 64 KiB room frames. Program size, charged work, demonstrated
ability and money remain distinct; complexity or botcaptcha cannot mint host
authority, prove agency or establish financial value.

## Current boundary and promotion rule

The production workspace currently contains these crates:

| Crate | Owns now | Must own after promotion |
| --- | --- | --- |
| `vhalla-core` | no-`std` identifiers, epochs, bounded untrusted bytes | typed event/checkpoint identities, bounded state transitions, and no authority-bearing constructors from raw data |
| `vhalla-ledger` | bounded linear event history and locally derived checkpoint roots | durable history/recovery, signed checkpoint proofs, explicit quorum/trust configuration, and compaction anchors |
| `vhalla-wire` | canonical bounded envelope encoding/decoding | versioned canonical evidence envelopes, strict length/count limits, and compatibility rules for checkpoint/provenance objects |
| `vhalla-crypto` | Ed25519 signed envelopes, SHA-256 peer handles, a sequence replay window | domain-separated transcript/hash helpers, signed provenance/receipt verification, revocation binding, and bounded replay state |
| `vhalla-policy` | local owner policy and single-use epoch-bound effects | admission decisions that consume authenticated evidence while keeping remote data separate from authority |
| `vhalla-transport` | opaque bounded frames and bounded in-memory queues | delivery only: backpressure, duplication/reorder/loss simulation, and no inspection-based authority |
| `vhalla-host` | typed in-memory effect runner and receipts | host execution and durable receipt handoff, with no path from wire data to an effect |
| `vhalla-steel-thread` | signed envelope → transport → policy → host receipt | integrated proof that provenance, checkpoint, replay, expiry, and recovery boundaries compose |
| `vhalla-session` | experimental paired chat handshake and directional replay | reviewed app/transport identity binding, real reconnect/restart and browser integration |
| `vhalla-identity` | experimental Unix private-file application key | qualified secret custody, recovery, transport-key integration and installable native program |
| `vhalla-witness` | `no_std` witness-mode VM (Platonik habitat-v1 restated), canonical codecs, digests, task manifests, keyless move-only run capability, receipts | the game kernel behind the Slice 5 Platonik adapter and any later witness language, with replay evidence and vectors kept bit-exact across versions |
| `vhalla-botcaptcha` | signed witness-mode challenge and response, verified challenge as the only capability source, one-use window, and a replaying verifier | steel-thread witness frames (Gate 5), Hashcash mode, and receipt export as a signed claim for a per-realm DAG |
| `vhalla-game-platonik` | game identifiers and domains, canonical encodings with every bound, the audience-free `GameRecord`, the `GameManifest`, the optional Platonik oracle converter, the `PlatonikV1` engine seam, host-ordered sessions over `vhalla-ledger` with the two-phase live bind, replay-checked checkpoints, and the receiver with pre-charged allowances, settlement, pause and replace across an epoch bump, bounded artifacts, the signed-claim export, and the `quorum` attestation hook | a rooms record kind carrying a game commitment, after which `Authority::Quorum` sessions can open |
| `vhalla-native` | explicitly pinned paired loopback chat | qualified public routing, identity lifecycle and browser interoperability |
| `vhalla-cli` | feature-gated native chat and local signed social/discovery commands | installable client with separately qualified public transport and storage adapters |
| `vhalla-social` | signed owner/agent records, causal projections, exact facets and bounded archive sync | preserve verified control/history under any future retention or network extension |
| `vhalla-social-store` | complete Unix signed archives with exact publication recovery | separately qualify other storage platforms and external freshness anchors |
| `vhalla-discovery` | bounded local search, Following/Discover and private reader signals | measured workload-specific indexes, wider retention and target memory qualification |
| `vhalla-attention` | derived owner notifications and exact per-reader acknowledgement | preserve bounded honest read precision in future adapters |
| `vhalla-discovery-store` | separate Unix private reader state with source-first recovery | browser durability and privacy qualification before browser activation |
| `vhalla-retrieval` | optional pinned-peer candidate rounds with verified local hydration | actual adapter evidence and separate public-network qualification; no discovery or wake authority |

The rule is **model first, production second, integration third**. A reference
crate may be promoted only after its invariant is restated in production types,
its dependency and wire format are reviewed, its failure and recovery behavior
are tested, and the steel thread exercises it through the real crate seams.
Prototype APIs and lossy toy digests must not be copied into production merely
because their examples pass.

The first production seam is deliberately split in two. `vhalla-core` owns
typed identifiers and bounded event/checkpoint value types;
`vhalla-ledger` crate owns retained history, state-root derivation, compaction,
and recovery. This keeps persistence and authority out of the no-`std` kernel
and prevents a caller-supplied root from becoming a core-level capability.
Likewise, `vhalla-crypto` may own stateless signed-claim verification and a
bounded replay primitive, while durable receipt retention remains an explicit
ledger/host concern.

## Execution status

### Platonik session adapter, stage 1 — 2026-09-17

The [[plans/valhalla-platonik-session-adapter|session adapter plan]] landed its
stage 0 (`platform::run_observed` in `vhalla-witness`, spike 1 passed with
per-frame hashing at 4.4 ms native worst case and 15 ms for the corpus under
wasm32) and its stage 1 skeleton, `crates/vhalla-game-platonik`: `ids`,
`wire` with every `MAX_*` bound and the widest-variant bound tests, `record`,
`manifest`, and the feature-gated `oracle` converter whose output reproduces
all 28 witness corpus vectors byte for byte and whose six `Replay`-kind
manifest vectors carry experiment ids equal to Platonik's `artifact_hash`.
The default path carries no `platonik-core` on normal dependency edges and
compiles for wasm32; CI checks both. Stage 2 followed the same day: `PlatonikV1`
over `run_observed` with the hashing frame observer, sessions with admission,
the two-phase live bind, the reveal checks, the input gate, seal planning and
commit over `vhalla-ledger`, and the receiver with budgets and the prefix
check. Two end-to-end sessions (a fixture replay and a live session with two
seals) verify at one receiver, a lying host is refused with the seal retained,
and equivocation freezes its author. Stage 3 followed: settlement admitted only by
reproducing the receipt, ranked by self-verifiability in either arrival order,
pause on a missing member with a sealed `Replace` resuming in the next epoch,
fills carrying their fallback program, cancellation, spike 4 (18 sessions with
a replace at a random seal, every result equal to the plain run), the
adversarial mutation corpus, and the stable-toolchain fuzz harness prototype;
`prototypes/game-session` and `prototypes/settlement` are deleted. Stage 4 followed: the bounded artifact
assembly with the browser record mapping (spike 2: the largest corpus artifact
is 1.5 % of the 8 MiB ceiling, peak retention exactly 1.0 ×), the oracle audit
(spike 6: 81 artifacts, every id equal to Platonik's own), wasm32 parity of
the game vectors, and `vhalla game replay <bundle>`, the reproducible user
journey that verifies a session bundle from a second receiver. Slice 5's
stated result, Platonik running through an optional Valhalla session adapter
with a receiver independently verifying the result, is now implemented and
tested; the row stays open only for stage 5 (quorum hook, signed-claim export,
steel-thread evidence kind) and human review at merge time.

### Platonik session adapter, stage 5 — 2026-09-17

Stage 5 landed: `VerifiedSettlement::export_claim` signs a `SignedClaim` in
`ClaimDomain::Receipt` with the settlement hash as subject and the verifier's
own seed, verified back through `vhalla-crypto` under the exact context and
refused under another key or domain; the `quorum` feature adds
`quorum::attest`, which decodes the decided `Batch`, requires the
`CommitCertificate` to decide its value id, calls the caller's
`Adapter::absorb`-shaped verify hook, locates the settlement hash inside the
batch through the caller's locator, and yields a `QuorumSettlement` (no
`Clone`) only when that hash is the reproduced one; `vhalla-steel-thread`
gains `KIND_GAME_SETTLEMENT` and `GameSession`, which admits game records only
from frames the session's host signed, routes events to the receiver and
settlements to the settlement check, and whose evidence types cannot enter
`RemoteRequest` (compile-fail doctests). The frozen live vector plays through
the steel thread to a reproduced settlement; a player-signed frame, a
relabelled kind, a non-record body, a transport replay, and a duplicate claim
are each refused at their own layer, and a memory session refuses the kind
with zero reads. `Authority::Quorum` at open stays reserved: no rooms or
social record kind carries a game commitment yet.

### Witness platform crates — 2026-09-16

The [[plans/valhalla-witness-platform|witness platform plan]] applied the
Roc-style platform/application split to Botcaptcha witness mode and landed two
pure crates after four discovery spikes.

- `crates/vhalla-witness` restates the Platonik `habitat-v1` engine as a
  `no_std` library with `sha2` as its only dependency, adds fixed-width canonical
  codecs with bounds derived from the widest variants, domain-separated SHA-256
  digests, the validated `TaskManifest` with fixed and open program slots and a
  per-case loading-work floor, the keyless move-only `RunCapability`, `run`,
  `WitnessRun`, `WitnessReceipt`, and the decodable `ClaimedReceipt`. Its
  `tests/vectors/` hold one file per fixture, `bridge-v1` case, and the 64 KiB
  worst case; every test run replays them.
- `crates/vhalla-botcaptcha` owns the signed `Challenge` and `Response` with
  the games plan field names, `VerifiedChallenge` as the crate's only source of
  run capabilities and receipt bindings (module privacy plus a `clippy.toml`
  `disallowed-methods` entry), the non-`Clone` `OneUseWindow` keyed by the
  dedup scope with `Replay` and `Equivocation` distinguished, and
  `WitnessVerifier` with one error variant per step and window consumption
  last. Clock and entropy are injected; nothing executes network-supplied code.
- Evidence: `prototypes/witness-restatement` replays every fixture, all 21
  `bridge-v1` cases, 400 random experiments, and the worst case bit for bit
  against `platonik-core` at `5eedec07`, and its allocation probe observes zero
  tick-loop allocations; `prototypes/witness-wasm-parity` finds native, wasm32,
  and committed renderings identical on 28 vectors (release: 5.3 ms native
  worst case, 10.9 ms for the corpus under wasm); `prototypes/witness-contract-spike`
  shows the delivered-sparks floor admits working programs, tolerates padding
  within the activation budget, and rejects idle programs that a
  transfers-plus-messages floor would have admitted. Both crates pass the
  workspace format, clippy, test, and doctest gates and the wasm32 check, which
  `rust.yml` now runs for `vhalla-witness`.
- Limits: `RunCapability` is minted locally from data the caller holds and
  proves no remote fact. A `VerifiedWitness` is not identity, personhood, or
  host authority, and cannot enter `RemoteRequest::from_verified`. The
  one-use window is volatile: a restarted verifier restores it durably or
  starts with a fresh `started_at`, which refuses earlier challenges; two
  verifier instances sharing an issuer key need a shared durable ledger, which
  is outside these crates. The Gate 5 witness frame and the independent Python vector oracle landed the
  same day (`WitnessSession`, `KIND_WITNESS_RESPONSE`, the `compile_fail` proof
  against `RemoteRequest::from_verified`, and `/vectors/witness-v1.json`). Hashcash mode
  followed as `Algorithm::Hashcash` in the same crate. The Slice 5 Platonik
  session adapter remains open.

### Shared public room directory — 2026-09-13

The user selected one shared public slug namespace: a finalized `#rust` has one
owner in the pinned directory; offline proposals remain pending. The
[[plans/valhalla-room-directory|room directory plan]] extends existing channels
with owner-bound creation, bounded slug/description search, engagement-earned
creation allowance, escalating lifetime-slot prices and a rolling rate limit.
Ordinary social history remains eventually consistent; public name allocation
and allowance spending need one agreed order.

The isolated Rust model exercises sequential allocation, exact signed proposals,
owner-slot races, accounting, tombstones and bounded search. Its partition
counterexample rejects independent local-map finalization as a uniqueness
guarantee. This is reference evidence only: R1–R6 still require
authority/control-history integration, authoritative social-evidence
admission, a qualified consensus engine, durable state, CLI/Dioxus journeys and
release qualification. No live room-registration service or command is admitted
by this increment, and existing chat, invitation, portrait and launch gates stay
open according to their own evidence.

The maintained `vhalla-rooms` crate adds R1a's bounded canonical permission,
permit, proposal and metadata-update records with distinct signature domains,
full owner/agent identities and private immutable verified wrappers. Its 2 KiB
decoder and cryptographic verification produce evidence only. The crate cannot
register a name, accept a claimed current controller, spend allowance or create
a finalized-room value. The R1b authority adapter, the R2 mature-award
derivation and the R4 registry application layer are now implemented in the
same crate — see the
[[plans/valhalla-room-directory|room directory plan]] for their basis-freshness,
snapshot-commitment, committed-evidence and deterministic-application evidence.
Durable manifests, the registry service, CLI surfaces, Sybil/collusion
calibration and consensus integration remain open. Old social v1 wire and
`Rights::ALL` remain unchanged.

### Dioxus application decision — 2026-09-13

The user selected Dioxus and its maintained tooling for the browser and desktop
applications. The accepted [[plans/valhalla-security-first-design|security design]]
now separates shared Rust UI/client state from web and desktop launchers, storage,
transport and custody. Dioxus dependencies are confined to standalone prototype
workspaces; no maintained application binary is promoted. Shared screens, typed
services and source-derived renderer boundary experiments have baseline evidence.
Stock WebView interception is insufficient for the intended privileged client;
the native/Blitz candidate passed its compiled feature audit with explicit closed
providers. Actual baseline browser/native journeys exercised profiles, portraits,
threads and private reader acknowledgments; the browser IndexedDB qualifier passed
its specified recovery/cancellation cases. Native input/disclosure failures led to
reviewed shared Rust corrections whose rebuilds were rejected before execution.
Corrected-artifact qualification, native adapter execution, platform security and
accessibility, maintained integration and final repository gates remain open.
The new pure-Rust Dioxus preview assembler produces a fresh generated closure
with an explicit `#main` shell and SHA-256/size manifest; its focused tests,
Clippy and assembly against the corrected WASM output pass. This is packaging
evidence only and does not close live browser or desktop qualification. The
shell now uses a same-origin CSP with an exact hash for its sole module
bootstrap, enables only the required `wasm-unsafe-eval`, and rejects control or
markup delimiters in asset names before HTML insertion. Response headers,
origin pairing and live renderer security remain separate gates.

### Local discovery and private attention — 2026-09-13

The [[plans/valhalla-social-discovery|discovery implementation record]] adds signed
UTF-8 mention/tag facets without rewriting legacy bytes, Following and explainable
Discover feeds, bounded local text/typed search, boards, a known-owner directory,
owner notifications and separate private reader preferences/read state. The
`experimental-social` CLI exposes these local surfaces. Public signed snapshots
exclude private signals; sibling readers acknowledge and personalize independently.

Independent reviews and focused tests cover current exact revisions, stale cursor
rejection, late revocation, partial history, request floods, private feedback and
source-before-private persistence. The seven-test actual CLI walkthrough and the
11-test native private-store suite passed, including real child-process locking and
nine publication fault points. A signed fixture has passed native/WASM execution
parity; the full joined tree repeats that evidence before delivery. Compiler tests
reject conversion of discovery and notification outputs into host requests.

Optional `vhalla-retrieval` accepts only explicitly pinned peers and context-bound
finite requests. Candidate IDs are hints; every signed record traverses ordinary
archive admission, and candidate presentation is rechecked against the current
local query. Its actual paired-QUIC fixture passed alongside six model tests and
strict Clippy. Final integration remains in progress, with no public-network or
browser activation.

Native scanner/index measurements support a scanner baseline and disclose partial
coverage at exhausted budgets. The measured capacities and whole-process RSS do
not qualify isolated query peak allocation, maintained end-to-end latency, browser
memory or embedded targets. Canonical retention remains capped at 4,096 total
records, with no semantic garbage collection. Endless feeds, public view-count
credit, private encrypted publication, automatic agent wake and public retrieval
services remain unqualified extensions; this change grants none of them authority.

### Owner social records and local CLI — 2026-09-13

The [[plans/valhalla-social-capital|reviewed social plan]] and
[[plans/valhalla-social-implementation|implementation record]] select a bounded signed
event archive rather than applying linear ledger consensus to ordinary social
activity. Maintained [social](../../crates/vhalla-social/README.md) and
[Unix store](../../crates/vhalla-social-store/README.md) crates implement owner-bound
agent lifecycles, causal profiles/bios, profile/channel threads and exact replies,
revisions/retractions, reposts/quotes, owner-deduplicated follows/reactions, and
locally weighted historical contribution. The explicit `experimental-social`
CLI exposes these operations and signed file exchange; it opens no public network.

Independent review and three disposable spikes resolved causal conflicts,
revocation/history boundaries, commitment selection, capacity and recovery.
Capacity pressure closes current eligibility without erasing accepted history;
missing/disputed evidence produces an incomplete result. Results bind complete
local limits and eligible-owner policy. Native recovery uses exact signed intent
and an optional external exact pin; without an independent pin coherent disk
rollback remains undetectable. Automatic compromised-key recovery is unavailable.

The local integration gate passed 119 commands, including 166 workspace tests,
15 doc/compiler tests, strict Clippy and all prototype checks. The final social
source compiles to WASM. Complete dependency admission checked 37 lockfiles with
zero vulnerabilities; the existing `paste` maintenance advisory remains. Exact
commit Rust/security CI remains the remote delivery gate. Social records cannot enter host capabilities. Browser storage/UI, private
encrypted publication, public discovery/transport, unbounded archival scaling,
Sybil-resistant identity and economic settlement remain separate promotion work.

### Native social steel thread — 2026-09-13

`vhalla-steel-thread/tests/native_social.rs` now drives the maintained native
QUIC adapter rather than the in-memory session. A persisted sender identity
reopens for each fresh session; five signed social bodies cross real loopback
sockets, including an exact duplicate and a forged inner signature. The
receiver checks the outer application signer, then independently verifies and
admits the inner record under an archive budget. The focused paired-listener
test passes with three inserted records, one duplicate and one rejected
forgery; it also checks that a successful transport acknowledgment does not
imply social admission and that the archive root/length are unchanged by the
forgery. A second test launches the actual test binary as a receiver process,
restarts it with the same persisted identity, and proves a stable application
key with fresh routes, duplicate idempotence and forged-inner rejection. This
is process-level loopback evidence, not public routing, browser
interoperability or durable multi-peer replication; the helper uses the same
test binary and does not claim OS sandbox isolation.

### Owner-related agent portraits — 2026-09-13

The user's supplied Codex sidebar reference leads to a separate deterministic
Rust [portrait prototype](../../prototypes/agent-portraits/README.md) and
[[plans/valhalla-agent-portraits|design plan]]. Every owner can use all 16 form
families; shared cuts, material, palette and emblem carry family resemblance.
No identity/affiliation authority is inferred from images. The native renderer,
property tests, XML allowlist and golden vectors remain excluded reference work;
visual matching, runtime WASM parity and signed affiliation admission remain open.
The implemented social genesis can supply a future display adapter; inactive
agents retain historical affiliation. Compact grayscale currently has only 48
family categories (35 occupied by the 64-owner sample), so distinct SVG source
does not qualify large-population recognition. The generated gallery has been
reviewed on desktop/mobile; the prototype remains excluded from live UI.

The preceding `62b78e9` source passed Rust CI
[34741101275](https://github.com/hraness/valhalla/actions/runs/34741101275)
and security CI
[34741101061](https://github.com/hraness/valhalla/actions/runs/34741101061).

### Dependency and pre-admission checks — 2026-09-13

At `87a1987`, cargo-audit 0.22.2 checked all **32** repository lockfiles against
RustSec database `b50980aad8b8f14f77e25a97b32dd94bf008b0af` (1,243 advisories),
without ignored advisories or target filtering. All exited successfully with
zero known vulnerabilities. The workspace, native QUIC reference and nested
browser fixture retain the informational `RUSTSEC-2024-0436` warning for
unmaintained `paste` 1.0.15, reached through `netlink-packet-core` and `if-watch`
in the all-target graph. It is not compiled in the inspected macOS graph. Keep
this maintenance issue visible; no warning was suppressed or dependency silently
replaced. [The snapshot](../../docs/evidence/rustsec-2026-09-13.json) binds every
lock hash, tool release digest and database commit. This is known-advisory
evidence, not review of vendored code or a general safety claim.

A separate bounded loopback diagnostic confirmed a pre-admission retention
problem in native `libp2p-webrtc` 0.10.0-alpha. The UDP multiplexer records a new
source address before returning an offer. Dropping that offer without creating
its connection left **32 retained addresses, zero connections and zero mapped
addresses**; they remained after the sockets closed and a 150 ms poll. Source
inspection finds no size bound or expiry on this set. The probe drives the
actual private multiplexer in a disposable source copy; it models declined
offers, not a full Swarm flood or a process-memory measurement.

The diagnostic is retained next to the browser fixture. No native dependency
patch is enabled. Before public WebRTC admission, prototype bounded reservations
that are released on decline, cancellation, timeout and success, and prove a
fixed memory bound plus cooperative polling under churn. Raising the outer
connection cap does not address state created below that cap. The reference
remains public-fixture, loopback-only and limited to a ten-minute process lifetime.

### Actual browser records and closure repair — 2026-09-13

The standalone `prototypes/browser-records` now contains a `no_std` bounded
transfer state machine and a nested, reproducible Rust/WASM-to-native WebRTC
fixture. This is the first actual-browser transport evidence in this plan; it
does not pass the browser room, key custody or application-session gates.

The actual browser established these distinct results:

1. A single 64 KiB frame with small flushed writes succeeded while the reader
   kept up, but a 100 ms read pause triggered the browser dependency's explicit
   `remote overloaded us with messages` error. Its aggregate unread buffer is
   16 KiB. Write fragmentation alone did not solve receive flow control.
2. Sixteen acknowledged 4 KiB records transferred the same 64 KiB with a 100 ms
   pause before every record read. Each record carries an exact total, offset
   and object digest; the receiver validates the complete digest before its
   final acknowledgment. Connection-owned assembly is capped at 64 KiB and ten
   seconds. Invalid ordering, metadata, acknowledgments or time permanently
   closes the corresponding transfer owner. No receive cap was raised.
3. Duplicate stream closure caused native `BrokenPipe` errors after otherwise
   successful responses. The codec had closed and libp2p's request-response
   handler closed again. The codec now flushes and leaves closure to that
   handler. The real browser test then produced sixteen `RESPONSE_SENT` events,
   one complete object, and no native or current-page console errors. The
   correction also applies to the maintained QUIC codec, with a regression that
   permits exactly one close after codec return.
4. The browser dependency retained JavaScript event handlers after destroying
   their Rust closures. A local experimental patch detaches handlers on the
   final shared callback-owner drop and closes peer connections on failed or
   cancelled authentication. The narrower patch passes the observed transfers
   and reconnect after native closure. A variant that also closed the raw data
   channel in Drop caused a timeout and was rejected. Provenance and the MIT
   license accompany the vendored reference; independent review is still open.

The fixture binds loopback, uses public transport keys, safe text rendering,
self-only CSP, four connection/stream/event caps and owned process teardown.
CI compiles its native and WASM paths; actual-browser execution is a separate
gate. See the [reproduction and recorded evidence](../../prototypes/browser-records/interop/README.md).
The parent crate has nine unit/property tests, including a fixed wire vector;
the nested codec has three tests. These are experimental transfer bytes and
acknowledgments, not signed application receipts or durable storage.

Next: review the dependency patch independently; exercise cancellation, page
suspension, peer rejection, resource recovery and supported browser engines;
then carry the existing paired session through this transport with explicit
browser key custody. Long-lived per-channel cleanup, Internet/NAT reachability,
selected ICE paths, browser-to-browser routes and replaceable relays remain
unqualified. The account usage limit still prevents the review workers from
running; no unavailable review has been counted as passed.

### Platonik capacity update and artifact fork — 2026-09-13

Read-only source review and GitHub HEAD verification now identify Platonik
`5eedec07c84af3b4beb82f22cc6c2b9fa3520d42`. Its
[capacity report](https://github.com/hraness/platonik/blob/5eedec07c84af3b4beb82f22cc6c2b9fa3520d42/docs/exchange-capacity.md)
admits the measured six reference worlds/eight controls, not a general service
or runtime sandbox. On its recorded host, process-inclusive run and fresh
verification medians were about 32 ms; the largest receipt was **7,141,362 bytes**.
The recorder's maximum was 211.2 MiB, while individual CLI processes reached
15.1 MiB. This evidence is inspected upstream data, not a Valhalla rerun.

The earlier 7.14 MB local artifact is now published, reviewed Platonik evidence.
That reinforces the existing adapter boundary: keep game receipts out of chat
frames and never import the archive's roughly 160:1 compression ratio as a
storage assumption. The next artifact spike should announce a signed manifest,
request at most 8 MiB only under local policy, and transfer independently
verified blocks of at most 64 KiB using bounded records. Cap the manifest's
block count, total retained bytes, concurrent transfers, decompressed bytes,
verification work and total deadline separately. Resume only blocks bound to
the same immutable manifest; changed metadata, missing blocks, duplicates,
digest mismatch, exhausted budgets and restart must have explicit outcomes.

Validate exact Platonik receipt bytes and expected grades across all six worlds
and eight controls before considering any core extraction. Preserve separate
costs for execution, verification, transport and evidence retention. The current
4 KiB stop-and-wait prototype qualifies one small object; it does not yet carry
these multi-megabyte receipts or provide a game adapter.

### Admission-order repair from real browser testing — 2026-09-13

A real Rust/WASM page exchanged 17-byte and, after smaller flushed writes,
8,192-byte payloads with the native WebRTC fixture. Larger transfers and
reconnects exposed several distinct failures. Browser execution must remain a
qualification gate: compile success did not detect these problems.

One failure also affected the native QUIC composition at `fd4b529`: the derived
libp2p behaviour called request-response admission before the allowlist and
connection limits. Request-response 0.30 preloads a connection in that hook;
a later sibling denial did not remove it. A rejected identity therefore remained
in its bookkeeping, and rejecting a second connection then closing the first
could panic in debug builds. Release builds could retain stale state instead;
disabling the assertion would not be a repair.

Two focused regression tests reproduced both failures before the change. All
rejecting behaviours now precede request-response in declaration order, in the
native adapter and earlier QUIC reference. The tests exercise 64 rejected keys
and the exact establish/deny/close sequence; existing socket and process tests
must continue to pass. Future behaviours that can reject connections must remain
before request-response. Independent review remains outstanding, so the runtime
and build restrictions stay in place.

The browser fixture additionally reports callbacks invoked after their Rust
closures were dropped, and larger-frame reliability remains unresolved. Neither
small-frame success nor this admission repair qualifies its receive buffer,
cleanup, ICE path, application signing or browser-to-browser support. Preserve
those as separate tests instead of increasing memory limits or claiming the
whole browser path works.

### Maintained native chat integration — 2026-09-13

The coordinator owns this increment. `422022e` passed the local aggregate,
Rust CI [34737491792](https://github.com/hraness/valhalla/actions/runs/34737491792)
and CodeQL [34737491359](https://github.com/hraness/valhalla/actions/runs/34737491359).
The next maintained adapter builds on its session and identity APIs. Independent
review is still unavailable because the worker account remains usage-limited.
The CLI therefore requires `experimental-network`, and both bind and dial are
restricted to literal loopback QUIC addresses. This is source/prototype admission,
not public room activation or acceptance of product Slice 2.

`vhalla-cli` now owns the command entry point; `vhalla-identity` remains a custody
library with no transport dependency. Its default build supports only identity
commands. `vhalla-native` provides a bounded listener and one-message sender.
They use OS-generated transport secrets per process, independently pinned full
application keys, actual authenticated transport identities and fresh paired
sessions. Address/expiry handoff is explicitly untrusted routing information,
not a signed invitation. This avoids treating a remote advertisement as a
membership policy; reviewed invitation UX and public transport qualification
remain open. The output-only JSON-lines interface is covered by an actual
two-process hostile-byte test and remains experimental.

The native state machine keeps at most four exact connection IDs, discards each
connection's pending/session state on rejection or closure, and limits pending
handshakes to five monotonic seconds. Readiness and exact-frame acknowledgments
are themselves signed chat. Acknowledgment means volatile reception only. CLI
bodies are hex-encoded so remote text cannot inject terminal controls or forge
output records. Realm/room/epoch remain fixed at 1/2/1 for this short-lived test
path, and no policy or host execution is connected.

Focused tests cross real socket and process boundaries: stranger/wrong-recipient
rejection followed by valid chat, persisted keys after process restart, fresh
transport/session IDs, maximum signed frames, and two simultaneous connections
for one app identity. Replaying a frame on the second connection is rejected
while the original remains usable. This exposed duplicate diagnostics from a
late transport failure after rejection; state-free close failures are now ignored.
Unit/property tests retain frame/route bounds and permanent clock-failure closure.
The maintained tests separately establish process restart and cross-connection
replay rejection; the earlier scratch experiment combined restart and captured
wire replay. Do not label either as physical crash or adversarial disk rollback
qualification.

The native dependency addition reuses libp2p 0.57.0 from the existing transport
experiment and preserves every previously locked package version. Network
features remain absent from the default CLI graph. The full native graph still
includes C/assembly TLS dependencies and is not the embedded profile.

**Next acceptance work:** independent review of identity/session/native joins;
a real Rust/WASM browser connection with measured buffer behavior; reviewed
invitation and owner-pairing UX; public/NAT and replaceable-relay qualification;
then bounded multi-peer history and the Platonik consumer. No networking gate is
satisfied by a compile-only WASM check or an opaque socket echo.

### Fresh sessions and persistent application identity — 2026-09-13

Commit `4dac7fa` passed the 94-command local aggregate, Linux/WASM Rust CI
[34736562561](https://github.com/hraness/valhalla/actions/runs/34736562561), and
security analysis [34736562718](https://github.com/hraness/valhalla/actions/runs/34736562718).
That revision includes independently reviewed authority repairs and a real
loopback QUIC experiment. The following session/identity increment was authored
locally after worker agents hit their account usage limit; it has automated and
local source-review evidence but **no independent protocol/security review**.
Keep it experimental and disconnected from live room ingress until that review
and the relevant operational gates pass. No general host effects are added.

`vhalla-session` supplies a bounded three-message paired handshake. Hello,
response and confirmation have distinct signed packet kinds. Both complete
application keys, both observed transport keys, realm, room, epoch and expiry
are bound through the pairing digest; both fresh nonces derive the common
session ID. Replaying an old Hello receives a new responder challenge, so an
old confirmation cannot establish the new session. Each direction retains its
own chat-only replay window. Local close, expiry and observed clock rollback
permanently close that session. The caller owns pending-handshake capacity and
must supply fresh entropy and trusted transport observations.

The pure session suite currently has 14 public-API unit/property tests and one
compile-fail test, including a separately calculated Python pairing-digest
vector. Cases cover role reflection, handshake/chat replay after a new nonce,
changed context or keys, malformed framing, signature tampering, timeout,
revocation, maximum-size frames and direction checks. They do not prove Internet
connectivity, durable exactly-once semantics, signed invitations or browser
execution. Pairing remains trusted local configuration; no remote descriptor
can authorize itself by constructing it.

`vhalla-identity` adds the first `vhalla identity init/show` commands and Unix
private-file custody of a single application key. Creation requires a new
directory, OS entropy, synchronized publication and an exclusive lifetime
lock. Open never creates or repairs missing/corrupt state. Tests cover real
filesystem reopen/locking, symlinks/hardlinks, permissions, partial records and
the CLI. Its joined session test reopens the same key, obtains fresh OS nonces,
rejects old transcript/chat traffic and accepts a new message. A borrowed-key
signing helper avoids reconstructing the retained key for every message.

Unlike the earlier two-persistent-seed proposal, this first custody layer stores
only the application identity. Native transport secret custody and rotation
remain adapter work; transport keys must still be authenticated and explicitly
bound by every pairing. The identity record is unencrypted owner-private data
with a corruption checksum. It provides neither hostile-host isolation nor
adversarial rollback protection, and interrupted-publication tests are not
physical crash qualification. No command is installed globally or shadows `vh`.

**Target recorded for this increment:** connect the persisted key and fresh
session exchange to real native transports. The later maintained native section
above records that progress; browser execution and reviewed invitation UX remain
next. Preserve
private keys, verify observed transport identities, reject recorded old traffic
after an actual process restart, and keep kind 2 out of the chat dispatch path.
Independent review and live evidence are admission gates, not completed claims.

### Typed owner invitation claim — 2026-09-13

`vhalla-session::Invitation` is a fixed-width, versioned owner signature over
the complete owner and invitee application keys, realm, room, membership epoch,
exclusive expiry and a nonzero nonce. Canonical decoding is bounded and strict;
verification requires an explicitly supplied expected owner and caller clock.
The type returns claims only: it does not authenticate transport keys, mutate
membership, establish a session or provide single-use state. Three focused unit
tests cover round-trip/issuer binding, scope/expiry/signature tampering and
malformed or zero-nonce rejection. Integrating this claim into native/browser
pairing UX, spent-token persistence and independent protocol review remain open.

The native library adapter now requires an independently supplied expected owner
when sending with an invitation, and verifies it before transport setup. Sender
and listener translate exclusive invitation expiry `T` into inclusive route and
session expiry `T-1`. Reviewed regressions reject a substituted issuer before
dialing, preserve the valid invited socket exchange, and drive handshake and
message processing at `T-1` and `T` without wall-clock sleeps. The current CLI
still uses its ordinary explicit-peer-key path. These adapter repairs do not
close the remaining pairing UX, durable spent-nonce or public-transport gates.

The session crate also exposes `SpentInvitationNonces`, a move-only bounded
check-and-insert guard. Duplicate nonces return `AlreadySpent`; capacity
overflow returns `Capacity` without eviction or mutation. Property tests cover
arbitrary capacities and nonce schedules. This is a local replay primitive,
scoped to one issuer/authorization domain; durable persistence, crash recovery
and integration at the owner admission boundary remain separate gates.

Invitation CLI surface and durable spend — 2026-09-15. `vhalla experimental`
now carries the invitation path end to end: `invite` issues the canonical
owner-signed token, `listen ... invitation` binds through
`bind_with_invitation`, and `send ... invitation` redeems through
`send_message_with_invitation` with an independently pinned expected owner.
Because the nonce never reaches the wire, single-use is necessarily a local
redemption boundary: `vhalla-native::SpentFile` persists consumed nonces as a
bounded (1024-entry) atomically republished `VSN1` file at
`<identity-directory>.spent`, consumed after verification and before dialing.
The subprocess e2e proves the full journey — issue, invited listen, invited
send — and that a second redemption from the same identity in a fresh process
is rejected `AlreadySpent`. Remaining open gates are unchanged: pairing UX
review, owner-side admission evidence and public transport.

### Message and effect authority repair — 2026-09-12

Two isolated tests reproduced the old public-API bypasses against `c373c71`:
a fabricated, copyable `EffectRequest` executed without policy, and one
authorization could be cloned into two executions. A foreign requester was
also accepted by an author-agnostic scope grant. These were defects in the
demonstration boundary; the host only counted in-memory reads and exposed no
OS command or file operation.

The repaired path consumes a signed message into private, immutable,
non-cloneable `VerifiedEnvelope` evidence. Verification checks the full key,
strict Ed25519 signature, owner, realm, room, epoch, session, expiry and a
bounded full-key replay frontier before returning evidence. Invalid traffic
does not mutate that frontier. `RemoteRequest` consumes that proof and checks
the typed request kind. Local policy grants one exact key, context and scope;
`AuthorizedEffect` moves into the host, whose own current policy and injected
clock are checked immediately before execution. The fabricable effect request
and unrestricted runner trait are removed. Policy replacement must advance the
epoch in the same owner/realm/room/session; old prepared capabilities fail.

The signed transport format is now **v2**, with an explicit version and signed
epoch/session. Legacy unversioned signed frames are rejected; there is no
automatic downgrade. The inner unsigned envelope retains its canonical v1
bytes and now has private fields. The complete signed frame, not just its body,
must fit in 65,536 bytes; the maximum signed body is 65,341 bytes. This is an
intentional pre-release API/protocol break. No deployed network or signed
message store depended on the previous format.

`MemorySession` keeps verification and host policy together across successive
deliveries, pins one full key, rejects weak-key configuration, and changes its
verifier only after a valid policy rotation. Integration tests cover duplicate
and reordered delivery, forged or expired traffic, wrong room/key, authenticated
chat denied as an effect, maximum-size frames, failed rotation preserving replay
state, and valid key/epoch rotation. Generated schedules compare each effect
count with an independent high-water model. Compiler tests reject fabricated
requests, mutated verified evidence, capability cloning and reuse after move.

This is **in-process, volatile** protection. Trusted local code still configures
policy and supplies the clock. Constructing another replay window with the same
context or restoring old process state can reopen old requests; native identity,
fresh-session negotiation and persistence must address this before unattended
network operation. Move-only types do not provide durable exactly-once effects,
defend a compromised process, or stop model prompt injection. Public receipts
are observations of the local demonstration, not signed execution attestations.
The workspace no-`std` policy/host boundary still needs runtime target evidence.

Gate 0 is complete against baseline commit `b0d091c`: the workspace was clean,
the production aggregate tests and Clippy gate passed, and the prototype
workspace remained excluded from production dependencies.

Gate 1 has a first narrow implementation in `vhalla-crypto::claims`: typed
closed-domain claims, canonical bounded encoding, context-bound Ed25519
signatures, expiry checks, equivocation detection, and a fail-closed replay
window with an explicit scope limit. It is intentionally stateless beyond the
bounded in-memory window; durable receipt retention, checkpoint ancestry, and
quorum evidence remain future gates. The primitive does not yet supply issuer
trust configuration, policy-scope or revocation handles, durable compaction,
or a checkpoint quorum; `ClaimDomain::Capability` therefore remains evidence,
never an authorization result.

The isolated `vhalla-ledger` seam is also present now. It derives a SHA-256
root from a bounded linear history and rejects forged, stale, forked, and
wrong-context checkpoints. It intentionally has no durable storage, quorum proof,
compaction anchor, or host integration, so its accepted checkpoint remains
single-replica evidence. Commit `80c77df` additionally caps configured history
at `MAX_EVENTS`, enforces actor sequence monotonicity, and permits a validated
checkpoint to advance to a later descendant tip. The workspace format, test,
Clippy, and diff gates passed after that repair. Commit `ba6db83` adds bounded
canonical snapshot/restore with round-trip, truncation, trailing-byte, and
header-tamper tests; snapshots remain unauthenticated until a future signed
storage layer wraps them.

### Checkpoint certificates and recovery repair — 2026-09-12

Independent recovery review found two defects in the snapshot implementation:
restoring an older accepted checkpoint failed after appending newer events, and
out-of-order actor sequence records were accepted despite the canonical format.
Both were reproduced before repair. Restore now rederives an anchor's root and
height from retained linear history while preserving the latest tip. New live
checkpoint admission still requires the current tip. Snapshot actor records
must be strictly sorted; duplicate and alternate-order encodings fail closed.

The public-API recovery suite includes a generated sequence of appends,
checkpoints, restarts, and attempted sequence reuse. Its checked-in regression
seed reduces the original recovery defect to two events with a checkpoint after
the first. Negative tests mutate each retained checkpoint field: wrong realm,
epoch, unknown head, forged root, and wrong height all fail. This establishes
serialization consistency, not authenticated storage, crash durability, or
protection against loading an older valid snapshot. Those remain open gates.

The standalone `prototypes/checkpoint-proof` reference now tests bounded
Ed25519 approvals over a canonical statement tied to an immutable trust
configuration. Its digest commits to the realm, epoch, sorted full public keys,
threshold, signer limit, and byte limit. Configuration changes require new
approvals. Strict verification produces immutable evidence with a compile-fail
mutation test; it cannot produce a policy or host capability.

A bounded observer reports conflicting head/root pairs at a retained height
and rejects capacity exhaustion without eviction. A regression test constructs
two conflicting certificates that both verify: certificate validity is not
consensus, ancestry, finality, or freshness. Root derivation remains the ledger's
job; the prototype deliberately has no production imports or host integration.
Its realm strings still require a reviewed mapping to production `RealmId`.

Focused evidence: four recovery integration tests, nine certificate unit/property
tests, and one certificate compile-fail doc test pass locally. The certificate
suite includes a canonical transcript hash independently generated using Python
`struct` and `hashlib`, configuration permutation/replacement, field mutation,
malformed approvals, and fail-closed limits. Local worker review stopped at the
account usage limit; the integration owner completed and audited the reference
implementation. No independent review of that final certificate implementation
is claimed. It remains excluded from production.

Reproducible final gates for this change are workspace format, all-target tests,
doc tests and Clippy, plus format/test/Clippy for every standalone prototype,
Wordcell percolation/refresh/check, and the managed repository baseline check.
CI additionally compiles core, wire, crypto, policy, ledger, and the certificate
reference for `wasm32-unknown-unknown`; this expands the former core-only gate.
The local Homebrew Rust installation lacks that target, so CI owns cross-target
evidence. Compilation alone does not satisfy native/WASM execution agreement.

**Checkpoint-specific next targets:** prototype the explicit trust/epoch transition below,
including competing transitions and interrupted rotation recovery. Specify a
protected-pin backend contract separately from ordinary filesystem storage;
qualify real crash behavior before claiming it. Add bounded retention/compaction
and durable conflict evidence before policy/host composition. The reference
transaction now models crash boundaries, but an ordinary local pin is not
adversarial rollback protection or distributed settlement.

### Marketing release and bounded certificate decoding

The user prioritized a minimal public introduction before further internals.
Commit `bf8846b` adds the static vhalla.com page, a shorter README, and a compact
docs index. Vercel deployment `dpl_6QXTqfTgEArq1CTYCAC4v44tge3Y` serves that
revision in the Hraness `valhalla` project. Public HTTPS returned matching bytes
for the page, CSS, font, favicon, robots file, and sitemap; desktop and mobile
browser inspection passed. Marketing content keeps prototype status explicit.
The earlier internal commit `f048550` passed Rust, the expanded WASM gate,
reference tests, and GitHub security checks.

After deployment, the certificate reference gained a canonical byte encoder and
bounded decoder. Approvals sort by full public key; decoding rejects alternate
orders, duplicates, mixed statements, malformed fields, and trailing bytes.
Total bytes and counts are checked before allocating approval slots, and UTF-8
realm byte lengths are capped before copying strings. `verify_bytes` uses the
configured policy limits during decoding, then performs signature verification.
A compile-fail test keeps parsed certificates distinct from verified evidence.

The native tests exercise every truncated prefix, maximum realm/count bounds,
generated valid and arbitrary-input round trips, bit mutations, and a second
Python-generated framing hash. This advances the parser model only: independent
review, production identifier mapping, ledger-root composition, durable conflict
records, trust rotation, and rollback resistance remain open. No production
crate imports the reference, and no decoded or verified certificate can grant
host authority.

### Certified history and externally pinned recovery — 2026-09-12

Independent source review of `checkpoint-proof` found no concrete defect in the
bounded byte-to-verified-evidence boundary. The reviewer checked pre-allocation
limits, canonical ordering, full-key and trust binding, and strict verification,
and ran the 19 unit/property tests plus two compile-fail doctests. This is a
bounded code review, not a dependency cryptographic audit or consensus proof.

`prototypes/checkpoint-ledger` now composes that verifier with the actual
`vhalla-ledger` implementation. It remains excluded from production and adds
no dependency from production to prototypes. Its `CertifiedLedger` owns the
ledger and immutable trust policy with no mutable projection. Admission verifies
certificate bytes, then requires the real ledger to accept the exact current
tip, derived root, realm, epoch, and height before constructing a sealed
`CheckedCheckpoint`. Raw or merely signature-verified claims cannot construct
that type. Rejections preserve history and previously checked evidence.

The adapter maps `RealmId(u128)` to `vhalla/realm/u128/v1/` followed by exactly
32 lowercase hexadecimal digits. This preserves all realm bits and rejects
alternate spellings; construction checks the mapping and epoch against the
policy. The certificate format itself is unchanged. This is an experimental
mapping decision, not a realm allocation scheme or a released protocol version.

Recovery re-verifies a certificate under the anchor's exact trust-policy digest,
compares the complete checkpoint with a separately retained `RecoveryAnchor`,
replays bounded snapshot history, and validates that checkpoint at the restored
current tip. It rejects old or divergent histories and uncheckpointed suffixes.
It performs no truncation or roll-forward. Snapshot-local checkpoint metadata
cannot select the anchor; valid older metadata may be replaced by the pin.

The important limit is **freshness relative to the supplied pin**. The anchor
is sealed evidence retained in memory by the owner, with no serialization or
disk implementation. A caller deliberately supplying a matching old snapshot,
certificate, and old anchor can still recover old state. Protecting the latest
anchor against rollback, and committing it atomically with recoverable history
and certificate bytes, remain operational requirements. Rust privacy enforces
construction discipline, not persistence or freshness. The model retains the
latest checked checkpoint; certificate bytes must be retained separately.

Independent review of the implemented adapter found no blocking issue and
confirmed exact context binding, immutable boundaries, admission atomicity,
and recovery checks. Review also called out two preserved limits: ledger actor
IDs are unauthenticated claims, and malicious staged appends can advance or fill
the bounded history. Checkpoint signatures do not prove individual authorship,
authorize payloads, guarantee availability, or mint a host capability.

The runnable `recovery` example recovers two certified events, then rejects an
older valid certificate against the retained newer pin. Focused validation is
`cargo run --manifest-path prototypes/checkpoint-ledger/Cargo.toml --example recovery --locked --offline`.
Public-API tests cover context and trust changes, false signed roots/heights,
rejection atomicity, fork/rollback/suffix rejection, and generated bounded
append/admit/recover schedules. All 13 integration/property tests and three
compile-fail cases pass locally; each of the three properties uses 64 cases.
The focused format and all-target Clippy checks also pass with warnings denied.
The compile-fail cases protect evidence and anchor construction. CI now also
compiles this composition for
`wasm32-unknown-unknown`; runtime cross-target agreement remains open.

### Conditional persistence and native storage — 2026-09-12

The persistence fork is now executable in `checkpoint-ledger::persistence`.
`PreparedCommit` binds a certified snapshot/certificate bundle to the complete
expected predecessor pin. Preparation re-verifies the exact current frontier,
requires the same realm, epoch, and trust policy, and independently checks the
predecessor's root and height inside the candidate's retained history. A higher
signed fork is not an extension. Local commit generations cannot wrap.

The only production API addition exposes the existing read-only
`Ledger::validate_retained_checkpoint` check; its validation body is unchanged.
A public-API regression verifies ancestor validation leaves snapshot bytes
unchanged, rejects a false height, and does not relax current-tip admission.

The commit order is immutable bundle contents and name first, then a durable
compare-and-exchange over the full expected pin. Stale writers must reload and
prepare again, not silently rebase. Failed operations may retain bounded orphan
bundles. A pin write can be indeterminate: retries reconcile the exact target,
repeat durability operations, and return an acknowledgement only after durable
CAS succeeds. No automatic pruning or fallback occurs.

Independent review caught an important design gap before acceptance: visible
bytes or a visible pin after a failed sync do not prove durability. Both the
core retry path and native adapter now re-sync identical content and re-publish
the identical pin before acknowledging a retry. The crash oracle keeps visible
and durable records separate and tests that precise failure window. Review of
the implemented core and native adapter found no blocking defect and requested
an additional race test; that test covers another writer winning after the
initial read but before CAS, leaving an orphan without changing the winning pin.

The optional `native-store` feature adds a Unix `FileStore` using standard-library
file locking (Rust 1.89+), private permissions, bounded record reads and retention,
immutable hard-link publication, atomic pin rename, and file/directory syncs.
An OS lock spans each adapter's lifetime. Symlinks and unexpected entries are
rejected; the owner must control the directory and its ancestors. Capacity is
explicitly 1–64 bundles, counting orphans. Only fixed temporary names are cleaned
up; immutable bundles are never deleted. The default core stays `no_std` +
`alloc`, and CI still compiles it for WASM. Native tests and Clippy are now a
separate required CI step; no authored JavaScript or new runtime package was added.

Canonical pin and bundle formats have independent Python-generated SHA-256
vectors, bounded decoding, truncation and oversized-field rejection. The native
test suite closes and reopens a real store, verifies its certificates and history,
advances it, and reopens again. The model tests inject failures before writes,
after visible/synced contents, after name sync, before CAS, after visible pin
replacement, and after pin sync/lost acknowledgement. Generated 64-case schedules
check acknowledged frontiers across crashes and retries. Other tests cover
malformed pin errors versus absence, stale writers, forks, generation overflow,
policy changes, missing/corrupt pinned bundles, and typed preparation fences.

This is a **crash-consistency reference under backend contracts**, not protected
freshness. An ordinary file store cannot detect deletion or coordinated rollback
of the pin and matching bundles by someone controlling the disk. Tests explicitly
demonstrate that limit. A decoded pin is plain data; the local owner-selected
backend supplies the recovery expectation. Filesystem tests exercise API behavior,
not physical power loss or arbitrary filesystems. Loading captures the pin at its
initial read and does not promise the newest pin if another writer advances later.

### Next trust-rotation experiment

Ordinary commits reject all implicit trust or epoch changes. The next reference
should keep rotation a separate protocol with these proposed constraints:

1. A signed transition binds the realm, exact old and new policy digests, the old
   certified frontier, and exactly the next epoch. Incoming certificates never
   select their own trust policy.
2. Require old-quorum authorization and new-quorum acknowledgement in the first
   experiment. Neither alone establishes consensus. Key-loss recovery needs a
   separately predeclared local authority; timeout cannot waive approval.
3. Start an explicit new-epoch genesis that commits the transition digest and old
   certified root. Do not silently reset history or actor sequence counters.
4. Persist transition evidence, new policy, and the new-epoch bundle before
   conditionally advancing the complete pin. Inject interrupted-write failures
   and verify rotation from the old pinned policy before accepting the new one.
5. Treat competing valid transitions from one frontier as a conflict. Retain
   evidence and fail closed until an explicit selection/agreement rule exists;
   higher generation, epoch, or arrival order must not silently choose a winner.

These are upcoming acceptance targets, not implemented rotation support. Protected
freshness, conflict retention, compaction, and host integration remain open gates.

## Invariant map

| Hardened reference invariant | Production destination | Required production evidence | Promotion blocker if absent |
| --- | --- | --- | --- |
| Provenance receipt binds issuer, subject, module/content digest, policy scope, epoch, expiry, and revocation; signatures are context-bound | `vhalla-crypto` transcript/hash/signature helpers; `vhalla-wire` receipt encoding; `vhalla-policy` admission | independent sign/verify vectors, wrong-context and wrong-epoch rejection, expiry/revocation tests, canonical bytes stable on native and WASM | a valid signature can be replayed in another realm, epoch, audience, or policy scope |
| A failed or revoked transfer cannot leave an admitted module or capability behind | `vhalla-policy` admission state; `vhalla-host` receipt handoff | transactional apply test, crash/retry simulation, before/after state-root equality on failure, revocation-before-next-effect test | partial transfer changes authority or retry consumes an invalid attempt |
| Checkpoint root is derived from canonical bounded history, membership epoch, and parent head; stale, forked, or forged heads are rejected | `vhalla-core` checkpoint/event types; `vhalla-wire` checkpoint envelope; `vhalla-crypto` hash/signature; `vhalla-steel-thread` verification | golden root vectors, parent/epoch binding tests, fork/stale-head rejection, independent verifier agreement, bounded history/compaction proof | caller-supplied `state_root` is accepted without recomputation or current-head validation |
| Replay windows, seen IDs, queues, and lifecycle receipts are bounded; overflow fails closed | `vhalla-crypto::ReplayWindow`, `vhalla-transport` queues, policy and host receipt stores | explicit memory/count limits, duplicate/reorder property schedules, overflow denial, deterministic compaction and restart behavior | unbounded attacker-controlled map/vector or silent eviction that reopens replay |
| Revocation and epoch changes invalidate stale work without transferring authority | `vhalla-core::Epoch`, `vhalla-policy`, `vhalla-crypto`, host receipt checks | revoke/re-admit sequence tests, stale epoch rejection, key/policy rotation recovery, no authority transfer on timeout | stale capability, receipt, or lease remains executable after epoch change |
| Property/state-machine schedules preserve noninterference, queue, expiry, budget, and idempotence laws | all pure crates; integration oracle in `vhalla-steel-thread` | checked-in proptest cases, deterministic model oracle, loss/duplication/reorder/partition schedules, regression seeds | only hand-written happy-path tests cover the stateful invariant |
| Transport and display content remain data even when authenticated | `vhalla-core`, `vhalla-wire`, `vhalla-transport`, `vhalla-policy` | hostile-content tests, compile-fail/API review showing only local policy creates `AuthorizedEffect`, no parser-to-host shortcut | authentication or message text is treated as authorization |
| Receipts distinguish delivery, verification, authorization, execution, and settlement | `vhalla-wire`, `vhalla-host`, `vhalla-steel-thread` | typed receipt-state transitions and duplicate delivery tests; no “received = executed” shortcut | UI or caller can infer an effect from transport delivery alone |

## Dependency-ordered gates

### Gate 0: baseline and ownership freeze

Before changing a production crate, record the exact commit, Rust toolchain,
lockfile, current public types, and aggregate baseline. The owner writes a
short invariant statement and names the crate that owns it. Prototypes remain
outside the workspace and continue to serve as executable references.

**Acceptance evidence:** `cargo fmt --all -- --check`, workspace tests, Clippy
with warnings denied, and a clean tree receipt containing the exact commit and
commands. A design review confirms no prototype dependency has been promoted
by import accident.

**Recovery:** discard an unaccepted production branch and retain the prototype
commit. Do not alter the default wire version or persisted data during this
gate.

### Gate 1: canonical evidence primitives

Define production domain-separated transcript helpers and canonical encodings
for provenance, revocation, checkpoint, and receipt objects. Use fixed-size or
explicitly bounded fields. Keep cryptographic verification in `vhalla-crypto`
and structural decoding in `vhalla-wire`; neither creates host authority.

**Acceptance evidence:** golden vectors generated by two independent code paths
or implementations, round-trip tests, rejection of trailing/duplicate/unknown
fields according to the chosen version policy, and native/WASM byte equality.
Property tests must cover arbitrary bounded bytes and lengths.

**Recovery:** gate the new object kinds behind a new wire version or feature
flag. Unknown objects remain opaque and forwardable only where policy allows;
old peers must never interpret a new authority-bearing object as an old one.

### Gate 2: authenticated provenance and lifecycle receipts

Add a production receipt type that binds issuer identity, subject/content
digest, realm, audience, policy scope, membership/policy epoch, expiry, nonce,
and revocation context. Verify signatures before admission, then pass a typed
admission result to policy. A signature proves key control for this transcript;
it does not mint a capability.

The transfer path must be transactional: validate all evidence and policy
before mutating installed state; failed validation, expiry, revocation, ABI
mismatch, or downgrade leaves the prior state unchanged. Receipt retention has
an explicit bound and deterministic compaction rule.

**Acceptance evidence:** valid/invalid signature vectors; wrong realm,
audience, epoch, scope, content, expiry, and revocation tests; equivocation and
replay tests; crash/retry simulation; bounded receipt-store tests; and an
offline verifier that reaches the same admission decision as the issuer.

**Recovery:** rotate the policy/key epoch, revoke the affected receipt or
module lineage, stop new admissions, and replay the last known-good durable
receipt frontier. Never repair by silently accepting an old receipt or deleting
conflicting evidence.

### Gate 3: derived checkpoint roots and recovery

Introduce a bounded canonical event/checkpoint model. A root must be derived
from the event frontier, parent root, membership/policy epoch, and protocol
domain. A checkpoint may be accepted only if its parent is known, its history is
canonical under the selected rules, its epoch is current or explicitly
recoverable, and its signature/quorum evidence verifies.

This gate does not choose a global consensus protocol. DAG heads and unresolved
forks remain explicit. The production API must not accept a caller-supplied
root as sufficient evidence.

**Acceptance evidence:** fixed root vectors; append/replay determinism;
forged-root, stale-head, sibling-fork, wrong-epoch, and unknown-parent rejection;
bounded compaction with a retained recovery anchor; two independent verifiers
agreeing on the root; and a light verifier that does not need every payload.

**Recovery:** retain the last accepted anchor and conflicting heads as evidence;
quarantine the unresolved branch; request missing ancestors or an owner/quorum
repair; and resume only from an explicitly accepted descendant. Never rewrite
history in place or treat a timeout as authority transfer.

### Gate 4: bounded replay and state-machine verification

Replace any unbounded production replay/receipt state with an explicit limit,
retention horizon, or checkpointed compaction rule. Model schedules must include
duplicate, reorder, delay, loss, expiry, cancellation, revocation, restart,
partition, queue pressure, and clock rollback. The model oracle and production
state machine must agree on allow/deny, queue, and receipt outcomes.

**Acceptance evidence:** proptest or equivalent generated schedules with checked
regression seeds; deterministic state-machine traces; memory/count assertions;
queue overflow and replay-overflow denial; no duplicate effect execution; and
restart/compaction tests showing that old evidence cannot be replayed after
retention changes.

**Recovery:** apply backpressure or fail closed when a bound is reached; persist
the last accepted frontier before compaction; restore from that frontier plus
uncompacted evidence; and require an epoch change if replay state cannot be
recovered with confidence.

### Gate 5: steel-thread integration

Extend `vhalla-steel-thread` so one end-to-end path covers:

```text
foreign bytes
  -> bounded wire parse
  -> signature/provenance verification
  -> replay/expiry/revocation checks
  -> derived checkpoint or receipt validation
  -> local policy authorization
  -> one typed host effect
  -> distinct execution receipt
```

The test must inject hostile content and adversarial delivery schedules. It
must show that a message can be received, authenticated, or checkpointed while
still being denied by local policy, and that a successful host effect produces
exactly one receipt.

**Acceptance evidence:** native end-to-end tests; no-effect-on-denial tests;
duplicate/reorder/loss tests; policy epoch rotation; checkpoint recovery;
receipt replay rejection; and a compile-fail or API-level proof that remote
content cannot construct an `AuthorizedEffect`.

**Recovery:** disable the affected effect/evidence path while preserving receipts
and anchors. A rollback must retain the repaired authorization boundary; never
restore the old raw request or cloneable capability APIs. A failed integration
must not broaden policy or silently downgrade signed framing or verification.

### Gate 6: portability and operational admission

After the native path is stable, compile the pure core, wire, crypto, and policy
surfaces to `wasm32-unknown-unknown` and an embedded-like no-`std` target where
supported. Confirm that browser or transport adapters do not add authority.
Run dependency, license, provenance, and advisory review before adding a new
production dependency.

**Acceptance evidence:** WASM compilation and vector tests; bounded allocation
benchmarks; no filesystem/process/network imports in pure crates; reproducible
lockfile build; fuzz targets for new decoders; and an adapter review covering
origin checks, relay metadata, and key custody.

**Recovery:** ship the native/reference path while keeping the new object kind
disabled for unsupported targets. Do not add a JavaScript or TypeScript second
implementation to work around a Rust portability failure.

## Verification matrix

| Evidence class | Minimum required before promotion | Owner |
| --- | --- | --- |
| Unit tests | success/error transitions for each new type and bound | crate owner |
| Property tests | bounded arbitrary inputs, canonicalization, replay, expiry, and idempotence | pure-crate owner |
| State-machine tests | loss, duplication, reorder, delay, restart, revocation, partition, and recovery | integration owner |
| Compile-time boundary | no external constructor or parser path to host authority; `unsafe` remains forbidden in pure crates | core/policy owner |
| Golden vectors | canonical bytes, signatures, roots, and rejection cases | wire/crypto owner |
| Fuzzing | bounded decoders and manifest/receipt/checkpoint parsers | verification owner |
| Cross-target | native and WASM agreement on bytes, hashes, and decisions | portability owner |
| Review | threat model, dependency provenance, residual risk, and rollback recorded in this plan | integration owner |

The final gate is exact-tree validation after all workers converge. A worker's
prototype result or earlier receipt may be reused as design evidence, but not as
the final integration, release, or production-verification receipt.

## Recovery and rollback principles

- **Preserve evidence.** Keep conflicting receipts, heads, and invalid
  signatures available for diagnosis; quarantine them rather than deleting them.
- **Fail closed at authority boundaries.** Unknown, stale, over-limit, or
  unverifiable evidence may be forwarded as opaque data only when the local
  policy permits it; it cannot execute.
- **Use epochs for repair.** Key rotation, policy changes, revocation, and
  recovered state must advance an explicit epoch so stale work cannot regain
  authority.
- **Recover from anchors.** Durable stores retain a last-known-good checkpoint
  or receipt frontier plus enough evidence to verify descendants. Compaction
  without an anchor is not recovery.
- **Make retries idempotent.** Transfer, checkpoint admission, and host effect
  handoff carry stable IDs/nonces and never apply a failed operation twice.
- **Keep feature/version escape hatches.** New evidence kinds can be disabled
  or negotiated away without changing the meaning of existing signed bytes.
- **Do not call partial evidence final.** A delivery receipt, checkpoint, quorum
  signature, TEE report, or Botcaptcha result has only the authority assigned by
  the applicable local or realm policy.

## Explicit non-goals

This plan does not authorize or promise:

- promotion of every prototype crate into the production workspace;
- a global blockchain, permissionless consensus, token, or redeemable currency;
- treating program complexity, Botcaptcha work, hardware fingerprints, or TEE
  evidence as proof of agency or as a substitute for authorization;
- an authored JavaScript/TypeScript protocol implementation or an indispensable
  hosted relay service (a Rust/WASM browser client is in product scope);
- transparent persistence of private prompts, game state, or owner metadata;
- availability through partitions, honest relays, or stable network identity;
- recovery from a compromised owner host, browser origin, kernel, or key store;
- a claim that Ed25519, SHA-256, ZK proofs, or memory-safe Rust alone provide
  complete system security; or
- a claim that passing this plan's tests is a security audit or distributed
  consensus proof.

## Decision record and durable memory

Full promotion remains **unaccepted** until Gates 0–5 have named owners,
production APIs, acceptance receipts, and residual risks. When a gate is
accepted, append its exact commit, commands, vectors, and recovery result to
this plan rather than creating a separate progress note. If the protocol later
adopts realm finality or settlement, update
[the blockchain architecture plan](valhalla-blockchain-architecture.md) and
link the accepted checkpoint/receipt format here.

## Result

Partial: bounded claims, derived ledger roots, and canonical recovery have narrow
workspace implementations. The disposable certificate/history adapter now joins
signature checks to real linear history, conditional persistence, and an optional
Unix store. Crash models and native reopen tests exercise recovery against a local
pin. Full promotion remains unaccepted; physical crash qualification, protected
pin freshness, trust rotation, compaction, and policy/host composition remain open.

## Durable memory

Promotion requires derived evidence and bounded recovery at the production
crate seams. The maintained owners are the security-first design plan for
authority boundaries and the blockchain architecture plan for any future realm
finality or settlement. The eukaryotic transition plan remains the owner of the
disposable reference models.
