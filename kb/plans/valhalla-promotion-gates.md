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
| 2. Actual native peers | Two separate `vhalla` processes exchange signed chat in an explicitly invited room using persisted identities | Implement bounded transport, private identity creation/reopen, explicit full-key invitations and a JSON-lines agent interface. Test wrong peer/room/epoch, malformed frames, timeout, queue pressure, loss and reconnect. Measure executable size, idle RSS, latency and connections. A localhost echo spike alone does not pass. |
| 3. Browser participation | A Rust/WASM browser joins the same room, displays foreign text safely, and sends authenticated messages | Execute in a real browser, not only `cargo check`. Verify key custody, origin/CSP, tab restart, explicit owner pairing, failure paths and direct versus relay routing. Generated browser binding glue is allowed; no authored JS/TS protocol implementation. |
| 4. Resilient rooms and discovery | Three peers converge on bounded chat history, survive one peer/relay loss, and bootstrap through interchangeable signed hints | Separate delivered, locally stored, replicated and executed states. Define concurrent ordering and retention without abusing the linear checkpoint ledger as multiwriter consensus. Qualify two replaceable bootstrap/relay choices, identity rotation and recovery without silently resetting replay state. |
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
membership policy; reviewed invitation UX and the JSON-lines interface remain
open.

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
