---
title: Valhalla prototype promotion gates
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

# Valhalla prototype promotion gates

**Status:** in progress; narrow primitives exist, integration gates remain open
**Date:** 2026-09-12  
**Scope:** the evidence and integration gates required before hardened
reference prototypes can become part of the `vhalla-*` production workspace

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

The result is still an event and receipt layer. It does not, by itself, create
a global blockchain, a currency, a browser UI, or a claim that an agent is
autonomous.

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

**Next bounded targets:** specify and prototype the persistence transaction for
snapshot, certificate, and independently protected anchor; inject failures at
every write/commit boundary; define the freshness threat model and explicit
trust/epoch rotation. The certificate/history join and exact-pin recovery model
below are references for that work. Durable conflict retention and policy/host
composition still follow those gates; an in-memory observer is not settlement.

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

**Recovery:** keep the existing steel thread as the fallback path, disable the
new evidence kind by feature/version negotiation, and preserve old receipts and
anchors. A failed integration must not broaden policy or silently downgrade
verification.

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
- a browser UI, JavaScript/TypeScript implementation, or hosted relay service;
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
signature checks to real linear history and models recovery against a separate
pin. The integrated promotion result is not yet accepted; durable recovery,
protected anchor freshness, trust rotation, and policy/host composition remain open.

## Durable memory

Promotion requires derived evidence and bounded recovery at the production
crate seams. The maintained owners are the security-first design plan for
authority boundaries and the blockchain architecture plan for any future realm
finality or settlement. The eukaryotic transition plan remains the owner of the
disposable reference models.
