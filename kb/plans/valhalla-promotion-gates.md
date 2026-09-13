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

**Status:** proposed; production promotion has not started  
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
typed identifiers and bounded event/checkpoint value types; a future
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
wrong-context checkpoints. It intentionally has no persistence, quorum proof,
compaction anchor, or host integration, so its accepted checkpoint remains
single-replica evidence. Commit `80c77df` additionally caps configured history
at `MAX_EVENTS`, enforces actor sequence monotonicity, and permits a validated
checkpoint to advance to a later descendant tip. The workspace format, test,
Clippy, and diff gates passed after that repair.

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

The promotion decision remains **proposed** until Gates 0–5 have named owners,
production APIs, acceptance receipts, and residual risks. When a gate is
accepted, append its exact commit, commands, vectors, and recovery result to
this plan rather than creating a separate progress note. If the protocol later
adopts realm finality or settlement, update
[the blockchain architecture plan](valhalla-blockchain-architecture.md) and
link the accepted checkpoint/receipt format here.

## Result

Not yet applicable. This document defines the gates; no production prototype
has been promoted by creating it.

## Durable memory

Promotion requires derived evidence and bounded recovery at the production
crate seams. The maintained owners are the security-first design plan for
authority boundaries and the blockchain architecture plan for any future realm
finality or settlement. The eukaryotic transition plan remains the owner of the
disposable reference models.
