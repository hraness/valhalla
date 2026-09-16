---
title: Valhalla witness platform
type: plan
area: valhalla-witness-platform
status: proposed
tags:
  - security
  - proof-of-work
  - games
  - wasm
  - verification
---

# Valhalla witness platform

**Status:** proposed; a shared restatement crate and five discovery spikes gate the first crate
**Date:** 2026-09-16
**Scope:** the witness-mode language, its verifier-owned execution platform, the signed challenge
and response that carry it, and the seams a later Platonik session adapter and Hashcash mode reuse

This plan grows fork 1 of the
[[plans/valhalla-botcaptcha-ledger-games|Botcaptcha, receipts, and games plan]] into a concrete
design. It follows the promotion rule in [[plans/valhalla-promotion-gates|the readiness plan]]
(model first, production second, integration third) and the typestate boundaries in the accepted
[[plans/valhalla-security-first-design|security design]].

## Outcome

Two pure crates exist and pass the workspace gates:

- `crates/vhalla-witness` restates the `platonik-habitat-v1` execution model in Valhalla production
  types. It owns the world, the tick loop, the seeded activation order, the four memory slots and
  four inbox ports a cell may touch, the work ledger, the canonical program and manifest codecs, a
  move-only `RunCapability`, and the plain-bytes `ReceiptBinding`. It has no key type, no clock, no
  entropy, no host effect, and no notion of a challenge.
- `crates/vhalla-botcaptcha` owns the signed `Challenge` and `Response` from the games plan in
  witness mode, the one-use window, the private `VerifiedChallenge` admission type, and the private
  `VerifiedWitness` evidence type. Hashcash mode
  stays in `prototypes/botcaptcha` until it is promoted as a separate entry.

A valid witness proves bounded, replayable work on a verifier-selected task for one challenge and
nothing else. It is never identity, personhood, intelligence, originality, or host authority. It may
remove a rate limit, award the `passed-witness` badge, or qualify an event for a game session.

## Context

The games plan requires a tiny versioned instruction subset: bounded size and depth, checked integer
arithmetic, no host imports, deterministic fuel and memory limits, canonical serialization with a
stable program hash, and a `no_std` verifier. It recommends a Platonik-derived finite rule VM first,
behind a language boundary that can later host Lisp.

`prototypes/witness` proves the challenge, bounded program, exact replay, and work range shape with
a six-variant `Expr` AST, but has no serializer, no cryptographic hash, no memory ceiling, wrapping
arithmetic, and no corpus. `prototypes/botcaptcha` proves challenge binding and a replay guard for
Hashcash mode. `prototypes/game-session` uses integer approvers and toy hashes and may not be
imported.

`platonik-core` at commit `5eedec07c84af3b4beb82f22cc6c2b9fa3520d42` is a `std` crate whose v1 model
is a first-match rule list per cell with typed sensors and actions, a 13-counter fuel meter charged
one unit at a time, a splitmix64 seeded activation order, and an independent frame checker. Its
identity is compact serde JSON without domain separation and its `std::io::Write` writers block a
`no_std` port, but its bridge corpus is the only existing witness corpus with deterministic
receipts.

## Reference design: the Roc split applied to Valhalla

Roc separates a platform from an application. The platform owns the process entrypoint, memory
allocation, every effect (declared under `hosted`), the types it exposes to the application
(`exposes`), and the artifact that gets built (`targets`). The application supplies only the pure
values the platform demands (`requires`) and can reach nothing the platform did not expose. Roc's
standard library has no effectful function, and one application uses exactly one platform.

| Roc | Valhalla witness platform |
| --- | --- |
| platform module plus host | `vhalla-witness`: the world, the tick loop, the ledger, and `run` |
| `requires { main! }` | the `Program` for each open `ProgramSlot` in the `TaskManifest` |
| `exposes [..]` | `Condition` sensors, `Action` effects, `BitSource`, four memory slots, four ports |
| `hosted { .. }` | empty; the only effects are typed `Action`s that mutate platform-owned bounded state and are charged to the ledger |
| host owns `main()` and memory | the verifier mints `RunCapability`, allocates the bounded state, and decides when `run` executes |
| `provides { "roc_main" }` | the `WitnessReceipt` the platform hands back |
| exactly one platform per app | exactly one `LanguageId` per manifest, program, challenge, and receipt |

Roc itself is not adopted. It is pre-0.1, distributed as exact nightlies with no compatibility
promise, compiles applications to native or wasm code linked through a C ABI host, and treats the
platform as a compiled binary. Valhalla must not execute network-supplied code of any kind: the
witness program is data interpreted by a function with no imports, and the platform is a pure Rust
crate that compiles to `wasm32-unknown-unknown`. Valhalla borrows the rule, not the toolchain: the
application supplies pure logic under a fixed contract, the platform supplies every effect and every
resource bound, and exclusivity is the point.

## Scope and non-goals

In scope:

- `LanguageId::FiniteRuleV1`, the Platonik habitat-v1 cell program restated as Valhalla types with a
  canonical binary codec and a `ProgramHash`.
- `TaskManifest`, `Case`, `WorkContract`, `WorkLedger`, `RunCapability`, `WitnessRun`,
  `ReceiptBinding`, `WitnessReceipt`, and the codecs and digests for each.
- Signed `Challenge` and `Response` in witness mode, `VerifiedChallenge`, `OneUseWindow`,
  `WitnessVerifier`, `VerifiedWitness`, and a `ProofProfile` boundary with a single
  `TransparentReceipt` profile.
- Golden vectors from an independent Python generator, a parity prototype against the pinned
  Platonik engine, and a wasm32 parity harness.

Non-goals:

- No wallet, credit, voucher, or transferable value; no per-realm receipt DAG or chain. Receipts are
  content-addressed so `vhalla-ledger` can carry them later.
- No decision about when to challenge; invitation-first and adaptive Hashcash under load stay in
  `vhalla-policy` and rooms.
- No game authority, checkpoint quorum, or Platonik adapter; the Slice 5 adapter is a separate plan
  that consumes the seams named here.
- No Platonik v2 `EdgeBlocked`, v3 construction, or v4 direction edits; no frame trace codec, trace
  hash, or checkpoint continuation in v1.
- No steel-thread wire kind in the first landing; no ZK, VDF, memory-hard, or attestation profile.

## Constraints and decisions

### Platform interface

The program is the only application-supplied artifact. It can name only `Condition`, `Action`,
`BitSource`, `MemoryWrite`, `Slot`, and `Port`. It cannot read another cell's memory, the world, the
tick, the seed, the ledger, or the challenge. There is no clock, randomness, host import,
reflection, dynamic loading, or recursion. Rules are flat and conditions are leaves, so every rule
evaluation terminates in at most eight sensor reads.

Session input is the verifier-authored `TaskManifest { version, language, world, slots, cases,
contract, loading_work }`. `world` is the Platonik `Experiment` minus cell programs and fuel fields.
`slots` names which cells the candidate programs (`ProgramSlot { cell, fixed: Option<Program> }`).
Each `Case { seed, ticks, fuel, activation_fuel, events }` is one replay. The `WorkContract {
useful_floor, total_ceiling, require_passed }` is the games plan threshold: pass all cases with at
least N delivered sparks and at most M total work. `loading_work` is declared, not derived from a
serializer's byte length; the validator requires `loading_work >= canonical_len(manifest)` so
parsing work is never under-charged, and the Platonik adapter sets it to the JSON byte length of the
original experiment to reproduce Platonik cost trajectories bit for bit.

The work ledger keeps Platonik's eleven v1 counters (`loading, scheduling, conditions, sensors,
memory_reads, memory_writes, actions, messages, transfers, checking, draining`) and its charge
schedule verbatim, one unit per iteration, with `Stop::Fuel` and `Stop::Activation` semantics
unchanged. `WorkLedger::total()` is the ceiling and covers every admitted loading, scheduling,
execution, and checking cost. No ledger counter is the floor. In the pinned engine `Turn` charges
`transfers` unconditionally and cannot fault, `Move` charges `transfers` whenever it is not blocked,
`emit` charges `messages` once per matching link before the queued, full, or disabled outcome is
decided, every unread inbox slot is charged `messages` again at the next tick's expiry sweep, and
`Fault::Action` keeps the meter charges, so `transfers + messages` is raised by a one-rule `[] =>
Turn` program or by two linked cells ping-ponging constant-bit `Send`s without moving a spark.
Conditions, sensors, and memory reads are charged by a padded rule with an unsatisfiable condition on
every activation, and `actions` is charged once per activation including `Wait`. The floor is
therefore an outcome quantity read from replayed state, not a cost: `WitnessRun::useful()` is `Σ
beacons[i].delivered` over every case, the beacon field that `credit()` increments and `passed`
already checks. It is bounded by the finite, conserved spark supply and cannot be padded, so padding
raises ceiling-bound counters visibly and never the floor. `CaseResult.outcome` carries `delivered:
u16` and `passed: bool`, so the receipt commits to the floor quantity and the verifier reads it from
its own replay. `require_passed` defaults to `true` for both v1 purposes and every fixture default
contract sets it; a manifest that sets it `false` stays legal and expresses a partial-progress
contract, which is safe only because the floor is unpaddable. If spike 4 shows the outcome quantity
does not separate the classes, the fallback is a twelfth `useful` counter outside `total()` (so
spike 1 parity is unaffected), charged only where a spark changes custody toward the task:
`credit()`, `Drop` into a depot, and `Pickup` from a source; never `Turn`, `Move`, `Send`, `emit`,
inbox expiry, or `TakeMessage`.

`RunCapability` is minted locally by `RunCapability::mint(ManifestHash, ProgramHash,
WorkAllowance, RunRole)` in `vhalla-witness`, with no challenge input, and consumed by value by
`run(&TaskManifest, &Assignment, RunCapability)`. It derives only `Debug`, has private fields, has
no encoder or decoder, and never crosses the wire. It carries no cryptographic claim and proves no
remote fact; it is a local run budget and one-run token. Within `vhalla-witness` the compiler proves
a capability cannot be cloned, fabricated by struct literal, or used for two runs, and `run` checks
that the capability's `ManifestHash` and `ProgramHash` equal the manifest and assignment it is
handed. `mint` is `pub` because the corpus tests and the Slice 5 `vhalla-game-platonik` adapter
rerun `vhalla_witness::run` under `RunRole::Replay` with no challenge at all; inside
`vhalla-botcaptcha` the only caller is `VerifiedChallenge::run_capability` (see the admission
section).

`run` returns `WitnessRun`, whose `CaseResult { status, ticks_completed, outcome, final_state:
StateHash, ledger }` values are plain data. The prover seals it with
`WitnessRun::into_receipt(ReceiptBinding)`, where `ReceiptBinding { challenge_id: [u8; 32],
subject_key: [u8; 32] }` is a public `Copy` plain-bytes value owned by `vhalla-witness` with no key
semantics and no signature; the manifest and program hashes are not repeated because the run already
carries them from its capability, and `ReceiptHash` covers them together with the binding.
`WitnessReceipt` has private fields,
`Copy`, accessors, `encode`, `hash`, and no decoder. The wire form is `ClaimedReceipt` with public
fields, `Clone`, and `decode`, so tests can tamper with it. Verification compares `receipt.encode()
== claimed.encode()` after a fresh replay, so a prover gains nothing by reporting fewer or more
charged operations.

### Application language

`LanguageId::FiniteRuleV1` is a `#[repr(u8)]` closed enum threaded through the manifest, the program
encoding, the challenge, the receipt, and every domain tag. `vhalla-botcaptcha` never inspects
program internals. A later `LanguageId::LispV1 = 2` adds its own codec module and domain tags and
reuses `TaskManifest`, `RunCapability`, `WorkLedger`, `WitnessReceipt`, and `WorkContract`
unchanged.

`Program` and `Rule` have private fields. `Program::new(rules)` enforces the structural bounds;
`Slot`, `Port`, and `ValveId` are private-checked newtypes. Network bytes stop at
`UntrustedProgram`. `Assignment::validate(&TaskManifest, Vec<(CellId, UntrustedProgram)>)` performs
the manifest-dependent checks (open slot, sorted cells, `Route` valve exists) and is the only
constructor of `Assignment`, the only type `run` accepts. A locally built unvalidated program cannot
reach `run`.

The canonical codec follows `vhalla-wire` exactly: fixed-width big-endian fields, counts bounded
before use, `u8` discriminants with 0 reserved, `Option` as a 0 or 1 tag byte, no floats or strings,
sorted ids required on decode. Every decoder checks the total size bound, then version, language,
and discriminants, uses `checked_add` on offsets, and rejects `Truncated` and `TrailingBytes`.
`decode(encode(x)) == x` and `encode(decode(raw)) == raw` are laws.

```text
program (vhalla/witness/program/v1):
[0x01 version][0x01 language][rule_count u8 1..=32]
  per rule: [cond_count u8 0..=8] per cond: [tag u8][fields]
            [action tag u8][fields]
            [remember 0|1][slot u8][value u8]
```

The largest rule is `1 + 8 * 4 + 6 + 3 = 42` bytes (`Route` is a tag, a `u16` valve, and a
three-byte `BitSource`), so a program is at most `3 + 32 * 42 = 1347` bytes and `MAX_PROGRAM_BYTES =
2048`. An `Assignment` is `[slot_count u8]` then `[cell_id u16][program]` sorted by cell, at most `1
+ 16 * 2050 = 32801` bytes, so `MAX_ASSIGNMENT_BYTES = 32832`. That fits with the receipt inside one
signed body (`MAX_SIGNED_BODY_BYTES = 65341`). `MAX_MANIFEST_BYTES = 32768`. `MAX_STATE_BYTES` is a
`const` computed from the static bounds and asserted in a test.

Digests are SHA-256 over `b"vhalla/witness/<thing>/v1"` followed by a `u32` length and the canonical
bytes. The version byte inside the encoding and the tag version move together; other versions are
rejected, never negotiated.

| Digest | Domain | Over |
| --- | --- | --- |
| `ProgramHash` | `vhalla/witness/program/v1` | `encode(Assignment)` |
| `ManifestHash` | `vhalla/witness/manifest/v1` | `encode(TaskManifest)` |
| `StateHash` | `vhalla/witness/state/v1` | `encode(State)` |
| `OutputHash` | `vhalla/witness/output/v1` | `case_count u8` then each `encode(CaseResult)`; a run that stops early still encodes every case with its status |
| `ReceiptHash` | `vhalla/witness/receipt/v1` | `encode(WitnessReceipt)` |
| challenge transcript | `vhalla/botcaptcha/challenge/v1` | `encode(Challenge)` without the signature |
| response transcript | `vhalla/botcaptcha/response/v1` | `encode(Response)` without the signature |
| dedup scope | `vhalla/botcaptcha/dedup/v1` | `issuer_key || challenge_id || subject_key`; the `OneUseWindow` key, which stores `response_hash` and `expires_at` as its value |
| reward identity | `vhalla/botcaptcha/reward/v1` | `scope_key || response_hash`, the games plan's `(issuer, challenge_id, subject_key, response_hash)` tuple, used by policy to name the badge grant |

Static bounds are Platonik v1 values: `MAX_RULES = 32`, `MAX_CONDITIONS = 8`, `MEMORY_SLOTS = 4`,
`PORTS = 4`, `MAX_CELLS = 16`, side 3..=32, `MAX_WALLS = 512`, at most 8 sources, depots, beacons,
and valves, `MAX_LINKS = 32`, `MAX_EVENTS = 64`, `MAX_INITIAL_SPARKS = 128`, `MAX_PENDING = 128`,
`MAX_TICKS = 128`, `MAX_FUEL = 2_000_000`, `MAX_ACTIVATION_FUEL = 1024`, `MAX_CASES = 8`. Every
`Vec` in the run state is allocated to its static bound before tick 1 and never grows; the tick loop
allocates nothing. Every counter and state update uses `checked_*`; `RunError::Arithmetic` exists
and a property test shows it is unreachable within the bounds. The v1 language has no arithmetic
operator, so the checked-arithmetic requirement holds by construction: `u8` memory values are
assigned, never computed. Determinism relies on integer-only state, `BTreeMap` only, the splitmix64
`mix` copied verbatim, and no `usize` in any charged quantity. `no_std` with `alloc` is feasible:
the VM needs `Vec`, `BTreeMap`, and `sha2` without default features; Platonik's blockers
(`std::io::Write`, `serde_json::to_writer`, `AtomicU64`) are dropped by the restatement.

### Challenge, response, and admission

`vhalla-botcaptcha` uses the games plan field names verbatim:

```text
Challenge { version, algorithm, challenge_id: 32 random bytes, issuer_key, subject_key,
            realm, room, purpose, task_manifest_hash, issued_at, expires_at,
            target_or_work_floor, signature }
Response  { challenge_id, subject_key, task_manifest_hash, program_hash, output_hash,
            receipt_hash, measured_work, optional_hashcash_nonce, signature }
```

`algorithm` is a closed `u8` enum with `Hashcash = 1` reserved and `Witness = 2` accepted by this
crate. `target_or_work_floor` carries the `WorkContract` in witness mode. `realm` and `room` are
`vhalla_core::RealmId` and `RoomId`; `purpose` is a closed `u8` enum (`RateLimitRelief = 1`,
`GameQualification = 2`). `issuer_key` and `subject_key` are full 32-byte Ed25519 keys, never the
16-byte `PeerId` handle. `measured_work` is the `WorkLedger`. The response also carries
`proof_profile: ProofProfile` with the single variant `TransparentReceipt = 1`, the `Assignment`
bytes, and the `ClaimedReceipt`; a later ZK profile carries a proof of the same public statement
(`version || challenge_id || subject_key || task_manifest_hash || output_hash || work_floor ||
work_ceiling`) in place of the receipt. `MAX_CHALLENGE_LIFETIME = 15 * 60`. Entropy and clock are
injected: `ChallengeIssuer::issue(entropy: [u8; 32], now: u64, ..)` and every verifier call takes
`now`.

The challenge is not a `vhalla_crypto::SignedClaim`: the claim field set lacks the manifest hash and
the work range, and one-use consumption is not the epoch and sequence ordering `ClaimReplayWindow`
provides. `VerifiedWitness` can later be exported as a `SignedClaim` with `ClaimDomain::Receipt` and
`SubjectDigest = ReceiptHash` so a per-realm DAG can record it.

`VerifiedChallenge` has private fields, derives only `Debug`, is not `Clone`, and is produced only
by `challenge::verify_challenge`, which performs the size, version, algorithm, language, issuer
signature, `ChallengeContext`, and time-window steps below. It is the only source of capabilities
and bindings in `vhalla-botcaptcha`: `VerifiedChallenge::run_capability(&self, WorkAllowance,
RunRole) -> RunCapability` and `VerifiedChallenge::receipt_binding(&self) -> ReceiptBinding` wrap
`RunCapability::mint` and the `ReceiptBinding` constructor and are that crate's only call sites of
them. That is a `vhalla-botcaptcha` invariant enforced by module privacy, a `clippy.toml`
`disallowed-methods` entry for `vhalla_witness::RunCapability::mint` with a single `allow` at
`run_capability`, and the adversarial tests, not a cross-crate compiler proof. Both sides mint from
data they hold, so a capability still proves no remote fact; the only path to `VerifiedWitness` is
`WitnessVerifier::verify_response`.

`WitnessVerifier::new(started_at: u64, window: OneUseWindow)` records the injected clock at
construction. `OneUseWindow` state is volatile, and the steel-thread `ReplayWindow` does not cover
a consumed `Response`, because the subject can re-sign the same body in a fresh envelope with a
fresh session and sequence. `crates/vhalla-crypto/src/lib.rs` states the rule for its own replay
state: "a restarted owner must retain it durably or establish a fresh session before accepting
traffic". Here that means a restarted verifier either restores its window durably or is constructed
with a fresh `started_at`, and the time-window step rejects any challenge with `issued_at <
started_at` as `WitnessError::BeforeVerifierStart`. Exactly one `OneUseWindow` serves a given
`issuer_key` at a time; two verifier instances sharing an issuer key must share a durable dedup
ledger, which is outside these crates. Binding an `issuer_session` into the challenge transcript
would also cover the two-instance case but changes the decided games plan field set, so it is
deferred and would need a dated deviation entry plus a matching `ChallengeIssuer` change.

`WitnessVerifier::verify_response(&mut self, challenge, manifest, response, issuer, expected:
ChallengeContext, now)` follows the games plan's eight verifier steps in this order: size bounds;
version, algorithm, and language; issuer signature with `verify_strict` after rejecting weak keys;
`ChallengeContext` equality on full keys, realm, room, and purpose; `now` within `[issued_at,
expires_at]`, `issued_at >= started_at`, and lifetime at most the maximum (these steps yield the
`VerifiedChallenge`); `ManifestHash` recompute; subject signature; receipt fields equal the
challenge; assignment validation and `ProgramHash`; `Σ case.fuel <= WorkAllowance.max_total`;
replay under a `RunRole::Replay` capability from `VerifiedChallenge::run_capability`; exact
`encode` equality of receipts; `Σ delivered >= useful_floor`, `total <= ceiling`, `require_passed`;
and last `OneUseWindow::consume(scope_key, response_hash, expires_at)`. `WitnessError` has one
`Copy + Eq` variant per step.

`OneUseWindow` is non-`Clone`, bounded by `MAX_OPEN_CHALLENGES = 4096`, keyed by the dedup scope
digest, and inserts as the last fallible step. `consume(scope_key, response_hash, expires_at)`: an
unseen scope inserts `(response_hash, expires_at)` or fails with `Capacity`; the same scope with the
same `response_hash` is `Replay`; the same scope with a different `response_hash` is
`Equivocation`, refused and reported, never rewarded, and never overwrites the stored entry. The
window never evicts an entry before that entry's challenge expiry; `prune(now)` removes entries
whose stored `expires_at < now`, which is safe because the expiry check precedes the dedup check.
Policy names a badge grant by the reward digest over `scope_key || response_hash`, so one scope
yields at most one reward.

`VerifiedWitness` has private fields, derives only `Debug`, and has no `From`, decoder, or `Clone`.
It is not a `VerifiedEnvelope`. When Gate 5 integration lands, `vhalla-steel-thread` gains a
`compile_fail` doctest that `RemoteRequest::from_verified(witness, scope)` does not type-check, a
`KIND_WITNESS_RESPONSE: u8 = 3` constant, and a `WitnessSession` that decodes the frame, verifies
through `ReplayWindow`, and hands the body to `WitnessVerifier`. `RemoteRequest::from_verified`
keeps gating on kind 2 only.

### The five forks, restricted to these crates

| Fork | Decision here | Owner of the rest |
| --- | --- | --- |
| 1 Witness language | `LanguageId::FiniteRuleV1`, closed enum as the boundary for a later `LispV1`. Rejected: the `prototypes/witness` `Expr` AST; a fresh term bytecode; Platonik v3 and v4. | this plan |
| 2 Admission default | The crates never decide when to challenge; `ChallengeIssuer` and `WitnessVerifier` are the only surface. Invitations for trusted peers and adaptive Hashcash under load stay in policy and rooms. | policy, rooms |
| 3 Ledger scope | `VerifiedWitness::as_receipt_claim` produces a `SignedClaim` in `ClaimDomain::Receipt`; no DAG, voucher, or chain here. | `vhalla-ledger` |
| 4 Game authority | Out of scope. `TaskManifest`, `Case.events`, `StateHash`, `WorkAllowance`, and `VerifiedWitness` are the readiness plan's smallest shared contract: versioned session input, ruleset identity, explicit work allowance, ordered replay inputs, checkpoint identity, checked-result evidence. | Slice 5 adapter plan |
| 5 Currency | None. `passed-witness` is a badge minted by policy from `VerifiedWitness`; no value field exists. | policy, settlement |

### Crate plan

`crates/vhalla-witness`: `#![no_std] #![forbid(unsafe_code)] #![warn(missing_docs)]`, `extern crate
alloc`, deps `vhalla-core` and `sha2 0.10` without default features, dev-deps `proptest 1.6` and
`trybuild 1.0`. Modules: `bounds`, `model`, `codec`, `hash`, `manifest`, `ledger`, `vm` (sim.rs and
policy.rs restated), `capability` (`RunCapability::mint`), `receipt` (`ReceiptBinding`,
`WitnessRun::into_receipt`). Tests: `tests/{codec,vm,vectors,adversarial,no_alloc}.rs`,
`tests/ui/*.rs`, `tests/vectors/*.hex|*.id`. The crate has no key type and no challenge type;
`ReceiptBinding` holds two 32-byte values, not keys. It is created from
`prototypes/witness-restatement` once the spikes pass, not by moving that prototype.

`crates/vhalla-botcaptcha`: same attributes, deps `vhalla-core`, `vhalla-crypto`, `vhalla-witness`,
`sha2`, `ed25519-dalek 2.2` with `alloc` only. Modules: `challenge` (`VerifiedChallenge`),
`response`, `window`, `admit`, plus a `clippy.toml` `disallowed-methods` entry for
`RunCapability::mint`. Tests: `tests/{challenge,admit,adversarial,window}.rs`. Within
`vhalla-botcaptcha` every capability and binding is minted from a locally verified challenge through
`VerifiedChallenge`, and the only path to `VerifiedWitness` is `WitnessVerifier::verify_response`;
`vhalla_witness::run` itself is challenge-free, so corpus tests and the Slice 5 adapter replay
without key material.

Both crates are appended to the root `members` list and to the wasm32 `cargo check -p` list in
`.github/workflows/rust.yml`, each gets a README that states what a valid value does not prove, a
row in `docs/README.md` "Find the code", a row in the crate ownership table and a dated
execution-status entry in [[plans/valhalla-promotion-gates|the readiness plan]], and rows in
`prototypes/README.md`.

Deviation from the games plan: the first production crate is `vhalla-witness`, not
`vhalla-botcaptcha`, because the VM is also the game kernel and must not depend on key material.
`vhalla-botcaptcha` follows as the second stage.

`prototypes/witness` (README row rewritten as a superseded reference), `prototypes/botcaptcha`, and
`prototypes/game-session` stay as they are, beside `prototypes/witness-restatement` and the
disposable spike crates below.
`prototypes/witness-platonik-parity` git-pins `platonik-core` with a committed lockfile; the CI
prototype loop runs `cargo test --locked` with network, and local runs need one prior fetch before
`--offline`. Absent from both crates: serde, `std`, wall clock, entropy, signing-key storage,
network-supplied code execution, host effects, wallets, chains, and any `From` between evidence and
authority types.

Slice 5 seam: a later `std` crate `crates/vhalla-game-platonik` (optional, git-pinned
`platonik-core`, never a default platform dependency) maps `Experiment` to `TaskManifest` plus
`Assignment` with `loading_work` set to the JSON byte length, carries Platonik's `experiment_hash`
and `result_hash` as opaque `InnerArtifactId`s, reruns `vhalla_witness::run` under a capability
from `RunCapability::mint` with `RunRole::Replay` and no botcaptcha challenge for independent
receiver verification, and reuses `Case.events` as ordered replay inputs and `StateHash` as
checkpoint identity. It owns `GameManifest`, `SessionOpen`, `GameEvent`, `Checkpoint`, and
`Settlement`, the tampering, duplication, wrong ruleset or case, pause and resume, and failed
exchange tests, and the rule that traces of up to 7 MB are requested as bounded artifacts of at most
8 MiB in 64 KiB blocks, never carried in 64 KiB room frames.

## Threat model for this layer

| Threat | Mitigation |
| --- | --- |
| Padded or equivalent programs harvesting duplicate value | Reward is keyed by the dedup scope `(issuer_key, challenge_id, subject_key)` and consumed once; a second receipt with the same `response_hash` is `Replay`, and a different `response_hash` under the same scope is `Equivocation`. The floor is the delivered-spark outcome quantity plus `require_passed`; unsatisfiable-condition padding, `Turn` or `Move` spinners, constant-bit `Send`s, and two-cell `Send` ping-pong raise `conditions`, `sensors`, `transfers`, `messages`, and `checking` toward the ceiling and never the floor. |
| Hash or encoding collisions | Full 256-bit SHA-256 with distinct domain tags and length prefixes; a bijective codec with sorted ids, so one program has exactly one hash. |
| Verifier fuel exhaustion | `Σ case.fuel <= WorkAllowance.max_total` is checked before replay; `Meter` cannot exceed `fuel` by construction; `MAX_CASES = 8` and `MAX_FUEL = 2_000_000` bound the worst case, measured in spike 3; manifests with `total_ceiling > Σ fuel` are rejected at validation. Verifier and prover are symmetric by design: replay costs at most `total_ceiling`. |
| Malformed bytes | Bounded-first decoders, `checked_add`, `Truncated` and `TrailingBytes`, no indexing without `get`, `#![forbid(unsafe_code)]`, and a property test that arbitrary bytes never panic or decode to a non-canonical value. |
| Replay of responses | `challenge_id` is 32 injected random bytes, expiry at most 15 minutes, `OneUseWindow` is scope-keyed, non-`Clone`, and inserts last; a verifier rejects every challenge issued before its own `started_at`, so a restart or window loss within the lifetime cannot re-admit a consumed response; the steel-thread `ReplayWindow` covers only the envelope, since the subject can re-sign a consumed `Response` under a fresh session. |
| Wrong version, language, manifest, or world | Version and language bytes in every encoding and tag, no negotiation; the receipt and the challenge bind `ManifestHash`, which the verifier recomputes; seeds and events live inside the manifest. |
| Evidence laundering into authority | `VerifiedWitness`, `VerifiedChallenge`, and `RunCapability` have private fields, no `From`, no decoder, and no `Clone`; `compile_fail` doctests prove none reaches `RemoteRequest::from_verified` or a second `run`, and `ReceiptBinding`, which is plain bytes, converts into no `vhalla-botcaptcha` evidence type. |
| Divergent engines, clock, or entropy | Corpus vectors execute natively, under wasm32, and against the pinned Platonik engine in CI; neither crate reads a clock or entropy, and tests use constant seeds. |

## Discovery spikes

Each spike is a disposable crate under `prototypes/` with its own `[workspace]` table and lockfile.
The restated `model`, `codec`, `hash`, `manifest`, `ledger`, `vm`, `capability`, and `receipt`
modules and the `bridge-v1` `Experiment` to `TaskManifest` plus `Assignment` converter live once, in
`prototypes/witness-restatement` (stage 0: `no_std` plus `alloc` core with the converter behind a
`std` feature, its own `[workspace]` table and lockfile); every spike path-depends on it exactly as
`prototypes/checkpoint-ledger` path-depends on `../checkpoint-proof`. No spike carries a private
copy of any of these types, so every spike result is evidence about one implementation. Results are
recorded as dated entries under "Execution status" here. A failed spike changes the design and
`prototypes/witness-restatement` before `crates/vhalla-witness` lands.

### Spike 1: platonik-parity

- Question: does the restated VM reproduce the committed Platonik engine exactly?
- Method: `prototypes/witness-platonik-parity` (`std`, git-pins `platonik-core` at `5eedec07`,
  path-depends on `prototypes/witness-restatement`) converts every `bridge-v1` fixture and 200
  proptest-generated v1 experiments to `TaskManifest` plus `Assignment` with `loading_work` set to
  the JSON byte length, runs both engines, and diffs every frame's state, activations, signal
  outcomes, and all eleven cost counters, including fuel-exhausted and activation-limit cases.
- Pass: zero divergence. Fail: record the diff and fix the restatement or the model before
  proceeding.
- Settles: the charge schedule restatement, declared `loading_work`, and the corpus vector files for
  `tests/vectors/`.

### Spike 2: codec-bounds

- Question: is the binary codec bijective and do the byte bounds hold?
- Method: `prototypes/witness-codec-spike` (over the restatement's codec) plus
  `prototypes/witness-vectors/generate.py` (Python `struct` and `hashlib`) encode every corpus
  program, assignment, manifest, state, and receipt from spike 1's vector files;
  proptest over 10^5 values checks both codec laws; the Python generator produces
  `/vectors/witness-v1.json` independently.
- Pass: every manifest at most 32768 bytes, every assignment at most 32832 bytes, both laws hold,
  and Rust and Python digests agree on every vector. Fail: raise bounds or split the manifest before
  freezing v1.
- Settles: `MAX_*_BYTES`, the codec freeze, and the vector oracle location.

### Spike 3: nostd-wasm-parity

- Question: does the VM build as `no_std` plus `alloc`, produce identical hashes under wasm32,
  allocate nothing in the tick loop, and verify within budget?
- Method: `prototypes/witness-wasm-parity` (pattern `prototypes/discovery-parity`, wasm-bindgen-cli
  0.2.108, over the restatement's `vm`) runs spike 1's corpus natively and under
  `wasm32-unknown-unknown` and diffs every `OutputHash` and `StateHash`; a counting global allocator
  wraps `run` in a `std` test; timing covers the dense 16-cell 128-tick case. The local machine has
  no rustup or wasm32 target; the spike installs rustup into the scratchpad or runs in CI and
  records which.
- Pass: identical hashes on both targets; zero allocations after `initial_state`; native p95 replay
  at most 100 ms and wasm at most 500 ms; peak heap at most 32 MiB. Fail: fix the platform-dependent
  operation or lower `MAX_CASES` before Gate 6.
- Settles: the `no_std` and pre-bounded allocation rule, the wasm CI step, and the default
  `WorkAllowance`.

### Spike 4: work-contract-separation

- Question: does the outcome-quantity floor `useful = Σ beacons[i].delivered` separate working,
  padded, and idle programs?
- Method: `prototypes/witness-contract-spike` (over the restatement's converter, `ledger`, `vm`,
  and `WorkContract`; needs only stage 0) generates at least 50 assignments per `bridge-v1` fixture
  in three classes and evaluates one `WorkContract` per fixture. Working: a program that passes.
  Padded working: a working program plus unsatisfiable-condition rules, idle memory writes,
  always-true `[] => Turn` and `Move` spinners, constant-bit `Send`s to an open port, `Send`s into
  disabled or full links, and `TakeMessage` loops. Idle: `Wait`-only, `Turn`-only, `Move`-only, and
  two adjacent linked cells ping-ponging `Send`s with no `Pickup`, `Drop`, or beacon delivery.
- Pass: the contract admits every working program, admits padded variants only as the same
  one-reward challenge, rejects every idle program, and padding never raises `useful`. Fail: switch
  to the twelfth `useful` counter charged only in `credit()`, `Drop` into a depot, and `Pickup` from
  a source, kept outside `total()` so spike 1 parity is unaffected, before the floor is signed into
  receipts.
- Settles: the floor definition (`WitnessRun::useful`), the `require_passed` default, and the
  fixture default contracts.

### Spike 5: capability-fences

- Question: do the move-only and private-field fences hold on stable Rust, and does the one-use
  window with expiry pruning match a model?
- Method: `prototypes/witness-fences-spike` (needs only the restatement's type signatures) holds
  trybuild cases for `RunCapability` (struct literal, `clone`, second `run`), `Assignment`,
  `Program`, `VerifiedChallenge`, `VerifiedWitness`, and `WitnessReceipt` fabrication, and for
  `ReceiptBinding` converting into any `vhalla-botcaptcha` evidence type, run on current stable and
  the previous two; a proptest drives `OneUseWindow` against a `BTreeMap<[u8; 32], ([u8; 32], u64)>`
  model keyed by scope and storing `(response_hash, expires_at)`, under random accept, replay,
  equivocate, prune, and state-loss (window dropped, `started_at` advanced) schedules.
- Pass: every case fails to compile with the expected error code (E0382, E0451, E0599, E0624) on
  every toolchain, and the window never admits a replay, reports every equivocation without
  overwriting, never evicts an unexpired entry, always prunes expired ones, and after state loss
  refuses every challenge issued before the new `started_at`. Fail: keep `compile_fail` doctests as
  the CI proof and drop `.stderr` pinning for the churning case; redesign pruning if the model
  diverges.
- Settles: trybuild versus doctest as the boundary proof and the `OneUseWindow` capacity and pruning
  rule.

## Dependency-ordered work

1. Land `prototypes/witness-restatement` (stage 0): the restated modules, the `bridge-v1`
   converter, and the type signatures every spike compiles against. Nothing else runs before it
   compiles.
2. Spike 1 runs against it and writes the corpus vector files. Spike 4 (converter, ledger, contract
   only) and spike 5 (type signatures only) start as soon as stage 0 compiles and need no other
   spike's output.
3. Spikes 2 and 3 start once spike 1's corpus files exist and run in parallel over them.
4. A spike 1 failure changes `prototypes/witness-restatement`; spikes 2 and 3 then rerun, and spike
   4 reruns if the ledger, outcome fields, or charge schedule changed. Record each result under
   "Execution status" with the commit, toolchain, and reproducible command.
5. Land `crates/vhalla-witness`, created from the restatement, with `bounds`, `model`, `codec`,
   `hash`, `manifest`, `ledger`, `vm`, `capability`, `receipt`, the corpus vectors from spike 1, the
   Python vectors from spike 2, README, workspace membership, and the wasm32 CI entry.
6. Land `crates/vhalla-botcaptcha` with `challenge`, `response`, `window`, `admit`, `clippy.toml`,
   adversarial tests, and its README and CI entries.
7. Update `docs/README.md`, `prototypes/README.md`, and the crate ownership table plus a dated entry
   in [[plans/valhalla-promotion-gates|the readiness plan]]; run `wordcell percolate`, `wordcell
   refresh`, and `wordcell check` with `--root kb`, or record that the `wordcell` CLI is
   unavailable.
8. Gate 5 integration as a separate execution-status entry: `KIND_WITNESS_RESPONSE = 3`,
   `SteelError::Witness(WitnessError)`, `WitnessSession::receive_witness`, the steel-thread
   `compile_fail` doctest, and an e2e test that a witness frame never moves `MemoryHost::reads()`.
9. Slice 5 adapter plan for `crates/vhalla-game-platonik`, then Hashcash mode promotion into
   `vhalla-botcaptcha` as its own entry.

## Verification

Deterministic vectors:

- `/vectors/witness-v1.json` from `prototypes/witness-vectors/generate.py`: program encoding and
  `ProgramHash`, a minimal manifest and `ManifestHash`, a challenge transcript and signature over
  public seed `[9; 32]`, a receipt encoding and `ReceiptHash`, the dedup scope digest, and the
  reward digest. Hex is asserted
  verbatim in the crate tests and `python3 prototypes/witness-vectors/verify-vectors.py` runs in CI
  beside the social-facets step.
- `crates/vhalla-witness/tests/vectors/`: for each `bridge-v1` fixture the converted manifest
  `.hex`, assignment `.hex`, and expected `OutputHash`, per-case `StateHash`, and `WorkLedger` `.id`
  files produced by spike 1 and loaded with `include_str!`; golden ledger tables for the
  fuel-exhaustion and activation-limit fixtures (`total() == fuel` on exhaustion).

Property tests (proptest, 64 cases, regression files committed): codec round-trip and canonicality
for every type; arbitrary bytes never panic; `run(m, a) == run(m, a)`; `total <= fuel` and
per-counter monotonicity; activation-limit rollback restores the pre-activation state while work
increases; spark conservation; activation order is a prefix of the seeded order; any single-byte
flip of a signed challenge or response is rejected with the expected variant; `OneUseWindow` against
its model; `RunError::Arithmetic` unreachable.

Compile-fail: `RunCapability` cannot be cloned, struct-literal built, decoded, or used for two runs;
`Assignment`, `Program`, `VerifiedChallenge`, and `VerifiedWitness` cannot be fabricated or cloned;
`UntrustedProgram` cannot reach `run`; `WitnessReceipt` cannot become `VerifiedWitness` without
`verify_response`; `ReceiptBinding` cannot become any `vhalla-botcaptcha` evidence type.
Doctests are the CI proof; trybuild pins the error codes per spike 5.

Adversarial corpus (`tests/adversarial.rs`, exhaustive error-variant tables): wrong issuer key,
subject, realm, room, or purpose; expired; not yet valid; lifetime over 15 minutes; manifest or
program hash mismatch; tampered output; tampered ledger per counter; padded program (passes replay,
visible in `checking`, one reward); idle program (fails floor: `Wait`-only, `Turn`-only, and
two-cell `Send` ping-pong); over-ceiling program; assignment for a fixed slot; unsorted assignment;
`Replay`; `Equivocation`; `Capacity`; `BeforeVerifierStart`; verifier restart within the lifetime
rejects the consumed response; a re-wrapped envelope with a fresh session around a consumed
`Response` is still rejected (the "replay after restart" case in the
[[plans/valhalla-security-first-design|security design]] verification list); oversized manifest or
assignment; trailing bytes; `LanguageId = 2`; `algorithm = 1`; version 2; wrong case count;
`proof_profile = 2`.

Gate commands from the repository root:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
cargo test --workspace --doc --all-features --locked
cargo check -p vhalla-witness -p vhalla-botcaptcha --target wasm32-unknown-unknown --locked
python3 prototypes/witness-vectors/verify-vectors.py
sh prototypes/witness-wasm-parity/verify.sh
for manifest in prototypes/witness-*/Cargo.toml; do cargo fmt --manifest-path "$manifest" -- --check; cargo test --manifest-path "$manifest" --locked; cargo clippy --manifest-path "$manifest" --all-targets --locked -- -D warnings; done
```

Security review statement for the promotion entry: foreign input is `Challenge`, `Response`,
`Assignment`, `ClaimedReceipt`, and `TaskManifest` bytes; no authorization-proving type exists (this
layer mints evidence only); limits are the static bounds above; fixtures are
`/vectors/witness-v1.json` and `tests/vectors/`; the remaining failure mode is that witness mode
alone is not proof of work, and a hostile issuer can publish a trivially satisfiable manifest, which
is issuer policy.

## Recovery

- A spike failure changes this plan and `prototypes/witness-restatement`, not the crates; nothing
  is promoted until all five spikes record a pass.
- Any codec, tag, or bound change after v1 freezes requires a new version byte, a new tag string, a
  new vector file, and a dated plan entry; v1 vectors stay in the tree and keep passing.
- If native and wasm32 hashes diverge after landing, the wasm CI step fails the build; the fix is a
  determinism rule recorded here, never a per-target vector.
- If `OneUseWindow` reaches capacity, verification fails closed with `Capacity`; the operator lowers
  challenge issuance or shortens expiry so `prune` frees entries. No eviction of unexpired entries
  is ever added.
- If a verifier process restarts or loses `OneUseWindow` state, it is constructed with `started_at
  = now` and refuses every challenge issued before that instant; no window is ever rebuilt from
  peer-supplied data.
- If the Platonik pin moves, spike 1 reruns against the new commit before any corpus vector is
  regenerated. Rollback of either crate is removal from `members` and the CI lists; no other crate
  depends on them until the Gate 5 entry.

## Decision record

| Decision | Chosen | Rejected | Status |
| --- | --- | --- | --- |
| Witness language v1 | `LanguageId::FiniteRuleV1`, Platonik habitat-v1 cell programs | `prototypes/witness` `Expr` AST; new term bytecode; Platonik v3 and v4 | decided |
| Language boundary for Lisp | closed `#[repr(u8)] LanguageId` in manifest, program, challenge, receipt, tags | interpreter trait; compiling rules to a term core | decided |
| Crate split | `vhalla-witness` (keyless VM) then `vhalla-botcaptcha` (challenge, response, admission) | one crate; VM inside `vhalla-botcaptcha`; VM inside `vhalla-crypto::claims` | decided |
| Platonik reuse | restate model, sim, policy in production types; pinned engine as test oracle only | production git or path dependency; upstream `std` feature flag | decided |
| Canonical encoding | fixed-width binary codec per `vhalla-wire` conventions; bounds derived from the widest variants | serde_json compact bytes; CBOR or postcard | decided (Rust half of spike 2); Python oracle pending |
| Hashing | SHA-256, `vhalla/witness/<thing>/v1` and `vhalla/botcaptcha/<thing>/v1`, `u32` length prefix | Platonik `sha256:` hex JSON hashes; `vhalla/signed-claim/v1` transcripts | decided |
| Loading cost | per-case declared `loading_work`, each at least the manifest's canonical length | derive from serializer byte length; one manifest-level value | decided (spike 1) |
| Floor and ceiling | floor `useful = Σ beacons[i].delivered` read from replayed state; ceiling `total()`; `require_passed` defaults to `true` | floor `transfers + messages` (`Turn`, unblocked `Move`, `emit`, and inbox expiry charge them without moving a spark); floor including conditions and sensors; single fuel counter; fallback twelfth `useful` counter | pending spike work-contract-separation |
| Checked arithmetic | no arithmetic operator in v1; all counters `checked_*`; `RunError::Arithmetic` proven unreachable | wrapping arithmetic; reliance on `overflow-checks` | decided |
| Memory limit | static `MAX_STATE_BYTES` from Platonik v1 limits; no memory counter | dynamic memory counter | decided |
| `no_std` shape | `no_std` plus `alloc`, every `Vec` pre-bounded, zero allocation in the tick loop | fixed arrays only; `heapless` | decided (spike 3) |
| Run capability | local, move-only `RunCapability::mint(ManifestHash, ProgramHash, WorkAllowance, RunRole)` in `vhalla-witness` with no challenge input, consumed by `run`; `VerifiedChallenge::run_capability` is its only caller in `vhalla-botcaptcha` | `RunCapability::for_challenge(&VerifiedChallenge, ..)` in `vhalla-witness` (circular dependency, blocks challenge-free replay); capability on the wire; runtime `used` flag; `Copy` grant | decided |
| Program validation | private fields; `Assignment::validate` is the only path to `run` | public-field `Program` with a validate helper | decided |
| Receipt shape | private `WitnessReceipt` from `into_receipt(ReceiptBinding)`; `ReceiptBinding { challenge_id, subject_key }` as `Copy` plain bytes in `vhalla-witness`; public `ClaimedReceipt` on the wire; bit-exact compare | `into_receipt(&VerifiedChallenge, subject_key)` in `vhalla-witness`; receipt with a decoder; self-hash inside the receipt | decided |
| Verifier restart | `WitnessVerifier::new(started_at, ..)` rejects `issued_at < started_at` (`BeforeVerifierStart`); one `OneUseWindow` per `issuer_key`; games plan field set kept verbatim | `issuer_session` in the challenge transcript (deferred; needs a dated deviation and a `ChallengeIssuer` change); durable window rebuilt from peers | decided |
| Spike staging | `prototypes/witness-restatement` as stage 0; spikes path-depend on it; spike 1 before spikes 2 and 3; spikes 4 and 5 after stage 0 | five parallel spikes each restating the types; drafting `crates/vhalla-witness` outside `members` | decided |
| Trace and audit | no frame codec, trace hash, or `check.rs` audit in v1; deferred to the Slice 5 adapter plan | streamed `TraceHash` and `audit.rs` in v1 | decided |
| Challenge type | independent signed `Challenge` and `Response` with the games plan field names | `SignedClaim` domain; carrying `RunCapability` | decided |
| Proof profile | `ProofProfile::TransparentReceipt = 1` in the response transcript | no profile field until ZK exists | decided |
| One-use window | 4096 entries keyed by dedup scope `(issuer_key, challenge_id, subject_key)` storing `(response_hash, expires_at)`; same hash `Replay`, different hash `Equivocation`; non-`Clone`, insert last, prune only expired entries | key over the 4-tuple including `response_hash` (makes `Equivocation` undetectable); 1024 with no eviction; `ClaimReplayWindow` | pending spike capability-fences |
| Boundary proof | `compile_fail` doctests as CI proof, trybuild for error codes | trybuild only | pending spike capability-fences |
| Vector oracle | `/vectors/witness-v1.json` from Python plus per-crate corpus `.hex` and `.id` | Rust-only vectors | pending spike codec-bounds |
| Steel thread | kind 3 and `WitnessSession` in a later Gate 5 entry, never through `RemoteRequest` | wire kind in the first landing; widening `from_verified` | decided |
| Platonik pin | `5eedec07c84af3b4beb82f22cc6c2b9fa3520d42` | `76ea2db` | decided |
| Game layer | separate Slice 5 adapter plan for `vhalla-game-platonik` | game types in these crates; porting `prototypes/game-session` | decided |
| Hashcash mode | stays in `prototypes/botcaptcha`; `algorithm = 1` reserved | promoted with witness mode | decided |
| Plan location and Roc | this file plus a dated entry in the readiness plan; Roc as reference design only | section inside the games plan; Roc toolchain or platform host | decided |

## Review findings

Applied on 2026-09-16 from the confirmed review; each line is id, lens, and what changed.

- W1, authority: `RunCapability::for_challenge` and `into_receipt(&VerifiedChallenge, ..)` left `vhalla-witness`; the crate now has keyless `RunCapability::mint` and `WitnessRun::into_receipt(ReceiptBinding)`, `VerifiedChallenge` with `run_capability` and `receipt_binding` lives in `vhalla-botcaptcha`, the "cannot start without a verified challenge" compiler claim is gone, and the only path to `VerifiedWitness` is `verify_response`.
- W4, authority: `WitnessVerifier::new(started_at, ..)` rejects `issued_at < started_at` (`BeforeVerifierStart`); the volatile-window rule from `vhalla-crypto` is quoted; one window per `issuer_key`; a Recovery bullet, two adversarial cases, a spike 5 state-loss schedule, and a decision row were added; `issuer_session` is recorded as deferred.
- H1, codec-math: the window key is the dedup scope `issuer_key || challenge_id || subject_key` with `(response_hash, expires_at)` as the value; `consume(scope_key, response_hash, expires_at)` distinguishes `Replay` from `Equivocation`; a separate reward digest keeps the games plan 4-tuple; the digest table, threat row, vector list, spike 5 model, and decision row follow.
- F1, scope-delivery: `prototypes/witness-restatement` is stage 0 and every spike path-depends on it; the work order is stage 0, then spike 1 with spikes 4 and 5, then spikes 2 and 3 over spike 1's corpus; `crates/vhalla-witness` is created from the restatement.
- F1, threat-model: the floor is no longer `transfers + messages` (charged by `Turn`, unblocked `Move`, `emit`, and inbox expiry); it is the outcome quantity `Σ beacons[i].delivered` read from replayed state, `require_passed` defaults to `true`, spike 4's padded and idle classes cover spinners and `Send` ping-pong, and the fallback is a twelfth custody counter outside `total()`.
- N1, conventions: the constructor is `mint` over data `vhalla-witness` owns and `ReceiptBinding` is `Copy` plain bytes with no key type; the Slice 5 adapter mints with `RunRole::Replay`; the single-caller rule in `vhalla-botcaptcha` is enforced by privacy, a clippy `disallowed-methods` entry, and tests; spike 5 gains a `ReceiptBinding` trybuild case.

## Execution status

### 2026-09-16: stage 0 and spike 1 pass; codec laws and bounds hold over the corpus

Commit `6900d9c` plus the platform-layer commit that follows it; Homebrew `cargo 1.97.1` on
`aarch64-apple-darwin`; `cargo test --locked`, `cargo clippy --all-targets --locked -- -D warnings`,
`cargo test --locked --doc`, and `cargo fmt -- --check` from `prototypes/witness-restatement`, plus
`cargo test --locked` from its `alloc-probe/` subcrate.

- Stage 0 landed as `prototypes/witness-restatement`: `bounds`, `model`, `world`, `ledger`, `vm`,
  `codec`, `hash`, `manifest`, and `platform`. The library is `no_std` plus `alloc` with `sha2` as
  its only dependency. Spike 1 lives in that crate's `tests/parity.rs` rather than a separate
  `witness-platonik-parity` crate: the parity test is the evidence about stage 0 itself, and one
  crate keeps one lockfile for the pinned oracle.
- Spike 1 passes with zero divergence: every fixture, all 21 `bridge-v1` suite cases (equal to the
  suite's own receipts), 400 deterministic random v1 experiments including fuel exhausted at load,
  fuel exhausted mid-run, and activation-limit stops, and the densest 16-cell 128-tick case that
  fits Platonik's 64 KiB input bound. Every frame's state, activations, signal outcomes, outcome,
  final state, and all thirteen counters match `platonik-core` at `5eedec07`.
- Ground truth corrections applied to this plan's text: the meter has thirteen counters, not
  eleven; `copying` and `construction` exist in v1 receipts and are always zero, and the
  restatement keeps them so `Costs` compares bit for bit. Platonik charges `loading` as the JSON
  byte length of the whole experiment including every cell's program, so loading depends on the
  assignment; the restatement declares `loading_work` per case, and `ValidManifest::validate`
  requires every case to declare at least the manifest's canonical length. `Turn`, unblocked
  `Move`, `emit`, and inbox expiry charge `transfers` or `messages`, which is why the floor is the
  outcome quantity `Σ beacons.delivered`.
- Allocation: the counting allocator in `alloc-probe/` observes zero allocations inside the tick
  loop across 122 corpus runs totalling 831,709 work units; `tests/no_alloc.rs` shows every state
  vector keeps its pre-bounded capacity.
- Timing (unoptimized dev profile, best of 5): densest suite case 838 µs for 6,011 units over 55
  ticks; the 64 KiB worst case 87.6 ms for 422,061 units over 128 ticks. The release-profile p95
  figures the spike 3 pass criterion names are still to be measured.
- Spike 2, Rust half: the fixed-width codec round-trips every corpus program, assignment,
  manifest, and output (`decode(encode(x)) == x` and `encode(decode(raw)) == raw`), 20,000 random
  byte strings never panic, and the bounds derived from the widest variants are
  `MAX_PROGRAM_BYTES = 1059`, `MAX_ASSIGNMENT_BYTES = 16947`, `MAX_MANIFEST_BYTES = 23991`, and
  `MAX_STATE_BYTES = 9572`; the largest corpus encodings are 313, 2,915, 1,592, and 2,349 bytes. The
  plan's earlier 42-byte rule and 2048/32832/32768 figures are superseded by these derived
  constants. `ProgramHash` is over the assignment bytes under `vhalla/witness/assignment/v1`, so no
  tag names two encodings. The Python oracle and `/vectors/witness-v1.json` are still pending.
- Platform chain: `ValidManifest::validate`, `assign` (fixed and open slots), keyless
  `RunCapability::mint`, `run` (refuses a foreign manifest hash, program hash, or short allowance),
  `WitnessRun::into_receipt(ReceiptBinding)`, and `ClaimedReceipt::decode` plus bit-exact `matches`
  are implemented and tested; three `compile_fail` doctests cover cloning or forging
  `RunCapability` and decoding into `WitnessReceipt`.

### 2026-09-16: spikes 3 and 4 pass; spike 2's Rust half and vector oracle land

Commits `2ee38b6` (vectors), `3ae7be6` (contract spike), `f7c6bba` (wasm parity); Homebrew
`cargo 1.97.1` for native gates, a scratchpad rustup `stable 1.98.1` with the
`wasm32-unknown-unknown` target, `wasm-bindgen-cli 0.2.108`, and Node 24.18.1 for the wasm run.

- Corpus vectors: `prototypes/witness-restatement/vectors/*.txt` hold, for every fixture, every
  `bridge-v1` case, and the 64 KiB worst case, the canonical manifest and candidate bytes and the
  expected `ManifestHash`, `ProgramHash`, `OutputHash`, per-case `StateHash`, `useful`, `total`,
  and `passed`. `tests/vectors.rs` parses, re-renders, and replays every file on each test run.
- Spike 3 passes: `prototypes/witness-wasm-parity/verify.sh` builds the replay for both targets,
  runs the wasm through wasm-bindgen under Node, and finds native, wasm32, and committed renderings
  identical on 28 files. Release profile: the 64 KiB worst case replays in 5.3 ms natively (oracle
  7.5 ms) and the densest suite case in 34 µs; the whole 28-file corpus replays in 10.9 ms under
  wasm with a 0.3 MiB wasm heap; native maximum resident set 2.6 MB; the wasm artifact is 238 KB.
  The pass criteria (native p95 at most 100 ms, wasm at most 500 ms, heap at most 32 MiB) hold
  with two orders of magnitude to spare. The `no_std` plus `alloc` shape and the pre-bounded
  allocation rule are decided.
- Spike 4 passes with the floor `useful = Σ beacons.delivered`: on the five fixtures that deliver,
  working programs are admitted; unsatisfiable-condition, dead-effect, and unreachable padding
  within the activation budget preserves the final state and only raises `total`; padding beyond
  the activation budget (24 unsatisfiable rules against a 64-unit activation budget) makes the
  program idle and is rejected; `Wait`, `Turn`, `Move`, and two-cell `Send` ping-pong programs
  deliver nothing and are rejected. The rejected `transfers + messages` floor would have admitted
  every turn-only spinner (44 to 220 charged units) and the ping-pong pair on the ark fixtures (148
  messages). `require_passed` defaults to `true`.
- Spike 2, still pending: the independent Python generator and `/vectors/witness-v1.json`. The
  Rust vector files above are the oracle until it lands.
- Deviation recorded: `prototypes/witness-restatement` carries the corpus converter and generators
  in a `std`-gated `corpus` module (with `platonik-core` as an optional dependency and as the
  dev-dependency oracle) instead of a separate parity crate; the contract and wasm spikes
  path-depend on it as the plan requires.
