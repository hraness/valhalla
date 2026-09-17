---
title: Valhalla Platonik session adapter
type: plan
area: valhalla-platonik-session-adapter
status: in-progress
tags:
  - games
  - verification
  - checkpoints
  - wasm
---

# Valhalla Platonik session adapter

**Status:** proposed; one platform change and six discovery spikes gate the first release
**Date:** 2026-09-16
**Scope:** `crates/vhalla-game-platonik`, the Slice 5 crate that carries a Platonik session as a
host-ordered signed event log, commits its state through `vhalla-witness` replay, and lets any
receiver verify the result without trusting the host
**Owner:** the repository owner (benguo) is the implementation owner; an independent reviewer is
named in the stage 1 execution-status entry before any promotion claim
**Pin:** `platonik-core` at `5eedec07c84af3b4beb82f22cc6c2b9fa3520d42`; if the pin moves,
`prototypes/witness-restatement` parity reruns before anything else

This plan is work item 9 of [[plans/valhalla-witness-platform|the witness platform plan]] and
fills its Slice 5 seam. It implements the "5. A real game" row of
[[plans/valhalla-promotion-gates|the readiness plan]], grows fork 4 (game authority) of
[[plans/valhalla-botcaptcha-ledger-games|the games plan]] into a decision, and is the session
substrate that P4 (multicell sessions) and P6 (Platonik endosymbiosis and evolutionary ecology) of
[[plans/valhalla-eukaryotic-transition|the eukaryotic transition plan]] consume. Realm finality and
settlement stay where [[plans/valhalla-blockchain-architecture|the blockchain architecture plan]]
puts them. One sentence: a Platonik session is a host-ordered, multi-author, signed event log on
`vhalla-ledger` whose game state is committed by `vhalla-witness` replay, and every receiver
re-derives every root and re-runs every segment before it calls anything verified.

## Outcome

- `crates/vhalla-game-platonik` is a `std` workspace member that owns the five game-layer objects in
  the games plan's words: `GameManifest` = signed content-addressed package metadata; `SessionOpen`
  = manifest, ruleset, seed commitment, players, limits; `GameEvent` = author, parent heads,
  sequence, bounded action/input; `Checkpoint` = state hash, event-head hash, receipt/work summary;
  `Settlement` = signed result or explicit unresolved fork.
- A receiver holding a signed manifest, an opening, and the host's sealed segments replays every
  segment through `vhalla_witness::platform` under `RunRole::Replay`, derives every ledger root,
  and produces private `VerifiedCheckpoint` and `VerifiedSettlement` evidence or an explicit
  `Unresolved` outcome with retained evidence. No remote report, flag, root, or receipt is trusted.
- Platonik's `experiment_hash`, `result_hash`, and the `artifact_hash` of any whole artifact that
  moves ride through unchanged as opaque `InnerArtifactId`s tagged by `InnerKind`; multi-megabyte
  Platonik receipts move as bounded artifacts, never in frames.
- A pause, a member replacement, and a resume reproduce the unpaused run's `StateHash`es and
  receipt bit for bit on native and wasm32, which is the P4 exit condition.
- The crate has no clock, entropy, file, socket, signing-key storage, currency, chain, quorum, or
  `From` between evidence and authority; game authority is one explicit session host.

## Context

The witness crates landed a keyless replay chain (`ValidManifest::validate` and `assign`,
`RunCapability::mint`, `platform::run`, `WitnessRun::into_receipt`, `ClaimedReceipt::matches`) and
deferred the frame trace, trace hash, `check.rs` audit, checkpoint continuation, and every game
type to this plan. `vhalla-ledger` is a promoted linear, single-tip history keyed by `(RealmId,
Epoch)` with per-actor monotone `Sequence` and a derived `StateRoot` that refuses caller-supplied
roots. The only production quorum path is `vhalla-rooms-consensus` with engine-owned certificates.
`prototypes/game-session` and `prototypes/settlement` use integer approvers and may not be
imported. Platonik at the pin already has a session protocol (the habitat journal with Started and
Completed entries, `expected_revision` fencing, `recover`, `MAX_ADVANCES = 8`) and continuation at
complete tick boundaries; its largest measured receipt is 7,141,362 bytes and a full eight-advance
verify costs 226 engine executions.

## Scope and non-goals

In scope: the crate, its wire objects and digests, the host-ordered session state machine, the
ledger binding, receiver verification with budgets, bounded artifact assembly, the `oracle`
feature, golden vectors with an independent Python oracle, property, adversarial, and fuzz tests,
the wasm32 parity run, and the documentation and readiness-plan entries a landing needs.

Non-goals, each named so no reader infers it: no currency, vouchers, credits, escrow, or leases
(contracts are receipt-based, eukaryotic decision 3); no permissionless finality, fork choice,
global chain, or quorum host in the first release (`Authority::Quorum` is reserved on the wire);
no network-supplied code execution (programs are `finite-rule-v1` data bounded by
`MAX_PROGRAM_BYTES = 1059`, interpreted only by `vhalla-witness`); no host effects, files, sockets,
wall clock, entropy, or signing-key storage in the crate; no Platonik v2 `EdgeBlocked`, v3
construction, or v4 direction edits (the oracle refuses `version != 1` and
`construction.is_some()`); no `platonik-core` or serde on the default path and no Dioxus; no `From`
or `Into` between `VerifiedCheckpoint`, `VerifiedSettlement`, or `VerifiedWitness` and
`AuthorizedEffect` or `RemoteRequest`; no frame codec, trace hash, or continuation API in
`vhalla-witness` (the single platform change is an observer hook, recorded as a dated deviation
in the witness plan).

## Constraints and decisions

### Crate plan

`crates/vhalla-game-platonik`: `std`, appended to `members` after `crates/vhalla-botcaptcha`,
`version = "0.0.0"`, `[lints] workspace = true`, `#![forbid(unsafe_code)]`,
`#![warn(missing_docs)]`. Nothing in the workspace depends on it; a later `vhalla-cli` subcommand
and a later steel-thread evidence kind reach it from above.

| Feature | Default | Pulls in | Purpose |
| --- | --- | --- | --- |
| (none) | yes | `vhalla-witness`, `vhalla-core`, `vhalla-crypto`, `vhalla-ledger`, `sha2` | session, checkpoint, settlement, receiver, artifact assembly; no serde, clock, file, or socket |
| `oracle` | no | `platonik-core` (git, `rev = 5eedec07…`, optional), `serde`, `serde_json` (optional; `=1.0.229`, `=1.0.151` inherited from the pin) | `Experiment` to `TaskManifest` plus `Assignment` with `loading_work` = JSON byte length; `check::verify_receipt` audit of fetched artifacts; corpus generation. Test oracle and publisher tool, never a receiver requirement |
| `quorum` | no | `vhalla-rooms-consensus` | stage 5 only: `Authority::Quorum` settlement through an `Adapter::absorb`-style certificate verify hook |

`[dev-dependencies]` carry `vhalla-game-platonik = { path = ".", features = ["oracle"] }` and a
non-optional `platonik-core` git dependency (the `witness-restatement` pattern), so every test sees
the oracle. That self path unifies `oracle` into the library whenever dev targets are built
(resolver 2 skips dev-dependency features only when dev targets are not built), so no `cargo test`
invocation in this crate can exercise the default path and a `#[cfg(not(feature = "oracle"))]` test
inside this crate is unreachable. The default-path surface is the native and wasm32 `cargo check`
lines of the verification block plus the dependency-graph assertion beside them; runtime coverage of
the oracle-free path would need a separate test package that depends on `vhalla-game-platonik` with
`default-features = false`. CI runs `--all-features --locked`, so the git fetch and the oracle run
on every workspace step; `Cargo.lock` gains the `platonik-core` entry once through `cargo check
--workspace --all-features --offline` (never `generate-lockfile`). The crate joins the wasm32 CI
list with default features; the probe showed the crate and even `platonik-core` compile there. A
`clippy.toml` `disallowed-methods` entry fences `RunCapability::mint` to `platonik.rs`, copied from
`vhalla-botcaptcha`. Dependency review for the first PR: `platonik-core` (MIT, pinned commit,
hraness-owned), `serde`, `serde_json` (MIT or Apache-2.0, exact versions already in the lock),
`ed25519-dalek` reached only through `vhalla-crypto`; the advisory check is recorded in the stage 1
entry.

Modules: `ids`, `wire` (encodings over `vhalla_witness::codec::{Writer, Reader}` and every
`MAX_*` bound), `record` (audience-free signed carrier), `manifest`, `engine` (the one
`GameEngine` seam), `platonik` (`PlatonikV1`, the only engine), `session`, `checkpoint` (over
`vhalla_ledger`), `settlement`, `receiver`, `artifact`, `vectors`, `oracle/` (feature gated), and
`quorum/` (stage 5); golden vectors under `tests/vectors/game-v1-*.txt`.

Stays in `prototypes/`: `game-session` and `settlement` (disposable, deleted at stage 3),
`checkpoint-proof` and `checkpoint-ledger` (consumed only when `quorum` lands), `browser-records`
(reference for 4 KiB records), and `witness-restatement` (its `corpus::convert` is restated in
`oracle/convert.rs`, never path depended on). Rejected: game types inside `vhalla-witness`; a
generic `vhalla-game` crate before a second engine exists; `platonik-core` as production replay;
`rooms-consensus` as a first-release dependency.

### Vocabulary mapping

Every digest is `vhalla_witness::hash::digest(domain, bytes)`, that is SHA-256 over the domain, a
`u32` big-endian length, and the bytes. Every encoding uses the witness `Writer` and `Reader`:
version byte first, fixed-width big-endian, `u8` discriminants with 0 reserved, `Option` as a 0/1
tag, no strings, no floats, bound checked before decode, `finish()` rejects trailing bytes. An
object's `encode()` is its signature body and its hash preimage.

| Object | Domain | Maps onto |
| --- | --- | --- |
| `GameManifest` | `vhalla/game/manifest/v1` | `WorldSpec`, `ProgramSlot` roles, `WorkContract`, `RulesetId`, limits, `InnerArtifactId`s; the world digest is the `ManifestHash` of a `TaskManifest` template with seed 0 and empty events |
| `SessionOpen` | `vhalla/game/session/v1` | `SessionKey` (digest) and `SessionId` (`u128`, first 16 bytes); `RealmId`, `RoomId`, `Epoch` from `vhalla-core` |
| `GameEvent` | `vhalla/game/event/v1` | `BindReveal` feeds `ValidManifest::assign`; `Input` becomes a `CaseSpec.events` entry; each admitted event is a `vhalla_ledger::Event` whose payload is the `GameEventDigest` |
| `Checkpoint` | `vhalla/game/checkpoint/v1` | embeds `vhalla_ledger::Checkpoint { realm, epoch, head, state_root, height }` unchanged; per case `StateHash`, `TraceHead`, ledger total, `RunStatus` |
| `Settlement` | `vhalla/game/settlement/v1` | `ClaimedReceipt` (180 bytes) from `WitnessRun::into_receipt`, the final `CheckpointHash`, or `Unresolved` with reason, heads, and evidence digests |
| `InnerArtifactId` | none (opaque) | Platonik `sha256:` hex parsed to 32 bytes plus `InnerKind` (`PlatonikExperimentV1 = 1`, `PlatonikResultV1 = 2`, `PlatonikReceiptV1 = 3`, `PlatonikCheckpointV1 = 4`, `FrameTraceV1 = 5`) and protocol `HabitatV1 = 1` |
| `FrameDigest` | `vhalla/game/frame/v1` | tick, complete flag, and `encode_state(&State)` read from `vm::FrameView`; the frame's `Ledger` is deliberately excluded, because `initial_checking` charges one `Category::Checking` unit per declared event (`crates/vhalla-witness/src/vm.rs:987`, `vm.rs:997`, `vm.rs:1219`) before the tick-0 frame is emitted (`vm.rs:1231`), so a ledger-committing `FrameDigest` is a per-segment quantity and could never be prefix stable across seals; the `complete` flag stays, so a fuel stop is still witnessed per frame |
| `TraceHead` | `vhalla/game/trace/v1` | running chain over `FrameDigest`s seeded with the world digest (the template hash of the `GameManifest` row), `ProgramHash`, and case index, never with the per-segment `ManifestHash`; replaces Platonik `prefix_hash` without carrying frames |
| `ArtifactManifest`, `Block` | `vhalla/game/artifact/v1`, `vhalla/game/block/v1` | bounded transfer of one `InnerArtifactId`'s bytes |
| `GameRecord` signature | `vhalla/game/record/v1` | Ed25519 over kind byte, `SessionKey`, and the object digest; audience free |

`InnerKind` names the object whose canonical bytes an `InnerArtifactId` hashes:
`PlatonikExperimentV1 = 1` hashes the `Experiment`, `PlatonikResultV1 = 2` the `RunResult`,
`PlatonikReceiptV1 = 3` the whole `Receipt` (Platonik's `artifact_hash(&receipt)`, a third value
distinct from the `experiment_hash` and `result_hash` fields the receipt itself carries),
`PlatonikCheckpointV1 = 4` the habitat checkpoint object, `FrameTraceV1 = 5` the adapter's frame
trace. The hashed bytes are always Platonik's compact canonical encoding (`serde_json::to_vec`, no
pretty printing, no trailing newline); the `platonik` CLI writes receipts pretty printed with a
trailing newline and habitat exports append a newline, so a publisher re-serializes compactly before
computing an id or shipping bytes. That is a publisher-side precondition, never a receiver check.

Two different hashes carry the Platonik name `ManifestHash`. This plan writes "world digest" for the
template hash of the `GameManifest` row (seed 0, empty events) and "`SegmentManifest` hash" for the
per-segment hash the receiver recomputes at replay; a bare `ManifestHash` never stands alone in the
session or receiver sections.

Field sets, fixed here so vectors can be written:

- `RulesetId`: codec version 1, `LANGUAGE_FINITE_RULE_V1`, protocol 1 (`platonik-habitat-v1`).
- `GameManifest`: ruleset, world digest, slots (at most `MAX_CELLS = 16`, `Fixed` or `Open` with an
  optional fallback `ProgramHash`), contract, case count `1..=8`, per-case `loading_work`, at most
  four `InnerArtifactId`s each tagged by its `InnerKind`, `SessionLimits`, publisher key (full 32
  bytes). Any artifact the session expects to move carries its own id of the matching kind, so a
  session that moves whole receipts needs a `PlatonikReceiptV1` id the publisher computed as
  `artifact_hash(&receipt)`; without it the stage 4 `ArtifactAssembly` check on a fetched receipt
  has nothing to compare against on the default path.
- `SessionLimits`: `max_events <= 1024`, `max_segments <= 8`, replay `WorkAllowance`,
  `VerificationAllowance { max_replays, max_work, max_event_bytes, max_artifact_bytes <= 8 MiB }`,
  `MissingMember::{Pause, Fill}`, `SessionKind::{Replay, Live}`. `max_events` is a session ceiling
  above, never a substitute for, the per-case cap of `MAX_EVENTS = 64` admitted `Input`s that
  `Case::new` enforces (`crates/vhalla-witness/src/world.rs:514`); with case count `1..=8` the
  per-case caps alone can never exceed 512, so the session ceiling is deliberate headroom and the
  live `loading_work` rule keeps charging `max_events` rather than `64 × case count`.
  `max_artifact_bytes` is charged as peak retained bytes, not as a cumulative session total: an
  artifact is assembled, checked against its `InnerArtifactId`, consumed, and dropped, and the
  bounded-artifacts section caps concurrent assemblies per session at 1, so 8 MiB bounds the largest
  single artifact and the one assembly in flight. `max_segments` counts seals across
  every epoch of one session, so a `Replace` never buys extra segments. The 8 is a deliberate reuse
  of Platonik's `MAX_ADVANCES = 8`, not an inherited bound: Platonik's eight advances are per
  experiment with `until <= experiment.ticks`, while a segment here seals every case of a multi-case
  session at one session-wide `through_tick`.
- `SessionOpen`: realm, room, manifest hash, ruleset, seed commitment, `Authority::Host { key }`
  (`Quorum` is discriminant 2, decode-only until the feature), players (at most 16, sorted by key,
  disjoint slots covering every `Open` slot, host key excluded), epoch 0, 32-byte nonce.
- `GameEvent`: session key, epoch, author key, per-author `Sequence` from 1, `parents` (at most 4
  sorted unique digests; informational under `Host`, binding under `Quorum`), body: `BindCommit {
  slot, commit }`, `BindReveal { slot, program, salt }`, `BindClose { commits }` (host signed, the
  sorted `(slot, digest)` set, at most `MAX_CELLS` entries), `Reveal { task, host_salt }`, `Input {
  case, tick, kind }`, `Seal { segment, through_tick, order, checkpoint }`, `Replace { slot, old,
  new }`, `Fill { slot, program_hash, evidence }`. There is no `Settle` body: a settlement travels
  only as its own `GameRecord`, for the reason **Missing members, failed exchange, settlement**
  gives. `Seal.order` is a list of 32-byte `GameEventDigest`s, at most `MAX_SEAL_ORDER = 512` of
  them, and `Seal.checkpoint` is the 32-byte `CheckpointHash` of the checkpoint the seal commits,
  never an embedded `Checkpoint`: a `Checkpoint` already travels as its own `GameRecord` under its
  own domain, and the same `CheckpointHash` is the ledger payload of the `Seal` event.
  `MAX_GAME_EVENT_BYTES = 24_576` is derived from the widest variant, which is `Seal` and not
  `BindReveal`: 512 × 32 = 16_384 bytes of `order`, plus the 32-byte `CheckpointHash`, plus
  `segment` and `through_tick`, plus the common header (session key, epoch, author key, sequence, at
  most four parent digests, version byte, discriminants, and length prefixes), about 16.3 KiB,
  leaving roughly 8 KiB of margin. Dropping the former `Settle` body does not move that bound and it
  is not re-derived here: `Seal` was already the widest variant, and a `Settlement` is separately
  bounded at 1024 bytes on its own record. `MAX_SEAL_ORDER` is tied to the 512-unsealed-per-session
  pending cap and never to `max_events <= 1024`: at 1024 the `order` field alone would be 32_768
  bytes and the variant would exceed `MAX_GAME_EVENT_BYTES`, so neither cap moves without
  re-deriving the other. `BindReveal` is the widest player-signed variant, carrying a
  `finite-rule-v1` program bounded by `MAX_PROGRAM_BYTES = 1059`
  (`crates/vhalla-witness/src/codec.rs:43`), about 1.2 KiB with its slot, 32-byte salt, and header.
  Two bind events per `Open` slot fit inside `max_events <= 1024` against `MAX_CELLS = 16` and
  inside the 512-per-session and 16-per-author pending caps. `Fill.evidence` commits to the host's
  pending-claim state for the slot, that is the slot's last admitted `(author, sequence)` and the
  seal or segment at which the slot was still unbound, so a censoring fill is a signed
  self-incriminating object rather than a silent omission.
- `Checkpoint` (at most 1024 bytes): session key, embedded ledger checkpoint, parent, segment,
  `SegmentManifest` hash (a checkpoint field only, never a trace input), `ProgramHash`,
  `through_tick`, per-case `{ state, trace, ledger_total, status }` at that case's checkpoint read
  tick (defined under **Checkpoints**, and not the same as the effective tick admission uses),
  `WorkSummary { useful, total }`. `ledger_total` is the value the producing segment's replay
  reached, not a session invariant; **Checkpoints** and **Pause, replace, resume** state how it is
  checked across segments.
- `Settlement` (at most 1024 bytes): `Result { session, epoch, final checkpoint, ClaimedReceipt
  bound to challenge_id = SessionKey and subject_key = host key, passed }` or `Unresolved { session,
  epoch, ForkReason, at most 4 heads, at most 8 evidence digests }` with `ForkReason::{
  CompetingSeals, Equivocation, RevealMissing, MemberMissing, BudgetExhausted, ReplayMismatch,
  HostSilent, Cancelled}`.

Platonik mapping rules: the revealed `TaskManifest` carries world, merged fixed slots, cases with
seeds, ticks, fuel, activation fuel, `loading_work`, and empty events; `Assignment` comes only from
`ValidManifest::assign` over admitted `BindReveal`s in slot order; `Case.events` is the ordered
replay input, filled from admitted `Input`s in seal order (admission order, not tick order; the
64-event per-case cap and the tick horizon are both admission checks, and `World::new` and
`Case::new` re-check them defensively at `SegmentManifest` construction, `MAX_EVENTS = 64` at
`crates/vhalla-witness/src/world.rs:514` and the `MIN_TICKS..=spec.ticks` range and target existence
beside it); every case's declared `fuel` must leave headroom for the frame-0 `Category::Checking`
charge computed at the full 64-event cap rather than at the count the current segment declares,
which is checked at `Reveal` the way the fixed live `loading_work` rule is. That reveal check is the
tick-0 base case and nothing more: it makes frame 0 itself complete at the full cap, and it cannot
hold a later fuel stop in place, because `Meter::charge` computes `fuel_room` against the cumulative
whole-case `Ledger::total()` (`crates/vhalla-witness/src/ledger.rs:179`-`181`) rather than against a
per-tick budget, so n extra frame-0 units lower the room at every later charge. The per-seal slack
rule under **Checkpoints** is what keeps the replayed prefix stable. `StateHash` at the case's
checkpoint read tick, defined under **Checkpoints**, is checkpoint identity;
`WitnessRun::into_receipt` is the checked-result evidence; inner ids are never recomputed on the
default path because their serializer and domain differ. Rejected: re-deriving Platonik JSON hashes
in the receiver; one digest domain for all game objects; frames inside checkpoints.

### Signed carrier

`vhalla_crypto::SignedEnvelope` binds an `audience` `PeerId`, an `epoch`, a `session`, and a
clock-bound `expires_at`; it authenticates delivery to one owner. A game object must verify
identically at every receiver, so game objects travel as `GameRecord { kind, body, signer,
signature }`: the signature is Ed25519 over the `vhalla/game/record/v1` transcript, keys pass
`vhalla-crypto`'s weak-key check, and the same `ed25519-dalek` version is reached through
`vhalla-crypto`. Room delivery may wrap records in transport envelopes per receiver; that is
delivery, never authority. Duplicate detection is by content digest and by `(author, sequence)`
claims, so no `ReplayWindow` is needed. Rejected: `SignedEnvelope` as the object signature
(per-receiver, clock-bound); `SignedClaim` (256-byte cap, protocol-owned domains);
`vhalla_social::SignedRecord` (social vocabulary). Export of a `VerifiedSettlement` as a
`SignedClaim { ClaimDomain::Receipt, SubjectDigest = SettlementHash }` for the per-realm DAG is
stage 5.

### Session semantics

**Authority (games plan fork 4).** `Authority::Host { key }`. The host's signed `Seal` events
define the total order; `vhalla-ledger` (linear, single tip, per-actor monotone `Sequence`) is the
exact fit for a host-ordered log. The host has ordering and inclusion authority only: it cannot
forge state (every receiver replays), forge an input (inputs are player signed), rewrite history
(seals chain through ledger heads and checkpoint parents), or drop a player silently (absence is
an explicit `Unresolved` or `Fill` with evidence). The host is not a player in v1. Records are
portable content-addressed signed objects, so a later consensus layer orders the same bytes.
Rejected: quorum first (no promoted threshold certificate exists); optimistic peer state with
dispute replay (needs a DAG merge rule `vhalla-ledger` cannot express and a dispute forum that
does not exist); relays as tie-breakers.

**Opening and seeds.** Anyone holding a `GameRecord(GameManifest)` from a publisher local policy
trusts may open; the host signs `SessionOpen`. `Replay` sessions (corpus parity) use the seeds in
the revealed manifest. `Live` sessions derive them from a two-phase bind, so no party can choose a
seed. A player first signs `BindCommit { slot, commit }` where `commit =
digest("vhalla/game/bindcommit/v1", session_key ‖ slot ‖ program_hash ‖ salt)` over a 32-byte salt;
committing the program beside the salt costs nothing here and closes the matching last-mover program
advantage a plaintext bind leaves open, which is the games plan's "commitments bind a hidden
program, move, or bid before reveal". The host then signs exactly one `BindClose { commits }`
carrying the sorted `(slot, digest)` set. No `BindReveal { slot, program, salt }` is admissible
before `BindClose` and no `BindCommit` after it, and a `BindReveal` whose recomputed digest is not
in the closed set is refused. A pre-`Reveal` seal would close the set the same way but is not
expressible (a `Checkpoint` carries per-case values derived from replay, and there is no
`TaskManifest`, no cases, and no `Running(k)` before `Reveal`) and would spend one of
`max_segments`, so the host-signed close carries this instead. `digest(BindClose)` rides in
`Reveal`, and `BindClose` is itself an admitted event appended in `Seal.order`, so the closed set is
inside `state_root` from the first seal onward and the host cannot retroactively swap or append a
commit.

The host's `seed_commitment` is `digest("vhalla/game/hostsalt/v1", host_salt ‖ world digest)`, a
domain of its own because the derivation preimage has a different structure, and at `Reveal` each
`cases[i].seed` must equal the first eight bytes of `digest("vhalla/game/seed/v1", host_salt ‖ slot
salts in slot order ‖ i)`. Slot order runs over the manifest's slots in slot order, one per world
cell and so `MIN_CELLS..=MAX_CELLS` of them (`ValidManifest::validate` refuses any manifest whose
named slot ids are not exactly the world's cell ids,
`crates/vhalla-witness/src/manifest.rs:98`-`104`): a `Fixed`
slot contributes nothing, a revealed slot contributes its 32-byte salt, a filled slot
contributes the fixed value `digest("vhalla/game/fillsalt/v1", fallback ProgramHash ‖ slot)`, and
absent cells contribute nothing and are never padded out to `MAX_CELLS`, so the
preimage length is fixed by the manifest's slot roles (32 bytes per non-`Fixed` slot) and never by
which `Open` slots were revealed rather than filled, which is what makes the vectors writable. For
seed purposes `Fill` is admissible only for a slot that has no commit at `BindClose`, which forces
the host to choose fill before any salt is revealed, so fill versus bind is no longer a lever
against a known seed; `Fill` for mid-session member absence under `MissingMember::Fill` is
unaffected. No party, including the host, knows a seed before every `Open` slot is revealed or
filled. The residual is an abort: after `BindClose` a withholding player or a cancelling or silent
host can force a fresh open, which is a restart bias and never a re-choice. Such an abort is
recorded with the existing vocabulary, `Unresolved { Cancelled }` for a signed cancel and
`Unresolved { RevealMissing }` or `Unresolved { HostSilent }` for silence, carrying
`digest(BindClose)` and the retained commit digests as evidence so local policy can count aborts per
host key; no new `ForkReason` variant is added. States: `Opened`, `Binding`, `Revealed`,
`Running(k)`, `Finished`, `Unresolved`; transitions come only from admitted events; deadlines are
the host's signed decisions, and receivers apply step budgets outside the crate.

**Admission (Gate 5 shape).** Bounded decode, signature and session binding, `(author, sequence)`
claim table, pending buffer (at most 512 unsealed per session, 16 per author), then on `Seal` the
ledger append in `Seal.order`. `BindCommit`, `BindReveal`, and `Input` only from players for their
own slots and cases; `BindClose`, `Reveal`, `Seal`, `Replace`, and `Fill` only from the host, and
`BindClose` at most once. A `Settlement` is not a `GameEvent` and so never enters the claim table,
the pending buffer, or a `Seal.order`; it is admissible only as a `GameRecord` signed by the host
key `SessionOpen` names, under the settlement rules below. Per-author sequence strictly increases;
an identical resend is `Duplicate` and changes nothing; a different digest at the same `(author,
sequence)` is `Equivocation`: both digests retained, the author frozen from that sequence, any seal
admitting either refused. A `Seal` that admits `Fill { slot }` is refused when the receiver holds a
valid, session-bound `BindCommit` or `BindReveal` for that slot from the player `SessionOpen` lists
for it: both records are retained and the session goes `Unresolved { MemberMissing }` with the bind
digest as evidence, and a receiver that sees such a bind only after accepting the fill moves the
session to `Unresolved { MemberMissing }` rather than keeping the derived seed. This is the
retained-evidence pattern the `Equivocation` rule already uses, so it costs "verify identically at
every receiver" nothing more than that rule does, and it needs no host-signed marker or extra round
trip before a `Fill`. `Seal.order` must respect each author's `Sequence` or the seal is refused
before the first append, and a seal whose order would take any case past `MAX_EVENTS = 64`
cumulative admitted `Input`s is refused before the first append too. That tally is counted across
every segment and every epoch of the session, because the receiver replays from genesis and a
`Replace` bumps the epoch without removing the events already in `Case.events`; resetting it at a
segment boundary or at a `Replace` would rebuild the same unreplayable `SegmentManifest`. The
refused seal is retained as evidence and the refusal is an admission rejection, `CaseEventLimit`, in
the same family as `Duplicate` and `StaleTick`, so it is deterministic and identical at every
receiver; if the host never seals an order that fits, the session ends `Unresolved { HostSilent }`
by local policy. The cap is enforced where `Seal.order` is validated and never over the
arrival-ordered pending buffer, so which `Input` survives is never a function of arrival order; the
gate rule is the seal-derived form of the same check, that is an `Input` for a case whose sealed
tally already equals 64 is refused exactly as an input for a fuel-exhausted case is. Staleness is
per case: an `Input` whose `tick` is at or below its case's last sealed effective tick is
`StaleTick`, so a case that has already reached its own `ticks` accepts no further inputs at all; an
`Input` whose `tick > case.ticks` is refused at the gate, matching the `MIN_TICKS..=spec.ticks`
range `Case::new` enforces per event, so an out-of-horizon input fails at admission rather than at
`SegmentManifest` construction; a fuel-exhausted case accepts no further inputs; and a still-running
case whose fuel slack at its checkpoint read tick has fallen below the inputs it could still admit
accepts no further inputs either, refused as `CaseFuelSlack` under the rule **Checkpoints** states.
Exactly one `Reveal`, after every `Open` slot is revealed or filled, checked against the commitment,
`digest(BindClose)`, world digest, slots, contract, and the loading rule: `Replay` sessions carry
the JSON byte length the oracle computed and reproduce Platonik's charge bit for bit; `Live`
sessions have no Platonik counterpart and use the fixed rule `loading_work = template_len +
max_events × INPUT_ENCODED_BYTES`, so no admissible input set can fail `ManifestError::LoadingWork`
(recorded as a deviation for the live path).

**Ledger binding, no circularity.** Segment k's admitted events are appended in `Seal.order`; the
tip after the last is `T_k`. `Checkpoint(k).ledger` is `{ realm, epoch, head: T_k, state_root:
root(T_k), height(T_k) }`, derived by the receiver and passed through `accept_checkpoint` (current
tip, root re-derivation, matching height, strictly greater height than before). Only then is the
`Seal` event appended, payload `CheckpointHash(k)`, host actor and sequence: it is the first event
of segment k+1, so `state_root(k+1)` commits to `CheckpointHash(k)` and the parent link is inside
the root. An epoch's terminal `Seal` is never appended to that epoch's ledger. The seal that carries
a `Replace` becomes the genesis event of the `epoch + 1` ledger with payload `CheckpointHash(k)`,
and the session's last seal has no segment k+1 to open, so `Checkpoint(final).head` is the last
event of that seal's `order`. A k-segment epoch therefore holds `k - 1` `Seal` events, which is the
number the settlement height check under **Missing members, failed exchange, settlement** counts.

The ledger actor is `vhalla_crypto::peer_id_from_key(author)`, a 128-bit truncation of SHA-256 over
the key (`crates/vhalla-crypto/src/lib.rs:379`-`386`) that `vhalla-crypto` itself disclaims as a
policy identity. The full 32-byte key is in the record and is what every authority check, the claim
table, and the `Seal.order` sequence check run on, so the `PeerId` is a routing handle and never an
identity. Admission keeps the two namespaces in bijection rather than assuming it: a `SessionOpen`
whose host key and player keys are not pairwise distinct under `peer_id_from_key` is refused, and a
`Replace { slot, old, new }` whose `new` key is not distinct under `peer_id_from_key` from the host
key and from every other current slot key in the epoch the bump opens is refused too, which the
opening check alone cannot cover because a replacement key never appeared in `SessionOpen`. The
rejection is `ActorAliasing`, in the same family as `Duplicate` and `CaseEventLimit` and so
deterministic and identical at every receiver. Without it two keys colliding in 128 bits would share
one `Ledger::last_sequences` counter (`crates/vhalla-ledger/src/lib.rs:146`) and one
`NonMonotonicSequence` decision while the game layer still read them as two authors. The session's
genesis event carries the `SessionKey`.

Applying a seal's order is all-or-nothing. `vhalla-ledger` exposes no rollback and `append` mutates
`head` and `last_sequences` on success (`crates/vhalla-ledger/src/lib.rs:200`-`202`), so the
receiver takes `Ledger::snapshot` before the first append and `Ledger::restore(raw, max_events)` on
any `append` error, refuses the seal as `SealApplyFailed` in the same rejection family, and retains
it as evidence; that is what makes "every rejected input leaves state bit-identical" hold for seals
as well as for inputs. Each per-epoch `Ledger::new` is constructed with `1 + max_events +
max_segments`, that is 1033 at the stated ceilings, and `restore` is passed the same bound: genesis,
every event an epoch's `Seal.order`s can append, and one per `Seal` event. `Ledger::new` silently
clamps to `vhalla_ledger::MAX_EVENTS = 4096` (`crates/vhalla-ledger/src/lib.rs:25`, `lib.rs:156`),
so an undersized argument would surface as a mid-order `Error::Capacity`
(`crates/vhalla-ledger/src/lib.rs:197`-`199`) rather than at construction; at 1033 `Capacity` is
unreachable for any admissible session. `Seal` events sit outside the session's `max_events <= 1024`
ceiling, which counts the admitted `GameEvent`s the host seals, and the `+ max_segments` term is
what carries them.

**Checkpoints.** One per seal; `through_tick` is session-wide and strictly increasing. Two per-case
ticks are named and they are not the same. The *effective tick* `min(through_tick, case.ticks)` is
the admission threshold: staleness, the per-case input caps, and the seal-derived gate rule are all
measured against it, and it is unchanged by this section. The *checkpoint read tick* `T =
min(through_tick, last_frame_tick)` is the tick every checkpoint field is read at, where
`last_frame_tick` is the highest tick the case's replay emitted a `vm::FrameView` for and is
therefore never above `case.ticks`, which is why `T` needs no third term. The two differ exactly for
a case whose run ended before `through_tick`: a case with `case.ticks = 50` that fuel-exhausted at
tick 12 has no frame at a later seal's `through_tick = 20`, so its `StateHash`, `ledger_total`, and
`status` are read at tick 12 and its `TraceHead` chains the `FrameDigest`s of the frames the replay
actually emitted through `T`, which names the chain's stopping point rather than leaving it
inferred. A case whose `status` at `T` is terminal, that is `FuelExhausted`, or that has reached its
`ticks`, repeats its final `StateHash`, `TraceHead`, `ledger_total`, and `status` unchanged in every
later checkpoint, because such a case accepts no further `Input` and so gains no further frame-0
charge; for it the offset equality under **Pause, replace, resume** degenerates to plain equality
with n equal to zero, and its `status` at the next seal must be equal rather than merely
non-decreasing. A `Seal` whose `through_tick` exceeds `max(case.ticks)` is refused and the final
seal's `through_tick` equals `max(case.ticks)`; that final `through_tick` gives a fuel-exhausted
case no frame there either, so the final checkpoint a `Settlement::Result` names carries that case's
values at its own `T` and the settlement receipt comparison inherits no ambiguity. At most
`max_segments` seals across every epoch of the session. Case values come from replay only.

Prefix stability of a still-running case is bought by a per-seal slack rule, never by the
reveal-time fuel headroom check. Define that case's slack at seal k as `slack_k = case.fuel -
Checkpoint(k).ledger_total` read at its `T`, and its remaining admissible inputs as `remaining_k =
MAX_EVENTS - n_k`, where `n_k` is the count of `Input`s declared for it in `SegmentManifest(k)`.
Every receiver already holds `fuel` from the revealed `TaskManifest`, `ledger_total` from the
accepted checkpoint, and `n_k` by differencing manifests, so the rule is receiver-derivable and
needs no new wire field. When `slack_k < remaining_k` that case accepts no further `Input`, refused
at the gate as `CaseFuelSlack`, an admission rejection in the same family as `Duplicate`,
`StaleTick`, and `CaseEventLimit` and so deterministic and identical at every receiver. Closing
inputs rather than refusing the seal preserves liveness: the seal is still accepted and the case
keeps running. The rule is exactly what the prefix needs. A still-running case is one whose replay
reached `through_tick`, so its two ticks coincide and `T` is also the staleness threshold. The meter
is cumulative and monotone, so that case's slack is smallest at `T`; every `Input` admitted after
seal k carries `tick > T` by the staleness rule and so adds work inside frames `0..=T` only through
its single frame-0 `Category::Checking` unit; and at most `remaining_k` such units can ever be
added. No admissible input set can therefore move a case's fuel stop to a tick at or below `T`,
which is what makes `StateHash`, `TraceHead`, and `status` on frames `0..=T` stable across seals.

A still-running case's `ledger_total` is not invariant across segments: `initial_checking` charges
one `Category::Checking` unit per declared event at frame 0 (`crates/vhalla-witness/src/vm.rs:987`,
`vm.rs:997`, `vm.rs:1219`), so every `Input` admitted since the last seal raises the value every
frame from tick 0 onward carries. A checkpoint's `ledger_total` is therefore read against the
segment that produced it, and the cross-segment check is the exact offset equality stated under
**Pause, replace, resume**, never a bare prefix equality; the slack rule is also what makes that
offset exact rather than hoped for, since it is the condition under which all n new frame-0 units
are actually charged before `T` instead of the run stopping early. The embedded struct is the realm
checkpoint: a realm finality layer (promoted `checkpoint-proof` or a rooms-consensus certificate)
signs `{ realm, epoch, head, state_root, height }` unchanged and so certifies the game state without
a second format. Two host-signed seals for one segment with different order or checkpoint are
`CompetingSeals`: both retained, neither applied, session `Unresolved`. History is never rewritten
in place.

**Pause, replace, resume (P4 exit condition).** A pause is a seal; a resume is the next seal; there
is no state injection. The receiver replays from genesis with `SegmentManifest(k+1)` and requires
frames `0..=T` to reproduce `Checkpoint(k)`'s per-case `StateHash`, `TraceHead`, and `status`
exactly, where `T` is that case's checkpoint read tick at seal k and both sides are evaluated at it,
and requires that case's `ledger_total` at `T` to equal `Checkpoint(k).ledger_total + n`,
where `n` is the number of `Input`s admitted for that case between seal k and seal k+1, a value the
receiver derives by differencing the two `SegmentManifest`s it already holds; only then is
`Checkpoint(k+1)` accepted. The offset is an exact equality rather than a relaxation, so a reset or
a reduced ledger is still refused, and it exists because `initial_checking` charges one
`Category::Checking` unit per declared event at frame 0 (`crates/vhalla-witness/src/vm.rs:987`,
`vm.rs:997`, `vm.rs:1219`), which makes `ledger_total` a per-segment quantity while `StateHash` and
`TraceHead` are not. Those two are prefix stable because of the per-seal slack rule under
**Checkpoints**, never because of the reveal-time fuel headroom check: that check bounds only the
frame-0 charge, while a case's fuel stop is a function of the cumulative whole-case total
(`crates/vhalla-witness/src/ledger.rs:179`-`181`), so without the slack rule a fuel-tight case could
flip `Complete` to `FuelExhausted` at an earlier tick once more inputs were declared and diverge the
state prefix as well. For a terminal case n is zero, the offset equality is plain equality, and its
`status` must be equal rather than merely non-decreasing. Replay at 5.3 ms native worst case is
cheaper than a state decoder and keeps `vm::State` constructors private. Fuel never resets because
the ledger is cumulative; `ledger_total` is monotone across checkpoints, and `status` only advances
along the partial order `Complete -> ActivationLimit -> FuelExhausted`, with `Complete ->
FuelExhausted` also permitted directly, never reversing and never leaving the terminal
`FuelExhausted`: `crates/vhalla-witness/src/vm.rs:1142` sets `ActivationLimit` and lets the tick
loop continue, `vm.rs:1225`-`1228` sets `FuelExhausted` when loading itself exhausts fuel with no
activation window ever hit, and `vm.rs:1263` overwrites any earlier status with `FuelExhausted` and
breaks. A case observed as `ActivationLimit` at seal k's read tick may therefore legitimately be
`FuelExhausted` at a strictly later seal's read tick, and a receiver must accept that edge rather
than read it as a forged resume; a `Complete` case may likewise reach `ActivationLimit` or
`FuelExhausted` at a later tick, but never at a tick already inside a sealed prefix, which is what
the slack rule forbids; for a case already at its `ticks` the status must be equal, which is the
"repeats its final ... `status` unchanged" rule above turned into a check. Platonik's own loop
agrees (`platonik-core` `sim.rs:884` sets `ActivationLimit` mid-tick, `sim.rs:918` overwrites it on
a later charge failure, and `sim.rs:692`-`707` seeds a resumed status to `ActivationLimit`), but the
authority here is `vhalla-witness`, which is the path receivers actually run. `Replace { slot, old,
new }` replaces the member, not the program: the new key inherits the slot's bound program
(`ProgramHash` unchanged), the epoch bumps, a new `vhalla_ledger::Ledger` opens for `epoch + 1`
whose genesis payload is `CheckpointHash(k)`, old-epoch events become inadmissible, and the replayed
prefix must still match. The bump rides on the existing seal and consumes no segment: the resume
seal is segment k+1 as usual and the segment index continues across the bump, so a `Replace` never
buys extra segments. The trace seed is segment-independent and epoch-independent by construction
(world digest, `ProgramHash`, case index), which is what makes the `0..=T` prefix check meaningful;
`ProgramHash` is admissible in that seed only because `Replace` leaves the slot's program unchanged,
so if spike 4's rebind half ever lands in a later version, `ProgramHash` must leave the trace seed
at that time. Program replacement mid-session needs continuation the platform lacks and is not in
v1; spike 4 measures whether a case-boundary rebind is bit-exact so a later version can add it.

**Missing members (eukaryotic decision 5), failed exchange (decision 3), settlement.**
`SessionLimits.missing_member` is `Pause` (the session rests `Unresolved { MemberMissing }` until
the host `Replace`s) or `Fill` (`Fill { slot, program_hash, evidence }`, where `program_hash` must
equal the manifest's declared fallback for that slot and `evidence` commits to the host's
pending-claim state for it, so the fill is a signed self-incriminating object; admission refuses a
seal admitting a fill for a slot the receiver holds a bind for, and a filled slot's seed
contribution is the fixed fill salt); degrading by dropping a cell changes the world and is
rejected. Contracts are receipt-based: failed exchange evidence is a `Settlement::Result { passed:
false }` whose receipt the receiver reproduced, or an `Unresolved` with retained digests.
A settlement is post-ledger evidence about the final checkpoint, never a sealed event: it travels
solely as a `GameRecord` of `Settlement` under `vhalla/game/settlement/v1`, signed by the host key
`SessionOpen` names, and the receiver admits it by reproducing the receipt itself rather than by
finding it inside `state_root`. A `Settlement` never rides inside a `GameEvent`, for the reason
`Seal.checkpoint` carries a `CheckpointHash` rather than an embedded `Checkpoint`: it commits to
`CheckpointHash(final)`, which is only derivable once the final seal's order is appended, so
sealing it would be circular, and no seal can follow the final one, whose `through_tick` already
equals `max(case.ticks)`. `Settlement::Result` is admitted only when the host signed it,
`checkpoint` is the accepted final checkpoint, the receiver's own replay produced a `WitnessReceipt`
the claimed receipt `matches`, `passed == run.passed()`, and every admitted event has been sealed,
that is the pending buffer is empty and the final checkpoint's height matches, stated in
`vhalla-ledger`'s own units. There `height` is a parent-link count, `chain(head).len() - 1`
(`crates/vhalla-ledger/src/lib.rs:436`), so an epoch's genesis event contributes zero to it and the
sum carries no genesis term. The check is `Checkpoint(final).height == Σ|order_j| + s`, where
`Σ|order_j|` runs over that epoch's segments and `s` is the number of `Seal` events appended to that
epoch's ledger at or before `Checkpoint(final).head`; under the seal placement in **Ledger binding,
no circularity** that is `Σ|order_j| + (k - 1)` for a k-segment epoch. It is read at the head the
final checkpoint names and never at a later tip, and `s` counts `Seal` events appended to that
epoch's ledger rather than seals of that epoch, because an epoch's terminal seal appends no `Seal`
event to it. That count is per epoch and has no pending-buffer term: a `Replace` opens a new ledger
at `epoch + 1`, so each pre-bump epoch is checked through its own final checkpoint. Two vectors pin
the numbers. A two-segment epoch with no `Replace`: genesis carries the `SessionKey` at height 0,
`|order_1|` events give `Checkpoint(1).height == |order_1|`, the `Seal(1)` event opens segment 2,
and `|order_2|` events give `Checkpoint(2).height == |order_1| + 1 + |order_2|`, which is the value
the `Result` for that epoch must name. A two-segment, one-`Replace` session: epoch e ends at
`Checkpoint(1).height == |order_1|`, the `Replace` opens the epoch `e + 1` ledger whose genesis is
the `CheckpointHash(1)` payload at height 0, `|order_2|` events give a `Checkpoint(2).height` of
`|order_2|`, and the `Result` naming `(realm, e + 1)` admits at exactly that number.
`Settlement::Unresolved` is admitted when the host signed it or the receiver derives it from
evidence it holds. Resolution between competing settlements ranks them by self-verifiability and
never by arrival order, because first-accepted-wins lets one host hand a cancel to one receiver and
a result to another and leave both honest receivers permanently divergent with no fork verdict on
either side. A `Result` the receiver admitted under the full test above outranks any bare
host-signed `Unresolved` for the same `(session, epoch)` in either arrival order: a verified
`Result` proves the session ran to `through_tick == max(case.ticks)` with every admitted event, so
it proves a cancel for that `(session, epoch)` was false or premature, and a cancel that arrives
later does not displace it. Two settlements of equal rank that disagree, that is two `Result`s with
different final checkpoints or different `passed`, or two bare `Unresolved`s with different reason
or heads, are host equivocation over the settlement object: both retained, neither applied, session
`Unresolved { Equivocation }`. That is the retained-evidence shape `CompetingSeals` and
`Equivocation` already use, it converges both receivers, and it adds no wire variant.
`Contradiction` is the name of the admission rejection that produces that outcome, in the same
family as `Duplicate`, `StaleTick`, and `CaseEventLimit`; it is never a `ForkReason` and never
travels on the wire. Settlement disagreement is governed by that self-verifiability ranking and
`Contradiction` alone: the `(author, sequence)` claim-table `Equivocation` rule never reaches a
settlement, because a settlement is not a `GameEvent` and carries no event sequence. A host-signed
`Unresolved { Cancelled }` is inadmissible once the receiver has accepted a final checkpoint whose
`through_tick` equals `max(case.ticks)`, and an admitted cancel ends the whole session rather than
only the `(session, epoch)` it names: nothing further is admitted, including a `Replace`, so no
later epoch can settle around it. `Cancelled` stays terminal against every further `Unresolved` and
every unverified claim, but not against a `Result` the receiver reproduced itself. Settlement is a
signed result or an explicit unresolved fork; it is not money, finality, or host authority, and
local policy alone decides what it unlocks (for example `Purpose::GameQualification`); the
resolution rule above is a convergence property of receiver verdicts, not finality.

### Receiver verification

**The one engine seam.** `GameEngine` exposes `ruleset()`, `segment_manifest(revealed, inputs)`, and
`replay(world, manifest, candidate, allowance, through_tick)` returning `SegmentEvidence { world
digest, segment manifest hash, program hash, per-case checkpoints, work summary, WitnessReceipt }`.
The `world` argument is the session's world digest, carried from `GameManifest` through the session
and used only as the `TraceHead` seed. It is explicit because a `Live` session's revealed
`SegmentManifest` does not contain the template hash (its case seeds are derived, not seed 0), so
the seed can never be silently taken from the manifest being replayed, and `SegmentEvidence` reports
it so a receiver can check which seed was used. `PlatonikV1` is the only implementation:
`ValidManifest::assign`, `ProgramHash::of(encode_assignment)`, `RunCapability::mint(..,
RunRole::Replay)` at its single fenced call site, `platform::run_observed` with a hashing
`FrameObserver`, then per case `StateHash` at the case's checkpoint read tick `T`, `TraceHead`
chained over the `FrameDigest`s of the frames actually emitted through `T`, `ledger_total` at `T`,
and `WitnessRun::into_receipt`. A case whose run ended before `T` clamps to its last emitted frame
by the definition of `T`, so no field is ever read at a tick with no frame. The same `FrameObserver`
derives each
case's `status` at `T`, because `vm::FrameView` has no status field and `WitnessRun` and
`CaseResult` expose only the whole-case `RunStatus`: the status at `T` is `FuelExhausted` if any
frame `t <= T`, including the tick-0 loading frame, has `FrameView.complete == false`; otherwise
`ActivationLimit` if any frame `t <= T` carries an `Activation` whose `error` is
`Some(ActivationError::ActivationLimit)`; otherwise `Complete`. Both latches are sticky, and at `T`
equal to the case's `ticks` this derivation reproduces the engine's own `RunStatus` exactly, which
is the property the frozen vectors pin. `run_observed` is the stage 0 change to
`vhalla-witness`: identical to `run` but taking `&mut impl vm::Observer`; `run` delegates with `&mut
()`; no codec, tag, bound, or vector changes. Rejected: calling `vm::run` from the adapter (bypasses
the capability discipline); running twice (double cost); a `State` decoder or continuation API (v1
non-goal).

**Recomputed on every accepted checkpoint:** the ledger root, the `SegmentManifest` and its hash,
`Assignment`, `ProgramHash`, every case's `StateHash`, `TraceHead`, `ledger_total`, `status`,
`WorkSummary`, and at settlement the 180-byte receipt; equality is exact. Accepted as opaque:
`InnerArtifactId`s, Platonik JSON artifacts (fetched on request, audited only under `oracle`), the
host's ordering, and quorum certificate bytes (stage 5, through the hook). Replays are memoized by
`(world digest, SegmentManifest hash, ProgramHash, through_tick)`, the world digest included because
it seeds the trace head, so a re-sent seal or checkpoint costs no work.
Outputs `VerifiedCheckpoint` and `VerifiedSettlement` have private fields, derive `Debug` only, have
no `Clone`, no decoder, and no `From` into any authority type; accessors expose digests, work,
`passed`, and epoch.

**Budgets, all charged before work.** Per segment replay: `manifest.fuel_total()` checked against
the allowance before mint, never refunded on failure. Per session: `VerificationAllowance` clamped
by the receiver's `ReceiverPolicy` (the minimum applies): `max_replays <= 64` (a full session with
prefix re-checks is 8), `max_work`, `max_event_bytes <= 1024 × 24_576`, `max_artifact_bytes <= 8
MiB`; exhaustion is `BudgetExhausted` with evidence retained and nothing applied. Per event: one
bounded decode and one signature check; events beyond `max_events` or the pending caps are dropped
without state change. Receiver-wide: `MAX_OPEN_SESSIONS`, per-host caps, and a step budget per
session in `ReceiverPolicy`; every state-changing call takes a caller-supplied monotone `step`,
a lower step is rejected, and the host of the crate maps steps to time. Clock rollback is a no-op
by construction.

### Bounded artifacts

Room frames carry only `GameRecord`s of `GameEvent`, `Checkpoint`, `Settlement`, `ArtifactRequest`,
and `ArtifactManifest`; anything larger than one frame is an artifact. `ArtifactRequest { session,
id, max_bytes <= 8 MiB, nonce }`; `ArtifactManifest { id, total_len, block_len = 65_536, at most 128
block digests, decompressed_len == total_len }` signed by the holder; `Block { manifest digest,
index, offset, bytes <= 65_536 }`. `ArtifactAssembly` is a pure state machine the transport drives:
a block is accepted only if its digest equals `blocks[index]` and `offset == index × block_len`;
duplicates are idempotent; a changed manifest for the same `id` aborts (`Restart`); the completed
bytes must SHA-256 to `id.sha256`, where the id's `InnerKind` fixes which object those bytes must be
and they must be that object's compact canonical encoding, or the whole artifact is discarded.
Comparing a receipt's bytes to the `result_hash` the receipt carries is a known non-check and never
stands in for a kind-3 id. Caps are separate: block count, retained bytes, concurrent assemblies per
session (1) and per receiver, verification work (one SHA-256 per block plus one over the whole), and
a step deadline. `SessionLimits.max_artifact_bytes <= 8 MiB` is charged as peak retained bytes
against that single concurrent assembly and not as a cumulative session total: an artifact is
assembled, checked against its `InnerArtifactId`, consumed, and dropped, so a full eight-segment,
eight-case session's 64 trace fetches are 64 sequential assemblies inside the same 8 MiB rather than
80 MB of budget, and spike 2 confirms the figure by measurement.
Granularity: one artifact per `(segment, case)` frame trace (worst case about 1.25
MB) or one per Platonik receipt (largest known 7,141,362 bytes, 109 blocks). Platonik's 32 MiB
checkpoints and 64 MiB bundles are refused, never chunked further. Browser receivers use 4 KiB
records inside a 64 KiB block; the block digest is unchanged. Rejected: traces in checkpoints;
compression in v1 (the 160:1 archive ratio is not a storage assumption); whole sessions as one
artifact.

## Threat model

| Threat | Mitigation | Test |
| --- | --- | --- |
| Tampered or rehashed checkpoint or receipt | every root, hash, and receipt recomputed; `matches` bit-exact; signatures over canonical bytes | `adversarial::mutate_every_field` |
| Duplicate event or resend | claim table plus content digest; identical digest is a no-op; memoized replays | `session::duplicate_is_idempotent` |
| Equivocation, same `(author, sequence)` | both retained; author frozen; seal admitting either refused; `Unresolved { Equivocation }` | `session::equivocation_freezes_author` |
| Two author keys aliasing to one ledger actor, sharing a `Sequence` counter | `peer_id_from_key` is a 128-bit routing handle, never the policy identity; `SessionOpen` and `Replace` are refused as `ActorAliasing` unless every host and slot key is pairwise distinct under it, so the claim table and `Ledger::last_sequences` stay in bijection | `session::actor_aliasing_rejected`, `session::replace_actor_aliasing_rejected` |
| A seal whose order half applies and leaves the ledger mutated | `Seal.order` application is all-or-nothing over `Ledger::snapshot` and `restore`; a failed `append` is `SealApplyFailed` with the seal retained; the per-epoch `Ledger::new` bound of `1 + max_events + max_segments` makes `Error::Capacity` unreachable | `checkpoint::seal_apply_is_atomic`, `checkpoint::ledger_capacity_unreachable` |
| Wrong ruleset, case, or world | `RulesetId` in every object; `Reveal` checked against commitment, world digest, slots, contract; `Case::new` validates targets | `checkpoint::wrong_ruleset_rejected`, `wrong_case_rejected` |
| Replay across sessions or epochs | `SessionKey` and epoch in every object; ledger realm and epoch `WrongContext`; receipt bound to `SessionKey` | `session::cross_session_replay_rejected` |
| Pause or resume forgery (fake state, reset fuel, foreign checkpoint) | replay from genesis re-derives state, trace, totals, and status; the `0..=T` prefix at that case's checkpoint read tick must reproduce `StateHash`, `TraceHead`, and `status` exactly and `ledger_total` must satisfy the offset equality (`Checkpoint(k).ledger_total` plus that case's admitted-input count), so a reset or reduced ledger is still refused while an honest host's newly admitted inputs are not read as forgery; the per-seal slack rule closes a case's inputs once `slack_k < remaining_k`, so no admissible input set can move a fuel stop into a sealed prefix and turn an honest resume into `ReplayMismatch`; a terminal case repeats all four fields exactly; `status` advances only along `Complete -> ActivationLimit -> FuelExhausted`; parent and head must match | `checkpoint::resume_requires_prefix_match`, `fuel_never_resets`, `checkpoint::ledger_offset_exact`, `checkpoint::status_monotone_across_seals`, `session::case_fuel_slack_closes_inputs`, `checkpoint::terminal_case_fields_frozen` |
| Host lies about state or result | receivers replay; mismatch is `Unresolved { ReplayMismatch }` with the signed seal as evidence | `receiver::host_forged_checkpoint` |
| Host censors or reorders players | explicit authority; player-signed events are portable evidence; missing members are `Unresolved` or `Fill`; a seal admitting a `Fill` for a slot the receiver holds a bind for is refused and the session goes `Unresolved { MemberMissing }`; `Fill` carries pending-claim evidence | `settlement::censorship_is_visible`, `session::fill_over_held_bind_is_unresolved` |
| Host equivocates (two seals) | `CompetingSeals`; both retained; session `Unresolved` | `checkpoint::competing_seals` |
| Host or player learns the seed early | live seeds derived from every player's committed-then-revealed salt plus a committed host salt, with the commit set closed by a host-signed `BindClose` before any reveal and a fixed salt for a filled slot, so no party can choose or re-roll a seed; residual, all recorded as limitations: after `BindClose` a withholding player or a cancelling or silent host can abort and force a fresh open (a restart bias, never a re-choice), the host can leak a revealed seed after `Reveal`, and a receiver that never saw a player's bind can accept a `Fill` for that slot | `session::seed_needs_every_salt`, `session::commit_before_reveal` |
| Relay reorders, delays, drops, duplicates | order comes from `Seal`, not arrival; bounded pending buffer; idempotent resend; relays hold no keys | proptest schedule |
| Stale tick after a seal | `StaleTick` | `session::stale_tick` |
| Inputs past the per-case 64 cap, bricking replay for every receiver | a seal whose order would take any case past `MAX_EVENTS = 64` cumulative admitted `Input`s is refused before the first append, counted across every segment and epoch; the gate refuses an `Input` for a case whose sealed tally is already 64, so the failure is an admission rejection rather than a `SegmentManifest` construction error | `session::case_event_limit` |
| Host hands a cancel to one receiver and a result to another | settlement resolution ranks by self-verifiability, not arrival: a reproduced `Result` outranks a bare `Unresolved`, and equal-rank disagreement is `Unresolved { Equivocation }` with both objects retained | `settlement::order_independent_resolution` |
| Oversized input, trailing bytes, bad discriminant | bound-first decoders, `finish()` | stable corpus-seeded fuzz harnesses on every decoder |
| Verifier exhaustion | pre-charged replays, allowance ∩ policy, pending caps, artifact caps per resource, no compression, step budgets | `receiver::budget_exhausted_retains_evidence` |
| Evidence promoted to authority | private, non-`Clone`, decoder-less verified types; no `From`; `compile_fail` doctests | verification list |
| Expiry, cancellation, revocation | step budgets prune stale sessions; `Cancelled` ends the whole session and is terminal against every further `Unresolved` but not against a `Result` the receiver reproduced itself, and is inadmissible once a final checkpoint at `max(case.ticks)` is accepted; epoch bump revokes old-epoch events; realm epoch change ends admission | proptest schedule |
| Clock rollback or partition | no clock; epochs and heights order state; partition yields `Unresolved`, never authority transfer | proptest schedule |
| Oracle divergence when the pin moves | `oracle` parity over 28 vectors and six fixtures fails the build; rerun parity before regenerating vectors | CI |

Tests are not a security audit; the README says so. Not mitigated: host liveness (a silent host is
`HostSilent` by local policy), Sybil players, and any claim about physical energy, agency, or worth.

## Discovery spikes

| # | Question | Method | Pass | Decides |
| --- | --- | --- | --- | --- |
| 1 | Does per-frame hashing keep replay within budget? | `prototypes/game-trace-cost`: `run_observed` with a hashing observer over the 28 vectors and the 64 KiB worst case, native and wasm32 | native p95 ≤ 100 ms, wasm ≤ 500 ms, peak heap ≤ 32 MiB | hash every frame (proposal) versus hash only at seal ticks (fallback) |
| 2 | Do 64 KiB blocks, 128 blocks, and per-`(segment, case)` granularity fit real sizes, and do the largest `GameManifest` and `SessionOpen` fit one frame? | measure Platonik receipts for six worlds and eight controls and adapter traces; drive `ArtifactAssembly` natively and through `browser-records` with 4 KiB records; encode the widest manifest and opening against `MAX_SIGNED_BODY_BYTES` | every artifact ≤ 8 MiB; a full eight-segment, eight-case session's fetches fit the session budget under the peak-retention accounting; assembly memory ≤ 1.25 × artifact; browser path completes a 1.25 MB trace; manifest and opening fit with ≥ 8 KiB margin | block size, granularity, record size; whether the manifest becomes the first non-trace artifact |
| 3 | Does the live `loading_work` rule keep every admissible input set valid, does the per-seal slack rule hold the sealed prefix, and does `Replay`-kind parity hold? | property test over random revealed manifests and admitted input sets; a generator that drives a case to `slack_k < remaining_k` so `CaseFuelSlack` is actually exercised; oracle parity over the corpus | zero `LoadingWork` refusals; zero fuel-headroom refusals at `Reveal`; under the slack rule no admissible input set moves any case's fuel stop to a tick at or below that case's checkpoint read tick, which is the property the slack rule enforces and not a property of the reveal check; the slack rejection fires only after inputs are closed and never refuses a seal; 100 % cost parity for `Replay` sessions | the exact `INPUT_ENCODED_BYTES` constant, the fuel headroom the reveal check requires at the 64-event cap, and how often the slack rule closes a case early on real corpus fuel budgets |
| 4 | Do pause, member replacement, and resume reproduce identical outcomes across an epoch bump, and is a case-boundary program rebind bit-exact? | proptest over corpus sessions with random seal ticks and one `Replace`, including sessions that admit further `Input`s for a still-running case between seals, one fuel-tight case, one case that fuel-exhausts strictly before a later seal's `through_tick`, and one that exhausts during loading; separately partition each corpus manifest's cases into 1..8 epochs and compare every `CaseResult` to the full run | every intermediate checkpoint's `0..=T` prefix at that case's checkpoint read tick reproduces `StateHash`, `TraceHead`, and `status` with `ledger_total` equal to the offset, checked at the checkpoints and not only on final values; every terminal case's four checkpoint fields are byte-identical in every subsequent checkpoint; the two-segment and two-segment-one-`Replace` ledger height vectors hold; final state hashes, trace heads, and receipt identical on native and wasm32; zero divergence over 28 vectors plus 400 random | epoch semantics and the P4 claim; whether a later version may add program rebind at case boundaries |
| 5 | Does `Seal.order` survive a lossy relay and a partition without unbounded buffering, and is every host fork detected once both seals are seen? | state-machine test with loss, reorder, duplication, partition and reconnect, a lying host, a host that aborts between `BindClose` and `Reveal`, a host that seals a 65th `Input` for one case (one shape accumulating across segments, one across a `Replace`), a host that delivers `Result` and `Unresolved { Cancelled }` to two receivers in both orders, and the 512/16 pending caps over 1024-event sessions | every honest receiver converges after resends; every run with two seals at one segment ends `Unresolved { CompetingSeals }` on both sides; every abort after `BindClose` ends `Unresolved` with the closed commit set retained as evidence; the 65th-input seal is refused at admission rather than failing at `SegmentManifest` construction; both receivers reach the same terminal settlement outcome and retain the same evidence in either delivery order; no two `Result`s accepted | pending caps and whether the 512 cap and `MAX_GAME_EVENT_BYTES` stay consistent (any revision of the pending caps re-derives `MAX_GAME_EVENT_BYTES`); whether per-event host acks are needed (expected: no); whether a signed fork-proof object is needed (expected: no) |
| 6 | Can a receiver without `oracle` audit an inner artifact? | for six worlds and eight controls, serialize each artifact with compact `serde_json::to_vec` and compare its plain SHA-256 to the id of its own kind: the `Experiment` to a `PlatonikExperimentV1` id (equal to `experiment_hash`), the `RunResult` to a `PlatonikResultV1` id (equal to `result_hash`), and the whole `Receipt` to a `PlatonikReceiptV1` id the publisher computed as `artifact_hash(&receipt)`; hash 8 MiB native and wasm32 | each artifact's bytes hash to its own kind's id, with no cross-kind comparison attempted; 8 MiB hashed in ≤ 200 ms native, ≤ 1 s wasm | whether `InnerArtifactId` byte identity is checkable on the default path (expected: yes), which `InnerKind`s the manifest must carry for that path to be self-sufficient, and whether the publisher must emit a kind-3 id; the default-path evidence is the `cargo tree` absence assertion plus the two `cargo check` targets, never a test run |

## Dependency-ordered work

1. **Stage 0 (`witness: add platform::run_observed`), its own PR.** Add `run_observed`, make `run`
   delegate; no codec, tag, bound, or vector change; dated deviation entry and spike 1 numbers in
   the witness plan. CI unchanged.
2. **Stage 1, the first PR (`game: land vhalla-game-platonik skeleton`).** Exact scope: the crate
   directory with `Cargo.toml` (`oracle` feature, pinned optional git dependency, dev-dependency
   self path) and `clippy.toml` fencing `mint`; `ids.rs`; `wire.rs` (conventions and every `MAX_*`
   bound, including `MAX_SEAL_ORDER = 512`, plus a bound test that encodes the widest `Seal` against
   `MAX_GAME_EVENT_BYTES`); `record.rs` (`GameRecord` sign and verify); `manifest.rs`
   (`GameManifest`, `InnerArtifactId`, `SessionLimits`); `oracle/convert.rs` (restated `Experiment`
   to `TaskManifest` plus `Assignment`, `loading_work` = JSON byte length); six `Replay`-kind
   manifest vectors carrying the fixture experiment hashes (`opening-normal` is `377b1218…`); a
   parity test that the six fixtures and 28 witness vectors reproduce through the converter;
   `Cargo.lock` entries; the `members` and wasm32 CI rows; `README.md` ("What a verified checkpoint
   proves", "Boundaries"); the `docs/README.md` row; the ownership-table row and dated entry in the
   readiness plan; this plan moved to in-progress with a dated entry, the owner, the reviewer, and
   the dependency and advisory review note; `kb percolate`, `kb refresh`, `kb check`. No engine,
   session, or receiver code. 3. **Stage 2 (`game: engine seam, sessions, checkpoints`).**
   `engine.rs`, `platonik.rs` with `FrameObserver` and the world-digest-seeded `TraceHead`,
   `session.rs` with the two-phase bind, `BindClose`, and the fill-over-bind refusal,
   `checkpoint.rs` with the seal-after-checkpoint binding, `receiver.rs` with allowances, policy,
   memoization, and `VerifiedCheckpoint`; `compile_fail` fences; property schedules; spikes 3 and 5;
   event, seal, and checkpoint vectors; the Python oracle. v1 vectors freeze here. 4. **Stage 3
   (`game: settlement, pause, replace`).** `settlement.rs`, `MissingMember`, `Fill`, `Replace` with
   epoch bump and anchored ledger, cancellation, failed-exchange evidence, order-independent
   settlement resolution with `Contradiction` as an admission rejection; spike 4; delete
   `prototypes/game-session` and `prototypes/settlement` with README notes; adversarial mutation
   corpus; decoder fuzz harnesses under `prototypes/game-fuzz`, which is a plain stable-toolchain
   crate whose harnesses are `#[test]` driven and seeded from committed corpora under
   `prototypes/game-fuzz/corpus/<decoder>/` plus that adversarial mutation corpus, with a committed
   `Cargo.lock` so `--locked` resolves and a fixed per-target seed and iteration cap so runs are
   deterministic and bounded in CI time, written to pass the existing `prototypes/*/Cargo.toml` loop
   (`cargo fmt --check`, `cargo test --locked`, `cargo clippy --all-targets --locked -- -D
   warnings`) with no workflow change. Rejected for this release: `cargo-fuzz` and libFuzzer, which
   would add the repository's first nightly toolchain dependency, a separate scheduled CI lane, and
   an exclusion of `prototypes/game-fuzz` from that glob and from this plan's own
   `prototypes/game-*` loop. 5. **Stage 4 (`game: bounded artifacts`).**
   `artifact.rs`, `ArtifactAssembly`, per-resource caps, browser record mapping; spikes 2 and 6 fix
   the defaults and are appended here; `oracle/audit.rs` over fetched Platonik receipts; wasm parity
   of the game vectors; a `vhalla-cli` subcommand `game replay <bundle>` that plays a scripted
   session and verifies it from a second receiver (the reproducible user journey). 6. **Stage 5
   (later, separate entries).** `quorum` feature consuming a rooms-consensus certificate through a
   verify hook; `SignedClaim` export of `VerifiedSettlement`; a `KIND_GAME_SETTLEMENT` evidence kind
   in `vhalla-steel-thread` modelled on `WitnessSession`, never through `RemoteRequest`; Hashcash
   promotion proceeds independently.

## Verification

- Golden vectors `tests/vectors/game-v1-*.txt` in the witness `key: value` format extended with
  `game_manifest`, `session_open`, `event[n]`, `seal[k]`, `checkpoint[k]`, `settlement` hex and
  every digest (`session_key`, `event_digest`, `state_root`, `checkpoint_hash`, `trace_head`,
  `frame_digest`, `receipt`). `prototypes/game-vectors/verify-vectors.py` recomputes every digest
  and root with `hashlib` and `struct` and checks every signature with a committed pure-Python RFC
  8032 Ed25519 implementation; no third-party package, no skipped signature.
- Corpus parity under `oracle`: six fixtures and 20 bridge-v1 cases as `Replay` sessions; the
  deserialized `Receipt`'s own fields compared to the manifest ids, `experiment_hash == inner[0]`
  and `result_hash == inner[1]` (field equality, never a hash of the receipt's bytes), Platonik
  `verify_receipt` agrees with the adapter's `passed`, `Costs::total() == WorkSummary.total`; all 28
  witness vectors reproduce through `PlatonikV1::replay`.
- Property and state-machine tests (proptest, committed regression seeds): sessions of 2..=4
  players, at most 8 segments and up to 65 inputs per case so the per-case cap is actually reached,
  under loss, duplication, reorder, delay, partition, restart from `Ledger::snapshot`, clock
  rollback, expiry by step budget, cancellation, revocation by epoch bump, equivocation, and
  competing seals; plus `Live` schedules that cover commit-before-reveal ordering, a `BindCommit`
  arriving after `BindClose`, a grinding last revealer, an abort between `BindClose` and `Reveal`,
  and a host that holds a bind and seals a `Fill` for the same slot (the seal is refused and the
  session ends `Unresolved { MemberMissing }`), a host that seals a 65th `Input` for one case, and
  both delivery orders of a `Result` against an `Unresolved { Cancelled }`. Invariants: honest
  receivers that saw the same seals hold identical verified digests; any two honest receivers
  holding the same set of settlement objects for one `(session, epoch)` reach the same terminal
  outcome and retain the same evidence, independent of arrival order; no receiver accepts two
  checkpoints at one height; `ledger_total` is monotone across checkpoints and offset-exact across
  segments by that case's admitted-input count, with the offset exercised at zero on a terminal
  case; `status` is non-decreasing in the order `Complete <
  ActivationLimit < FuelExhausted`, never leaves `FuelExhausted`, and is equal rather than merely
  non-decreasing on a terminal case; no case's fuel stop ever moves to a tick at or below a sealed
  checkpoint read tick; every rejected input and every refused seal leaves state bit-identical,
  including a seal whose order fails partway through `append` and is rolled back from
  `Ledger::snapshot`.
- Pause, replace, resume over every corpus session with random seal ticks and one member
  replacement, including sessions that admit further `Input`s for a still-running case between
  seals, one fuel-tight case, one case that fuel-exhausts strictly before a later seal's
  `through_tick`, and one that exhausts during loading: every intermediate checkpoint's `0..=T`
  prefix at that case's checkpoint read tick reproduces `StateHash`,
  `TraceHead`, and `status`, its `ledger_total` satisfies the offset equality, every terminal case's
  four checkpoint fields are byte-identical in every subsequent checkpoint with n equal to zero, and
  the final state hashes and receipt equal the unpaused run's.
- `compile_fail` doctests: verified types are not `Clone` and have no decoder; a `Settlement` cannot
  become `VerifiedSettlement` without the receiver; `RemoteRequest::from_verified(verified, scope)`
  does not type-check; `mint` outside `platonik.rs` fails clippy.
- The no-oracle receiver surface is checked by compilation and by dependency-graph absence, that is
  the native and wasm32 `cargo check` lines below, neither of which may gain `--all-targets` or
  `--all-features`, plus the `cargo tree` assertion; no test run reaches it.
- Decoder fuzz harnesses for every decoder under `prototypes/game-fuzz`, driven by the stable
  `prototypes/game-*/Cargo.toml` `cargo test --locked` loop in the command block below from
  committed corpora at a fixed seed and iteration cap, with no nightly toolchain and no `cargo-fuzz`
  invocation anywhere in that block; wasm32 parity of the game vectors
  through `prototypes/witness-wasm-parity/verify.sh`, divergence fixed by a determinism rule.
- Review record for the promotion entry: threat model, dependency provenance (pinned commit,
  licenses, advisory check), residual risk (host liveness, Sybil players, abort after `BindClose`,
  seed leak after `Reveal`, and a `Fill` accepted by a receiver that never saw the player's bind),
  and rollback.

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
cargo test --workspace --doc --all-features --locked
cargo check -p vhalla-game-platonik --locked
! cargo tree -p vhalla-game-platonik -e normal --locked | grep -q platonik-core
cargo check -p vhalla-witness -p vhalla-botcaptcha -p vhalla-game-platonik --target wasm32-unknown-unknown --locked
python3 prototypes/witness-vectors/verify-vectors.py
python3 prototypes/game-vectors/verify-vectors.py
sh prototypes/witness-wasm-parity/verify.sh
for manifest in prototypes/witness-*/Cargo.toml prototypes/game-*/Cargo.toml; do cargo fmt --manifest-path "$manifest" -- --check; cargo test --manifest-path "$manifest" --locked; cargo clippy --manifest-path "$manifest" --all-targets --locked -- -D warnings; done
kb percolate plans/valhalla-platonik-session-adapter.md --root kb; kb refresh --root kb; kb check --root kb
```

## Recovery

- Rollback of any stage is removal from `members` and the CI lists plus reversal of the stage 0
  delegation; v1 vectors, once frozen at stage 2, stay in the tree and keep passing. Any later
  codec, tag, or bound change needs a new version byte, tag string, vector file, and dated entry.
- A failed integration never broadens `ReceiverPolicy`, downgrades signature verification, or
  reintroduces a caller-supplied root.
- If native and wasm32 game vectors diverge, the wasm CI step fails; the fix is a determinism rule
  recorded here.
- If the Platonik pin moves, `witness-restatement` parity and the `oracle` corpus test rerun before
  any vector is regenerated; inner artifact ids are never re-derived with a different serializer.
- If spike 1 fails, `TraceHead` covers seal frames only; if spike 4's rebind half fails, program
  rebind stays out of every version until continuation exists.
- A receiver that loses state restarts from `Ledger::snapshot` plus the last accepted checkpoint
  and replays forward; a session it cannot reconstruct is `Unresolved`, never trusted.

## Decision record

| Decision | Chosen | Rejected | Status |
| --- | --- | --- | --- |
| Game authority (fork 4) | one explicit session host with ordering and inclusion authority only; `Authority::Quorum` reserved on the wire | quorum first; optimistic peer state with dispute replay; relays as tie-breakers | decided |
| Session log | `vhalla-ledger` linear history, one ledger per `(realm, epoch)`, 32-byte event payloads | own head chain; per-realm DAG; rooms-consensus batches | decided |
| Ledger binding | checkpoint commits the pre-seal tip; the `Seal` event is appended after acceptance as the next segment's first event, so an epoch's terminal seal appends no `Seal` event to that epoch's ledger (a `Replace` seal becomes the next epoch's genesis, and the session's last seal opens nothing), giving a k-segment epoch `k - 1` `Seal` events; the settlement height check is stated in `vhalla-ledger`'s parent-link units, `Checkpoint(final).height == Σ\|order_j\| + s`, read at the final checkpoint's head with no genesis term | seal as the last event of its own segment (circular); an event-count sum with a genesis term (`height` is `chain(head).len() - 1`, so genesis contributes zero); reading the height at the epoch's tip rather than at the head the checkpoint names; counting "seals of that epoch" rather than `Seal` events appended to its ledger | decided |
| Ledger actor namespace | `peer_id_from_key` is the ledger's routing handle only; the full 32-byte key is the policy identity for every authority check, the claim table, and the `Seal.order` sequence check; `SessionOpen` and `Replace` are refused as `ActorAliasing` unless every host and slot key is pairwise distinct under `peer_id_from_key` | treating the 128-bit handle as an identity (`vhalla-crypto` disclaims it); checking distinctness at `SessionOpen` only, which a replacement key never passes through; accepting a shared `Ledger::last_sequences` counter for two game-layer authors | decided |
| Seal application and ledger capacity | `Seal.order` applies all-or-nothing over `Ledger::snapshot` and `restore`, with `SealApplyFailed` as the rejection and the seal retained as evidence; each per-epoch `Ledger::new` and `restore` take `1 + max_events + max_segments` (1033), which keeps `Error::Capacity` unreachable and stays inside `vhalla_ledger::MAX_EVENTS = 4096` | partial application (the crate exposes no rollback and `append` mutates `head` and `last_sequences`); leaving `max_events` unstated, which surfaces as a mid-order `Capacity` rather than a construction error because `Ledger::new` silently clamps; counting `Seal` events against the session's `max_events <= 1024` | decided |
| Signed carrier | audience-free `GameRecord` with its own transcript | `SignedEnvelope`; `SignedClaim`; `vhalla_social::SignedRecord` | decided |
| Live seeds | two-phase bind: salts and programs committed, closed by a host-signed `BindClose`, then revealed; a filled slot contributes a fixed salt; a fill over a held bind is refused | host-only commitment; open seeds; single-phase plaintext bind salts; a segment-0 seal of the commit set; a new `HostAborted` fork reason | decided |
| Loading cost | `Replay` sessions bit-exact with Platonik; `Live` sessions use the fixed template-plus-inputs rule | publisher-chosen headroom; oracle at reveal time | decided (deviation recorded) |
| Checkpoint identity | replay from genesis with `StateHash` at the case's checkpoint read tick `T = min(through_tick, last_frame_tick)`, a `TraceHead` chained from the world digest, `ProgramHash`, and case index over the ledger-free `FrameDigest`s the replay actually emitted through `T`, `ledger_total` monotone across checkpoints and offset-exact across segments by that case's admitted-input count, and a terminal case (`FuelExhausted` or at its `ticks`) repeating all four fields exactly | `State` decoder or continuation API; frames in checkpoints; a ledger-committing `FrameDigest` (the frame-0 `Category::Checking` charge scales with the declared event count, so it could never be prefix stable across seals); a bare cross-segment `ledger_total` prefix equality; reading checkpoint fields at `min(through_tick, case.ticks)`, which names no frame once a case has fuel-exhausted; seeding the trace with the per-segment `SegmentManifest` hash; `SessionKey` as the trace seed (it would embed a session key in frozen trace vectors) | decided, spike 1 sizes the trace |
| Fuel prefix stability | a per-seal slack rule: a still-running case whose `slack_k = case.fuel - Checkpoint(k).ledger_total` at its read tick is below `remaining_k = MAX_EVENTS - n_k` accepts no further `Input`, refused as `CaseFuelSlack`, which bounds the frame-0 units a sealed prefix can still accrue and so keeps `StateHash`, `TraceHead`, and `status` stable on `0..=T` and the `ledger_total` offset exact | the reveal-time frame-0 headroom check alone (`Meter::charge` sizes `fuel_room` against the cumulative whole-case total, so n extra frame-0 units move a mid-run fuel stop earlier and an honest resume reads as `ReplayMismatch`); refusing the seal instead of closing inputs (a liveness cost on honest hosts); padding each case's declared event slate to `MAX_EVENTS` (`EventKind` has no no-op variant and the padding would consume the 64-slot cap); a `fuel_effective = fuel + n` rewrite (it puts `Replay`-kind bit-exact cost parity at risk); a whole-case work bound at `Reveal` (not computable there, since the revealed manifest declares empty events) | decided, spike 3 sizes it |
| Replace | member replacement with the same program at a seal boundary, epoch bump that consumes no segment, anchored new ledger | program rebind mid-session; degrade by dropping a cell; an epoch bump that resets or buys segments | decided, spike 4 tests rebind for later |
| Missing members (eukaryotic 5) | `Pause` or `Fill` with the declared fallback and pending-claim evidence, declared in limits; a fill over a held bind is `Unresolved { MemberMissing }` | degrade; finalize with missing members; a silent fill; a mandatory host-signed `MemberMissing` before every fill | decided |
| Contracts (eukaryotic 3) | receipt-based | leases; escrow | decided |
| Settlement carrier | post-ledger evidence: a host-signed `GameRecord(Settlement)` under `vhalla/game/settlement/v1`, admitted against the final accepted checkpoint and never sealed | a `Settle { settlement }` `GameEvent` body (structurally unsealable: an admitted event reaches the ledger only through a later `Seal`, and no seal follows the final one); a terminal seal carrying the settlement (it would need a `through_tick` equal to the previous seal's, a second `Checkpoint`, and one of `max_segments`) | decided |
| Settlement resolution | order-independent, ranked by self-verifiability: a `Result` the receiver reproduced outranks a bare host-signed `Unresolved`; equal-rank disagreement is `Unresolved { Equivocation }` with both objects retained; `Contradiction` is an admission rejection; the claim-table `Equivocation` rule never applies, since a settlement carries no event sequence | first-accepted-wins; `Cancelled` terminal against a reproduced `Result`; a new `ForkReason::Contradiction` wire variant | decided |
| Per-case input cap | `MAX_EVENTS = 64` enforced where `Seal.order` is validated, counted across every segment and epoch, with the gate refusing an `Input` for a case whose sealed tally is already 64 | counting over the arrival-ordered pending buffer (survival would depend on arrival order); `max_events <= 1024` as the only cap; letting `Case::new` fail at `SegmentManifest` construction | decided |
| Event bound | `MAX_GAME_EVENT_BYTES = 24_576` derived from the widest variant `Seal` (`MAX_SEAL_ORDER = 512` digests plus a 32-byte `CheckpointHash`), tied to the 512-unsealed pending cap; `Seal.checkpoint` is a `CheckpointHash`; unchanged by the removal of the `Settle` body, which was never the widest variant | deriving the bound from `BindReveal` and `MAX_PROGRAM_BYTES`; embedding a whole `Checkpoint` in the seal; sizing `order` from `max_events <= 1024` | decided |
| Platform change | `platform::run_observed` only, as a dated witness-plan deviation | `vm::run` from the adapter; double run | decided |
| Platonik engine | `oracle` feature, git pin, test oracle and publisher tool | default dependency; production replay | decided |
| Inner artifacts | opaque `InnerArtifactId`; byte identity by plain SHA-256 over the compact canonical bytes of the object its `InnerKind` names; a moved receipt carries its own `PlatonikReceiptV1` id; JSON audit only under `oracle` | recomputing JSON hashes in the receiver; comparing receipt bytes to `result_hash` | decided, spike 6 |
| Frame budget | pre-charged per segment, memoized by manifest, program, and tick; allowance ∩ policy | refunds; per-advance re-execution (226 runs) | decided |
| Time | no clock; caller-supplied monotone step; deadlines as step budgets | `now` arguments; lease timers | decided |
| Artifacts | 8 MiB charged as peak retained bytes against one concurrent assembly, 64 KiB blocks, 128 blocks, no compression, separate caps | compression; whole-session artifacts; a cumulative per-session artifact total under the same field | decided, spike 2 sets defaults and confirms the aggregate |
| Fuzzing | `prototypes/game-fuzz` is a stable-toolchain crate whose decoder harnesses are `#[test]` driven from committed corpora at a fixed seed and iteration cap, passing the existing `prototypes/*/Cargo.toml` CI loop unchanged | `cargo-fuzz` plus libFuzzer (the repository's first nightly dependency, a separate CI lane, and an exclusion of the directory from the `prototypes/*` glob); leaving the runner and toolchain unstated while the CI loop already matches the directory | decided |
| wasm32 CI | crate in the list with default features | omitted as a `std` adapter | decided |
| Default-path check | native and wasm32 `cargo check` plus a `cargo tree` absence assertion for `platonik-core` | `cargo test --no-default-features` (the self dev-dependency unifies `oracle` into the library) | decided |
| Vector oracle | Python with committed pure-Python Ed25519 | signatures skipped | decided |
| Prototypes | `game-session` and `settlement` deleted at stage 3; `checkpoint-proof` and `checkpoint-ledger` wait for `quorum` | porting any prototype type | decided |
| First PR | skeleton, wire, record, manifest, converter, six vectors, docs | one PR with engine and receiver | decided |
| Plan location | this file plus a dated entry in the readiness plan | section inside the games plan | decided |

## Review findings

Applied from the plan review; each line is the finding id, its lens, and what changed here.

- F1 (threat-model, blocker): live seeds became a two-phase bind (`BindCommit`, a host-signed
  `BindClose` that a pre-`Reveal` seal cannot replace, then `BindReveal`) with a separate
  `vhalla/game/hostsalt/v1` commitment domain and a fixed fill salt, and the threat row, the `Live
  seeds` decision row, the residual-risk list, spike 5, and the property schedule now name
  abort-after-close as the only remaining lever.
- F8 (ledger-authority, minor): a `Seal` admitting `Fill { slot }` is refused when the receiver
  holds a bind for that slot (`Unresolved { MemberMissing }` with the bind digest retained), `Fill`
  gained an `evidence` field, the filled slot's salt contribution is defined over the manifest's
  slots in slot order, and a `session::fill_over_held_bind_is_unresolved` test and property case
  were added.
- W1 (witness-fidelity, major): `TraceHead` is seeded with the session-stable world digest instead
  of the per-segment `ManifestHash`, `GameEngine::replay` takes that seed explicitly and
  `SegmentEvidence` reports it, memoization keys on it, the two same-named hashes are disambiguated,
  and the `ProgramHash` seed input is tied to `Replace` leaving the program unchanged.
- PS-1 (platonik-fidelity, major): each `InnerKind` now names the object whose compact canonical
  bytes its id hashes, a moved receipt needs its own `PlatonikReceiptV1` id computed as
  `artifact_hash(&receipt)`, spike 6 compares every artifact to its own kind's id, and the
  receipt-bytes-versus-`result_hash` comparison is recorded as a known non-check.
- PS-6 (platonik-fidelity, minor): the per-case effective tick is `min(through_tick, case.ticks)`,
  staleness and input admission are per case and bounded by `case.ticks`, `max_segments` counts
  seals across every epoch, a `Replace` consumes no segment, and the `MAX_ADVANCES` gloss is
  restated as a deliberate reuse rather than an inherited bound.
- F7 (scope-delivery, minor): the `--no-default-features` test line is replaced by a native `cargo
  check` plus a `cargo tree` absence assertion, and the crate plan and verification section state
  that no test run in this crate can reach the default path.
- WF-1 (witness-fidelity, blocker): `FrameDigest` no longer commits the frame's `Ledger`, because
  `initial_checking` charges one `Category::Checking` unit per declared event at frame 0
  (`crates/vhalla-witness/src/vm.rs:987`, `vm.rs:997`, `vm.rs:1219`) and a ledger-committing frame
  could never be prefix stable across seals; the resume rule now requires `StateHash`, `TraceHead`,
  and `status` to reproduce exactly on frames `0..=T` at that case's checkpoint read tick and
  `ledger_total` to satisfy the exact
  offset equality `Checkpoint(k).ledger_total + n` for the inputs admitted since seal k; `Reveal`
  checks that each case's `fuel` leaves headroom for the frame-0 charge at the full 64-event cap,
  which F1 and PS3-1 below corrected to the tick-0 base case alone, with the per-seal slack rule
  carrying prefix stability instead; the `Checkpoint` field set,
  **Checkpoints**, the `Checkpoint identity` decision row, the resume-forgery threat row, spike 3,
  spike 4, and the property and pause-resume verification lines were updated to match. No
  `vhalla-witness` charge changes, so stage 0 stays "no codec, tag, bound, or vector change".
- WF-2 (witness-fidelity, major): the per-case cap of `MAX_EVENTS = 64`
  (`crates/vhalla-witness/src/world.rs:514`) is now enforced where `Seal.order` is validated rather
  than only inside `Case::new`, counted across every segment and epoch so it survives a `Replace`,
  with a seal-derived gate rule and a `CaseEventLimit` admission rejection; `SessionLimits` states
  that `max_events <= 1024` is a session ceiling above, never a substitute for, the per-case 64; the
  Platonik mapping rules read the cap as an admission check that `World::new` and `Case::new`
  re-check defensively; a threat row, a `session::case_event_limit` test, a `Per-case input cap`
  decision row, a spike 5 schedule, and a property generator that actually reaches the 65th input
  were added.
- WF-3 and PS2-3 (witness-fidelity and platonik-fidelity, major): the checkpoint status invariant is
  restated as the partial order `Complete -> ActivationLimit -> FuelExhausted` with the direct
  `Complete -> FuelExhausted` edge permitted and `FuelExhausted` terminal, anchored on
  `crates/vhalla-witness/src/vm.rs:1142`, `vm.rs:1225`-`1228`, and `vm.rs:1263` with Platonik
  `sim.rs:884`, `:918`, and `:692`-`707` cited as prior art; **The one engine seam** now says how
  the hashing `FrameObserver` derives per-tick status from `FrameView.complete` and
  `ActivationError::ActivationLimit`, since `WitnessRun` and `CaseResult` expose only the whole-case
  `RunStatus`; the threat row gained `checkpoint::status_monotone_across_seals` and the property
  invariants gained the non-decreasing status rule.
- WF-6, PS2-6, and N7 (witness-fidelity, platonik-fidelity, conventions, minor): the
  `MAX_GAME_EVENT_BYTES = 24_576` justification now names `Seal` rather than `BindReveal`, states
  `MAX_SEAL_ORDER = 512` and that `Seal.checkpoint` is a 32-byte `CheckpointHash` rather than an
  embedded `Checkpoint`, shows the arithmetic (512 × 32 + 32 + header, about 16.3 KiB), ties the
  bound to the 512-unsealed pending cap rather than to `max_events <= 1024`, and keeps
  `MAX_PROGRAM_BYTES = 1059` as the bound on `BindReveal`, the widest player-signed variant; stage
  1's `wire.rs` scope gained `MAX_SEAL_ORDER` and a widest-`Seal` bound test, spike 5 gained the
  consistency question, and an `Event bound` decision row was added.
- WF-7 (witness-fidelity, minor): the seed preimage runs over the manifest's slots in slot order,
  one per world cell and so `MIN_CELLS..=MAX_CELLS` of them, never padded out to `MAX_CELLS`
  (`ValidManifest::validate` pins the slot set to the world's cells,
  `crates/vhalla-witness/src/manifest.rs:98`-`104`); the F8 entry above was corrected the same way.
- R2-2 (threat-model, blocker): settlement resolution is order-independent and ranked by
  self-verifiability, so a `Result` the receiver reproduced outranks a bare host-signed
  `Unresolved`, equal-rank disagreement is `Unresolved { Equivocation }` with both objects retained,
  and `Contradiction` is named as an admission rejection rather than a missing `ForkReason`;
  `Cancelled` ends the whole session and stays terminal against further `Unresolved`s but not
  against a reproduced `Result`, and is inadmissible after a final checkpoint at `max(case.ticks)`;
  the convergence invariant, a threat row, a `Settlement resolution` decision row, and spike 5 and
  stage 3 property cases in both delivery orders were added.
- R2-8 (threat-model, minor): `max_artifact_bytes <= 8 MiB` is declared as peak retained bytes
  against the single concurrent assembly rather than a cumulative session total, stated in both
  `SessionLimits` and **Bounded artifacts**, with the 64-trace worst case read as 64 sequential
  assemblies; spike 2 gained an aggregate pass criterion and the `Artifacts` decision row records
  the accounting.
- SETTLE-1 (ledger-authority, major): `Settle { settlement }` left the `GameEvent` body list and the
  host-only admission list, because an admitted event reaches the ledger only through a later `Seal`
  and no seal follows the final one, so a sealed settlement could never be committed; a host-signed
  `GameRecord(Settlement)` under `vhalla/game/settlement/v1` is now the sole carrier, with the
  circularity reason stated beside the one `Seal.checkpoint` already gives and with no terminal seal
  added (that would need a `through_tick` equal to the previous seal's, a second `Checkpoint`, and
  one of `max_segments`); the `Result` admission test's "ledger height equals the admitted event
  count" is restated as an explicit per-epoch sum (genesis plus every event appended in that epoch's
  `Seal.order`s plus one per `Seal` event) with an empty pending buffer and no carve-out, which R3-4
  below corrected to `vhalla-ledger`'s parent-link units with no genesis term and with `s` counting
  only the `Seal` events actually appended to that epoch's ledger; the
  resolution paragraph states that the `(author, sequence)` claim-table `Equivocation` rule never
  governs settlements; a `Settlement carrier` decision row was added and the `Settlement resolution`
  and `Event bound` rows were updated to match. `MAX_GAME_EVENT_BYTES = 24_576` is confirmed
  untouched: `Seal` remains the widest variant at about 16.3 KiB and a `Settlement` is separately
  bounded at 1024 bytes, so no re-derivation is needed.
- F1 (witness-fidelity, blocker) and PS3-1 (platonik-fidelity, blocker), one defect and one fix:
  the reveal-time frame-0 headroom check cannot hold a case's fuel stop in place, because
  `Meter::charge` sizes `fuel_room` against the cumulative whole-case `Ledger::total()`
  (`crates/vhalla-witness/src/ledger.rs:179`-`181`), so n later-admitted `Input`s lower the room at
  every charge and can move a stop into an already-sealed prefix, which an honest receiver reads as
  `ReplayMismatch` and which fails the P4 exit condition. **Checkpoints** now carries a per-seal
  slack rule: a still-running case whose `slack_k = case.fuel - Checkpoint(k).ledger_total` at its
  read tick falls below `remaining_k = MAX_EVENTS - n_k` accepts no further `Input`, refused at the
  gate as `CaseFuelSlack`, which preserves liveness (the seal is still accepted) and bounds the
  frame-0 units a sealed prefix can still accrue, so `StateHash`, `TraceHead`, and `status` on
  `0..=T` stay stable and the `ledger_total` offset stays exact. The reveal check is restated as the
  tick-0 base case only; the two prefix-stability claims in the Platonik mapping rules and in
  **Pause, replace, resume** now attribute stability to the slack rule; the admission paragraph, the
  resume-forgery threat row, the `Checkpoint identity` decision row, a new `Fuel prefix stability`
  decision row, the WF-1 entry above, spike 3's pass criteria and generator, spike 4, and the
  property and pause-resume verification lines were updated to match. Rejected alternatives are
  recorded in the new decision row: padding the declared slate to `MAX_EVENTS` (`EventKind` has no
  no-op variant), a `fuel_effective = fuel + n` rewrite (it risks `Replay`-kind cost parity), and a
  whole-case work bound at `Reveal` (not computable from a manifest that declares empty events).
- PS3-2 (platonik-fidelity, major): the per-case tick is split in two, because
  `min(through_tick, case.ticks)` names no frame for a case that fuel-exhausted earlier. The
  *effective tick* `min(through_tick, case.ticks)` stays the admission threshold for staleness and
  the input caps, and a new *checkpoint read tick* `T = min(through_tick, last_frame_tick)` is what
  every checkpoint field is read at, with `TraceHead` chaining the `FrameDigest`s the replay
  actually emitted through `T`. The freeze rule generalized from "a case that has reached its
  `ticks`" to any terminal case, `FuelExhausted` included, whose four fields repeat exactly and
  whose `status` must be equal rather than merely non-decreasing, with n equal to zero in the offset
  equality; the final seal's `through_tick` is noted to give a fuel-exhausted case no frame either,
  so a `Settlement::Result` names that case's clamped values. The status derivation in **The one
  engine seam** is unchanged, since both latches already filter over emitted frames. The
  `Checkpoint` field set, the engine seam, the resume prefix check, the `Checkpoint identity`
  decision row, spike 4, and the property and pause-resume schedules now generate a case that
  exhausts strictly before a later seal's `through_tick` and one that exhausts during loading, and
  assert their fields are byte-identical in every later checkpoint.
- R3-4 (ledger-authority, major): the `Settlement::Result` completeness check is restated in
  `vhalla-ledger`'s own units. `height` is a parent-link count, `chain(head).len() - 1`
  (`crates/vhalla-ledger/src/lib.rs:436`), so the genesis term is dropped and the check is
  `Checkpoint(final).height == Σ|order_j| + s`, read at the head the final checkpoint names, where
  `s` counts `Seal` events appended to that epoch's ledger rather than seals of that epoch.
  **Ledger binding, no circularity** now fixes seal placement in one sentence: an epoch's terminal
  `Seal` is never appended to that epoch's ledger, since a `Replace` seal becomes the `epoch + 1`
  genesis with payload `CheckpointHash(k)` and the session's last seal opens no segment k+1, so a
  k-segment epoch holds `k - 1` `Seal` events and `s = k - 1`. "Only derivable once the final seal
  is appended" became "once the final seal's order is appended" so it no longer implies a terminal
  `Seal` event. Two vectors pin the numbers, a two-segment epoch at `|order_1| + 1 + |order_2|` and
  a two-segment one-`Replace` session at `|order_1|` then `|order_2|`, and spike 4 checks them; the
  `Ledger binding` decision row records the placement and the units.
- R3-6 (ledger-authority, major): `peer_id_from_key` is named as a 128-bit SHA-256 truncation
  (`crates/vhalla-crypto/src/lib.rs:379`-`386`) that `vhalla-crypto` disclaims as a policy identity,
  so it is the ledger's routing handle while the full 32-byte key stays the identity every authority
  check, the claim table, and the `Seal.order` sequence check run on. Admission now keeps the two
  namespaces in bijection for the whole session: `SessionOpen` and `Replace` are refused as
  `ActorAliasing` unless every host and slot key is pairwise distinct under `peer_id_from_key`, the
  `Replace` half being what an opening-time check alone cannot cover. `Seal.order` application
  became all-or-nothing over `Ledger::snapshot` and `restore` with a `SealApplyFailed` rejection,
  since the crate exposes no rollback and `append` mutates `head` and `last_sequences`
  (`crates/vhalla-ledger/src/lib.rs:200`-`202`), and each per-epoch `Ledger::new` and `restore` take
  `1 + max_events + max_segments` (1033), inside `vhalla_ledger::MAX_EVENTS = 4096`, which makes
  `Error::Capacity` unreachable rather than a mid-order failure; `Seal` events sit outside the
  session's `max_events <= 1024`. Two threat rows, two decision rows (`Ledger actor namespace`,
  `Seal application and ledger capacity`), and the property invariant that a refused seal leaves
  state bit-identical were added.
- SD-7 (scope-delivery, minor): `prototypes/game-fuzz` is now specified as a plain stable-toolchain
  crate whose decoder harnesses are `#[test]` driven and seeded from committed corpora under
  `prototypes/game-fuzz/corpus/<decoder>/` plus the stage 3 adversarial mutation corpus, with a
  committed `Cargo.lock`, a fixed per-target seed, and a fixed iteration cap, written to pass the
  existing `prototypes/*/Cargo.toml` CI loop and this plan's own `prototypes/game-*` loop with no
  workflow change and no nightly toolchain; `cargo-fuzz` plus libFuzzer is recorded as the rejected
  alternative with the nightly lane and glob exclusion it would need. Stage 3, the verification
  bullet, the decoder threat row, and a new `Fuzzing` decision row were updated.

## Execution status

### 2026-09-17: stage 0 lands and spike 1 passes

Owner: this task (Ben's authority, the Claude session that wrote the plan); independent reviewer:
the two-skeptic adversarial workflow recorded under **Review findings**, with a human review still
required at PR time. `vhalla-witness` gained `platform::run_observed`; `run` delegates to it and
the observed and plain runs are proven identical over the 28 vectors (see the witness plan's
2026-09-17 deviation entry). `prototypes/game-trace-cost` hashes every frame through the seam:
`FrameDigest` over tick, complete flag, and the encoded state (never the ledger), chained into a
`TraceHead` seeded with the world digest, `ProgramHash`, and case index. Numbers (release): 1,542
frames and 499,094 state bytes over the corpus; native p95 0.11 ms and worst case (the 64 KiB
16-cell, 128-tick vector) 4.4 ms; the whole corpus under wasm32 in 15.0 ms with a 0.3 MiB heap;
trace heads identical on native and wasm32 and every output hash unchanged under observation.
Spike 1 passes against its criteria (native p95 at most 100 ms, wasm at most 500 ms, heap at most
32 MiB) with two orders of magnitude to spare, so v1 hashes every frame; the fallback of hashing
only at seal ticks is not needed. Stage 1 follows.
