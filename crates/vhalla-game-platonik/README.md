# vhalla-game-platonik

The Platonik session adapter: the games plan's `GameManifest`, `SessionOpen`,
`GameEvent`, `Checkpoint`, and `Settlement` over
[`vhalla-witness`](../vhalla-witness/README.md), so that Platonik runs through
an optional Valhalla session and a receiver independently verifies the result.
Read the [session adapter plan](../../kb/plans/valhalla-platonik-session-adapter.md)
for the design, its review record, and the staged delivery.

Stages 1 through 4 land the identifiers and digest domains, the canonical
encodings with every bound, the audience-free signed `GameRecord`, the
`GameManifest` with its limits, the optional Platonik oracle converter and
audit, the one engine seam (`GameEngine`, implemented only by `PlatonikV1`
over `platform::run_observed`), host-ordered sessions over `vhalla-ledger` with
the two-phase live bind, checkpoints, the receiver, settlement with
order-independent resolution, pause and member replacement across an epoch
bump, fills, cancellation, and the bounded artifact assembly with its browser
record mapping. Stage 5 lands `VerifiedSettlement::export_claim` (a
`SignedClaim` in `ClaimDomain::Receipt` whose subject is the settlement hash,
signed by the verifier's own seed), the `quorum` feature (`quorum::attest`: a
rooms-consensus `CommitCertificate` checked through the `Adapter::absorb`
verify-hook signature and required to decide the batch it is presented with),
and `KIND_GAME_SETTLEMENT` with `GameSession` in `vhalla-steel-thread`.
Rooms-consensus `VRB3` batches now carry bounded typed game commitments, so
`attest` locates the exact realm/room/session/epoch settlement itself rather
than trusting a caller-supplied locator. `Authority::Quorum` at session open
stays reserved until the adapter replaces its host-key assumptions with a
certificate-backed admission path.

## What a verified checkpoint proves

A `VerifiedCheckpoint` proves that this receiver itself replayed the session's
revealed task with every admitted input through `vhalla-witness`, reproduced
every case's state hash, trace head, ledger total, and status at its
checkpoint read tick, re-derived the ledger root over the host's sealed order,
and found the host's signed checkpoint hash equal to its own. Across seals it
also proves the sealed prefix reproduced exactly and the ledger total moved by
exactly the inputs admitted since. Replays are charged against the session's
verification allowance before any work.

It proves nothing else. A session host has ordering and inclusion authority
only; multiplayer does not imply permissionless finality; a game object is
evidence and never host authority, and no verified type here converts into
one.

## What a verified settlement proves

A `VerifiedSettlement` holding a `Result` proves that this receiver
reproduced the final segment's receipt itself and found the host's signed
receipt, checkpoint, and pass flag equal to its own, with every admitted event
sealed and the epoch's ledger height exactly the sealed events plus the seal
events. An `Unresolved` verdict is the host's signed fork claim or the
receiver's own derivation, ranked below any reproduced result in either
arrival order. Neither is money, finality, or host authority.

## Boundaries

- `std`; nothing in the workspace depends on it. Dependencies on the default
  path are `vhalla-witness`, `vhalla-core`, `vhalla-crypto`, `vhalla-ledger`,
  `ed25519-dalek`, and `sha2`; no serde, clock, file, or socket.
- The `oracle` feature pulls the pinned `platonik-core` as converter source
  and test oracle, never as a receiver requirement. `cargo tree -e normal`
  shows no `platonik-core` on the default path.
- The `quorum` feature pulls `vhalla-rooms-consensus` for `CommitCertificate`,
  `Batch`, and its typed game commitments; the certificate check is the
  caller's hook, never this crate's, and a certificate never replaces
  reproduction: `quorum::attest` takes a `VerifiedSettlement` that replay
  already produced.
- Every decoder checks its byte bound first, then the version, reads with
  bounds-checked slices, and rejects trailing bytes. The widest `Seal` (512
  ordered digests) and the widest `Reveal` (a full task manifest) both fit
  `MAX_GAME_EVENT_BYTES`; the test prints their sizes.
- A `GameRecord` signature covers the kind, the session key, and the object
  digest under the object's own domain, so a record verifies identically at
  every receiver; room envelopes are delivery, never authority.
- `RunCapability::mint` is fenced by `clippy.toml` to its single call site in
  `PlatonikV1::replay`.
- The session never runs a program: a seal yields a `SealPlan`, the receiver
  replays it, and only a reproduced checkpoint is committed. Every rejection
  leaves the session bit-identical except for retained evidence.
- No clock: every receiver call takes a caller-supplied monotone step.
- Anything larger than one room frame is an artifact: 64 KiB blocks, at most
  128 of them, one assembly in flight per session, 8 MiB charged as peak
  retained bytes, no compression, and a whole-artifact digest check against
  the inner artifact id before the bytes are handed over. Browser receivers
  carry each block as 4 KiB records; the block digest is unchanged.
- Inner Platonik artifacts are opaque on the default path: the receiver
  compares plain SHA-256 to the id of the artifact's own kind and never parses
  JSON. Parsing, re-serialization, and Platonik's own receipt verification live
  behind the `oracle` feature for publishers and tests.

## Evidence

`tests/vectors/game-v1-*.txt` hold the six `Replay`-kind manifests of the
Platonik fixtures with their experiment ids, which equal Platonik's own
`artifact_hash` of each experiment. The converter reproduces all 28 witness
corpus vectors byte for byte.
