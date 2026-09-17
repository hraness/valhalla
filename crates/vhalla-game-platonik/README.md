# vhalla-game-platonik

The Platonik session adapter: the games plan's `GameManifest`, `SessionOpen`,
`GameEvent`, `Checkpoint`, and `Settlement` over
[`vhalla-witness`](../vhalla-witness/README.md), so that Platonik runs through
an optional Valhalla session and a receiver independently verifies the result.
Read the [session adapter plan](../../kb/plans/valhalla-platonik-session-adapter.md)
for the design, its review record, and the staged delivery.

Stage 1 lands the identifiers and digest domains, the canonical encodings with
every bound, the audience-free signed `GameRecord`, the `GameManifest` with its
limits, and the optional Platonik oracle converter with six `Replay`-kind
manifest vectors. The engine seam, sessions, checkpoints, settlement, the
receiver, and bounded artifacts follow in later stages; nothing here yet
verifies a checkpoint.

## What a verified checkpoint proves

When the receiver lands, a verified checkpoint or settlement will prove that
the receiver itself replayed the session's revealed task and admitted inputs
through `vhalla-witness` and reproduced every state hash, trace head, ledger
total, and the final receipt bit for bit under one explicit session host.

It proves nothing else. A session host has ordering and inclusion authority
only; multiplayer does not imply permissionless finality; a game object is
evidence and never host authority, and no verified type here converts into
one.

## Boundaries

- `std`; nothing in the workspace depends on it. Dependencies on the default
  path are `vhalla-witness`, `vhalla-core`, `vhalla-crypto`, `vhalla-ledger`,
  `ed25519-dalek`, and `sha2`; no serde, clock, file, or socket.
- The `oracle` feature pulls the pinned `platonik-core` as converter source
  and test oracle, never as a receiver requirement. `cargo tree -e normal`
  shows no `platonik-core` on the default path.
- Every decoder checks its byte bound first, then the version, reads with
  bounds-checked slices, and rejects trailing bytes. The widest `Seal` (512
  ordered digests) and the widest `Reveal` (a full task manifest) both fit
  `MAX_GAME_EVENT_BYTES`; the test prints their sizes.
- A `GameRecord` signature covers the kind, the session key, and the object
  digest under the object's own domain, so a record verifies identically at
  every receiver; room envelopes are delivery, never authority.
- `RunCapability::mint` is fenced by `clippy.toml` to the engine seam that
  lands in stage 2.

## Evidence

`tests/vectors/game-v1-*.txt` hold the six `Replay`-kind manifests of the
Platonik fixtures with their experiment ids, which equal Platonik's own
`artifact_hash` of each experiment. The converter reproduces all 28 witness
corpus vectors byte for byte.
