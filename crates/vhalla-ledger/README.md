# vhalla-ledger

`vhalla-ledger` is the first production-shaped state seam for Valhalla. It
keeps a bounded linear event history (capped at `MAX_EVENTS`) and derives
checkpoint roots from the canonical ancestor chain, realm, and epoch. Actor
sequences must advance monotonically. Forged roots, stale heads, forks,
wrong-context events, malformed IDs, and capacity exhaustion fail closed.
Deterministic snapshot/restore supports restart testing, but snapshot bytes are
unauthenticated and are not a durable trust anchor.

`validate_retained_checkpoint` checks an ancestor's context, derived root, and
height without changing state. Live checkpoint admission still requires the
current tip. The separate [checkpoint persistence experiment](../../prototypes/checkpoint-ledger/README.md)
uses this check to reject higher signed forks before a storage commit.

This crate does not provide persistence, quorum signatures, distributed
consensus, compaction proofs, or host authority. A checkpoint accepted here is
local evidence from one retained history. Durable recovery and signed
`CheckpointProof` admission must be added before this layer is wired into the
steel thread.

```console
cargo test -p vhalla-ledger --all-targets --offline
cargo clippy -p vhalla-ledger --all-targets --all-features --offline -- -D warnings
```
