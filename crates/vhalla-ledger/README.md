# vhalla-ledger

`vhalla-ledger` is the first production-shaped state seam for Valhalla. It
keeps a bounded linear event history and derives checkpoint roots from the
canonical ancestor chain, realm, and epoch. Forged roots, stale heads, forks,
wrong-context events, malformed IDs, and capacity exhaustion fail closed.

This crate does not provide persistence, quorum signatures, distributed
consensus, compaction proofs, or host authority. A checkpoint accepted here is
local evidence from one retained history. Durable recovery and signed
`CheckpointProof` admission must be added before this layer is wired into the
steel thread.

```console
cargo test -p vhalla-ledger --all-targets --offline
cargo clippy -p vhalla-ledger --all-targets --all-features --offline -- -D warnings
```
