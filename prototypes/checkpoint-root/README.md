# Checkpoint-root prototype

This disposable Rust crate answers one narrow design question: can a
checkpoint name a head and a state root that a peer can derive from bounded
history, while preventing rollback to a competing branch?

`History` content-addresses each event with a domain-separated SHA-256
transcript. `state_root(head)` hashes the canonical ancestor chain, and
`accept_checkpoint` checks the derived root, exact height, and descendant
relationship with the previously accepted head. The event store has an
explicit maximum size and rejects unknown parents, malformed IDs, and
oversized payloads.

This is a reference model rather than a consensus implementation. It has one
parent per event, in-memory storage, no signatures or authorisation, no
durable receipt log, and no distributed finality. A production design must
bind roots to authenticated event receipts, define retention and snapshot
proofs, and obtain agreement from a quorum or another explicit authority.

Run it with:

```console
cargo fmt --manifest-path prototypes/checkpoint-root/Cargo.toml -- --check
cargo test --manifest-path prototypes/checkpoint-root/Cargo.toml --offline
cargo clippy --manifest-path prototypes/checkpoint-root/Cargo.toml --all-targets --offline -- -D warnings
```
