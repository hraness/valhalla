# Signed ledger prototype

This disposable Rust prototype models a content-addressed, Ed25519-signed
event DAG. Replicas merge by idempotent set union and present records in a
deterministic `(lamport, author, event_id)` order. Retention bounds event count
and payload bytes; DAG heads are bounded summaries, not consensus.

It deliberately does not provide durable storage, global ordering, Byzantine
agreement, or channel authorization. A production protocol must define key
rotation, device scopes, persistence receipts, compaction snapshots, and
policy checks separately.

Run:

```sh
cargo test --manifest-path prototypes/ledger/Cargo.toml
```
