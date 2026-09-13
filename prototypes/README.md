# Disposable Valhalla prototypes

These standalone Rust crates are reference experiments for unresolved protocol forks. They are excluded from the production workspace and may be replaced after design review.

| Prototype | Decision surface |
| --- | --- |
| `botcaptcha` | Signed, context-bound SHA-256 challenge work and one-use replay |
| `attestation` | Portable, hardware-key, and TEE/RATS evidence policy |
| `witness` | Bounded deterministic program execution and work receipts |
| `ledger` | Signed content-addressed event DAG, equivocation, heads, retention |
| `game-session` | Single-host versus quorum checkpoint authority |
| `settlement` | Voucher consumption, quorum finality, and light-client continuity |
| `zk-profile` | Transparent/SNARK/Nova proof envelopes separated from authority |
| `control-plane` | Protected policy authority versus hostile execution requests |
| `membrane` | Realm admission, capability boundaries, queues, and revocation |
| `genome-bundle` | Versioned agent manifests, component imports, budgets, rollback |
| `module-transfer` | Provenance-bound horizontal module transfer and downgrade rejection |
| `provenance` | Authenticated module manifests, revocations, lifecycle receipts, and bounded replay/equivocation checks |
| `symbiosis` | Typed contracts, obligations, expiry, and bounded signaling |
| `liveness` | Partition-aware leases and suspicion without authority transfer |
| `multicell` | Differentiated members, budgets, checkpoints, and graceful failure |
| `checkpoint-root` | Derived state roots, canonical history, and checkpoint ancestry |
| `ecology` | Deterministic Platonik-style composition and lineage replay |
| `immune-cancer` | Quarantine, appeal, revocation, and runaway-lineage containment |
| `extension-interop` | Opaque future objects, negotiation, and downgrade resistance |
| Existing forks | `wire-format`, `transport`, `discovery`, `browser`, `privacy`, `effects`, and `replication` |

Run every prototype with:

```console
for manifest in prototypes/*/Cargo.toml; do
  cargo fmt --manifest-path "$manifest" -- --check
  cargo test --manifest-path "$manifest" --offline
  cargo clippy --manifest-path "$manifest" --all-targets --offline -- -D warnings
done
```

Passing a prototype test is evidence about its stated boundary only. It is not production cryptography, a consensus proof, a security audit, or evidence that an agent is autonomous.
