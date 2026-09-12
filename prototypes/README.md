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
