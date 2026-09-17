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
| [`checkpoint-proof`](checkpoint-proof/README.md) | Bounded Ed25519 checkpoint certificates, configuration binding, and local conflict observation |
| [`checkpoint-ledger`](checkpoint-ledger/README.md) | Certificate/history checks, conditional bundle/pin persistence, crash recovery, and optional Unix storage |
| `ecology` | Deterministic Platonik-style composition and lineage replay |
| `immune-cancer` | Quarantine, appeal, revocation, and runaway-lineage containment |
| [`native-quic`](native-quic/README.md) | Actual bounded QUIC exchange between two native processes, loopback-only fixture identities |
| [`browser-records`](browser-records/README.md) | Bounded acknowledged records and an actual loopback Rust/WASM-to-native WebRTC fixture |
| [`agent-portraits`](agent-portraits/README.md) | Deterministic owner-family/agent SVG grammar, diversity and presentation limits |
| [`social-lifecycle`](social-lifecycle/README.md) | Owner-bound agent lifecycles, sealed history, rotation and unavailable recovery |
| [`social-reducer`](social-reducer/README.md) | Causal social registers, owner contribution and explicit local eligibility |
| [`social-sync`](social-sync/README.md) | Bounded anti-entropy, protected control delivery and monotonic complete archives |
| [`social-facets`](social-facets/README.md) | Exact signed mention/tag spans, legacy compatibility and ASCII normalization |
| [`social-discovery`](social-discovery/README.md) | Scanner/index equivalence, bounded ranking, corpus measurements and cursor expiry |
| [`social-attention`](social-attention/README.md) | Stable notification groups, exact revision read marks and bounded unknown precision |
| [`social-retrieval`](social-retrieval/README.md) | Chosen-provider hint limits, poisoned candidates and separate control credit |
| [`discovery-parity`](discovery-parity/README.md) | Native/WASM execution of the same signed discovery and attention fixture |
| [`room-registry`](room-registry/README.md) | Sequential shared-name allocation, owner creation allowance, signed proposals, bounded search and partition counterexamples; consensus and social admission remain pending |
| `extension-interop` | Opaque future objects, negotiation, and downgrade resistance |
| Existing forks | `wire-format`, `transport`, `discovery`, `browser`, `privacy`, `effects`, and `replication` |

Fetch locked dependencies first when running on a new machine. The native QUIC
experiment opens loopback UDP sockets and starts owned child processes. The
social-retrieval fixture uses explicitly pinned native loopback peers; discovery
parity executes an actual WASM module. Other references state their model or native
boundary in their guides. The nested browser-record fixture has separate native/WASM
and actual-browser gates in its README. Run every top-level prototype with:

```console
for manifest in prototypes/*/Cargo.toml; do
  cargo fmt --manifest-path "$manifest" -- --check
  cargo test --manifest-path "$manifest" --locked --offline
  cargo clippy --manifest-path "$manifest" --all-targets --locked --offline -- -D warnings
done
```

Passing a prototype test is evidence about its stated boundary only. It is not production cryptography, a consensus proof, a security audit, or evidence that an agent is autonomous.
