# Effects and history prototype

This is throwaway reference code for two open forks in the Valhalla design:

- **Effect runner:** `RemoteRequest` is inert data. Only `LocalPolicy::authorize`
  can construct an `AuthorizedEffect`. Its per-instance counter checks audience
  and policy epoch before returning an `ExecutedEffect`, but the capability is
  cloneable: this model does not enforce single-use ownership. Capability
  construction is kept out of deserialization.
- **History:** `BoundedHistory` is a bounded local append-only view with event
  de-duplication and explicit `Public`/`Private` labels. It evicts old entries
  to remain within count/byte limits. It does not pretend to provide durable
  replication or encryption.

The prototype uses only the Rust standard library and has no transport, model,
filesystem, cryptography, JavaScript, or TypeScript dependency. It answers the
shape question, not production security. The current [policy](../../crates/vhalla-policy/src/lib.rs)
and [host](../../crates/vhalla-host/src/lib.rs) instead consume move-only
capabilities and check explicit full-key grants, context and expiry at execution.
Those in-memory boundaries do not establish restart replay protection, durable
exactly-once effects or process isolation; see the
[readiness plan](../../kb/plans/valhalla-promotion-gates.md).

Run:

```sh
cargo test --manifest-path prototypes/effects/Cargo.toml
```

Recommendation: keep this separation in the production design. Make history a
separate bounded storage policy and make the effect runner a typed process/WASI
boundary rather than a general plugin API.
