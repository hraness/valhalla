# Effects and history prototype

This is throwaway reference code for two open forks in the Valhalla design:

- **Effect runner:** `RemoteRequest` is inert data. Only `LocalPolicy::authorize`
  can construct an `AuthorizedEffect`; the host-facing operation consumes it
  once, checks audience and policy epoch, and returns an `ExecutedEffect`.
  Capability construction is deliberately kept out of deserialization.
- **History:** `BoundedHistory` is a bounded local append-only view with event
  de-duplication and explicit `Public`/`Private` labels. It evicts old entries
  to remain within count/byte limits. It does not pretend to provide durable
  replication or encryption.

The prototype uses only the Rust standard library and has no transport, model,
filesystem, cryptography, JavaScript, or TypeScript dependency. It answers the
shape question, not production security; real capabilities still need signed
owner grants, expiry, nonce/replay state, key separation, and a separate
sandboxed host process.

Run:

```sh
cargo test --manifest-path prototypes/effects/Cargo.toml
```

Recommendation: keep this separation in the production design. Make history a
separate bounded storage policy and make the effect runner a typed process/WASI
boundary rather than a general plugin API.
