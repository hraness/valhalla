# Authenticated provenance prototype

This disposable Rust crate models a narrow provenance boundary for Valhalla:

- an origin signs a canonical module manifest containing a SHA-256 content hash,
  version, source locator, validity interval, and origin key;
- a bounded registry checks the signature, expiry, and caller-supplied source/origin
  binding before admission;
- origin-signed revocations are authenticated and sequence-scoped;
- runtime actors sign lifecycle receipts, with replay and equivocation detection;
- manifest and receipt retention are bounded, and receipt capacity fails closed.

The transcript uses domain separation and length-prefixed fields so changes to a
source locator, artifact bytes, or lifecycle fields cannot silently collide. The
prototype does not provide durable storage, distributed convergence, key rotation,
threshold authorization, a WASM loader, or a consensus/blockchain receipt log.

Run:

```sh
cargo test --manifest-path prototypes/provenance/Cargo.toml
cargo clippy --manifest-path prototypes/provenance/Cargo.toml --all-targets --offline -- -D warnings
```
