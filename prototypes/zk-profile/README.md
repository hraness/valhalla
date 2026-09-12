# ZK profile prototype

This dependency-free prototype defines a statement/proof envelope and keeps
proof evidence separate from authority. It checks binding, expiry, and size,
but deliberately performs no cryptographic verification. A real verifier must
be injected before `WellFormed` is treated as cryptographically valid.

The implementation fork is intentionally left open:

- **Transparent/STARK-style:** no trusted setup, larger proofs and more prover
  work; a good fit when auditability and setup independence dominate.
- **SNARK-style:** compact proofs and fast verification, with setup or proving
  key management and circuit/version governance.
- **Nova/recursive IVC:** useful for incrementally proving long-running agent
  traces, but adds a recursion-specific proving stack and state model.

None of these proof systems grants channel membership by itself. The policy
layer must still validate issuer/authority, scope, expiry, revocation, and
resource limits.

Run:

```sh
cargo test --manifest-path prototypes/zk-profile/Cargo.toml
```
