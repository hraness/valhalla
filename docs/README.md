# Valhalla docs

Valhalla is in development. This is a small guide to the current code and the
design work behind it; the plans describe proposed behavior as well as accepted
decisions.

## Run and check

Install Rust and Cargo, then run these from the repository root:

```console
cargo run -p vhalla-steel-thread --locked
cargo test --workspace --all-targets --locked
cargo test --workspace --doc --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

The demo is entirely in memory. It delivers a signed envelope through a bounded
queue, verifies the full key and session context, applies an explicit local
grant, and returns an in-memory execution receipt. The session retains replay
state across messages; policy and expiry are checked again at execution.
The first `vhalla` identity commands are available through Cargo; rooms and
networking are not connected to the CLI yet. See the
[identity guide](../crates/vhalla-identity/README.md) for explicit initialization
and reopening of a private key directory.

Signed framing is now v2 and rejects the earlier unversioned format. Restart
freshness, durable effects and real browser connectivity remain unqualified.

## Find the code

| Area | Entry point |
| --- | --- |
| Protocol values and bounded parsing | [core](../crates/vhalla-core/src/lib.rs), [wire](../crates/vhalla-wire/src/lib.rs) |
| Signatures and replay checks | [crypto](../crates/vhalla-crypto/src/lib.rs) |
| Fresh explicitly paired chat sessions | [session](../crates/vhalla-session/README.md), experimental and awaiting independent protocol review |
| Native key custody and identity CLI | [identity](../crates/vhalla-identity/README.md), experimental Unix private-file storage |
| Local authority and effects | [policy](../crates/vhalla-policy/src/lib.rs), [host](../crates/vhalla-host/src/lib.rs) |
| In-memory delivery and end-to-end tests | [transport](../crates/vhalla-transport/README.md), [steel thread](../crates/vhalla-steel-thread/tests/e2e.rs) |
| Real two-process transport experiment | [native QUIC](../prototypes/native-quic/README.md), loopback-only with public fixture keys |
| Derived roots and snapshot recovery | [ledger](../crates/vhalla-ledger/README.md) |
| Certified history, crash recovery, and optional native storage experiment | [checkpoint ledger](../prototypes/checkpoint-ledger/README.md) |
| Disposable design experiments | [prototype index](../prototypes/README.md) |

The isolated ledger has no policy/host integration. Its snapshots are
unauthenticated bytes, and the checkpoint certificate experiment is not a
consensus protocol. Those boundaries are tracked in the promotion plan.

## Read the design

- [Security and architecture](../kb/plans/valhalla-security-first-design.md): owner control, Rust boundaries, portability, and the threat model.
- [Implementation and promotion gates](../kb/plans/valhalla-promotion-gates.md): current evidence, missing layers, and next targets.
- [Botcaptcha and games](../kb/plans/valhalla-botcaptcha-ledger-games.md): program work, receipts, and multiplayer ideas.
- [Blockchain tradeoffs](../kb/plans/valhalla-blockchain-architecture.md): trust, agreement, and possible settlement designs.
- [Agent composition](../kb/plans/valhalla-eukaryotic-transition.md): organisms, cooperation, and the Platonik-inspired experiments.

The plans live in the [Wordcell vault](../kb/index.md). They preserve design
history; use the promotion plan to check implementation status.

## Marketing page

[vhalla.com](https://vhalla.com) serves the static HTML, CSS, and self-hosted font
in [site/](../site/). It has no JavaScript, tracking, build dependencies, or backend.
See the [site guide](../site/README.md) for preview and deployment.
