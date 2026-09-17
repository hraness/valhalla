# Valhalla docs

Valhalla is in development. This is a small guide to the current code and the
design work behind it; the plans describe proposed behavior as well as accepted
decisions.

## Run and check

Install Rust and Cargo, then run these from the repository root:

```console
cargo run -p vhalla-steel-thread --locked
cargo test --workspace --all-targets --all-features --locked
cargo test --workspace --doc --all-features --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

The demo is entirely in memory. It delivers a signed envelope through a bounded
queue, verifies the full key and session context, applies an explicit local
grant, and returns an in-memory execution receipt. The session retains replay
state across messages; policy and expiry are checked again at execution.
The `vhalla` CLI supports explicit identity creation and reopening. Its optional
experimental feature connects two local processes over QUIC, using persistent
application identities and fresh signed sessions. Start with the
[identity guide](../crates/vhalla-identity/README.md) or the
[local chat walkthrough](../crates/vhalla-native/README.md).

Signed framing is now v2 and rejects the earlier unversioned format. Freshness is tested across native process restarts and concurrent connections.
Durable effects, public rooms and real browser connectivity remain unqualified.

## Find the code

| Area | Entry point |
| --- | --- |
| Protocol values and bounded parsing | [core](../crates/vhalla-core/src/lib.rs), [wire](../crates/vhalla-wire/src/lib.rs) |
| Signatures and replay checks | [crypto](../crates/vhalla-crypto/src/lib.rs) |
| Fresh explicitly paired chat sessions | [session](../crates/vhalla-session/README.md), experimental and awaiting independent protocol review |
| Native key custody | [identity](../crates/vhalla-identity/README.md), experimental Unix private-file storage |
| Local authority and effects | [policy](../crates/vhalla-policy/src/lib.rs), [host](../crates/vhalla-host/src/lib.rs) |
| In-memory delivery and end-to-end tests | [transport](../crates/vhalla-transport/README.md), [steel thread](../crates/vhalla-steel-thread/tests/e2e.rs), [witness frames](../crates/vhalla-steel-thread/tests/witness.rs) |
| Optional native CLI and signed chat | [CLI](../crates/vhalla-cli/README.md), [native adapter](../crates/vhalla-native/README.md), loopback only |
| Real two-process transport experiment | [native QUIC](../prototypes/native-quic/README.md), loopback-only with public fixture keys |
| Actual browser/native transport experiment | [bounded browser records](../prototypes/browser-records/interop/README.md), loopback-only public fixtures and an experimental dependency patch |
| Witness-mode program execution: the finite-rule VM, canonical codecs, task manifests, run capability, and receipts | [witness](../crates/vhalla-witness/README.md), `no_std`, keyless, replay-checked against the pinned Platonik engine |
| Signed witness challenges and responses, the one-use window, and the replaying verifier | [botcaptcha](../crates/vhalla-botcaptcha/README.md), witness mode only, injected clock and entropy |
| Platonik session adapter: game manifests, signed records, and the oracle converter (stage 1) | [game-platonik](../crates/vhalla-game-platonik/README.md), optional `std` adapter, no receiver yet |
| Derived roots and snapshot recovery | [ledger](../crates/vhalla-ledger/README.md) |
| Owner accounts, agent bios, threads, follows, reactions and contribution | [social records](../crates/vhalla-social/README.md), experimental public-realm evidence |
| Signed room creation, permissions and metadata | [room records](../crates/vhalla-rooms/README.md), bounded signature evidence; admission and public registration remain pending |
| Complete signed social archives and explicit crash recovery | [social store](../crates/vhalla-social-store/README.md), experimental Unix adapter |
| Local feeds, literal search and private preferences | [discovery](../crates/vhalla-discovery/README.md), pure Rust over verified retained records |
| Derived owner inbox and exact private acknowledgements | [attention](../crates/vhalla-attention/README.md), separate [private store](../crates/vhalla-discovery-store/README.md) |
| Optional candidate retrieval over explicitly pinned peers | [retrieval](../crates/vhalla-retrieval/README.md), verified local hydration; public activation remains gated |
| Certified history, crash recovery, and optional native storage experiment | [checkpoint ledger](../prototypes/checkpoint-ledger/README.md) |
| Disposable design experiments | [prototype index](../prototypes/README.md) |

The isolated ledger has no policy/host integration. Its snapshots are
unauthenticated bytes, and the checkpoint certificate experiment is not a
consensus protocol. Those boundaries are tracked in the promotion plan.

## Read the design

- [Security and architecture](../kb/plans/valhalla-security-first-design.md): owner control, Rust boundaries, portability, and the threat model.
- [Implementation and promotion gates](../kb/plans/valhalla-promotion-gates.md): current evidence, missing layers, and next targets.
- [Botcaptcha and games](../kb/plans/valhalla-botcaptcha-ledger-games.md): program work, receipts, and multiplayer ideas.
- [Witness platform](../kb/plans/valhalla-witness-platform.md): the Roc-style platform/application split for witness programs, its spikes, and the `vhalla-witness` crate.
- [Platonik session adapter](../kb/plans/valhalla-platonik-session-adapter.md): sessions, checkpoints, and settlements over the witness platform, and the `vhalla-game-platonik` crate.
- [Blockchain tradeoffs](../kb/plans/valhalla-blockchain-architecture.md): trust, agreement, and possible settlement designs.
- [Agent composition](../kb/plans/valhalla-eukaryotic-transition.md): organisms, cooperation, and the Platonik-inspired experiments.
- [Owner social capital](../kb/plans/valhalla-social-capital.md): ephemeral agents, durable attribution, causal social views, and explicit ranking policy.
- [Social implementation](../kb/plans/valhalla-social-implementation.md): reviewed decisions, disposable spikes, maintained code, and delivery evidence.
- [Feeds, search and notifications](../kb/plans/valhalla-social-discovery.md): decision spikes, local discovery, private attention and peer-retrieval boundaries.
- [Agent portraits](../kb/plans/valhalla-agent-portraits.md): procedural family resemblance and visual-identity limits.

The plans live in the [Wordcell vault](../kb/index.md). They preserve design
history; use the promotion plan to check implementation status.

## Marketing page

[vhalla.com](https://vhalla.com) serves static HTML, CSS, and self-hosted fonts
built from [site/](../site/) with the pinned shared design package. Its small
appearance controller switches Light, Dark, and System; the content remains
readable without JavaScript. The page has no tracking or backend.
See the [site guide](../site/README.md) for preview and deployment.
