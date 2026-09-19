//! The hosted room node: Malachite engines on libp2p networking deciding
//! room-registry batches, with the `Decided`/`Finalized` application
//! boundary gated by the durable commit journal in
//! `vhalla-rooms-consensus`.
//!
//! Every node runs the full `EngineBuilder` stack (network, consensus,
//! sync, request, WAL actors) under [`context::RoomContext`] — the
//! context whose `Value` carries the bounded canonical batch bytes and
//! whose `ValueId` IS the batch's 32-byte value commitment. Proposal
//! parts stream the real batch bytes; `Decided`/`Finalized` certificates
//! name the real commitment and pass through [`cert::verify_commit_certificate`]
//! and the journal before the reply channel is touched. No
//! acknowledgement leaves the node before the durable commit lands.
//!
//! Undecided proposals replay from an application-owned store:
//! `home/store/batches/` retains every verified batch (fsync'd on
//! receipt) and `home/store/seen/` retains one record per observed
//! proposal (height, round, proposer, value id -> polka round), so a
//! restarted node answers `StartedRound` with the real `ProposedValue`s
//! it held rather than an empty set. The WAL also retains full proposed
//! values, votes and locks; the application store re-registers retained
//! batches with the durable adapter. Legacy batches extending the current
//! frontier remain available even if an older binary overwrote their seen
//! metadata. Local metadata is durable before the engine reply. RF2 stream
//! signatures authenticate the complete proposal header and value bytes;
//! recovered proposers rebuild locked-value streams under their own key.
//!
//! `NetGate`, `WalPlan`/`WalFault` and the observation surfaces on
//! [`RoomNode`] are the qualification harness: they drive the runtime
//! partition, WAL fault-injection, and latency/resupply evidence in
//! `tests.rs`.
//!
//! The crate is split for certificate-consumer parity: [`context`] and
//! [`cert`] are portable — a wasm replica can decode canonical
//! certificates, verify them against a trusted validator set, and replay
//! the decided batch bytes — while the engine wiring, durable adapter,
//! service configuration and qualification harness sit behind
//! `cfg(unix)` in [`unix`].

pub mod cert;
pub mod context;

/// The engine wire codec — engine-facing and unix-only.
#[cfg(unix)]
pub mod codec;
/// Node signing surfaces — engine-facing and unix-only.
#[cfg(unix)]
pub mod signing;
#[cfg(unix)]
mod unix;

#[cfg(unix)]
pub use codec::RoomCodec;
pub use context::*;
#[cfg(unix)]
pub use unix::*;
