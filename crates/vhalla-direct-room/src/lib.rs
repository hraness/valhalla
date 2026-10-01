#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Independently pinned, owner-authorized public rooms.
//!
//! Signatures authenticate bytes. Admission additionally requires a pinned
//! genesis, an observed owner policy and author continuity. The native controller
//! must persist prepared transitions before publishing their effects. These
//! records are a new protocol; legacy consensus-room records are not converted.

extern crate alloc;

mod codec;
mod history;
mod records;
mod state;

pub use history::{
    HistoryRequirement, SealedHistoryVerifier, VerifiedHistoricalEvent, MAX_CHAIN_PAGE,
};
pub use records::{
    EventClaims, EventId, GenesisClaims, PinnedGenesis, PolicyClaims, PolicyId, RoomId, SealHead,
    SignedEvent, SignedGenesis, SignedPolicy, Text, UnsignedEvent, UnsignedGenesis, UnsignedPolicy,
    VerifiedEvent, VerifiedGenesis, VerifiedPolicy, MAX_EVENT_BYTES, MAX_GENESIS_BYTES,
    MAX_POLICY_BYTES, MAX_TEXT_BYTES, MAX_WRITERS,
};
pub use state::{
    AnchorReconciliation, AuthorChain, AuthorHead, ClosedPolicy, PolicyPosition, PolicyState,
    PreparedContinuity, PreparedEvent, PreparedPolicy, MAX_OBSERVED_POLICIES, MAX_SEALED_AUTHORS,
};

/// Structural, cryptographic, policy or continuity refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A fixed bound was exceeded or a required value was empty.
    Bounds,
    /// A bounded retained-author or unresolved-observation index is full.
    Capacity,
    /// Noncanonical framing, ordering, text or trailing bytes.
    Encoding,
    /// Wrong protocol version or record kind.
    Protocol,
    /// Invalid or weak Ed25519 public key.
    Key,
    /// The custodian's public key differs from the claimed signer.
    Signer,
    /// Strict signature verification failed.
    Signature,
    /// The full room ID differs from the pinned genesis.
    Scope,
    /// The signer is not the pinned room owner.
    Owner,
    /// Unknown, stale or incompatible owner policy.
    Policy,
    /// A newer authenticated owner policy is awaiting history verification.
    PolicyPending,
    /// The author is absent from the applicable writer list.
    Author,
    /// Invalid sequence or initial predecessor shape.
    Sequence,
    /// The exact admitted record was offered again.
    Duplicate,
    /// Missing predecessor or incomplete ancestry proof.
    Gap,
    /// Competing signed content occupies the same sequence or revision.
    Fork,
    /// An older record requires retained-history reconciliation.
    Replay,
    /// The sequence or revision has no successor.
    Exhausted,
    /// The state changed after a transition was prepared.
    StaleBase,
    /// The owner policy changed after an event was prepared.
    StalePolicy,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl core::error::Error for Error {}
