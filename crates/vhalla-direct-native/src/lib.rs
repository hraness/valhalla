//! Durable local controllers for direct public rooms.
//!
//! New live joins always generate a fresh per-room author. Opening intact local
//! custody is different from importing an archive or restoring a key: neither
//! archive import nor key-only author/owner recovery is provided here. This
//! crate has no transport and never claims remote delivery or global freshness.

#![forbid(unsafe_code)]

mod capacity;
mod follower;
pub use follower::{Follower, FollowerError, FollowerOutcome, FollowerResult, FollowerStatus};
mod replica;
pub use replica::{Replica, ReplicaError, ReplicaFrame, ReplicaPage, ReplicaResult};
mod codec;
mod controller;
mod model;
mod operations;
pub use operations::{OperationEntry, OperationKind, OperationPage};
mod projection;
pub use projection::{
    Projection, ProjectionDirection, ProjectionError, ProjectionResult, ProjectionStatus,
    ProjectionStep,
};
mod runtime;
mod scoped_send;
#[cfg(test)]
mod tests;

use std::{collections::BTreeMap, fs::File, path::PathBuf, sync::Arc};
use vhalla_direct_room::{PinnedGenesis, PolicyPosition, PolicyState, RoomId, VerifiedEvent};
use vhalla_direct_store::Store;
use vhalla_identity::Identity;

use codec::Image;
use runtime::{CachedAuthor, PolicyReplay};
pub use vhalla_direct_store::{Accounting, Limits};

/// Ordinary payloads cannot consume the final control/fault record allowance.
pub const CONTROL_RESERVED_RECORDS: u64 = 64;
/// Ordinary payloads cannot consume the final control/fault byte allowance.
pub const CONTROL_RESERVED_BYTES: u64 = 256 * 1024;
/// Maximum retained ancestry frames replayed in one reconciliation pass.
pub const MAX_REPLAY_FRAMES: usize = 128;
/// Maximum owner-policy commits in one reconciliation pass.
pub const MAX_POLICY_COMMITS: usize = 8;
/// Maximum source records inspected by one filtered message/public page.
pub const MAX_FILTER_SCAN: usize = 128;
/// Current writers plus the local author; removed nonlocal caches are evicted.
pub const MAX_CACHED_AUTHORS: usize = vhalla_direct_room::MAX_WRITERS + 1;

/// A refusal never licenses resetting custody or deleting retained evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Public record validation or authority refusal.
    Protocol(vhalla_direct_room::Error),
    /// Exclusive custody is unavailable or the path is unsafe.
    Custody,
    /// Missing, inconsistent or foreign controller evidence.
    Corrupt,
    /// A prior write may have committed; explicitly reopen the same intact home.
    Uncertain,
    /// Finite retained-data capacity was reached. History remains retained.
    Capacity,
    /// An operation identifier was reused with different intent.
    OperationConflict,
    /// An unfinished operation must be reconciled before reserving another.
    OperationPending,
    /// This joined controller has no retained local owner capability.
    NotOwner,
    /// Lost/cloned signing state or a retained fault prevents new signatures.
    ReadOnly,
    /// Input bounds or a zero operation identifier were refused.
    Bounds,
    /// The operating system could not generate new entropy.
    Entropy,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
impl From<vhalla_direct_room::Error> for Error {
    fn from(value: vhalla_direct_room::Error) -> Self {
        Self::Protocol(value)
    }
}
impl From<vhalla_direct_store::Error> for Error {
    fn from(value: vhalla_direct_store::Error) -> Self {
        match value {
            vhalla_direct_store::Error::Conflict => Self::Corrupt,
            vhalla_direct_store::Error::Refused => Self::Capacity,
            vhalla_direct_store::Error::Uncertain => Self::Uncertain,
            vhalla_direct_store::Error::Corrupt => Self::Corrupt,
        }
    }
}
/// Controller result.
pub type Result<T> = std::result::Result<T, Error>;

/// Local evidence for one message; none of these states implies delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Visibility {
    /// Authorized by the currently observed owner policy; future seals may exclude it.
    Provisional,
    /// Exact ancestry is included in the immutable seal for this message's policy.
    OwnerSealed,
    /// Signed bytes are retained solely as ancestry or fork evidence.
    ContinuityOnly,
    /// Missing policy, ancestry or reconciliation prevents an admission claim.
    Incomplete,
}
/// Current durable outcome of an exact local operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationState {
    /// Current-policy message, retained locally and awaiting any transport.
    Provisional,
    /// Historical message covered by an owner seal.
    OwnerSealed,
    /// Old-policy message excluded by the owner; explicit new send is required.
    NeedsRepost,
    /// Required policy or ancestry is not yet available.
    PendingHistory,
    /// Owner policy is committed locally.
    PolicyApplied,
}
/// Exact signed operation bytes, never a host or recipient acknowledgment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationOutcome {
    /// Caller-selected immutable operation ID.
    pub operation: [u8; 16],
    /// Exact signed frame retained by this operation.
    pub bytes: Vec<u8>,
    /// Current local evidence state.
    pub state: OperationState,
    /// This request reused an already retained operation intent.
    pub exact_retry: bool,
}
/// Local result of retaining a signed remote event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiveOutcome {
    /// Exact content was already retained.
    pub duplicate: bool,
    /// Current authorization/history classification.
    pub visibility: Visibility,
}
/// Local result of observing an authenticated owner policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyOutcome {
    /// Exact content was already retained.
    pub duplicate: bool,
    /// Latest fully reconciled local owner policy.
    pub current: PolicyPosition,
    /// A newer retained owner update still requires history.
    pub pending: Option<PolicyPosition>,
    /// Authenticated owner fork evidence is retained.
    pub forked: bool,
}
/// Honest local controller status; no field asserts network completeness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Status {
    /// Full pinned room commitment.
    pub room: RoomId,
    /// Fresh room-local author key.
    pub author: [u8; 32],
    /// This home was locally created with retained owner custody.
    pub created_here: bool,
    /// Current verified policy.
    pub policy: PolicyPosition,
    /// Highest newer policy awaiting reconciliation.
    pub pending_policy: Option<PolicyPosition>,
    /// Owner equivocation has been observed.
    pub owner_forked: bool,
    /// Capacity or overflow requires preserved-state recovery.
    pub capacity_fenced: bool,
    /// A signed frame outside retained local operations exposed lost author custody.
    pub author_custody_lost: bool,
    /// Unexpected owner signatures exposed lost owner-controller custody.
    pub owner_custody_lost: bool,
    /// An exact event reservation awaits completion.
    pub pending_event_operation: Option<[u8; 16]>,
    /// An exact owner-policy reservation awaits completion.
    pub pending_policy_operation: Option<[u8; 16]>,
    /// Local reservations or known replay work await reconciliation. Repeat
    /// `reconcile`; a gap may also require additional frames. This is not a claim
    /// that all remote author history has been discovered.
    pub reconciliation_pending: bool,
    /// Authority and logical capacity permit a minimum-size fresh message.
    /// A larger message can still exceed its exact byte budget.
    pub can_send: bool,
    /// Retained local storage accounting.
    pub storage: Accounting,
}
/// One retained message and its current local evidence classification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Message {
    /// Local controller cursor, not room-wide order.
    pub cursor: u64,
    /// Authenticated immutable event.
    pub event: VerifiedEvent,
    /// Current local visibility.
    pub visibility: Visibility,
}
/// A bounded scan of local records containing zero or more messages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessagePage {
    /// Local source tip observed for this page.
    pub tip: u64,
    /// Messages found in the bounded scanned range.
    pub messages: Vec<Message>,
    /// Continue at this local cursor even when this page contains no messages.
    pub next: Option<u64>,
}
/// Only authenticated public wire records may be exposed to a future transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicRecordKind {
    /// Pinned genesis.
    Genesis,
    /// Authenticated owner policy, possibly awaiting ancestry.
    Policy,
    /// Authenticated event, possibly continuity/fork evidence.
    Event,
}
/// A public record filtered from the trusted local controller journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicRecord {
    /// Source-local cursor; never a globally ordered sequence.
    pub cursor: u64,
    /// Exact public record type.
    pub kind: PublicRecordKind,
    /// Exact signed public bytes.
    pub bytes: Vec<u8>,
}
/// A bounded filtered local page. This is not an authenticated network snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicPage {
    /// Source-local retained tip.
    pub tip: u64,
    /// Public records within the bounded scan.
    pub records: Vec<PublicRecord>,
    /// Continuation cursor, including across an empty filtered page.
    pub next: Option<u64>,
}

/// One exclusive room controller, retaining the account and fresh author locks.
pub struct RoomSession {
    // Rust drops fields in declaration order. Release storage and the room key
    // before the outer room lock, and retain account custody through all of it.
    store: Store,
    author: Identity,
    home: PathBuf,
    genesis: PinnedGenesis,
    created_here: bool,
    creation_nonce: [u8; 32],
    policy: PolicyState,
    author_cache: BTreeMap<[u8; 32], CachedAuthor>,
    policy_replay: Option<PolicyReplay>,
    author_rotation: usize,
    #[cfg(test)]
    full_replays: usize,
    #[cfg(test)]
    frame_reads: usize,
    image: Image,
    image_bytes: Vec<u8>,
    poisoned: bool,
    directory: File,
    lock: File,
    account: Arc<Identity>,
}
