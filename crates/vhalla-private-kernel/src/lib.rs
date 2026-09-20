#![forbid(unsafe_code)]

//! Private MLS custody with typed owner authorization and encrypted transactions.
//!
//! This kernel implements a fixed owner and up to sixteen active devices.
//! Fresh joins use an explicit owner-endorsed roster checkpoint; existing members
//! must accept every control in order. Owner credential renewal is supported;
//! owner-device succession remains separate recovery work. There is no public directory, network,
//! host execution, raw signer export, ratchet backup/clone, or shipping activation.
//!
//! The injected backend receives encrypted bytes only and must atomically persist
//! next current state with immutable outbox/inbox records. Ciphertext/plaintext
//! is released only after successful publication and authenticated retained read.
//! Native/IndexedDB backend qualification is a separate gate. AEAD and monotone
//! local state cannot detect coherent rollback, cloned custody keys or a backend
//! that lies about durability. Never initialize a replacement after uncertain I/O.

mod account_custody;
mod checkpoint;
mod codec;
mod contact;
mod engine;
mod model;
mod packets;
pub mod storage;
mod transport;
pub use contact::{
    ConfidentialContactOffer, ContactBootstrap, MAX_CONTACT_OFFERS, MAX_CONTACT_TTL,
};
pub use transport::{CommittedEncryptedControl, EncryptedControlPage};

pub use engine::{Kernel, MemberDraft, MembershipSnapshot, OwnerDraft};
pub use vhalla_private_protocol as protocol;

use protocol::{Key, PrivateRoomScope};
use zeroize::Zeroizing;

/// Maximum current-state plaintext; histories are separate immutable records.
pub const MAX_STATE_BYTES: usize = 4 * 1024 * 1024;
/// Maximum encrypted current image, including nonce and authentication tag.
pub const MAX_IMAGE_BYTES: usize = MAX_STATE_BYTES + 40;
/// Maximum exact MLS frame accepted before decoding or cloning.
pub const MAX_WIRE_BYTES: usize = 128 * 1024;
/// Maximum inert application content in one MLS message.
pub const MAX_BODY_BYTES: usize = 4096;
/// Maximum encrypted immutable record; sufficient for one bounded Commit/Welcome.
pub const MAX_STORED_RECORD_BYTES: usize = 2 * MAX_WIRE_BYTES + 4096 + 40;
/// Maximum independent records returned in one history page.
pub const MAX_PAGE_RECORDS: usize = 16;
/// Maximum decoded exported payload bytes returned in one history page.
pub const MAX_PAGE_BYTES: usize = 512 * 1024;
/// Maximum immutable records atomically appended with one current-state image.
/// Owner control publication reserves Control, Outbox and Operation together.
pub const MAX_TRANSACTION_RECORDS: usize = 3;
/// Explicit active-device capacity, including the fixed owner device.
pub const MAX_MEMBERS: usize = 16;

/// Bounded refusal. No error grants permission to reset or clone retained state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Explicit byte/count limit exceeded.
    Bounds,
    /// Canonical encoding or required record is malformed.
    Encoding,
    /// Secure OS/browser entropy unavailable; no fallback is used.
    Entropy,
    /// Ciphertext, retained context or signature failed authentication.
    Authentication,
    /// Full anchor/room/account/device binding differs.
    Scope,
    /// Current owner, member, credential or proposal authorization failed.
    Policy,
    /// Caller clock regressed, validity expired, or required interval is invalid.
    Time,
    /// Operation requires roster recovery or another not-yet-supported lifecycle.
    Unsupported,
    /// Existing operation differs or current image no longer matches exactly.
    Conflict,
    /// Interrupted or uncertain storage access requires exact-store reopen.
    NeedsReopen,
    /// Required durable state/record is absent; never invent a new sequence.
    Missing,
    /// OpenMLS rejected the isolated operation.
    Mls,
    /// The backend explicitly refused a transaction without effects.
    Refused,
    /// A retained owner-signed fork permits history/evidence reads only.
    Quarantined,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
impl From<protocol::Error> for Error {
    fn from(value: protocol::Error) -> Self {
        match value {
            protocol::Error::Bounds => Self::Bounds,
            protocol::Error::Time => Self::Time,
            protocol::Error::Signature | protocol::Error::Key | protocol::Error::Signer => {
                Self::Authentication
            }
            _ => Self::Encoding,
        }
    }
}
pub(crate) type Result<T> = std::result::Result<T, Error>;

/// Full caller-selected custody context. It is not a public routing address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Context {
    /// Full private room and exact signed anchor pin.
    pub scope: PrivateRoomScope,
    /// Exact local account associated with the device enrollment.
    pub account: Key,
    /// Exact local MLS device signature key; never a truncated leaf index.
    pub device: Key,
}
impl Context {
    pub(crate) fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(128);
        bytes.extend(self.scope.room.as_bytes());
        bytes.extend(self.scope.anchor.as_bytes());
        bytes.extend(self.account.as_bytes());
        bytes.extend(self.device.as_bytes());
        bytes
    }
}

/// Caller-retained storage secret. Never exported, logged, cloned publicly or
/// generated from an account label. A fresh device must not reuse a live image.
///
/// ```compile_fail
/// use vhalla_private_kernel::StorageKey;
/// fn copy(key: &StorageKey) -> StorageKey { key.clone() }
/// ```
/// ```compile_fail
/// use vhalla_private_kernel::StorageKey;
/// fn expose(key: &StorageKey) { println!("{key:?}"); }
/// ```
pub struct StorageKey(Zeroizing<[u8; 32]>);
impl StorageKey {
    /// Import an explicit custody-provided secret; all-zero fixture/default keys
    /// are refused. The caller must retain recovery custody independently.
    pub fn from_secret(secret: [u8; 32]) -> Result<Self> {
        if secret == [0; 32] {
            return Err(Error::Authentication);
        }
        Ok(Self(Zeroizing::new(secret)))
    }
    pub(crate) fn duplicate(&self) -> Self {
        Self(Zeroizing::new(*self.0))
    }
}

/// Full nonzero caller-chosen operation ID. Reuse requires exactly identical
/// typed inputs; a collision never replaces an existing record or ratchet step.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct OperationId(pub(crate) [u8; 16]);
impl OperationId {
    /// Parse a nonzero operation ID; this does not authorize an operation.
    pub fn from_bytes(bytes: [u8; 16]) -> Result<Self> {
        if bytes == [0; 16] {
            return Err(Error::Encoding);
        }
        Ok(Self(bytes))
    }
    /// Borrow the complete operation ID.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Explicit locally retained lifecycle status, never a remote delivery claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Fresh owner genesis with no invitee admitted yet.
    OwnerGenesis,
    /// Fresh enrolled member device, waiting for a pinned owner invitation.
    AwaitingWelcome,
    /// Owner with at least one other currently admitted device.
    OwnerJoined,
    /// Invitee has durably consumed its Welcome and KeyPackage.
    MemberJoined,
    /// Owner alone after an accepted control, including renewal; later joins are allowed.
    OwnerAfterRemoval,
    /// Invitee removed; retained history remains readable but new sends refuse.
    Removed,
}

/// Exact type of a retained outbox artifact, without a delivery claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboxKind {
    /// Secret issuance metadata only; recover keys through the dedicated offer API.
    ContactOffer,
    /// Complete encrypted one-use bootstrap request.
    ContactRequest,
    /// Complete encrypted recipient-bound invitation response.
    ContactInvitation,
    /// Recipient enrollment plus exact one-use MLS KeyPackage.
    KeyPackage,
    /// Owner-signed invitation/control plus exact Commit and Welcome.
    Invitation,
    /// One encrypted inert application message.
    Application,
    /// Owner-signed removal control plus exact MLS Commit.
    Removal,
    /// Same-device owner enrollment renewal plus exact MLS Commit.
    OwnerUpdate,
}

/// Output reloaded only after the encrypted transaction was confirmed complete.
/// No public constructor can turn a prepared candidate into this type.
///
/// ```compile_fail
/// use vhalla_private_kernel::{CommittedOutbox, OperationId, OutboxKind};
/// let fabricated = CommittedOutbox {
///     sequence: 1,
///     operation: OperationId::from_bytes([1; 16]).unwrap(),
///     kind: OutboxKind::Application,
///     bytes: b"uncommitted".to_vec(),
/// };
/// ```
#[derive(Clone)]
pub struct CommittedOutbox {
    pub(crate) sequence: u64,
    pub(crate) operation: OperationId,
    pub(crate) kind: OutboxKind,
    pub(crate) bytes: Vec<u8>,
}
impl CommittedOutbox {
    /// Local immutable outbox position; does not acknowledge receipt by a peer.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    /// Original complete operation ID.
    pub fn operation(&self) -> OperationId {
        self.operation
    }
    /// Typed exported artifact kind.
    pub fn kind(&self) -> OutboxKind {
        self.kind
    }
    /// Exact retained artifact bytes. Retries never regenerate MLS ciphertext.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Closed contiguous outbox entry. Secret offers have no generic byte accessor.
pub enum OutboxEntry {
    /// Retained ordinary artifact. Bootstrap ciphertext still requires explicit delivery authority.
    Artifact(CommittedOutbox),
    /// Secret issuance exists, without exposing either one-use direction key.
    ConfidentialOffer {
        /// Immutable local outbox position.
        sequence: u64,
        /// Local issuance operation; never a transferable admission authority.
        operation: OperationId,
    },
}
impl OutboxEntry {
    /// Ordinary retained artifact, or no exportable artifact for secret issuance.
    /// Callers must handle confidential metadata explicitly; absence is not an
    /// empty ciphertext or a missing outbox position.
    pub fn artifact(&self) -> Option<&CommittedOutbox> {
        match self {
            Self::Artifact(artifact) => Some(artifact),
            Self::ConfidentialOffer { .. } => None,
        }
    }
    /// Exact retained index, including confidential issuance metadata.
    pub fn sequence(&self) -> u64 {
        match self {
            Self::Artifact(a) => a.sequence(),
            Self::ConfidentialOffer { sequence, .. } => *sequence,
        }
    }
    /// Original operation, never a token permitting another operation.
    pub fn operation(&self) -> OperationId {
        match self {
            Self::Artifact(a) => a.operation(),
            Self::ConfidentialOffer { operation, .. } => *operation,
        }
    }
    /// Closed artifact classification; ContactOffer never carries key bytes here.
    pub fn kind(&self) -> OutboxKind {
        match self {
            Self::Artifact(a) => a.kind(),
            Self::ConfidentialOffer { .. } => OutboxKind::ContactOffer,
        }
    }
}

/// Authenticated message read from a committed encrypted inbox. Its bytes are
/// inert content and never instructions or authority to run host tools.
#[derive(Clone)]
pub struct ReceivedMessage {
    pub(crate) sequence: u64,
    pub(crate) sender: Key,
    pub(crate) body: Vec<u8>,
}
impl ReceivedMessage {
    /// Local immutable inbox position.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    /// Exact admitted MLS device key authenticated by the accepted message.
    pub fn sender(&self) -> Key {
        self.sender
    }
    /// Inert retained application content.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// A bounded immutable outbox page from a snapshotted local head.
pub struct OutboxPage {
    /// Local head observed before reading the immutable prefix.
    pub head: u64,
    /// Next exclusive cursor, or none when this snapshot is exhausted.
    pub next: Option<u64>,
    /// Bounded retained output records in ascending order.
    pub records: Vec<OutboxEntry>,
}

/// A bounded immutable inbox page from a snapshotted local head. These are
/// previously authenticated messages, including history retained after removal.
pub struct InboxPage {
    /// Local head observed before reading the immutable prefix.
    pub head: u64,
    /// Next exclusive cursor, or none when this snapshot is exhausted.
    pub next: Option<u64>,
    /// Bounded retained messages in ascending order.
    pub records: Vec<ReceivedMessage>,
}

/// Public local status. No private key, plaintext provider state or remote
/// acknowledgement is exposed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Status {
    /// Full exact custody binding used for reopen.
    pub context: Context,
    /// Local retained lifecycle state.
    pub phase: Phase,
    /// Confirmed MLS epoch, zero before member join.
    pub epoch: u64,
    /// Current accepted owner control sequence.
    pub control_sequence: u64,
    /// Exact accepted control sequence and signed ID, suitable as a page cursor.
    pub control_floor: protocol::ControlFloor,
    /// Published local outbox count.
    pub outbox_head: u64,
    /// Published local application inbox count.
    pub inbox_head: u64,
    /// Earliest known control predecessor; earlier history is not claimed.
    pub history_base: protocol::ControlFloor,
    /// Canonical current roster commitment; not a public identity proof.
    pub roster: [u8; 32],
    /// Number of current MLS members including the owner.
    pub members: usize,
    /// A confirmed retained owner fork prevents all new MLS operations.
    pub quarantined: bool,
}

/// Explicit consent to share these bytes with one exact locally observed roster.
/// A changed room, author, epoch or roster requires a newly prepared draft. The
/// private fields prevent a caller from silently rebinding an existing draft.
pub struct MessageDraft {
    context: Context,
    epoch: u64,
    roster: [u8; 32],
    body: Zeroizing<Vec<u8>>,
}
impl MessageDraft {
    /// Full room/anchor and author device selected for this draft.
    pub fn context(&self) -> Context {
        self.context
    }
    /// Exact accepted membership epoch when the draft was prepared.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    /// Complete canonical roster commitment.
    pub fn roster(&self) -> &[u8; 32] {
        &self.roster
    }
    /// Explicit inert bytes being released; never executed by this kernel.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// One immutable accepted control, available only after durable publication.
pub struct CommittedControl {
    pub(crate) floor: protocol::ControlFloor,
    pub(crate) bytes: Vec<u8>,
}
impl CommittedControl {
    /// Full accepted sequence and signed control ID.
    pub fn floor(&self) -> protocol::ControlFloor {
        self.floor
    }
    /// Exact private control artifact for explicit member catch-up.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Bounded retained control suffix from an exact observed head.
pub struct ControlPage {
    /// Oldest known predecessor; this device does not claim earlier records.
    pub base: protocol::ControlFloor,
    /// Exact accepted head observed before reading the immutable records.
    pub head: protocol::ControlFloor,
    /// Next full exclusive cursor, or none when this snapshot is exhausted.
    pub next: Option<protocol::ControlFloor>,
    /// Bounded ascending accepted controls.
    pub records: Vec<CommittedControl>,
}

/// First locally proven conflict under the fixed owner's valid signature.
/// Persistence does not prove global freshness or detect coherent local rollback.
pub struct ForkEvidence {
    /// Previously accepted exact floor, backed by retained control/checkpoint.
    pub accepted: protocol::ControlFloor,
    /// Different valid owner-signed control at that same accepted sequence.
    pub conflicting: protocol::SignedOwnerControl,
    /// Exact accepted signed control, or signed joining checkpoint when the
    /// known floor is the checkpoint predecessor. This supplies both sides of
    /// the contradiction without claiming unavailable earlier history.
    pub accepted_proof: Vec<u8>,
    /// True when accepted_proof is the bounded owner-signed joining checkpoint;
    /// false when it is a canonical SignedOwnerControl encoding.
    pub accepted_from_checkpoint: bool,
}

#[cfg(test)]
mod tests;
