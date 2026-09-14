//! Unauthenticated room vocabulary. Constructing these values grants no rights.
use alloc::string::String;
use vhalla_core::RealmId;
use vhalla_social::{AgentId, OwnerId, RecordId};

/// Maximum complete room or owner-permit frame, checked before parsing.
pub const MAX_RECORD_BYTES: usize = 2048;
/// Maximum canonical ASCII slug bytes.
pub const MAX_SLUG_BYTES: usize = 48;
/// Maximum inert UTF-8 description bytes.
pub const MAX_DESCRIPTION_BYTES: usize = 256;

macro_rules! digest_type {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 32]);
        impl $name {
            /// Parse an unauthenticated full digest reference.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
            /// Full digest, never a shortened authorization identifier.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}
digest_type!(
    DirectoryId,
    "Directory genesis/configuration commitment; not a caller-selected name."
);
digest_type!(
    PolicyId,
    "Exact directory or initial room-policy commitment."
);
digest_type!(
    RoomRecordId,
    "Canonical unsigned room-record content identifier."
);
digest_type!(
    RoomGenesisId,
    "Full room genesis commitment; distinct from the legacy 128-bit routing handle."
);
digest_type!(
    PermitId,
    "Exact owner-permit content commitment, independent of proof representation."
);

/// Failures at the structural and signature boundary, never admission decisions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A byte, count, numeric or textual bound was exceeded.
    Bounds,
    /// Malformed, noncanonical, unsupported or trailing bytes.
    Encoding,
    /// Invalid or weak full Ed25519 public key.
    Key,
    /// Required strict signature verification failed.
    Signature,
    /// The local key does not match this exact signing role.
    SigningKey,
}

/// Canonical lowercase ASCII slug, not evidence that its name is available.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Slug(String);
impl Slug {
    /// Reject alternate spellings instead of normalizing foreign input.
    pub fn new(value: &str) -> Result<Self, Error> {
        if value.is_empty() || value.len() > MAX_SLUG_BYTES {
            return Err(Error::Bounds);
        }
        if value.starts_with('-')
            || value.ends_with('-')
            || value.contains("--")
            || !value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(Error::Encoding);
        }
        Ok(Self(String::from(value)))
    }
    /// Borrow the canonical spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Short inert text; render escaped, never execute or interpret it as policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Description(String);
impl Description {
    /// Retain nonempty bounded UTF-8 without control characters.
    pub fn new(value: &str) -> Result<Self, Error> {
        if value.is_empty() || value.len() > MAX_DESCRIPTION_BYTES {
            return Err(Error::Bounds);
        }
        if value.chars().any(char::is_control) {
            return Err(Error::Encoding);
        }
        Ok(Self(String::from(value)))
    }
    /// Borrow the original untrusted text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Closed room-creation control actions, separate from social v1 rights.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CreateAction {
    /// Request a bounded grant to one exact agent incarnation.
    GrantCreate {
        /// Immutable social agent genesis ID.
        agent: AgentId,
        /// Claimed full incarnation key; affiliation still needs admission.
        agent_key: [u8; 32],
        /// Exclusive grant expiry at directory-agreed time.
        expires_at: u64,
        /// Maximum charge authorized by this grant for one creation.
        maximum_charge: u64,
        /// Nonzero grant incarnation salt.
        nonce: [u8; 32],
    },
    /// Request permanent closure of one exact grant.
    RevokeGrant {
        /// Full GrantCreate room-control record ID.
        grant: RoomRecordId,
    },
}

/// Owner-signed room-permission stream; it cannot rotate social owner keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoomControl {
    /// Exact pinned directory commitment.
    pub directory: DirectoryId,
    /// Exact public realm.
    pub realm: RealmId,
    /// Durable social owner identity.
    pub owner: OwnerId,
    /// Exact claimed social control basis; signature verification cannot prove freshness.
    pub social_control: RecordId,
    /// Claimed controller key at that basis.
    pub controller_key: [u8; 32],
    /// Exact previous room-control record; absent only at sequence zero.
    pub previous: Option<RoomRecordId>,
    /// Zero for a new stream; semantic predecessor increment remains an admission check.
    pub sequence: u64,
    /// Closed creation-specific action.
    pub action: CreateAction,
}

/// Exact creation content signed separately by an owner and agent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreationIntent {
    /// Exact pinned directory commitment.
    pub directory: DirectoryId,
    /// Exact public realm.
    pub realm: RealmId,
    /// Current pricing/admission policy commitment claimed by this proposal.
    pub policy: PolicyId,
    /// Initial room settings commitment, separate from the directory policy.
    pub initial_settings: PolicyId,
    /// Durable social owner identity, never a controller public key.
    pub owner: OwnerId,
    /// Exact creator incarnation, independent of transport identity.
    pub agent: AgentId,
    /// Claimed controller key at the exact social basis.
    pub owner_key: [u8; 32],
    /// Claimed full creator key at the immutable agent genesis.
    pub agent_key: [u8; 32],
    /// Exact claimed social control head.
    pub social_control: RecordId,
    /// Exact claimed room-control head, including grant/revocation history.
    pub room_control: RoomRecordId,
    /// Exact creation-specific grant record.
    pub grant: RoomRecordId,
    /// Canonical proposed slug; no reservation is implied.
    pub slug: Slug,
    /// Inert searchable description.
    pub description: Description,
    /// Expected one-based lifetime owner slot.
    pub slot: u32,
    /// Exact quoted charge; repricing requires a new permit.
    pub charge: u64,
    /// Exclusive expiry of this exact proposal at directory-agreed time.
    pub expires_at: u64,
    /// Nonzero exact-permit incarnation salt.
    pub nonce: [u8; 32],
}

/// Owner-only room edits; creation grants confer neither of these operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UpdateAction {
    /// Replace only the short description.
    Describe(Description),
    /// Request permanent archival; slug and creation debit remain reserved.
    Archive,
}

/// Exact predecessor-bound owner edit; cannot change slug or genesis ownership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoomUpdate {
    /// Exact pinned directory commitment.
    pub directory: DirectoryId,
    /// Exact public realm.
    pub realm: RealmId,
    /// Full immutable room genesis, never a routing-handle claim.
    pub genesis: RoomGenesisId,
    /// Exact previous proposal or update record ID.
    pub previous: RoomRecordId,
    /// Durable claimed owner identity.
    pub owner: OwnerId,
    /// Exact claimed social control basis.
    pub social_control: RecordId,
    /// Claimed controller key at that basis.
    pub controller_key: [u8; 32],
    /// Exclusive expiry at directory-agreed time.
    pub expires_at: u64,
    /// Nonzero edit salt.
    pub nonce: [u8; 32],
    /// Closed metadata edit.
    pub action: UpdateAction,
}

/// Immutable verified payloads still contain unauthenticated authority claims.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Body {
    /// A room-permission control action.
    Control(RoomControl),
    /// Exact owner-permitted and agent-signed creation proposal.
    Create(CreationIntent),
    /// Owner-signed room metadata change.
    Update(RoomUpdate),
}
