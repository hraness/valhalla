//! Bounded unsigned protocol vocabulary. These values alone confer no authority.
use alloc::{string::String, vec::Vec};
use vhalla_core::{RealmId, RoomId};

/// Maximum complete signed record, before allocating or checking signatures.
pub const MAX_RECORD_BYTES: usize = 8192;
/// Maximum UTF-8 text bytes in one post.
pub const MAX_TEXT_BYTES: usize = 4096;
/// Maximum UTF-8 text bytes in a profile or agent biography.
pub const MAX_BIO_BYTES: usize = 512;
/// Maximum exact hash references in one operation.
pub const MAX_REFS: usize = 16;
/// Hard ceiling for a retained archive, including control evidence.
pub const MAX_RECORDS: usize = 4096;
/// Maximum concurrent effective register heads before an unresolved result.
pub const MAX_HEADS: usize = 16;
/// Maximum thread ancestry depth.
pub const MAX_THREAD_DEPTH: usize = 64;

macro_rules! digest_type {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 32]);
        impl $name {
            /// Parse a digest reference. This does not authenticate its subject.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
            /// Complete digest bytes; never a shortened authorization key.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}
digest_type!(
    RecordId,
    "Content identifier of one canonical unsigned record."
);
digest_type!(
    OwnerId,
    "Immutable owner genesis identifier, distinct from controller keys."
);
digest_type!(AgentId, "Immutable owner-bound agent genesis identifier.");
digest_type!(
    EvidenceRoot,
    "Logical scope and sorted-event-ID commitment, not a proof of completeness."
);

/// Stable, bounded failures at the social boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A hard size, count, depth or arithmetic bound was exceeded.
    Bounds,
    /// Malformed, unsupported, trailing or noncanonical bytes.
    Encoding,
    /// An invalid or weak full public key was supplied.
    Key,
    /// A strict signature or required acknowledgement failed.
    Signature,
    /// The signing key differs from the requested signing role.
    SigningKey,
    /// An operation lacks a required ancestor or target.
    Missing,
    /// Evidence does not authorize this social operation.
    Unauthorized,
    /// A realm, owner, agent, grant or register reference has the wrong scope.
    Context,
    /// Valid concurrent evidence conflicts; no authoritative winner is selected.
    Conflict,
    /// A bounded archive cannot retain another record; nothing is evicted.
    Capacity,
    /// A per-call work or verification budget was exhausted.
    Budget,
    /// The retained evidence does not support a complete result.
    Incomplete,
    /// This adapter has no admitted private-audience implementation.
    PrivateDisabled,
    /// Automatic compromised-controller recovery is unavailable in this version.
    RecoveryDisabled,
    /// A required second signature is not present yet.
    AcknowledgementRequired,
}

/// Bounded UTF-8 data; render as escaped text, never executable markup.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Text(String);
impl Text {
    /// Retain text only after checking its UTF-8 byte bound.
    pub fn new(text: &str) -> Result<Self, Error> {
        if text.len() > MAX_TEXT_BYTES {
            return Err(Error::Bounds);
        }
        Ok(Self(String::from(text)))
    }
    /// Borrow the original untrusted text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Canonical sorted, unique, bounded exact references.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct References(Vec<RecordId>);
impl References {
    /// Check canonical order; decoding never silently normalizes foreign bytes.
    pub fn new(ids: Vec<RecordId>) -> Result<Self, Error> {
        if ids.len() > MAX_REFS || ids.windows(2).any(|w| w[0] >= w[1]) {
            return Err(Error::Bounds);
        }
        Ok(Self(ids))
    }
    /// Normalize locally assembled references, rejecting duplicates and overflow.
    pub fn sorted(mut ids: Vec<RecordId>) -> Result<Self, Error> {
        if ids.len() > MAX_REFS {
            return Err(Error::Bounds);
        }
        ids.sort_unstable();
        Self::new(ids)
    }
    /// Borrow immutable exact references.
    #[must_use]
    pub fn as_slice(&self) -> &[RecordId] {
        &self.0
    }
}

/// Closed operation rights. No host capability or permission string is accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rights(u8);
impl Rights {
    /// Create original posts and replies/quotes.
    pub const POST: Self = Self(1);
    /// Update this agent's own biography.
    pub const BIO: Self = Self(2);
    /// Set the owner's reaction to a post.
    pub const REACT: Self = Self(4);
    /// Set the owner's follow relationship.
    pub const FOLLOW: Self = Self(8);
    /// Set the owner's plain repost relationship.
    pub const REPOST: Self = Self(16);
    /// Revise or retract this agent's own posts.
    pub const REVISE: Self = Self(32);
    /// All defined social rights, never owner control or host effects.
    pub const ALL: Self = Self(63);
    /// Combine explicit social rights.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
    /// Check that a granted mask contains a required operation.
    #[must_use]
    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }
    /// Canonical wire mask.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }
    /// Reject empty or unknown rights at the foreign boundary.
    pub fn from_bits(bits: u8) -> Result<Self, Error> {
        if bits == 0 || bits & !63 != 0 {
            return Err(Error::Encoding);
        }
        Ok(Self(bits))
    }
}

/// Placement in a public realm, separate from any future private audience.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Placement {
    /// The attributed owner's profile timeline.
    Profile,
    /// A public channel within the signed realm.
    Channel(RoomId),
}
/// Exact original post and the revision that was actually reviewed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct PostRef {
    /// Stable Post creation record ID.
    pub post: RecordId,
    /// Original creation ID or an exact revision record ID.
    pub revision: RecordId,
}
/// A reply binds both its root and its immediate parent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplyRef {
    /// Stable root post ID.
    pub root: RecordId,
    /// Exact parent post/revision seen by the author.
    pub parent: PostRef,
}
/// One owner's revision-specific preference.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Reaction {
    /// Withdraw this owner's preference.
    Clear,
    /// Upvote the exact revision.
    Up(RecordId),
    /// Downvote the exact revision.
    Down(RecordId),
}

/// Inert social content. Authorization is evaluated separately against controls.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Operation {
    /// Create a profile/channel post, optionally replying or quoting.
    Post {
        /// Public placement inherited by replies.
        placement: Placement,
        /// Escaped text at every presentation boundary.
        text: Text,
        /// Exact root and parent, when replying.
        reply: Option<ReplyRef>,
        /// Exact original content being quoted.
        quote: Option<PostRef>,
    },
    /// Replace a post's displayed text without moving its earlier endorsements.
    Revise {
        /// Stable original creation ID.
        post: RecordId,
        /// Replacement text.
        text: Text,
        /// Previous revisions of this same post.
        supersedes: References,
    },
    /// Withdraw displayed content, retaining historical evidence.
    Retract {
        /// Stable original creation ID.
        post: RecordId,
    },
    /// Set or clear the owner's plain repost of an exact source revision.
    Repost {
        /// Stable original creation ID.
        post: RecordId,
        /// Exact revision, or None to clear.
        revision: Option<RecordId>,
        /// Prior same-owner/post repost updates.
        supersedes: References,
    },
    /// Set one owner-level preference for an original post.
    React {
        /// Stable original post.
        post: RecordId,
        /// Preference bound to reviewed content.
        reaction: Reaction,
        /// Prior same-owner/post preference updates.
        supersedes: References,
    },
    /// Set one owner-level follow relationship.
    Follow {
        /// Durable account being followed.
        target: OwnerId,
        /// False is an explicit unfollow and wins a concurrent race.
        following: bool,
        /// Prior same-owner/target follow updates.
        supersedes: References,
    },
    /// Update only the signing agent's biography.
    AgentBio {
        /// At most MAX_BIO_BYTES of untrusted text.
        text: Text,
        /// Prior biography updates for the same agent.
        supersedes: References,
    },
    /// Update the owner's profile; only a controller may issue this operation.
    OwnerProfile {
        /// At most MAX_BIO_BYTES of untrusted text.
        text: Text,
        /// Prior profile updates for the same owner.
        supersedes: References,
    },
}
impl Operation {
    /// Required agent right, or None for owner-controller-only profile edits.
    #[must_use]
    pub fn required_right(&self) -> Option<Rights> {
        match self {
            Self::Post { .. } => Some(Rights::POST),
            Self::Revise { .. } | Self::Retract { .. } => Some(Rights::REVISE),
            Self::Repost { .. } => Some(Rights::REPOST),
            Self::React { .. } => Some(Rights::REACT),
            Self::Follow { .. } => Some(Rights::FOLLOW),
            Self::AgentBio { .. } => Some(Rights::BIO),
            Self::OwnerProfile { .. } => None,
        }
    }
    /// Explicit mutable-register predecessors; other dependency kinds stay separate.
    #[must_use]
    pub fn supersedes(&self) -> &[RecordId] {
        match self {
            Self::Revise { supersedes, .. }
            | Self::Repost { supersedes, .. }
            | Self::React { supersedes, .. }
            | Self::Follow { supersedes, .. }
            | Self::AgentBio { supersedes, .. }
            | Self::OwnerProfile { supersedes, .. } => supersedes.as_slice(),
            _ => &[],
        }
    }
}

/// Explicit author and its immutable authority references, never transport identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Actor {
    /// An owner acting through its controller at an exact basis.
    Owner {
        /// Durable owner genesis ID.
        owner: OwnerId,
        /// Exact owner control basis.
        control: RecordId,
    },
    /// An agent acting through a bounded owner-signed grant.
    Agent {
        /// Claimed owner, checked against immutable agent genesis.
        owner: OwnerId,
        /// Owner-bound agent incarnation.
        agent: AgentId,
        /// Exact grant control record ID.
        grant: RecordId,
    },
}
impl Actor {
    /// Claimed owner reference; affiliation still requires control admission.
    #[must_use]
    pub const fn owner(self) -> OwnerId {
        match self {
            Self::Owner { owner, .. } | Self::Agent { owner, .. } => owner,
        }
    }
}

/// Owner-only control actions. A valid signature alone does not admit them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlAction {
    /// Grant bounded social rights to one immutable agent incarnation.
    Grant {
        /// Agent genesis ID.
        agent: AgentId,
        /// Exact public realm.
        realm: RealmId,
        /// Closed set of social operations.
        rights: Rights,
        /// Exclusive expiry at the supplied evaluation clock.
        expires_at: u64,
        /// Unique grant incarnation salt.
        nonce: [u8; 32],
    },
    /// Permanently close one grant, sealing a declared accepted frontier.
    Revoke {
        /// Exact grant control record ID.
        grant: RecordId,
        /// Exact same-grant history heads accepted by the owner.
        accepted: References,
    },
    /// Permanently close one agent incarnation, sealing accepted history.
    Retire {
        /// Agent incarnation; future grants cannot revive it.
        agent: AgentId,
        /// Realm of the optional accepted frontier; retirement itself is global.
        realm: RealmId,
        /// Exact same-agent history heads in that realm accepted by the owner.
        accepted: References,
    },
    /// Commit exact owner/agent history while current authority remains open.
    Seal {
        /// Scope of the accepted history; unrelated realm content need not replicate.
        realm: RealmId,
        /// Exact same-owner history heads; closure preserves all operation kinds.
        heads: References,
    },
    /// Explicitly adopt exact historical records without reactivating their grant.
    Ratify {
        /// Scope of explicitly ratified history.
        realm: RealmId,
        /// Exact same-owner history heads; this is deliberate owner endorsement.
        heads: References,
    },
    /// Planned key rotation; both old and new controllers sign this same record.
    Rotate {
        /// Full replacement controller key.
        new_key: [u8; 32],
    },
}

/// Unauthenticated, bounded record vocabulary. Only wire verification and control
/// admission may turn these assertions into derived affiliation evidence.
// Keep one flat bounded payload: no extra per-record box or pointer lifetime.
// The compile-time ceiling below makes growth an explicit memory-contract change.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Body {
    /// Immutable owner identity root.
    OwnerGenesis {
        /// Full initial controller key; must match the primary signer.
        controller: [u8; 32],
        /// Optional declared offline key; recovery activation remains disabled.
        recovery: Option<[u8; 32]>,
        /// Owner incarnation salt.
        nonce: [u8; 32],
    },
    /// A linear, owner-authorized control transition.
    Control {
        /// Immutable owner ID.
        owner: OwnerId,
        /// Exact prior control or owner genesis record.
        previous: RecordId,
        /// Typed action evaluated against predecessor state.
        action: ControlAction,
    },
    /// Jointly signed owner-bound agent identity root.
    AgentGenesis {
        /// Immutable owner ID.
        owner: OwnerId,
        /// Exact issuing owner control basis.
        control: RecordId,
        /// Full agent key; must supply the acknowledgement signature.
        key: [u8; 32],
        /// Agent incarnation salt.
        nonce: [u8; 32],
    },
    /// One public-realm social operation and its exact writer chain.
    Social {
        /// Immutable author/authority references.
        actor: Actor,
        /// Exact public realm.
        realm: RealmId,
        /// Zero at a new writer/grant chain, then exact predecessor sequence + 1.
        sequence: u64,
        /// Exact same-writer/grant/realm predecessor, absent only at sequence zero.
        previous: Option<RecordId>,
        /// Inert social operation.
        operation: Operation,
    },
}
impl Body {
    /// Required acknowledgement key for jointly signed record families.
    #[must_use]
    pub fn acknowledgement_key(&self) -> Option<[u8; 32]> {
        match self {
            Self::AgentGenesis { key, .. } => Some(*key),
            Self::Control {
                action: ControlAction::Rotate { new_key },
                ..
            } => Some(*new_key),
            _ => None,
        }
    }
}

// At most 2 MiB of inline payloads at MAX_RECORDS; variable text has separate caps.
const _: () = assert!(core::mem::size_of::<Body>() <= 512);
