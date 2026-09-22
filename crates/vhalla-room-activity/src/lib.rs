#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Signed public room text, separate from the bounded social/control archive.
//!
//! A signature attributes bytes to one full application key. It establishes
//! neither a human/owner identity nor host execution authority. Policy admission
//! requires an independently pinned network and a registry obtained by certified
//! replay; decoding a registry snapshot alone does not establish that trust.
//! Admission preparation never advances an author chain. The storage owner must
//! durably publish the event and outbox transaction before committing its candidate.

extern crate alloc;

pub mod continuity;
pub mod puzzle_share;

use alloc::{string::String, vec::Vec};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use vhalla_core::RealmId;
use vhalla_rooms::{DirectoryId, Registry, RoomGenesisId, RoomRecordId};

const MAGIC: &[u8; 5] = b"VHRA\x01";
const ID_DOMAIN: &[u8] = b"vhalla/room-activity/content-id/v1\0";
const SIGN_DOMAIN: &[u8] = b"vhalla/room-activity/signature/v1\0";
const FIXED_UNSIGNED_BYTES: usize = 5 + 32 + 16 + 32 + 32 + 32 + 32 + 8 + 32 + 8 + 1 + 2;
/// Maximum exact UTF-8 text bytes per version-1 event.
pub const MAX_TEXT_BYTES: usize = 4096;
/// Maximum complete signed frame; enforced before parsing or allocation.
pub const MAX_EVENT_BYTES: usize = FIXED_UNSIGNED_BYTES + MAX_TEXT_BYTES + 64;
/// Maximum canonical unsigned reservation frame, with no placeholder signature.
pub const MAX_UNSIGNED_BYTES: usize = MAX_EVENT_BYTES - 64;
/// The only activity content protocol implemented here.
pub const PROTOCOL_VERSION: u8 = 1;

/// A bounded structural, cryptographic, policy or author-chain refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Frame or text size exceeds a fixed bound, or text is empty.
    Bounds,
    /// Noncanonical framing, invalid UTF-8/control characters, or trailing bytes.
    Encoding,
    /// Unsupported envelope version or content kind.
    Protocol,
    /// Invalid or weak Ed25519 public key.
    Key,
    /// The signing provider's key differs from the exact claimed author.
    Signer,
    /// Strict signature verification failed.
    Signature,
    /// Network, realm, directory or full room genesis differs from the pinned scope.
    Scope,
    /// No such full room genesis exists in the supplied registry.
    UnknownRoom,
    /// The room is closed/archived or the exact policy revision is not current.
    Policy,
    /// The full author key differs from this chain's key.
    Author,
    /// Sequence is zero or the first/predecessor shape is inconsistent.
    Sequence,
    /// The exact current head was offered again.
    Duplicate,
    /// Sequence skips one or more expected predecessors.
    Gap,
    /// Competing content occupies the current sequence or names a different predecessor.
    Fork,
    /// Sequence is older than the retained head; consult disk history for fork evidence.
    Replay,
    /// The sequence space has no successor.
    SequenceExhausted,
    /// A prepared candidate no longer extends the exact chain it was prepared against.
    StaleBase,
    /// The policy basis changed after preparation; restart the durable transaction.
    StalePolicy,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl core::error::Error for Error {}

/// Full content commitment, never a routing handle or an authorization claim.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EventId([u8; 32]);
impl EventId {
    /// Reserved no-predecessor marker for sequence one only.
    pub const ZERO: Self = Self([0; 32]);
    /// Parse an unauthenticated full content identifier.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    /// Borrow all content-identifier bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Exact immutable routing and signing scope; constructing it grants no rights.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoomScope {
    /// Independently pinned immutable public network ID, not a mutable config fingerprint.
    pub network: [u8; 32],
    /// Full public realm.
    pub realm: RealmId,
    /// Exact directory commitment.
    pub directory: DirectoryId,
    /// Full immutable room genesis; never converted from a 128-bit routing handle.
    pub room: RoomGenesisId,
}
impl RoomScope {
    fn check(&self) -> Result<(), Error> {
        if self.network == [0; 32] {
            return Err(Error::Scope);
        }
        Ok(())
    }
}

/// Nonempty bounded inert text. No normalization is performed; only newline
/// and tab are allowed among control characters. Render it as untrusted text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Text(String);
impl Text {
    /// Check exact UTF-8 bytes before allocating owned text.
    pub fn new(text: &str) -> Result<Self, Error> {
        if text.is_empty() || text.len() > MAX_TEXT_BYTES {
            return Err(Error::Bounds);
        }
        if text
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
        {
            return Err(Error::Encoding);
        }
        Ok(Self(String::from(text)))
    }
    /// Borrow the exact signed text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Closed version-1 content vocabulary. Text never authorizes host execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Content {
    /// Inert public text, including discussion of work without executing it.
    Text(Text),
}

/// Proposed signed content; fields remain unauthenticated until verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventClaims {
    /// Exact network, realm, directory and full room genesis.
    pub scope: RoomScope,
    /// Exact admitted owner-signed public-policy revision.
    pub policy: RoomRecordId,
    /// Full Ed25519 application key; no implicit owner or human attribution.
    pub author: [u8; 32],
    /// One at a new per-room/full-key chain; then precisely predecessor + one.
    pub sequence: u64,
    /// Exact previous event ID, zero if and only if sequence is one.
    pub previous: EventId,
    /// Author-claimed Unix seconds, not trusted ordering or freshness evidence.
    pub created_at: u64,
    /// Bounded typed content.
    pub content: Content,
}

/// Frozen checked content awaiting a signature, with no policy authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsignedEvent {
    claims: EventClaims,
    id: EventId,
}
impl UnsignedEvent {
    /// Check bounded content without silently changing any signed field.
    pub fn new(claims: EventClaims) -> Result<Self, Error> {
        claims.scope.check()?;
        checked_key(&claims.author)?;
        if claims.sequence == 0 || (claims.sequence == 1) != (claims.previous == EventId::ZERO) {
            return Err(Error::Sequence);
        }
        let bytes = unsigned_bytes(&claims);
        if bytes.len() + 64 > MAX_EVENT_BYTES {
            return Err(Error::Bounds);
        }
        let mut hash = Sha256::new();
        hash.update(ID_DOMAIN);
        hash.update(&bytes);
        Ok(Self {
            claims,
            id: EventId(hash.finalize().into()),
        })
    }
    /// Encode exact canonical unsigned bytes for durable reservation before signing.
    /// This frame contains no signature and establishes no author or policy authority.
    pub fn encode(&self) -> Vec<u8> {
        unsigned_bytes(&self.claims)
    }
    /// Decode a bounded canonical reservation without changing its content ID.
    /// Structural/key checks do not authenticate the bytes or admit the event.
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() > MAX_UNSIGNED_BYTES {
            return Err(Error::Bounds);
        }
        if raw.len() < FIXED_UNSIGNED_BYTES + 1 {
            return Err(Error::Encoding);
        }
        let mut input = Reader(raw);
        if input.take(4)? != &MAGIC[..4] {
            return Err(Error::Encoding);
        }
        if input.array::<1>()?[0] != PROTOCOL_VERSION {
            return Err(Error::Protocol);
        }
        let scope = RoomScope {
            network: input.array()?,
            realm: RealmId(u128::from_be_bytes(input.array()?)),
            directory: DirectoryId::from_bytes(input.array()?),
            room: RoomGenesisId::from_bytes(input.array()?),
        };
        let policy = RoomRecordId::from_bytes(input.array()?);
        let author = input.array()?;
        let sequence = u64::from_be_bytes(input.array()?);
        let previous = EventId(input.array()?);
        let created_at = u64::from_be_bytes(input.array()?);
        if input.array::<1>()?[0] != 0 {
            return Err(Error::Protocol);
        }
        let length = usize::from(u16::from_be_bytes(input.array()?));
        if length == 0 || length > MAX_TEXT_BYTES {
            return Err(Error::Bounds);
        }
        let text = core::str::from_utf8(input.take(length)?).map_err(|_| Error::Encoding)?;
        let content = Content::Text(Text::new(text)?);
        if !input.0.is_empty() {
            return Err(Error::Encoding);
        }
        Self::new(EventClaims {
            scope,
            policy,
            author,
            sequence,
            previous,
            created_at,
            content,
        })
    }
    /// The exact unsigned content commitment, excluding signature representations.
    pub const fn id(&self) -> EventId {
        self.id
    }
    /// Borrow checked claims; they are not yet authenticated or admitted.
    pub const fn claims(&self) -> &EventClaims {
        &self.claims
    }
    /// Typed domain-separated transcript for an asynchronous external signer.
    pub fn signing_bytes(&self) -> Vec<u8> {
        signing_bytes(self.id)
    }
    /// Attach and strictly verify a detached signature; admission remains separate.
    pub fn attach_signature(self, signature: [u8; 64]) -> Result<SignedEvent, Error> {
        checked_key(&self.claims.author)?
            .verify_strict(&self.signing_bytes(), &Signature::from_bytes(&signature))
            .map_err(|_| Error::Signature)?;
        Ok(SignedEvent {
            unsigned: self,
            signature,
        })
    }
    /// Sign this checked request with the exact author key; no generic signing capability.
    pub fn sign_with_key(self, key: &SigningKey) -> Result<SignedEvent, Error> {
        if key.verifying_key().to_bytes() != self.claims.author {
            return Err(Error::Signer);
        }
        let signature = key.sign(&self.signing_bytes()).to_bytes();
        self.attach_signature(signature)
    }
}

/// Canonical decoded bytes whose signature and authorization remain untrusted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedEvent {
    unsigned: UnsignedEvent,
    signature: [u8; 64],
}
impl SignedEvent {
    /// Decode one bounded canonical frame without trusting its signer.
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() > MAX_EVENT_BYTES {
            return Err(Error::Bounds);
        }
        if raw.len() < FIXED_UNSIGNED_BYTES + 1 + 64 {
            return Err(Error::Encoding);
        }
        let split = raw.len() - 64;
        let unsigned = UnsignedEvent::decode(&raw[..split])?;
        let signature = raw[split..].try_into().map_err(|_| Error::Encoding)?;
        Ok(Self {
            unsigned,
            signature,
        })
    }
    /// Re-encode immutable content; this does not verify the signature.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = unsigned_bytes(&self.unsigned.claims);
        bytes.extend_from_slice(&self.signature);
        bytes
    }
    /// Borrow explicitly untrusted claims from decoded bytes.
    pub const fn unverified_claims(&self) -> &EventClaims {
        &self.unsigned.claims
    }
    /// Claimed content ID, not proof of signature or admission.
    pub const fn id(&self) -> EventId {
        self.unsigned.id
    }
    /// Strictly authenticate content to the complete author key only.
    pub fn verify(self) -> Result<VerifiedEvent, Error> {
        checked_key(&self.unsigned.claims.author)?
            .verify_strict(
                &self.unsigned.signing_bytes(),
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| Error::Signature)?;
        Ok(VerifiedEvent(self))
    }
}

/// Strictly authenticated bytes, still lacking policy and chain admission.
///
/// ```compile_fail
/// use vhalla_room_activity::{SignedEvent, VerifiedEvent};
/// fn bypass(event: SignedEvent) -> VerifiedEvent { VerifiedEvent(event) }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedEvent(SignedEvent);
impl VerifiedEvent {
    /// Exact authenticated claims; attribution is to a key, not an inferred owner.
    pub const fn claims(&self) -> &EventClaims {
        self.0.unverified_claims()
    }
    /// Full authenticated content ID.
    pub const fn id(&self) -> EventId {
        self.0.id()
    }
    /// Exact signed bytes for forwarding or durable retention.
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode()
    }
    /// Detect signed competing content at the same scope/full-author/sequence.
    /// Disk history should use this when an older sequence is replayed. Neither
    /// arrival order nor timestamp chooses a winner.
    pub fn conflicts_with(&self, other: &Self) -> bool {
        let a = self.claims();
        let b = other.claims();
        a.scope == b.scope
            && a.author == b.author
            && a.sequence == b.sequence
            && self.id() != other.id()
    }
}

/// Borrowed immutable policy basis. The caller must establish registry trust
/// by certified replay, replace this context on state advancement, and serialize
/// preparation plus durable publication against policy changes. A digest is
/// cached once per view rather than snapshotting the registry for every post.
pub struct AdmissionContext<'a> {
    network: [u8; 32],
    registry: &'a Registry,
    digest: [u8; 32],
}
impl<'a> AdmissionContext<'a> {
    /// Pin the immutable network independently of peer advertisements.
    pub fn new(network: [u8; 32], registry: &'a Registry) -> Result<Self, Error> {
        if network == [0; 32] {
            return Err(Error::Scope);
        }
        Ok(Self {
            network,
            registry,
            digest: registry.digest(),
        })
    }
    /// Digest of this exact evaluation basis; no certificate is implied.
    pub const fn registry_digest(&self) -> &[u8; 32] {
        &self.digest
    }
    fn check(&self, claims: &EventClaims) -> Result<(), Error> {
        if claims.scope.network != self.network
            || claims.scope.realm != self.registry.realm()
            || claims.scope.directory != self.registry.directory()
        {
            return Err(Error::Scope);
        }
        let room = self
            .registry
            .room_by_genesis(claims.scope.room)
            .ok_or(Error::UnknownRoom)?;
        if !room.allows_public_activity(&self.network, claims.policy) {
            return Err(Error::Policy);
        }
        Ok(())
    }
}

/// One retained author-chain position; a transport-provided head is not trusted state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainPosition {
    sequence: u64,
    id: EventId,
}
impl ChainPosition {
    /// Last admitted sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    /// Exact last admitted content ID.
    pub const fn id(&self) -> EventId {
        self.id
    }
}

/// One per-room/full-key chain. Policy epochs do not reset it. The storage owner
/// must serialize this state with its durable log and preserve competing signed
/// evidence; this bounded head alone cannot prove complete historical delivery.
#[derive(Debug)]
pub struct AuthorChain {
    scope: RoomScope,
    author: [u8; 32],
    head: Option<ChainPosition>,
}
impl AuthorChain {
    /// Begin at sequence one under an independently pinned complete room scope.
    pub fn new(scope: RoomScope, author: [u8; 32]) -> Result<Self, Error> {
        scope.check()?;
        checked_key(&author)?;
        Ok(Self {
            scope,
            author,
            head: None,
        })
    }
    /// Resume from a receipt already returned by a successful durable commit.
    /// Retaining an older receipt can roll back a local floor; the storage owner
    /// must choose its actual latest committed receipt, never a remote claim.
    pub fn from_receipt(receipt: &AdmittedEvent) -> Self {
        let claims = receipt.event.claims();
        Self {
            scope: claims.scope,
            author: claims.author,
            head: Some(receipt.position()),
        }
    }
    /// Restore the exact head of this storage owner's previously durable admission.
    ///
    /// This is a TRUSTED LOCAL STORAGE boundary, not remote admission. The caller
    /// must tie these exact verified bytes to its own previously published
    /// admission log/index and select its actual latest persisted author head.
    /// A valid signature, remote event, or peer-advertised sequence alone is
    /// insufficient. Historical policy is deliberately not re-admitted under
    /// today's registry: revocation must not erase a previously stored floor.
    ///
    /// The expected full scope and key are checked. This returns chain state only,
    /// never a fresh admission receipt, history-completeness or freshness proof.
    pub fn restore_local_admitted_head(
        scope: RoomScope,
        author: [u8; 32],
        event: VerifiedEvent,
    ) -> Result<Self, Error> {
        let mut chain = Self::new(scope, author)?;
        if event.claims().scope != scope {
            return Err(Error::Scope);
        }
        if event.claims().author != author {
            return Err(Error::Author);
        }
        chain.head = Some(ChainPosition {
            sequence: event.claims().sequence,
            id: event.id(),
        });
        Ok(chain)
    }
    /// Current local committed position; preparation does not change it.
    pub const fn position(&self) -> Option<ChainPosition> {
        self.head
    }
    /// Prepare a move-only candidate without advancing local state. Unknown
    /// ancestors stay outside this chain; storage may retain them in a separate
    /// bounded pending area. No last-writer-wins or timestamp arbitration occurs.
    pub fn prepare_next(
        &self,
        event: VerifiedEvent,
        context: &AdmissionContext<'_>,
    ) -> Result<PendingAdmission, Error> {
        let claims = event.claims();
        if claims.scope != self.scope {
            return Err(Error::Scope);
        }
        if claims.author != self.author {
            return Err(Error::Author);
        }
        context.check(claims)?;
        if let Some(head) = self.head {
            if claims.sequence == head.sequence {
                return Err(if event.id() == head.id {
                    Error::Duplicate
                } else {
                    Error::Fork
                });
            }
            if claims.sequence < head.sequence {
                return Err(Error::Replay);
            }
            let next = head
                .sequence
                .checked_add(1)
                .ok_or(Error::SequenceExhausted)?;
            if claims.sequence != next {
                return Err(Error::Gap);
            }
            if claims.previous != head.id {
                return Err(Error::Fork);
            }
        } else if claims.sequence != 1 {
            return Err(Error::Gap);
        }
        let next = ChainPosition {
            sequence: claims.sequence,
            id: event.id(),
        };
        Ok(PendingAdmission {
            event,
            base: self.head,
            next,
            registry_digest: context.digest,
        })
    }
    /// Consume a candidate ONLY after its log/outbox transaction is durable.
    /// This portable method cannot perform or attest to I/O. A changed base is
    /// rejected instead of overwriting another publication; reconcile durable
    /// state on any uncertainty before signing or publishing another event.
    /// The durable transaction must compare-and-set BOTH the author base and
    /// registry digest. Supply the current locally verified frontier here; this
    /// cannot prove that no newer certified state exists elsewhere.
    pub fn commit_after_persist(
        &mut self,
        candidate: PendingAdmission,
        context: &AdmissionContext<'_>,
    ) -> Result<AdmittedEvent, Error> {
        let claims = candidate.event.claims();
        if self.head != candidate.base || self.scope != claims.scope || self.author != claims.author
        {
            return Err(Error::StaleBase);
        }
        if candidate.registry_digest != context.digest || claims.scope.network != context.network {
            return Err(Error::StalePolicy);
        }
        context.check(claims)?;
        self.head = Some(candidate.next);
        Ok(AdmittedEvent {
            event: candidate.event,
            registry_digest: candidate.registry_digest,
        })
    }
}

/// Checked but NOT durable candidate. It is deliberately not Clone; dropping
/// it after a failed transaction leaves the author chain unchanged.
#[derive(Debug)]
pub struct PendingAdmission {
    event: VerifiedEvent,
    base: Option<ChainPosition>,
    next: ChainPosition,
    registry_digest: [u8; 32],
}
impl PendingAdmission {
    /// Authenticated bytes the caller must durably retain before commit.
    pub const fn event(&self) -> &VerifiedEvent {
        &self.event
    }
    /// Compare-and-set base for the durable author head.
    pub const fn base(&self) -> Option<ChainPosition> {
        self.base
    }
    /// Position to store atomically with the event and outbox entry.
    pub const fn next(&self) -> ChainPosition {
        self.next
    }
    /// Exact evaluation digest; not a signed receipt or quorum certificate.
    pub const fn registry_digest(&self) -> &[u8; 32] {
        &self.registry_digest
    }
}

/// Local receipt after the caller reports durable publication. This proves
/// neither current permission, global finality, network delivery nor storage
/// honesty. Re-check the latest certified policy for every future publication.
#[derive(Debug)]
pub struct AdmittedEvent {
    event: VerifiedEvent,
    registry_digest: [u8; 32],
}
impl AdmittedEvent {
    /// Authenticated event retained by the caller.
    pub const fn event(&self) -> &VerifiedEvent {
        &self.event
    }
    /// Policy evaluation basis used when preparing this historical event.
    pub const fn registry_digest(&self) -> &[u8; 32] {
        &self.registry_digest
    }
    /// Position this event occupied in its admitted author chain.
    pub fn position(&self) -> ChainPosition {
        ChainPosition {
            sequence: self.event.claims().sequence,
            id: self.event.id(),
        }
    }
}

fn checked_key(raw: &[u8; 32]) -> Result<VerifyingKey, Error> {
    let key = VerifyingKey::from_bytes(raw).map_err(|_| Error::Key)?;
    if key.is_weak() {
        return Err(Error::Key);
    }
    Ok(key)
}
fn signing_bytes(id: EventId) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(SIGN_DOMAIN.len() + 32);
    bytes.extend_from_slice(SIGN_DOMAIN);
    bytes.extend_from_slice(id.as_bytes());
    bytes
}
fn unsigned_bytes(claims: &EventClaims) -> Vec<u8> {
    let Content::Text(text) = &claims.content;
    let mut out = Vec::with_capacity(FIXED_UNSIGNED_BYTES + text.as_str().len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&claims.scope.network);
    out.extend_from_slice(&claims.scope.realm.0.to_be_bytes());
    out.extend_from_slice(claims.scope.directory.as_bytes());
    out.extend_from_slice(claims.scope.room.as_bytes());
    out.extend_from_slice(claims.policy.as_bytes());
    out.extend_from_slice(&claims.author);
    out.extend_from_slice(&claims.sequence.to_be_bytes());
    out.extend_from_slice(claims.previous.as_bytes());
    out.extend_from_slice(&claims.created_at.to_be_bytes());
    out.push(0);
    out.extend_from_slice(&(text.as_str().len() as u16).to_be_bytes());
    out.extend_from_slice(text.as_str().as_bytes());
    out
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let out = self.0.get(..length).ok_or(Error::Encoding)?;
        self.0 = &self.0[length..];
        Ok(out)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Encoding)
    }
}
