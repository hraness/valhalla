use crate::{codec::*, Error};
use alloc::{string::String, vec::Vec};
use ed25519_dalek::{Signature, Signer, SigningKey};
use sha2::{Digest, Sha256};

/// Maximum explicitly authorized writers, including the immutable owner.
pub const MAX_WRITERS: usize = 64;
/// Maximum exact UTF-8 bytes in one inert text message.
pub const MAX_TEXT_BYTES: usize = 4096;
/// Maximum complete signed genesis frame.
pub const MAX_GENESIS_BYTES: usize = 5 + 32 + 32 + 2 + 32 * MAX_WRITERS + 64;
/// Maximum complete signed owner-policy frame.
pub const MAX_POLICY_BYTES: usize =
    5 + 32 + 32 + 8 + 32 + 2 + 32 * MAX_WRITERS + 2 + 72 * MAX_WRITERS + 64;
/// Maximum complete signed text frame.
pub const MAX_EVENT_BYTES: usize = 5 + 32 + 32 + 32 + 8 + 32 + 8 + 4 + MAX_TEXT_BYTES + 64;

const GENESIS_MAGIC: &[u8; 5] = b"VHDG\x01";
const POLICY_MAGIC: &[u8; 5] = b"VHDP\x01";
const EVENT_MAGIC: &[u8; 5] = b"VHDE\x01";
const GENESIS_DOMAIN: &[u8] = b"vhalla/direct-room/genesis/v1\0";
const POLICY_DOMAIN: &[u8] = b"vhalla/direct-room/policy/v1\0";
const EVENT_DOMAIN: &[u8] = b"vhalla/direct-room/event/v1\0";

macro_rules! identifier {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 32]);
        impl $name {
            /// Reserved empty marker; its validity depends on the containing field.
            pub const ZERO: Self = Self([0; 32]);
            /// Construct an unauthenticated content identifier.
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
            /// Borrow the complete commitment.
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}
identifier!(
    RoomId,
    "Full genesis commitment, pinned independently when joining."
);
identifier!(
    PolicyId,
    "Full owner-policy commitment, never a routing hint."
);
identifier!(
    EventId,
    "Full signed-content commitment excluding the signature encoding."
);

impl RoomId {
    /// Domain-separated policy zero derived from this room's genesis commitment.
    pub fn initial_policy(self) -> PolicyId {
        let mut hash = Sha256::new();
        hash.update(b"vhalla/direct-room/policy-root/v1\0");
        hash.update(self.0);
        PolicyId(hash.finalize().into())
    }
}

/// Nonempty inert text; newline and tab are the only accepted control characters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Text(String);
impl Text {
    /// Validate exact UTF-8 without normalization or truncation.
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
    /// Borrow the exact message body.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Independently pinned room creation claims.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenesisClaims {
    /// Immutable owner application key.
    pub owner: [u8; 32],
    /// Fresh, nonzero, cryptographically random room nonce.
    pub nonce: [u8; 32],
    /// Sorted, unique authorized keys, including the owner.
    pub writers: Vec<[u8; 32]>,
}

/// Exact author-chain terminal endorsed for a policy being closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SealHead {
    /// Full author application key.
    pub author: [u8; 32],
    /// Positive sequence of the endorsed terminal event.
    pub sequence: u64,
    /// Exact terminal event commitment; sequence alone proves no ancestry.
    pub event: EventId,
}

/// Complete owner-authorized policy replacement, including the preceding seal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyClaims {
    /// Full pinned room ID.
    pub room: RoomId,
    /// Claimed immutable owner, separately checked against the pinned genesis.
    pub owner: [u8; 32],
    /// One for the first replacement, then exactly previous revision plus one.
    pub revision: u64,
    /// Exact preceding policy commitment, including the initial policy root.
    pub previous: PolicyId,
    /// Sorted, unique complete replacement, including the immutable owner.
    pub writers: Vec<[u8; 32]>,
    /// Sorted, unique author terminals closing only the immediately prior policy.
    /// An omitted author has no owner-endorsed feed events under that policy.
    pub sealed_heads: Vec<SealHead>,
}

/// Signed author-chain content. Attribution and admission are separate checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventClaims {
    /// Full pinned room ID.
    pub room: RoomId,
    /// Exact policy observed when preparing these bytes.
    pub policy: PolicyId,
    /// Full author application key.
    pub author: [u8; 32],
    /// One at a new per-room author chain; then precisely predecessor plus one.
    pub sequence: u64,
    /// Zero exactly for sequence one; otherwise the exact preceding content ID.
    pub previous: EventId,
    /// Author-claimed Unix seconds; never authorization or trusted ordering.
    pub created_at: u64,
    /// Text has no host execution authority.
    pub text: Text,
}

fn writers_check(writers: &[[u8; 32]], owner: &[u8; 32]) -> Result<(), Error> {
    checked_key(owner)?;
    if writers.is_empty() || writers.len() > MAX_WRITERS {
        return Err(Error::Bounds);
    }
    for key in writers {
        checked_key(key)?;
    }
    if writers.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(Error::Encoding);
    }
    if writers.binary_search(owner).is_err() {
        return Err(Error::Owner);
    }
    Ok(())
}

fn write_writers(bytes: &mut Vec<u8>, writers: &[[u8; 32]]) {
    bytes.extend_from_slice(&(writers.len() as u16).to_be_bytes());
    for key in writers {
        bytes.extend_from_slice(key);
    }
}

fn read_writers(reader: &mut Reader<'_>) -> Result<Vec<[u8; 32]>, Error> {
    let count = reader.count(MAX_WRITERS)?;
    let mut keys = Vec::with_capacity(count);
    for _ in 0..count {
        keys.push(reader.array()?);
    }
    Ok(keys)
}

impl GenesisClaims {
    fn check(&self) -> Result<(), Error> {
        if self.nonce == [0; 32] {
            return Err(Error::Encoding);
        }
        writers_check(&self.writers, &self.owner)
    }
    fn encode(&self) -> Vec<u8> {
        let mut bytes = prefix(GENESIS_MAGIC);
        bytes.extend_from_slice(&self.owner);
        bytes.extend_from_slice(&self.nonce);
        write_writers(&mut bytes, &self.writers);
        bytes
    }
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes, GENESIS_MAGIC)?;
        let claims = Self {
            owner: reader.array()?,
            nonce: reader.array()?,
            writers: read_writers(&mut reader)?,
        };
        reader.finish()?;
        Ok(claims)
    }
}

impl PolicyClaims {
    fn check(&self) -> Result<(), Error> {
        if self.room == RoomId::ZERO || self.previous == PolicyId::ZERO {
            return Err(Error::Scope);
        }
        if self.revision == 0 {
            return Err(Error::Sequence);
        }
        writers_check(&self.writers, &self.owner)?;
        if self.sealed_heads.len() > MAX_WRITERS {
            return Err(Error::Bounds);
        }
        for head in &self.sealed_heads {
            checked_key(&head.author)?;
            if head.sequence == 0 || head.event == EventId::ZERO {
                return Err(Error::Sequence);
            }
        }
        if self
            .sealed_heads
            .windows(2)
            .any(|pair| pair[0].author >= pair[1].author)
        {
            return Err(Error::Encoding);
        }
        Ok(())
    }
    fn encode(&self) -> Vec<u8> {
        let mut bytes = prefix(POLICY_MAGIC);
        bytes.extend_from_slice(self.room.as_bytes());
        bytes.extend_from_slice(&self.owner);
        bytes.extend_from_slice(&self.revision.to_be_bytes());
        bytes.extend_from_slice(self.previous.as_bytes());
        write_writers(&mut bytes, &self.writers);
        bytes.extend_from_slice(&(self.sealed_heads.len() as u16).to_be_bytes());
        for head in &self.sealed_heads {
            bytes.extend_from_slice(&head.author);
            bytes.extend_from_slice(&head.sequence.to_be_bytes());
            bytes.extend_from_slice(head.event.as_bytes());
        }
        bytes
    }
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes, POLICY_MAGIC)?;
        let room = RoomId(reader.array()?);
        let owner = reader.array()?;
        let revision = u64::from_be_bytes(reader.array()?);
        let previous = PolicyId(reader.array()?);
        let writers = read_writers(&mut reader)?;
        let count = reader.count(MAX_WRITERS)?;
        let mut sealed_heads = Vec::with_capacity(count);
        for _ in 0..count {
            sealed_heads.push(SealHead {
                author: reader.array()?,
                sequence: u64::from_be_bytes(reader.array()?),
                event: EventId(reader.array()?),
            });
        }
        reader.finish()?;
        Ok(Self {
            room,
            owner,
            revision,
            previous,
            writers,
            sealed_heads,
        })
    }
}

impl EventClaims {
    fn check(&self) -> Result<(), Error> {
        if self.room == RoomId::ZERO || self.policy == PolicyId::ZERO {
            return Err(Error::Scope);
        }
        checked_key(&self.author)?;
        if self.sequence == 0 || (self.sequence == 1) != (self.previous == EventId::ZERO) {
            return Err(Error::Sequence);
        }
        Ok(())
    }
    fn encode(&self) -> Vec<u8> {
        let mut bytes = prefix(EVENT_MAGIC);
        bytes.extend_from_slice(self.room.as_bytes());
        bytes.extend_from_slice(self.policy.as_bytes());
        bytes.extend_from_slice(&self.author);
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(self.previous.as_bytes());
        bytes.extend_from_slice(&self.created_at.to_be_bytes());
        bytes.extend_from_slice(&(self.text.as_str().len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.text.as_str().as_bytes());
        bytes
    }
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes, EVENT_MAGIC)?;
        let room = RoomId(reader.array()?);
        let policy = PolicyId(reader.array()?);
        let author = reader.array()?;
        let sequence = u64::from_be_bytes(reader.array()?);
        let previous = EventId(reader.array()?);
        let created_at = u64::from_be_bytes(reader.array()?);
        let length = u32::from_be_bytes(reader.array()?) as usize;
        if length > MAX_TEXT_BYTES {
            return Err(Error::Bounds);
        }
        let text =
            Text::new(core::str::from_utf8(reader.take(length)?).map_err(|_| Error::Encoding)?)?;
        reader.finish()?;
        Ok(Self {
            room,
            policy,
            author,
            sequence,
            previous,
            created_at,
            text,
        })
    }
}

macro_rules! record {
    ($unsigned:ident, $signed:ident, $verified:ident, $claims:ident, $id:ident, $signer:ident, $domain:ident, $max:ident) => {
        /// Structurally checked immutable claims awaiting their exact typed signature.
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $unsigned {
            claims: $claims,
            id: $id,
        }
        impl $unsigned {
            /// Validate bounded canonical claims without granting admission.
            pub fn new(claims: $claims) -> Result<Self, Error> {
                claims.check()?;
                let mut hash = Sha256::new();
                hash.update($domain);
                hash.update(claims.encode());
                Ok(Self {
                    claims,
                    id: $id(hash.finalize().into()),
                })
            }
            /// Decode canonical unsigned claims with allocation bounds.
            pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
                if bytes.len() > $max - 64 {
                    return Err(Error::Bounds);
                }
                Self::new($claims::decode(bytes)?)
            }
            /// Borrow checked but unsigned claims.
            pub const fn claims(&self) -> &$claims {
                &self.claims
            }
            /// Content commitment, excluding the signature representation.
            pub const fn id(&self) -> $id {
                self.id
            }
            /// Exact canonical unsigned frame.
            pub fn encode(&self) -> Vec<u8> {
                self.claims.encode()
            }
            /// Domain-separated transcript for this specific record type.
            pub fn signing_bytes(&self) -> Vec<u8> {
                let mut bytes = Vec::from($domain);
                bytes.extend_from_slice(&self.encode());
                bytes
            }
            /// Attach and strictly verify a signature over these exact claims.
            pub fn attach_signature(self, signature: [u8; 64]) -> Result<$signed, Error> {
                checked_key(&self.claims.$signer)?
                    .verify_strict(&self.signing_bytes(), &Signature::from_bytes(&signature))
                    .map_err(|_| Error::Signature)?;
                Ok($signed {
                    unsigned: self,
                    signature,
                })
            }
            /// Sign only this checked record with the exact claimed key.
            pub fn sign_with_key(self, key: &SigningKey) -> Result<$signed, Error> {
                if key.verifying_key().to_bytes() != self.claims.$signer {
                    return Err(Error::Signer);
                }
                let signature = key.sign(&self.signing_bytes()).to_bytes();
                self.attach_signature(signature)
            }
        }
        /// Decoded signed bytes whose signature and authorization remain untrusted.
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $signed {
            unsigned: $unsigned,
            signature: [u8; 64],
        }
        impl $signed {
            /// Decode exactly one bounded frame; signature verification is separate.
            pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
                if bytes.len() > $max {
                    return Err(Error::Bounds);
                }
                let split = bytes.len().checked_sub(64).ok_or(Error::Encoding)?;
                let unsigned = $unsigned::decode(&bytes[..split])?;
                let signature = bytes[split..].try_into().map_err(|_| Error::Encoding)?;
                Ok(Self {
                    unsigned,
                    signature,
                })
            }
            /// Exact signed frame, without asserting validity.
            pub fn encode(&self) -> Vec<u8> {
                let mut bytes = self.unsigned.encode();
                bytes.extend_from_slice(&self.signature);
                bytes
            }
            /// Explicitly unauthenticated decoded claims.
            pub const fn unverified_claims(&self) -> &$claims {
                self.unsigned.claims()
            }
            /// Claimed content commitment, not proof of its signature.
            pub const fn id(&self) -> $id {
                self.unsigned.id()
            }
            /// Authenticate the claimed key; room pinning and policy remain separate.
            pub fn verify(self) -> Result<$verified, Error> {
                checked_key(&self.unsigned.claims.$signer)?
                    .verify_strict(
                        &self.unsigned.signing_bytes(),
                        &Signature::from_bytes(&self.signature),
                    )
                    .map_err(|_| Error::Signature)?;
                Ok($verified(self))
            }
        }
        /// Immutable strictly authenticated content with no unchecked constructor.
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $verified($signed);
        impl $verified {
            /// Authenticated claims; a signature alone grants no policy authority.
            pub const fn claims(&self) -> &$claims {
                self.0.unverified_claims()
            }
            /// Full authenticated content commitment.
            pub const fn id(&self) -> $id {
                self.0.id()
            }
            /// Preserve exact signed bytes when storing or forwarding.
            pub fn encode(&self) -> Vec<u8> {
                self.0.encode()
            }
        }
    };
}
record!(
    UnsignedGenesis,
    SignedGenesis,
    VerifiedGenesis,
    GenesisClaims,
    RoomId,
    owner,
    GENESIS_DOMAIN,
    MAX_GENESIS_BYTES
);
record!(
    UnsignedPolicy,
    SignedPolicy,
    VerifiedPolicy,
    PolicyClaims,
    PolicyId,
    owner,
    POLICY_DOMAIN,
    MAX_POLICY_BYTES
);
record!(
    UnsignedEvent,
    SignedEvent,
    VerifiedEvent,
    EventClaims,
    EventId,
    author,
    EVENT_DOMAIN,
    MAX_EVENT_BYTES
);

impl SignedGenesis {
    /// Authenticate the genesis and match an independently chosen full room pin.
    pub fn verify_pin(self, expected: RoomId) -> Result<PinnedGenesis, Error> {
        let verified = self.verify()?;
        if verified.id() != expected {
            return Err(Error::Scope);
        }
        Ok(PinnedGenesis(verified))
    }
}

/// A genesis verified against the caller's separately selected full room ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedGenesis(VerifiedGenesis);
impl PinnedGenesis {
    /// The full independently pinned room commitment.
    pub const fn id(&self) -> RoomId {
        self.0.id()
    }
    /// Authenticated creation claims.
    pub const fn claims(&self) -> &GenesisClaims {
        self.0.claims()
    }
    /// Exact signed genesis for durable pin storage.
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode()
    }
}
