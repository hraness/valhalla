//! Canonical signed records. Verification is immutable evidence, not affiliation.
use crate::facets::*;
use crate::model::*;
#[cfg(test)]
use alloc::vec;
use alloc::vec::Vec;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use vhalla_core::{RealmId, RoomId};

const MAGIC: &[u8; 5] = b"VHSO\x01";
const ID_DOMAIN: &[u8] = b"vhalla/social/content-id/v1";
const SIGN_DOMAIN: &[u8] = b"vhalla/social/signature/v1";

/// A checked but unsigned record. It has no authority and contains no private key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsignedRecord {
    primary: [u8; 32],
    body: Body,
    id: RecordId,
}
impl UnsignedRecord {
    /// Validate all local fields and the complete eventual signed-frame bound.
    pub fn new(primary: [u8; 32], body: Body) -> Result<Self, Error> {
        checked_key(&primary)?;
        validate_body(&body, &primary)?;
        let mut value = Self {
            primary,
            body,
            id: RecordId::from_bytes([0; 32]),
        };
        let bytes = value.unsigned_bytes();
        let proof_size = 4
            + 64
            + 1
            + if value.body.acknowledgement_key().is_some() {
                64
            } else {
                0
            };
        if bytes.len() > MAX_RECORD_BYTES - proof_size {
            return Err(Error::Bounds);
        }
        let mut hash = Sha256::new();
        hash.update(ID_DOMAIN);
        hash.update(&bytes);
        value.id = RecordId::from_bytes(hash.finalize().into());
        Ok(value)
    }
    /// Content ID, excluding signature representations.
    #[must_use]
    pub const fn id(&self) -> RecordId {
        self.id
    }
    /// The exact immutable unsigned vocabulary.
    #[must_use]
    pub const fn body(&self) -> &Body {
        &self.body
    }
    /// Full primary signing key.
    #[must_use]
    pub const fn primary_key(&self) -> &[u8; 32] {
        &self.primary
    }
    /// Sign only the social domain, consuming this checked signing request.
    pub fn sign_with_key(self, key: &SigningKey) -> Result<PrimarySignedRecord, Error> {
        if key.verifying_key().to_bytes() != self.primary {
            return Err(Error::SigningKey);
        }
        let signature = key.sign(&signature_transcript(self.id)).to_bytes();
        Ok(PrimarySignedRecord {
            unsigned: self,
            signature,
        })
    }
    fn unsigned_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.primary);
        encode_body(&self.body, &mut out);
        out
    }
}

/// First signature, awaiting an explicit finish or the required second signer.
/// No decoder, mutable body, key export or generic signing transcript is exposed.
pub struct PrimarySignedRecord {
    unsigned: UnsignedRecord,
    signature: [u8; 64],
}
impl PrimarySignedRecord {
    /// Content ID remains unchanged when acknowledgement is attached.
    #[must_use]
    pub fn id(&self) -> RecordId {
        self.unsigned.id()
    }
    /// Finish a record that requires only its primary signer.
    pub fn finish(self) -> Result<SignedRecord, Error> {
        if self.unsigned.body.acknowledgement_key().is_some() {
            return Err(Error::AcknowledgementRequired);
        }
        Ok(SignedRecord {
            unsigned: self.unsigned,
            signature: self.signature,
            acknowledgement: None,
        })
    }
    /// Acknowledge exactly the agent genesis or planned key transition consumed here.
    pub fn countersign(self, key: &SigningKey) -> Result<SignedRecord, Error> {
        if self.unsigned.body.acknowledgement_key() != Some(key.verifying_key().to_bytes()) {
            return Err(Error::SigningKey);
        }
        let acknowledgement = key.sign(&signature_transcript(self.unsigned.id)).to_bytes();
        Ok(SignedRecord {
            unsigned: self.unsigned,
            signature: self.signature,
            acknowledgement: Some(acknowledgement),
        })
    }
}

/// Structurally checked signed bytes. A decoder cannot authenticate its own input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedRecord {
    unsigned: UnsignedRecord,
    signature: [u8; 64],
    acknowledgement: Option<[u8; 64]>,
}
impl SignedRecord {
    /// Parse bounded canonical bytes without admitting affiliation or authority.
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() > MAX_RECORD_BYTES {
            return Err(Error::Bounds);
        }
        let mut reader = Reader(raw);
        let len = reader.u32()? as usize;
        if !(38..=MAX_RECORD_BYTES - 69).contains(&len) {
            return Err(Error::Bounds);
        }
        let canonical = reader.take(len)?;
        let mut body_reader = Reader(canonical);
        if body_reader.take(MAGIC.len())? != MAGIC {
            return Err(Error::Encoding);
        }
        let primary = body_reader.array()?;
        let body = decode_body(&mut body_reader)?;
        if !body_reader.0.is_empty() {
            return Err(Error::Encoding);
        }
        let unsigned = UnsignedRecord::new(primary, body)?;
        if unsigned.unsigned_bytes() != canonical {
            return Err(Error::Encoding);
        }
        let signature = reader.array()?;
        let acknowledgement = match reader.u8()? {
            0 => None,
            1 => Some(reader.array()?),
            _ => return Err(Error::Encoding),
        };
        if !reader.0.is_empty()
            || acknowledgement.is_some() != unsigned.body.acknowledgement_key().is_some()
        {
            return Err(Error::Encoding);
        }
        Ok(Self {
            unsigned,
            signature,
            acknowledgement,
        })
    }
    /// Canonical exact proof bytes; structural construction already checked the bound.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let unsigned = self.unsigned.unsigned_bytes();
        let mut out = Vec::with_capacity(unsigned.len() + 133);
        out.extend_from_slice(&(unsigned.len() as u32).to_be_bytes());
        out.extend_from_slice(&unsigned);
        out.extend_from_slice(&self.signature);
        out.push(u8::from(self.acknowledgement.is_some()));
        if let Some(signature) = self.acknowledgement {
            out.extend_from_slice(&signature);
        }
        out
    }
    /// Claimed content ID. It is not signature or affiliation evidence.
    #[must_use]
    pub fn id(&self) -> RecordId {
        self.unsigned.id()
    }
    /// Inspect only the immutable unauthenticated vocabulary.
    #[must_use]
    pub fn body(&self) -> &Body {
        self.unsigned.body()
    }
    /// Verify every required full-key signature strictly. Replay deduplicates by ID
    /// in the archive; this operation alone grants no social or host authority.
    pub fn verify(self) -> Result<VerifiedRecord, Error> {
        let transcript = signature_transcript(self.id());
        checked_key(self.unsigned.primary_key())?
            .verify_strict(&transcript, &Signature::from_bytes(&self.signature))
            .map_err(|_| Error::Signature)?;
        match (
            self.unsigned.body.acknowledgement_key(),
            self.acknowledgement,
        ) {
            (Some(key), Some(signature)) => checked_key(&key)?
                .verify_strict(&transcript, &Signature::from_bytes(&signature))
                .map_err(|_| Error::Signature)?,
            (None, None) => {}
            _ => return Err(Error::Signature),
        }
        Ok(VerifiedRecord(self))
    }
}

/// Immutable signature evidence. It is cloneable historical data, not a consumable
/// effect capability; current affiliation must be derived against control history.
///
/// ```compile_fail
/// use vhalla_social::{SignedRecord, VerifiedRecord};
/// fn skip_verification(raw: SignedRecord) -> VerifiedRecord { raw.into() }
/// ```
/// ```compile_fail
/// use vhalla_social::VerifiedRecord;
/// fn replace_body(record: &mut VerifiedRecord) { record.0 = todo!(); }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRecord(SignedRecord);
impl VerifiedRecord {
    /// Exact logical record ID.
    #[must_use]
    pub fn id(&self) -> RecordId {
        self.0.id()
    }
    /// Exact immutable authenticated payload; authorization remains separate.
    #[must_use]
    pub fn body(&self) -> &Body {
        self.0.body()
    }
    /// Complete authenticated primary key.
    #[must_use]
    pub fn primary_key(&self) -> &[u8; 32] {
        self.0.unsigned.primary_key()
    }
    /// Re-emit complete signed evidence; never serialize a derived authority state.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode()
    }
}

fn checked_key(bytes: &[u8; 32]) -> Result<VerifyingKey, Error> {
    let key = VerifyingKey::from_bytes(bytes).map_err(|_| Error::Key)?;
    if key.is_weak() {
        return Err(Error::Key);
    }
    Ok(key)
}
fn signature_transcript(id: RecordId) -> Vec<u8> {
    let mut out = Vec::with_capacity(SIGN_DOMAIN.len() + 32);
    out.extend_from_slice(SIGN_DOMAIN);
    out.extend_from_slice(id.as_bytes());
    out
}
fn validate_body(body: &Body, primary: &[u8; 32]) -> Result<(), Error> {
    match body {
        Body::OwnerGenesis {
            controller,
            recovery,
            ..
        } => {
            if controller != primary {
                return Err(Error::SigningKey);
            }
            checked_key(controller)?;
            if let Some(key) = recovery {
                checked_key(key)?;
            }
        }
        Body::Control { action, .. } => match action {
            ControlAction::Grant { expires_at, .. } if *expires_at == 0 => {
                return Err(Error::Bounds)
            }
            ControlAction::Rotate { new_key } => {
                checked_key(new_key)?;
            }
            _ => {}
        },
        Body::AgentGenesis { key, .. } => {
            checked_key(key)?;
        }
        Body::Social {
            sequence,
            previous,
            operation,
            ..
        } => {
            if (*sequence == 0) != previous.is_none() {
                return Err(Error::Encoding);
            }
            match operation {
                Operation::AgentBio { text, .. } | Operation::OwnerProfile { text, .. }
                    if text.as_str().len() > MAX_BIO_BYTES =>
                {
                    return Err(Error::Bounds)
                }
                Operation::Revise { supersedes, .. }
                | Operation::ReviseFaceted { supersedes, .. }
                    if supersedes.as_slice().is_empty() =>
                {
                    return Err(Error::Encoding)
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn put_id(out: &mut Vec<u8>, id: RecordId) {
    out.extend_from_slice(id.as_bytes());
}
fn put_owner(out: &mut Vec<u8>, id: OwnerId) {
    out.extend_from_slice(id.as_bytes());
}
fn put_agent(out: &mut Vec<u8>, id: AgentId) {
    out.extend_from_slice(id.as_bytes());
}
fn put_realm(out: &mut Vec<u8>, realm: RealmId) {
    out.extend_from_slice(&realm.0.to_be_bytes());
}
fn put_refs(out: &mut Vec<u8>, refs: &References) {
    out.push(refs.as_slice().len() as u8);
    for id in refs.as_slice() {
        put_id(out, *id);
    }
}
fn put_text(out: &mut Vec<u8>, text: &Text) {
    out.extend_from_slice(&(text.as_str().len() as u16).to_be_bytes());
    out.extend_from_slice(text.as_str().as_bytes());
}
fn put_post_ref(out: &mut Vec<u8>, reference: PostRef) {
    put_id(out, reference.post);
    put_id(out, reference.revision);
}
fn put_optional_id(out: &mut Vec<u8>, id: Option<RecordId>) {
    out.push(u8::from(id.is_some()));
    if let Some(id) = id {
        put_id(out, id);
    }
}
fn encode_actor(actor: Actor, out: &mut Vec<u8>) {
    match actor {
        Actor::Owner { owner, control } => {
            out.push(0);
            put_owner(out, owner);
            put_id(out, control);
        }
        Actor::Agent {
            owner,
            agent,
            grant,
        } => {
            out.push(1);
            put_owner(out, owner);
            put_agent(out, agent);
            put_id(out, grant);
        }
    }
}
fn encode_body(body: &Body, out: &mut Vec<u8>) {
    match body {
        Body::OwnerGenesis {
            controller,
            recovery,
            nonce,
        } => {
            out.push(0);
            out.extend_from_slice(controller);
            out.push(u8::from(recovery.is_some()));
            if let Some(key) = recovery {
                out.extend_from_slice(key);
            }
            out.extend_from_slice(nonce);
        }
        Body::Control {
            owner,
            previous,
            action,
        } => {
            out.push(1);
            put_owner(out, *owner);
            put_id(out, *previous);
            match action {
                ControlAction::Grant {
                    agent,
                    realm,
                    rights,
                    expires_at,
                    nonce,
                } => {
                    out.push(0);
                    put_agent(out, *agent);
                    put_realm(out, *realm);
                    out.push(rights.bits());
                    out.extend_from_slice(&expires_at.to_be_bytes());
                    out.extend_from_slice(nonce);
                }
                ControlAction::Revoke { grant, accepted } => {
                    out.push(1);
                    put_id(out, *grant);
                    put_refs(out, accepted);
                }
                ControlAction::Retire {
                    agent,
                    realm,
                    accepted,
                } => {
                    out.push(2);
                    put_agent(out, *agent);
                    put_realm(out, *realm);
                    put_refs(out, accepted);
                }
                ControlAction::Seal { realm, heads } => {
                    out.push(3);
                    put_realm(out, *realm);
                    put_refs(out, heads);
                }
                ControlAction::Ratify { realm, heads } => {
                    out.push(4);
                    put_realm(out, *realm);
                    put_refs(out, heads);
                }
                ControlAction::Rotate { new_key } => {
                    out.push(5);
                    out.extend_from_slice(new_key);
                }
            }
        }
        Body::AgentGenesis {
            owner,
            control,
            key,
            nonce,
        } => {
            out.push(2);
            put_owner(out, *owner);
            put_id(out, *control);
            out.extend_from_slice(key);
            out.extend_from_slice(nonce);
        }
        Body::Social {
            actor,
            realm,
            sequence,
            previous,
            operation,
        } => {
            out.push(3);
            encode_actor(*actor, out);
            put_realm(out, *realm);
            out.extend_from_slice(&sequence.to_be_bytes());
            put_optional_id(out, *previous);
            encode_operation(operation, out);
        }
    }
}
fn encode_post_fields(
    placement: Placement,
    text: &Text,
    reply: Option<ReplyRef>,
    quote: Option<PostRef>,
    out: &mut Vec<u8>,
) {
    match placement {
        Placement::Profile => out.push(0),
        Placement::Channel(room) => {
            out.push(1);
            out.extend_from_slice(&room.0.to_be_bytes());
        }
    }
    put_text(out, text);
    out.push(u8::from(reply.is_some()));
    if let Some(reply) = reply {
        put_id(out, reply.root);
        put_post_ref(out, reply.parent);
    }
    out.push(u8::from(quote.is_some()));
    if let Some(quote) = quote {
        put_post_ref(out, quote);
    }
}
fn encode_revision_fields(post: RecordId, text: &Text, supersedes: &References, out: &mut Vec<u8>) {
    put_id(out, post);
    put_text(out, text);
    put_refs(out, supersedes);
}
fn encode_facets(facets: &[Facet], out: &mut Vec<u8>) {
    out.push(facets.len() as u8);
    for facet in facets {
        out.extend_from_slice(&facet.start.to_be_bytes());
        out.extend_from_slice(&facet.end.to_be_bytes());
        match &facet.kind {
            FacetKind::Mention(MentionTarget::Owner(id)) => {
                out.push(0);
                put_owner(out, *id);
            }
            FacetKind::Mention(MentionTarget::Agent(id)) => {
                out.push(1);
                put_agent(out, *id);
            }
            FacetKind::Tag(tag) => {
                out.push(2);
                out.push(tag.as_str().len() as u8);
                out.extend_from_slice(tag.as_str().as_bytes());
            }
        }
    }
}
fn encode_operation(operation: &Operation, out: &mut Vec<u8>) {
    match operation {
        Operation::Post {
            placement,
            text,
            reply,
            quote,
        } => {
            out.push(0);
            encode_post_fields(*placement, text, *reply, *quote, out);
        }
        Operation::PostFaceted {
            placement,
            content,
            reply,
            quote,
        } => {
            out.push(8);
            encode_post_fields(*placement, content.text(), *reply, *quote, out);
            encode_facets(content.facets(), out);
        }
        Operation::Revise {
            post,
            text,
            supersedes,
        } => {
            out.push(1);
            encode_revision_fields(*post, text, supersedes, out);
        }
        Operation::ReviseFaceted {
            post,
            content,
            supersedes,
        } => {
            out.push(9);
            encode_revision_fields(*post, content.text(), supersedes, out);
            encode_facets(content.facets(), out);
        }
        Operation::Retract { post } => {
            out.push(2);
            put_id(out, *post);
        }
        Operation::Repost {
            post,
            revision,
            supersedes,
        } => {
            out.push(3);
            put_id(out, *post);
            put_optional_id(out, *revision);
            put_refs(out, supersedes);
        }
        Operation::React {
            post,
            reaction,
            supersedes,
        } => {
            out.push(4);
            put_id(out, *post);
            match reaction {
                Reaction::Clear => out.push(0),
                Reaction::Up(rev) => {
                    out.push(1);
                    put_id(out, *rev);
                }
                Reaction::Down(rev) => {
                    out.push(2);
                    put_id(out, *rev);
                }
            }
            put_refs(out, supersedes);
        }
        Operation::Follow {
            target,
            following,
            supersedes,
        } => {
            out.push(5);
            put_owner(out, *target);
            out.push(u8::from(*following));
            put_refs(out, supersedes);
        }
        Operation::AgentBio { text, supersedes } => {
            out.push(6);
            put_text(out, text);
            put_refs(out, supersedes);
        }
        Operation::OwnerProfile { text, supersedes } => {
            out.push(7);
            put_text(out, text);
            put_refs(out, supersedes);
        }
    }
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let part = self.0.get(..len).ok_or(Error::Encoding)?;
        self.0 = &self.0[len..];
        Ok(part)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Encoding)
    }
    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.array::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn u128(&mut self) -> Result<u128, Error> {
        Ok(u128::from_be_bytes(self.array()?))
    }
    fn bool(&mut self) -> Result<bool, Error> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Encoding),
        }
    }
    fn id(&mut self) -> Result<RecordId, Error> {
        Ok(RecordId::from_bytes(self.array()?))
    }
    fn owner(&mut self) -> Result<OwnerId, Error> {
        Ok(OwnerId::from_bytes(self.array()?))
    }
    fn agent(&mut self) -> Result<AgentId, Error> {
        Ok(AgentId::from_bytes(self.array()?))
    }
    fn realm(&mut self) -> Result<RealmId, Error> {
        Ok(RealmId(self.u128()?))
    }
    fn optional_id(&mut self) -> Result<Option<RecordId>, Error> {
        if self.bool()? {
            Ok(Some(self.id()?))
        } else {
            Ok(None)
        }
    }
    fn text(&mut self) -> Result<Text, Error> {
        let len = self.u16()? as usize;
        if len > MAX_TEXT_BYTES {
            return Err(Error::Bounds);
        }
        Text::new(core::str::from_utf8(self.take(len)?).map_err(|_| Error::Encoding)?)
    }
    fn facets(&mut self) -> Result<Vec<Facet>, Error> {
        let count = usize::from(self.u8()?);
        if count > MAX_FACETS {
            return Err(Error::Bounds);
        }
        let mut facets = Vec::with_capacity(count);
        for _ in 0..count {
            let start = self.u16()?;
            let end = self.u16()?;
            let kind = match self.u8()? {
                0 => FacetKind::Mention(MentionTarget::Owner(self.owner()?)),
                1 => FacetKind::Mention(MentionTarget::Agent(self.agent()?)),
                2 => {
                    let len = usize::from(self.u8()?);
                    if len > MAX_TAG_BYTES {
                        return Err(Error::Bounds);
                    }
                    let text =
                        core::str::from_utf8(self.take(len)?).map_err(|_| Error::Encoding)?;
                    FacetKind::Tag(CanonicalTag::canonical(text)?)
                }
                _ => return Err(Error::Encoding),
            };
            facets.push(Facet { start, end, kind });
        }
        Ok(facets)
    }
    fn refs(&mut self) -> Result<References, Error> {
        let len = self.u8()? as usize;
        if len > MAX_REFS {
            return Err(Error::Bounds);
        }
        let mut ids = Vec::with_capacity(len);
        for _ in 0..len {
            ids.push(self.id()?);
        }
        References::new(ids)
    }
    fn post_ref(&mut self) -> Result<PostRef, Error> {
        Ok(PostRef {
            post: self.id()?,
            revision: self.id()?,
        })
    }
}
fn decode_actor(r: &mut Reader<'_>) -> Result<Actor, Error> {
    match r.u8()? {
        0 => Ok(Actor::Owner {
            owner: r.owner()?,
            control: r.id()?,
        }),
        1 => Ok(Actor::Agent {
            owner: r.owner()?,
            agent: r.agent()?,
            grant: r.id()?,
        }),
        _ => Err(Error::Encoding),
    }
}
fn decode_body(r: &mut Reader<'_>) -> Result<Body, Error> {
    match r.u8()? {
        0 => Ok(Body::OwnerGenesis {
            controller: r.array()?,
            recovery: if r.bool()? { Some(r.array()?) } else { None },
            nonce: r.array()?,
        }),
        1 => {
            let owner = r.owner()?;
            let previous = r.id()?;
            let action = match r.u8()? {
                0 => ControlAction::Grant {
                    agent: r.agent()?,
                    realm: r.realm()?,
                    rights: Rights::from_bits(r.u8()?)?,
                    expires_at: r.u64()?,
                    nonce: r.array()?,
                },
                1 => ControlAction::Revoke {
                    grant: r.id()?,
                    accepted: r.refs()?,
                },
                2 => ControlAction::Retire {
                    agent: r.agent()?,
                    realm: r.realm()?,
                    accepted: r.refs()?,
                },
                3 => ControlAction::Seal {
                    realm: r.realm()?,
                    heads: r.refs()?,
                },
                4 => ControlAction::Ratify {
                    realm: r.realm()?,
                    heads: r.refs()?,
                },
                5 => ControlAction::Rotate {
                    new_key: r.array()?,
                },
                _ => return Err(Error::Encoding),
            };
            Ok(Body::Control {
                owner,
                previous,
                action,
            })
        }
        2 => Ok(Body::AgentGenesis {
            owner: r.owner()?,
            control: r.id()?,
            key: r.array()?,
            nonce: r.array()?,
        }),
        3 => Ok(Body::Social {
            actor: decode_actor(r)?,
            realm: r.realm()?,
            sequence: r.u64()?,
            previous: r.optional_id()?,
            operation: decode_operation(r)?,
        }),
        128 => Err(Error::PrivateDisabled),
        _ => Err(Error::Encoding),
    }
}
fn decode_operation(r: &mut Reader<'_>) -> Result<Operation, Error> {
    match r.u8()? {
        opcode @ (0 | 8) => {
            let placement = match r.u8()? {
                0 => Placement::Profile,
                1 => Placement::Channel(RoomId(r.u128()?)),
                _ => return Err(Error::Encoding),
            };
            let text = r.text()?;
            let reply = if r.bool()? {
                Some(ReplyRef {
                    root: r.id()?,
                    parent: r.post_ref()?,
                })
            } else {
                None
            };
            let quote = if r.bool()? { Some(r.post_ref()?) } else { None };
            if opcode == 8 {
                let content = FacetedText::new(text, r.facets()?)?;
                Ok(Operation::PostFaceted {
                    placement,
                    content,
                    reply,
                    quote,
                })
            } else {
                Ok(Operation::Post {
                    placement,
                    text,
                    reply,
                    quote,
                })
            }
        }
        opcode @ (1 | 9) => {
            let post = r.id()?;
            let text = r.text()?;
            let supersedes = r.refs()?;
            if opcode == 9 {
                let content = FacetedText::new(text, r.facets()?)?;
                Ok(Operation::ReviseFaceted {
                    post,
                    content,
                    supersedes,
                })
            } else {
                Ok(Operation::Revise {
                    post,
                    text,
                    supersedes,
                })
            }
        }
        2 => Ok(Operation::Retract { post: r.id()? }),
        3 => Ok(Operation::Repost {
            post: r.id()?,
            revision: r.optional_id()?,
            supersedes: r.refs()?,
        }),
        4 => {
            let post = r.id()?;
            let reaction = match r.u8()? {
                0 => Reaction::Clear,
                1 => Reaction::Up(r.id()?),
                2 => Reaction::Down(r.id()?),
                _ => return Err(Error::Encoding),
            };
            Ok(Operation::React {
                post,
                reaction,
                supersedes: r.refs()?,
            })
        }
        5 => Ok(Operation::Follow {
            target: r.owner()?,
            following: r.bool()?,
            supersedes: r.refs()?,
        }),
        6 => Ok(Operation::AgentBio {
            text: r.text()?,
            supersedes: r.refs()?,
        }),
        7 => Ok(Operation::OwnerProfile {
            text: r.text()?,
            supersedes: r.refs()?,
        }),
        _ => Err(Error::Encoding),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }
    fn root(n: u8) -> SignedRecord {
        let k = key(n);
        UnsignedRecord::new(
            k.verifying_key().to_bytes(),
            Body::OwnerGenesis {
                controller: k.verifying_key().to_bytes(),
                recovery: None,
                nonce: [42; 32],
            },
        )
        .unwrap()
        .sign_with_key(&k)
        .unwrap()
        .finish()
        .unwrap()
    }
    #[test]
    fn owner_genesis_matches_independent_python_transcript_vector() {
        // vectors/social-v1.json, generated with Python hashlib/struct rather
        // than this encoder. The complete fixture is public, never deployable.
        let signed = root(1);
        let id = signed
            .id()
            .as_bytes()
            .iter()
            .map(|b| alloc::format!("{b:02x}"))
            .collect::<alloc::string::String>();
        assert_eq!(
            id,
            "55790ef35564706a7cf3e24f9d16caa7c312b3e2719b22170cd8b41103065088"
        );
        let raw = signed.encode();
        assert_eq!(&raw[..4], &103_u32.to_be_bytes());
        assert_eq!(&raw[4..9], b"VHSO\x01");
        assert_eq!(raw.len(), 172);
    }

    #[test]
    fn full_bound_and_required_acknowledgements_are_checked_before_evidence() {
        let owner = key(1);
        let agent = key(2);
        let body = Body::AgentGenesis {
            owner: OwnerId::from_bytes(*root(1).id().as_bytes()),
            control: root(1).id(),
            key: agent.verifying_key().to_bytes(),
            nonce: [7; 32],
        };
        let request = UnsignedRecord::new(owner.verifying_key().to_bytes(), body).unwrap();
        assert_eq!(
            request
                .clone()
                .sign_with_key(&owner)
                .unwrap()
                .finish()
                .err(),
            Some(Error::AcknowledgementRequired)
        );
        assert_eq!(
            request
                .clone()
                .sign_with_key(&agent)
                .err()
                .map(|_| Error::SigningKey),
            Some(Error::SigningKey)
        );
        let signed = request
            .sign_with_key(&owner)
            .unwrap()
            .countersign(&agent)
            .unwrap();
        let raw = signed.encode();
        assert_eq!(
            SignedRecord::decode(&raw)
                .unwrap()
                .verify()
                .unwrap()
                .encode(),
            raw
        );
        let mut bad = raw.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert_eq!(
            SignedRecord::decode(&bad).unwrap().verify().err(),
            Some(Error::Signature)
        );
        assert_eq!(
            SignedRecord::decode(&vec![0; MAX_RECORD_BYTES + 1]).err(),
            Some(Error::Bounds)
        );
    }
    #[test]
    fn wire_rejects_every_truncation_trailing_bytes_and_invalid_keys() {
        let signed = root(1);
        let raw = signed.encode();
        for len in 0..raw.len() {
            assert!(SignedRecord::decode(&raw[..len]).is_err());
        }
        let mut trailing = raw.clone();
        trailing.push(0);
        assert!(SignedRecord::decode(&trailing).is_err());
        let mut invalid = raw;
        invalid[4 + MAGIC.len()..4 + MAGIC.len() + 32].fill(0);
        assert!(SignedRecord::decode(&invalid).is_err());
        assert!(References::new(vec![RecordId::from_bytes([1; 32]); 2]).is_err());
        assert!(Rights::from_bits(128).is_err());
        assert!(Rights::from_bits(0).is_err());
    }
    #[test]
    fn content_identity_ignores_proof_mutation_but_verification_does_not() {
        let signed = root(4);
        let mut raw = signed.encode();
        let len = raw.len();
        raw[len - 2] ^= 1;
        let mutated = SignedRecord::decode(&raw).unwrap();
        assert_eq!(mutated.id(), signed.id());
        assert_eq!(mutated.verify().err(), Some(Error::Signature));
    }
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        #[test]
        fn arbitrary_bounded_foreign_bytes_never_make_unchecked_evidence(raw in prop::collection::vec(any::<u8>(),0..MAX_RECORD_BYTES+2)) {
            if let Ok(record) = SignedRecord::decode(&raw) {
                prop_assert_eq!(record.encode(), raw);
                let _ = record.verify();
            }
        }
        #[test]
        fn text_sign_roundtrip_and_mutation(text in ".{0,256}", sequence in 0u64..100) {
            let k=key(8); let genesis=root(8);
            let body=Body::Social { actor:Actor::Owner { owner:OwnerId::from_bytes(*genesis.id().as_bytes()), control:genesis.id() }, realm:RealmId(7), sequence,
                previous:if sequence==0 {None}else{Some(RecordId::from_bytes([9;32]))},
                operation:Operation::Post { placement:Placement::Profile,text:Text::new(&text).unwrap(),reply:None,quote:None } };
            let signed=UnsignedRecord::new(k.verifying_key().to_bytes(),body).unwrap().sign_with_key(&k).unwrap().finish().unwrap();
            let raw=signed.encode(); prop_assert!(raw.len()<=MAX_RECORD_BYTES);
            let verified=SignedRecord::decode(&raw).unwrap().verify().unwrap(); prop_assert_eq!(verified.encode(),raw);
        }
    }
}
