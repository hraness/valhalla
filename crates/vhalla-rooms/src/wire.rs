//! Canonical room signature evidence. No decoder or signer admits authority.
use crate::model::*;
use alloc::vec::Vec;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use vhalla_core::RealmId;
use vhalla_social::{AgentId, OwnerId, RecordId};

const MAGIC: &[u8; 5] = b"VHRM\x01";
const CONTROL: u8 = 0;
const CREATE: u8 = 1;
const UPDATE: u8 = 2;
const PERMIT: u8 = 3;
const RECORD_DOMAIN: &[u8] = b"vhalla/rooms/record-id/v1";
const GENESIS_DOMAIN: &[u8] = b"vhalla/rooms/genesis-id/v1";
const PERMIT_DOMAIN: &[u8] = b"vhalla/rooms/permit-id/v1";
const CONTROL_SIGN: &[u8] = b"vhalla/rooms/control-signature/v1";
const UPDATE_SIGN: &[u8] = b"vhalla/rooms/update-signature/v1";
const OWNER_SIGN: &[u8] = b"vhalla/rooms/owner-permit-signature/v1";
const AGENT_SIGN: &[u8] = b"vhalla/rooms/agent-proposal-signature/v1";

/// Structurally checked owner signature over one exact intent. It is not a grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerPermit {
    intent: CreationIntent,
    signature: [u8; 64],
}
impl OwnerPermit {
    /// Sign only the dedicated exact-permit domain with the claimed owner key.
    /// Local custody policy must decide whether to call this signing operation.
    pub fn sign_with_key(intent: CreationIntent, key: &SigningKey) -> Result<Self, Error> {
        check_intent(&intent)?;
        require_signer(key, &intent.owner_key)?;
        let signature = key.sign(&owner_transcript(&intent)).to_bytes();
        Ok(Self { intent, signature })
    }
    /// Parse a bounded canonical permit, without authenticating its signature.
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        let frame = split_frame(raw)?;
        if frame.tag != PERMIT {
            return Err(Error::Encoding);
        }
        let mut reader = Reader(frame.payload);
        let intent = read_intent(&mut reader)?;
        reader.finish()?;
        check_intent(&intent)?;
        let permit = Self {
            intent,
            signature: frame.primary,
        };
        if permit.encode() != raw {
            return Err(Error::Encoding);
        }
        Ok(permit)
    }
    /// Serialize only immutable signed evidence, never a current-authority token.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        frame(PERMIT, &intent_bytes(&self.intent), &self.signature, None)
    }
    /// Exact content commitment; signature verification remains separate.
    #[must_use]
    pub fn id(&self) -> PermitId {
        permit_id(&self.intent)
    }
    /// Full proposed room genesis commitment, with no routing conversion.
    #[must_use]
    pub fn genesis_id(&self) -> RoomGenesisId {
        genesis_id(&self.intent)
    }
    /// Borrow immutable, still-untrusted authority claims.
    #[must_use]
    pub const fn intent(&self) -> &CreationIntent {
        &self.intent
    }
    /// Check the full-key owner signature strictly; affiliation remains unproved.
    pub fn verify(self) -> Result<VerifiedOwnerPermit, Error> {
        verify_signature(
            &self.intent.owner_key,
            &owner_transcript(&self.intent),
            &self.signature,
        )?;
        Ok(VerifiedOwnerPermit(self))
    }
}

/// Immutable owner signature evidence, not current permission or controller proof.
///
/// ```compile_fail
/// use vhalla_rooms::{OwnerPermit, VerifiedOwnerPermit};
/// fn skip(raw: OwnerPermit) -> VerifiedOwnerPermit { raw.into() }
/// ```
/// ```compile_fail
/// use vhalla_rooms::{OwnerPermit, VerifiedOwnerPermit};
/// fn fabricate(raw: OwnerPermit) -> VerifiedOwnerPermit { VerifiedOwnerPermit(raw) }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedOwnerPermit(OwnerPermit);
impl VerifiedOwnerPermit {
    /// Exact immutable signed intent; no mutable references escape.
    #[must_use]
    pub const fn intent(&self) -> &CreationIntent {
        &self.0.intent
    }
    /// Exact permit commitment, independent of signature representation.
    #[must_use]
    pub fn id(&self) -> PermitId {
        self.0.id()
    }
    /// Full immutable proposed genesis commitment.
    #[must_use]
    pub fn genesis_id(&self) -> RoomGenesisId {
        self.0.genesis_id()
    }
    /// Re-emit evidence; verification and admission must be repeated on receipt.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode()
    }
    /// Sign the agent-proposal domain for this exact verified owner permit.
    /// This acknowledges content, not affiliation, freshness or directory finality.
    pub fn propose_with_key(self, key: &SigningKey) -> Result<AgentProposal, Error> {
        require_signer(key, &self.0.intent.agent_key)?;
        let acknowledgement = key.sign(&agent_transcript(&self.0.intent)).to_bytes();
        Ok(AgentProposal(SignedRecord {
            body: Body::Create(self.0.intent),
            signature: self.0.signature,
            acknowledgement: Some(acknowledgement),
        }))
    }
}

/// Exact owner-permitted and agent-signed proposal, still not an admitted room.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentProposal(SignedRecord);
impl AgentProposal {
    /// Decode only a complete creation proposal, without admitting signatures.
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        let record = SignedRecord::decode(raw)?;
        if !matches!(record.body(), Body::Create(_)) {
            return Err(Error::Encoding);
        }
        Ok(Self(record))
    }
    /// Encode the complete bounded proposal.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode()
    }
    /// Full immutable proposed genesis commitment, never a routing handle.
    #[must_use]
    pub fn genesis_id(&self) -> RoomGenesisId {
        // The private wrapper is constructed only around Body::Create.
        match self.0.body() {
            Body::Create(intent) => genesis_id(intent),
            _ => unreachable!("private creation wrapper"),
        }
    }
    /// Move the proposal into the common immutable evidence representation.
    #[must_use]
    pub fn into_record(self) -> SignedRecord {
        self.0
    }
    /// Strictly verify both distinct signature roles, without admission.
    pub fn verify(self) -> Result<VerifiedRecord, Error> {
        self.0.verify()
    }
}

impl RoomControl {
    /// Sign only the room-control domain with the claimed controller key.
    pub fn sign_with_key(self, key: &SigningKey) -> Result<SignedRecord, Error> {
        check_control(&self)?;
        require_signer(key, &self.controller_key)?;
        let body = Body::Control(self);
        let signature = key.sign(&controller_transcript(&body)).to_bytes();
        Ok(SignedRecord {
            body,
            signature,
            acknowledgement: None,
        })
    }
}
impl RoomUpdate {
    /// Sign only the room-update domain with the claimed controller key.
    pub fn sign_with_key(self, key: &SigningKey) -> Result<SignedRecord, Error> {
        check_update(&self)?;
        require_signer(key, &self.controller_key)?;
        let body = Body::Update(self);
        let signature = key.sign(&controller_transcript(&body)).to_bytes();
        Ok(SignedRecord {
            body,
            signature,
            acknowledgement: None,
        })
    }
}

/// Structurally checked signed bytes. Its claimed signer may lack any authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedRecord {
    body: Body,
    signature: [u8; 64],
    acknowledgement: Option<[u8; 64]>,
}
impl SignedRecord {
    /// Reject oversized, unknown, noncanonical and trailing input before verification.
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        let frame = split_frame(raw)?;
        let mut reader = Reader(frame.payload);
        let body = match frame.tag {
            CONTROL => Body::Control(read_control(&mut reader)?),
            CREATE => Body::Create(read_intent(&mut reader)?),
            UPDATE => Body::Update(read_update(&mut reader)?),
            _ => return Err(Error::Encoding),
        };
        reader.finish()?;
        check_body(&body)?;
        let record = Self {
            body,
            signature: frame.primary,
            acknowledgement: frame.secondary,
        };
        if record.encode() != raw {
            return Err(Error::Encoding);
        }
        Ok(record)
    }
    /// Canonical complete bytes; private construction preserves all frame bounds.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let (tag, payload) = body_bytes(&self.body);
        frame(
            tag,
            &payload,
            &self.signature,
            self.acknowledgement.as_ref(),
        )
    }
    /// Canonical unsigned content ID, excluding signature representations.
    #[must_use]
    pub fn id(&self) -> RoomRecordId {
        record_id(&self.body)
    }
    /// Full genesis commitment for a creation proposal only.
    #[must_use]
    pub fn genesis_id(&self) -> Option<RoomGenesisId> {
        match &self.body {
            Body::Create(intent) => Some(genesis_id(intent)),
            _ => None,
        }
    }
    /// Inspect immutable claims, without assigning authority to them.
    #[must_use]
    pub const fn body(&self) -> &Body {
        &self.body
    }
    /// Strictly verify every required role. No controller/grant/current-state claim
    /// is admitted, and no room is reserved or finalized by this operation.
    pub fn verify(self) -> Result<VerifiedRecord, Error> {
        match &self.body {
            Body::Create(intent) => {
                verify_signature(
                    &intent.owner_key,
                    &owner_transcript(intent),
                    &self.signature,
                )?;
                let secondary = self.acknowledgement.as_ref().ok_or(Error::Signature)?;
                verify_signature(&intent.agent_key, &agent_transcript(intent), secondary)?;
            }
            Body::Control(control) => {
                if self.acknowledgement.is_some() {
                    return Err(Error::Signature);
                }
                verify_signature(
                    &control.controller_key,
                    &controller_transcript(&self.body),
                    &self.signature,
                )?;
            }
            Body::Update(update) => {
                if self.acknowledgement.is_some() {
                    return Err(Error::Signature);
                }
                verify_signature(
                    &update.controller_key,
                    &controller_transcript(&self.body),
                    &self.signature,
                )?;
            }
        }
        Ok(VerifiedRecord(self))
    }
}

/// Immutable signature evidence only. It cannot be upgraded to authority here.
///
/// ```compile_fail
/// use vhalla_rooms::{SignedRecord, VerifiedRecord};
/// fn skip(raw: SignedRecord) -> VerifiedRecord { raw.into() }
/// ```
/// ```compile_fail
/// use vhalla_rooms::{SignedRecord, VerifiedRecord};
/// fn fabricate(raw: SignedRecord) -> VerifiedRecord { VerifiedRecord(raw) }
/// ```
/// ```compile_fail
/// use vhalla_rooms::{Body, VerifiedRecord};
/// fn mutate(record: &mut VerifiedRecord, body: Body) { *record.body() = body; }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRecord(SignedRecord);
impl VerifiedRecord {
    /// Canonical unsigned room-record identifier.
    #[must_use]
    pub fn id(&self) -> RoomRecordId {
        self.0.id()
    }
    /// Full proposed genesis commitment, with no routing conversion.
    #[must_use]
    pub fn genesis_id(&self) -> Option<RoomGenesisId> {
        self.0.genesis_id()
    }
    /// Immutable signed content; every authority field still needs admission.
    #[must_use]
    pub const fn body(&self) -> &Body {
        self.0.body()
    }
    /// Re-emit historical evidence, never a serializable authority capability.
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
fn require_signer(key: &SigningKey, expected: &[u8; 32]) -> Result<(), Error> {
    if &key.verifying_key().to_bytes() != expected {
        return Err(Error::SigningKey);
    }
    Ok(())
}
fn verify_signature(key: &[u8; 32], transcript: &[u8], signature: &[u8; 64]) -> Result<(), Error> {
    checked_key(key)?
        .verify_strict(transcript, &Signature::from_bytes(signature))
        .map_err(|_| Error::Signature)
}
fn check_control(value: &RoomControl) -> Result<(), Error> {
    checked_key(&value.controller_key)?;
    if (value.sequence == 0) != value.previous.is_none() {
        return Err(Error::Encoding);
    }
    if let CreateAction::GrantCreate {
        agent_key,
        expires_at,
        maximum_charge,
        nonce,
        ..
    } = &value.action
    {
        checked_key(agent_key)?;
        if *expires_at == 0 || *maximum_charge == 0 || *nonce == [0; 32] {
            return Err(Error::Bounds);
        }
    }
    Ok(())
}
fn check_intent(value: &CreationIntent) -> Result<(), Error> {
    checked_key(&value.owner_key)?;
    checked_key(&value.agent_key)?;
    if value.slot == 0 || value.charge == 0 || value.expires_at == 0 || value.nonce == [0; 32] {
        return Err(Error::Bounds);
    }
    Ok(())
}
fn check_update(value: &RoomUpdate) -> Result<(), Error> {
    checked_key(&value.controller_key)?;
    if value.expires_at == 0 || value.nonce == [0; 32] {
        return Err(Error::Bounds);
    }
    if matches!(&value.action, UpdateAction::SetPublicActivityPolicy { network, .. } if *network == [0; 32])
    {
        return Err(Error::Bounds);
    }
    Ok(())
}
fn check_body(body: &Body) -> Result<(), Error> {
    match body {
        Body::Control(v) => check_control(v),
        Body::Create(v) => check_intent(v),
        Body::Update(v) => check_update(v),
    }
}
fn hash(domain: &[u8], tag: u8, payload: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(MAGIC);
    hash.update([tag]);
    hash.update((payload.len() as u16).to_be_bytes());
    hash.update(payload);
    hash.finalize().into()
}
fn record_id(body: &Body) -> RoomRecordId {
    let (tag, payload) = body_bytes(body);
    RoomRecordId::from_bytes(hash(RECORD_DOMAIN, tag, &payload))
}
fn permit_id(intent: &CreationIntent) -> PermitId {
    PermitId::from_bytes(hash(PERMIT_DOMAIN, PERMIT, &intent_bytes(intent)))
}
fn genesis_id(intent: &CreationIntent) -> RoomGenesisId {
    RoomGenesisId::from_bytes(hash(GENESIS_DOMAIN, CREATE, &intent_bytes(intent)))
}
fn transcript(domain: &[u8], id: &[u8; 32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(domain.len() + 32);
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(id);
    bytes
}
fn owner_transcript(intent: &CreationIntent) -> Vec<u8> {
    transcript(OWNER_SIGN, permit_id(intent).as_bytes())
}
fn agent_transcript(intent: &CreationIntent) -> Vec<u8> {
    let mut bytes = transcript(AGENT_SIGN, genesis_id(intent).as_bytes());
    bytes.extend_from_slice(permit_id(intent).as_bytes());
    bytes
}
fn controller_transcript(body: &Body) -> Vec<u8> {
    let domain = match body {
        Body::Control(_) => CONTROL_SIGN,
        Body::Update(_) => UPDATE_SIGN,
        Body::Create(_) => unreachable!("separate creation signing roles"),
    };
    transcript(domain, record_id(body).as_bytes())
}

// Fixed fields plus bounded strings give a ceiling below 1024 bytes even for a
// complete two-signature proposal. Keep a separate reviewed framing ceiling.
const MAX_INTENT_PAYLOAD: usize =
    32 * 12 + 16 + 4 + 8 + 8 + 1 + MAX_SLUG_BYTES + 2 + MAX_DESCRIPTION_BYTES;
const MAX_CONTROL_PAYLOAD: usize = 32 * 8 + 16 + 1 + 8 + 1 + 8 + 8;
const MAX_UPDATE_PAYLOAD: usize = 32 * 7 + 16 + 8 + 1 + 2 + MAX_DESCRIPTION_BYTES;
const _: () = assert!(8 + MAX_INTENT_PAYLOAD + 128 <= MAX_RECORD_BYTES);
const _: () = assert!(8 + MAX_CONTROL_PAYLOAD + 64 <= MAX_RECORD_BYTES);
const _: () = assert!(8 + MAX_UPDATE_PAYLOAD + 64 <= MAX_RECORD_BYTES);

fn frame(tag: u8, payload: &[u8], primary: &[u8; 64], secondary: Option<&[u8; 64]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + payload.len() + 128);
    out.extend_from_slice(MAGIC);
    out.push(tag);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(primary);
    if let Some(signature) = secondary {
        out.extend_from_slice(signature);
    }
    out
}
struct Frame<'a> {
    tag: u8,
    payload: &'a [u8],
    primary: [u8; 64],
    secondary: Option<[u8; 64]>,
}
fn split_frame(raw: &[u8]) -> Result<Frame<'_>, Error> {
    if raw.len() > MAX_RECORD_BYTES {
        return Err(Error::Bounds);
    }
    let mut reader = Reader(raw);
    if reader.take(MAGIC.len())? != MAGIC {
        return Err(Error::Encoding);
    }
    let tag = reader.u8()?;
    if !matches!(tag, CONTROL | CREATE | UPDATE | PERMIT) {
        return Err(Error::Encoding);
    }
    let len = usize::from(reader.u16()?);
    let proof_len = if tag == CREATE { 128 } else { 64 };
    if len > MAX_RECORD_BYTES - 8 - proof_len {
        return Err(Error::Bounds);
    }
    let payload = reader.take(len)?;
    let primary = reader.array()?;
    let secondary = if tag == CREATE {
        Some(reader.array()?)
    } else {
        None
    };
    reader.finish()?;
    Ok(Frame {
        tag,
        payload,
        primary,
        secondary,
    })
}
fn put_text(out: &mut Vec<u8>, description: &Description) {
    out.extend_from_slice(&(description.as_str().len() as u16).to_be_bytes());
    out.extend_from_slice(description.as_str().as_bytes());
}
fn put_scope(out: &mut Vec<u8>, directory: DirectoryId, realm: RealmId) {
    out.extend_from_slice(directory.as_bytes());
    out.extend_from_slice(&realm.0.to_be_bytes());
}
fn put_owner(out: &mut Vec<u8>, owner: OwnerId, basis: RecordId, key: &[u8; 32]) {
    out.extend_from_slice(owner.as_bytes());
    out.extend_from_slice(basis.as_bytes());
    out.extend_from_slice(key);
}
fn body_bytes(body: &Body) -> (u8, Vec<u8>) {
    match body {
        Body::Create(intent) => (CREATE, intent_bytes(intent)),
        Body::Control(control) => {
            let mut out = Vec::with_capacity(MAX_CONTROL_PAYLOAD);
            put_scope(&mut out, control.directory, control.realm);
            put_owner(
                &mut out,
                control.owner,
                control.social_control,
                &control.controller_key,
            );
            out.push(u8::from(control.previous.is_some()));
            if let Some(previous) = control.previous {
                out.extend_from_slice(previous.as_bytes());
            }
            out.extend_from_slice(&control.sequence.to_be_bytes());
            match &control.action {
                CreateAction::GrantCreate {
                    agent,
                    agent_key,
                    expires_at,
                    maximum_charge,
                    nonce,
                } => {
                    out.push(0);
                    out.extend_from_slice(agent.as_bytes());
                    out.extend_from_slice(agent_key);
                    out.extend_from_slice(&expires_at.to_be_bytes());
                    out.extend_from_slice(&maximum_charge.to_be_bytes());
                    out.extend_from_slice(nonce);
                }
                CreateAction::RevokeGrant { grant } => {
                    out.push(1);
                    out.extend_from_slice(grant.as_bytes());
                }
            }
            (CONTROL, out)
        }
        Body::Update(update) => {
            let mut out = Vec::with_capacity(MAX_UPDATE_PAYLOAD);
            put_scope(&mut out, update.directory, update.realm);
            out.extend_from_slice(update.genesis.as_bytes());
            out.extend_from_slice(update.previous.as_bytes());
            put_owner(
                &mut out,
                update.owner,
                update.social_control,
                &update.controller_key,
            );
            out.extend_from_slice(&update.expires_at.to_be_bytes());
            out.extend_from_slice(&update.nonce);
            match &update.action {
                UpdateAction::Describe(text) => {
                    out.push(0);
                    put_text(&mut out, text);
                }
                UpdateAction::Archive => out.push(1),
                UpdateAction::SetPublicActivityPolicy { network, enabled } => {
                    out.push(2);
                    out.push(PUBLIC_ACTIVITY_VERSION);
                    out.extend_from_slice(network);
                    out.push(u8::from(*enabled));
                }
            }
            (UPDATE, out)
        }
    }
}
fn intent_bytes(intent: &CreationIntent) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAX_INTENT_PAYLOAD);
    put_scope(&mut out, intent.directory, intent.realm);
    out.extend_from_slice(intent.policy.as_bytes());
    out.extend_from_slice(intent.initial_settings.as_bytes());
    put_owner(
        &mut out,
        intent.owner,
        intent.social_control,
        &intent.owner_key,
    );
    out.extend_from_slice(intent.agent.as_bytes());
    out.extend_from_slice(&intent.agent_key);
    out.extend_from_slice(intent.room_control.as_bytes());
    out.extend_from_slice(intent.grant.as_bytes());
    out.push(intent.slug.as_str().len() as u8);
    out.extend_from_slice(intent.slug.as_str().as_bytes());
    put_text(&mut out, &intent.description);
    out.extend_from_slice(&intent.slot.to_be_bytes());
    out.extend_from_slice(&intent.charge.to_be_bytes());
    out.extend_from_slice(&intent.expires_at.to_be_bytes());
    out.extend_from_slice(&intent.nonce);
    out
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        if len > self.0.len() {
            return Err(Error::Encoding);
        }
        let (value, remaining) = self.0.split_at(len);
        self.0 = remaining;
        Ok(value)
    }
    fn finish(self) -> Result<(), Error> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Encoding)
        }
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
    fn realm(&mut self) -> Result<RealmId, Error> {
        Ok(RealmId(u128::from_be_bytes(self.array()?)))
    }
    fn description(&mut self) -> Result<Description, Error> {
        let len = usize::from(self.u16()?);
        if len > MAX_DESCRIPTION_BYTES {
            return Err(Error::Bounds);
        }
        let value = core::str::from_utf8(self.take(len)?).map_err(|_| Error::Encoding)?;
        Description::new(value)
    }
    fn slug(&mut self) -> Result<Slug, Error> {
        let len = usize::from(self.u8()?);
        if len > MAX_SLUG_BYTES {
            return Err(Error::Bounds);
        }
        let value = core::str::from_utf8(self.take(len)?).map_err(|_| Error::Encoding)?;
        Slug::new(value)
    }
}
fn read_control(r: &mut Reader<'_>) -> Result<RoomControl, Error> {
    let directory = DirectoryId::from_bytes(r.array()?);
    let realm = r.realm()?;
    let owner = OwnerId::from_bytes(r.array()?);
    let social_control = RecordId::from_bytes(r.array()?);
    let controller_key = r.array()?;
    let previous = match r.u8()? {
        0 => None,
        1 => Some(RoomRecordId::from_bytes(r.array()?)),
        _ => return Err(Error::Encoding),
    };
    let sequence = r.u64()?;
    let action = match r.u8()? {
        0 => CreateAction::GrantCreate {
            agent: AgentId::from_bytes(r.array()?),
            agent_key: r.array()?,
            expires_at: r.u64()?,
            maximum_charge: r.u64()?,
            nonce: r.array()?,
        },
        1 => CreateAction::RevokeGrant {
            grant: RoomRecordId::from_bytes(r.array()?),
        },
        _ => return Err(Error::Encoding),
    };
    Ok(RoomControl {
        directory,
        realm,
        owner,
        social_control,
        controller_key,
        previous,
        sequence,
        action,
    })
}
fn read_intent(r: &mut Reader<'_>) -> Result<CreationIntent, Error> {
    Ok(CreationIntent {
        directory: DirectoryId::from_bytes(r.array()?),
        realm: r.realm()?,
        policy: PolicyId::from_bytes(r.array()?),
        initial_settings: PolicyId::from_bytes(r.array()?),
        owner: OwnerId::from_bytes(r.array()?),
        social_control: RecordId::from_bytes(r.array()?),
        owner_key: r.array()?,
        agent: AgentId::from_bytes(r.array()?),
        agent_key: r.array()?,
        room_control: RoomRecordId::from_bytes(r.array()?),
        grant: RoomRecordId::from_bytes(r.array()?),
        slug: r.slug()?,
        description: r.description()?,
        slot: r.u32()?,
        charge: r.u64()?,
        expires_at: r.u64()?,
        nonce: r.array()?,
    })
}
fn read_update(r: &mut Reader<'_>) -> Result<RoomUpdate, Error> {
    let directory = DirectoryId::from_bytes(r.array()?);
    let realm = r.realm()?;
    let genesis = RoomGenesisId::from_bytes(r.array()?);
    let previous = RoomRecordId::from_bytes(r.array()?);
    let owner = OwnerId::from_bytes(r.array()?);
    let social_control = RecordId::from_bytes(r.array()?);
    let controller_key = r.array()?;
    let expires_at = r.u64()?;
    let nonce = r.array()?;
    let action = match r.u8()? {
        0 => UpdateAction::Describe(r.description()?),
        1 => UpdateAction::Archive,
        2 => {
            if r.u8()? != PUBLIC_ACTIVITY_VERSION {
                return Err(Error::Encoding);
            }
            let network = r.array()?;
            let enabled = match r.u8()? {
                0 => false,
                1 => true,
                _ => return Err(Error::Encoding),
            };
            UpdateAction::SetPublicActivityPolicy { network, enabled }
        }
        _ => return Err(Error::Encoding),
    };
    Ok(RoomUpdate {
        directory,
        realm,
        genesis,
        previous,
        owner,
        social_control,
        controller_key,
        expires_at,
        nonce,
        action,
    })
}
