//! Bounded one-use bootstrap frames; no generic key or cipher API.
use crate::{
    codec::{self, Reader, Writer},
    model::{State, Working},
    packets::MAX_PACKET,
    protocol::*,
    Error, OperationId, Result,
};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signature, VerifyingKey};
use openmls_traits::signatures::Signer;
use zeroize::Zeroizing;

/// Maximum outstanding unused offers in one owner image.
pub const MAX_CONTACT_OFFERS: usize = 64;
/// Maximum remaining lifetime at issuance, additionally bounded by owner expiry.
pub const MAX_CONTACT_TTL: u64 = 24 * 60 * 60;
// Protocol v1 fixed records: prefix5+kind1+claims+signature64.
const ANCHOR_BYTES: usize = 6 + 96 + 3 + 64;
const ENROLLMENT_BYTES: usize = 6 + 64 + 16 + 64;
// The proof is a predecessor-signed owner control embedding the account grant.
// Fixed v1 control fields add 261 bytes to the 376-byte succession grant.
const SUCCESSION_BYTES: usize = 637;
/// Maximum encoded confidential contact offer, including the bounded retained
/// succession chain a post-handoff room must disclose to a contact joiner.
pub const MAX_OFFER_BYTES: usize = 10
    + 32
    + 64
    + 128
    + 24
    + 64
    + 4
    + ANCHOR_BYTES
    + 4
    + ENROLLMENT_BYTES
    + 1
    + crate::model::MAX_SUCCESSIONS * (4 + SUCCESSION_BYTES)
    + 64;
const SIGN_DOMAIN: &[u8] = b"vhalla/private/contact/owner-offer/v1\0";
// v3 requires predecessor-signed handoff proofs. Older grant-only offers
// are refused by magic rather than interpreted as completed owner authority.
const OFFER: &[u8] = b"VHPKOFFER\x03";
const FRAME: &[u8] = b"VHPKCONTACT\x01";
const HEADER: usize = FRAME.len() + 1 + 32 + 32 + 24 + 4;

/// Committed bootstrap secret for an explicitly confidential recipient transfer.
/// This is not a relay artifact. No generic outbox accessor returns these bytes.
/// No public constructor can label arbitrary bytes as a committed secret offer.
pub struct ConfidentialContactOffer {
    pub(crate) operation: OperationId,
    pub(crate) bytes: Zeroizing<Vec<u8>>,
}
impl ConfidentialContactOffer {
    /// Original issuance operation; exact retries never reactivate consumption.
    pub fn operation(&self) -> OperationId {
        self.operation
    }
    /// Export only through a separately authorized confidential channel. These
    /// bytes include one-use keys; do not log, post publicly or send to a relay.
    pub fn confidential_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Checked bootstrap metadata for fresh device setup. This contains no contact
/// direction keys. The whole offer’s owner-device signature and current validity are checked, but this
/// cannot prove global freshness or that the owner has not since renewed.
pub struct ContactBootstrap {
    anchor: VerifiedRoomAnchor,
    owner: VerifiedDeviceEnrollment,
    successions: Vec<OwnerSuccessionProof>,
    recipient: Key,
    validity: Validity,
}
impl ContactBootstrap {
    /// Inspect a confidential file against independently selected full account
    /// keys. The signed room selection must still be shown to the recipient;
    /// parsing neither joins a room nor authorizes a relay or network request.
    pub fn inspect(
        raw: &[u8],
        expected_owner: Key,
        expected_recipient: Key,
        now: u64,
    ) -> Result<Self> {
        let offer = Offer::decode(raw)?;
        Self::from_offer(&offer, expected_owner, expected_recipient, now)
    }

    /// Authenticate one encrypted request against the exact confidential offer
    /// and independently selected owner/recipient accounts. Returns only signed
    /// metadata, never KeyPackage bytes or contact keys. A controller can cap its
    /// invitation interval to both returned validity intervals before admission.
    ///
    /// This does not check current retained owner state, unused offer authority,
    /// roster capacity or the actual MLS KeyPackage. The caller must still compare
    /// the selected room/current owner and use `Kernel::accept_contact`; inspection
    /// performs no storage access and does not grant or consume membership.
    pub fn inspect_request(
        raw_offer: &[u8],
        raw_request: &[u8],
        expected_owner: Key,
        expected_recipient: Key,
        now: u64,
    ) -> Result<(Self, SignedDeviceEnrollment)> {
        let offer = Offer::decode(raw_offer)?;
        let metadata = Self::from_offer(&offer, expected_owner, expected_recipient, now)?;
        let frame = Frame::decode(raw_request)?;
        let clear = offer.open(&frame, None)?;
        let join = crate::packets::JoinRequest::decode(&clear)?;
        if join.scope != metadata.scope() || join.enrollment.claims().account != expected_recipient
        {
            return Err(Error::Scope);
        }
        join.enrollment.claims().validity.check_at(now)?;
        Ok((metadata, join.enrollment.signed().clone()))
    }

    fn from_offer(
        offer: &Offer,
        expected_owner: Key,
        expected_recipient: Key,
        now: u64,
    ) -> Result<Self> {
        if offer.owner_account != expected_owner || offer.recipient != expected_recipient {
            return Err(Error::Scope);
        }
        offer.check_time(now)?;
        offer.owner.claims().validity.check_at(now)?;
        Ok(Self {
            anchor: offer.anchor.clone(),
            owner: offer.owner.clone(),
            successions: offer.successions.clone(),
            recipient: offer.recipient,
            validity: offer.validity,
        })
    }
    /// Verified exact private room scope, not a public directory identifier.
    pub fn scope(&self) -> PrivateRoomScope {
        self.anchor.scope()
    }
    /// Canonical account-signed anchor for MemberDraft initialization.
    pub fn anchor(&self) -> &SignedRoomAnchor {
        self.anchor.signed()
    }
    /// Exact account-signed owner enrollment for MemberDraft initialization.
    pub fn owner(&self) -> &SignedDeviceEnrollment {
        self.owner.signed()
    }
    /// Complete predecessor-signed handoff chain proving `owner` against `anchor`;
    /// empty before the first handoff. Required by `MemberDraft::new_succeeded`.
    pub fn successions(&self) -> Vec<OwnerSuccessionProof> {
        self.successions.clone()
    }
    /// Account the offer can admit; this does not select or invent a device.
    pub fn recipient(&self) -> Key {
        self.recipient
    }
    /// Contact expiry, not a grant of membership or device lifetime.
    pub fn validity(&self) -> Validity {
        self.validity
    }
}

pub(crate) struct Offer {
    pub(crate) id: [u8; 32],
    pub(crate) scope: PrivateRoomScope,
    pub(crate) owner_account: Key,
    pub(crate) owner_device: Key,
    pub(crate) owner_basis: [u8; 32],
    pub(crate) recipient: Key,
    pub(crate) issued: u64,
    pub(crate) validity: Validity,
    anchor: VerifiedRoomAnchor,
    owner: VerifiedDeviceEnrollment,
    /// Exact retained handoff chain proving `owner` under `anchor`; never a
    /// substitute for the kernel's retained floor/roster checks.
    successions: Vec<OwnerSuccessionProof>,
    request_key: Zeroizing<[u8; 32]>,
    response_key: Zeroizing<[u8; 32]>,
    signature: [u8; 64],
}
impl Offer {
    pub(crate) fn new(
        work: &Working,
        recipient: Key,
        validity: Validity,
        now: u64,
    ) -> Result<Self> {
        let state = &work.state;
        if !state.owner_role() {
            return Err(Error::Policy);
        }
        let mut offer = Self {
            id: codec::random()?,
            scope: state.context().scope,
            owner_account: state.owner.claims().account,
            owner_device: state.owner.claims().device,
            owner_basis: owner_basis(state),
            recipient,
            issued: now,
            validity,
            anchor: state.anchor.clone(),
            owner: state.owner.clone(),
            successions: state.successions.clone(),
            request_key: Zeroizing::new(codec::random()?),
            response_key: Zeroizing::new(codec::random()?),
            signature: [0; 64],
        };
        offer.validate()?;
        offer.check_owner(state)?;
        offer.check_time(now)?;
        offer.signature = work
            .signer()?
            .sign(&offer.signing_bytes()?)
            .map_err(|_| Error::Mls)?
            .try_into()
            .map_err(|_| Error::Encoding)?;
        offer.verify_signature()?;
        Ok(offer)
    }
    fn validate(&self) -> Result<()> {
        self.validity.check_at(self.issued)?;
        self.owner.claims().validity.check_at(self.issued)?;
        if self.anchor.scope() != self.scope
            || self.anchor.claims().owner_account != self.owner_account
            || crate::model::check_succession_chain(&self.anchor, &self.successions)?
                != self.owner_device
            || self.owner.claims().account != self.owner_account
            || self.owner.claims().device != self.owner_device
            || self.owner_basis != owner_record_basis(&self.owner)
            || self.validity.expires_at() > self.owner.claims().validity.expires_at()
        {
            return Err(Error::Scope);
        }
        if self.id == [0; 32]
            || self
                .validity
                .expires_at()
                .checked_sub(self.issued)
                .is_none_or(|n| n > MAX_CONTACT_TTL)
            || *self.request_key == [0; 32]
            || *self.response_key == [0; 32]
            || self.request_key == self.response_key
        {
            return Err(Error::Policy);
        }
        Ok(())
    }
    pub(crate) fn check_time(&self, now: u64) -> Result<()> {
        if now < self.issued {
            return Err(Error::Time);
        }
        Ok(self.validity.check_at(now)?)
    }
    pub(crate) fn check_owner(&self, state: &State) -> Result<()> {
        if self.scope != state.context().scope
            || self.owner_account != state.owner.claims().account
            || self.owner_device != state.owner.claims().device
            || self.owner_basis != owner_basis(state)
            || self.validity.expires_at() > state.owner.claims().validity.expires_at()
        {
            return Err(Error::Scope);
        }
        Ok(())
    }
    fn binding(&self) -> Vec<u8> {
        let mut out = b"vhalla/private/contact/binding/v1\0".to_vec();
        out.extend(self.id);
        out.extend(self.scope.room.as_bytes());
        out.extend(self.scope.anchor.as_bytes());
        out.extend(self.owner_account.as_bytes());
        out.extend(self.owner_device.as_bytes());
        out.extend(self.owner_basis);
        out.extend(self.recipient.as_bytes());
        out.extend(self.issued.to_be_bytes());
        out.extend(self.validity.not_before().to_be_bytes());
        out.extend(self.validity.expires_at().to_be_bytes());
        out
    }
    fn unsigned_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.validate()?;
        let anchor = self.anchor.signed().encode();
        let owner = self.owner.signed().encode();
        if anchor.len() != ANCHOR_BYTES || owner.len() != ENROLLMENT_BYTES {
            return Err(Error::Encoding);
        }
        // All fixed lengths are checked before the first key copy. The complete
        // file buffer is guarded from allocation, including all early returns.
        let mut raw = Zeroizing::new(Vec::with_capacity(MAX_OFFER_BYTES));
        raw.extend(OFFER);
        raw.extend(self.id);
        raw.extend(self.scope.room.as_bytes());
        raw.extend(self.scope.anchor.as_bytes());
        raw.extend(self.owner_account.as_bytes());
        raw.extend(self.owner_device.as_bytes());
        raw.extend(self.owner_basis);
        raw.extend(self.recipient.as_bytes());
        raw.extend(self.issued.to_be_bytes());
        raw.extend(self.validity.not_before().to_be_bytes());
        raw.extend(self.validity.expires_at().to_be_bytes());
        raw.extend((ANCHOR_BYTES as u32).to_be_bytes());
        raw.extend(anchor);
        raw.extend((ENROLLMENT_BYTES as u32).to_be_bytes());
        raw.extend(owner);
        raw.push(u8::try_from(self.successions.len()).map_err(|_| Error::Bounds)?);
        for grant in &self.successions {
            let signed = grant.encode();
            if signed.len() > SUCCESSION_BYTES {
                return Err(Error::Encoding);
            }
            raw.extend((signed.len() as u32).to_be_bytes());
            raw.extend(signed);
        }
        raw.extend_from_slice(&*self.request_key);
        raw.extend_from_slice(&*self.response_key);
        if raw.len() > MAX_OFFER_BYTES - 64 {
            return Err(Error::Encoding);
        }
        Ok(raw)
    }
    fn signing_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        let raw = self.unsigned_bytes()?;
        let mut signed = Zeroizing::new(Vec::with_capacity(SIGN_DOMAIN.len() + raw.len()));
        signed.extend(SIGN_DOMAIN);
        signed.extend_from_slice(&raw);
        Ok(signed)
    }
    fn verify_signature(&self) -> Result<()> {
        let owner = VerifyingKey::from_bytes(self.owner_device.as_bytes())
            .map_err(|_| Error::Authentication)?;
        if owner.is_weak() {
            return Err(Error::Authentication);
        }
        owner
            .verify_strict(
                &self.signing_bytes()?,
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| Error::Authentication)
    }
    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.verify_signature()?;
        let mut raw = self.unsigned_bytes()?;
        raw.extend(self.signature);
        Ok(raw)
    }
    pub(crate) fn decode(raw: &[u8]) -> Result<Self> {
        let mut r = Reader::new(raw, OFFER, MAX_OFFER_BYTES)?;
        let result = Self {
            id: r.array()?,
            scope: PrivateRoomScope {
                room: RoomId::from_bytes(r.array()?)?,
                anchor: AnchorId::from_bytes(r.array()?)?,
            },
            owner_account: Key::from_bytes(r.array()?)?,
            owner_device: Key::from_bytes(r.array()?)?,
            owner_basis: r.array()?,
            recipient: Key::from_bytes(r.array()?)?,
            issued: r.u64()?,
            validity: Validity::new(r.u64()?, r.u64()?)?,
            anchor: SignedRoomAnchor::decode(r.blob(ANCHOR_BYTES)?)?.verify()?,
            owner: SignedDeviceEnrollment::decode(r.blob(ENROLLMENT_BYTES)?)?.verify()?,
            successions: {
                let count = usize::from(r.byte()?);
                if count > crate::model::MAX_SUCCESSIONS {
                    return Err(Error::Bounds);
                }
                let mut grants = Vec::with_capacity(count);
                for _ in 0..count {
                    grants.push(OwnerSuccessionProof::decode(r.blob(SUCCESSION_BYTES)?)?);
                }
                grants
            },
            request_key: Zeroizing::new(r.array()?),
            response_key: Zeroizing::new(r.array()?),
            signature: r.array()?,
        };
        r.end()?;
        result.validate()?;
        result.verify_signature()?;
        Ok(result)
    }
    pub(crate) fn seal(&self, response_to: Option<[u8; 32]>, clear: &[u8]) -> Result<Vec<u8>> {
        let len = clear.len().checked_add(16).ok_or(Error::Bounds)?;
        if clear.is_empty() || len.checked_add(HEADER).is_none_or(|n| n > MAX_PACKET) {
            return Err(Error::Bounds);
        }
        let direction = if response_to.is_some() { 2 } else { 1 };
        let nonce: [u8; 24] = codec::random()?;
        let mut w = Writer::new(FRAME, MAX_PACKET)?;
        w.byte(direction)?;
        w.put(&self.id)?;
        w.put(&response_to.unwrap_or([0; 32]))?;
        w.put(&nonce)?;
        w.put(&u32::try_from(len).map_err(|_| Error::Bounds)?.to_be_bytes())?;
        let mut raw = w.finish();
        let aad = self.aad(&raw);
        let key = if direction == 1 {
            &self.request_key
        } else {
            &self.response_key
        };
        let cipher = XChaCha20Poly1305::new((&**key).into())
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: clear,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Authentication)?;
        raw.extend(cipher);
        Ok(raw)
    }
    fn aad(&self, header: &[u8]) -> Vec<u8> {
        let mut out = self.binding();
        out.extend(header);
        out
    }
    pub(crate) fn open(
        &self,
        frame: &Frame<'_>,
        expected: Option<[u8; 32]>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        if frame.id != self.id
            || frame.direction != if expected.is_some() { 2 } else { 1 }
            || frame.request != expected.unwrap_or([0; 32])
        {
            return Err(Error::Scope);
        }
        let key = if expected.is_some() {
            &self.response_key
        } else {
            &self.request_key
        };
        Ok(Zeroizing::new(
            XChaCha20Poly1305::new((&**key).into())
                .decrypt(
                    XNonce::from_slice(frame.nonce),
                    Payload {
                        msg: frame.cipher,
                        aad: &self.aad(&frame.raw[..HEADER]),
                    },
                )
                .map_err(|_| Error::Authentication)?,
        ))
    }
}
pub(crate) fn owner_basis(state: &State) -> [u8; 32] {
    owner_record_basis(&state.owner)
}
fn owner_record_basis(owner: &VerifiedDeviceEnrollment) -> [u8; 32] {
    codec::hash(
        b"vhalla/private/contact/owner-basis/v1\0",
        &owner.signed().encode(),
    )
}
pub(crate) fn request_hash(raw: &[u8]) -> [u8; 32] {
    codec::hash(b"vhalla/private/contact/request/v1\0", raw)
}
pub(crate) fn response_hash(raw: &[u8]) -> [u8; 32] {
    codec::hash(b"vhalla/private/contact/response/v1\0", raw)
}

pub(crate) struct PendingContact {
    pub(crate) offer: Offer,
    pub(crate) request: [u8; 32],
}
pub(crate) struct Frame<'a> {
    pub(crate) raw: &'a [u8],
    pub(crate) direction: u8,
    pub(crate) id: [u8; 32],
    pub(crate) request: [u8; 32],
    nonce: &'a [u8],
    cipher: &'a [u8],
}
impl<'a> Frame<'a> {
    pub(crate) fn decode(raw: &'a [u8]) -> Result<Self> {
        let mut r = Reader::new(raw, FRAME, MAX_PACKET)?;
        let direction = r.byte()?;
        if !(1..=2).contains(&direction) {
            return Err(Error::Encoding);
        }
        let id = r.array()?;
        if id == [0; 32] {
            return Err(Error::Encoding);
        }
        let request = r.array()?;
        if (direction == 1) != (request == [0; 32]) {
            return Err(Error::Encoding);
        }
        let nonce = r.take(24)?;
        let cipher = r.blob(MAX_PACKET - HEADER)?;
        if cipher.len() <= 16 {
            return Err(Error::Encoding);
        }
        r.end()?;
        Ok(Self {
            raw,
            direction,
            id,
            request,
            nonce,
            cipher,
        })
    }
}
