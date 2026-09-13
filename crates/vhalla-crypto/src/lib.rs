#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Context-bound signatures and bounded replay admission for vhalla (valhalla).
//!
//! Authentication produces immutable, move-only [`VerifiedEnvelope`] evidence.
//! It never grants a host capability: local policy must separately admit the
//! complete signing key and scope. Replay state is volatile; a restarted owner
//! must retain it durably or establish a fresh session before accepting traffic.

extern crate alloc;

pub mod claims;

pub use claims::{
    sign_claim, Claim, ClaimBuildError, ClaimContext, ClaimDecodeError, ClaimDomain,
    ClaimReplayWindow, ClaimVerifyError, SessionId, SignedClaim, SubjectDigest,
};

use alloc::{collections::BTreeMap, vec::Vec};
pub use ed25519_dalek::VerifyingKey;
use ed25519_dalek::{Signature, Signer, SigningKey};
use sha2::{Digest, Sha256};
use vhalla_core::{Epoch, PeerId, RealmId, RoomId, Sequence};
use vhalla_wire::{DecodeError, Envelope};

const DOMAIN: &[u8] = b"vhalla/signed-envelope/v2";
/// Signed transport format version. Legacy unversioned v1 frames are rejected.
pub const SIGNED_VERSION: u8 = 2;
/// Maximum complete signed transport frame, including every fixed field.
pub const MAX_SIGNED_BYTES: usize = vhalla_core::MAX_ENVELOPE_BYTES;
/// Signed framing overhead around the unchanged v1 unsigned envelope.
pub const SIGNED_OVERHEAD_BYTES: usize = 1 + 4 + 16 + 8 + 16 + 8 + 64;
/// Maximum body that fits inside a complete signed transport frame.
pub const MAX_SIGNED_BODY_BYTES: usize =
    MAX_SIGNED_BYTES - SIGNED_OVERHEAD_BYTES - vhalla_wire::HEADER_BYTES;
/// Hard maximum distinct full signing keys retained by one replay window.
pub const MAX_REPLAY_AUTHORS: usize = 256;

/// Owner-selected authentication context; all fields are bound by the signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerificationContext {
    /// Intended receiving owner.
    pub audience: PeerId,
    /// Exact realm.
    pub realm: RealmId,
    /// Exact room within the realm.
    pub room: RoomId,
    /// Current local authorization or membership epoch.
    pub epoch: Epoch,
    /// Current session; the owner must avoid reuse after losing replay state.
    pub session: SessionId,
}

/// Untrusted signed claim. Transport can forward its bounded encoded bytes.
/// Public fields may be edited; only replay admission creates verified evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedEnvelope {
    /// Structurally valid but unauthenticated application envelope.
    pub envelope: Envelope,
    /// Claimed intended owner/recipient.
    pub audience: PeerId,
    /// Claimed authorization or membership epoch.
    pub epoch: Epoch,
    /// Claimed owner session.
    pub session: SessionId,
    /// Absolute expiry in the caller's injected clock units, inclusive.
    pub expires_at: u64,
    /// Signature over the domain, version, envelope and complete signed context.
    pub signature: [u8; 64],
}

/// Sealed authentication evidence, consumed by the local policy boundary.
///
/// It owns the exact immutable message, context and full key that were checked.
/// There is no mutable projection, `Clone`, decoder or unchecked constructor.
/// A borrowed/cloned unsigned envelope remains untrusted data.
///
/// ```compile_fail
/// use vhalla_crypto::VerifiedEnvelope;
/// fn mutate(verified: &mut VerifiedEnvelope) { verified.envelope.body.push(0); }
/// ```
/// ```compile_fail
/// use vhalla_crypto::VerifiedEnvelope;
/// fn duplicate(verified: VerifiedEnvelope) -> (VerifiedEnvelope, VerifiedEnvelope) {
///     (verified.clone(), verified)
/// }
/// ```
/// ```compile_fail
/// use vhalla_crypto::{SignedEnvelope, VerifiedEnvelope};
/// fn skip_authentication(raw: SignedEnvelope) -> VerifiedEnvelope { raw.into() }
/// ```
#[derive(Debug)]
pub struct VerifiedEnvelope {
    envelope: Envelope,
    signer_key: [u8; 32],
    context: VerificationContext,
    expires_at: u64,
}

impl VerifiedEnvelope {
    /// The exact authenticated message, available only immutably.
    #[must_use]
    pub fn envelope(&self) -> &Envelope {
        &self.envelope
    }
    /// Complete Ed25519 identity; policy must not authorize a truncated handle.
    #[must_use]
    pub fn signer_key(&self) -> &[u8; 32] {
        &self.signer_key
    }
    /// Exact context checked at replay admission.
    #[must_use]
    pub fn context(&self) -> VerificationContext {
        self.context
    }
    /// Authenticated expiry, inclusive, for a later delayed-use policy check.
    #[must_use]
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

/// Signing or encoding failures, checked before allocating a signed transcript.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignError {
    /// The complete signed frame exceeds [`MAX_SIGNED_BYTES`].
    TooLarge,
    /// The seed's public key does not match the envelope's claimed author handle.
    AuthorMismatch,
}

/// Errors while decoding the bounded signed transport payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeSignedError {
    /// The complete frame exceeds the hard byte limit.
    TooLarge,
    /// Signed version differs from [`SIGNED_VERSION`].
    UnsupportedVersion,
    /// The unsigned envelope was malformed.
    Wire(DecodeError),
    /// A fixed field or declared envelope was truncated.
    Truncated,
    /// Extra bytes followed the signature.
    TrailingBytes,
}

/// Failures from context, strict signature, expiry or replay admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifyError {
    /// Replay capacity must be between one and [`MAX_REPLAY_AUTHORS`].
    InvalidBound,
    /// The complete signed frame is too large.
    TooLarge,
    /// Weak Ed25519 public keys cannot identify an authenticated author.
    WeakKey,
    /// The full key does not map to the claimed author handle.
    AuthorMismatch,
    /// The envelope targets another owner.
    AudienceMismatch,
    /// The envelope is from another realm.
    RealmMismatch,
    /// The envelope is from another room.
    RoomMismatch,
    /// The envelope names another epoch.
    EpochMismatch,
    /// The envelope names another session.
    SessionMismatch,
    /// The envelope has expired.
    Expired,
    /// The signature does not verify strictly.
    InvalidSignature,
    /// The full signing key's sequence is not strictly newer.
    Replay,
    /// No unused author slot remains; accepted authors are never evicted.
    Capacity,
}

/// Volatile last sequence per full signing key in one immutable context.
///
/// This window is not cloneable, automatically resettable or evicting. Invalid
/// traffic leaves it unchanged. A separate window in the same context cannot
/// detect this window's replays; the owner must maintain a single admission path.
#[derive(Debug)]
pub struct ReplayWindow {
    context: VerificationContext,
    max_authors: usize,
    last: BTreeMap<[u8; 32], Sequence>,
}

impl SignedEnvelope {
    fn validate_size(&self) -> Result<(), SignError> {
        if self.envelope.encoded_len() > MAX_SIGNED_BYTES - SIGNED_OVERHEAD_BYTES {
            return Err(SignError::TooLarge);
        }
        Ok(())
    }

    /// Encode v2 framing around an unchanged canonical v1 unsigned envelope.
    /// Bounds are checked before allocating either envelope or frame bytes.
    pub fn encode(&self) -> Result<Vec<u8>, SignError> {
        self.validate_size()?;
        let mut out = Vec::with_capacity(self.envelope.encoded_len() + SIGNED_OVERHEAD_BYTES);
        self.encode_unsigned(&mut out);
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    fn encode_unsigned(&self, out: &mut Vec<u8>) {
        out.push(SIGNED_VERSION);
        out.extend_from_slice(&(self.envelope.encoded_len() as u32).to_be_bytes());
        out.extend_from_slice(&self.envelope.encode());
        out.extend_from_slice(&self.audience.0.to_be_bytes());
        out.extend_from_slice(&self.epoch.0.to_be_bytes());
        out.extend_from_slice(&self.session.0.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
    }

    /// Decode bounded bytes into an untrusted claim, never authentication proof.
    pub fn decode(raw: &[u8]) -> Result<Self, DecodeSignedError> {
        if raw.len() > MAX_SIGNED_BYTES {
            return Err(DecodeSignedError::TooLarge);
        }
        let version = *raw.first().ok_or(DecodeSignedError::Truncated)?;
        if version != SIGNED_VERSION {
            return Err(DecodeSignedError::UnsupportedVersion);
        }
        if raw.len() < 5 {
            return Err(DecodeSignedError::Truncated);
        }
        let envelope_len = u32::from_be_bytes(raw[1..5].try_into().expect("four bytes")) as usize;
        if envelope_len > MAX_SIGNED_BYTES - SIGNED_OVERHEAD_BYTES {
            return Err(DecodeSignedError::TooLarge);
        }
        let envelope_end = 5 + envelope_len;
        let end = envelope_len + SIGNED_OVERHEAD_BYTES;
        if raw.len() < end {
            return Err(DecodeSignedError::Truncated);
        }
        if raw.len() > end {
            return Err(DecodeSignedError::TrailingBytes);
        }
        let envelope = Envelope::decode(&raw[5..envelope_end]).map_err(DecodeSignedError::Wire)?;
        let context = &raw[envelope_end..];
        let audience = PeerId(u128::from_be_bytes(
            context[..16].try_into().expect("sixteen bytes"),
        ));
        let epoch = Epoch(u64::from_be_bytes(
            context[16..24].try_into().expect("eight bytes"),
        ));
        let session = SessionId(u128::from_be_bytes(
            context[24..40].try_into().expect("sixteen bytes"),
        ));
        let expires_at = u64::from_be_bytes(context[40..48].try_into().expect("eight bytes"));
        let signature = context[48..112].try_into().expect("signature bytes");
        Ok(Self {
            envelope,
            audience,
            epoch,
            session,
            expires_at,
            signature,
        })
    }
}

impl ReplayWindow {
    /// Start one bounded window in an explicit owner-selected context.
    pub fn new(context: VerificationContext, max_authors: usize) -> Result<Self, VerifyError> {
        if !(1..=MAX_REPLAY_AUTHORS).contains(&max_authors) {
            return Err(VerifyError::InvalidBound);
        }
        Ok(Self {
            context,
            max_authors,
            last: BTreeMap::new(),
        })
    }

    /// Context retained by this admission path.
    #[must_use]
    pub fn context(&self) -> VerificationContext {
        self.context
    }

    /// Authenticate and consume a claim once; no fallible work follows insertion.
    pub fn verify_and_accept(
        &mut self,
        signed: SignedEnvelope,
        key: &VerifyingKey,
        now: u64,
    ) -> Result<VerifiedEnvelope, VerifyError> {
        signed.validate_size().map_err(|_| VerifyError::TooLarge)?;
        if key.is_weak() {
            return Err(VerifyError::WeakKey);
        }
        if peer_id_from_key(key) != signed.envelope.author() {
            return Err(VerifyError::AuthorMismatch);
        }
        if signed.audience != self.context.audience {
            return Err(VerifyError::AudienceMismatch);
        }
        if signed.envelope.realm() != self.context.realm {
            return Err(VerifyError::RealmMismatch);
        }
        if signed.envelope.room() != self.context.room {
            return Err(VerifyError::RoomMismatch);
        }
        if signed.epoch != self.context.epoch {
            return Err(VerifyError::EpochMismatch);
        }
        if signed.session != self.context.session {
            return Err(VerifyError::SessionMismatch);
        }
        if now > signed.expires_at {
            return Err(VerifyError::Expired);
        }
        let transcript = transcript(&signed).map_err(|_| VerifyError::TooLarge)?;
        key.verify_strict(&transcript, &Signature::from_bytes(&signed.signature))
            .map_err(|_| VerifyError::InvalidSignature)?;
        let signer_key = key.to_bytes();
        match self.last.get(&signer_key) {
            Some(last) if signed.envelope.sequence() <= *last => return Err(VerifyError::Replay),
            None if self.last.len() >= self.max_authors => return Err(VerifyError::Capacity),
            _ => {}
        }
        self.last.insert(signer_key, signed.envelope.sequence());
        Ok(VerifiedEnvelope {
            envelope: signed.envelope,
            signer_key,
            context: self.context,
            expires_at: signed.expires_at,
        })
    }
}

/// Sign explicit owner, epoch, session and expiry with a deterministic seed.
/// The seed's author handle and the complete frame bound are checked first.
pub fn sign(
    envelope: Envelope,
    audience: PeerId,
    epoch: Epoch,
    session: SessionId,
    expires_at: u64,
    seed: [u8; 32],
) -> Result<SignedEnvelope, SignError> {
    let key = SigningKey::from_bytes(&seed);
    sign_with_key(envelope, audience, epoch, session, expires_at, &key)
}

/// Sign using a borrowed key held by a trusted custodian, without exporting or
/// reconstructing its seed for each message. Context and bounds match [`sign`].
pub fn sign_with_key(
    envelope: Envelope,
    audience: PeerId,
    epoch: Epoch,
    session: SessionId,
    expires_at: u64,
    key: &SigningKey,
) -> Result<SignedEnvelope, SignError> {
    let mut signed = SignedEnvelope {
        envelope,
        audience,
        epoch,
        session,
        expires_at,
        signature: [0; 64],
    };
    signed.validate_size()?;
    if signed.envelope.author() != peer_id_from_key(&key.verifying_key()) {
        return Err(SignError::AuthorMismatch);
    }
    signed.signature = key.sign(&transcript(&signed)?).to_bytes();
    Ok(signed)
}

/// Derive a protocol routing handle from a key, not a sufficient policy identity.
#[must_use]
pub fn peer_id_from_key(key: &VerifyingKey) -> PeerId {
    let digest = Sha256::digest(key.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    PeerId(u128::from_be_bytes(bytes))
}

/// Derive the routing handle for a deterministic signing seed.
#[must_use]
pub fn peer_id_from_seed(seed: [u8; 32]) -> PeerId {
    peer_id_from_key(&SigningKey::from_bytes(&seed).verifying_key())
}

/// Derive the verifying key for a deterministic signing seed.
#[must_use]
pub fn verifying_key_from_seed(seed: [u8; 32]) -> VerifyingKey {
    SigningKey::from_bytes(&seed).verifying_key()
}

fn transcript(signed: &SignedEnvelope) -> Result<Vec<u8>, SignError> {
    signed.validate_size()?;
    let mut out = Vec::with_capacity(
        DOMAIN.len() + signed.envelope.encoded_len() + SIGNED_OVERHEAD_BYTES - 64,
    );
    out.extend_from_slice(DOMAIN);
    signed.encode_unsigned(&mut out);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use proptest::prelude::*;
    use vhalla_core::EventId;

    fn context() -> VerificationContext {
        VerificationContext {
            audience: PeerId(44),
            realm: RealmId(1),
            room: RoomId(2),
            epoch: Epoch(3),
            session: SessionId(4),
        }
    }
    fn event(seed: [u8; 32], sequence: u64, body: &[u8]) -> Envelope {
        Envelope::chat(
            peer_id_from_seed(seed),
            RealmId(1),
            RoomId(2),
            EventId(u128::from(sequence)),
            Sequence(sequence),
            body,
        )
        .unwrap()
    }
    fn signed(seed: [u8; 32], sequence: u64) -> SignedEnvelope {
        sign(
            event(seed, sequence, b"untrusted content"),
            PeerId(44),
            Epoch(3),
            SessionId(4),
            100,
            seed,
        )
        .unwrap()
    }

    #[test]
    fn v2_frame_matches_an_independent_fixed_width_fixture() {
        // Python struct.pack/hashlib fixture, signature intentionally not valid.
        // This pins framing independently of the decoder and signature library.
        let claim = SignedEnvelope {
            envelope: Envelope::chat(
                PeerId(1),
                RealmId(2),
                RoomId(3),
                EventId(4),
                Sequence(5),
                b"hello",
            )
            .unwrap(),
            audience: PeerId(6),
            epoch: Epoch(7),
            session: SessionId(8),
            expires_at: 9,
            signature: [85; 64],
        };
        let encoded = claim.encode().unwrap();
        assert_eq!(encoded.len(), 200);
        assert_eq!(
            alloc::format!("{:x}", Sha256::digest(&encoded)),
            "742101e6e29e6ae367d1bed31d88cd6dd98de6e6de2a18150a6cdf1030fad413"
        );
        assert_eq!(SignedEnvelope::decode(&encoded).unwrap(), claim);
    }

    #[test]
    fn consumes_authentication_evidence_and_rejects_replay() {
        let claim = signed([7; 32], 1);
        let mut window = ReplayWindow::new(context(), 1).unwrap();
        let verified = window
            .verify_and_accept(claim.clone(), &verifying_key_from_seed([7; 32]), 100)
            .unwrap();
        assert_eq!(verified.envelope(), &claim.envelope);
        assert_eq!(
            verified.signer_key(),
            &verifying_key_from_seed([7; 32]).to_bytes()
        );
        assert_eq!(verified.context(), context());
        assert_eq!(verified.expires_at(), 100);
        assert_eq!(
            window
                .verify_and_accept(claim, &verifying_key_from_seed([7; 32]), 100)
                .err(),
            Some(VerifyError::Replay)
        );
    }

    #[test]
    fn complete_maximum_frame_round_trips_and_one_more_byte_fails() {
        let envelope = event([7; 32], 1, &vec![9; MAX_SIGNED_BODY_BYTES]);
        let claim = sign(envelope, PeerId(44), Epoch(3), SessionId(4), 100, [7; 32]).unwrap();
        let encoded = claim.encode().unwrap();
        assert_eq!(encoded.len(), MAX_SIGNED_BYTES);
        assert_eq!(SignedEnvelope::decode(&encoded).unwrap(), claim);
        let mut window = ReplayWindow::new(context(), 1).unwrap();
        assert!(window
            .verify_and_accept(
                SignedEnvelope::decode(&encoded).unwrap(),
                &verifying_key_from_seed([7; 32]),
                1
            )
            .is_ok());
        let mut too_big = claim;
        too_big.envelope = event([7; 32], 1, &vec![9; MAX_SIGNED_BODY_BYTES + 1]);
        assert_eq!(too_big.encode(), Err(SignError::TooLarge));
        assert_eq!(
            sign(
                too_big.envelope.clone(),
                PeerId(44),
                Epoch(3),
                SessionId(4),
                100,
                [7; 32]
            ),
            Err(SignError::TooLarge)
        );
        let before = window.last.clone();
        assert_eq!(
            window
                .verify_and_accept(too_big, &verifying_key_from_seed([7; 32]), 1)
                .err(),
            Some(VerifyError::TooLarge)
        );
        assert_eq!(window.last, before);
        let mut oversized = encoded;
        oversized.push(0);
        assert_eq!(
            SignedEnvelope::decode(&oversized),
            Err(DecodeSignedError::TooLarge)
        );
    }

    #[test]
    fn every_context_field_expiry_author_and_signature_are_checked_atomically() {
        let original = signed([7; 32], 1);
        let mut window = ReplayWindow::new(context(), 1).unwrap();
        let key = verifying_key_from_seed([7; 32]);
        for (mut claim, error) in [
            (original.clone(), VerifyError::AudienceMismatch),
            (original.clone(), VerifyError::EpochMismatch),
            (original.clone(), VerifyError::SessionMismatch),
            (original.clone(), VerifyError::RealmMismatch),
            (original.clone(), VerifyError::RoomMismatch),
            (original.clone(), VerifyError::Expired),
            (original.clone(), VerifyError::InvalidSignature),
        ] {
            match error {
                VerifyError::AudienceMismatch => claim.audience = PeerId(45),
                VerifyError::EpochMismatch => claim.epoch = Epoch(4),
                VerifyError::SessionMismatch => claim.session = SessionId(5),
                VerifyError::RealmMismatch => {
                    claim.envelope = Envelope::chat(
                        claim.envelope.author(),
                        RealmId(9),
                        RoomId(2),
                        EventId(1),
                        Sequence(1),
                        b"untrusted content",
                    )
                    .unwrap()
                }
                VerifyError::RoomMismatch => {
                    claim.envelope = Envelope::chat(
                        claim.envelope.author(),
                        RealmId(1),
                        RoomId(9),
                        EventId(1),
                        Sequence(1),
                        b"untrusted content",
                    )
                    .unwrap()
                }
                VerifyError::Expired => claim.expires_at = 0,
                VerifyError::InvalidSignature => claim.signature[0] ^= 1,
                _ => unreachable!(),
            }
            assert_eq!(window.verify_and_accept(claim, &key, 1).err(), Some(error));
            assert!(window.last.is_empty());
        }
        assert_eq!(
            window
                .verify_and_accept(original.clone(), &verifying_key_from_seed([8; 32]), 1)
                .err(),
            Some(VerifyError::AuthorMismatch)
        );
        assert!(window.last.is_empty());
        assert!(window.verify_and_accept(original, &key, 1).is_ok());
    }

    #[test]
    fn weak_public_key_is_rejected_before_replay_allocation() {
        let mut identity = [0; 32];
        identity[0] = 1;
        let key = VerifyingKey::from_bytes(&identity).unwrap();
        assert!(key.is_weak());
        let mut claim = signed([7; 32], 1);
        claim.envelope = Envelope::chat(
            peer_id_from_key(&key),
            RealmId(1),
            RoomId(2),
            EventId(1),
            Sequence(1),
            b"data",
        )
        .unwrap();
        let mut window = ReplayWindow::new(context(), 1).unwrap();
        assert_eq!(
            window.verify_and_accept(claim, &key, 1).err(),
            Some(VerifyError::WeakKey)
        );
        assert!(window.last.is_empty());
    }

    #[test]
    fn capacity_never_evicts_existing_full_keys() {
        assert_eq!(
            ReplayWindow::new(context(), 0).err(),
            Some(VerifyError::InvalidBound)
        );
        assert_eq!(
            ReplayWindow::new(context(), MAX_REPLAY_AUTHORS + 1).err(),
            Some(VerifyError::InvalidBound)
        );
        let mut window = ReplayWindow::new(context(), 1).unwrap();
        let key = verifying_key_from_seed([7; 32]);
        window
            .verify_and_accept(signed([7; 32], 1), &key, 1)
            .unwrap();
        let before = window.last.clone();
        assert_eq!(
            window
                .verify_and_accept(signed([8; 32], 100), &verifying_key_from_seed([8; 32]), 1)
                .err(),
            Some(VerifyError::Capacity)
        );
        assert_eq!(window.last, before);
        window
            .verify_and_accept(signed([7; 32], 2), &key, 1)
            .unwrap();
        assert_eq!(
            window.verify_and_accept(signed([7; 32], 1), &key, 1).err(),
            Some(VerifyError::Replay)
        );
        assert_eq!(window.last.len(), 1);
    }

    #[test]
    fn fresh_sequence_requires_the_exact_new_epoch_and_session() {
        let old = signed([7; 32], 10);
        let mut new_context = context();
        new_context.session = SessionId(5);
        new_context.epoch = Epoch(4);
        let mut window = ReplayWindow::new(new_context, 1).unwrap();
        assert_eq!(
            window
                .verify_and_accept(old, &verifying_key_from_seed([7; 32]), 1)
                .err(),
            Some(VerifyError::EpochMismatch)
        );
        let next = sign(
            event([7; 32], 0, b"new session"),
            PeerId(44),
            Epoch(4),
            SessionId(5),
            100,
            [7; 32],
        )
        .unwrap();
        assert!(window
            .verify_and_accept(next, &verifying_key_from_seed([7; 32]), 1)
            .is_ok());
    }

    #[test]
    fn relabelling_a_claim_cannot_move_its_signature_into_a_fresh_context() {
        let mut claim = signed([7; 32], 1);
        let mut next_context = context();
        next_context.epoch = Epoch(4);
        next_context.session = SessionId(5);
        claim.epoch = next_context.epoch;
        claim.session = next_context.session;
        let mut window = ReplayWindow::new(next_context, 1).unwrap();
        assert_eq!(
            window
                .verify_and_accept(claim, &verifying_key_from_seed([7; 32]), 1)
                .err(),
            Some(VerifyError::InvalidSignature)
        );
        assert!(window.last.is_empty());
    }

    #[test]
    fn decoder_rejects_truncation_legacy_version_malformed_inner_and_trailing_bytes() {
        let encoded = signed([7; 32], 1).encode().unwrap();
        for length in 0..encoded.len() {
            assert!(
                SignedEnvelope::decode(&encoded[..length]).is_err(),
                "prefix {length}"
            );
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            SignedEnvelope::decode(&trailing),
            Err(DecodeSignedError::TrailingBytes)
        );
        let mut legacy = encoded.clone();
        legacy[0] = 1;
        assert_eq!(
            SignedEnvelope::decode(&legacy),
            Err(DecodeSignedError::UnsupportedVersion)
        );
        let mut malformed = encoded;
        malformed[6] = 0;
        assert_eq!(
            SignedEnvelope::decode(&malformed),
            Err(DecodeSignedError::Wire(DecodeError::InvalidKind))
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        #[test]
        fn signed_round_trip_binds_every_bit(body in proptest::collection::vec(any::<u8>(),0..256), sequence in any::<u64>(), offset in any::<usize>(), bit in 0_u8..8) {
            let claim = sign(event([7;32], sequence, &body), PeerId(44), Epoch(3), SessionId(4), 100, [7;32]).unwrap();
            let mut raw = claim.encode().unwrap();
            prop_assert_eq!(SignedEnvelope::decode(&raw), Ok(claim));
            let index = offset % raw.len(); raw[index] ^= 1 << bit;
            if let Ok(tampered) = SignedEnvelope::decode(&raw) {
                let mut window = ReplayWindow::new(context(),1).unwrap();
                prop_assert!(window.verify_and_accept(tampered,&verifying_key_from_seed([7;32]),1).is_err());
                prop_assert!(window.last.is_empty());
            }
        }
        #[test]
        fn arbitrary_bytes_never_panic_or_accept_noncanonical_frames(raw in proptest::collection::vec(any::<u8>(),0..4096)) {
            if let Ok(claim) = SignedEnvelope::decode(&raw) { prop_assert_eq!(claim.encode().unwrap(), raw); }
        }
        #[test]
        fn arbitrary_sequences_only_advance_retained_maximum(sequences in proptest::collection::vec(any::<u64>(),0..50)) {
            let key = verifying_key_from_seed([7;32]);
            let mut window = ReplayWindow::new(context(),1).unwrap();
            let mut highest = None;
            for sequence in sequences {
                let accepted = window.verify_and_accept(signed([7;32],sequence),&key,1).is_ok();
                prop_assert_eq!(accepted, highest.is_none_or(|value| sequence > value));
                if accepted { highest = Some(sequence); }
                prop_assert_eq!(window.last.get(&key.to_bytes()).map(|v|v.0),highest);
            }
        }
    }
}
