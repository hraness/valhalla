//! Typed, context-bound signed claims.
//!
//! Claims are deliberately smaller and more constrained than arbitrary signed
//! application bytes.  Their canonical transcript binds the protocol domain,
//! realm, session, subject digest, sequence, epoch, lifetime, audience, and
//! issuer.  This makes a receipt or capability portable between transports
//! without making it portable between unrelated contexts.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use vhalla_core::{Epoch, PeerId, RealmId, Sequence};

const TRANSCRIPT_DOMAIN: &[u8] = b"vhalla/signed-claim/v1";
const CLAIM_VERSION: u8 = 1;
/// Maximum canonical bytes in a decoded signed claim.
pub const MAX_SIGNED_CLAIM_BYTES: usize = 256;
/// Maximum number of replay scopes retained by the default window.
pub const DEFAULT_REPLAY_LIMIT: usize = 1024;

/// A protocol-owned claim domain.  Unknown domains cannot be decoded.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ClaimDomain {
    /// A session membership or handshake claim.
    Session = 1,
    /// A module or artifact provenance claim.
    Provenance = 2,
    /// A capability authorization claim.
    Capability = 3,
    /// A durable receipt claim.
    Receipt = 4,
}

impl ClaimDomain {
    fn label(self) -> &'static [u8] {
        match self {
            Self::Session => b"session",
            Self::Provenance => b"provenance",
            Self::Capability => b"capability",
            Self::Receipt => b"receipt",
        }
    }

    fn from_wire(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Session),
            2 => Some(Self::Provenance),
            3 => Some(Self::Capability),
            4 => Some(Self::Receipt),
            _ => None,
        }
    }
}

/// A session namespace, distinct from a realm and an issuer identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SessionId(pub u128);

/// A fixed-size digest identifying the subject of a claim.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SubjectDigest([u8; 32]);

impl SubjectDigest {
    /// Construct a subject digest from an already-computed digest.
    #[must_use]
    pub const fn from_digest(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the digest bytes without exposing an arbitrary transcript.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The typed context a verifier expects for a claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimContext {
    /// Required claim domain.
    pub domain: ClaimDomain,
    /// Required realm namespace.
    pub realm: RealmId,
    /// Required session namespace.
    pub session: SessionId,
    /// Required audience peer.
    pub audience: PeerId,
    /// Required policy or membership epoch.
    pub epoch: Epoch,
}

/// A canonical claim before it is signed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Claim {
    /// Protocol-owned semantic domain.
    pub domain: ClaimDomain,
    /// Realm in which the claim is valid.
    pub realm: RealmId,
    /// Session in which the claim is valid.
    pub session: SessionId,
    /// Digest of the claim subject.
    pub subject: SubjectDigest,
    /// Monotonic sequence within the epoch.
    pub sequence: Sequence,
    /// Policy or membership epoch.
    pub epoch: Epoch,
    /// Inclusive issuance time in caller-provided clock units.
    pub issued_at: u64,
    /// Inclusive expiry time in caller-provided clock units.
    pub expires_at: u64,
    /// Peer to which the claim is addressed.
    pub audience: PeerId,
}

/// A signed claim with an authenticated issuer identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedClaim {
    /// Canonical claim fields.
    pub claim: Claim,
    /// Stable identity derived from the signing key.
    pub issuer: PeerId,
    /// Ed25519 signature over the private, domain-separated transcript.
    pub signature: [u8; 64],
}

/// Errors while constructing or encoding a claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimBuildError {
    /// The expiry is not strictly after the issuance time.
    InvalidLifetime,
}

/// Errors while decoding a signed claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimDecodeError {
    /// The input is larger than the bounded claim size.
    TooLarge,
    /// A field was truncated.
    Truncated,
    /// The version is unknown.
    UnsupportedVersion,
    /// The domain tag is unknown.
    UnknownDomain,
    /// A declared length does not match the canonical payload.
    InvalidLength,
    /// The expiry is not strictly after issuance.
    InvalidLifetime,
    /// Extra bytes followed the signature.
    TrailingBytes,
}

/// Errors from context, signature, and replay verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimVerifyError {
    /// The signing key does not match the embedded issuer.
    IssuerMismatch,
    /// The claim domain differs from the expected context.
    DomainMismatch,
    /// The claim realm differs from the expected context.
    RealmMismatch,
    /// The claim session differs from the expected context.
    SessionMismatch,
    /// The claim audience differs from the expected context.
    AudienceMismatch,
    /// The claim epoch differs from the expected context.
    EpochMismatch,
    /// The current time is before issuance.
    NotYetValid,
    /// The current time is after expiry.
    Expired,
    /// The signature is invalid.
    InvalidSignature,
    /// The same signed claim was already accepted.
    Replay,
    /// The same scope and sequence were used for different claims.
    Equivocation,
    /// The bounded replay window cannot retain a new scope.
    Capacity,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct ReplayScope {
    domain: ClaimDomain,
    realm: RealmId,
    session: SessionId,
    audience: PeerId,
    issuer: PeerId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Accepted {
    epoch: Epoch,
    sequence: Sequence,
    digest: [u8; 32],
}

/// A bounded replay and equivocation window for signed claims.
#[derive(Clone, Debug)]
pub struct ClaimReplayWindow {
    accepted: BTreeMap<ReplayScope, Accepted>,
    limit: usize,
}

impl Default for ClaimReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl Claim {
    /// Construct a claim, rejecting an inverted lifetime.
    pub fn new(
        context: ClaimContext,
        subject: SubjectDigest,
        sequence: Sequence,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self, ClaimBuildError> {
        if expires_at <= issued_at {
            return Err(ClaimBuildError::InvalidLifetime);
        }
        Ok(Self {
            domain: context.domain,
            realm: context.realm,
            session: context.session,
            subject,
            sequence,
            epoch: context.epoch,
            issued_at,
            expires_at,
            audience: context.audience,
        })
    }

    /// Encode fields in the canonical, length-prefixed claim representation.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let label = self.domain.label();
        let mut out = Vec::with_capacity(1 + 1 + 2 + label.len() + 16 * 3 + 32 + 8 * 4);
        out.push(CLAIM_VERSION);
        out.push(self.domain as u8);
        out.extend_from_slice(&(label.len() as u16).to_be_bytes());
        out.extend_from_slice(label);
        out.extend_from_slice(&self.realm.0.to_be_bytes());
        out.extend_from_slice(&self.session.0.to_be_bytes());
        out.extend_from_slice(self.subject.as_bytes());
        out.extend_from_slice(&self.sequence.0.to_be_bytes());
        out.extend_from_slice(&self.epoch.0.to_be_bytes());
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&self.audience.0.to_be_bytes());
        out
    }

    fn decode(raw: &[u8]) -> Result<Self, ClaimDecodeError> {
        let fixed = 1 + 1 + 2 + 16 + 16 + 32 + 8 + 8 + 8 + 8 + 16;
        if raw.len() > MAX_SIGNED_CLAIM_BYTES || raw.len() < fixed {
            return Err(if raw.len() > MAX_SIGNED_CLAIM_BYTES {
                ClaimDecodeError::TooLarge
            } else {
                ClaimDecodeError::Truncated
            });
        }
        if raw[0] != CLAIM_VERSION {
            return Err(ClaimDecodeError::UnsupportedVersion);
        }
        let domain = ClaimDomain::from_wire(raw[1]).ok_or(ClaimDecodeError::UnknownDomain)?;
        let label_len = u16::from_be_bytes([raw[2], raw[3]]) as usize;
        if label_len != domain.label().len() {
            return Err(ClaimDecodeError::InvalidLength);
        }
        let mut offset = 4;
        let label_end = offset + label_len;
        if label_end > raw.len() || &raw[offset..label_end] != domain.label() {
            return Err(ClaimDecodeError::InvalidLength);
        }
        offset = label_end;
        let realm = read_u128(raw, &mut offset)?;
        let session = read_u128(raw, &mut offset)?;
        let mut subject = [0_u8; 32];
        read_exact(raw, &mut offset, &mut subject)?;
        let sequence = read_u64(raw, &mut offset)?;
        let epoch = read_u64(raw, &mut offset)?;
        let issued_at = read_u64(raw, &mut offset)?;
        let expires_at = read_u64(raw, &mut offset)?;
        let audience = read_u128(raw, &mut offset)?;
        if offset != raw.len() {
            return Err(ClaimDecodeError::TrailingBytes);
        }
        Self::new(
            ClaimContext {
                domain,
                realm: RealmId(realm),
                session: SessionId(session),
                audience: PeerId(audience),
                epoch: Epoch(epoch),
            },
            SubjectDigest(subject),
            Sequence(sequence),
            issued_at,
            expires_at,
        )
        .map_err(|_| ClaimDecodeError::InvalidLifetime)
    }
}

impl SignedClaim {
    /// Encode a signed claim for opaque transport delivery.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let claim = self.claim.encode();
        let mut out = Vec::with_capacity(4 + claim.len() + 16 + 64);
        out.extend_from_slice(&(claim.len() as u32).to_be_bytes());
        out.extend_from_slice(&claim);
        out.extend_from_slice(&self.issuer.0.to_be_bytes());
        out.extend_from_slice(&self.signature);
        out
    }

    /// Decode a bounded canonical signed claim.
    pub fn decode(raw: &[u8]) -> Result<Self, ClaimDecodeError> {
        if raw.len() > MAX_SIGNED_CLAIM_BYTES {
            return Err(ClaimDecodeError::TooLarge);
        }
        if raw.len() < 4 {
            return Err(ClaimDecodeError::Truncated);
        }
        let claim_len = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
        let claim_end = 4usize
            .checked_add(claim_len)
            .ok_or(ClaimDecodeError::InvalidLength)?;
        let fixed_end = claim_end
            .checked_add(16 + 64)
            .ok_or(ClaimDecodeError::InvalidLength)?;
        if raw.len() < fixed_end {
            return Err(ClaimDecodeError::Truncated);
        }
        if raw.len() > fixed_end {
            return Err(ClaimDecodeError::TrailingBytes);
        }
        let claim = Claim::decode(&raw[4..claim_end])?;
        let issuer = PeerId(u128::from_be_bytes(
            raw[claim_end..claim_end + 16]
                .try_into()
                .map_err(|_| ClaimDecodeError::Truncated)?,
        ));
        let mut signature = [0_u8; 64];
        signature.copy_from_slice(&raw[claim_end + 16..fixed_end]);
        Ok(Self {
            claim,
            issuer,
            signature,
        })
    }

    /// Verify the signature and typed context without changing replay state.
    pub fn verify(
        &self,
        key: &VerifyingKey,
        expected: ClaimContext,
        now: u64,
    ) -> Result<(), ClaimVerifyError> {
        self.verify_context(key, expected, now)?;
        key.verify(&transcript(self), &Signature::from_bytes(&self.signature))
            .map_err(|_| ClaimVerifyError::InvalidSignature)
    }

    fn verify_context(
        &self,
        key: &VerifyingKey,
        expected: ClaimContext,
        now: u64,
    ) -> Result<(), ClaimVerifyError> {
        if peer_id_from_key(key) != self.issuer {
            return Err(ClaimVerifyError::IssuerMismatch);
        }
        if self.claim.domain != expected.domain {
            return Err(ClaimVerifyError::DomainMismatch);
        }
        if self.claim.realm != expected.realm {
            return Err(ClaimVerifyError::RealmMismatch);
        }
        if self.claim.session != expected.session {
            return Err(ClaimVerifyError::SessionMismatch);
        }
        if self.claim.audience != expected.audience {
            return Err(ClaimVerifyError::AudienceMismatch);
        }
        if self.claim.epoch != expected.epoch {
            return Err(ClaimVerifyError::EpochMismatch);
        }
        if now < self.claim.issued_at {
            return Err(ClaimVerifyError::NotYetValid);
        }
        if now > self.claim.expires_at {
            return Err(ClaimVerifyError::Expired);
        }
        Ok(())
    }
}

/// Sign a typed claim with a deterministic Ed25519 seed.
#[must_use]
pub fn sign_claim(claim: Claim, seed: [u8; 32]) -> SignedClaim {
    let key = SigningKey::from_bytes(&seed);
    let mut signed = SignedClaim {
        claim,
        issuer: peer_id_from_key(&key.verifying_key()),
        signature: [0; 64],
    };
    signed.signature = key.sign(&transcript(&signed)).to_bytes();
    signed
}

impl ClaimReplayWindow {
    /// Create an empty replay window with [`DEFAULT_REPLAY_LIMIT`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            accepted: BTreeMap::new(),
            limit: DEFAULT_REPLAY_LIMIT,
        }
    }

    /// Create an empty replay window with an explicit bounded scope limit.
    #[must_use]
    pub fn with_limit(limit: usize) -> Self {
        Self {
            accepted: BTreeMap::new(),
            limit,
        }
    }

    /// Verify and accept a claim exactly once per scope and sequence.
    pub fn verify_and_accept(
        &mut self,
        signed: &SignedClaim,
        key: &VerifyingKey,
        expected: ClaimContext,
        now: u64,
    ) -> Result<(), ClaimVerifyError> {
        signed.verify(key, expected, now)?;
        let scope = ReplayScope {
            domain: signed.claim.domain,
            realm: signed.claim.realm,
            session: signed.claim.session,
            audience: signed.claim.audience,
            issuer: signed.issuer,
        };
        let accepted = Accepted {
            epoch: signed.claim.epoch,
            sequence: signed.claim.sequence,
            digest: claim_digest(signed),
        };
        match self.accepted.get(&scope).copied() {
            None if self.accepted.len() >= self.limit => Err(ClaimVerifyError::Capacity),
            None => {
                self.accepted.insert(scope, accepted);
                Ok(())
            }
            Some(previous) if accepted.epoch < previous.epoch => Err(ClaimVerifyError::Replay),
            Some(previous) if accepted.epoch > previous.epoch => {
                self.accepted.insert(scope, accepted);
                Ok(())
            }
            Some(previous) if accepted.sequence < previous.sequence => {
                Err(ClaimVerifyError::Replay)
            }
            Some(previous) if accepted.sequence > previous.sequence => {
                self.accepted.insert(scope, accepted);
                Ok(())
            }
            Some(previous) if accepted.digest == previous.digest => Err(ClaimVerifyError::Replay),
            Some(_) => Err(ClaimVerifyError::Equivocation),
        }
    }
}

fn transcript(signed: &SignedClaim) -> Vec<u8> {
    let claim = signed.claim.encode();
    let mut out = Vec::with_capacity(TRANSCRIPT_DOMAIN.len() + 4 + claim.len() + 16);
    out.extend_from_slice(TRANSCRIPT_DOMAIN);
    out.extend_from_slice(&(claim.len() as u32).to_be_bytes());
    out.extend_from_slice(&claim);
    out.extend_from_slice(&signed.issuer.0.to_be_bytes());
    out
}

fn claim_digest(signed: &SignedClaim) -> [u8; 32] {
    let digest = Sha256::digest(transcript(signed));
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn read_exact(raw: &[u8], offset: &mut usize, out: &mut [u8]) -> Result<(), ClaimDecodeError> {
    let end = offset
        .checked_add(out.len())
        .ok_or(ClaimDecodeError::Truncated)?;
    if end > raw.len() {
        return Err(ClaimDecodeError::Truncated);
    }
    out.copy_from_slice(&raw[*offset..end]);
    *offset = end;
    Ok(())
}

fn read_u64(raw: &[u8], offset: &mut usize) -> Result<u64, ClaimDecodeError> {
    let mut bytes = [0_u8; 8];
    read_exact(raw, offset, &mut bytes)?;
    Ok(u64::from_be_bytes(bytes))
}

fn read_u128(raw: &[u8], offset: &mut usize) -> Result<u128, ClaimDecodeError> {
    let mut bytes = [0_u8; 16];
    read_exact(raw, offset, &mut bytes)?;
    Ok(u128::from_be_bytes(bytes))
}

fn peer_id_from_key(key: &VerifyingKey) -> PeerId {
    let digest = Sha256::digest(key.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    PeerId(u128::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const SEED: [u8; 32] = [9; 32];

    fn claim(sequence: u64, epoch: u64, subject: u8) -> Claim {
        Claim::new(
            ClaimContext {
                domain: ClaimDomain::Capability,
                realm: RealmId(7),
                session: SessionId(8),
                audience: PeerId(55),
                epoch: Epoch(epoch),
            },
            SubjectDigest::from_digest([subject; 32]),
            Sequence(sequence),
            10,
            20,
        )
        .unwrap()
    }

    fn context(epoch: u64) -> ClaimContext {
        ClaimContext {
            domain: ClaimDomain::Capability,
            realm: RealmId(7),
            session: SessionId(8),
            audience: PeerId(55),
            epoch: Epoch(epoch),
        }
    }

    #[test]
    fn canonical_claim_round_trip_and_length_prefix_are_unambiguous() {
        let signed = sign_claim(claim(1, 2, 3), SEED);
        let encoded = signed.encode();
        assert_eq!(SignedClaim::decode(&encoded).unwrap(), signed);
        let mut altered = encoded.clone();
        altered[3] ^= 1;
        assert_ne!(SignedClaim::decode(&altered), Ok(signed));
    }

    #[test]
    fn context_tampering_wrong_key_epoch_domain_and_audience_fail_closed() {
        let signed = sign_claim(claim(1, 2, 3), SEED);
        let key = SigningKey::from_bytes(&SEED).verifying_key();
        assert_eq!(signed.verify(&key, context(2), 15), Ok(()));
        assert_eq!(
            signed.verify(
                &SigningKey::from_bytes(&[4; 32]).verifying_key(),
                context(2),
                15
            ),
            Err(ClaimVerifyError::IssuerMismatch)
        );
        assert_eq!(
            signed.verify(&key, context(3), 15),
            Err(ClaimVerifyError::EpochMismatch)
        );
        assert_eq!(
            signed.verify(
                &key,
                ClaimContext {
                    domain: ClaimDomain::Receipt,
                    ..context(2)
                },
                15
            ),
            Err(ClaimVerifyError::DomainMismatch)
        );
        assert_eq!(
            signed.verify(
                &key,
                ClaimContext {
                    audience: PeerId(56),
                    ..context(2)
                },
                15
            ),
            Err(ClaimVerifyError::AudienceMismatch)
        );
        assert_eq!(
            signed.verify(&key, context(2), 9),
            Err(ClaimVerifyError::NotYetValid)
        );
        assert_eq!(
            signed.verify(&key, context(2), 21),
            Err(ClaimVerifyError::Expired)
        );
        let mut tampered = signed.clone();
        tampered.signature[0] ^= 1;
        assert_eq!(
            tampered.verify(&key, context(2), 15),
            Err(ClaimVerifyError::InvalidSignature)
        );
    }

    #[test]
    fn replay_and_equivocation_are_distinct_and_epoch_rollover_is_explicit() {
        let key = SigningKey::from_bytes(&SEED).verifying_key();
        let mut window = ClaimReplayWindow::new();
        let first = sign_claim(claim(1, 2, 3), SEED);
        assert_eq!(
            window.verify_and_accept(&first, &key, context(2), 15),
            Ok(())
        );
        assert_eq!(
            window.verify_and_accept(&first, &key, context(2), 15),
            Err(ClaimVerifyError::Replay)
        );
        let conflicting = sign_claim(claim(1, 2, 4), SEED);
        assert_eq!(
            window.verify_and_accept(&conflicting, &key, context(2), 15),
            Err(ClaimVerifyError::Equivocation)
        );
        let next_epoch = sign_claim(claim(1, 3, 4), SEED);
        assert_eq!(
            window.verify_and_accept(&next_epoch, &key, context(3), 15),
            Ok(())
        );
    }

    proptest! {
        #[test]
        fn signed_claim_bytes_round_trip(sequence in any::<u64>(), epoch in any::<u64>(), subject in any::<u8>()) {
            let signed = sign_claim(claim(sequence, epoch, subject), SEED);
            prop_assert_eq!(SignedClaim::decode(&signed.encode()), Ok(signed));
        }
    }
}
