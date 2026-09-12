#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Deterministic application signatures and replay checks for the steel thread.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use vhalla_core::{PeerId, Sequence};
use vhalla_wire::{DecodeError, Envelope};

const DOMAIN: &[u8] = b"vhalla/steel-thread/v1";

/// A signed application envelope. Transport may forward it as opaque bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedEnvelope {
    /// The canonical unsigned application envelope.
    pub envelope: Envelope,
    /// Intended owner/recipient peer.
    pub audience: PeerId,
    /// Absolute expiry in the caller's injected clock units.
    pub expires_at: u64,
    /// Ed25519 signature over the domain-separated transcript.
    pub signature: [u8; 64],
}

/// Errors while decoding the signed transport payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeSignedError {
    /// The unsigned envelope was malformed.
    Wire(DecodeError),
    /// A fixed field was truncated.
    Truncated,
    /// Extra bytes followed the signature.
    TrailingBytes,
}

/// A replay/expiry verification error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifyError {
    /// The signing key does not map to the envelope author.
    AuthorMismatch,
    /// The envelope targets another peer.
    AudienceMismatch,
    /// The envelope has expired.
    Expired,
    /// The sender sequence is not newer than the accepted value.
    Replay,
    /// The signature does not verify.
    InvalidSignature,
}

/// Last accepted sequence per author.
#[derive(Clone, Debug, Default)]
pub struct ReplayWindow {
    last: BTreeMap<PeerId, Sequence>,
}

impl SignedEnvelope {
    /// Encode the signed envelope for opaque transport delivery.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let envelope = self.envelope.encode();
        let mut out = Vec::with_capacity(4 + envelope.len() + 16 + 8 + 64);
        out.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
        out.extend_from_slice(&envelope);
        out.extend_from_slice(&self.audience.0.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&self.signature);
        out
    }

    /// Decode the fixed signed payload received from transport.
    pub fn decode(raw: &[u8]) -> Result<Self, DecodeSignedError> {
        if raw.len() < 4 {
            return Err(DecodeSignedError::Truncated);
        }
        let envelope_len = u32::from_be_bytes(raw[0..4].try_into().expect("four bytes")) as usize;
        let envelope_end = 4usize
            .checked_add(envelope_len)
            .ok_or(DecodeSignedError::Truncated)?;
        let fixed_end = envelope_end
            .checked_add(16 + 8 + 64)
            .ok_or(DecodeSignedError::Truncated)?;
        if raw.len() < fixed_end {
            return Err(DecodeSignedError::Truncated);
        }
        if raw.len() > fixed_end {
            return Err(DecodeSignedError::TrailingBytes);
        }
        let envelope = Envelope::decode(&raw[4..envelope_end]).map_err(DecodeSignedError::Wire)?;
        let audience = PeerId(u128::from_be_bytes(
            raw[envelope_end..envelope_end + 16]
                .try_into()
                .expect("sixteen bytes"),
        ));
        let expires_at = u64::from_be_bytes(
            raw[envelope_end + 16..envelope_end + 24]
                .try_into()
                .expect("eight bytes"),
        );
        let mut signature = [0_u8; 64];
        signature.copy_from_slice(&raw[envelope_end + 24..fixed_end]);
        Ok(Self {
            envelope,
            audience,
            expires_at,
            signature,
        })
    }
}

impl ReplayWindow {
    /// Create an empty replay window.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify and accept a signed envelope once.
    pub fn verify_and_accept(
        &mut self,
        signed: &SignedEnvelope,
        key: &VerifyingKey,
        expected_audience: PeerId,
        now: u64,
    ) -> Result<(), VerifyError> {
        if peer_id_from_key(key) != signed.envelope.author {
            return Err(VerifyError::AuthorMismatch);
        }
        if signed.audience != expected_audience {
            return Err(VerifyError::AudienceMismatch);
        }
        if now > signed.expires_at {
            return Err(VerifyError::Expired);
        }
        let transcript = transcript(signed);
        let signature = Signature::from_bytes(&signed.signature);
        key.verify(&transcript, &signature)
            .map_err(|_| VerifyError::InvalidSignature)?;
        if self
            .last
            .get(&signed.envelope.author)
            .is_some_and(|last| signed.envelope.sequence <= *last)
        {
            return Err(VerifyError::Replay);
        }
        self.last
            .insert(signed.envelope.author, signed.envelope.sequence);
        Ok(())
    }
}

/// Sign an envelope with a deterministic Ed25519 key and explicit audience/expiry.
#[must_use]
pub fn sign(
    envelope: Envelope,
    audience: PeerId,
    expires_at: u64,
    seed: [u8; 32],
) -> SignedEnvelope {
    let key = SigningKey::from_bytes(&seed);
    let mut signed = SignedEnvelope {
        envelope,
        audience,
        expires_at,
        signature: [0; 64],
    };
    signed.signature = key.sign(&transcript(&signed)).to_bytes();
    signed
}

/// Derive the stable protocol peer handle from an Ed25519 verifying key.
#[must_use]
pub fn peer_id_from_key(key: &VerifyingKey) -> PeerId {
    let digest = Sha256::digest(key.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    PeerId(u128::from_be_bytes(bytes))
}

/// Derive the stable peer handle for a deterministic signing seed.
#[must_use]
pub fn peer_id_from_seed(seed: [u8; 32]) -> PeerId {
    let key = SigningKey::from_bytes(&seed);
    peer_id_from_key(&key.verifying_key())
}

/// Derive the verifying key for a deterministic signing seed.
#[must_use]
pub fn verifying_key_from_seed(seed: [u8; 32]) -> VerifyingKey {
    SigningKey::from_bytes(&seed).verifying_key()
}

fn transcript(signed: &SignedEnvelope) -> Vec<u8> {
    let encoded = signed.envelope.encode();
    let mut bytes = Vec::with_capacity(DOMAIN.len() + encoded.len() + 16 + 8);
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&encoded);
    bytes.extend_from_slice(&signed.audience.0.to_be_bytes());
    bytes.extend_from_slice(&signed.expires_at.to_be_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use vhalla_core::{EventId, RealmId, RoomId};

    fn envelope(sequence: u64) -> (Envelope, SigningKey) {
        let key = SigningKey::from_bytes(&[7; 32]);
        let author = peer_id_from_key(&key.verifying_key());
        (
            Envelope::chat(
                author,
                RealmId(1),
                RoomId(2),
                EventId(sequence as u128),
                Sequence(sequence),
                b"hostile prose",
            )
            .unwrap(),
            key,
        )
    }

    #[test]
    fn signature_binds_author_audience_expiry_and_wire_bytes() {
        let (event, key) = envelope(1);
        let audience = PeerId(44);
        let signed = sign(event.clone(), audience, 100, [7; 32]);
        let mut replay = ReplayWindow::new();
        assert_eq!(
            replay.verify_and_accept(&signed, &key.verifying_key(), audience, 50),
            Ok(())
        );
        assert_eq!(
            replay.verify_and_accept(&signed, &key.verifying_key(), audience, 50),
            Err(VerifyError::Replay)
        );
        let wrong_audience = sign(event, PeerId(45), 100, [7; 32]);
        assert_eq!(
            replay.verify_and_accept(&wrong_audience, &key.verifying_key(), audience, 50),
            Err(VerifyError::AudienceMismatch)
        );
    }

    #[test]
    fn signed_payload_round_trips_through_transport_bytes() {
        let (event, _) = envelope(1);
        let signed = sign(event, PeerId(44), 100, [7; 32]);
        assert_eq!(SignedEnvelope::decode(&signed.encode()).unwrap(), signed);
    }

    #[test]
    fn expiry_and_tampering_fail_closed() {
        let (event, key) = envelope(1);
        let audience = PeerId(44);
        let signed = sign(event, audience, 10, [7; 32]);
        let mut replay = ReplayWindow::new();
        assert_eq!(
            replay.verify_and_accept(&signed, &key.verifying_key(), audience, 11),
            Err(VerifyError::Expired)
        );
        let mut tampered = signed.clone();
        tampered.envelope.body[0] ^= 1;
        assert_eq!(
            replay.verify_and_accept(&tampered, &key.verifying_key(), audience, 1),
            Err(VerifyError::InvalidSignature)
        );
    }

    proptest! {
        #[test]
        fn signed_transport_round_trip_is_stable(body in proptest::collection::vec(any::<u8>(), 0..256), sequence in 1_u64..10_000) {
            let key = SigningKey::from_bytes(&[7; 32]);
            let event = Envelope::chat(
                peer_id_from_key(&key.verifying_key()),
                RealmId(1),
                RoomId(2),
                EventId(sequence as u128),
                Sequence(sequence),
                &body,
            ).unwrap();
            let signed = sign(event, PeerId(44), 100, [7; 32]);
            let encoded = signed.encode();
            prop_assert_eq!(SignedEnvelope::decode(&encoded), Ok(signed));
        }
    }
}
