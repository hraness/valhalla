//! Fixed-width owner-signed pairing invitations.
//!
//! An invitation is an authorization claim, not a transport handshake.  It
//! names the owner and the invited application key plus a bounded room scope.
//! The caller must still bind observed transport keys and construct a fresh
//! [`crate::Pairing`] before starting a session.  In particular, decoding or
//! verifying an invitation never admits a peer by itself.

use alloc::vec::Vec;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use vhalla_core::{Epoch, RealmId, RoomId};

const MAGIC: &[u8; 4] = b"VHIN";
const VERSION: u8 = 1;
const DOMAIN: &[u8] = b"vhalla/owner-invitation/v1";
const NONCE_BYTES: usize = 32;
const UNSIGNED_BYTES: usize = 4 + 1 + 32 + 32 + 16 + 16 + 8 + 8 + NONCE_BYTES;
/// Canonical encoded invitation length.
pub const INVITATION_BYTES: usize = UNSIGNED_BYTES + 64;

/// A bounded failure at the invitation trust boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvitationError {
    /// The bytes have the wrong version, length, magic or nonce.
    Malformed,
    /// A key is invalid, weak or the owner and invitee are identical.
    Key,
    /// The embedded owner differs from the explicitly expected owner.
    Issuer,
    /// The owner signature does not verify.
    Signature,
    /// The invitation is no longer valid at the supplied clock value.
    Expired,
}

/// The verified, typed authorization carried by an invitation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvitationClaims {
    /// Owner application key which authorized the invitation.
    pub owner: [u8; 32],
    /// Invited application key. The caller must bind it to a fresh transport.
    pub invitee: [u8; 32],
    /// Realm namespace.
    pub realm: RealmId,
    /// Room namespace within the realm.
    pub room: RoomId,
    /// Membership/policy epoch at which the invitation was issued.
    pub epoch: Epoch,
    /// Exclusive expiration in the caller's trusted clock units.
    pub expires_at: u64,
    /// Owner-provided uniqueness value; it prevents ambiguous token reuse.
    pub nonce: [u8; NONCE_BYTES],
}

/// An owner-signed, fixed-width invitation descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Invitation {
    claims: InvitationClaims,
    signature: [u8; 64],
}

impl Invitation {
    /// Issue an invitation with a caller-supplied unpredictable nonce.
    ///
    /// This function does not persist or publish the token. The owner must
    /// retain the nonce or an equivalent spent-token record if it wants
    /// single-use semantics.
    pub fn issue(
        owner: &SigningKey,
        invitee: [u8; 32],
        realm: RealmId,
        room: RoomId,
        epoch: Epoch,
        expires_at: u64,
        nonce: [u8; NONCE_BYTES],
    ) -> Result<Self, InvitationError> {
        let owner_key = owner.verifying_key().to_bytes();
        validate_keys(owner_key, invitee)?;
        if expires_at == 0 || nonce == [0; NONCE_BYTES] {
            return Err(InvitationError::Malformed);
        }
        let claims = InvitationClaims {
            owner: owner_key,
            invitee,
            realm,
            room,
            epoch,
            expires_at,
            nonce,
        };
        let signature = owner.sign(&transcript(&claims)).to_bytes();
        Ok(Self { claims, signature })
    }

    /// Decode one canonical invitation without assigning it authority.
    pub fn decode(raw: &[u8]) -> Result<Self, InvitationError> {
        if raw.len() != INVITATION_BYTES || &raw[..4] != MAGIC || raw[4] != VERSION {
            return Err(InvitationError::Malformed);
        }
        let owner = raw[5..37]
            .try_into()
            .map_err(|_| InvitationError::Malformed)?;
        let invitee = raw[37..69]
            .try_into()
            .map_err(|_| InvitationError::Malformed)?;
        let realm = RealmId(u128::from_be_bytes(
            raw[69..85]
                .try_into()
                .map_err(|_| InvitationError::Malformed)?,
        ));
        let room = RoomId(u128::from_be_bytes(
            raw[85..101]
                .try_into()
                .map_err(|_| InvitationError::Malformed)?,
        ));
        let epoch = Epoch(u64::from_be_bytes(
            raw[101..109]
                .try_into()
                .map_err(|_| InvitationError::Malformed)?,
        ));
        let expires_at = u64::from_be_bytes(
            raw[109..117]
                .try_into()
                .map_err(|_| InvitationError::Malformed)?,
        );
        let nonce = raw[117..149]
            .try_into()
            .map_err(|_| InvitationError::Malformed)?;
        if expires_at == 0 || nonce == [0; NONCE_BYTES] {
            return Err(InvitationError::Malformed);
        }
        validate_keys(owner, invitee)?;
        let signature = raw[UNSIGNED_BYTES..]
            .try_into()
            .map_err(|_| InvitationError::Malformed)?;
        Ok(Self {
            claims: InvitationClaims {
                owner,
                invitee,
                realm,
                room,
                epoch,
                expires_at,
                nonce,
            },
            signature,
        })
    }

    /// Encode the canonical fixed-width representation.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(INVITATION_BYTES);
        out.extend_from_slice(&unsigned(self.claims));
        out.extend_from_slice(&self.signature);
        out
    }

    /// Verify the signature and bind it to the expected owner identity.
    pub fn verify_for(
        &self,
        expected_owner: [u8; 32],
    ) -> Result<InvitationClaims, InvitationError> {
        if self.claims.owner != expected_owner {
            return Err(InvitationError::Issuer);
        }
        checked_key(expected_owner)?
            .verify_strict(
                &transcript(&self.claims),
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| InvitationError::Signature)?;
        Ok(self.claims)
    }

    /// Verify and enforce the exclusive expiration boundary (`now < expires_at`).
    pub fn verify_at(
        &self,
        expected_owner: [u8; 32],
        now: u64,
    ) -> Result<InvitationClaims, InvitationError> {
        let claims = self.verify_for(expected_owner)?;
        if now >= claims.expires_at {
            return Err(InvitationError::Expired);
        }
        Ok(claims)
    }

    /// Return the claims without treating them as verified authority.
    #[must_use]
    pub fn claims(&self) -> InvitationClaims {
        self.claims
    }
}

fn validate_keys(owner: [u8; 32], invitee: [u8; 32]) -> Result<(), InvitationError> {
    if owner == invitee {
        return Err(InvitationError::Key);
    }
    checked_key(owner)?;
    checked_key(invitee)?;
    Ok(())
}

fn checked_key(bytes: [u8; 32]) -> Result<VerifyingKey, InvitationError> {
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| InvitationError::Key)?;
    if key.is_weak() {
        return Err(InvitationError::Key);
    }
    Ok(key)
}

fn unsigned(claims: InvitationClaims) -> Vec<u8> {
    let mut out = Vec::with_capacity(UNSIGNED_BYTES);
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&claims.owner);
    out.extend_from_slice(&claims.invitee);
    out.extend_from_slice(&claims.realm.0.to_be_bytes());
    out.extend_from_slice(&claims.room.0.to_be_bytes());
    out.extend_from_slice(&claims.epoch.0.to_be_bytes());
    out.extend_from_slice(&claims.expires_at.to_be_bytes());
    out.extend_from_slice(&claims.nonce);
    out
}

fn transcript(claims: &InvitationClaims) -> Vec<u8> {
    let bytes = unsigned(*claims);
    let mut out = Vec::with_capacity(DOMAIN.len() + bytes.len());
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(&bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn invitation() -> (SigningKey, [u8; 32]) {
        (key(7), key(8).verifying_key().to_bytes())
    }

    #[test]
    fn fixed_width_invitation_round_trips_and_binds_owner() {
        let (owner, invitee) = invitation();
        let issued = Invitation::issue(
            &owner,
            invitee,
            RealmId(9),
            RoomId(10),
            Epoch(11),
            100,
            [3; NONCE_BYTES],
        )
        .unwrap();
        assert_eq!(issued.encode().len(), INVITATION_BYTES);
        let decoded = Invitation::decode(&issued.encode()).unwrap();
        assert_eq!(
            decoded
                .verify_at(owner.verifying_key().to_bytes(), 99)
                .unwrap()
                .room,
            RoomId(10)
        );
        assert_eq!(
            decoded.verify_for(key(6).verifying_key().to_bytes()),
            Err(InvitationError::Issuer)
        );
    }

    #[test]
    fn tampering_expiry_signature_or_scope_is_rejected() {
        let (owner, invitee) = invitation();
        let issued = Invitation::issue(
            &owner,
            invitee,
            RealmId(1),
            RoomId(2),
            Epoch(3),
            10,
            [4; NONCE_BYTES],
        )
        .unwrap();
        let mut raw = issued.encode();
        raw[117] ^= 1;
        assert_eq!(
            Invitation::decode(&raw)
                .unwrap()
                .verify_for(owner.verifying_key().to_bytes()),
            Err(InvitationError::Signature)
        );
        let mut raw = issued.encode();
        raw[109..117].fill(0);
        assert_eq!(Invitation::decode(&raw), Err(InvitationError::Malformed));
        assert_eq!(
            issued.verify_at(owner.verifying_key().to_bytes(), 10),
            Err(InvitationError::Expired)
        );
    }

    #[test]
    fn malformed_lengths_and_zero_nonce_never_allocate_unbounded_state() {
        assert_eq!(Invitation::decode(&[]), Err(InvitationError::Malformed));
        let owner = key(1);
        assert_eq!(
            Invitation::issue(
                &owner,
                key(2).verifying_key().to_bytes(),
                RealmId(0),
                RoomId(0),
                Epoch(0),
                1,
                [0; NONCE_BYTES]
            ),
            Err(InvitationError::Malformed)
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn arbitrary_issued_claims_have_a_canonical_round_trip(
            owner_seed in any::<u8>(),
            invitee_seed in any::<u8>(),
            realm in any::<u128>(),
            room in any::<u128>(),
            epoch in any::<u64>(),
            expires_at in any::<u64>(),
            mut nonce in any::<[u8; NONCE_BYTES]>(),
        ) {
            prop_assume!(owner_seed != invitee_seed);
            nonce[0] |= 1;
            let owner = key(owner_seed);
            let invitee = key(invitee_seed).verifying_key().to_bytes();
            let expires_at = expires_at.max(1);
            let issued = Invitation::issue(
                &owner,
                invitee,
                RealmId(realm),
                RoomId(room),
                Epoch(epoch),
                expires_at,
                nonce,
            ).unwrap();
            let encoded = issued.encode();
            let decoded = Invitation::decode(&encoded).unwrap();
            prop_assert_eq!(encoded.len(), INVITATION_BYTES);
            prop_assert_eq!(decoded.encode(), encoded);
            prop_assert_eq!(
                decoded.verify_at(owner.verifying_key().to_bytes(), expires_at - 1),
                Ok(decoded.claims())
            );
        }

        #[test]
        fn any_changed_invitation_bit_cannot_still_verify(
            owner_seed in any::<u8>(),
            invitee_seed in any::<u8>(),
            bit_offset in any::<usize>(),
            bit in 0u8..8,
        ) {
            prop_assume!(owner_seed != invitee_seed);
            let owner = key(owner_seed);
            let invitee = key(invitee_seed).verifying_key().to_bytes();
            let issued = Invitation::issue(
                &owner,
                invitee,
                RealmId(1),
                RoomId(2),
                Epoch(3),
                100,
                [9; NONCE_BYTES],
            ).unwrap();
            let mut tampered = issued.encode();
            let index = bit_offset % tampered.len();
            tampered[index] ^= 1 << bit;
            let result = Invitation::decode(&tampered)
                .and_then(|decoded| decoded.verify_for(owner.verifying_key().to_bytes()));
            prop_assert!(result.is_err());
        }

        #[test]
        fn arbitrary_bytes_are_bounded_and_never_panic(raw in prop::collection::vec(any::<u8>(), 0..256)) {
            if let Ok(decoded) = Invitation::decode(&raw) {
                let encoded = decoded.encode();
                prop_assert_eq!(encoded.len(), INVITATION_BYTES);
                prop_assert_eq!(Invitation::decode(&encoded), Ok(decoded));
            }
        }
    }
}
