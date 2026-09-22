#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Portable password-encrypted application-key custody.
//!
//! The caller supplies fresh CSPRNG seed, salt and nonce bytes and owns storage,
//! password entry, operation concurrency and explicit user authorization. This
//! crate has no browser, network, clock, filesystem or entropy source. Its fixed
//! envelope is a recovery backup, not a freshness or durable-publication proof.
//! Unlocking exposes only typed social and public-activity signing. Same-origin script compromise,
//! an unlocked process, browser eviction and storage rollback remain outside
//! this boundary. See the crate README for the format and recovery contract.

extern crate alloc;

pub mod backup;

use alloc::vec::Vec;
use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::{AeadInPlace, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{SigningKey, VerifyingKey};
use vhalla_social::{PrimarySignedRecord, SignedRecord, UnsignedRecord};
use zeroize::{ZeroizeOnDrop, Zeroizing};

const MAGIC: &[u8; 5] = b"VHBV\x01";
const SALT_START: usize = MAGIC.len();
const NONCE_START: usize = SALT_START + 16;
const PUBLIC_START: usize = NONCE_START + 24;
const CIPHER_START: usize = PUBLIC_START + 32;
const TAG_START: usize = CIPHER_START + 32;

/// Exact canonical v1 envelope length, including its 16-byte authentication tag.
pub const ENVELOPE_BYTES: usize = TAG_START + 16;
/// Smallest admitted password in bytes; this does not measure password entropy.
pub const MIN_PASSWORD_BYTES: usize = 12;
/// Largest admitted password in bytes, checked before key derivation.
pub const MAX_PASSWORD_BYTES: usize = 1024;
/// Fixed Argon2id memory cost in 1 KiB blocks: 19 MiB per in-flight operation.
pub const KDF_MEMORY_KIB: u32 = 19 * 1024;
/// Fixed Argon2id pass count. An envelope cannot select another value.
pub const KDF_PASSES: u32 = 2;
/// Fixed Argon2id lane count. An envelope cannot select another value.
pub const KDF_LANES: u32 = 1;

/// Closed failures which never contain passwords, seeds or decrypted bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Password byte length is outside the fixed range.
    PasswordBounds,
    /// Envelope size, version or claimed public-key encoding is invalid.
    Malformed,
    /// Wrong password, altered envelope or decrypted/header key mismatch.
    Authentication,
    /// The bounded KDF allocation or cryptographic operation could not complete.
    Resource,
}

/// Opaque encrypted backup. Its public-key header is untrusted until unlock.
///
/// The bytes are safe to persist without exposing a plaintext key, but permit
/// offline password guessing. Do not log or publish backups unnecessarily.
#[derive(Clone, Eq, PartialEq)]
pub struct Envelope([u8; ENVELOPE_BYTES]);

impl Envelope {
    /// Parse the exact bounded format without deriving a key or authenticating it.
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() != ENVELOPE_BYTES || &raw[..MAGIC.len()] != MAGIC {
            return Err(Error::Malformed);
        }
        let mut bytes = [0; ENVELOPE_BYTES];
        bytes.copy_from_slice(raw);
        let envelope = Self(bytes);
        let public = VerifyingKey::from_bytes(&envelope.claimed_public_key())
            .map_err(|_| Error::Malformed)?;
        if public.is_weak() {
            return Err(Error::Malformed);
        }
        Ok(envelope)
    }

    /// Exact versioned bytes for storage or an explicitly requested backup.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ENVELOPE_BYTES] {
        &self.0
    }

    /// Unauthenticated header label; do not use it to authorize an identity.
    #[must_use]
    pub fn claimed_public_key(&self) -> [u8; 32] {
        let mut public = [0; 32];
        public.copy_from_slice(&self.0[PUBLIC_START..CIPHER_START]);
        public
    }
}

/// An unlocked Ed25519 identity, zeroized on drop by its private signing key.
///
/// It deliberately has no `Debug`, `Clone`, serialization, raw seed getter or
/// generic signing operation. A caller must still authorize each typed request;
/// this object is key custody, not an owner-policy or physical-gesture check.
///
/// ```compile_fail
/// use vhalla_browser_vault::UnlockedIdentity;
/// fn duplicate(key: &UnlockedIdentity) -> UnlockedIdentity { key.clone() }
/// ```
/// ```compile_fail
/// use vhalla_browser_vault::UnlockedIdentity;
/// fn needs_debug<T: core::fmt::Debug>(_: &T) {}
/// fn expose(key: &UnlockedIdentity) { needs_debug(key); }
/// ```
pub struct UnlockedIdentity {
    key: SigningKey,
}

// SigningKey's zeroize feature clears its secret material when the field drops.
impl ZeroizeOnDrop for UnlockedIdentity {}

impl UnlockedIdentity {
    /// Authenticated application public key, checked against the decrypted seed.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// Derive opaque private storage custody for this exact account and context.
    /// Keep the returned key and private kernel inside the unlocked worker; no
    /// worker response may export secret bytes. Lock must destroy both identity
    /// and kernels. This neither restores missing state nor prevents clones.
    /// See `StorageKey::derive_for_account` for the fixed versioned contract.
    #[cfg(feature = "private-storage")]
    pub fn private_storage_key(
        &self,
        context: vhalla_private_kernel::Context,
    ) -> Result<vhalla_private_kernel::StorageKey, vhalla_private_kernel::Error> {
        vhalla_private_kernel::StorageKey::derive_for_account(&self.key, context)
    }

    /// Sign the exact private-room anchor request with its owner account key.
    /// The trusted controller must authorize room creation independently and
    /// persist the corresponding device before releasing any MLS artifact.
    /// This account signature never grants host execution or relay authority.
    #[cfg(feature = "private-rooms")]
    pub fn sign_private_anchor(
        &self,
        request: &vhalla_private_protocol::UnsignedRoomAnchor,
    ) -> Result<vhalla_private_protocol::SignedRoomAnchor, vhalla_private_protocol::Error> {
        request.sign(&self.key)
    }

    /// Sign one exact account/device/validity binding without exposing key bytes.
    /// Enrollment alone is not room membership. Creation, renewal and recovery
    /// require separately checked owner policy, current state and durable output.
    #[cfg(feature = "private-rooms")]
    pub fn sign_private_enrollment(
        &self,
        request: &vhalla_private_protocol::UnsignedDeviceEnrollment,
    ) -> Result<vhalla_private_protocol::SignedDeviceEnrollment, vhalla_private_protocol::Error>
    {
        request.sign(&self.key)
    }

    /// Sign one exact owner-succession grant bound to a retained floor and an
    /// already-enrolled successor device. The account signature alone transfers
    /// nothing; only the predecessor device's carrying control commits it.
    #[cfg(feature = "private-rooms")]
    pub fn sign_private_succession(
        &self,
        request: &vhalla_private_protocol::UnsignedOwnerSuccession,
    ) -> Result<vhalla_private_protocol::SignedOwnerSuccession, vhalla_private_protocol::Error>
    {
        request.sign(&self.key)
    }

    /// Sign a typed public-room event with this exact author key.
    ///
    /// The host must durably reserve these exact unsigned bytes before calling,
    /// admit their room policy separately, and retain the reservation after any
    /// uncertain outcome. This method neither allocates sequences nor publishes.
    pub fn sign_activity(
        &self,
        request: vhalla_room_activity::UnsignedEvent,
    ) -> Result<vhalla_room_activity::SignedEvent, vhalla_room_activity::Error> {
        request.sign_with_key(&self.key)
    }

    /// Sign a checked social record whose primary key must match this identity.
    pub fn sign_social(
        &self,
        request: UnsignedRecord,
    ) -> Result<PrimarySignedRecord, vhalla_social::Error> {
        request.sign_with_key(&self.key)
    }

    /// Countersign exactly the agent genesis or key transition supplied here.
    pub fn countersign_social(
        &self,
        request: PrimarySignedRecord,
    ) -> Result<SignedRecord, vhalla_social::Error> {
        request.countersign(&self.key)
    }
}

fn check_password(password: &[u8]) -> Result<(), Error> {
    if !(MIN_PASSWORD_BYTES..=MAX_PASSWORD_BYTES).contains(&password.len()) {
        return Err(Error::PasswordBounds);
    }
    Ok(())
}

fn derive_key(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
    check_password(password)?;
    let params = Params::new(KDF_MEMORY_KIB, KDF_PASSES, KDF_LANES, Some(32))
        .map_err(|_| Error::Resource)?;
    // The convenience Argon2 allocator does not clear its full block buffer.
    // Own it explicitly so both success and errors drop zeroizing scratch.
    let mut memory = Zeroizing::new(Vec::new());
    memory
        .try_reserve_exact(params.block_count())
        .map_err(|_| Error::Resource)?;
    memory.resize(params.block_count(), Block::default());
    let mut key = Zeroizing::new([0; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(password, salt, &mut key[..], memory.as_mut_slice())
        .map_err(|_| Error::Resource)?;
    Ok(key)
}

/// Encrypt a caller-supplied seed as an exact v1 recovery envelope.
///
/// Production callers must obtain all three inputs from the OS/browser CSPRNG:
/// a fresh 32-byte seed when creating an identity and fresh independent 16-byte
/// salt/24-byte nonce for every seal. There is no default or fixture entropy path.
/// The crate cannot prove randomness or remember prior nonces. Reusing a seed
/// restores an identity; using a new seed creates a different identity.
///
/// `seed` is consumed and cleared on every return path. The borrowed password
/// is never retained; its owner must clear password buffers and UI fields.
pub fn seal(
    mut seed: Zeroizing<[u8; 32]>,
    password: &[u8],
    salt: [u8; 16],
    nonce: [u8; 24],
) -> Result<Envelope, Error> {
    check_password(password)?;
    let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let mut envelope = Envelope([0; ENVELOPE_BYTES]);
    envelope.0[..MAGIC.len()].copy_from_slice(MAGIC);
    envelope.0[SALT_START..NONCE_START].copy_from_slice(&salt);
    envelope.0[NONCE_START..PUBLIC_START].copy_from_slice(&nonce);
    envelope.0[PUBLIC_START..CIPHER_START].copy_from_slice(&public);
    let key = derive_key(password, &salt)?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let tag = cipher
        .encrypt_in_place_detached(
            XNonce::from_slice(&nonce),
            &envelope.0[..CIPHER_START],
            &mut seed[..],
        )
        .map_err(|_| Error::Resource)?;
    envelope.0[CIPHER_START..TAG_START].copy_from_slice(&seed[..]);
    envelope.0[TAG_START..].copy_from_slice(&tag);
    Ok(envelope)
}

/// Authenticate/decrypt an exact v1 envelope and bind its claimed public key.
///
/// Format and password bounds are checked before allocating the fixed KDF
/// scratch. Wrong passwords and authenticated-header mismatches share the same
/// error. No candidate identity escapes before every check succeeds. Each call
/// costs 19 MiB and two Argon2id passes: the adapter must serialize/rate-limit
/// attempts and avoid blocking an interactive browser render loop.
pub fn unlock(raw: &[u8], password: &[u8]) -> Result<UnlockedIdentity, Error> {
    let envelope = Envelope::from_bytes(raw)?;
    let key = derive_key(password, &raw[SALT_START..NONCE_START])?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let mut seed = Zeroizing::new([0; 32]);
    seed.copy_from_slice(&raw[CIPHER_START..TAG_START]);
    cipher
        .decrypt_in_place_detached(
            XNonce::from_slice(&raw[NONCE_START..PUBLIC_START]),
            &raw[..CIPHER_START],
            &mut seed[..],
            Tag::from_slice(&raw[TAG_START..]),
        )
        .map_err(|_| Error::Authentication)?;
    let identity = UnlockedIdentity {
        key: SigningKey::from_bytes(&seed),
    };
    if identity.public_key() != envelope.claimed_public_key() {
        return Err(Error::Authentication);
    }
    Ok(identity)
}

#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "private-rooms"))]
mod private_signing_tests {
    use super::*;
    use vhalla_private_protocol::{
        DeviceEnrollmentClaims, Key, RoomAnchorClaims, RoomId, UnsignedDeviceEnrollment,
        UnsignedRoomAnchor, Validity,
    };

    #[test]
    fn private_signatures_bind_account_device_room_and_validity() {
        let owner = UnlockedIdentity {
            key: SigningKey::from_bytes(&[101; 32]),
        };
        let wrong = UnlockedIdentity {
            key: SigningKey::from_bytes(&[102; 32]),
        };
        let account = Key::from_bytes(owner.public_key()).unwrap();
        let device = Key::from_bytes(wrong.public_key()).unwrap();
        let request = UnsignedRoomAnchor::new(RoomAnchorClaims {
            room: RoomId::from_bytes([103; 32]).unwrap(),
            owner_account: account,
            owner_device: device,
        })
        .unwrap();
        let enrollment = UnsignedDeviceEnrollment::new(DeviceEnrollmentClaims {
            account,
            device,
            validity: Validity::new(10, 20).unwrap(),
        })
        .unwrap();
        assert!(matches!(
            wrong.sign_private_anchor(&request),
            Err(vhalla_private_protocol::Error::Signer)
        ));
        assert!(matches!(
            wrong.sign_private_enrollment(&enrollment),
            Err(vhalla_private_protocol::Error::Signer)
        ));
        assert_eq!(
            owner
                .sign_private_anchor(&request)
                .unwrap()
                .verify()
                .unwrap()
                .claims(),
            request.claims()
        );
        assert_eq!(
            owner
                .sign_private_enrollment(&enrollment)
                .unwrap()
                .verify()
                .unwrap()
                .claims(),
            enrollment.claims()
        );
        let other = UnsignedDeviceEnrollment::new(DeviceEnrollmentClaims {
            account,
            device,
            validity: Validity::new(10, 21).unwrap(),
        })
        .unwrap();
        let signed = owner.sign_private_enrollment(&enrollment).unwrap().encode();
        assert!(other
            .attach(signed[signed.len() - 64..].try_into().unwrap())
            .is_err());
    }
}
