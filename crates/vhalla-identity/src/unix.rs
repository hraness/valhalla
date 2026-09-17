use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, Write},
    path::Path,
};
use vhalla_crypto::{sign_with_key, SignError, SignedEnvelope, VerificationContext};
use vhalla_custody::{self as custody, Error as CustodyError};
use vhalla_session::{ChatSession, Invitation, InvitationError, Pairing, Pending, Reject};
use vhalla_wire::Envelope;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"VHID0001";
const RECORD_BYTES: usize = 72;

/// Errors preserve the distinction between absence, unsafe input and uncertain
/// creation. An I/O error never authorizes implicit replacement of a key.
#[derive(Debug)]
pub enum IdentityError {
    /// Path permissions, file type or link count is not acceptable.
    UnsafePath,
    /// The fixed record is corrupt, partial, oversized or unsupported.
    Corrupt,
    /// Another cooperating process holds the identity lock.
    Busy,
    /// OS entropy failed; no identity should be considered created.
    Entropy,
    /// The explicit pairing or authenticated session transition was rejected.
    Session(Reject),
    /// Filesystem operation failed. A failed create may have left a directory
    /// or record; reconcile by explicit open, never regenerate automatically.
    Io(io::Error),
}

impl From<io::Error> for IdentityError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<CustodyError> for IdentityError {
    fn from(error: CustodyError) -> Self {
        match error {
            CustodyError::Io(e) => Self::Io(e),
            CustodyError::UnsafePath => Self::UnsafePath,
            CustodyError::Busy => Self::Busy,
            CustodyError::Capacity | CustodyError::Corrupt => Self::Corrupt,
        }
    }
}

/// A privately held application signing key and lifetime exclusive file lock.
/// No seed getter, Clone, Debug, serializer or generic signing oracle is exposed.
///
/// ```compile_fail
/// use vhalla_identity::Identity;
/// fn copy(identity: Identity) { let _ = identity.clone(); }
/// ```
pub struct Identity {
    key: SigningKey,
    _lock: File,
}

impl Identity {
    /// Create a new private directory and key. Existing paths are never reused.
    /// File and directory synchronization precede a success result; uncertain
    /// errors leave owned partial state available for explicit inspection.
    pub fn create_new(path: impl AsRef<Path>) -> Result<Self, IdentityError> {
        let path = path.as_ref();
        let absolute = custody::absolute(path)?;
        let parent = absolute.parent().ok_or(IdentityError::UnsafePath)?;
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| IdentityError::Entropy)?;
        let (directory, _uid) = custody::create_private_directory(&absolute)?;
        let lock = custody::create_private_file(&absolute.join("lock"))?;
        custody::acquire_exclusive(&lock)?;
        lock.sync_all()?;
        let record = encode(&seed);
        let mut pending = custody::create_private_file(&absolute.join("identity.tmp"))?;
        pending.write_all(record.as_ref())?;
        pending.sync_all()?;
        // Publish without replacing an existing name, then sync the directory.
        fs::hard_link(absolute.join("identity.tmp"), absolute.join("identity"))?;
        directory.sync_all()?;
        fs::remove_file(absolute.join("identity.tmp"))?;
        directory.sync_all()?;
        File::open(parent)?.sync_all()?;
        Ok(Self {
            key: SigningKey::from_bytes(&seed),
            _lock: lock,
        })
    }

    /// Open one complete existing identity. Reject interrupted or unexpected
    /// directory entries, symlinks and hardlinks. Never create or repair files.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, IdentityError> {
        let path = path.as_ref();
        let (_, uid) = custody::open_private_directory(path)?;
        let lock = custody::open_private_file(&path.join("lock"), uid, 0)?;
        custody::acquire_exclusive(&lock)?;
        let mut count = 0;
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_name() != "lock" && entry.file_name() != "identity" {
                return Err(IdentityError::Corrupt);
            }
            count += 1;
        }
        if count != 2 {
            return Err(IdentityError::Corrupt);
        }
        let raw = custody::read_private_file(&path.join("identity"), uid, RECORD_BYTES)?;
        let seed = decode(raw.as_ref())?;
        Ok(Self {
            key: SigningKey::from_bytes(&seed),
            _lock: lock,
        })
    }

    /// Full application public key. Routing handles must not replace it in
    /// pairing or membership policy.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// Issue an owner-signed pairing invitation without exporting private key
    /// material. The caller remains responsible for publishing or tracking
    /// the returned token and for enforcing any single-use policy.
    pub fn issue_invitation(
        &self,
        invitee: [u8; 32],
        realm: vhalla_core::RealmId,
        room: vhalla_core::RoomId,
        epoch: vhalla_core::Epoch,
        expires_at: u64,
        nonce: [u8; 32],
    ) -> Result<Invitation, InvitationError> {
        Invitation::issue(&self.key, invitee, realm, room, epoch, expires_at, nonce)
    }

    /// Start an explicitly paired chat handshake with a fresh OS-generated
    /// nonce, without exposing the application signing key.
    pub fn initiate_session(
        &self,
        pairing: Pairing,
        observed_local: [u8; 32],
        observed_remote: [u8; 32],
        now: u64,
        deadline: u64,
    ) -> Result<(Pending, Vec<u8>), IdentityError> {
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| IdentityError::Entropy)?;
        Pending::initiate(
            pairing,
            &self.key,
            observed_local,
            observed_remote,
            nonce,
            now,
            deadline,
        )
        .map_err(IdentityError::Session)
    }

    /// Respond with a fresh OS-generated nonce; even a replayed Hello gets a new
    /// receiver challenge. Transport keys must come from the actual connection.
    pub fn respond_session(
        &self,
        pairing: Pairing,
        observed_local: [u8; 32],
        observed_remote: [u8; 32],
        hello: &[u8],
        now: u64,
        deadline: u64,
    ) -> Result<(Pending, Vec<u8>), IdentityError> {
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| IdentityError::Entropy)?;
        Pending::respond(
            pairing,
            &self.key,
            observed_local,
            observed_remote,
            hello,
            nonce,
            now,
            deadline,
        )
        .map_err(IdentityError::Session)
    }

    /// Confirm a verified peer challenge through the retained signing key.
    pub fn confirm_session(
        &self,
        pending: Pending,
        response: &[u8],
        now: u64,
    ) -> Result<(ChatSession, Vec<u8>), IdentityError> {
        pending
            .confirm(response, &self.key, now)
            .map_err(IdentityError::Session)
    }

    /// Sign a checked social-domain request without exporting the retained key.
    /// This signs content; remote affiliation still requires control admission.
    #[cfg(feature = "social")]
    pub fn sign_social(
        &self,
        request: vhalla_social::UnsignedRecord,
    ) -> Result<vhalla_social::PrimarySignedRecord, vhalla_social::Error> {
        request.sign_with_key(&self.key)
    }

    /// Acknowledge an exact agent genesis or planned controller rotation.
    /// The required second key is fixed by the already signed request.
    #[cfg(feature = "social")]
    pub fn countersign_social(
        &self,
        request: vhalla_social::PrimarySignedRecord,
    ) -> Result<vhalla_social::SignedRecord, vhalla_social::Error> {
        request.countersign(&self.key)
    }

    /// Sign a room-control record without exporting the retained key.
    /// Admission against the agreed room-control chain remains the
    /// directory's decision; this produces signed evidence only.
    #[cfg(feature = "rooms")]
    pub fn sign_room_control(
        &self,
        control: vhalla_rooms::RoomControl,
    ) -> Result<vhalla_rooms::SignedRecord, vhalla_rooms::Error> {
        control.sign_with_key(&self.key)
    }

    /// Sign a room update record without exporting the retained key.
    /// The update's claimed owner, basis and predecessor still face the
    /// directory's admission assessment.
    #[cfg(feature = "rooms")]
    pub fn sign_room_update(
        &self,
        update: vhalla_rooms::RoomUpdate,
    ) -> Result<vhalla_rooms::SignedRecord, vhalla_rooms::Error> {
        update.sign_with_key(&self.key)
    }

    /// Sign an owner permit for one exact creation intent without exporting
    /// the retained key. The returned permit is verified but not yet a
    /// proposal; the creating agent adds its own signature layer.
    #[cfg(feature = "rooms")]
    pub fn sign_room_permit(
        &self,
        intent: vhalla_rooms::CreationIntent,
    ) -> Result<vhalla_rooms::VerifiedOwnerPermit, vhalla_rooms::Error> {
        vhalla_rooms::OwnerPermit::sign_with_key(intent, &self.key)?.verify()
    }

    /// Add the agent proposal layer over an already verified owner permit
    /// without exporting the retained key. The result is the complete signed
    /// room record a directory may assess.
    #[cfg(feature = "rooms")]
    pub fn sign_room_proposal(
        &self,
        permit: vhalla_rooms::VerifiedOwnerPermit,
    ) -> Result<vhalla_rooms::SignedRecord, vhalla_rooms::Error> {
        Ok(permit.propose_with_key(&self.key)?.into_record())
    }

    /// Sign a bounded envelope using retained key custody. The caller supplies
    /// locally admitted context; this method alone grants no remote authority.
    pub fn sign_envelope(
        &self,
        envelope: Envelope,
        context: VerificationContext,
        expires_at: u64,
    ) -> Result<SignedEnvelope, SignError> {
        sign_with_key(
            envelope,
            context.audience,
            context.epoch,
            context.session,
            expires_at,
            &self.key,
        )
    }
}

fn encode(seed: &[u8; 32]) -> Zeroizing<[u8; RECORD_BYTES]> {
    let mut record = Zeroizing::new([0; RECORD_BYTES]);
    record[..8].copy_from_slice(MAGIC);
    record[8..40].copy_from_slice(seed);
    let digest = Sha256::digest(&record[..40]);
    record[40..].copy_from_slice(&digest);
    record
}

fn decode(raw: &[u8]) -> Result<Zeroizing<[u8; 32]>, IdentityError> {
    if raw.len() != RECORD_BYTES || &raw[..8] != MAGIC {
        return Err(IdentityError::Corrupt);
    }
    if Sha256::digest(&raw[..40]).as_slice() != &raw[40..] {
        return Err(IdentityError::Corrupt);
    }
    let mut seed = Zeroizing::new([0; 32]);
    seed.copy_from_slice(&raw[8..40]);
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn seed_roundtrip_and_any_changed_record_bit_is_rejected(seed in any::<[u8;32]>(), offset in 0usize..RECORD_BYTES, bit in 0u8..8) {
            let mut raw = encode(&seed);
            prop_assert_eq!(*decode(raw.as_ref()).unwrap(), seed);
            raw[offset] ^= 1 << bit;
            prop_assert!(decode(raw.as_ref()).is_err());
        }
        #[test]
        fn arbitrary_records_never_panic(raw in prop::collection::vec(any::<u8>(), 0..144)) {
            if let Ok(seed) = decode(&raw) {
                let encoded = encode(&seed);
                prop_assert_eq!(encoded.as_ref(), raw);
            }
        }
    }
}
