use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::Path,
};
use vhalla_crypto::{sign_with_key, SignError, SignedEnvelope, VerificationContext};
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
        // Resolve a relative directory before opening its parent for sync.
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        let parent = absolute.parent().ok_or(IdentityError::UnsafePath)?;
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| IdentityError::Entropy)?;
        DirBuilder::new().mode(0o700).create(&absolute)?;
        let directory = File::open(&absolute)?;
        let lock = create_file(&absolute.join("lock"))?;
        acquire_lock(&lock)?;
        lock.sync_all()?;
        let record = encode(&seed);
        let mut pending = create_file(&absolute.join("identity.tmp"))?;
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
        check_directory(path)?;
        check_file(&path.join("lock"), 0)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path.join("lock"))?;
        check_open_file(&lock, 0)?;
        acquire_lock(&lock)?;
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
        check_file(&path.join("identity"), RECORD_BYTES as u64)?;
        let mut file = File::open(path.join("identity"))?;
        check_open_file(&file, RECORD_BYTES as u64)?;
        let mut raw = Zeroizing::new([0; RECORD_BYTES]);
        file.read_exact(raw.as_mut())?;
        let mut extra = [0; 1];
        if file.read(&mut extra)? != 0 {
            return Err(IdentityError::Corrupt);
        }
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

fn create_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

fn acquire_lock(lock: &File) -> Result<(), IdentityError> {
    match lock.try_lock() {
        Ok(()) => Ok(()),
        Err(fs::TryLockError::WouldBlock) => Err(IdentityError::Busy),
        Err(fs::TryLockError::Error(error)) => Err(IdentityError::Io(error)),
    }
}

fn check_directory(path: &Path) -> Result<(), IdentityError> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir() || meta.mode() & 0o7777 != 0o700 {
        return Err(IdentityError::UnsafePath);
    }
    Ok(())
}

fn check_metadata(meta: fs::Metadata, len: u64) -> Result<(), IdentityError> {
    if !meta.is_file() || meta.mode() & 0o7777 != 0o600 || meta.nlink() != 1 {
        return Err(IdentityError::UnsafePath);
    }
    if meta.len() != len {
        return Err(IdentityError::Corrupt);
    }
    Ok(())
}
fn check_file(path: &Path, len: u64) -> Result<(), IdentityError> {
    check_metadata(fs::symlink_metadata(path)?, len)
}
fn check_open_file(file: &File, len: u64) -> Result<(), IdentityError> {
    check_metadata(file.metadata()?, len)
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
