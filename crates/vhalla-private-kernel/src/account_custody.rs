//! One typed, versioned derivation shared by native and browser custodians.
//! This creates no room, device, storage, recovery state or signing authority.

use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{Context, Error, Result, StorageKey};

// Frozen custody contract. Labels include their terminal NUL. Context::encode
// is exactly room32 || anchor32 || account32 || device32, without mutable state.
const SALT: &[u8] = b"vhalla/private-room/storage/extract/v1\0";
const INFO: &[u8] = b"vhalla/private-room/storage/key/v1\0";

impl StorageKey {
    /// Derive opaque storage custody for this account's exact private context.
    ///
    /// HKDF-SHA256 uses the account's secret Ed25519 seed, the fixed salt
    /// `vhalla/private-room/storage/extract/v1\0`, and expansion info
    /// `vhalla/private-room/storage/key/v1\0` followed by the full 128-byte
    /// room/anchor/account/device encoding, producing exactly 32 bytes. No
    /// password, path, origin, public network, epoch or roster enters the KDF.
    /// The account must match before derivation; there is no public-key fallback.
    ///
    /// Only the existing trusted account custodian should call this. The result
    /// exposes no secret bytes, but enables decryption of the selected retained
    /// store. Account compromise affects every derived context. Password changes
    /// keep custody; account-key changes do not. A key-only backup cannot restore
    /// missing ratchets, authorize reset, detect rollback or prevent live clones.
    ///
    /// A live kernel keeps its own storage-key copy. Lock must end both account
    /// and kernel custody; dropping the account object alone is insufficient.
    /// Seed/output buffers are zeroizing; this does not promise erasure of every
    /// internal HKDF allocation or upstream secret copy.
    pub fn derive_for_account(account: &SigningKey, context: Context) -> Result<Self> {
        if account.verifying_key().as_bytes() != context.account.as_bytes() {
            return Err(Error::Scope);
        }
        let seed = Zeroizing::new(account.to_bytes());
        let hkdf = Hkdf::<Sha256>::new(Some(SALT), seed.as_ref());
        let mut secret = Zeroizing::new([0; 32]);
        hkdf.expand_multi_info(&[INFO, &context.encode()], secret.as_mut())
            .map_err(|_| Error::Bounds)?;
        if *secret == [0; 32] {
            return Err(Error::Authentication);
        }
        Ok(Self(secret))
    }
}

#[cfg(test)]
mod tests;
