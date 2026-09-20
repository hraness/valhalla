//! Identity-bound encrypted author-state pages, separate from the key envelope.
//!
//! Only the unlocked worker should call these methods. A final page authenticates
//! its bytes, not backup freshness. The storage controller validates complete
//! chains, page continuity and durable publication before enabling authoring.
use crate::{Error, UnlockedIdentity};
use alloc::vec::Vec;
use chacha20poly1305::{AeadInPlace, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"VHBENC01";
const HEADER: usize = 8 + 176 + 32 + 8 + 32 + 1 + 24 + 4;
/// Maximum plaintext page; this is an operation bound, never a lifetime cap.
pub const MAX_AUTHOR_PAGE_BYTES: usize = 128 * 1024;
/// Maximum encrypted page checked before allocation or decryption.
pub const MAX_ENCRYPTED_AUTHOR_PAGE_BYTES: usize = HEADER + MAX_AUTHOR_PAGE_BYTES + 16;

/// A bounded author-state page bound to one full room/key and bootstrap pin.
///
/// `scope` is the canonical network/realm/directory/room/author (144 bytes), then
/// bootstrap pin (32 bytes). Storage supplies and verifies this exact context.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthorBackupPage {
    scope: [u8; 176],
    backup: [u8; 32],
    index: u64,
    previous: [u8; 32],
    final_page: bool,
    payload: Vec<u8>,
}
impl AuthorBackupPage {
    /// Construct one bounded typed page; domain validation belongs to storage.
    pub fn new(
        scope: [u8; 176],
        backup: [u8; 32],
        index: u64,
        previous: [u8; 32],
        final_page: bool,
        payload: &[u8],
    ) -> Result<Self, Error> {
        if payload.len() > MAX_AUTHOR_PAGE_BYTES || (index == 0 && previous != [0; 32]) {
            return Err(Error::Malformed);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(payload.len())
            .map_err(|_| Error::Resource)?;
        bytes.extend_from_slice(payload);
        Ok(Self {
            scope,
            backup,
            index,
            previous,
            final_page,
            payload: bytes,
        })
    }
    /// Full author scope plus independently selected bootstrap pin.
    pub const fn scope(&self) -> &[u8; 176] {
        &self.scope
    }
    /// Caller-generated fresh CSPRNG backup identifier.
    pub const fn backup_id(&self) -> [u8; 32] {
        self.backup
    }
    /// Exact zero-based page number, without JavaScript number conversion.
    pub const fn index(&self) -> u64 {
        self.index
    }
    /// Digest of the preceding complete canonical plaintext page.
    pub const fn previous(&self) -> [u8; 32] {
        self.previous
    }
    /// Only a complete, rechecked export may issue its final page.
    pub const fn is_final(&self) -> bool {
        self.final_page
    }
    /// Bounded canonical storage payload, never a plaintext key.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    /// Stable chain identifier independent of the encryption nonce.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }
    /// Canonical bounded worker message, containing public signed state only.
    pub fn encode(&self) -> Vec<u8> {
        let mut raw = Vec::with_capacity(8 + 176 + 32 + 8 + 32 + 1 + 4 + self.payload.len());
        raw.extend_from_slice(b"VHBPAG01");
        raw.extend_from_slice(&self.scope);
        raw.extend_from_slice(&self.backup);
        raw.extend_from_slice(&self.index.to_be_bytes());
        raw.extend_from_slice(&self.previous);
        raw.push(u8::from(self.final_page));
        raw.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        raw.extend_from_slice(&self.payload);
        raw
    }
    /// Decode exact canonical page framing before dispatch to the worker.
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        const PREFIX: usize = 8 + 176 + 32 + 8 + 32 + 1 + 4;
        if raw.len() < PREFIX
            || raw.len() > PREFIX + MAX_AUTHOR_PAGE_BYTES
            || &raw[..8] != b"VHBPAG01"
            || raw[256] > 1
        {
            return Err(Error::Malformed);
        }
        let length =
            u32::from_be_bytes(raw[257..261].try_into().map_err(|_| Error::Malformed)?) as usize;
        if length > MAX_AUTHOR_PAGE_BYTES || raw.len() != PREFIX + length {
            return Err(Error::Malformed);
        }
        Self::new(
            raw[8..184].try_into().map_err(|_| Error::Malformed)?,
            raw[184..216].try_into().map_err(|_| Error::Malformed)?,
            u64::from_be_bytes(raw[216..224].try_into().map_err(|_| Error::Malformed)?),
            raw[224..256].try_into().map_err(|_| Error::Malformed)?,
            raw[256] == 1,
            &raw[PREFIX..],
        )
    }
}

impl UnlockedIdentity {
    fn author_backup_key(
        &self,
        scope: &[u8; 176],
        backup: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>, Error> {
        if scope[112..144] != self.public_key() {
            return Err(Error::Authentication);
        }
        let seed = Zeroizing::new(self.key.to_bytes());
        let hkdf = Hkdf::<Sha256>::new(Some(backup), &seed[..]);
        let mut key = Zeroizing::new([0; 32]);
        hkdf.expand_multi_info(&[b"vhalla/author-state/backup/key/v1", scope], &mut key[..])
            .map_err(|_| Error::Resource)?;
        Ok(key)
    }
    /// Encrypt one author-state page with fresh caller-supplied CSPRNG nonce.
    /// This key is domain-separated from Ed25519 signing and password storage.
    pub fn encrypt_author_page(
        &self,
        page: &AuthorBackupPage,
        nonce: [u8; 24],
    ) -> Result<Vec<u8>, Error> {
        let key = self.author_backup_key(&page.scope, &page.backup)?;
        let mut raw = Vec::with_capacity(HEADER + page.payload.len() + 16);
        raw.extend_from_slice(MAGIC);
        raw.extend_from_slice(&page.scope);
        raw.extend_from_slice(&page.backup);
        raw.extend_from_slice(&page.index.to_be_bytes());
        raw.extend_from_slice(&page.previous);
        raw.push(u8::from(page.final_page));
        raw.extend_from_slice(&nonce);
        raw.extend_from_slice(&(page.payload.len() as u32).to_be_bytes());
        raw.extend_from_slice(&page.payload);
        let (aad, payload) = raw.split_at_mut(HEADER);
        let tag = XChaCha20Poly1305::new((&*key).into())
            .encrypt_in_place_detached(XNonce::from_slice(&nonce), aad, payload)
            .map_err(|_| Error::Resource)?;
        raw.extend_from_slice(&tag);
        Ok(raw)
    }
    /// Authenticate and decrypt one bounded identity-bound author-state page.
    /// Its stream order, completeness and retained-state CAS still need checking.
    pub fn decrypt_author_page(&self, raw: &[u8]) -> Result<AuthorBackupPage, Error> {
        if raw.len() < HEADER + 16
            || raw.len() > MAX_ENCRYPTED_AUTHOR_PAGE_BYTES
            || &raw[..8] != MAGIC
            || raw[256] > 1
        {
            return Err(Error::Malformed);
        }
        let length =
            u32::from_be_bytes(raw[281..285].try_into().map_err(|_| Error::Malformed)?) as usize;
        if length > MAX_AUTHOR_PAGE_BYTES || raw.len() != HEADER + length + 16 {
            return Err(Error::Malformed);
        }
        let scope = raw[8..184].try_into().map_err(|_| Error::Malformed)?;
        let backup = raw[184..216].try_into().map_err(|_| Error::Malformed)?;
        let key = self.author_backup_key(&scope, &backup)?;
        let mut payload = Zeroizing::new(raw[HEADER..HEADER + length].to_vec());
        XChaCha20Poly1305::new((&*key).into())
            .decrypt_in_place_detached(
                XNonce::from_slice(&raw[257..281]),
                &raw[..HEADER],
                &mut payload,
                Tag::from_slice(&raw[HEADER + length..]),
            )
            .map_err(|_| Error::Authentication)?;
        AuthorBackupPage::new(
            scope,
            backup,
            u64::from_be_bytes(raw[216..224].try_into().map_err(|_| Error::Malformed)?),
            raw[224..256].try_into().map_err(|_| Error::Malformed)?,
            raw[256] == 1,
            &payload,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    #[test]
    fn pages_bind_identity_scope_sequence_nonce_and_exact_ciphertext() {
        let identity = UnlockedIdentity {
            key: SigningKey::from_bytes(&[7; 32]),
        };
        let mut scope = [2; 176];
        scope[112..144].copy_from_slice(&identity.public_key());
        let page = AuthorBackupPage::new(
            scope,
            [3; 32],
            0,
            [0; 32],
            false,
            b"bounded signed author state",
        )
        .unwrap();
        let first = identity.encrypt_author_page(&page, [4; 24]).unwrap();
        let frozen = include_str!("../vectors/author-page-v1.hex").trim();
        let frozen: Vec<u8> = frozen
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(first, frozen);
        assert!(identity.decrypt_author_page(&first).unwrap() == page);
        assert!(AuthorBackupPage::decode(&page.encode()).unwrap() == page);
        assert_ne!(first, identity.encrypt_author_page(&page, [5; 24]).unwrap());
        for index in [0, 8, 184, 216, 224, 256, 257, 281, HEADER, first.len() - 1] {
            let mut corrupt = first.clone();
            corrupt[index] ^= 1;
            assert!(identity.decrypt_author_page(&corrupt).is_err());
        }
        for size in 0..first.len() {
            assert!(identity.decrypt_author_page(&first[..size]).is_err());
        }
        let mut extra = first.clone();
        extra.push(0);
        assert!(identity.decrypt_author_page(&extra).is_err());
        let other = UnlockedIdentity {
            key: SigningKey::from_bytes(&[8; 32]),
        };
        assert!(other.decrypt_author_page(&first).is_err());
        let mut encoded = page.encode();
        encoded.push(0);
        assert!(AuthorBackupPage::decode(&encoded).is_err());
        let mut encoded = page.encode();
        encoded[257..261].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(AuthorBackupPage::decode(&encoded).is_err());
        let mut oversized = first;
        oversized[281..285].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(identity.decrypt_author_page(&oversized).is_err());
    }
}
