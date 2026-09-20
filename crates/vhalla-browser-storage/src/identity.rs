//! Local key-creation provenance, distinct from key possession or recovery.
//!
//! A birth record is local metadata under the trusted application's control. It
//! is not signed, an anti-rollback primitive, or evidence that an exported key
//! has never signed on another device. Only the genuine new-key creation path
//! may publish it, atomically with that key's encrypted vault.

use crate::{Error, Image, Slot};
use vhalla_browser_vault::Envelope;

#[cfg(any(target_arch = "wasm32", test))]
const BIRTH_MAGIC: &[u8; 8] = b"VHBBTH01";
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const BIRTH_BYTES: usize = 40;
#[cfg(target_arch = "wasm32")]
pub(crate) const BIRTH_KEY: &str = "identity/v1/local-birth";

/// Local creation metadata bound to one exact application public key.
///
/// This is available only through a coherent stored identity snapshot. Its
/// presence is insufficient without authenticating the vault, preserving local
/// author floors, and honoring the application's single-author-device contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalCreation([u8; 32]);

impl LocalCreation {
    /// The public key created by this profile's original new-identity path.
    #[must_use]
    pub const fn public_key(self) -> [u8; 32] {
        self.0
    }

    #[cfg(any(target_arch = "wasm32", test))]
    fn encode(self) -> [u8; BIRTH_BYTES] {
        let mut raw = [0; BIRTH_BYTES];
        raw[..8].copy_from_slice(BIRTH_MAGIC);
        raw[8..].copy_from_slice(&self.0);
        raw
    }

    #[cfg(any(target_arch = "wasm32", test))]
    fn decode(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() != BIRTH_BYTES || &raw[..8] != BIRTH_MAGIC {
            return Err(Error::Corrupt);
        }
        Ok(Self(raw[8..].try_into().map_err(|_| Error::Corrupt)?))
    }
}

/// An exact vault and provenance pair read in a single storage transaction.
///
/// An existing vault without local creation metadata is valid imported/legacy
/// state, but cannot authorize a fresh author sequence. A birth record without
/// its matching vault is corrupt and never becomes an empty profile.
#[derive(Clone, Eq, PartialEq)]
pub struct IdentitySnapshot {
    vault: Option<Image>,
    birth: Option<LocalCreation>,
}

impl IdentitySnapshot {
    /// Explicit absent pair, useful only as an exact creation/import expectation.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            vault: None,
            birth: None,
        }
    }

    /// Structurally checked encrypted vault, not password-authenticated here.
    #[must_use]
    pub const fn vault(&self) -> Option<&Image> {
        self.vault.as_ref()
    }

    /// Obtain matching local metadata for an independently authenticated key.
    ///
    /// A restored key or absent provenance fails rather than inferring that the
    /// key has never signed. Fresh-scope initialization must recheck this exact
    /// snapshot inside the same transaction that creates the author floor.
    pub fn local_creation(&self, authenticated_public: [u8; 32]) -> Result<LocalCreation, Error> {
        let public = self.vault.as_ref().map(vault_public).transpose()?;
        if public != Some(authenticated_public) {
            return Err(Error::WrongScope);
        }
        let birth = self.birth.ok_or(Error::RecoveryRequired)?;
        if birth.public_key() != authenticated_public {
            return Err(Error::Corrupt);
        }
        Ok(birth)
    }

    #[cfg(any(target_arch = "wasm32", test))]
    pub(crate) fn decode(vault: Option<&[u8]>, birth: Option<&[u8]>) -> Result<Self, Error> {
        let vault = vault
            .map(|raw| Image::from_bytes(Slot::Vault, raw))
            .transpose()?;
        let birth = birth.map(LocalCreation::decode).transpose()?;
        if let Some(birth) = birth {
            if vault.as_ref().map(vault_public).transpose()? != Some(birth.public_key()) {
                return Err(Error::Corrupt);
            }
        }
        Ok(Self { vault, birth })
    }

    #[cfg(any(target_arch = "wasm32", test))]
    pub(crate) fn birth_bytes(&self) -> Option<[u8; BIRTH_BYTES]> {
        self.birth.map(LocalCreation::encode)
    }
}

pub(crate) fn vault_public(vault: &Image) -> Result<[u8; 32], Error> {
    if vault.slot() != Slot::Vault {
        return Err(Error::WrongSlot);
    }
    let raw = vault.records().next().ok_or(Error::Corrupt)?;
    Ok(Envelope::from_bytes(raw)
        .map_err(|_| Error::Corrupt)?
        .claimed_public_key())
}

// These preparation functions are private to the actual storage transaction
// and the native event model; callers cannot fabricate a successful receipt.
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) fn created(next: &Image) -> Result<IdentitySnapshot, Error> {
    let public = vault_public(next)?;
    Ok(IdentitySnapshot {
        vault: Some(next.clone()),
        birth: Some(LocalCreation(public)),
    })
}

#[cfg(any(target_arch = "wasm32", test))]
pub(crate) fn replaced(
    expected: &IdentitySnapshot,
    next: &Image,
) -> Result<IdentitySnapshot, Error> {
    let public = vault_public(next)?;
    if let Some(previous) = expected.vault() {
        if vault_public(previous)? != public {
            return Err(Error::WrongScope);
        }
    }
    Ok(IdentitySnapshot {
        vault: Some(next.clone()),
        birth: expected.birth,
    })
}

#[cfg(any(target_arch = "wasm32", test))]
pub(crate) fn compare_identity(
    expected: &IdentitySnapshot,
    observed: &IdentitySnapshot,
) -> Result<(), Error> {
    if expected == observed {
        Ok(())
    } else {
        Err(Error::Stale)
    }
}

#[cfg(any(target_arch = "wasm32", test))]
pub(crate) fn fresh_author_check(
    expected: &IdentitySnapshot,
    observed: &IdentitySnapshot,
    author: [u8; 32],
    occupied: bool,
) -> Result<(), Error> {
    compare_identity(expected, observed)?;
    observed.local_creation(author)?;
    if occupied {
        Err(Error::Stale)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
