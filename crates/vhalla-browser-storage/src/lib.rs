#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Bounded opaque images and an IndexedDB publication boundary.
//!
//! Browser storage success means an IndexedDB transaction completed. It is not a
//! signature, consensus, freshness or physical-durability claim. The Unix native
//! author outbox separately synchronizes exact recovery intents and immutable
//! evidence, with explicit retained-history capacities and no automatic pruning.
//! The domain
//! controller verifies evidence, authorizes replacements and partitions history;
//! these independently replaceable slots do not impose a lifetime history cap.
//! Only the vault slot has a domain-format check: an encrypted envelope's shape,
//! not password authentication. Never store plaintext passwords or private keys.

use std::ops::Range;
use vhalla_browser_vault::{Envelope, ENVELOPE_BYTES};

#[cfg(target_arch = "wasm32")]
pub mod browser;

pub mod history;
pub mod identity;
pub mod outbox;

#[cfg(all(feature = "private-rooms", any(target_arch = "wasm32", test)))]
pub mod private_rooms;

#[cfg(all(feature = "private-rooms", any(target_arch = "wasm32", test)))]
pub mod private_archives;

#[cfg(unix)]
pub mod native;

const MAGIC: &[u8; 8] = b"VHBI\0\0\0\x01";
const HEADER_BYTES: usize = MAGIC.len() + 1 + 2;

/// Maximum encoded bytes in one independently replaced slot image.
pub const MAX_IMAGE_BYTES: usize = 2 * 1024 * 1024;
/// Maximum framed records in one checkpoint or outbox image, not all history.
pub const MAX_IMAGE_RECORDS: usize = 256;
/// Maximum opaque record bytes; the image ceiling also applies.
pub const MAX_RECORD_BYTES: usize = 1024 * 1024;
/// Maximum opens awaiting terminal IndexedDB events, including canceled opens.
pub const MAX_PENDING_OPENS: usize = 4;

/// Locally selected profile namespace. This is isolation, not authentication.
///
/// The trusted adapter selects this value; a URL, incoming peer or UI text must
/// not choose another profile's namespace. Storage does not derive or authorize it.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Namespace([u8; 32]);

impl Namespace {
    /// Bind a host-selected profile identifier to this storage handle.
    #[must_use]
    pub const fn new(identifier: [u8; 32]) -> Self {
        Self(identifier)
    }

    /// Host-selected profile identifier; it carries no authorization evidence.
    #[must_use]
    pub const fn identifier(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Fixed, independent object keys. No arbitrary remote-selected key is accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Slot {
    /// One structurally checked password-encrypted vault envelope.
    Vault,
    /// Opaque signed evidence/checkpoint records; the controller verifies them.
    Checkpoint,
    /// Opaque bounded signed submissions; the controller verifies their meaning.
    Outbox,
}

impl Slot {
    fn tag(self) -> u8 {
        match self {
            Self::Vault => 1,
            Self::Checkpoint => 2,
            Self::Outbox => 3,
        }
    }

    #[cfg(target_arch = "wasm32")]
    fn key(self) -> &'static str {
        match self {
            Self::Vault => "vault",
            Self::Checkpoint => "checkpoint",
            Self::Outbox => "outbox",
        }
    }
}

/// Closed storage failures without persisted contents or profile identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Byte/record/allocation or outstanding-open ceiling exceeded.
    Bounds,
    /// Stored bytes or vault framing are malformed; never replace them implicitly.
    Corrupt,
    /// The supplied image belongs to another fixed slot.
    WrongSlot,
    /// A history record or head belongs to another exact network/bootstrap scope.
    WrongScope,
    /// The exact prior image differs, including present-versus-absent state.
    Stale,
    /// Browser storage was unavailable or an operation failed.
    Storage,
    /// A blocked schema open remains owned until its eventual terminal event.
    Blocked,
    /// Drop this handle, reopen and load before further operations.
    NeedsReopen,
    /// A key without retained local creation provenance needs author recovery.
    RecoveryRequired,
}

/// A publication either was rejected before starting or requires reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublishError {
    /// No transaction was started by this attempt.
    Rejected(Error),
    /// A started operation failed or the handle was invalidated; reopen/load.
    /// This is deliberately conservative even when a stale CAS clearly aborted.
    ReopenRequired(Error),
}

/// An immutable bounded opaque image, not semantically verified evidence.
///
/// The codec enforces only canonical framing, slot membership and resource
/// limits. A checkpoint may contain bad signatures until the domain controller
/// checks it. Keeping that distinction explicit prevents storage from becoming
/// an alternate path around protocol verification.
#[derive(Clone, Eq, PartialEq)]
pub struct Image {
    slot: Slot,
    bytes: Vec<u8>,
    records: Vec<Range<usize>>,
}

impl Image {
    /// Frame bounded opaque records for one slot. Empty checkpoint/outbox images
    /// are representable; only the domain controller may authorize their use.
    pub fn new(slot: Slot, records: &[&[u8]]) -> Result<Self, Error> {
        if records.len() > MAX_IMAGE_RECORDS {
            return Err(Error::Bounds);
        }
        let mut size = HEADER_BYTES;
        for record in records {
            if record.len() > MAX_RECORD_BYTES {
                return Err(Error::Bounds);
            }
            size = size
                .checked_add(4 + record.len())
                .filter(|size| *size <= MAX_IMAGE_BYTES)
                .ok_or(Error::Bounds)?;
        }
        if slot == Slot::Vault {
            if records.len() != 1 || records[0].len() != ENVELOPE_BYTES {
                return Err(Error::Corrupt);
            }
            Envelope::from_bytes(records[0]).map_err(|_| Error::Corrupt)?;
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(size).map_err(|_| Error::Bounds)?;
        bytes.extend_from_slice(MAGIC);
        bytes.push(slot.tag());
        bytes.extend_from_slice(&(records.len() as u16).to_be_bytes());
        for record in records {
            bytes.extend_from_slice(&(record.len() as u32).to_be_bytes());
            bytes.extend_from_slice(record);
        }
        Self::from_bytes(slot, &bytes)
    }

    /// Decode exactly one canonical image, checking bounds before copying bytes.
    /// This does not verify signatures, vault passwords or authority/freshness.
    pub fn from_bytes(slot: Slot, raw: &[u8]) -> Result<Self, Error> {
        if raw.len() > MAX_IMAGE_BYTES {
            return Err(Error::Bounds);
        }
        if raw.len() < HEADER_BYTES || &raw[..MAGIC.len()] != MAGIC {
            return Err(Error::Corrupt);
        }
        if raw[MAGIC.len()] != slot.tag() {
            return Err(Error::WrongSlot);
        }
        let count = u16::from_be_bytes([raw[9], raw[10]]) as usize;
        if count > MAX_IMAGE_RECORDS {
            return Err(Error::Bounds);
        }
        let mut records = Vec::new();
        records
            .try_reserve_exact(count)
            .map_err(|_| Error::Bounds)?;
        let mut at = HEADER_BYTES;
        for _ in 0..count {
            let length_end = at.checked_add(4).ok_or(Error::Bounds)?;
            let length = u32::from_be_bytes(
                raw.get(at..length_end)
                    .ok_or(Error::Corrupt)?
                    .try_into()
                    .map_err(|_| Error::Corrupt)?,
            ) as usize;
            if length > MAX_RECORD_BYTES {
                return Err(Error::Bounds);
            }
            let end = length_end.checked_add(length).ok_or(Error::Bounds)?;
            if end > raw.len() {
                return Err(Error::Corrupt);
            }
            records.push(length_end..end);
            at = end;
        }
        if at != raw.len() {
            return Err(Error::Corrupt);
        }
        if slot == Slot::Vault {
            if records.len() != 1 {
                return Err(Error::Corrupt);
            }
            Envelope::from_bytes(&raw[records[0].clone()]).map_err(|_| Error::Corrupt)?;
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(raw.len())
            .map_err(|_| Error::Bounds)?;
        bytes.extend_from_slice(raw);
        Ok(Self {
            slot,
            bytes,
            records,
        })
    }

    /// Fixed slot this image belongs to.
    #[must_use]
    pub const fn slot(&self) -> Slot {
        self.slot
    }

    /// Exact canonical bytes for comparison or explicitly requested export.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Borrow the opaque records without interpreting their domain semantics.
    pub fn records(&self) -> impl ExactSizeIterator<Item = &[u8]> {
        self.records.iter().map(|range| &self.bytes[range.clone()])
    }
}

// Shared by the real transaction callback and native failure-sequence model.
#[cfg(any(target_arch = "wasm32", unix, test))]
fn compare_exact(expected: Option<&[u8]>, observed: Option<&[u8]>) -> Result<(), Error> {
    if expected == observed {
        Ok(())
    } else {
        Err(Error::Stale)
    }
}

#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Access {
    Ready,
    Publishing,
    NeedsReopen,
}

#[cfg(any(target_arch = "wasm32", test))]
impl Access {
    fn ready(self) -> Result<(), Error> {
        match self {
            Self::Ready => Ok(()),
            Self::Publishing | Self::NeedsReopen => Err(Error::NeedsReopen),
        }
    }

    fn begin(&mut self) -> Result<(), Error> {
        self.ready()?;
        *self = Self::Publishing;
        Ok(())
    }

    fn completed(&mut self) -> Result<(), Error> {
        if *self != Self::Publishing {
            return Err(Error::NeedsReopen);
        }
        *self = Self::Ready;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
