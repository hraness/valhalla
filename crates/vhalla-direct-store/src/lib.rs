//! Local atomic state and immutable records for direct public rooms.
//!
//! This store treats all state and payloads as opaque bytes. It verifies local
//! file ownership, storage checksums and transaction boundaries, not signatures,
//! room authority or network history. Pages cover a local contiguous cursor
//! range; they make no claim that all remote records have arrived.
//!
//! One cooperating writer holds an exclusive lifetime lock. Explicit reopen
//! recovers SQLite transactions; ordinary reads never repair. Checksums detect
//! inconsistent damage, not coherent edits by the file owner, restored copies
//! of older valid state, or hardware that reports an undurable sync as complete.

#![forbid(unsafe_code)]

mod backend;
mod format;

pub use backend::Store;

/// Maximum opaque state size in bytes.
pub const MAX_STATE_BYTES: usize = 4 * 1024 * 1024;
/// Maximum immutable record payload size in bytes.
pub const MAX_RECORD_BYTES: usize = 16 * 1024;
/// Maximum input records in one publication, including exact duplicates.
pub const MAX_TRANSACTION_RECORDS: usize = 8;
/// Maximum records returned by one local page.
pub const MAX_PAGE_RECORDS: usize = 32;

const JOURNAL_ALLOWANCE: usize = 32 * 1024 * 1024;

/// Storage outcome. No error permits deleting evidence or initializing again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The expected state or an immutable record's bytes did not match.
    Conflict,
    /// Input, capacity or the exclusive store lock refused the operation.
    Refused,
    /// Effects may have committed. Drop this handle and reopen the same store.
    Uncertain,
    /// Required state is missing, damaged, unsafe or from another format.
    Corrupt,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}

/// Result returned by the direct room store.
pub type Result<T> = std::result::Result<T, Error>;

/// Exact local room and account namespace. This is not proof of authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Context([u8; 64]);

impl Context {
    /// Require full nonzero room and account identifiers, in that order.
    pub fn new(room: [u8; 32], account: [u8; 32]) -> Result<Self> {
        if room == [0; 32] || account == [0; 32] {
            return Err(Error::Refused);
        }
        let mut bytes = [0; 64];
        bytes[..32].copy_from_slice(&room);
        bytes[32..].copy_from_slice(&account);
        Ok(Self(bytes))
    }

    /// Borrow the complete canonical room and account identifiers.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// Retained-data limits. They may grow in place, but never shrink or prune records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum distinct retained records, from 1 through 1,000,000.
    pub max_records: u64,
    /// Maximum retained payload bytes, from 1 through 8 GiB, excluding SQLite overhead.
    pub max_record_bytes: u64,
}

impl Limits {
    fn check(self) -> Result<()> {
        if !(1..=1_000_000).contains(&self.max_records)
            || !(1..=8 * 1024 * 1024 * 1024).contains(&self.max_record_bytes)
            || usize::try_from(self.database_bound() + JOURNAL_ALLOWANCE as u64).is_err()
        {
            return Err(Error::Refused);
        }
        Ok(())
    }

    fn database_bound(self) -> u64 {
        // Conservative payload, index, free-page and state-image overhead.
        2 * self.max_record_bytes + self.max_records * 512 + 64 * 1024 * 1024
    }

    fn database_bytes(self) -> usize {
        self.database_bound() as usize
    }

    // Reopen must recover SQLite before knowing whether old or expanded limits
    // committed. Bound that bootstrap by the format and the local address size.
    fn absolute_database_bytes() -> usize {
        Self {
            max_records: 1_000_000,
            max_record_bytes: 8 * 1024 * 1024 * 1024,
        }
        .database_bound()
        .min(usize::MAX.saturating_sub(JOURNAL_ALLOWANCE) as u64) as usize
    }
}

/// One immutable opaque payload under a nonzero type byte and full identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    key: [u8; 33],
    data: Vec<u8>,
}

impl Record {
    /// Validate the key and nonempty payload of at most 16 KiB before copying.
    pub fn new(key: [u8; 33], data: &[u8]) -> Result<Self> {
        check_key(&key)?;
        bounds(data, MAX_RECORD_BYTES)?;
        Ok(Self {
            key,
            data: data.to_vec(),
        })
    }

    /// Exact immutable local key.
    pub fn key(&self) -> [u8; 33] {
        self.key
    }

    /// Borrow the retained opaque payload.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

/// One retained record at its immutable local cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry {
    /// Nonzero contiguous position assigned when this distinct key was first retained.
    pub cursor: u64,
    /// Exact immutable key.
    pub key: [u8; 33],
    /// Complete opaque payload, at most [`MAX_RECORD_BYTES`].
    pub data: Vec<u8>,
}

/// A verified contiguous range within one observed local tip.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Page {
    /// Total local records observed for this call; never a remote completeness claim.
    pub tip: u64,
    /// Exact records following the requested cursor, in increasing order.
    pub records: Vec<Entry>,
    /// Last returned cursor when more records remain within this call's tip.
    pub next: Option<u64>,
}

/// Current local generation, retained usage and configured limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Accounting {
    /// Number of successful state publications; limit expansion does not advance it.
    pub generation: u64,
    /// Highest retained local cursor; zero before the first distinct record.
    pub tip: u64,
    /// Number of distinct immutable keys retained locally.
    pub records: u64,
    /// Sum of retained distinct record payload lengths.
    pub bytes: u64,
    /// Current operator-selected retained-data limits, which may grow in place.
    pub limits: Limits,
}

fn bounds(raw: &[u8], max: usize) -> Result<()> {
    if raw.is_empty() || raw.len() > max {
        Err(Error::Refused)
    } else {
        Ok(())
    }
}

fn check_key(key: &[u8; 33]) -> Result<()> {
    if key[0] == 0 || key[1..] == [0; 32] {
        Err(Error::Refused)
    } else {
        Ok(())
    }
}
