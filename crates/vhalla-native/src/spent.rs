//! Durable bounded single-use tracking for invitation nonces.
//!
//! `vhalla_session::SpentInvitationNonces` is deliberately in-memory; this
//! file-backed variant persists consumed nonces so an invitation cannot be
//! redeemed twice by one local identity across process restarts. The nonce
//! never reaches the wire, so single-use is necessarily a local
//! authorization boundary: the caller consumes at redemption, before
//! dialing. Each consume atomically republishes the whole bounded set —
//! `VSN1` followed by strictly ascending 32-byte nonces — through a
//! temporary sibling, a file sync, a rename and a directory sync.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 4] = b"VSN1";
/// Hard bound on distinct consumed nonces: 1024 ids = 32,772-byte file.
pub const SPENT_CAPACITY: usize = 1024;

/// Failure opening or consuming through a durable spent-nonce file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpentError {
    /// Filesystem operation failed.
    Io,
    /// The file is not a canonical spent set.
    Malformed,
    /// This nonce was consumed previously.
    AlreadySpent,
    /// The file already holds `SPENT_CAPACITY` distinct nonces.
    Capacity,
}

/// A durable bounded set of redeemed invitation nonces.
///
/// Missing files open empty; the file is created on the first consume.
/// Consumption is atomic within the process and durable across crashes:
/// the replacement file is fully synced before it is renamed over the old.
pub struct SpentFile {
    path: PathBuf,
    spent: BTreeSet<[u8; 32]>,
}

impl SpentFile {
    /// Open a spent set, decoding an existing file strictly or starting
    /// empty. Foreign entries, symlinks and noncanonical layouts fail closed.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SpentError> {
        let path = path.as_ref().to_path_buf();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            return Ok(Self {
                path,
                spent: BTreeSet::new(),
            });
        };
        if !meta.file_type().is_file() || meta.len() > (4 + 32 * SPENT_CAPACITY) as u64 {
            return Err(SpentError::Malformed);
        }
        let raw = fs::read(&path).map_err(|_| SpentError::Io)?;
        if raw.len() < 4 || raw.len() % 32 != 4 || &raw[..4] != MAGIC {
            return Err(SpentError::Malformed);
        }
        let mut spent = BTreeSet::new();
        for chunk in raw[4..].chunks_exact(32) {
            let nonce: [u8; 32] = chunk.try_into().map_err(|_| SpentError::Malformed)?;
            if nonce == [0; 32] || !spent.insert(nonce) {
                // Reserved zero value or a duplicate entry is noncanonical.
                return Err(SpentError::Malformed);
            }
        }
        if raw[4..]
            .chunks_exact(32)
            .zip(raw[4..].chunks_exact(32).skip(1))
            .any(|(a, b)| a >= b)
        {
            return Err(SpentError::Malformed);
        }
        Ok(Self { path, spent })
    }

    /// The persisted set's hard admission bound.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        SPENT_CAPACITY
    }

    /// Distinct nonces currently recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.spent.len()
    }

    /// Whether no nonce has been consumed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.spent.is_empty()
    }

    /// Whether a nonce is already recorded spent.
    #[must_use]
    pub fn contains(&self, nonce: &[u8; 32]) -> bool {
        self.spent.contains(nonce)
    }

    /// Atomically record one nonce and republish the set durably.
    ///
    /// Duplicate, reserved and capacity-overflow nonces are rejected before
    /// any write; a consumed nonce is never evicted to admit a new one.
    pub fn consume(&mut self, nonce: [u8; 32]) -> Result<(), SpentError> {
        if nonce == [0; 32] {
            return Err(SpentError::Malformed);
        }
        if self.spent.contains(&nonce) {
            return Err(SpentError::AlreadySpent);
        }
        if self.spent.len() >= SPENT_CAPACITY {
            return Err(SpentError::Capacity);
        }
        self.spent.insert(nonce);
        self.publish()
    }

    fn publish(&self) -> Result<(), SpentError> {
        let mut raw = Vec::with_capacity(4 + 32 * self.spent.len());
        raw.extend_from_slice(MAGIC);
        for nonce in &self.spent {
            raw.extend_from_slice(nonce);
        }
        let tmp = self.path.with_extension("spent.tmp");
        {
            let mut file = File::create(&tmp).map_err(|_| SpentError::Io)?;
            file.write_all(&raw).map_err(|_| SpentError::Io)?;
            file.sync_all().map_err(|_| SpentError::Io)?;
        }
        fs::rename(&tmp, &self.path).map_err(|_| SpentError::Io)?;
        if let Some(parent) = self.path.parent() {
            File::open(parent)
                .and_then(|d| d.sync_all())
                .map_err(|_| SpentError::Io)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn dir() -> PathBuf {
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "spent-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn consumed_nonces_survive_reopen_and_never_repeat() {
        let dir = dir();
        let path = dir.join("identity.spent");
        let mut file = SpentFile::open(&path).unwrap();
        assert!(!file.contains(&[7; 32]));
        file.consume([7; 32]).unwrap();
        file.consume([9; 32]).unwrap();
        assert_eq!(file.len(), 2);
        drop(file);

        // A fresh process view sees the durable set.
        let mut file = SpentFile::open(&path).unwrap();
        assert!(file.contains(&[7; 32]) && file.contains(&[9; 32]));
        assert_eq!(file.consume([7; 32]), Err(SpentError::AlreadySpent));
        file.consume([5; 32]).unwrap();
        assert_eq!(file.len(), 3);
        assert_eq!(file.consume([0; 32]), Err(SpentError::Malformed));
    }

    #[test]
    fn malformed_and_capacity_fail_closed_without_mutation() {
        let dir = dir();
        let path = dir.join("identity.spent");
        std::fs::write(&path, b"not a spent set").unwrap();
        assert_eq!(
            SpentFile::open(&path).map(|_| ()),
            Err(SpentError::Malformed)
        );
        // Unsorted entries are noncanonical.
        let mut raw = b"VSN1".to_vec();
        raw.extend_from_slice(&[9; 32]);
        raw.extend_from_slice(&[7; 32]);
        std::fs::write(&path, &raw).unwrap();
        assert_eq!(
            SpentFile::open(&path).map(|_| ()),
            Err(SpentError::Malformed)
        );
        // Capacity fails closed and preserves existing entries.
        let mut raw = b"VSN1".to_vec();
        for i in 0..SPENT_CAPACITY {
            let mut nonce = [0u8; 32];
            nonce[..16].copy_from_slice(&(i as u128 + 1).to_be_bytes());
            raw.extend_from_slice(&nonce);
        }
        std::fs::write(&path, &raw).unwrap();
        let mut file = SpentFile::open(&path).unwrap();
        assert_eq!(file.consume([250; 32]), Err(SpentError::Capacity));
        assert_eq!(file.len(), SPENT_CAPACITY);
        assert!(file.contains(&[9; 32]) == false);
    }
}
