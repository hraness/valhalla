//! Prospective immutable publication. The one scratch name never grants a pin.

use super::*;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

const SCRATCH: &str = ".bundle.tmp";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BundleWriteStep {
    Created,
    Partial,
    Written,
    Synced,
    Published,
    Removed,
}

/// Called under the journal's cooperating-writer lock, after frontier checks.
/// The caller still syncs the final file and containing directory before HEAD.
pub(super) fn create_bundle(
    dir: &Path,
    id: [u8; 32],
    bytes: &[u8],
    mut step: impl FnMut(BundleWriteStep) -> Result<(), JournalError>,
) -> Result<bool, JournalError> {
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err(JournalError::Oversized);
    }
    let destination = FsStore::bundle_path(dir, id);
    match fs::symlink_metadata(&destination) {
        // Never modify an existing final name, even if its bytes are corrupt.
        // Journal::commit checks exact equality and resyncs successful retries.
        Ok(_) => return Ok(false),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }

    let parent = dir.join(BUNDLES);
    let scratch = parent.join(SCRATCH);
    match fs::symlink_metadata(&scratch) {
        Ok(metadata) => {
            // A crash may leave this inode linked to a published final bundle.
            // Unlink only the reserved scratch name; NEVER open with truncate.
            // Unknown path kinds, ownership, permissions or link counts remain
            // intact. Same-owner hostile disk mutation is not this lock's model.
            if !metadata.is_file()
                || metadata.len() > MAX_BUNDLE_BYTES as u64
                || metadata.mode() & 0o777 != 0o600
                || metadata.uid() != fs::metadata(&parent)?.uid()
                || !(1..=2).contains(&metadata.nlink())
            {
                return Err(JournalError::Corrupt);
            }
            fs::remove_file(&scratch)?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&scratch)?;
    step(BundleWriteStep::Created)?;
    let split = bytes.len() / 2;
    file.write_all(&bytes[..split])?;
    step(BundleWriteStep::Partial)?;
    file.write_all(&bytes[split..])?;
    step(BundleWriteStep::Written)?;
    file.sync_all()?;
    step(BundleWriteStep::Synced)?;
    let created = match fs::hard_link(&scratch, &destination) {
        Ok(()) => true,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => false,
        Err(e) => return Err(e.into()),
    };
    step(BundleWriteStep::Published)?;
    fs::remove_file(&scratch)?;
    step(BundleWriteStep::Removed)?;
    Ok(created)
}

#[cfg(test)]
mod tests;
