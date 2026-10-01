//! Local retained usage without opening another writer or returning raw state.

use super::*;
use crate::storage::{ArchiveStore, StorageUsage};

impl<S: ArchiveStore> Kernel<S> {
    /// Read bounded local counters and immutable limits under existing custody.
    /// The backend's atomic image must equal this session's authenticated image.
    /// A failed or canceled read requires exact-store reopen; no current image,
    /// keys, MLS state, signer, or archive activation authority is returned.
    pub async fn storage_accounting(&mut self) -> Result<StorageUsage> {
        if self.needs_reopen {
            return Err(Error::NeedsReopen);
        }
        self.needs_reopen = true;
        let value = self
            .store
            .accounting(self.context)
            .await
            .map_err(store_error)?;
        if value.image.as_ref() != Some(&self.image)
            || value.records > value.max_records
            || value.bytes > value.max_bytes
        {
            return Err(Error::Conflict);
        }
        self.needs_reopen = false;
        Ok(StorageUsage {
            records: value.records,
            bytes: value.bytes,
            max_records: value.max_records,
            max_bytes: value.max_bytes,
        })
    }
}
