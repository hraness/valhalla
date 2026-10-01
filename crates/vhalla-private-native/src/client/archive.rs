//! Shared account custody for inert archive export, import and inspection.

use super::{AccountController, Result};
use crate::archive::{ArchiveExporter, ArchiveInput, ArchiveSession};
use std::{path::Path, sync::Arc};
use vhalla_private_kernel::Context;

impl AccountController {
    /// Open an existing authenticated room for encrypted archive export.
    ///
    /// The source store remains exclusively locked until this exporter drops or
    /// locks. Stop the selected room's operations first; an existing room writer
    /// is refused, never interrupted. Other account rooms remain independent.
    /// Interrupted export needs a new stream and output file, not a guessed cursor.
    pub async fn open_archive_export(
        &self,
        path: impl AsRef<Path>,
        context: Context,
    ) -> Result<ArchiveExporter> {
        ArchiveExporter::open_shared(Arc::clone(&self.identity), path, context).await
    }

    /// Pin an archive's full context and stream ID without opening a destination.
    ///
    /// The account must match before decryption. Authenticate the source prefix
    /// with [`ArchiveInput::push_source`], then explicitly create a new destination
    /// or resume that exact stream's receiving state. Neither operation restores
    /// a live device or resets retained state. This input retains account custody
    /// independently of the controller until dropped or consumed by import.
    pub fn prepare_archive_import(
        &self,
        context: Context,
        archive_id: [u8; 32],
    ) -> Result<ArchiveInput> {
        ArchiveInput::new_shared(Arc::clone(&self.identity), context, archive_id)
    }

    /// Open only completed, read-only archive state under its exact final seal.
    ///
    /// The final page is authenticated before native store recovery. Use this to
    /// reconcile an uncertain import finalization with the retained source file;
    /// missing or receiving state never falls back to creation or live room open.
    /// Plaintext archive reads require explicit trusted-client authorization and
    /// do not inherit permission from a live-room agent grant.
    pub async fn open_archive(
        &self,
        path: impl AsRef<Path>,
        context: Context,
        archive_id: [u8; 32],
        final_page: &[u8],
    ) -> Result<ArchiveSession> {
        ArchiveSession::open_shared(
            Arc::clone(&self.identity),
            path,
            context,
            archive_id,
            final_page,
        )
        .await
    }
}
