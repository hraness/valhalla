//! Account-owned archive custody. No API returns a live kernel, storage key,
//! provider image, plaintext archive page or mutable backend.
//!
//! These synchronous native stores block inside async methods; use a native
//! worker. Explicit native open retains its SQLite recovery/sync behavior.
//! Archive reads themselves never publish, reset or activate a device.
use crate::{bridge::KernelStore, client::Error, private_rooms::Limits};
use std::path::Path;
use vhalla_identity::Identity;
use vhalla_private_kernel::{
    recovery::{
        ArchiveExport, ArchiveImport, ArchivePage, ArchiveSeal, ArchiveSourceReader, ArchiveView,
        ImportProgress,
    },
    storage::ArchiveStore,
    Context, InboxPage, MembershipSnapshot, OutboxPage, StorageKey,
};

type Result<T> = std::result::Result<T, Error>;

struct Owned<T> {
    // Destroy state/key/backend before releasing the account lock.
    value: T,
    identity: Identity,
}

/// One read-only source export with account and exact room custody held together.
/// A failed or canceled export must restart into a different file; it never
/// resumes a guessed page offset or fences the still-live source device.
pub struct ArchiveExporter {
    owned: Option<Owned<ArchiveExport<KernelStore>>>,
    context: Context,
    limits: Limits,
}
impl ArchiveExporter {
    /// Open and authenticate an existing exact source with its account custody.
    /// Missing/corrupt state never initializes a replacement device.
    pub async fn open(
        identity: Identity,
        path: impl AsRef<Path>,
        context: Context,
    ) -> Result<Self> {
        let key = identity.private_storage_key(context)?;
        let mut store = KernelStore::open(path, context)?;
        let accounting = store.accounting(context).await?;
        let limits = Limits {
            max_records: accounting.max_records,
            max_record_bytes: accounting.max_bytes,
        };
        let value = ArchiveExport::open(store, &key, context).await?;
        Ok(Self {
            owned: Some(Owned { value, identity }),
            context,
            limits,
        })
    }
    /// Source full context authenticated at open; never live restore authority.
    pub const fn context(&self) -> Context {
        self.context
    }
    /// Source store's immutable ceilings, for bounded file framing only.
    pub const fn limits(&self) -> Limits {
        self.limits
    }
    /// Random identifier of this one exact source stream.
    pub fn archive_id(&self) -> Result<[u8; 32]> {
        Ok(self.owned.as_ref().ok_or(Error::Locked)?.value.archive_id())
    }
    /// Read the next bounded encrypted page after exact source revalidation.
    /// None is returned only after the authenticated final page was produced.
    pub async fn next_page(&mut self) -> Result<Option<ArchivePage>> {
        Ok(self
            .owned
            .as_mut()
            .ok_or(Error::Locked)?
            .value
            .next_page()
            .await?)
    }
    /// Whether lock, failure or cancellation requires a new export lifetime.
    pub fn needs_reopen(&self) -> bool {
        self.owned
            .as_ref()
            .is_none_or(|owner| owner.value.needs_reopen())
    }
    /// Destroy the exporter/store and then release the account lock.
    pub fn lock(&mut self) {
        drop(self.owned.take());
    }
}

/// Authenticate initial image pages before touching a destination. Supplied
/// context/ID are untrusted selections until the complete prefix authenticates;
/// the selected full account must match before any decryption or store access.
pub struct ArchiveInput {
    reader: ArchiveSourceReader,
    key: StorageKey,
    identity: Identity,
}
impl ArchiveInput {
    /// Take existing account custody and pin the requested context/stream ID.
    /// Wrong account refuses before opening any source/destination backend.
    pub fn new(identity: Identity, context: Context, archive_id: [u8; 32]) -> Result<Self> {
        let key = identity.private_storage_key(context)?;
        let reader = ArchiveSourceReader::new(&key, context, archive_id)?;
        Ok(Self {
            reader,
            key,
            identity,
        })
    }
    /// True means the bounded initial source image is ready. No backend exists
    /// yet and no request here can export its decrypted state.
    pub fn push_source(&mut self, raw: &[u8]) -> Result<bool> {
        Ok(self.reader.push(raw)?)
    }
    /// Only create_new may allocate a destination. Authentication and canonical
    /// full-context checks precede creation; a failed create is never reset.
    pub async fn create(self, path: impl AsRef<Path>, limits: Limits) -> Result<ArchiveReceiver> {
        let source = self.reader.finish()?;
        let store = KernelStore::create_new(path, source.context(), limits)?;
        let value = ArchiveImport::begin(store, &self.key, source).await?;
        Ok(ArchiveReceiver {
            owned: Some(Owned {
                value,
                identity: self.identity,
            }),
        })
    }
    /// Receiving state only. A completed archive is opened explicitly through
    /// ArchiveSession; missing/partial initialization never falls back to create.
    pub async fn resume(self, path: impl AsRef<Path>) -> Result<ArchiveReceiver> {
        let source = self.reader.finish()?;
        let store = KernelStore::open(path, source.context())?;
        let value = ArchiveImport::resume(store, &self.key, source).await?;
        Ok(ArchiveReceiver {
            owned: Some(Owned {
                value,
                identity: self.identity,
            }),
        })
    }
}

/// Inert destination progress. Exact retries are checked by the existing kernel
/// codec and immutable records; this type cannot sign, receive MLS or send.
pub struct ArchiveReceiver {
    owned: Option<Owned<ArchiveImport<KernelStore>>>,
}
impl ArchiveReceiver {
    /// Last confirmed receiving cursor, not a completeness or activation claim.
    pub fn progress(&self) -> Result<ImportProgress> {
        Ok(self.owned.as_ref().ok_or(Error::Locked)?.value.progress()?)
    }
    /// Atomically retain one checked records page, or verify the exact last retry.
    pub async fn append(&mut self, raw: &[u8]) -> Result<ImportProgress> {
        Ok(self
            .owned
            .as_mut()
            .ok_or(Error::Locked)?
            .value
            .append(raw)
            .await?)
    }
    /// Whether lock, uncertainty, cancellation or refusal latched this receiver.
    pub fn needs_reopen(&self) -> bool {
        self.owned
            .as_ref()
            .is_none_or(|owner| owner.value.needs_reopen())
    }
    /// Preserve the source file on uncertainty. Reconcile a potentially completed
    /// finalization with ArchiveSession::open; do not reset receiving state.
    pub async fn finish(mut self, final_page: &[u8]) -> Result<ArchiveSession> {
        let owner = self.owned.take().ok_or(Error::Locked)?;
        let value = owner.value.finish(final_page).await?;
        Ok(ArchiveSession {
            owned: Some(Owned {
                value,
                identity: owner.identity,
            }),
        })
    }
    /// Drop receiving state/custody without deleting or resetting any evidence.
    pub fn lock(&mut self) {
        drop(self.owned.take());
    }
}

/// Account-owned read-only archive view, with no conversion to ordinary state.
/// This proves exact retained completeness, not freshness or absence of clones.
pub struct ArchiveSession {
    owned: Option<Owned<ArchiveView<KernelStore>>>,
}
impl ArchiveSession {
    /// Authenticate the final page before native open, then require the existing
    /// exact archive-only image/accounting. No live-state fallback is attempted.
    pub async fn open(
        identity: Identity,
        path: impl AsRef<Path>,
        context: Context,
        archive_id: [u8; 32],
        final_page: &[u8],
    ) -> Result<Self> {
        let key = identity.private_storage_key(context)?;
        // Authenticate the requested final seal before native recovery effects.
        let seal = ArchiveSeal::from_final_page(&key, context, archive_id, final_page)?;
        let store = KernelStore::open(path, context)?;
        let value = ArchiveView::open(store, &key, seal).await?;
        Ok(Self {
            owned: Some(Owned { value, identity }),
        })
    }
    /// Metadata of the authenticated final claim, with no keys or provider state.
    pub fn seal(&self) -> Result<&ArchiveSeal> {
        Ok(self.owned.as_ref().ok_or(Error::Locked)?.value.seal())
    }
    /// Last authenticated archived membership; never proof of current membership.
    pub async fn membership(&mut self) -> Result<MembershipSnapshot> {
        Ok(self
            .owned
            .as_mut()
            .ok_or(Error::Locked)?
            .value
            .membership()
            .await?)
    }
    /// Read at most 16 retained plaintext messages after an exclusive cursor.
    /// The trusted caller must explicitly authorize any later disclosure.
    pub async fn inbox(&mut self, after: u64, limit: usize) -> Result<InboxPage> {
        Ok(self
            .owned
            .as_mut()
            .ok_or(Error::Locked)?
            .value
            .inbox(after, limit)
            .await?)
    }
    /// Secret offer records remain metadata only, as in the ordinary outbox.
    pub async fn outbox(&mut self, after: u64, limit: usize) -> Result<OutboxPage> {
        Ok(self
            .owned
            .as_mut()
            .ok_or(Error::Locked)?
            .value
            .outbox(after, limit)
            .await?)
    }
    /// Whether this view was locked or a failed/canceled read requires reopen.
    pub fn needs_reopen(&self) -> bool {
        self.owned
            .as_ref()
            .is_none_or(|owner| owner.value.needs_reopen())
    }
    /// Destroy archive state/store and account custody together.
    pub fn lock(&mut self) {
        drop(self.owned.take());
    }
}
