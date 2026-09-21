use super::*;

/// One authenticated bounded source image, with no provider/key/raw-state getter.
/// It is not an archive-completeness or live-restore token.
pub struct ArchiveSource {
    pub(super) context: Context,
    pub(super) id: [u8; 32],
    pub(super) header: Header,
    pub(super) clear: Zeroizing<Vec<u8>>,
    pub(super) snapshot: Snapshot,
    pub(super) next: u64,
    pub(super) previous: [u8; 32],
    custody_check: Vec<u8>,
}
impl ArchiveSource {
    // The caller cannot rewrap an authenticated source under another custody
    // key, including a source with no immutable records. This transient proof
    // has no serialization/getter and uses the existing bounded AEAD contract.
    pub(super) fn check_key(&self, key: &StorageKey) -> Result<()> {
        let clear = codec::unseal(
            key,
            self.context,
            b"private-archive-source-binding/v1\0",
            &self.custody_check,
            72,
        )?;
        if clear.as_slice() != self.header.state_hash {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    /// Private full-context metadata authenticated from the complete image.
    pub const fn context(&self) -> Context {
        self.context
    }
    /// Original local revision, not proof of newest remote state.
    pub const fn revision(&self) -> u64 {
        self.header.revision
    }
    /// Random archive correlation ID; not a device or membership identity.
    pub const fn archive_id(&self) -> [u8; 32] {
        self.id
    }
}

/// Consumes only bounded initial image pages. At most one existing image is
/// assembled; no lifetime history buffer or backend write occurs here.
pub struct ArchiveSourceReader {
    key: StorageKey,
    context: Context,
    id: [u8; 32],
    header: Option<Header>,
    image: Vec<u8>,
    next: u64,
    previous: [u8; 32],
    failed: bool,
}
impl ArchiveSourceReader {
    /// Independently pin the full context and selected archive before decoding.
    pub fn new(key: &StorageKey, context: Context, archive_id: [u8; 32]) -> Result<Self> {
        if archive_id == [0; 32] {
            return Err(Error::Encoding);
        }
        Ok(Self {
            key: key.duplicate(),
            context,
            id: archive_id,
            header: None,
            image: Vec::new(),
            next: 0,
            previous: [0; 32],
            failed: false,
        })
    }
    /// Accept exactly the next image fragment. True means finish is available.
    /// Any failure poisons this reader; caller must start again from the same file.
    pub fn push(&mut self, raw: &[u8]) -> Result<bool> {
        if self.failed {
            return Err(Error::NeedsReopen);
        }
        self.failed = true;
        let page = Page::open(&self.key, self.context, self.id, raw)?;
        if page.index != self.next || page.previous != self.previous {
            return Err(Error::Conflict);
        }
        let mut r = codec::Reader::new(&page.payload, &[0], MAX_ARCHIVE_PAGE_BYTES)?;
        let header = Header::read(&mut r)?;
        if self.header.is_some_and(|old| old != header) {
            return Err(Error::Conflict);
        }
        let offset = u32::from_be_bytes(r.array()?) as usize;
        let chunk = r.blob(IMAGE_FRAGMENT_BYTES)?;
        r.end()?;
        if offset != self.image.len()
            || chunk.is_empty()
            || offset
                .checked_add(chunk.len())
                .is_none_or(|n| n > header.image_len as usize)
            || (chunk.len() != IMAGE_FRAGMENT_BYTES
                && offset + chunk.len() != header.image_len as usize)
        {
            return Err(Error::Bounds);
        }
        self.image
            .try_reserve(chunk.len())
            .map_err(|_| Error::Bounds)?;
        self.image.extend_from_slice(chunk);
        self.header = Some(header);
        self.next = self.next.checked_add(1).ok_or(Error::Bounds)?;
        self.previous = page_digest(raw);
        self.failed = false;
        Ok(self.image.len() == header.image_len as usize)
    }
    /// Authenticate canonical v4 state, retained provider, revision and required
    /// record count. No method returns the decrypted provider map.
    pub fn finish(self) -> Result<ArchiveSource> {
        if self.failed {
            return Err(Error::NeedsReopen);
        }
        let header = self.header.ok_or(Error::Missing)?;
        if self.image.len() != header.image_len as usize || hash(&self.image) != header.image_hash {
            return Err(Error::Authentication);
        }
        let image = Image::from_bytes(&self.image)?;
        let (clear, state) = canonical_state(&self.key, self.context, &image)?;
        let snapshot = Snapshot::of(&state);
        if hash(&clear) != header.state_hash
            || snapshot.revision != header.revision
            || snapshot.records()? != header.records
        {
            return Err(Error::Conflict);
        }
        let custody_check = codec::seal(
            &self.key,
            self.context,
            b"private-archive-source-binding/v1\0",
            &header.state_hash,
            72,
        )?;
        Ok(ArchiveSource {
            custody_check,
            context: self.context,
            id: self.id,
            header,
            clear,
            snapshot,
            next: self.next,
            previous: self.previous,
        })
    }
}

/// Bounded read-only export, retaining one exact source image and custody key.
/// A changed source, missing index or canceled read requires dropping this owner.
/// Restart may create a new archive ID; no partially written output is completed
/// by guessing a cursor or combining pages from separate source generations.
pub struct ArchiveExport<S: ArchiveStore> {
    store: S,
    key: StorageKey,
    context: Context,
    image: Image,
    snapshot: Snapshot,
    header: Header,
    id: [u8; 32],
    offset: usize,
    unit: u64,
    records: u64,
    bytes: u64,
    floor: ControlFloor,
    next: u64,
    previous: [u8; 32],
    done: bool,
    failed: bool,
}
impl<S: ArchiveStore> ArchiveExport<S> {
    /// Open only an existing exact authenticated ordinary v4 source. This does
    /// not freeze it, mutate it or grant transfer/live-restore authority.
    pub async fn open(mut store: S, key: &StorageKey, context: Context) -> Result<Self> {
        let value = store.accounting(context).await.map_err(store_error)?;
        let image = value.image.as_ref().ok_or(Error::Missing)?.clone();
        let (clear, state) = canonical_state(key, context, &image)?;
        let snapshot = Snapshot::of(&state);
        accounting(&value, Some(&image), snapshot.records()?, value.bytes)?;
        let header = Header {
            revision: state.revision,
            records: value.records,
            bytes: value.bytes,
            image_len: u32::try_from(image.0.len()).map_err(|_| Error::Bounds)?,
            image_hash: hash(&image.0),
            state_hash: hash(&clear),
        };
        let id = codec::random()?;
        if id == [0; 32] {
            return Err(Error::Entropy);
        }
        Ok(Self {
            store,
            key: key.duplicate(),
            context,
            image,
            snapshot,
            header,
            id,
            offset: 0,
            unit: 0,
            records: 0,
            bytes: 0,
            floor: snapshot.base,
            next: 0,
            previous: [0; 32],
            done: false,
            failed: false,
        })
    }
    /// Stable ID of this exact stream, retained independently with its context.
    pub const fn archive_id(&self) -> [u8; 32] {
        self.id
    }
    /// Any failed/canceled access requires this exporter to be dropped.
    pub const fn needs_reopen(&self) -> bool {
        self.failed
    }
    /// Produce one encrypted page only after exact source/accounting checks.
    /// A None result follows the authenticated final page, never a partial export.
    pub async fn next_page(&mut self) -> Result<Option<ArchivePage>> {
        if self.failed {
            return Err(Error::NeedsReopen);
        }
        if self.done {
            return Ok(None);
        }
        self.failed = true;
        let observed = self
            .store
            .accounting(self.context)
            .await
            .map_err(store_error)?;
        accounting(
            &observed,
            Some(&self.image),
            self.header.records,
            self.header.bytes,
        )?;
        let payload = if self.offset < self.image.0.len() {
            let end = (self.offset + IMAGE_FRAGMENT_BYTES).min(self.image.0.len());
            let mut w = codec::Writer::new(&[0], MAX_ARCHIVE_PAGE_BYTES - 256)?;
            self.header.put(&mut w)?;
            w.put(&(self.offset as u32).to_be_bytes())?;
            w.blob(&self.image.0[self.offset..end], IMAGE_FRAGMENT_BYTES)?;
            self.offset = end;
            Zeroizing::new(w.finish())
        } else if self.unit < self.snapshot.units()? {
            let (records, floor) = records::load(
                &mut self.store,
                &self.key,
                self.context,
                self.snapshot,
                self.unit,
                self.floor,
            )
            .await?;
            self.records = self
                .records
                .checked_add(records.len() as u64)
                .ok_or(Error::Bounds)?;
            self.bytes = self
                .bytes
                .checked_add(records::bytes(&records)?)
                .ok_or(Error::Bounds)?;
            let payload = records::payload(self.unit, &records)?;
            self.unit += 1;
            self.floor = floor;
            payload
        } else {
            if self.records != self.header.records
                || self.bytes != self.header.bytes
                || self.floor != self.snapshot.floor
            {
                return Err(Error::Conflict);
            }
            self.done = true;
            let mut w = codec::Writer::new(&[2], 128)?;
            self.header.put(&mut w)?;
            w.u64(self.unit)?;
            Zeroizing::new(w.finish())
        };
        // No output escapes if another cooperating writer advanced during reads.
        let observed = self
            .store
            .accounting(self.context)
            .await
            .map_err(store_error)?;
        accounting(
            &observed,
            Some(&self.image),
            self.header.records,
            self.header.bytes,
        )?;
        let page = Page {
            id: self.id,
            index: self.next,
            previous: self.previous,
            payload,
        };
        let encrypted = page.seal(&self.key, self.context)?;
        self.previous = page_digest(encrypted.encrypted_bytes());
        self.next = self.next.checked_add(1).ok_or(Error::Bounds)?;
        self.failed = false;
        Ok(Some(encrypted))
    }
}
