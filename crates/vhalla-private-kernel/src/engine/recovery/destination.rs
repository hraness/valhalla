use super::*;

const PROGRESS_MAX: usize = 512;
const PROGRESS_PURPOSE: &[u8] = b"private-archive-receiving/v1\0";

/// Metadata authenticated by a final archive page, not proof of local import or
/// newest state. Retain that encrypted final page to reconstruct this seal after
/// locking; no key, provider state or active-device authority is carried here.
#[derive(Clone)]
pub struct ArchiveSeal {
    context: Context,
    id: [u8; 32],
    header: Header,
    index: u64,
    previous: [u8; 32],
    units: u64,
    binding: [u8; 32],
}
impl ArchiveSeal {
    /// Accept only an authenticated final page in the independently selected
    /// full context/archive. Completeness of a destination is checked separately.
    pub fn from_final_page(
        key: &StorageKey,
        context: Context,
        archive_id: [u8; 32],
        raw: &[u8],
    ) -> Result<Self> {
        let page = Page::open(key, context, archive_id, raw)?;
        let mut r = codec::Reader::new(&page.payload, &[2], 128)?;
        let header = Header::read(&mut r)?;
        let units = r.u64()?;
        r.end()?;
        if page.index == 0 {
            return Err(Error::Encoding);
        }
        Ok(Self {
            context,
            id: archive_id,
            header,
            index: page.index,
            previous: page.previous,
            units,
            binding: page_digest(raw),
        })
    }
    /// Exact private namespace, not public discovery metadata.
    pub const fn context(&self) -> Context {
        self.context
    }
    /// Exact original local revision; not a global freshness statement.
    pub const fn source_revision(&self) -> u64 {
        self.header.revision
    }
    /// Correlation identity of the authenticated archive file.
    pub const fn archive_id(&self) -> [u8; 32] {
        self.id
    }
    fn purpose(&self) -> Vec<u8> {
        let mut p = b"private-archive-read-only/v1\0".to_vec();
        p.extend(self.binding);
        p
    }
}

/// Bounded durable receiving cursor. It grants no completeness or send authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImportProgress {
    /// Exact next encrypted stream page (image fragments were already checked).
    pub next_page: u64,
    /// Immutable records durably copied so far.
    pub records: u64,
    /// Encrypted immutable payload bytes durably copied so far.
    pub bytes: u64,
}
#[derive(Clone, Copy)]
struct Progress {
    next: u64,
    previous: [u8; 32],
    unit: u64,
    records: u64,
    bytes: u64,
    floor: ControlFloor,
    last_floor: ControlFloor,
}
impl Progress {
    fn public(self) -> ImportProgress {
        ImportProgress {
            next_page: self.next,
            records: self.records,
            bytes: self.bytes,
        }
    }
    fn encode(self, source: &ArchiveSource) -> Result<Zeroizing<Vec<u8>>> {
        let magic: &[u8] = if self.unit == 0 {
            b"VHPRDEST1"
        } else {
            b"VHPRRECV1"
        };
        let mut w = codec::Writer::new(magic, PROGRESS_MAX - 40)?;
        w.put(&source.id)?;
        source.header.put(&mut w)?;
        w.u64(self.next)?;
        w.put(&self.previous)?;
        w.u64(self.unit)?;
        w.u64(self.records)?;
        w.u64(self.bytes)?;
        put_floor(&mut w, self.floor)?;
        put_floor(&mut w, self.last_floor)?;
        Ok(Zeroizing::new(w.finish()))
    }
    fn decode(raw: &[u8], source: &ArchiveSource) -> Result<Self> {
        let magic = raw.get(..9).ok_or(Error::Encoding)?;
        if magic != b"VHPRDEST1" && magic != b"VHPRRECV1" {
            return Err(Error::Encoding);
        }
        let mut r = codec::Reader::new(raw, magic, PROGRESS_MAX)?;
        if r.array::<32>()? != source.id || Header::read(&mut r)? != source.header {
            return Err(Error::Conflict);
        }
        let p = Self {
            next: r.u64()?,
            previous: r.array()?,
            unit: r.u64()?,
            records: r.u64()?,
            bytes: r.u64()?,
            floor: read_floor(&mut r)?,
            last_floor: read_floor(&mut r)?,
        };
        r.end()?;
        if p.unit > source.snapshot.units()?
            || p.next != source.next.checked_add(p.unit).ok_or(Error::Bounds)?
            || p.records > source.header.records
            || p.bytes > source.header.bytes
            || (p.unit == 0) != (magic == b"VHPRDEST1")
            || {
                let (min, max) = count_range(&source.snapshot, p.unit)?;
                !(min..=max).contains(&p.records)
            }
            || p.floor.sequence() != floor_before(&source.snapshot, p.unit)?
            || p.last_floor.sequence() != floor_before(&source.snapshot, p.unit.saturating_sub(1))?
            || (p.unit == 0
                && (p.previous != source.previous
                    || p.bytes != 0
                    || p.floor != source.snapshot.base
                    || p.last_floor != source.snapshot.base))
        {
            return Err(Error::Encoding);
        }
        Ok(p)
    }
}
/// Records durably imported after `unit` units: each outbox/inbox unit carries
/// two to three records and each control unit exactly one, so only a range is
/// derivable before per-unit content is authenticated.
fn count_range(s: &Snapshot, unit: u64) -> Result<(u64, u64)> {
    let pairs = s.outbox.checked_add(s.inbox).ok_or(Error::Bounds)?;
    let pair_units = unit.min(pairs);
    let controls = unit.saturating_sub(pairs);
    let min = pair_units
        .checked_mul(2)
        .and_then(|v| v.checked_add(controls))
        .ok_or(Error::Bounds)?;
    let max = pair_units
        .checked_mul(3)
        .and_then(|v| v.checked_add(controls))
        .ok_or(Error::Bounds)?;
    Ok((min, max))
}
fn floor_before(s: &Snapshot, unit: u64) -> Result<u64> {
    let pairs = s.outbox.checked_add(s.inbox).ok_or(Error::Bounds)?;
    s.base
        .sequence()
        .checked_add(unit.saturating_sub(pairs))
        .ok_or(Error::Bounds)
}
fn put_floor(w: &mut codec::Writer, value: ControlFloor) -> Result<()> {
    w.u64(value.sequence())?;
    w.put(value.id().as_ref().map_or(&[0; 32], |id| id.as_bytes()))
}
fn read_floor(r: &mut codec::Reader<'_>) -> Result<ControlFloor> {
    let sequence = r.u64()?;
    let id = r.array()?;
    Ok(ControlFloor::new(
        sequence,
        if id == [0; 32] {
            None
        } else {
            Some(protocol::ControlId::from_bytes(id)?)
        },
    )?)
}

/// Inert bounded destination. The existing Store transaction appends a checked
/// outbox/index pair, inbox/index pair or single control with small progress.
/// No method yields a live Kernel, and failures/cancellation latch before await.
pub struct ArchiveImport<S: ArchiveStore> {
    store: S,
    key: StorageKey,
    source: ArchiveSource,
    image: Image,
    progress: Progress,
    failed: bool,
}
impl<S: ArchiveStore> ArchiveImport<S> {
    /// Begin only in an explicitly created, wholly unused destination. No absent
    /// existing image, orphan marker or interrupted import is reset.
    pub async fn begin(mut store: S, key: &StorageKey, source: ArchiveSource) -> Result<Self> {
        source.check_key(key)?;
        let before = store
            .accounting(source.context)
            .await
            .map_err(store_error)?;
        accounting(&before, None, 0, 0)?;
        if source.header.records > before.max_records || source.header.bytes > before.max_bytes {
            return Err(Error::Bounds);
        }
        let progress = Progress {
            next: source.next,
            previous: source.previous,
            unit: 0,
            records: 0,
            bytes: 0,
            floor: source.snapshot.base,
            last_floor: source.snapshot.base,
        };
        let image = Image(codec::seal(
            &frame::receiving_key(key, source.context, source.id)?,
            source.context,
            PROGRESS_PURPOSE,
            &progress.encode(&source)?,
            PROGRESS_MAX,
        )?);
        store
            .publish(source.context, None, &image, &[])
            .await
            .map_err(store_error)?;
        let after = store
            .accounting(source.context)
            .await
            .map_err(store_error)?;
        accounting(&after, Some(&image), 0, 0)?;
        Ok(Self {
            store,
            key: key.duplicate(),
            source,
            image,
            progress,
            failed: false,
        })
    }
    /// Reopen only the exact retained receiving state with the same authenticated
    /// source image pages. Missing input/state never initializes a replacement.
    pub async fn resume(mut store: S, key: &StorageKey, source: ArchiveSource) -> Result<Self> {
        source.check_key(key)?;
        let value = store
            .accounting(source.context)
            .await
            .map_err(store_error)?;
        let image = value.image.as_ref().ok_or(Error::Missing)?.clone();
        let clear = codec::unseal(
            &frame::receiving_key(key, source.context, source.id)?,
            source.context,
            PROGRESS_PURPOSE,
            image.as_bytes(),
            PROGRESS_MAX,
        )?;
        let progress = Progress::decode(&clear, &source)?;
        accounting(&value, Some(&image), progress.records, progress.bytes)?;
        if source.header.records > value.max_records || source.header.bytes > value.max_bytes {
            return Err(Error::Bounds);
        }
        Ok(Self {
            store,
            key: key.duplicate(),
            source,
            image,
            progress,
            failed: false,
        })
    }
    /// Last confirmed receiving cursor. Check needs_reopen after any interruption.
    pub fn progress(&self) -> Result<ImportProgress> {
        if self.failed {
            return Err(Error::NeedsReopen);
        }
        Ok(self.progress.public())
    }
    /// A failed/canceled operation requires an exact reopen before any retry.
    pub const fn needs_reopen(&self) -> bool {
        self.failed
    }
    async fn check_current(&mut self) -> Result<()> {
        let value = self
            .store
            .accounting(self.source.context)
            .await
            .map_err(store_error)?;
        accounting(
            &value,
            Some(&self.image),
            self.progress.records,
            self.progress.bytes,
        )
    }
    /// Accept one exact records page. The last committed page may be retried:
    /// compare its exact wire digest and every retained ciphertext before success.
    pub async fn append(&mut self, raw: &[u8]) -> Result<ImportProgress> {
        if self.failed {
            return Err(Error::NeedsReopen);
        }
        self.failed = true;
        let page = Page::open(&self.key, self.source.context, self.source.id, raw)?;
        let (unit, records) = records::decode(&page.payload)?;
        self.check_current().await?;
        let digest = page_digest(raw);
        if page.index.checked_add(1) == Some(self.progress.next)
            && unit.checked_add(1) == Some(self.progress.unit)
            && digest == self.progress.previous
        {
            let floor = records::check(
                &mut self.store,
                &self.key,
                self.source.context,
                &self.source.snapshot,
                unit,
                self.progress.last_floor,
                &records,
            )
            .await?;
            if floor != self.progress.floor {
                return Err(Error::Conflict);
            }
            for expected in &records {
                let actual = self
                    .store
                    .read(self.source.context, expected.key())
                    .await
                    .map_err(store_error)?
                    .ok_or(Error::Missing)?;
                if actual != *expected {
                    return Err(Error::Conflict);
                }
            }
            self.check_current().await?;
            self.failed = false;
            return Ok(self.progress.public());
        }
        if page.index != self.progress.next
            || page.previous != self.progress.previous
            || unit != self.progress.unit
        {
            return Err(Error::Conflict);
        }
        let floor = records::check(
            &mut self.store,
            &self.key,
            self.source.context,
            &self.source.snapshot,
            unit,
            self.progress.floor,
            &records,
        )
        .await?;
        let next = Progress {
            next: self.progress.next.checked_add(1).ok_or(Error::Bounds)?,
            previous: digest,
            unit: self.progress.unit.checked_add(1).ok_or(Error::Bounds)?,
            records: self
                .progress
                .records
                .checked_add(records.len() as u64)
                .ok_or(Error::Bounds)?,
            bytes: self
                .progress
                .bytes
                .checked_add(records::bytes(&records)?)
                .ok_or(Error::Bounds)?,
            floor,
            last_floor: self.progress.floor,
        };
        if next.records > self.source.header.records || next.bytes > self.source.header.bytes {
            return Err(Error::Bounds);
        }
        let image = Image(codec::seal(
            &frame::receiving_key(&self.key, self.source.context, self.source.id)?,
            self.source.context,
            PROGRESS_PURPOSE,
            &next.encode(&self.source)?,
            PROGRESS_MAX,
        )?);
        self.store
            .publish(self.source.context, Some(&self.image), &image, &records)
            .await
            .map_err(store_error)?;
        let after = self
            .store
            .accounting(self.source.context)
            .await
            .map_err(store_error)?;
        accounting(&after, Some(&image), next.records, next.bytes)?;
        for expected in &records {
            let actual = self
                .store
                .read(self.source.context, expected.key())
                .await
                .map_err(store_error)?
                .ok_or(Error::Missing)?;
            if actual != *expected {
                return Err(Error::Conflict);
            }
        }
        let observed = self
            .store
            .accounting(self.source.context)
            .await
            .map_err(store_error)?;
        accounting(&observed, Some(&image), next.records, next.bytes)?;
        self.image = image;
        self.progress = next;
        self.failed = false;
        Ok(next.public())
    }
    /// Confirm the complete authenticated stream, then publish only an archive-
    /// purpose image. Retain its seal before this await; after uncertain finish,
    /// ArchiveView::open reconciles completion without reinstalling any old image.
    pub async fn finish(mut self, raw: &[u8]) -> Result<ArchiveView<S>> {
        if self.failed {
            return Err(Error::NeedsReopen);
        }
        self.failed = true;
        let seal =
            ArchiveSeal::from_final_page(&self.key, self.source.context, self.source.id, raw)?;
        if seal.header != self.source.header
            || seal.index != self.progress.next
            || seal.previous != self.progress.previous
            || seal.units != self.progress.unit
            || self.progress.unit != self.source.snapshot.units()?
            || self.progress.records != seal.header.records
            || self.progress.bytes != seal.header.bytes
            || self.progress.floor != self.source.snapshot.floor
        {
            return Err(Error::Conflict);
        }
        self.check_current().await?;
        let next = Image(codec::seal(
            &frame::read_only_key(&self.key, self.source.context, self.source.id)?,
            self.source.context,
            &seal.purpose(),
            &self.source.clear,
            MAX_IMAGE_BYTES,
        )?);
        self.store
            .publish(self.source.context, Some(&self.image), &next, &[])
            .await
            .map_err(store_error)?;
        let observed = self
            .store
            .accounting(self.source.context)
            .await
            .map_err(store_error)?;
        accounting(
            &observed,
            Some(&next),
            seal.header.records,
            seal.header.bytes,
        )?;
        ArchiveView::open(self.store, &self.key, seal).await
    }
}

/// Authenticated read-only imported history. There is deliberately no conversion
/// to Kernel/RoomSession, raw image/provider getter, signer or MLS operation.
pub struct ArchiveView<S: ArchiveStore> {
    store: S,
    key: StorageKey,
    seal: ArchiveSeal,
    image: Image,
    /// Authenticated decode of exactly `self.image`. The accounting snapshot
    /// proves the committed image unchanged, so repeat reads never re-verify
    /// the sealed archive state.
    cached: Option<State>,
    failed: bool,
}
impl<S: ArchiveStore> ArchiveView<S> {
    /// Open only a completed archive matching its authenticated retained seal.
    /// Live, destination and receiving images cannot be interpreted as archives.
    pub async fn open(mut store: S, key: &StorageKey, seal: ArchiveSeal) -> Result<Self> {
        let value = store.accounting(seal.context).await.map_err(store_error)?;
        let image = value.image.as_ref().ok_or(Error::Missing)?.clone();
        accounting(&value, Some(&image), seal.header.records, seal.header.bytes)?;
        let state = archive_state(key, &seal, &image)?;
        Ok(Self {
            store,
            key: key.duplicate(),
            seal,
            image,
            cached: Some(state),
            failed: false,
        })
    }
    /// A failed or canceled read requires an exact reopen.
    pub const fn needs_reopen(&self) -> bool {
        self.failed
    }
    /// Small authenticated metadata for reconstructing this view after lock.
    pub fn seal(&self) -> &ArchiveSeal {
        &self.seal
    }
    /// Revalidate the committed image by one atomic accounting snapshot, then
    /// return its authenticated decoded state. An unchanged image makes the
    /// previously verified decode authoritative; nothing is re-derived.
    async fn begin(&mut self) -> Result<State> {
        if self.failed {
            return Err(Error::NeedsReopen);
        }
        self.failed = true;
        let value = self
            .store
            .accounting(self.seal.context)
            .await
            .map_err(store_error)?;
        accounting(
            &value,
            Some(&self.image),
            self.seal.header.records,
            self.seal.header.bytes,
        )?;
        if let Some(state) = &self.cached {
            return Ok(state.clone());
        }
        let state = archive_state(&self.key, &self.seal, &self.image)?;
        self.cached = Some(state.clone());
        Ok(state)
    }
    async fn check_current(&mut self) -> Result<()> {
        let value = self
            .store
            .accounting(self.seal.context)
            .await
            .map_err(store_error)?;
        accounting(
            &value,
            Some(&self.image),
            self.seal.header.records,
            self.seal.header.bytes,
        )
    }
    /// Private last-observed membership; never current posting authorization.
    pub async fn membership(&mut self) -> Result<MembershipSnapshot> {
        let state = self.begin().await?;
        let result = super::super::snapshot::MembershipSnapshot::from_state(&state);
        self.failed = false;
        Ok(result)
    }
    /// Read inert retained inbox content. No receive/ratchet operation occurs.
    pub async fn inbox(&mut self, after: u64, limit: usize) -> Result<InboxPage> {
        if limit == 0 || limit > MAX_PAGE_RECORDS {
            return Err(Error::Bounds);
        }
        let state = self.begin().await?;
        if after > state.inbox {
            return Err(Error::Bounds);
        }
        let snapshot = Snapshot::of(&state);
        let mut result = Vec::new();
        let mut cursor = after;
        let mut bytes = 0usize;
        while cursor < state.inbox && result.len() < limit {
            let unit = state.outbox.checked_add(cursor).ok_or(Error::Bounds)?;
            let (records, _) = records::load(
                &mut self.store,
                &self.key,
                self.seal.context,
                &snapshot,
                unit,
                state.base,
            )
            .await?;
            let clear = record_clear(&self.key, self.seal.context, &records[0])?;
            let mut received = Received::decode(&clear)?;
            let body = Zeroizing::new(std::mem::take(&mut received.body));
            let next_bytes = bytes.checked_add(body.len()).ok_or(Error::Bounds)?;
            if next_bytes > MAX_PAGE_BYTES {
                break;
            }
            bytes = next_bytes;
            cursor += 1;
            result.push(ReceivedMessage {
                sequence: received.sequence,
                sender: received.sender,
                body: body.to_vec(),
            });
        }
        self.check_current().await?;
        self.failed = false;
        Ok(InboxPage {
            head: state.inbox,
            next: (cursor < state.inbox).then_some(cursor),
            records: result,
        })
    }
    /// Read original committed artifacts with the ordinary secret-offer metadata
    /// redaction. This does not confirm network delivery or grant reencryption.
    pub async fn outbox(&mut self, after: u64, limit: usize) -> Result<OutboxPage> {
        if limit == 0 || limit > MAX_PAGE_RECORDS {
            return Err(Error::Bounds);
        }
        let state = self.begin().await?;
        if after > state.outbox {
            return Err(Error::Bounds);
        }
        let snapshot = Snapshot::of(&state);
        let mut result = Vec::new();
        let mut cursor = after;
        let mut bytes = 0usize;
        while cursor < state.outbox && result.len() < limit {
            let (records, _) = records::load(
                &mut self.store,
                &self.key,
                self.seal.context,
                &snapshot,
                cursor,
                state.base,
            )
            .await?;
            let clear = record_clear(&self.key, self.seal.context, &records[0])?;
            let sent = Sent::decode(&clear)?;
            let next_bytes = bytes.checked_add(sent.bytes.len()).ok_or(Error::Bounds)?;
            if next_bytes > MAX_PAGE_BYTES {
                break;
            }
            bytes = next_bytes;
            cursor += 1;
            result.push(sent.entry()?);
        }
        self.check_current().await?;
        self.failed = false;
        Ok(OutboxPage {
            head: state.outbox,
            next: (cursor < state.outbox).then_some(cursor),
            records: result,
        })
    }
}
fn archive_state(key: &StorageKey, seal: &ArchiveSeal, image: &Image) -> Result<State> {
    let clear = codec::unseal(
        &frame::read_only_key(key, seal.context, seal.id)?,
        seal.context,
        &seal.purpose(),
        image.as_bytes(),
        MAX_IMAGE_BYTES,
    )?;
    if hash(&clear) != seal.header.state_hash {
        return Err(Error::Authentication);
    }
    let state = Working::hydrate(State::decode(&clear, seal.context)?)?.capture()?;
    let snapshot = Snapshot::of(&state);
    let encoded = Zeroizing::new(state.encode()?);
    let (min, max) = snapshot.records_range()?;
    if snapshot.revision != seal.header.revision
        || !(min..=max).contains(&seal.header.records)
        || snapshot.units()? != seal.units
        || encoded.as_slice() != clear.as_slice()
    {
        return Err(Error::Conflict);
    }
    Ok(state)
}
