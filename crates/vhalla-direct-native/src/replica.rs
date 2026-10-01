//! Durable public frames for one source incarnation. The caller authenticates
//! the source and checkpoint when serving them over a network. This local log
//! holds no room signing key and grants no room admission or delivery claim.

use std::path::Path;

use sha2::{Digest, Sha256};
use vhalla_direct_room::{
    PinnedGenesis, RoomId, MAX_EVENT_BYTES, MAX_GENESIS_BYTES, MAX_POLICY_BYTES,
};
use vhalla_direct_store::{Accounting, Context, Entry, Limits, Record, Store};
use vhalla_direct_sync::{Checkpoint, Frame, FrameKind, SourceAccumulator};

const IMAGE_MAGIC: &[u8; 8] = b"VHRP0001";
const RECORD_MAGIC: &[u8; 8] = b"VHRR0001";
const IMAGE_BYTES: usize = 152;
const RECORD_HEADER: usize = 57;

/// Replica failure. Refusal never permits deleting evidence or resetting an epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplicaError {
    /// Invalid signed input, checkpoint, source binding or requested range.
    Sync(vhalla_direct_sync::Error),
    /// Local storage refused the operation or requires explicit reopening.
    Store(vhalla_direct_store::Error),
    /// The operating system did not supply a fresh nonzero epoch.
    Entropy,
}
impl core::fmt::Display for ReplicaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ReplicaError {}
impl From<vhalla_direct_sync::Error> for ReplicaError {
    fn from(error: vhalla_direct_sync::Error) -> Self {
        Self::Sync(error)
    }
}
impl From<vhalla_direct_store::Error> for ReplicaError {
    fn from(error: vhalla_direct_store::Error) -> Self {
        Self::Store(error)
    }
}
/// Durable public replica result.
pub type ReplicaResult<T> = std::result::Result<T, ReplicaError>;

/// One exact public signed frame. No local controller metadata is included.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplicaFrame {
    /// Canonical public record type.
    pub kind: FrameKind,
    /// Complete canonical signed bytes.
    pub bytes: Vec<u8>,
}
impl ReplicaFrame {
    /// Borrow this frame for the pure sync verifier or another replica append.
    pub fn as_frame(&self) -> Frame<'_> {
        Frame {
            kind: self.kind,
            bytes: &self.bytes,
        }
    }
}

/// Nonempty range belonging to the exact requested frozen checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplicaPage {
    /// Frozen statement; network authentication remains the transport's job.
    pub checkpoint: Checkpoint,
    /// One-based inclusive position of the first frame.
    pub first: u64,
    /// One-based inclusive position of the last frame.
    pub last: u64,
    /// At most 32 exact signed public frames in source order.
    pub frames: Vec<ReplicaFrame>,
}

/// Exclusive append-only storage for one public source, room and random epoch.
/// Opening reconstructs the complete verified prefix with bounded memory.
/// Ordinary operations use that proof and checked immutable records; they never
/// rebuild a lifetime in-memory index or accept an advertised cursor as proof.
pub struct Replica {
    store: Store,
    accumulator: SourceAccumulator,
    image: Vec<u8>,
    poisoned: bool,
    #[cfg(test)]
    fault: Option<PublicationPoint>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublicationPoint {
    BeforePublish,
    AfterPublish,
}

impl Replica {
    /// Create an absent namespace and atomically retain its exact pinned genesis
    /// and first checkpoint. A partially created namespace is preserved, never
    /// reset on a later open or create. No signing identity is opened or created.
    pub fn create_new(
        path: impl AsRef<Path>,
        genesis: PinnedGenesis,
        source: [u8; 32],
        limits: Limits,
    ) -> ReplicaResult<Self> {
        if source == [0; 32] {
            return Err(vhalla_direct_sync::Error::Source.into());
        }
        let mut epoch = [0; 32];
        getrandom::fill(&mut epoch).map_err(|_| ReplicaError::Entropy)?;
        if epoch == [0; 32] {
            return Err(ReplicaError::Entropy);
        }
        let bytes = genesis.encode();
        let frame = Frame {
            kind: FrameKind::Genesis,
            bytes: &bytes,
        };
        let mut accumulator = SourceAccumulator::new(source, genesis, epoch)?;
        accumulator.push(frame)?;
        let checkpoint = accumulator.checkpoint()?;
        let record = encode_record(checkpoint, frame)?;
        if limits.max_records == 0 || limits.max_record_bytes < record.as_bytes().len() as u64 {
            return Err(vhalla_direct_store::Error::Refused.into());
        }
        let image = encode_image(checkpoint);
        let context = Context::new(*checkpoint.room.as_bytes(), source)?;
        let mut store = Store::create_new(path, context, limits)?;
        store.publish(None, &image, &[record])?;
        check_store(&mut store, checkpoint, &image).map_err(|_| uncertain())?;
        Ok(Self {
            store,
            accumulator,
            image,
            poisoned: false,
            #[cfg(test)]
            fault: None,
        })
    }

    /// Open under independently selected room and source identities. Every frame
    /// is replayed and checked against its retained cumulative digest and the
    /// image. Missing or foreign images are refused without initialization.
    pub fn open(
        path: impl AsRef<Path>,
        genesis: PinnedGenesis,
        source: [u8; 32],
    ) -> ReplicaResult<Self> {
        if source == [0; 32] {
            return Err(vhalla_direct_sync::Error::Source.into());
        }
        let context = Context::new(*genesis.id().as_bytes(), source)?;
        let mut store = Store::open(path, context)?;
        let image = store.load()?.ok_or_else(corrupt)?;
        let target = decode_image(&image)?;
        if target.source != source || target.room != genesis.id() {
            return Err(corrupt());
        }
        check_store(&mut store, target, &image)?;
        let mut accumulator =
            SourceAccumulator::new(source, genesis, target.epoch).map_err(|_| corrupt())?;
        let mut after = 0;
        while after < target.records {
            let page = store.page(after, vhalla_direct_store::MAX_PAGE_RECORDS)?;
            if page.tip != target.records || page.records.is_empty() {
                return Err(corrupt());
            }
            for entry in page.records {
                let retained = decode_entry(&entry)?;
                if entry.cursor != after + 1 {
                    return Err(corrupt());
                }
                accumulator.push(retained.frame).map_err(|_| corrupt())?;
                let checked = accumulator.checkpoint().map_err(|_| corrupt())?;
                if retained.checkpoint(target) != checked {
                    return Err(corrupt());
                }
                after = entry.cursor;
            }
        }
        if accumulator.checkpoint().map_err(|_| corrupt())? != target {
            return Err(corrupt());
        }
        Ok(Self {
            store,
            accumulator,
            image,
            poisoned: false,
            #[cfg(test)]
            fault: None,
        })
    }

    /// Copy the current frozen checkpoint. It covers this source only, and is
    /// not authenticated to a network recipient until the transport binds it.
    pub fn checkpoint(&mut self) -> ReplicaResult<Checkpoint> {
        self.ready()?;
        let result = self
            .accumulator
            .checkpoint()
            .map_err(ReplicaError::from)
            .and_then(|target| {
                check_store(&mut self.store, target, &self.image)?;
                Ok(target)
            });
        self.finish_read(result)
    }

    /// Retrieve one retained signed frame by its exact kind and whole-frame
    /// SHA-256. This is a local immutable lookup, not source-order coverage or
    /// room admission. The append/open proof and checked position are reused;
    /// no lifetime history scan is performed.
    pub fn lookup(
        &mut self,
        kind: FrameKind,
        frame_hash: [u8; 32],
    ) -> ReplicaResult<Option<ReplicaFrame>> {
        self.ready()?;
        if frame_hash == [0; 32] {
            return Err(vhalla_direct_sync::Error::Bounds.into());
        }
        let current = self.checkpoint()?;
        let result = (|| {
            let mut key = [0; 33];
            key[0] = kind as u8;
            key[1..].copy_from_slice(&frame_hash);
            let Some(raw) = self.store.read(key)? else {
                return Ok(None);
            };
            let retained = decode_record(key, &raw)?;
            if retained.position > current.records || retained.bytes > current.bytes {
                return Err(corrupt());
            }
            let page = self.store.page(retained.position - 1, 1)?;
            let entry = page.records.first().ok_or_else(corrupt)?;
            if page.tip != current.records
                || entry.cursor != retained.position
                || entry.key != key
                || entry.data != raw
            {
                return Err(corrupt());
            }
            Ok(Some(ReplicaFrame {
                kind,
                bytes: retained.frame.bytes.to_vec(),
            }))
        })();
        self.finish_read(result)
    }

    /// Atomically append up to eight offered frames, deduplicating exact kind
    /// and byte retries within the call and against retained history. Empty or
    /// duplicate-only calls do not change the checkpoint or store generation.
    /// Refusal leaves the live accumulator unchanged. Any uncertain publication
    /// disables this handle until it is dropped and explicitly reopened.
    pub fn append(&mut self, frames: &[Frame<'_>]) -> ReplicaResult<Checkpoint> {
        self.ready()?;
        if frames.len() > vhalla_direct_store::MAX_TRANSACTION_RECORDS {
            return Err(vhalla_direct_sync::Error::Bounds.into());
        }
        let current = self.checkpoint()?;
        let mut next = self.accumulator.clone();
        let mut records: Vec<Record> = Vec::new();
        let prepared = (|| {
            for frame in frames {
                let key = frame_key(*frame)?;
                if let Some(record) = records.iter().find(|record| record.key() == key) {
                    let retained = decode_record(key, record.as_bytes())?;
                    if retained.frame.bytes != frame.bytes {
                        return Err(vhalla_direct_store::Error::Conflict.into());
                    }
                    continue;
                }
                if let Some(raw) = self.store.read(key)? {
                    let retained = decode_record(key, &raw)?;
                    if retained.position > current.records || retained.bytes > current.bytes {
                        return Err(corrupt());
                    }
                    if retained.frame.bytes != frame.bytes {
                        return Err(vhalla_direct_store::Error::Conflict.into());
                    }
                    continue;
                }
                next.push(*frame)?;
                records.push(encode_record(next.checkpoint()?, *frame)?);
            }
            Ok(())
        })();
        self.finish_read(prepared)?;
        if records.is_empty() {
            return Ok(current);
        }
        let target = next.checkpoint()?;
        let image = encode_image(target);
        self.poisoned = true;
        self.hit(PublicationPoint::BeforePublish)?;
        if let Err(error) = self.store.publish(Some(&self.image), &image, &records) {
            if error == vhalla_direct_store::Error::Refused {
                self.poisoned = false;
            }
            return Err(error.into());
        }
        self.hit(PublicationPoint::AfterPublish)?;
        check_store(&mut self.store, target, &image).map_err(|_| uncertain())?;
        self.accumulator = next;
        self.image = image;
        self.poisoned = false;
        Ok(target)
    }

    /// Read a nonempty page after a local cursor, capped at the exact frozen
    /// target. A completed range returns None. The target must match a retained
    /// prefix of this source and epoch, including its exact byte total and hash.
    /// An old checkpoint remains usable after later appends.
    pub fn page(
        &mut self,
        target: Checkpoint,
        after: u64,
        limit: usize,
    ) -> ReplicaResult<Option<ReplicaPage>> {
        self.ready()?;
        if limit == 0 || limit > vhalla_direct_sync::MAX_PAGE_FRAMES {
            return Err(vhalla_direct_sync::Error::Bounds.into());
        }
        let current = self.checkpoint()?;
        if target.source != current.source {
            return Err(vhalla_direct_sync::Error::Source.into());
        }
        if target.room != current.room {
            return Err(vhalla_direct_sync::Error::Room.into());
        }
        if target.epoch != current.epoch {
            return Err(vhalla_direct_sync::Error::Epoch.into());
        }
        if target.records == 0 || target.records > current.records {
            return Err(vhalla_direct_sync::Error::Bounds.into());
        }
        if after > target.records {
            return Err(vhalla_direct_sync::Error::Sequence.into());
        }
        let result = self.page_inner(target, after, limit);
        self.finish_read(result)
    }

    fn page_inner(
        &mut self,
        target: Checkpoint,
        after: u64,
        limit: usize,
    ) -> ReplicaResult<Option<ReplicaPage>> {
        if self.retained_checkpoint(target.records, target)? != target {
            return Err(vhalla_direct_sync::Error::Checkpoint.into());
        }
        if after == target.records {
            return Ok(None);
        }
        let mut previous_bytes = if after == 0 {
            0
        } else {
            self.retained_checkpoint(after, target)?.bytes
        };
        let count = limit.min((target.records - after) as usize);
        let page = self.store.page(after, count)?;
        if page.records.len() != count {
            return Err(corrupt());
        }
        let mut frames = Vec::with_capacity(count);
        for (offset, entry) in page.records.iter().enumerate() {
            let retained = decode_entry(entry)?;
            if retained.position != after + offset as u64 + 1
                || retained.bytes != previous_bytes + retained.frame.bytes.len() as u64
            {
                return Err(corrupt());
            }
            if retained.position == target.records && retained.checkpoint(target) != target {
                return Err(corrupt());
            }
            previous_bytes = retained.bytes;
            frames.push(ReplicaFrame {
                kind: retained.frame.kind,
                bytes: retained.frame.bytes.to_vec(),
            });
        }
        Ok(Some(ReplicaPage {
            checkpoint: target,
            first: after + 1,
            last: after + count as u64,
            frames,
        }))
    }

    // Append/open established the rolling-chain invariant for every immutable
    // source position. Point reads check the stored payload before reusing it;
    // no external checkpoint or numeric cursor establishes that invariant.
    fn retained_checkpoint(
        &mut self,
        position: u64,
        scope: Checkpoint,
    ) -> ReplicaResult<Checkpoint> {
        let page = self.store.page(position - 1, 1)?;
        let entry = page.records.first().ok_or_else(corrupt)?;
        if entry.cursor != position {
            return Err(corrupt());
        }
        Ok(decode_entry(entry)?.checkpoint(scope))
    }

    /// Local encoded-record usage. Payload allowances include each frame's
    /// storage header; checkpoint byte totals count signed wire bytes only.
    pub fn accounting(&mut self) -> ReplicaResult<Accounting> {
        let target = self.checkpoint()?;
        let result = check_store(&mut self.store, target, &self.image);
        self.finish_read(result)
    }

    /// Raise storage allowances without changing any checkpoint, record or epoch.
    /// Decreases and pruning are unsupported. Physical free space is separate.
    pub fn expand_limits(&mut self, target: Limits) -> ReplicaResult<Accounting> {
        let checkpoint = self.checkpoint()?;
        let expanded = self.store.expand_limits(target).map_err(ReplicaError::from);
        self.finish_read(expanded)?;
        let result = check_store(&mut self.store, checkpoint, &self.image);
        self.finish_read(result)
    }

    fn ready(&self) -> ReplicaResult<()> {
        if self.poisoned {
            return Err(uncertain());
        }
        Ok(())
    }

    fn finish_read<T>(&mut self, result: ReplicaResult<T>) -> ReplicaResult<T> {
        if matches!(
            &result,
            Err(ReplicaError::Store(
                vhalla_direct_store::Error::Corrupt
                    | vhalla_direct_store::Error::Uncertain
                    | vhalla_direct_store::Error::Conflict
            ))
        ) {
            self.poisoned = true;
        }
        result
    }

    fn hit(&mut self, point: PublicationPoint) -> ReplicaResult<()> {
        let _ = point;
        #[cfg(test)]
        if self.fault == Some(point) {
            self.fault = None;
            return Err(uncertain());
        }
        Ok(())
    }
}

struct Retained<'a> {
    position: u64,
    bytes: u64,
    digest: [u8; 32],
    frame: Frame<'a>,
}
impl Retained<'_> {
    fn checkpoint(&self, scope: Checkpoint) -> Checkpoint {
        Checkpoint {
            records: self.position,
            bytes: self.bytes,
            digest: self.digest,
            ..scope
        }
    }
}

fn frame_key(frame: Frame<'_>) -> ReplicaResult<[u8; 33]> {
    let bound = match frame.kind {
        FrameKind::Genesis => MAX_GENESIS_BYTES,
        FrameKind::Policy => MAX_POLICY_BYTES,
        FrameKind::Event => MAX_EVENT_BYTES,
    };
    if frame.bytes.is_empty() || frame.bytes.len() > bound {
        return Err(vhalla_direct_sync::Error::Bounds.into());
    }
    let mut key = [0; 33];
    key[0] = frame.kind as u8;
    key[1..].copy_from_slice(&Sha256::digest(frame.bytes));
    Ok(key)
}

fn encode_record(checkpoint: Checkpoint, frame: Frame<'_>) -> ReplicaResult<Record> {
    let mut raw = Vec::with_capacity(RECORD_HEADER + frame.bytes.len());
    raw.extend_from_slice(RECORD_MAGIC);
    raw.push(frame.kind as u8);
    raw.extend_from_slice(&checkpoint.records.to_be_bytes());
    raw.extend_from_slice(&checkpoint.bytes.to_be_bytes());
    raw.extend_from_slice(&checkpoint.digest);
    raw.extend_from_slice(frame.bytes);
    Ok(Record::new(frame_key(frame)?, &raw)?)
}

fn decode_entry(entry: &Entry) -> ReplicaResult<Retained<'_>> {
    let retained = decode_record(entry.key, &entry.data)?;
    if retained.position != entry.cursor {
        return Err(corrupt());
    }
    Ok(retained)
}

fn decode_record(key: [u8; 33], raw: &[u8]) -> ReplicaResult<Retained<'_>> {
    if raw.len() <= RECORD_HEADER || &raw[..8] != RECORD_MAGIC {
        return Err(corrupt());
    }
    let kind = match raw[8] {
        1 => FrameKind::Genesis,
        2 => FrameKind::Policy,
        3 => FrameKind::Event,
        _ => return Err(corrupt()),
    };
    let frame = Frame {
        kind,
        bytes: &raw[RECORD_HEADER..],
    };
    if frame_key(frame).map_err(|_| corrupt())? != key {
        return Err(corrupt());
    }
    let position = u64::from_be_bytes(array(&raw[9..17])?);
    let bytes = u64::from_be_bytes(array(&raw[17..25])?);
    if position == 0
        || position > vhalla_direct_sync::MAX_SNAPSHOT_RECORDS
        || bytes < frame.bytes.len() as u64
        || bytes > vhalla_direct_sync::MAX_SNAPSHOT_BYTES
        || (position == 1) != (kind == FrameKind::Genesis)
    {
        return Err(corrupt());
    }
    Ok(Retained {
        position,
        bytes,
        digest: array(&raw[25..57])?,
        frame,
    })
}

fn encode_image(checkpoint: Checkpoint) -> Vec<u8> {
    let mut raw = Vec::with_capacity(IMAGE_BYTES);
    raw.extend_from_slice(IMAGE_MAGIC);
    raw.extend_from_slice(&checkpoint.source);
    raw.extend_from_slice(checkpoint.room.as_bytes());
    raw.extend_from_slice(&checkpoint.epoch);
    raw.extend_from_slice(&checkpoint.records.to_be_bytes());
    raw.extend_from_slice(&checkpoint.bytes.to_be_bytes());
    raw.extend_from_slice(&checkpoint.digest);
    raw
}

fn decode_image(raw: &[u8]) -> ReplicaResult<Checkpoint> {
    if raw.len() != IMAGE_BYTES || &raw[..8] != IMAGE_MAGIC {
        return Err(corrupt());
    }
    let checkpoint = Checkpoint {
        source: array(&raw[8..40])?,
        room: RoomId::from_bytes(array(&raw[40..72])?),
        epoch: array(&raw[72..104])?,
        records: u64::from_be_bytes(array(&raw[104..112])?),
        bytes: u64::from_be_bytes(array(&raw[112..120])?),
        digest: array(&raw[120..152])?,
    };
    if checkpoint.source == [0; 32]
        || checkpoint.epoch == [0; 32]
        || checkpoint.records == 0
        || checkpoint.records > vhalla_direct_sync::MAX_SNAPSHOT_RECORDS
        || checkpoint.bytes == 0
        || checkpoint.bytes > vhalla_direct_sync::MAX_SNAPSHOT_BYTES
    {
        return Err(corrupt());
    }
    Ok(checkpoint)
}

fn check_store(
    store: &mut Store,
    checkpoint: Checkpoint,
    image: &[u8],
) -> ReplicaResult<Accounting> {
    if store.load()?.as_deref() != Some(image) {
        return Err(corrupt());
    }
    let accounting = store.accounting()?;
    if accounting.records != checkpoint.records
        || accounting.tip != checkpoint.records
        || accounting.bytes != checkpoint.bytes + checkpoint.records * RECORD_HEADER as u64
        || accounting.generation == 0
        || accounting.generation > checkpoint.records
    {
        return Err(corrupt());
    }
    Ok(accounting)
}

fn array<const N: usize>(raw: &[u8]) -> ReplicaResult<[u8; N]> {
    raw.try_into().map_err(|_| corrupt())
}
fn corrupt() -> ReplicaError {
    vhalla_direct_store::Error::Corrupt.into()
}
fn uncertain() -> ReplicaError {
    vhalla_direct_store::Error::Uncertain.into()
}

#[cfg(test)]
#[path = "replica_tests.rs"]
mod tests;
