//! Durable verification of one selected source, backed by a shared signed log.
//!
//! Source-order records contain hashes, not duplicate message bodies. Opening
//! replays every reference through the pure verifier. Projection into a local
//! authoring controller is separate and may lag this ledger's verified storage.

use crate::{Replica, ReplicaError, ReplicaFrame};
use sha2::{Digest as _, Sha256};
use std::path::Path;
use vhalla_direct_room::{PinnedGenesis, RoomId};
use vhalla_direct_store::{Accounting, Context, Entry, Limits, Record, Store};
use vhalla_direct_sync::{Checkpoint, Coverage, Frame, FrameKind, Page, Progress, Receiver};

const IMAGE_MAGIC: &[u8; 8] = b"VHFL0001";
const TARGET_MAGIC: &[u8; 8] = b"VHFT0001";
const PAGE_MAGIC: &[u8; 8] = b"VHFP0001";
const IMAGE_BYTES: usize = 328;
const CHECKPOINT_BYTES: usize = 144;
const PAGE_HEADER: usize = 57;
const TARGET: u8 = 1;
const PAGE: u8 = 2;

/// Local follower failures. No error authorizes deleting or resetting history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FollowerError {
    /// Source authentication, signed input or snapshot verification failed.
    Sync(vhalla_direct_sync::Error),
    /// The progress ledger refused input or requires explicit reopening.
    Store(vhalla_direct_store::Error),
    /// The shared signed-frame store refused the operation or needs reopening.
    Replica(ReplicaError),
    /// The backing replica is from a different room/source/incarnation, or a
    /// previously retained reference is missing. No progress may be inherited.
    Backing,
}
impl core::fmt::Display for FollowerError {
    fn fmt(&self, output: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(output, "{self:?}")
    }
}
impl std::error::Error for FollowerError {}
impl From<vhalla_direct_sync::Error> for FollowerError {
    fn from(error: vhalla_direct_sync::Error) -> Self {
        Self::Sync(error)
    }
}
impl From<vhalla_direct_store::Error> for FollowerError {
    fn from(error: vhalla_direct_store::Error) -> Self {
        Self::Store(error)
    }
}
impl From<ReplicaError> for FollowerError {
    fn from(error: ReplicaError) -> Self {
        Self::Replica(error)
    }
}
/// Durable selected-source verification result.
pub type FollowerResult<T> = Result<T, FollowerError>;

/// Evidence for the selected source only. Partial prefixes are not inclusion
/// proofs; complete coverage says nothing about other sources or room admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FollowerStatus {
    /// Exact frozen checkpoint authenticated when it was accepted.
    pub target: Checkpoint,
    /// Contiguous source-order frames verified and durably referenced locally.
    pub progress: Progress,
    /// Complete only when count, wire bytes and rolling hash match the target.
    pub coverage: Coverage,
    /// Minimum verified local backing prefix used by this open handle. This
    /// storage basis is independent of source-order coverage and room admission.
    pub backing_floor: Checkpoint,
}

/// A new durable page or an exact previously committed page retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FollowerOutcome {
    /// Current target and progress, which may be newer than an exact old retry.
    pub status: FollowerStatus,
    /// The exact checkpoint, page boundaries and frame hashes already existed.
    pub exact_retry: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Backing {
    source: [u8; 32],
    epoch: [u8; 32],
    progress: Progress,
}
impl Backing {
    fn from_checkpoint(checkpoint: Checkpoint) -> Self {
        Self {
            source: checkpoint.source,
            epoch: checkpoint.epoch,
            progress: Progress {
                records: checkpoint.records,
                bytes: checkpoint.bytes,
                digest: checkpoint.digest,
            },
        }
    }
    fn checkpoint(self, room: RoomId) -> Checkpoint {
        Checkpoint {
            source: self.source,
            room,
            epoch: self.epoch,
            records: self.progress.records,
            bytes: self.progress.bytes,
            digest: self.progress.digest,
        }
    }
    fn check(self, backing: &mut Replica, room: RoomId) -> FollowerResult<Checkpoint> {
        let checkpoint = backing.checkpoint()?;
        if checkpoint.source != self.source
            || checkpoint.epoch != self.epoch
            || checkpoint.room != room
        {
            return Err(FollowerError::Backing);
        }
        let floor = self.checkpoint(room);
        match backing.page(floor, floor.records, 1) {
            Ok(None) => Ok(checkpoint),
            Ok(Some(_)) | Err(ReplicaError::Sync(_)) => Err(FollowerError::Backing),
            Err(error) => Err(error.into()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Saved {
    backing: Backing,
    target: Checkpoint,
    progress: Progress,
    events: u64,
    bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Reference {
    kind: FrameKind,
    hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct References {
    checkpoint: [u8; 32],
    first: u64,
    last: u64,
    frames: Vec<Reference>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublicationPoint {
    AfterBackingBatch,
    BeforePublish,
    AfterPublish,
}

/// One exclusively held selected-source progress ledger. It owns no identity,
/// authoring controller or network connection. The caller authenticates every
/// new target and page source through its configured transport.
pub struct Follower {
    store: Store,
    receiver: Receiver,
    saved: Saved,
    checked_backing: Backing,
    image: Vec<u8>,
    poisoned: bool,
    #[cfg(test)]
    fault: Option<PublicationPoint>,
}

impl Follower {
    /// Begin at zero under independently configured and authenticated source
    /// identities. The checkpoint itself must be authenticated by the caller.
    /// Partial creation is preserved and never reused as a new empty ledger.
    pub fn create_new(
        path: impl AsRef<Path>,
        genesis: PinnedGenesis,
        expected_source: [u8; 32],
        authenticated_source: [u8; 32],
        target: Checkpoint,
        backing: &mut Replica,
        limits: Limits,
    ) -> FollowerResult<Self> {
        let receiver = Receiver::begin(genesis, expected_source, authenticated_source, target)?;
        let replica = backing.checkpoint()?;
        if replica.room != target.room {
            return Err(FollowerError::Backing);
        }
        let record = target_record(target)?;
        if limits.max_records == 0 || limits.max_record_bytes < record.as_bytes().len() as u64 {
            return Err(vhalla_direct_store::Error::Refused.into());
        }
        let saved = Saved {
            backing: Backing::from_checkpoint(replica),
            target,
            progress: receiver.progress(),
            events: 1,
            bytes: record.as_bytes().len() as u64,
        };
        let image = encode_image(saved);
        let mut store = Store::create_new(path, context(target.room, expected_source)?, limits)?;
        store.publish(None, &image, &[record])?;
        check_store(&mut store, saved, &image).map_err(|_| uncertain())?;
        Ok(Self {
            store,
            receiver,
            saved,
            checked_backing: saved.backing,
            image,
            poisoned: false,
            #[cfg(test)]
            fault: None,
        })
    }

    /// Replay every durable target and page through a fresh pure Receiver using
    /// actual backing bytes. Saved positions/hashes are comparisons, never a
    /// trusted resume setter. Local authenticated checkpoint receipts are replayed;
    /// this does not fabricate authentication of a new network connection.
    pub fn open(
        path: impl AsRef<Path>,
        genesis: PinnedGenesis,
        expected_source: [u8; 32],
        backing: &mut Replica,
    ) -> FollowerResult<Self> {
        let mut store = Store::open(path, context(genesis.id(), expected_source)?)?;
        let image = store.load()?.ok_or_else(corrupt)?;
        let saved = decode_image(&image)?;
        if saved.target.source != expected_source || saved.target.room != genesis.id() {
            return Err(corrupt());
        }
        saved.backing.check(backing, genesis.id())?;
        check_store(&mut store, saved, &image)?;
        let mut receiver: Option<Receiver> = None;
        let mut after = 0;
        let mut bytes = 0u64;
        while after < saved.events {
            let page = store.page(after, vhalla_direct_store::MAX_PAGE_RECORDS)?;
            if page.tip != saved.events || page.records.is_empty() {
                return Err(corrupt());
            }
            for entry in page.records {
                if entry.cursor != after + 1 {
                    return Err(corrupt());
                }
                match entry.key[0] {
                    TARGET => {
                        let target = decode_target(&entry)?;
                        if let Some(receiver) = &mut receiver {
                            if target == receiver.target() {
                                return Err(corrupt());
                            }
                            receiver
                                .extend(expected_source, target)
                                .map_err(|_| corrupt())?;
                        } else {
                            if entry.cursor != 1 {
                                return Err(corrupt());
                            }
                            receiver = Some(
                                Receiver::begin(
                                    genesis.clone(),
                                    expected_source,
                                    expected_source,
                                    target,
                                )
                                .map_err(|_| corrupt())?,
                            );
                        }
                    }
                    PAGE => {
                        let refs = decode_references(&entry.data)?;
                        if entry.key != page_key(refs.first) {
                            return Err(corrupt());
                        }
                        let frames = load_frames(backing, &refs)?;
                        let borrowed: Vec<_> = frames.iter().map(ReplicaFrame::as_frame).collect();
                        let receiver = receiver.as_mut().ok_or_else(corrupt)?;
                        let prepared = receiver
                            .prepare_page(refs.page(&borrowed))
                            .map_err(|_| corrupt())?;
                        receiver
                            .commit_after_persist(prepared)
                            .map_err(|_| corrupt())?;
                    }
                    _ => return Err(corrupt()),
                }
                bytes = bytes
                    .checked_add(entry.data.len() as u64)
                    .ok_or_else(corrupt)?;
                after = entry.cursor;
            }
        }
        let receiver = receiver.ok_or_else(corrupt)?;
        if receiver.target() != saved.target
            || receiver.progress() != saved.progress
            || bytes != saved.bytes
        {
            return Err(corrupt());
        }
        // Replay found every actual reference in this current replica. Pin that
        // verified prefix in memory, even if a persisted floor was smaller.
        // A subsequently supplied older object may not inherit this proof.
        let checked_backing = Backing::from_checkpoint(saved.backing.check(backing, genesis.id())?);
        check_store(&mut store, saved, &image)?;
        Ok(Self {
            store,
            receiver,
            saved,
            checked_backing,
            image,
            poisoned: false,
            #[cfg(test)]
            fault: None,
        })
    }

    /// Inspect the exact durable prefix and current backing incarnation. An
    /// in-memory handle cannot inherit progress from a replacement replica.
    pub fn status(&mut self, backing: &mut Replica) -> FollowerResult<FollowerStatus> {
        self.check(backing)?;
        Ok(self.snapshot())
    }

    /// Return the exact first authenticated target retained before any source
    /// progress. Hosts use this to bind a reopened follower to their own durable
    /// creation intent, including after the source's target has been extended.
    pub fn initial_target(&mut self, backing: &mut Replica) -> FollowerResult<Checkpoint> {
        self.check(backing)?;
        let result = (|| {
            let page = self.store.page(0, 1)?;
            if page.tip != self.saved.events
                || page.records.len() != 1
                || page.records[0].cursor != 1
                || page.records[0].key[0] != TARGET
            {
                return Err(corrupt());
            }
            decode_target(&page.records[0])
        })();
        self.finish_read(result)
    }

    /// Accept one source-authenticated page. Full verification precedes writes;
    /// backing frames precede atomic reference/progress publication. Exact retry
    /// means identical page boundaries, checkpoint and bytes; a different split
    /// of an already consumed range is not a resume operation.
    pub fn receive(
        &mut self,
        authenticated_source: [u8; 32],
        page: Page<'_>,
        backing: &mut Replica,
    ) -> FollowerResult<FollowerOutcome> {
        self.ready()?;
        if authenticated_source != self.saved.target.source {
            return Err(vhalla_direct_sync::Error::Source.into());
        }
        self.check(backing)?;
        let refs = References::from_page(page)?;
        let record = Record::new(page_key(refs.first), &refs.encode())?;
        if refs.first <= self.receiver.progress().records {
            let retained = self.store.read(record.key()).map_err(FollowerError::from);
            let retained = self.finish_read(retained)?;
            if retained.as_deref() != Some(record.as_bytes()) {
                return Err(vhalla_direct_sync::Error::Sequence.into());
            }
            // Re-check availability even on an exact retry; no duplicate frame
            // append or publication is needed to acknowledge these same bytes.
            let loaded = load_frames(backing, &refs);
            self.finish_read(loaded)?;
            return Ok(FollowerOutcome {
                status: self.status(backing)?,
                exact_retry: true,
            });
        }
        let prepared = self.receiver.prepare_page(page)?;
        let mut next = self.next_saved(
            self.receiver.target(),
            prepared.progress(),
            record.as_bytes().len(),
        )?;
        self.preflight(&record)?;
        let frames: Vec<_> = prepared
            .frames()
            .iter()
            .map(|frame| ReplicaFrame {
                kind: frame.kind(),
                bytes: frame.encode(),
            })
            .collect();
        let mut checkpoint = backing.checkpoint()?;
        let mut backing_changed = false;
        self.poisoned = true;
        for chunk in frames.chunks(vhalla_direct_store::MAX_TRANSACTION_RECORDS) {
            let borrowed: Vec<_> = chunk.iter().map(ReplicaFrame::as_frame).collect();
            match backing.append(&borrowed) {
                Ok(after) => {
                    backing_changed |= after != checkpoint;
                    checkpoint = after;
                }
                Err(error) => {
                    if !backing_changed && definite_replica_refusal(error) {
                        self.poisoned = false;
                    }
                    return Err(error.into());
                }
            }
            self.hit(PublicationPoint::AfterBackingBatch)?;
        }
        next.backing = Backing::from_checkpoint(checkpoint);
        self.publish(record, next, !backing_changed)?;
        self.receiver
            .commit_after_persist(prepared)
            .map_err(|_| uncertain())?;
        self.poisoned = false;
        let status = self.status(backing)?;
        Ok(FollowerOutcome {
            status,
            exact_retry: false,
        })
    }

    /// Record a new authenticated target only after the previous one completed.
    /// Repeating the current target is a no-op, including while it is pending.
    /// A changed epoch, rollback or fork preserves all prior references.
    pub fn extend(
        &mut self,
        authenticated_source: [u8; 32],
        target: Checkpoint,
        backing: &mut Replica,
    ) -> FollowerResult<FollowerStatus> {
        self.ready()?;
        if authenticated_source != self.saved.target.source || target.source != authenticated_source
        {
            return Err(vhalla_direct_sync::Error::Source.into());
        }
        self.check(backing)?;
        if target == self.receiver.target() {
            return Ok(self.snapshot());
        }
        let record = target_record(target)?;
        self.preflight(&record)?;
        // Receiver validates everything before its target changes. From that
        // point until durable publication this handle is fenced, including on a
        // definite store refusal: no arbitrary old-target setter is introduced.
        self.receiver.extend(authenticated_source, target)?;
        self.poisoned = true;
        let next = self.next_saved(target, self.receiver.progress(), record.as_bytes().len())?;
        self.publish(record, next, false)?;
        self.poisoned = false;
        self.status(backing)
    }

    /// Retained ledger bytes count target records and hash references only.
    /// Signed frame storage is accounted independently by the shared replica.
    pub fn accounting(&mut self, backing: &mut Replica) -> FollowerResult<Accounting> {
        self.check(backing)
    }

    /// Grow local ledger capacity without resetting source progress or history.
    /// The backing replica has its own independently selected capacity.
    pub fn expand_limits(
        &mut self,
        target: Limits,
        backing: &mut Replica,
    ) -> FollowerResult<Accounting> {
        self.check(backing)?;
        let result = self
            .store
            .expand_limits(target)
            .map_err(FollowerError::from);
        self.finish_read(result)?;
        self.check(backing)
    }

    fn snapshot(&self) -> FollowerStatus {
        FollowerStatus {
            target: self.receiver.target(),
            progress: self.receiver.progress(),
            coverage: self.receiver.coverage(),
            backing_floor: self.checked_backing.checkpoint(self.saved.target.room),
        }
    }

    fn ready(&self) -> FollowerResult<()> {
        if self.poisoned {
            return Err(uncertain());
        }
        Ok(())
    }

    fn check(&mut self, backing: &mut Replica) -> FollowerResult<Accounting> {
        self.ready()?;
        let result = (|| {
            self.checked_backing
                .check(backing, self.saved.target.room)?;
            if self.receiver.target() != self.saved.target
                || self.receiver.progress() != self.saved.progress
            {
                return Err(corrupt());
            }
            check_store(&mut self.store, self.saved, &self.image)
        })();
        self.finish_read(result)
    }

    fn finish_read<T>(&mut self, result: FollowerResult<T>) -> FollowerResult<T> {
        if matches!(
            &result,
            Err(FollowerError::Backing
                | FollowerError::Store(
                    vhalla_direct_store::Error::Corrupt
                        | vhalla_direct_store::Error::Conflict
                        | vhalla_direct_store::Error::Uncertain
                ))
                | Err(FollowerError::Replica(ReplicaError::Store(
                    vhalla_direct_store::Error::Corrupt
                        | vhalla_direct_store::Error::Conflict
                        | vhalla_direct_store::Error::Uncertain
                )))
        ) {
            self.poisoned = true;
        }
        result
    }

    fn next_saved(
        &self,
        target: Checkpoint,
        progress: Progress,
        added_bytes: usize,
    ) -> FollowerResult<Saved> {
        Ok(Saved {
            backing: self.checked_backing,
            target,
            progress,
            events: self.saved.events.checked_add(1).ok_or_else(corrupt)?,
            bytes: self
                .saved
                .bytes
                .checked_add(added_bytes as u64)
                .ok_or_else(corrupt)?,
        })
    }

    fn preflight(&mut self, record: &Record) -> FollowerResult<()> {
        let accounting = self.store.accounting().map_err(FollowerError::from);
        let accounting = self.finish_read(accounting)?;
        if accounting.records + 1 > accounting.limits.max_records
            || accounting.bytes + record.as_bytes().len() as u64
                > accounting.limits.max_record_bytes
        {
            return Err(vhalla_direct_store::Error::Refused.into());
        }
        Ok(())
    }

    fn publish(
        &mut self,
        record: Record,
        next: Saved,
        unchanged_on_refusal: bool,
    ) -> FollowerResult<()> {
        self.poisoned = true;
        let image = encode_image(next);
        self.hit(PublicationPoint::BeforePublish)?;
        if let Err(error) = self.store.publish(Some(&self.image), &image, &[record]) {
            if error == vhalla_direct_store::Error::Refused && unchanged_on_refusal {
                self.poisoned = false;
            }
            return Err(error.into());
        }
        self.hit(PublicationPoint::AfterPublish)?;
        check_store(&mut self.store, next, &image).map_err(|_| uncertain())?;
        self.saved = next;
        self.checked_backing = next.backing;
        self.image = image;
        // The caller still has to commit the exact prepared pure-verifier token.
        Ok(())
    }

    fn hit(&mut self, point: PublicationPoint) -> FollowerResult<()> {
        let _ = point;
        #[cfg(test)]
        if self.fault == Some(point) {
            self.fault = None;
            return Err(uncertain());
        }
        Ok(())
    }
}

fn definite_replica_refusal(error: ReplicaError) -> bool {
    matches!(
        error,
        ReplicaError::Sync(_) | ReplicaError::Store(vhalla_direct_store::Error::Refused)
    )
}

fn context(room: RoomId, source: [u8; 32]) -> FollowerResult<Context> {
    Ok(Context::new(*room.as_bytes(), source)?)
}
fn corrupt() -> FollowerError {
    vhalla_direct_store::Error::Corrupt.into()
}
fn uncertain() -> FollowerError {
    vhalla_direct_store::Error::Uncertain.into()
}
fn array<const N: usize>(raw: &[u8]) -> FollowerResult<[u8; N]> {
    raw.try_into().map_err(|_| corrupt())
}

fn record_key(tag: u8, value: &[u8]) -> [u8; 33] {
    let mut hash = Sha256::new();
    hash.update(b"vhalla/direct-native/follower/v1\0");
    hash.update([tag]);
    hash.update(value);
    let mut key = [0; 33];
    key[0] = tag;
    key[1..].copy_from_slice(&hash.finalize());
    key
}
fn page_key(first: u64) -> [u8; 33] {
    record_key(PAGE, &first.to_be_bytes())
}

fn checkpoint_bytes(target: Checkpoint) -> Vec<u8> {
    let mut raw = Vec::with_capacity(CHECKPOINT_BYTES);
    raw.extend_from_slice(&target.source);
    raw.extend_from_slice(target.room.as_bytes());
    raw.extend_from_slice(&target.epoch);
    raw.extend_from_slice(&target.records.to_be_bytes());
    raw.extend_from_slice(&target.bytes.to_be_bytes());
    raw.extend_from_slice(&target.digest);
    raw
}

fn decode_checkpoint(raw: &[u8]) -> FollowerResult<Checkpoint> {
    if raw.len() != CHECKPOINT_BYTES {
        return Err(corrupt());
    }
    Ok(Checkpoint {
        source: array(&raw[..32])?,
        room: RoomId::from_bytes(array(&raw[32..64])?),
        epoch: array(&raw[64..96])?,
        records: u64::from_be_bytes(array(&raw[96..104])?),
        bytes: u64::from_be_bytes(array(&raw[104..112])?),
        digest: array(&raw[112..144])?,
    })
}

fn target_record(target: Checkpoint) -> FollowerResult<Record> {
    let mut raw = TARGET_MAGIC.to_vec();
    raw.extend(checkpoint_bytes(target));
    Ok(Record::new(record_key(TARGET, &target.id()), &raw)?)
}

fn decode_target(entry: &Entry) -> FollowerResult<Checkpoint> {
    if !entry.data.starts_with(TARGET_MAGIC) {
        return Err(corrupt());
    }
    let target = decode_checkpoint(&entry.data[TARGET_MAGIC.len()..])?;
    if entry.key != record_key(TARGET, &target.id()) {
        return Err(corrupt());
    }
    Ok(target)
}

impl References {
    fn from_page(page: Page<'_>) -> FollowerResult<Self> {
        if page.frames.is_empty() || page.frames.len() > vhalla_direct_sync::MAX_PAGE_FRAMES {
            return Err(vhalla_direct_sync::Error::Bounds.into());
        }
        if page.first == 0
            || page.last
                != page
                    .first
                    .checked_add(page.frames.len() as u64 - 1)
                    .ok_or(vhalla_direct_sync::Error::Sequence)?
        {
            return Err(vhalla_direct_sync::Error::Sequence.into());
        }
        let mut frames = Vec::with_capacity(page.frames.len());
        for frame in page.frames {
            let max = match frame.kind {
                FrameKind::Genesis => vhalla_direct_room::MAX_GENESIS_BYTES,
                FrameKind::Policy => vhalla_direct_room::MAX_POLICY_BYTES,
                FrameKind::Event => vhalla_direct_room::MAX_EVENT_BYTES,
            };
            if frame.bytes.is_empty() || frame.bytes.len() > max {
                return Err(vhalla_direct_sync::Error::Bounds.into());
            }
            frames.push(Reference {
                kind: frame.kind,
                hash: Sha256::digest(frame.bytes).into(),
            });
        }
        Ok(Self {
            checkpoint: page.checkpoint_id,
            first: page.first,
            last: page.last,
            frames,
        })
    }

    fn encode(&self) -> Vec<u8> {
        let mut raw = Vec::with_capacity(PAGE_HEADER + 33 * self.frames.len());
        raw.extend_from_slice(PAGE_MAGIC);
        raw.extend_from_slice(&self.checkpoint);
        raw.extend_from_slice(&self.first.to_be_bytes());
        raw.extend_from_slice(&self.last.to_be_bytes());
        raw.push(self.frames.len() as u8);
        for frame in &self.frames {
            raw.push(frame.kind as u8);
            raw.extend_from_slice(&frame.hash);
        }
        raw
    }

    fn page<'a>(&self, frames: &'a [Frame<'a>]) -> Page<'a> {
        Page {
            checkpoint_id: self.checkpoint,
            first: self.first,
            last: self.last,
            frames,
        }
    }
}

fn decode_references(raw: &[u8]) -> FollowerResult<References> {
    if raw.len() < PAGE_HEADER || &raw[..8] != PAGE_MAGIC {
        return Err(corrupt());
    }
    let count = usize::from(raw[56]);
    if count == 0
        || count > vhalla_direct_sync::MAX_PAGE_FRAMES
        || raw.len() != PAGE_HEADER + 33 * count
    {
        return Err(corrupt());
    }
    let first = u64::from_be_bytes(array(&raw[40..48])?);
    let last = u64::from_be_bytes(array(&raw[48..56])?);
    if first == 0
        || first.checked_add(count as u64 - 1) != Some(last)
        || last > vhalla_direct_sync::MAX_SNAPSHOT_RECORDS
    {
        return Err(corrupt());
    }
    let mut frames = Vec::with_capacity(count);
    for raw in raw[PAGE_HEADER..].as_chunks::<33>().0 {
        let kind = match raw[0] {
            1 => FrameKind::Genesis,
            2 => FrameKind::Policy,
            3 => FrameKind::Event,
            _ => return Err(corrupt()),
        };
        let hash = array(&raw[1..])?;
        if hash == [0; 32] {
            return Err(corrupt());
        }
        frames.push(Reference { kind, hash });
    }
    Ok(References {
        checkpoint: array(&raw[8..40])?,
        first,
        last,
        frames,
    })
}

fn load_frames(backing: &mut Replica, refs: &References) -> FollowerResult<Vec<ReplicaFrame>> {
    refs.frames
        .iter()
        .map(|reference| {
            backing
                .lookup(reference.kind, reference.hash)?
                .ok_or(FollowerError::Backing)
        })
        .collect()
}

fn encode_image(saved: Saved) -> Vec<u8> {
    let mut raw = Vec::with_capacity(IMAGE_BYTES);
    raw.extend_from_slice(IMAGE_MAGIC);
    raw.extend_from_slice(&saved.backing.source);
    raw.extend_from_slice(&saved.backing.epoch);
    raw.extend_from_slice(&saved.backing.progress.records.to_be_bytes());
    raw.extend_from_slice(&saved.backing.progress.bytes.to_be_bytes());
    raw.extend_from_slice(&saved.backing.progress.digest);
    raw.extend(checkpoint_bytes(saved.target));
    raw.extend_from_slice(&saved.progress.records.to_be_bytes());
    raw.extend_from_slice(&saved.progress.bytes.to_be_bytes());
    raw.extend_from_slice(&saved.progress.digest);
    raw.extend_from_slice(&saved.events.to_be_bytes());
    raw.extend_from_slice(&saved.bytes.to_be_bytes());
    raw
}

fn decode_image(raw: &[u8]) -> FollowerResult<Saved> {
    if raw.len() != IMAGE_BYTES || &raw[..8] != IMAGE_MAGIC {
        return Err(corrupt());
    }
    let saved = Saved {
        backing: Backing {
            source: array(&raw[8..40])?,
            epoch: array(&raw[40..72])?,
            progress: Progress {
                records: u64::from_be_bytes(array(&raw[72..80])?),
                bytes: u64::from_be_bytes(array(&raw[80..88])?),
                digest: array(&raw[88..120])?,
            },
        },
        target: decode_checkpoint(&raw[120..264])?,
        progress: Progress {
            records: u64::from_be_bytes(array(&raw[264..272])?),
            bytes: u64::from_be_bytes(array(&raw[272..280])?),
            digest: array(&raw[280..312])?,
        },
        events: u64::from_be_bytes(array(&raw[312..320])?),
        bytes: u64::from_be_bytes(array(&raw[320..328])?),
    };
    if saved.backing.source == [0; 32]
        || saved.backing.epoch == [0; 32]
        || saved.backing.progress.records == 0
        || saved.backing.progress.records > vhalla_direct_sync::MAX_SNAPSHOT_RECORDS
        || saved.backing.progress.bytes == 0
        || saved.backing.progress.bytes > vhalla_direct_sync::MAX_SNAPSHOT_BYTES
        || saved.events == 0
        || saved.events > 1_000_000
        || saved.progress.records > vhalla_direct_sync::MAX_SNAPSHOT_RECORDS
        || saved.progress.bytes > vhalla_direct_sync::MAX_SNAPSHOT_BYTES
    {
        return Err(corrupt());
    }
    Ok(saved)
}

fn check_store(store: &mut Store, saved: Saved, image: &[u8]) -> FollowerResult<Accounting> {
    if store.load()?.as_deref() != Some(image) {
        return Err(corrupt());
    }
    let accounting = store.accounting()?;
    if accounting.records != saved.events
        || accounting.tip != saved.events
        || accounting.generation != saved.events
        || accounting.bytes != saved.bytes
    {
        return Err(corrupt());
    }
    Ok(accounting)
}

#[cfg(test)]
#[path = "follower_tests.rs"]
mod tests;
