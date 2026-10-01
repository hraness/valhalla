//! Local, resumable transfer between one authoring controller and signed replica.
//! The cursors describe local projection only. Source snapshot verification,
//! admission, delivery and signing reconciliation remain separate operations.

use crate::{codec, PublicRecordKind, Replica, ReplicaError, ReplicaFrame, RoomSession};
use sha2::{Digest as _, Sha256};
use std::{fs::File, path::Path};
use vhalla_direct_room::RoomId;
use vhalla_direct_store::{Accounting, Context, Entry, Limits, Record, Store};
use vhalla_direct_sync::{Checkpoint, FrameKind};

const IMAGE: &[u8; 8] = b"VHPJ0001";
const INIT: &[u8; 8] = b"VHPI0001";
const INTENT: &[u8; 8] = b"VHPN0001";
const DONE: &[u8; 8] = b"VHPD0001";
const INIT_TAG: u8 = 1;
const INTENT_TAG: u8 = 2;
const DONE_TAG: u8 = 3;
const MAX_OUTWARD: usize = 8;
// Each native receive may replay 128 ancestry frames. One inward frame keeps
// this bridge call within one reconciliation budget without changing native APIs.
const MAX_INWARD: usize = 1;
const DONE_BYTES: usize = 8 + 32 + 144 + 8;

/// The independently resumable local transfer directions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionDirection {
    /// Copy authenticated public controller records into the shared replica.
    Outward,
    /// Retain shared-replica signed frames in the native authoring controller.
    Inward,
}

/// A refusal never authorizes resetting either source or the progress ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionError {
    /// The trusted native controller refused input or requires recovery.
    Native(crate::Error),
    /// The shared signed-frame replica refused input or requires recovery.
    Replica(ReplicaError),
    /// The local progress ledger refused input or requires recovery.
    Store(vhalla_direct_store::Error),
    /// A controller identity, namespace, incarnation or retained prefix differs.
    Binding,
    /// Finish this exact retained direction before starting the other direction.
    Pending(ProjectionDirection),
}
impl core::fmt::Display for ProjectionError {
    fn fmt(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(out, "{self:?}")
    }
}
impl std::error::Error for ProjectionError {}
impl From<crate::Error> for ProjectionError {
    fn from(error: crate::Error) -> Self {
        Self::Native(error)
    }
}
impl From<ReplicaError> for ProjectionError {
    fn from(error: ReplicaError) -> Self {
        Self::Replica(error)
    }
}
impl From<vhalla_direct_store::Error> for ProjectionError {
    fn from(error: vhalla_direct_store::Error) -> Self {
        Self::Store(error)
    }
}
/// Local projection result, independent of remote-source coverage.
pub type ProjectionResult<T> = Result<T, ProjectionError>;

/// Exact durable local cursors. Numeric equality with a current local tip does
/// not assert that any other peer is current or that any message is admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionStatus {
    /// Native journal prefix whose public frames have been copied outward.
    pub outward_cursor: u64,
    /// Replica prefix whose signed frames have been durably retained natively.
    pub inward_cursor: u64,
    /// A durable exact transfer intent still awaits completion.
    pub pending: Option<ProjectionDirection>,
    /// Minimum backing prefix proved by this open handle.
    pub backing_floor: Checkpoint,
    /// Current local native journal tip, including private local metadata.
    pub native_tip: u64,
    /// Current shared-replica signed-frame tip.
    pub replica_tip: u64,
}

/// One bounded transfer, or a no-op when that local source has no new entries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionStep {
    /// The requested and completed local direction.
    pub direction: ProjectionDirection,
    /// At most eight outward frames or one inward frame, including exact retries.
    pub frames: usize,
    /// Native journal entries traversed outward, at most 128; zero inward.
    pub scanned: u64,
    /// This call resumed an already durable exact intent.
    pub resumed: bool,
    /// The resulting local projection state, not a delivery acknowledgment.
    pub status: ProjectionStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Binding {
    room: RoomId,
    author: [u8; 32],
    nonce: [u8; 32],
    created: bool,
}
impl Binding {
    fn from_room(room: &RoomSession) -> Self {
        Self {
            room: room.room_id(),
            author: room.author_key(),
            nonce: room.creation_nonce(),
            created: room.created_here,
        }
    }
    fn check(self, room: &RoomSession) -> ProjectionResult<()> {
        if self != Self::from_room(room) {
            return Err(ProjectionError::Binding);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct State {
    binding: Binding,
    backing: Checkpoint,
    outward: u64,
    inward: u64,
    native_floor: u64,
    pending: Option<[u8; 32]>,
    events: u64,
    bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Reference {
    cursor: u64,
    kind: FrameKind,
    hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Intent {
    direction: ProjectionDirection,
    from: u64,
    through: u64,
    native_tip: u64,
    backing: Checkpoint,
    frames: Vec<Reference>,
}
impl Intent {
    fn id(&self) -> [u8; 32] {
        Sha256::digest(encode_intent(self)).into()
    }
    fn check(&self, state: State) -> ProjectionResult<()> {
        if self.from
            != match self.direction {
                ProjectionDirection::Outward => state.outward,
                ProjectionDirection::Inward => state.inward,
            }
            || self.through <= self.from
            || self.native_tip < state.native_floor
        {
            return Err(corrupt());
        }
        monotonic(state.backing, self.backing)?;
        match self.direction {
            ProjectionDirection::Outward => {
                if self.through > self.native_tip
                    || self.through - self.from > crate::MAX_FILTER_SCAN as u64
                    || self.frames.len() > MAX_OUTWARD
                {
                    return Err(corrupt());
                }
            }
            ProjectionDirection::Inward => {
                if self.through > self.backing.records
                    || self.through - self.from != self.frames.len() as u64
                    || self.frames.is_empty()
                    || self.frames.len() > MAX_INWARD
                {
                    return Err(corrupt());
                }
            }
        }
        let mut previous = self.from;
        for frame in &self.frames {
            if frame.cursor <= previous || frame.cursor > self.through || frame.hash == [0; 32] {
                return Err(corrupt());
            }
            previous = frame.cursor;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FaultPoint {
    AfterIntent,
    AfterDestination,
    BeforeComplete,
    AfterComplete,
}

/// Exclusive local progress ledger. It neither owns signing keys nor invokes
/// signing reconciliation. Open performs complete evidence replay; ordinary
/// steps remain bounded and preserve one immutable interrupted intent.
pub struct Projection {
    store: Store,
    state: State,
    image: Vec<u8>,
    pending: Option<Intent>,
    checked_backing: Checkpoint,
    checked_native_tip: u64,
    controller_directory: File,
    poisoned: bool,
    #[cfg(test)]
    fault: Option<FaultPoint>,
}

impl Projection {
    /// Start both local cursors at zero. The intact native controller and replica
    /// must independently agree on the full room pin. Partial creation is kept.
    pub fn create_new(
        path: impl AsRef<Path>,
        room: &mut RoomSession,
        backing: &mut Replica,
        limits: Limits,
    ) -> ProjectionResult<Self> {
        let native = native_live(room)?;
        let binding = Binding::from_room(room);
        let checkpoint = backing.checkpoint()?;
        if checkpoint.room != binding.room {
            return Err(ProjectionError::Binding);
        }
        let controller_directory = room
            .directory
            .try_clone()
            .map_err(|_| ProjectionError::Native(crate::Error::Custody))?;
        let record = init_record(binding, checkpoint, native.tip)?;
        if limits.max_records == 0 || limits.max_record_bytes < record.as_bytes().len() as u64 {
            return Err(vhalla_direct_store::Error::Refused.into());
        }
        let state = State {
            binding,
            backing: checkpoint,
            outward: 0,
            inward: 0,
            native_floor: native.tip,
            pending: None,
            events: 1,
            bytes: record.as_bytes().len() as u64,
        };
        let image = encode_state(state);
        let mut store = Store::create_new(path, context(binding)?, limits)?;
        store.publish(None, &image, &[record])?;
        check_store(&mut store, state, &image).map_err(|_| uncertain())?;
        Ok(Self {
            store,
            state,
            image,
            pending: None,
            checked_backing: checkpoint,
            checked_native_tip: native.tip,
            controller_directory,
            poisoned: false,
            #[cfg(test)]
            fault: None,
        })
    }

    /// Rebuild both cursors from immutable intents and completions. Completed
    /// transfers must still exist in both stores; pending transfers need intact
    /// source bytes and are not silently completed by opening this ledger.
    pub fn open(
        path: impl AsRef<Path>,
        room: &mut RoomSession,
        backing: &mut Replica,
    ) -> ProjectionResult<Self> {
        let native = native_live(room)?;
        let binding = Binding::from_room(room);
        let controller_directory = room
            .directory
            .try_clone()
            .map_err(|_| ProjectionError::Native(crate::Error::Custody))?;
        let mut store = Store::open(path, context(binding)?)?;
        let image = store.load()?.ok_or_else(corrupt)?;
        let expected = decode_state(&image)?;
        expected.binding.check(room)?;
        if expected.backing.room != binding.room {
            return Err(ProjectionError::Binding);
        }
        if native.tip < expected.native_floor {
            return Err(ProjectionError::Binding);
        }
        backing_prefix(backing, expected.backing)?;
        check_store(&mut store, expected, &image)?;
        let mut reconstructed: Option<State> = None;
        let mut pending: Option<Intent> = None;
        let mut cursor = 0;
        while cursor < expected.events {
            let page = store.page(cursor, vhalla_direct_store::MAX_PAGE_RECORDS)?;
            if page.tip != expected.events || page.records.is_empty() {
                return Err(corrupt());
            }
            for entry in page.records {
                if entry.cursor != cursor + 1 {
                    return Err(corrupt());
                }
                match entry.key[0] {
                    INIT_TAG => {
                        if cursor != 0 || reconstructed.is_some() {
                            return Err(corrupt());
                        }
                        let (bound, checkpoint, floor) = decode_init(&entry)?;
                        if bound != binding || native.tip < floor {
                            return Err(ProjectionError::Binding);
                        }
                        backing_prefix(backing, checkpoint)?;
                        reconstructed = Some(State {
                            binding: bound,
                            backing: checkpoint,
                            outward: 0,
                            inward: 0,
                            native_floor: floor,
                            pending: None,
                            events: 0,
                            bytes: 0,
                        });
                    }
                    INTENT_TAG => {
                        let intent = decode_intent(&entry)?;
                        let state = reconstructed.as_mut().ok_or_else(corrupt)?;
                        if pending.is_some() || state.pending.is_some() {
                            return Err(corrupt());
                        }
                        intent.check(*state)?;
                        source_frames(&intent, room, backing)?;
                        state.pending = Some(intent.id());
                        state.native_floor = intent.native_tip;
                        state.backing = intent.backing;
                        pending = Some(intent);
                    }
                    DONE_TAG => {
                        let (id, checkpoint, floor) = decode_done(&entry)?;
                        let intent = pending.take().ok_or_else(corrupt)?;
                        let state = reconstructed.as_mut().ok_or_else(corrupt)?;
                        if state.pending != Some(id)
                            || intent.id() != id
                            || floor < state.native_floor
                            || floor > native.tip
                        {
                            return Err(corrupt());
                        }
                        monotonic(state.backing, checkpoint)?;
                        backing_prefix(backing, checkpoint)?;
                        let frames = source_frames(&intent, room, backing)?;
                        destination_frames(&intent, &frames, room, backing)?;
                        complete_state(state, &intent, checkpoint, floor);
                    }
                    _ => return Err(corrupt()),
                }
                let state = reconstructed.as_mut().ok_or_else(corrupt)?;
                state.events = state.events.checked_add(1).ok_or_else(corrupt)?;
                state.bytes = state
                    .bytes
                    .checked_add(entry.data.len() as u64)
                    .ok_or_else(corrupt)?;
                cursor = entry.cursor;
            }
        }
        if reconstructed != Some(expected) {
            return Err(corrupt());
        }
        let checked_backing = backing_prefix(backing, expected.backing)?;
        let checked_native_tip = native_live(room)?.tip;
        check_store(&mut store, expected, &image)?;
        Ok(Self {
            store,
            state: expected,
            image,
            pending,
            checked_backing,
            checked_native_tip,
            controller_directory,
            poisoned: false,
            #[cfg(test)]
            fault: None,
        })
    }

    /// Read only local progress after checking intact controller and backing
    /// namespace evidence. No remote completeness or admission claim is made.
    pub fn status(
        &mut self,
        room: &mut RoomSession,
        backing: &mut Replica,
    ) -> ProjectionResult<ProjectionStatus> {
        let (native, replica) = self.check(room, backing)?;
        Ok(ProjectionStatus {
            outward_cursor: self.state.outward,
            inward_cursor: self.state.inward,
            pending: self.pending.as_ref().map(|intent| intent.direction),
            backing_floor: self.checked_backing,
            native_tip: native.tip,
            replica_tip: replica.records,
        })
    }

    /// Transfer at most eight outward frames / 128 native journal entries, or
    /// one inward frame / one native reconciliation budget. A retained opposite
    /// direction returns Pending. This never calls controller signing reconcile.
    pub fn step(
        &mut self,
        direction: ProjectionDirection,
        room: &mut RoomSession,
        backing: &mut Replica,
    ) -> ProjectionResult<ProjectionStep> {
        let (native, replica) = self.check(room, backing)?;
        let resumed = self.pending.is_some();
        let (intent, frames) = if let Some(intent) = self.pending.clone() {
            if intent.direction != direction {
                return Err(ProjectionError::Pending(intent.direction));
            }
            let source = source_frames(&intent, room, backing);
            let frames = self.finish_read(source)?;
            self.preflight(1, DONE_BYTES as u64)?;
            (intent, frames)
        } else {
            let prepared = match direction {
                ProjectionDirection::Outward => prepare_outward(self.state, room, replica),
                ProjectionDirection::Inward => {
                    prepare_inward(self.state, backing, native.tip, replica)
                }
            };
            let prepared = self.finish_read(prepared)?;
            let Some((intent, frames)) = prepared else {
                return Ok(ProjectionStep {
                    direction,
                    frames: 0,
                    scanned: 0,
                    resumed: false,
                    status: self.status(room, backing)?,
                });
            };
            intent.check(self.state)?;
            let record = intent_record(&intent)?;
            self.preflight(2, record.as_bytes().len() as u64 + DONE_BYTES as u64)?;
            let mut next = self.state;
            next.pending = Some(intent.id());
            next.native_floor = intent.native_tip;
            next.backing = intent.backing;
            self.publish(next, record)?;
            self.pending = Some(intent.clone());
            self.poisoned = false;
            self.hit(FaultPoint::AfterIntent)?;
            (intent, frames)
        };
        self.poisoned = true;
        match direction {
            ProjectionDirection::Outward => {
                let borrowed: Vec<_> = frames.iter().map(ReplicaFrame::as_frame).collect();
                if let Err(error) = backing.append(&borrowed) {
                    // One Replica append is atomic. A definite refusal does not
                    // invalidate this known durable, still-pending intent.
                    if matches!(
                        error,
                        ReplicaError::Sync(_)
                            | ReplicaError::Store(vhalla_direct_store::Error::Refused)
                    ) {
                        self.poisoned = false;
                    }
                    return Err(error.into());
                }
            }
            ProjectionDirection::Inward => {
                for frame in &frames {
                    match frame.kind {
                        FrameKind::Genesis => native_retained(room, frame)?,
                        FrameKind::Policy => {
                            room.observe_policy(&frame.bytes)?;
                            native_retained(room, frame)?;
                        }
                        FrameKind::Event => {
                            room.receive_event(&frame.bytes)?;
                            native_retained(room, frame)?;
                        }
                    }
                }
            }
        }
        self.hit(FaultPoint::AfterDestination)?;
        destination_frames(&intent, &frames, room, backing)?;
        let checkpoint = backing_prefix(backing, self.checked_backing)?;
        let native = native_live(room)?;
        let mut next = self.state;
        complete_state(&mut next, &intent, checkpoint, native.tip);
        self.hit(FaultPoint::BeforeComplete)?;
        self.publish(next, done_record(intent.id(), checkpoint, native.tip)?)?;
        self.hit(FaultPoint::AfterComplete)?;
        self.pending = None;
        self.poisoned = false;
        Ok(ProjectionStep {
            direction,
            frames: frames.len(),
            scanned: if direction == ProjectionDirection::Outward {
                intent.through - intent.from
            } else {
                0
            },
            resumed,
            status: self.status(room, backing)?,
        })
    }

    /// Projection-ledger usage, excluding signed frames and native controller data.
    pub fn accounting(
        &mut self,
        room: &mut RoomSession,
        backing: &mut Replica,
    ) -> ProjectionResult<Accounting> {
        self.check(room, backing)?;
        let result = self.store.accounting().map_err(ProjectionError::from);
        self.finish_read(result)
    }

    /// Raise finite ledger limits without resetting either cursor or intent.
    pub fn expand_limits(
        &mut self,
        target: Limits,
        room: &mut RoomSession,
        backing: &mut Replica,
    ) -> ProjectionResult<Accounting> {
        self.check(room, backing)?;
        let result = self
            .store
            .expand_limits(target)
            .map_err(ProjectionError::from);
        self.finish_read(result)?;
        self.accounting(room, backing)
    }

    fn ready(&self) -> ProjectionResult<()> {
        if self.poisoned {
            Err(uncertain())
        } else {
            Ok(())
        }
    }

    fn check(
        &mut self,
        room: &mut RoomSession,
        backing: &mut Replica,
    ) -> ProjectionResult<(Accounting, Checkpoint)> {
        self.ready()?;
        let result = (|| {
            self.state.binding.check(room)?;
            if !vhalla_custody::same_open_file(&self.controller_directory, &room.directory)
                .map_err(|_| ProjectionError::Binding)?
            {
                return Err(ProjectionError::Binding);
            }
            let native = native_live(room)?;
            if native.tip < self.state.native_floor
                || native.tip < self.checked_native_tip
                || self.state.outward > native.tip
            {
                return Err(ProjectionError::Binding);
            }
            let replica = backing_prefix(backing, self.checked_backing)?;
            if self.state.inward > replica.records
                || self.pending.as_ref().map(Intent::id) != self.state.pending
            {
                return Err(corrupt());
            }
            check_store(&mut self.store, self.state, &self.image)?;
            Ok((native, replica))
        })();
        let (native, replica) = self.finish_read(result)?;
        self.checked_backing = replica;
        self.checked_native_tip = native.tip;
        Ok((native, replica))
    }

    fn finish_read<T>(&mut self, result: ProjectionResult<T>) -> ProjectionResult<T> {
        if matches!(
            &result,
            Err(ProjectionError::Binding
                | ProjectionError::Native(_)
                | ProjectionError::Store(
                    vhalla_direct_store::Error::Corrupt
                        | vhalla_direct_store::Error::Conflict
                        | vhalla_direct_store::Error::Uncertain
                )
                | ProjectionError::Replica(ReplicaError::Store(
                    vhalla_direct_store::Error::Corrupt
                        | vhalla_direct_store::Error::Conflict
                        | vhalla_direct_store::Error::Uncertain
                )))
        ) {
            self.poisoned = true;
        }
        result
    }

    fn preflight(&mut self, records: u64, bytes: u64) -> ProjectionResult<()> {
        let result = self.store.accounting().map_err(ProjectionError::from);
        let accounting = self.finish_read(result)?;
        if accounting.records.saturating_add(records) > accounting.limits.max_records
            || accounting.bytes.saturating_add(bytes) > accounting.limits.max_record_bytes
        {
            return Err(vhalla_direct_store::Error::Refused.into());
        }
        Ok(())
    }

    fn publish(&mut self, mut next: State, record: Record) -> ProjectionResult<()> {
        next.events = self.state.events.checked_add(1).ok_or_else(corrupt)?;
        next.bytes = self
            .state
            .bytes
            .checked_add(record.as_bytes().len() as u64)
            .ok_or_else(corrupt)?;
        let image = encode_state(next);
        self.poisoned = true;
        self.store.publish(Some(&self.image), &image, &[record])?;
        check_store(&mut self.store, next, &image).map_err(|_| uncertain())?;
        self.state = next;
        self.image = image;
        self.checked_backing = next.backing;
        self.checked_native_tip = next.native_floor;
        Ok(())
    }

    fn hit(&mut self, point: FaultPoint) -> ProjectionResult<()> {
        let _ = point;
        #[cfg(test)]
        if self.fault == Some(point) {
            self.fault = None;
            self.poisoned = true;
            return Err(uncertain());
        }
        Ok(())
    }
}

fn native_live(room: &mut RoomSession) -> ProjectionResult<Accounting> {
    room.ready()?;
    if room.store.load().map_err(crate::Error::from)?.as_deref()
        != Some(room.image_bytes.as_slice())
    {
        return Err(ProjectionError::Native(crate::Error::Corrupt));
    }
    Ok(room.store.accounting().map_err(crate::Error::from)?)
}

fn backing_prefix(backing: &mut Replica, floor: Checkpoint) -> ProjectionResult<Checkpoint> {
    let current = backing.checkpoint()?;
    match backing.page(floor, floor.records, 1) {
        Ok(None) => Ok(current),
        Ok(Some(_)) | Err(ReplicaError::Sync(_)) => Err(ProjectionError::Binding),
        Err(error) => Err(error.into()),
    }
}

fn monotonic(before: Checkpoint, after: Checkpoint) -> ProjectionResult<()> {
    if before.source != after.source
        || before.room != after.room
        || before.epoch != after.epoch
        || after.records < before.records
        || after.bytes < before.bytes
        || (before.records == after.records && before != after)
    {
        return Err(corrupt());
    }
    Ok(())
}

fn frame_kind(kind: PublicRecordKind) -> FrameKind {
    match kind {
        PublicRecordKind::Genesis => FrameKind::Genesis,
        PublicRecordKind::Policy => FrameKind::Policy,
        PublicRecordKind::Event => FrameKind::Event,
    }
}
fn reference(cursor: u64, frame: &ReplicaFrame) -> Reference {
    Reference {
        cursor,
        kind: frame.kind,
        hash: Sha256::digest(&frame.bytes).into(),
    }
}

fn prepare_outward(
    state: State,
    room: &mut RoomSession,
    backing: Checkpoint,
) -> ProjectionResult<Option<(Intent, Vec<ReplicaFrame>)>> {
    let page = room.replicated_records(state.outward, MAX_OUTWARD)?;
    let through = page.next.unwrap_or(page.tip);
    if through == state.outward {
        return Ok(None);
    }
    let mut frames = Vec::new();
    let mut refs = Vec::new();
    for record in page.records {
        let frame = ReplicaFrame {
            kind: frame_kind(record.kind),
            bytes: record.bytes,
        };
        refs.push(reference(record.cursor, &frame));
        frames.push(frame);
    }
    Ok(Some((
        Intent {
            direction: ProjectionDirection::Outward,
            from: state.outward,
            through,
            native_tip: page.tip,
            backing,
            frames: refs,
        },
        frames,
    )))
}

fn prepare_inward(
    state: State,
    backing: &mut Replica,
    native_tip: u64,
    target: Checkpoint,
) -> ProjectionResult<Option<(Intent, Vec<ReplicaFrame>)>> {
    let Some(page) = backing.page(target, state.inward, MAX_INWARD)? else {
        return Ok(None);
    };
    let refs = page
        .frames
        .iter()
        .enumerate()
        .map(|(i, frame)| reference(page.first + i as u64, frame))
        .collect();
    Ok(Some((
        Intent {
            direction: ProjectionDirection::Inward,
            from: state.inward,
            through: page.last,
            native_tip,
            backing: target,
            frames: refs,
        },
        page.frames,
    )))
}

fn source_frames(
    intent: &Intent,
    room: &mut RoomSession,
    backing: &mut Replica,
) -> ProjectionResult<Vec<ReplicaFrame>> {
    backing_prefix(backing, intent.backing)?;
    if native_live(room)?.tip < intent.native_tip {
        return Err(ProjectionError::Binding);
    }
    let mut found = Vec::new();
    let mut frames = Vec::new();
    match intent.direction {
        ProjectionDirection::Outward => {
            let page = room.replicated_records(intent.from, MAX_OUTWARD)?;
            if page.next.unwrap_or(page.tip) < intent.through {
                // Matching the first eight records is insufficient when a
                // forged cursor skips an uninspected ninth public record.
                return Err(ProjectionError::Binding);
            }
            for record in page
                .records
                .into_iter()
                .filter(|record| record.cursor <= intent.through)
            {
                let frame = ReplicaFrame {
                    kind: frame_kind(record.kind),
                    bytes: record.bytes,
                };
                found.push(reference(record.cursor, &frame));
                frames.push(frame);
            }
        }
        ProjectionDirection::Inward => {
            let page = backing
                .page(intent.backing, intent.from, intent.frames.len())?
                .ok_or_else(corrupt)?;
            if page.last != intent.through {
                return Err(corrupt());
            }
            for (index, frame) in page.frames.into_iter().enumerate() {
                found.push(reference(page.first + index as u64, &frame));
                frames.push(frame);
            }
        }
    }
    if found != intent.frames {
        return Err(ProjectionError::Binding);
    }
    Ok(frames)
}

fn destination_frames(
    intent: &Intent,
    frames: &[ReplicaFrame],
    room: &mut RoomSession,
    backing: &mut Replica,
) -> ProjectionResult<()> {
    for frame in frames {
        match intent.direction {
            ProjectionDirection::Outward => {
                let retained = backing
                    .lookup(frame.kind, Sha256::digest(&frame.bytes).into())?
                    .ok_or(ProjectionError::Binding)?;
                if retained != *frame {
                    return Err(ProjectionError::Binding);
                }
            }
            ProjectionDirection::Inward => native_retained(room, frame)?,
        }
    }
    Ok(())
}

fn native_retained(room: &mut RoomSession, frame: &ReplicaFrame) -> ProjectionResult<()> {
    native_live(room)?;
    let key = match frame.kind {
        FrameKind::Genesis => {
            if frame.bytes != room.genesis().encode() {
                return Err(ProjectionError::Binding);
            }
            codec::raw_key(codec::GENESIS, *room.room_id().as_bytes())
        }
        FrameKind::Policy => codec::raw_key(
            codec::POLICY,
            *room.policy_raw(&frame.bytes)?.id().as_bytes(),
        ),
        FrameKind::Event => {
            codec::raw_key(codec::EVENT, *room.event_raw(&frame.bytes)?.id().as_bytes())
        }
    };
    if room.store.read(key).map_err(crate::Error::from)?.as_deref() != Some(frame.bytes.as_slice())
    {
        return Err(ProjectionError::Binding);
    }
    Ok(())
}

fn complete_state(state: &mut State, intent: &Intent, backing: Checkpoint, native_floor: u64) {
    match intent.direction {
        ProjectionDirection::Outward => state.outward = intent.through,
        ProjectionDirection::Inward => state.inward = intent.through,
    }
    state.backing = backing;
    state.native_floor = native_floor;
    state.pending = None;
}

fn corrupt() -> ProjectionError {
    vhalla_direct_store::Error::Corrupt.into()
}
fn uncertain() -> ProjectionError {
    vhalla_direct_store::Error::Uncertain.into()
}
fn context(binding: Binding) -> ProjectionResult<Context> {
    Ok(Context::new(*binding.room.as_bytes(), binding.author)?)
}

fn key(tag: u8, bytes: &[u8]) -> [u8; 33] {
    let mut hash = Sha256::new();
    hash.update(b"vhalla/direct-native/projection/v1\0");
    hash.update([tag]);
    hash.update(bytes);
    let mut key = [0; 33];
    key[0] = tag;
    key[1..].copy_from_slice(&hash.finalize());
    key
}
fn checked_record(entry: &Entry, tag: u8, bytes: &[u8]) -> ProjectionResult<()> {
    if entry.key != key(tag, bytes) {
        return Err(corrupt());
    }
    Ok(())
}

fn put_binding(raw: &mut Vec<u8>, binding: Binding) {
    raw.extend_from_slice(binding.room.as_bytes());
    raw.extend_from_slice(&binding.author);
    raw.extend_from_slice(&binding.nonce);
    raw.push(u8::from(binding.created));
}
fn put_checkpoint(raw: &mut Vec<u8>, checkpoint: Checkpoint) {
    raw.extend_from_slice(&checkpoint.source);
    raw.extend_from_slice(checkpoint.room.as_bytes());
    raw.extend_from_slice(&checkpoint.epoch);
    raw.extend_from_slice(&checkpoint.records.to_be_bytes());
    raw.extend_from_slice(&checkpoint.bytes.to_be_bytes());
    raw.extend_from_slice(&checkpoint.digest);
}
fn encode_state(state: State) -> Vec<u8> {
    let mut raw = IMAGE.to_vec();
    put_binding(&mut raw, state.binding);
    put_checkpoint(&mut raw, state.backing);
    for value in [state.outward, state.inward, state.native_floor] {
        raw.extend_from_slice(&value.to_be_bytes());
    }
    raw.push(u8::from(state.pending.is_some()));
    raw.extend_from_slice(&state.pending.unwrap_or([0; 32]));
    raw.extend_from_slice(&state.events.to_be_bytes());
    raw.extend_from_slice(&state.bytes.to_be_bytes());
    raw
}
fn decode_state(raw: &[u8]) -> ProjectionResult<State> {
    let mut read = Reader::new(raw, IMAGE)?;
    let binding = read.binding()?;
    let backing = read.checkpoint()?;
    let outward = read.number()?;
    let inward = read.number()?;
    let native_floor = read.number()?;
    let pending_flag = read.boolean()?;
    let pending_id = read.take()?;
    if pending_flag == (pending_id == [0; 32]) {
        return Err(corrupt());
    }
    let events = read.number()?;
    let bytes = read.number()?;
    read.end()?;
    if events == 0 || events > 1_000_000 {
        return Err(corrupt());
    }
    Ok(State {
        binding,
        backing,
        outward,
        inward,
        native_floor,
        pending: pending_flag.then_some(pending_id),
        events,
        bytes,
    })
}
fn init_record(
    binding: Binding,
    checkpoint: Checkpoint,
    native_floor: u64,
) -> ProjectionResult<Record> {
    let mut raw = INIT.to_vec();
    put_binding(&mut raw, binding);
    put_checkpoint(&mut raw, checkpoint);
    raw.extend_from_slice(&native_floor.to_be_bytes());
    Ok(Record::new(key(INIT_TAG, &raw), &raw)?)
}
fn decode_init(entry: &Entry) -> ProjectionResult<(Binding, Checkpoint, u64)> {
    checked_record(entry, INIT_TAG, &entry.data)?;
    let mut read = Reader::new(&entry.data, INIT)?;
    let output = (read.binding()?, read.checkpoint()?, read.number()?);
    read.end()?;
    Ok(output)
}
fn encode_intent(intent: &Intent) -> Vec<u8> {
    let mut raw = INTENT.to_vec();
    raw.push(match intent.direction {
        ProjectionDirection::Outward => 1,
        ProjectionDirection::Inward => 2,
    });
    for value in [intent.from, intent.through, intent.native_tip] {
        raw.extend_from_slice(&value.to_be_bytes());
    }
    put_checkpoint(&mut raw, intent.backing);
    raw.push(intent.frames.len() as u8);
    for frame in &intent.frames {
        raw.extend_from_slice(&frame.cursor.to_be_bytes());
        raw.push(frame.kind as u8);
        raw.extend_from_slice(&frame.hash);
    }
    raw
}
fn intent_record(intent: &Intent) -> ProjectionResult<Record> {
    let raw = encode_intent(intent);
    Ok(Record::new(key(INTENT_TAG, &intent.id()), &raw)?)
}
fn decode_intent(entry: &Entry) -> ProjectionResult<Intent> {
    let mut read = Reader::new(&entry.data, INTENT)?;
    let direction = match read.byte()? {
        1 => ProjectionDirection::Outward,
        2 => ProjectionDirection::Inward,
        _ => return Err(corrupt()),
    };
    let from = read.number()?;
    let through = read.number()?;
    let native_tip = read.number()?;
    let backing = read.checkpoint()?;
    let count = read.byte()? as usize;
    if count > MAX_OUTWARD {
        return Err(corrupt());
    }
    let mut frames = Vec::with_capacity(count);
    for _ in 0..count {
        let cursor = read.number()?;
        let kind = match read.byte()? {
            1 => FrameKind::Genesis,
            2 => FrameKind::Policy,
            3 => FrameKind::Event,
            _ => return Err(corrupt()),
        };
        frames.push(Reference {
            cursor,
            kind,
            hash: read.take()?,
        });
    }
    read.end()?;
    let intent = Intent {
        direction,
        from,
        through,
        native_tip,
        backing,
        frames,
    };
    checked_record(entry, INTENT_TAG, &intent.id())?;
    Ok(intent)
}
fn done_record(id: [u8; 32], backing: Checkpoint, native_floor: u64) -> ProjectionResult<Record> {
    let mut raw = DONE.to_vec();
    raw.extend_from_slice(&id);
    put_checkpoint(&mut raw, backing);
    raw.extend_from_slice(&native_floor.to_be_bytes());
    Ok(Record::new(key(DONE_TAG, &id), &raw)?)
}
fn decode_done(entry: &Entry) -> ProjectionResult<([u8; 32], Checkpoint, u64)> {
    let mut read = Reader::new(&entry.data, DONE)?;
    let id = read.take()?;
    let checkpoint = read.checkpoint()?;
    let floor = read.number()?;
    read.end()?;
    checked_record(entry, DONE_TAG, &id)?;
    Ok((id, checkpoint, floor))
}

struct Reader<'a> {
    raw: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn new(raw: &'a [u8], magic: &[u8; 8]) -> ProjectionResult<Self> {
        if !raw.starts_with(magic) {
            return Err(corrupt());
        }
        Ok(Self { raw, at: 8 })
    }
    fn take<const N: usize>(&mut self) -> ProjectionResult<[u8; N]> {
        let end = self.at.checked_add(N).ok_or_else(corrupt)?;
        let raw = self.raw.get(self.at..end).ok_or_else(corrupt)?;
        self.at = end;
        raw.try_into().map_err(|_| corrupt())
    }
    fn byte(&mut self) -> ProjectionResult<u8> {
        Ok(self.take::<1>()?[0])
    }
    fn boolean(&mut self) -> ProjectionResult<bool> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(corrupt()),
        }
    }
    fn number(&mut self) -> ProjectionResult<u64> {
        Ok(u64::from_be_bytes(self.take()?))
    }
    fn binding(&mut self) -> ProjectionResult<Binding> {
        let binding = Binding {
            room: RoomId::from_bytes(self.take()?),
            author: self.take()?,
            nonce: self.take()?,
            created: self.boolean()?,
        };
        if binding.author == [0; 32] || binding.nonce == [0; 32] {
            return Err(corrupt());
        }
        Ok(binding)
    }
    fn checkpoint(&mut self) -> ProjectionResult<Checkpoint> {
        let checkpoint = Checkpoint {
            source: self.take()?,
            room: RoomId::from_bytes(self.take()?),
            epoch: self.take()?,
            records: self.number()?,
            bytes: self.number()?,
            digest: self.take()?,
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
    fn end(self) -> ProjectionResult<()> {
        if self.at == self.raw.len() {
            Ok(())
        } else {
            Err(corrupt())
        }
    }
}
fn check_store(store: &mut Store, state: State, image: &[u8]) -> ProjectionResult<Accounting> {
    if store.load()?.as_deref() != Some(image) {
        return Err(corrupt());
    }
    let accounting = store.accounting()?;
    if accounting.records != state.events
        || accounting.tip != state.events
        || accounting.generation != state.events
        || accounting.bytes != state.bytes
    {
        return Err(corrupt());
    }
    Ok(accounting)
}

#[cfg(test)]
#[path = "projection_tests.rs"]
mod tests;
