#![no_std]
#![forbid(unsafe_code)]

//! Verification of one selected peer's frozen public-room snapshot.
//!
//! The transport must authenticate the configured source and its checkpoint.
//! This crate does not sign checkpoints or authenticate network connections.
//! A partial page establishes valid canonical records and contiguous positions;
//! only the final count, byte total and rolling hash establish snapshot coverage.
//! Room admission, missing ancestry, delivery and other peers remain separate.

extern crate alloc;

use alloc::vec::Vec;
use sha2::{Digest, Sha256};
use vhalla_direct_room::{
    PinnedGenesis, RoomId, SignedEvent, SignedGenesis, SignedPolicy, VerifiedEvent, VerifiedPolicy,
    MAX_EVENT_BYTES, MAX_GENESIS_BYTES, MAX_POLICY_BYTES, MAX_TEXT_BYTES, MAX_WRITERS,
};

/// Maximum signed frames in one page.
pub const MAX_PAGE_FRAMES: usize = 32;
/// Maximum records in one selected source snapshot.
pub const MAX_SNAPSHOT_RECORDS: u64 = 1_000_000;
/// Maximum signed payload bytes in one selected source snapshot.
pub const MAX_SNAPSHOT_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MIN_POLICY_BYTES: usize = MAX_POLICY_BYTES - 32 * (MAX_WRITERS - 1) - 72 * MAX_WRITERS;
const MIN_EVENT_BYTES: usize = MAX_EVENT_BYTES - MAX_TEXT_BYTES + 1;
const MIN_RECORD_BYTES: usize = if MIN_POLICY_BYTES < MIN_EVENT_BYTES {
    MIN_POLICY_BYTES
} else {
    MIN_EVENT_BYTES
};
const MAX_RECORD_BYTES: usize = if MAX_POLICY_BYTES > MAX_EVENT_BYTES {
    MAX_POLICY_BYTES
} else {
    MAX_EVENT_BYTES
};

/// A refusal never permits resetting an existing receiver to excuse a mismatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid bounds, impossible byte counts, or an empty source snapshot.
    Bounds,
    /// The configured, authenticated and claimed source identities differ.
    Source,
    /// A checkpoint or frame belongs to another pinned room.
    Room,
    /// An epoch is zero or an existing source changed its epoch.
    Epoch,
    /// Page positions omit, repeat, reorder or exceed the expected range.
    Sequence,
    /// The page names another frozen checkpoint.
    Checkpoint,
    /// The exact terminal count, byte total or rolling digest differs.
    Digest,
    /// End of input arrived before the target snapshot was complete.
    Truncated,
    /// A prepared token's receiver base or frozen target changed.
    StaleBase,
    /// A source extension was attempted before exact completion.
    Pending,
    /// A new checkpoint decreases the source's count or byte total.
    Rollback,
    /// The same source count claims different bytes or a different hash.
    Fork,
    /// A signed frame is invalid or its policy signer is not the room owner.
    Protocol(vhalla_direct_room::Error),
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl core::error::Error for Error {}
impl From<vhalla_direct_room::Error> for Error {
    fn from(error: vhalla_direct_room::Error) -> Self {
        Self::Protocol(error)
    }
}
/// Snapshot verification result.
pub type Result<T> = core::result::Result<T, Error>;

/// Only public signed room frames participate in a snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameKind {
    /// The first and only genesis, matching the independent room pin.
    Genesis = 1,
    /// An owner-signed policy, including pending or conflicting evidence.
    Policy = 2,
    /// An author-signed event, including continuity or conflicting evidence.
    Event = 3,
}

/// Borrowed untrusted wire input. A prepared page owns its verified contents.
#[derive(Clone, Copy, Debug)]
pub struct Frame<'a> {
    /// Claimed signed record type.
    pub kind: FrameKind,
    /// Complete canonical signed bytes, without transport framing.
    pub bytes: &'a [u8],
}

/// Authenticated source statement supplied by the caller's transport.
/// Public fields permit wire decoding; constructing it establishes no trust.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Checkpoint {
    /// Full configured peer identity, authenticated outside this crate.
    pub source: [u8; 32],
    /// Independent full room pin.
    pub room: RoomId,
    /// Fresh random nonzero source incarnation, chosen by the source.
    pub epoch: [u8; 32],
    /// Number of public signed records, including the initial genesis.
    pub records: u64,
    /// Sum of the exact signed frame lengths.
    pub bytes: u64,
    /// Terminal rolling digest of that complete frozen source sequence.
    pub digest: [u8; 32],
}
impl Checkpoint {
    /// Domain-separated identifier binding every checkpoint field. This hash is
    /// not a signature; the transport must authenticate the checkpoint itself.
    pub fn id(&self) -> [u8; 32] {
        hash(&[
            b"vhalla/direct-sync/checkpoint/v1\0",
            &self.source,
            self.room.as_bytes(),
            &self.epoch,
            &self.records.to_be_bytes(),
            &self.bytes.to_be_bytes(),
            &self.digest,
        ])
    }
    fn check(&self, genesis: &PinnedGenesis) -> Result<()> {
        if self.source == [0; 32] {
            return Err(Error::Source);
        }
        if self.room != genesis.id() {
            return Err(Error::Room);
        }
        if self.epoch == [0; 32] {
            return Err(Error::Epoch);
        }
        if self.records == 0
            || self.records > MAX_SNAPSHOT_RECORDS
            || self.bytes > MAX_SNAPSHOT_BYTES
        {
            return Err(Error::Bounds);
        }
        let initial = genesis.encode().len() as u64;
        let minimum = initial + (self.records - 1) * MIN_RECORD_BYTES as u64;
        let maximum = initial + (self.records - 1) * MAX_RECORD_BYTES as u64;
        if self.bytes < minimum || self.bytes > maximum {
            return Err(Error::Bounds);
        }
        Ok(())
    }
}

/// One frozen-source range. Positions are one-based and inclusive.
#[derive(Clone, Copy, Debug)]
pub struct Page<'a> {
    /// Identifier of the checkpoint to which this page claims to belong.
    pub checkpoint_id: [u8; 32],
    /// Position of the first supplied frame.
    pub first: u64,
    /// Position of the last supplied frame.
    pub last: u64,
    /// Nonempty page of at most [`MAX_PAGE_FRAMES`] signed frames.
    pub frames: &'a [Frame<'a>],
}

/// A signature-checked, room-scoped public record. This does not grant message
/// admission or prove that a partial page is included in the checkpoint root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerifiedRecord {
    /// Exact independently pinned genesis.
    Genesis(PinnedGenesis),
    /// Policy authenticated to the pinned owner, including fork evidence.
    Policy(VerifiedPolicy),
    /// Event authenticated to its author, including unadmitted evidence.
    Event(VerifiedEvent),
}
impl VerifiedRecord {
    /// Public record type.
    pub const fn kind(&self) -> FrameKind {
        match self {
            Self::Genesis(_) => FrameKind::Genesis,
            Self::Policy(_) => FrameKind::Policy,
            Self::Event(_) => FrameKind::Event,
        }
    }
    /// Exact canonical signed bytes that must be retained before committing
    /// receiver progress. No unsigned operation or local metadata is returned.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Genesis(record) => record.encode(),
            Self::Policy(record) => record.encode(),
            Self::Event(record) => record.encode(),
        }
    }
}

/// Contiguous verified local prefix. It is not snapshot inclusion or coverage
/// until [`Receiver::coverage`] is [`Coverage::Complete`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Progress {
    /// Count of committed canonical source frames.
    pub records: u64,
    /// Sum of those frames' signed byte lengths.
    pub bytes: u64,
    /// Rolling prefix hash, bound to source, room and epoch.
    pub digest: [u8; 32],
}

/// Coverage of this selected source's frozen checkpoint only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Coverage {
    /// Canonical contiguous records may be saved; target inclusion is unproved.
    Pending,
    /// Count, byte total and terminal hash match the authenticated target.
    Complete,
}

/// Builds a checkpoint from canonical public signed frames in source order.
/// It stores one running hash, not a lifetime vector or record index.
#[derive(Clone)]
pub struct SourceAccumulator {
    genesis: PinnedGenesis,
    source: [u8; 32],
    epoch: [u8; 32],
    progress: Progress,
}
impl SourceAccumulator {
    /// Start at zero. The caller must supply a fresh random nonzero epoch and
    /// authenticate this source identity when publishing a checkpoint.
    pub fn new(source: [u8; 32], genesis: PinnedGenesis, epoch: [u8; 32]) -> Result<Self> {
        if source == [0; 32] {
            return Err(Error::Source);
        }
        if epoch == [0; 32] {
            return Err(Error::Epoch);
        }
        let progress = initial(source, genesis.id(), epoch);
        Ok(Self {
            genesis,
            source,
            epoch,
            progress,
        })
    }
    /// Verify and append one exact public frame. Any refusal leaves the source
    /// unchanged. The first frame is the pinned genesis; later genesis is refused.
    pub fn push(&mut self, frame: Frame<'_>) -> Result<()> {
        let sequence = self.progress.records.checked_add(1).ok_or(Error::Bounds)?;
        verify(&self.genesis, sequence, frame)?;
        let next = advance(self.progress, frame)?;
        self.progress = next;
        Ok(())
    }
    /// Freeze the current nonempty source prefix. Transport authentication of
    /// the resulting statement is required separately.
    pub fn checkpoint(&self) -> Result<Checkpoint> {
        let checkpoint = Checkpoint {
            source: self.source,
            room: self.genesis.id(),
            epoch: self.epoch,
            records: self.progress.records,
            bytes: self.progress.bytes,
            digest: self.progress.digest,
        };
        checkpoint.check(&self.genesis)?;
        Ok(checkpoint)
    }
}

/// Prepared canonical frames and prospective receiver progress. The token owns
/// its verified records independently of the borrowed input page.
#[derive(Debug)]
pub struct PreparedPage {
    checkpoint: [u8; 32],
    base: Progress,
    next: Progress,
    frames: Vec<VerifiedRecord>,
}
impl PreparedPage {
    /// Frames the caller must durably retain before publishing this progress.
    /// Partial-page records can be kept as evidence without claiming coverage.
    pub fn frames(&self) -> &[VerifiedRecord] {
        &self.frames
    }
    /// First source position in this prepared page.
    pub const fn first(&self) -> u64 {
        self.base.records + 1
    }
    /// Last source position in this prepared page.
    pub const fn last(&self) -> u64 {
        self.next.records
    }
    /// Prospective prefix after the caller has durably retained every frame.
    pub const fn progress(&self) -> Progress {
        self.next
    }
}

/// Receiver for one authenticated frozen checkpoint. Start is always zero;
/// there is no API accepting an arbitrary peer cursor or restored prefix hash.
pub struct Receiver {
    genesis: PinnedGenesis,
    target: Checkpoint,
    progress: Progress,
}
impl Receiver {
    /// Require the configured peer, authenticated connection identity and
    /// checkpoint's claimed source to match. `authenticated_source` must come
    /// from the transport's authentication result, never from this wire page.
    /// The transport must also authenticate the checkpoint contents.
    pub fn begin(
        genesis: PinnedGenesis,
        expected_source: [u8; 32],
        authenticated_source: [u8; 32],
        target: Checkpoint,
    ) -> Result<Self> {
        if expected_source != authenticated_source || expected_source != target.source {
            return Err(Error::Source);
        }
        target.check(&genesis)?;
        let progress = initial(target.source, target.room, target.epoch);
        Ok(Self {
            genesis,
            target,
            progress,
        })
    }
    /// Frozen source checkpoint whose complete terminal hash must be matched.
    pub const fn target(&self) -> Checkpoint {
        self.target
    }
    /// Locally committed canonical prefix, with no arbitrary-cursor setter.
    pub const fn progress(&self) -> Progress {
        self.progress
    }
    /// Selected-source snapshot coverage, never room-wide completeness.
    pub fn coverage(&self) -> Coverage {
        if self.progress.records == self.target.records
            && self.progress.bytes == self.target.bytes
            && self.progress.digest == self.target.digest
        {
            Coverage::Complete
        } else {
            Coverage::Pending
        }
    }
    /// Verify a page without mutating receiver progress. Altered valid signed
    /// prefixes may only be detected at the final rolling-hash comparison.
    /// Any invalid page or terminal mismatch produces no prepared token.
    pub fn prepare_page(&self, page: Page<'_>) -> Result<PreparedPage> {
        if page.checkpoint_id != self.target.id() {
            return Err(Error::Checkpoint);
        }
        if page.frames.is_empty() || page.frames.len() > MAX_PAGE_FRAMES {
            return Err(Error::Bounds);
        }
        if page.first != self.progress.records + 1
            || page.last
                != page
                    .first
                    .checked_add(page.frames.len() as u64 - 1)
                    .ok_or(Error::Sequence)?
            || page.last > self.target.records
        {
            return Err(Error::Sequence);
        }
        let mut next = self.progress;
        let mut frames = Vec::with_capacity(page.frames.len());
        for frame in page.frames {
            frames.push(verify(&self.genesis, next.records + 1, *frame)?);
            next = advance(next, *frame)?;
            if next.bytes > self.target.bytes {
                return Err(Error::Digest);
            }
        }
        if next.records == self.target.records
            && (next.bytes != self.target.bytes || next.digest != self.target.digest)
        {
            return Err(Error::Digest);
        }
        if next.bytes + (self.target.records - next.records) * MIN_RECORD_BYTES as u64
            > self.target.bytes
        {
            return Err(Error::Digest);
        }
        Ok(PreparedPage {
            checkpoint: self.target.id(),
            base: self.progress,
            next,
            frames,
        })
    }
    /// Publish progress only after durable retention of every prepared frame.
    /// This pure method cannot attest that the caller performed filesystem I/O.
    pub fn commit_after_persist(&mut self, prepared: PreparedPage) -> Result<Coverage> {
        if prepared.checkpoint != self.target.id() || prepared.base != self.progress {
            return Err(Error::StaleBase);
        }
        self.progress = prepared.next;
        Ok(self.coverage())
    }
    /// Check an end-of-input assertion. A short stream cannot claim coverage.
    pub fn finish(&self) -> Result<Checkpoint> {
        if self.coverage() != Coverage::Complete {
            return Err(Error::Truncated);
        }
        Ok(self.target)
    }
    /// Continue an exactly completed snapshot from the same authenticated source,
    /// room and epoch. Equal checkpoints are idempotent. Rollback, changed epoch
    /// and same-count forks are refused without discarding prior progress.
    pub fn extend(&mut self, authenticated_source: [u8; 32], target: Checkpoint) -> Result<()> {
        if self.coverage() != Coverage::Complete {
            return Err(Error::Pending);
        }
        if authenticated_source != self.target.source || target.source != self.target.source {
            return Err(Error::Source);
        }
        if target.room != self.target.room {
            return Err(Error::Room);
        }
        if target.epoch != self.target.epoch {
            return Err(Error::Epoch);
        }
        if target.records == self.target.records {
            return if target == self.target {
                Ok(())
            } else {
                Err(Error::Fork)
            };
        }
        if target.records < self.target.records || target.bytes < self.target.bytes {
            return Err(Error::Rollback);
        }
        target.check(&self.genesis)?;
        if target.bytes - self.progress.bytes
            < (target.records - self.progress.records) * MIN_RECORD_BYTES as u64
        {
            return Err(Error::Bounds);
        }
        self.target = target;
        Ok(())
    }
}

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}
fn initial(source: [u8; 32], room: RoomId, epoch: [u8; 32]) -> Progress {
    Progress {
        records: 0,
        bytes: 0,
        digest: hash(&[
            b"vhalla/direct-sync/source/v1\0",
            &source,
            room.as_bytes(),
            &epoch,
        ]),
    }
}
fn advance(previous: Progress, frame: Frame<'_>) -> Result<Progress> {
    let records = previous.records.checked_add(1).ok_or(Error::Bounds)?;
    let bytes = previous
        .bytes
        .checked_add(frame.bytes.len() as u64)
        .ok_or(Error::Bounds)?;
    if records > MAX_SNAPSHOT_RECORDS || bytes > MAX_SNAPSHOT_BYTES {
        return Err(Error::Bounds);
    }
    let digest = hash(&[
        b"vhalla/direct-sync/frame/v1\0",
        &previous.digest,
        &records.to_be_bytes(),
        &[frame.kind as u8],
        &(frame.bytes.len() as u64).to_be_bytes(),
        &hash(&[frame.bytes]),
    ]);
    Ok(Progress {
        records,
        bytes,
        digest,
    })
}
fn verify(genesis: &PinnedGenesis, sequence: u64, frame: Frame<'_>) -> Result<VerifiedRecord> {
    let bound = match frame.kind {
        FrameKind::Genesis => MAX_GENESIS_BYTES,
        FrameKind::Policy => MAX_POLICY_BYTES,
        FrameKind::Event => MAX_EVENT_BYTES,
    };
    if frame.bytes.is_empty() || frame.bytes.len() > bound {
        return Err(Error::Bounds);
    }
    if (sequence == 1) != (frame.kind == FrameKind::Genesis) {
        return Err(Error::Sequence);
    }
    let record = match frame.kind {
        FrameKind::Genesis => {
            let record = SignedGenesis::decode(frame.bytes)?.verify_pin(genesis.id())?;
            if record.encode() != genesis.encode() {
                return Err(Error::Room);
            }
            VerifiedRecord::Genesis(record)
        }
        FrameKind::Policy => {
            let record = SignedPolicy::decode(frame.bytes)?.verify()?;
            if record.claims().room != genesis.id() {
                return Err(Error::Room);
            }
            if record.claims().owner != genesis.claims().owner {
                return Err(vhalla_direct_room::Error::Owner.into());
            }
            VerifiedRecord::Policy(record)
        }
        FrameKind::Event => {
            let record = SignedEvent::decode(frame.bytes)?.verify()?;
            if record.claims().room != genesis.id() {
                return Err(Error::Room);
            }
            VerifiedRecord::Event(record)
        }
    };
    if record.encode() != frame.bytes {
        return Err(vhalla_direct_room::Error::Encoding.into());
    }
    Ok(record)
}
