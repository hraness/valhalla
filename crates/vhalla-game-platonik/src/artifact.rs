//! Bounded artifact assembly: the receiver side of the plan's
//! **Bounded artifacts** section.
//!
//! Anything larger than one room frame moves as an artifact. The transport
//! drives [`ArtifactAssembly`], a pure state machine with no clock, no socket,
//! and no allocation it has not already charged against a declared bound. The
//! caller supplies a monotone `step` and the assembly holds a step deadline,
//! so a stalled transfer frees its bytes without any notion of time.
//!
//! Every limit this module enforces, in one place:
//!
//! - `block_len` is exactly [`BLOCK_LEN`] (65,536 bytes). No other block size
//!   is admissible and no manifest may declare one.
//! - At most [`MAX_BLOCKS`] (128) blocks, so the largest admissible artifact is
//!   128 x 65,536 = 8,388,608 bytes, which is
//!   [`MAX_ARTIFACT_BYTES`](crate::manifest::MAX_ARTIFACT_BYTES).
//! - `total_len` is at most the minimum of the request's `max_bytes` and
//!   `MAX_ARTIFACT_BYTES`.
//! - `decompressed_len == total_len`. There is no compression in v1, so a
//!   manifest that claims any expansion is refused at opening.
//! - The block count is exactly `ceil(total_len / block_len)`. Every block but
//!   the last carries exactly `block_len` bytes and the last carries the exact
//!   remainder.
//! - Retained bytes are at most `total_len` at every moment, including
//!   completion: blocks land in one contiguous buffer and the whole-artifact
//!   digest streams over that buffer, so no second copy is ever made. The plan
//!   charges a ceiling of 1.25 x `total_len`; [`ArtifactAssembly::peak_retained`]
//!   reports the measured peak and [`ArtifactAssembly::retained_cap`] reports
//!   that ceiling.
//! - Verification work is one SHA-256 per stored block plus one over the whole
//!   artifact, counted by [`ArtifactAssembly::hashes`]. A duplicate costs no
//!   hash at all.
//! - One assembly per session and a receiver-wide cap on concurrent
//!   assemblies, both enforced by [`ArtifactSlots`].
//! - A step deadline. The first block at a step past the deadline drops every
//!   retained byte and closes the assembly.
//!
//! Browser receivers move a block's bytes as 4 KiB records, exactly the
//! encoding `prototypes/browser-records` fixed:
//! `VR01 | total:u32be | offset:u32be | sha256:32 | body`, every body exactly
//! [`RECORD_BODY_LEN`] bytes except the final exact remainder, and an empty
//! object as one header-only record carrying the SHA-256 of empty bytes.
//! [`split_block`] and [`join_records`] are that mapping and its inverse. The
//! mapping never changes a block's digest, so a browser receiver and a native
//! receiver accept exactly the same blocks.
//!
//! Nothing here trusts a byte. A block is retained only once its own digest
//! matches the manifest, and an artifact is released only once the whole bytes
//! hash to the `InnerArtifactId` the session already committed to. The id's
//! [`InnerKind`](crate::ids::InnerKind) fixes which object those bytes must be;
//! this module never parses them.

use sha2::{Digest, Sha256};

use crate::ids::{ArtifactManifestHash, InnerArtifactId, SessionKey};
use crate::manifest::MAX_ARTIFACT_BYTES;
use crate::wire::{ArtifactManifest, ArtifactRequest, Block, BLOCK_LEN, MAX_BLOCKS};

/// The four magic bytes every browser record starts with.
pub const RECORD_MAGIC: [u8; 4] = *b"VR01";
/// Magic, total, offset, and digest: the fixed record header.
pub const RECORD_HEADER_LEN: usize = 4 + 4 + 4 + 32;
/// Every record body but the last is exactly this long.
pub const RECORD_BODY_LEN: usize = 4_096;
/// The widest record, before transport framing.
pub const MAX_RECORD_LEN: usize = RECORD_HEADER_LEN + RECORD_BODY_LEN;
/// Records one full block splits into: 65,536 / 4,096.
pub const MAX_RECORDS_PER_BLOCK: usize = BLOCK_LEN as usize / RECORD_BODY_LEN;

/// Why an artifact request, manifest, block, or slot is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactError {
    /// The manifest names a different artifact than the request.
    IdMismatch,
    /// `block_len` is not [`BLOCK_LEN`].
    BlockLen,
    /// `decompressed_len` is not `total_len`; v1 carries no compression.
    Compressed,
    /// `total_len` is above the request's `max_bytes` or [`MAX_ARTIFACT_BYTES`].
    TooLarge,
    /// The block count is not `ceil(total_len / block_len)`, or above
    /// [`MAX_BLOCKS`].
    BlockCount,
    /// The deadline is below the opening step.
    Deadline,
    /// The block index names no block of this manifest.
    BlockIndex,
    /// `offset` is not `index * block_len`.
    BlockOffset,
    /// The block is not `block_len` long, or the final block is not the exact
    /// remainder.
    BlockLength,
    /// The block bytes do not hash to `blocks[index]`.
    BlockDigest,
    /// The caller's step went backwards.
    StepNotMonotone,
    /// The step is past the deadline; every retained byte is dropped.
    DeadlinePassed,
    /// Every block arrived and the whole bytes do not hash to `id.sha256`;
    /// the whole artifact is discarded.
    DigestMismatch,
    /// The assembly is complete, aborted, or already taken.
    Closed,
    /// The bytes were asked for before every block arrived.
    NotComplete,
    /// The session already drives an assembly; the cap is one.
    SessionBusy,
    /// The receiver-wide concurrent assembly cap is full.
    ReceiverFull,
    /// No assembly is open for this session.
    NoAssembly,
}

/// What accepting a block did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Accepted {
    /// The block was stored and more blocks are needed.
    Stored,
    /// That index was already held; nothing changed.
    Duplicate,
    /// Every block is present and the whole bytes match the artifact id.
    Complete,
    /// The block belongs to a different manifest of the same artifact. The
    /// assembly is aborted and every retained byte is dropped; the transport
    /// may open a fresh assembly against the new manifest.
    Restart,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Open,
    Complete,
    Closed,
}

/// One artifact under assembly.
///
/// Created from an [`ArtifactRequest`] and the holder's [`ArtifactManifest`],
/// which must name the same [`InnerArtifactId`]. Driven by [`accept`] and
/// released once by [`take`]. Holds no clock and no transport.
///
/// [`accept`]: ArtifactAssembly::accept
/// [`take`]: ArtifactAssembly::take
#[derive(Debug)]
pub struct ArtifactAssembly {
    id: InnerArtifactId,
    manifest: ArtifactManifestHash,
    total_len: u64,
    block_len: u32,
    digests: Vec<[u8; 32]>,
    present: Vec<bool>,
    stored: usize,
    bytes: Vec<u8>,
    peak_retained: u64,
    hashes: u64,
    step: u64,
    deadline: u64,
    state: State,
}

impl ArtifactAssembly {
    /// Opens an assembly for `request` against the holder's `manifest`.
    ///
    /// Refuses a manifest that names another artifact, declares any block
    /// length but [`BLOCK_LEN`], claims compression, exceeds the request's
    /// `max_bytes` or [`MAX_ARTIFACT_BYTES`], or lists a block count other
    /// than `ceil(total_len / block_len)`. A zero-length artifact has no
    /// blocks and completes at once against the SHA-256 of empty bytes, which
    /// is this assembly's single hash invocation.
    ///
    /// `step` is the caller's monotone step at opening and `deadline` is the
    /// last step at which a block is admissible.
    pub fn open(
        request: &ArtifactRequest,
        manifest: &ArtifactManifest,
        step: u64,
        deadline: u64,
    ) -> Result<Self, ArtifactError> {
        if manifest.id != request.id {
            return Err(ArtifactError::IdMismatch);
        }
        if manifest.block_len != BLOCK_LEN {
            return Err(ArtifactError::BlockLen);
        }
        if manifest.decompressed_len != manifest.total_len {
            return Err(ArtifactError::Compressed);
        }
        let ceiling = request.max_bytes.min(MAX_ARTIFACT_BYTES);
        if manifest.total_len > ceiling {
            return Err(ArtifactError::TooLarge);
        }
        let block_len = u64::from(manifest.block_len);
        let expected = manifest.total_len.div_ceil(block_len);
        if expected > MAX_BLOCKS as u64 || manifest.blocks.len() as u64 != expected {
            return Err(ArtifactError::BlockCount);
        }
        if deadline < step {
            return Err(ArtifactError::Deadline);
        }
        let count = manifest.blocks.len();
        let mut assembly = Self {
            id: manifest.id,
            manifest: manifest.hash(),
            total_len: manifest.total_len,
            block_len: manifest.block_len,
            digests: manifest.blocks.clone(),
            present: vec![false; count],
            stored: 0,
            bytes: Vec::new(),
            peak_retained: 0,
            hashes: 0,
            step,
            deadline,
            state: State::Open,
        };
        if count == 0 {
            assembly.hashes += 1;
            if <[u8; 32]>::from(Sha256::digest([])) != assembly.id.sha256 {
                assembly.state = State::Closed;
                return Err(ArtifactError::DigestMismatch);
            }
            assembly.state = State::Complete;
        }
        Ok(assembly)
    }

    /// Offers one block at the caller's monotone `step`.
    ///
    /// A block is stored only when it names this manifest, its index is inside
    /// the manifest, `offset == index * block_len`, its length is `block_len`
    /// (or the exact remainder for the final block), and its plain SHA-256
    /// equals `blocks[index]`.
    ///
    /// A resend at an index already held returns [`Accepted::Duplicate`]
    /// without a hash invocation: the retained bytes are the ones whose digest
    /// already matched, so a mutated resend changes nothing and buys no work.
    ///
    /// A block naming a different manifest is a changed manifest for the same
    /// artifact id: the assembly aborts as [`Accepted::Restart`] and drops
    /// every retained byte.
    ///
    /// The last block present triggers the whole-artifact digest. If it does
    /// not equal `id.sha256` the whole artifact is discarded and the assembly
    /// closes with [`ArtifactError::DigestMismatch`].
    pub fn accept(&mut self, block: &Block, step: u64) -> Result<Accepted, ArtifactError> {
        if self.state != State::Open {
            return Err(ArtifactError::Closed);
        }
        if step < self.step {
            return Err(ArtifactError::StepNotMonotone);
        }
        self.step = step;
        if step > self.deadline {
            self.discard();
            return Err(ArtifactError::DeadlinePassed);
        }
        if block.manifest != self.manifest {
            self.discard();
            return Ok(Accepted::Restart);
        }
        let index = usize::from(block.index);
        if index >= self.digests.len() {
            return Err(ArtifactError::BlockIndex);
        }
        if block.offset != index as u64 * u64::from(self.block_len) {
            return Err(ArtifactError::BlockOffset);
        }
        if block.bytes.len() as u64 != self.expected_len(index) {
            return Err(ArtifactError::BlockLength);
        }
        if self.present[index] {
            return Ok(Accepted::Duplicate);
        }
        self.hashes += 1;
        if <[u8; 32]>::from(Sha256::digest(&block.bytes)) != self.digests[index] {
            return Err(ArtifactError::BlockDigest);
        }
        if self.bytes.is_empty() {
            self.bytes = vec![0_u8; self.total_len as usize];
            self.peak_retained = self.total_len;
        }
        let start = block.offset as usize;
        self.bytes[start..start + block.bytes.len()].copy_from_slice(&block.bytes);
        self.present[index] = true;
        self.stored += 1;
        if self.stored < self.digests.len() {
            return Ok(Accepted::Stored);
        }
        self.hashes += 1;
        if <[u8; 32]>::from(Sha256::digest(&self.bytes)) != self.id.sha256 {
            self.discard();
            return Err(ArtifactError::DigestMismatch);
        }
        self.state = State::Complete;
        Ok(Accepted::Complete)
    }

    /// Yields the verified bytes once, consuming the assembly.
    ///
    /// Refused with [`ArtifactError::NotComplete`] until every block is
    /// present and the whole-artifact digest has matched. There is no second
    /// call: the assembly is gone.
    pub fn take(self) -> Result<Vec<u8>, ArtifactError> {
        match self.state {
            State::Complete => Ok(self.bytes),
            State::Open => Err(ArtifactError::NotComplete),
            State::Closed => Err(ArtifactError::Closed),
        }
    }

    /// Drops every retained byte and closes the assembly.
    pub fn abort(&mut self) {
        self.discard();
    }

    fn discard(&mut self) {
        self.bytes = Vec::new();
        self.present.iter_mut().for_each(|slot| *slot = false);
        self.stored = 0;
        self.state = State::Closed;
    }

    fn expected_len(&self, index: usize) -> u64 {
        let block_len = u64::from(self.block_len);
        let start = index as u64 * block_len;
        (self.total_len - start).min(block_len)
    }

    /// The artifact this assembly is bound to.
    #[must_use]
    pub const fn id(&self) -> InnerArtifactId {
        self.id
    }

    /// The manifest every block must name.
    #[must_use]
    pub const fn manifest(&self) -> ArtifactManifestHash {
        self.manifest
    }

    /// The declared total length.
    #[must_use]
    pub const fn total_len(&self) -> u64 {
        self.total_len
    }

    /// How many blocks the artifact has.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.digests.len()
    }

    /// How many distinct blocks are held.
    #[must_use]
    pub const fn stored_blocks(&self) -> usize {
        self.stored
    }

    /// Bytes retained right now: zero before the first block, `total_len`
    /// while blocks are held, zero again once the assembly is discarded.
    #[must_use]
    pub fn retained(&self) -> u64 {
        self.bytes.len() as u64
    }

    /// The highest [`retained`](Self::retained) value this assembly reached.
    #[must_use]
    pub const fn peak_retained(&self) -> u64 {
        self.peak_retained
    }

    /// The plan's retained-bytes ceiling for this artifact: 1.25 x `total_len`.
    #[must_use]
    pub const fn retained_cap(&self) -> u64 {
        self.total_len + self.total_len / 4
    }

    /// SHA-256 invocations charged so far: one per stored block plus one over
    /// the whole artifact.
    #[must_use]
    pub const fn hashes(&self) -> u64 {
        self.hashes
    }

    /// The highest invocation count this assembly can ever reach.
    #[must_use]
    pub fn max_hashes(&self) -> u64 {
        self.digests.len() as u64 + 1
    }

    /// The caller's last step.
    #[must_use]
    pub const fn step(&self) -> u64 {
        self.step
    }

    /// The last step at which a block is admissible.
    #[must_use]
    pub const fn deadline(&self) -> u64 {
        self.deadline
    }

    /// Whether every block is present and the whole digest matched.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.state == State::Complete
    }

    /// Whether the assembly is aborted, discarded, or spent.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.state == State::Closed
    }
}

/// The receiver's concurrent assemblies.
///
/// One assembly per session, so a second request for a session is refused
/// until that session's assembly completes, is taken, or aborts; and a
/// receiver-wide cap on how many sessions may assemble at once. The plan
/// charges `max_artifact_bytes` as peak retained bytes against the single
/// concurrent assembly of a session, which is what makes a session's sixty-four
/// sequential trace fetches fit inside 8 MiB rather than sum to 80 MB.
#[derive(Debug)]
pub struct ArtifactSlots {
    max_concurrent: usize,
    slots: Vec<(SessionKey, ArtifactAssembly)>,
    peak_retained: u64,
}

impl ArtifactSlots {
    /// A receiver that assembles at most `max_concurrent` artifacts at once.
    #[must_use]
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            max_concurrent,
            slots: Vec::new(),
            peak_retained: 0,
        }
    }

    /// The receiver-wide concurrency cap.
    #[must_use]
    pub const fn max_concurrent(&self) -> usize {
        self.max_concurrent
    }

    /// How many assemblies are open.
    #[must_use]
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Whether no assembly is open.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Bytes retained across every open assembly.
    #[must_use]
    pub fn retained(&self) -> u64 {
        self.slots
            .iter()
            .map(|(_, assembly)| assembly.retained())
            .sum()
    }

    /// The highest [`retained`](Self::retained) value this receiver reached.
    #[must_use]
    pub const fn peak_retained(&self) -> u64 {
        self.peak_retained
    }

    /// Opens one assembly for `session`.
    ///
    /// Refused as [`ArtifactError::SessionBusy`] while that session already
    /// drives one, and as [`ArtifactError::ReceiverFull`] once the
    /// receiver-wide cap is reached. Every manifest check of
    /// [`ArtifactAssembly::open`] applies.
    pub fn open(
        &mut self,
        session: SessionKey,
        request: &ArtifactRequest,
        manifest: &ArtifactManifest,
        step: u64,
        deadline: u64,
    ) -> Result<(), ArtifactError> {
        if self.slots.iter().any(|(held, _)| *held == session) {
            return Err(ArtifactError::SessionBusy);
        }
        if self.slots.len() >= self.max_concurrent {
            return Err(ArtifactError::ReceiverFull);
        }
        let assembly = ArtifactAssembly::open(request, manifest, step, deadline)?;
        self.slots.push((session, assembly));
        Ok(())
    }

    /// Offers a block to `session`'s assembly.
    ///
    /// An assembly that aborts, passes its deadline, or fails the whole-artifact
    /// digest frees its slot at once, so the session may request again. A
    /// completed assembly holds its slot until [`take`](Self::take).
    pub fn accept(
        &mut self,
        session: SessionKey,
        block: &Block,
        step: u64,
    ) -> Result<Accepted, ArtifactError> {
        let position = self.position(session).ok_or(ArtifactError::NoAssembly)?;
        let outcome = self.slots[position].1.accept(block, step);
        self.peak_retained = self.peak_retained.max(self.retained());
        match outcome {
            Ok(Accepted::Restart) | Err(_) => {
                if self.slots[position].1.is_closed() {
                    self.slots.remove(position);
                }
            }
            Ok(_) => {}
        }
        outcome
    }

    /// Yields `session`'s verified bytes once and frees its slot.
    pub fn take(&mut self, session: SessionKey) -> Result<Vec<u8>, ArtifactError> {
        let position = self.position(session).ok_or(ArtifactError::NoAssembly)?;
        if !self.slots[position].1.is_complete() {
            return Err(ArtifactError::NotComplete);
        }
        let (_, assembly) = self.slots.remove(position);
        assembly.take()
    }

    /// Drops `session`'s assembly and frees its slot.
    pub fn abort(&mut self, session: SessionKey) -> Result<(), ArtifactError> {
        let position = self.position(session).ok_or(ArtifactError::NoAssembly)?;
        self.slots.remove(position);
        Ok(())
    }

    /// Reads `session`'s assembly.
    #[must_use]
    pub fn get(&self, session: SessionKey) -> Option<&ArtifactAssembly> {
        self.position(session).map(|at| &self.slots[at].1)
    }

    fn position(&self, session: SessionKey) -> Option<usize> {
        self.slots.iter().position(|(held, _)| *held == session)
    }
}

/// Why a browser record sequence is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordError {
    /// A record is shorter than the header, longer than
    /// [`MAX_RECORD_LEN`], or its body is not the length its header implies.
    Length,
    /// A record does not start with [`RECORD_MAGIC`].
    Format,
    /// The records are not the exact in-order cover of the object, or there
    /// are too many of them.
    Order,
    /// The records disagree about the total, or claim more than one block.
    Total,
    /// The carried digest is not the SHA-256 of the reassembled bytes, or the
    /// records disagree about it.
    Digest,
}

/// Splits one block's bytes into `prototypes/browser-records` records.
///
/// Each record is `VR01 | total:u32be | offset:u32be | sha256:32 | body`,
/// where `total` is the block's byte count, `offset` is that record's start,
/// and `sha256` is the plain SHA-256 of the whole block bytes, repeated in
/// every record. Every body is exactly [`RECORD_BODY_LEN`] bytes except the
/// final one, which is the exact remainder. A block with no bytes is one
/// header-only record carrying the SHA-256 of empty bytes.
///
/// Refuses a block longer than [`BLOCK_LEN`], which the block decoder already
/// rejects on the wire. The block's digest is unchanged by the mapping, so
/// [`join_records`] hands [`ArtifactAssembly::accept`] exactly the bytes a
/// native receiver would have seen.
pub fn split_block(block: &Block) -> Result<Vec<Vec<u8>>, RecordError> {
    let body = &block.bytes;
    if body.len() > BLOCK_LEN as usize {
        return Err(RecordError::Length);
    }
    let digest = <[u8; 32]>::from(Sha256::digest(body));
    let total = body.len() as u32;
    let mut records = Vec::with_capacity(body.len().div_ceil(RECORD_BODY_LEN).max(1));
    let mut offset = 0_usize;
    loop {
        let end = body.len().min(offset + RECORD_BODY_LEN);
        let mut record = Vec::with_capacity(RECORD_HEADER_LEN + end - offset);
        record.extend_from_slice(&RECORD_MAGIC);
        record.extend_from_slice(&total.to_be_bytes());
        record.extend_from_slice(&(offset as u32).to_be_bytes());
        record.extend_from_slice(&digest);
        record.extend_from_slice(&body[offset..end]);
        records.push(record);
        offset = end;
        if offset >= body.len() {
            break;
        }
    }
    Ok(records)
}

/// Reassembles browser records into one block's bytes.
///
/// Checks the magic, that every record agrees on the total and the digest,
/// that the records are the exact in-order cover of that total with every body
/// but the last exactly [`RECORD_BODY_LEN`] bytes, that the total is at most
/// [`BLOCK_LEN`] and the records at most [`MAX_RECORDS_PER_BLOCK`], and that
/// the reassembled bytes hash to the carried digest. Nothing is allocated
/// before the total is admitted.
pub fn join_records(records: &[Vec<u8>]) -> Result<Vec<u8>, RecordError> {
    let first = records.first().ok_or(RecordError::Order)?;
    if records.len() > MAX_RECORDS_PER_BLOCK {
        return Err(RecordError::Order);
    }
    if first.len() < RECORD_HEADER_LEN {
        return Err(RecordError::Length);
    }
    if first[..4] != RECORD_MAGIC {
        return Err(RecordError::Format);
    }
    let total = u32::from_be_bytes([first[4], first[5], first[6], first[7]]) as usize;
    if total > BLOCK_LEN as usize {
        return Err(RecordError::Total);
    }
    if records.len() != total.div_ceil(RECORD_BODY_LEN).max(1) {
        return Err(RecordError::Order);
    }
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&first[12..RECORD_HEADER_LEN]);
    let mut bytes = Vec::with_capacity(total);
    for (index, record) in records.iter().enumerate() {
        if !(RECORD_HEADER_LEN..=MAX_RECORD_LEN).contains(&record.len()) {
            return Err(RecordError::Length);
        }
        if record[..4] != RECORD_MAGIC {
            return Err(RecordError::Format);
        }
        if u32::from_be_bytes([record[4], record[5], record[6], record[7]]) as usize != total {
            return Err(RecordError::Total);
        }
        if record[12..RECORD_HEADER_LEN] != digest {
            return Err(RecordError::Digest);
        }
        let offset = u32::from_be_bytes([record[8], record[9], record[10], record[11]]) as usize;
        if offset != index * RECORD_BODY_LEN {
            return Err(RecordError::Order);
        }
        if record.len() - RECORD_HEADER_LEN != RECORD_BODY_LEN.min(total - offset) {
            return Err(RecordError::Length);
        }
        bytes.extend_from_slice(&record[RECORD_HEADER_LEN..]);
    }
    if <[u8; 32]>::from(Sha256::digest(&bytes)) != digest {
        return Err(RecordError::Digest);
    }
    Ok(bytes)
}

/// Rebuilds the whole block a browser receiver was sent.
///
/// The block header travels beside the records, so the caller supplies the
/// manifest digest, index, and offset it already read, and [`join_records`]
/// supplies the bytes. The result is offered to
/// [`ArtifactAssembly::accept`] exactly as a natively delivered block is.
pub fn block_from_records(
    manifest: ArtifactManifestHash,
    index: u8,
    offset: u64,
    records: &[Vec<u8>],
) -> Result<Block, RecordError> {
    Ok(Block {
        manifest,
        index,
        offset,
        bytes: join_records(records)?,
    })
}
