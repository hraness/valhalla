//! E-2 spike: single fixed-name append log plus in-place double-slot heads for
//! the room-activity store. This is a measured design model, not production
//! code — it proves the barrier count, the tail/slot recovery cases, and the
//! bounded page read that a full port of `vhalla-room-activity-store` needs.
//!
//! Layout (all names fixed at store creation; nothing is ever created,
//! renamed or removed after that, so no directory barrier is ever needed):
//!
//! * `format`  — 8-byte format marker; a foreign marker is refused like the
//!   consensus WAL `VRW2` marker.
//! * `lock`    — empty lifetime lock (`try_lock_exclusive`).
//! * `log`     — append-only entry file. Entry =
//!   `[u32 len][kind=1][ordinal][author][sequence][expected_count]
//!   [expected_tail][cumulative_bytes][payload_len][payload][sha256]`.
//!   An entry present past the durable `HEAD.log_len` is exactly the retained
//!   intent of the v1 store: complete it or leave it, never rewrite it.
//! * `index`   — rebuildable ordinal→offset table, 16 bytes per record,
//!   appended before the head write and *not* synced: it is derived cache,
//!   never authority, and is re-verified against the log at open.
//! * `HEAD`    — one 8 KiB file holding two 4 KiB-aligned slots. Slot =
//!   `[generation][count][bytes][tail][log_len][author_count]
//!   [author table][pad][sha256]`. The writer alternates slots; the reader
//!   takes the highest-generation slot whose hash verifies, so a torn slot
//!   write can only produce the old or the new complete head.
//!
//! Steady-state append is two F_FULLFSYNC calls (log, then HEAD) versus
//! twelve in the shipped v1 store after E-1. `pwrite` on a 4 KiB-aligned
//! slot is a single-sector-class update; a crash either keeps the old slot
//! or installs the new one, and the hash check rejects the torn case.
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::path::Path;

const FORMAT_FILE: &str = "format";
const FORMAT_MAGIC: &[u8; 8] = b"VAAL\x02\0\0\0";
const LOCK_FILE: &str = "lock";
const LOG_FILE: &str = "log";
const INDEX_FILE: &str = "index";
const HEAD_FILE: &str = "HEAD";
const SLOT_BYTES: usize = 4096;
const SLOT_HASH_AT: usize = SLOT_BYTES - 32;
const HEAD_PREFIX: usize = 8 + 8 + 8 + 32 + 8 + 2;
const AUTHOR_SLOT: usize = 32 + 8 + 8 + 8;
pub const MAX_AUTHORS: usize = (SLOT_HASH_AT - HEAD_PREFIX) / AUTHOR_SLOT;
pub const MAX_PAGE: usize = 64;
const INDEX_ENTRY: u64 = 16;
const ENTRY_OVERHEAD: usize = 4 + 1 + 8 + 32 + 8 + 8 + 32 + 8 + 4 + 32;
const MAX_PAYLOAD: usize = 16 * 1024;

#[derive(Debug)]
pub enum Error {
    Busy,
    ForeignFormat,
    Corrupt,
    /// A complete retained entry or torn tail must be resolved by recover().
    RecoveryRequired,
    /// Author sequence does not extend the retained author head.
    Gap,
    /// An already-admitted (author, sequence) names different bytes.
    Conflict,
    /// Fixed bound exceeded (authors per head table, payload, page size).
    Capacity,
    Io(io::Error),
    /// An injected protocol interruption; the disk state is as left.
    Injected,
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

/// Protocol interruption points, the log-granularity port of the v1 `Step`
/// table: a fault armed at one fires once at that exact point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Step {
    /// Log entry bytes written, inode sync not yet attempted.
    EntryWritten,
    /// Log inode durable: this is the intent-before-effect boundary — a
    /// crash here leaves a complete retained intent on the tail.
    EntrySynced,
    /// Derived index entry written (never synced; rebuildable).
    IndexWritten,
    /// Head slot bytes written via pwrite, file sync not yet attempted.
    HeadSlotWritten,
    /// Head file durable: the acknowledgement boundary.
    HeadSlotSynced,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry {
    pub ordinal: u64,
    pub author: [u8; 32],
    pub sequence: u64,
    pub bytes: u64,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Head {
    pub generation: u64,
    pub count: u64,
    pub bytes: u64,
    pub tail: [u8; 32],
    pub log_len: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuthorHead {
    sequence: u64,
    ordinal: u64,
}

pub struct Store {
    _lock: File,
    log: File,
    index: File,
    head_file: File,
    head: Head,
    authors: BTreeMap<[u8; 32], AuthorHead>,
    sequences: BTreeMap<([u8; 32], u64), u64>,
    offsets: Vec<u64>,
    /// Complete retained intent: (frame length, entry, digest) for a valid
    /// tail entry the head does not cover.
    pending: Option<(u64, Entry, [u8; 32])>,
    /// Bytes after head.log_len that are not a valid entry: retained evidence.
    torn_tail: bool,
    syncs: Cell<u64>,
    fault: Cell<Option<Step>>,
}

impl Store {
    /// Create a fresh store; a preexisting directory is never adopted.
    pub fn create(dir: impl AsRef<Path>) -> Result<Self, Error> {
        let dir = dir.as_ref();
        fs::create_dir(dir)?;
        fs::write(dir.join(FORMAT_FILE), FORMAT_MAGIC)?;
        File::create(dir.join(LOCK_FILE))?;
        File::create(dir.join(LOG_FILE))?;
        File::create(dir.join(INDEX_FILE))?;
        File::create(dir.join(HEAD_FILE))?.set_len(2 * SLOT_BYTES as u64)?;
        Self::open(dir)
    }

    /// Open existing evidence: pick the highest valid head slot, validate the
    /// log prefix it names, and classify the tail as retained intent or torn.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, Error> {
        let dir = dir.as_ref().to_path_buf();
        if fs::read(dir.join(FORMAT_FILE)).map_err(|_| Error::Corrupt)? != FORMAT_MAGIC {
            return Err(Error::ForeignFormat);
        }
        let lock = File::open(dir.join(LOCK_FILE))?;
        lock.try_lock().map_err(|_| Error::Busy)?;
        let log = OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.join(LOG_FILE))?;
        let index = OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.join(INDEX_FILE))?;
        let head_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.join(HEAD_FILE))?;
        let (head, authors) = read_head(&head_file)?;
        let mut raw = Vec::new();
        File::open(dir.join(LOG_FILE))?.read_to_end(&mut raw)?;
        if (raw.len() as u64) < head.log_len {
            return Err(Error::Corrupt);
        }
        // Validate the authoritative prefix and rebuild the derived tables:
        // author heads, exact-retry sequence map, and entry offsets.
        let mut offsets = Vec::new();
        let mut sequences = BTreeMap::new();
        let mut live_authors = BTreeMap::new();
        let mut at = 0usize;
        let mut expect = Head::default();
        while (at as u64) < head.log_len {
            let (frame, entry, digest) = parse_frame(&raw[at..])?;
            if entry.ordinal != expect.count + 1 || entry.bytes <= expect.bytes {
                return Err(Error::Corrupt);
            }
            expect = Head {
                count: entry.ordinal,
                bytes: entry.bytes,
                tail: digest,
                ..expect
            };
            if sequences
                .insert((entry.author, entry.sequence), entry.ordinal)
                .is_some()
            {
                return Err(Error::Corrupt);
            }
            live_authors.insert(
                entry.author,
                AuthorHead {
                    sequence: entry.sequence,
                    ordinal: entry.ordinal,
                },
            );
            offsets.push(at as u64);
            at += frame;
        }
        if expect.count != head.count || expect.bytes != head.bytes || expect.tail != head.tail {
            return Err(Error::Corrupt);
        }
        if authors != live_authors {
            return Err(Error::Corrupt);
        }
        // One tail classification: a complete valid entry that continues the
        // head is a retained intent; anything else is torn evidence.
        let tail = &raw[at..];
        let mut pending = None;
        let mut torn_tail = false;
        if !tail.is_empty() {
            match parse_frame(tail) {
                Ok((frame, entry, digest))
                    if entry.ordinal == head.count + 1 && entry.bytes > head.bytes =>
                {
                    // Only the first tail frame is claimed; further complete
                    // frames become pending on the next open, in order.
                    pending = Some((frame as u64, entry, digest));
                }
                _ => torn_tail = true,
            }
        }
        let mut store = Self {
            _lock: lock,
            log,
            index,
            head_file,
            head,
            authors: live_authors,
            sequences,
            offsets,
            pending,
            torn_tail,
            syncs: Cell::new(0),
            fault: Cell::new(None),
        };
        store.rebuild_index()?;
        Ok(store)
    }

    pub fn head(&self) -> Head {
        self.head
    }
    /// Whether a retained intent or torn tail needs recover() before writes.
    pub fn recovery_required(&self) -> bool {
        self.pending.is_some() || self.torn_tail
    }
    /// F_FULLFSYNC-equivalent calls issued since open — the spike's ledger.
    pub fn sync_count(&self) -> u64 {
        self.syncs.get()
    }
    /// Arm a single-shot fault at a protocol point (tests only, unlike the
    /// production store the spike keeps this method unrestricted).
    pub fn fault(&self, step: Step) {
        self.fault.set(Some(step));
    }
    fn step(&self, step: Step) -> Result<(), Error> {
        if self.fault.get() == Some(step) {
            self.fault.set(None);
            return Err(Error::Injected);
        }
        Ok(())
    }
    fn sync(&self, file: &File) -> Result<(), Error> {
        file.sync_all()?;
        self.syncs.set(self.syncs.get() + 1);
        Ok(())
    }

    /// Admit one record. Exact retries reconcile; a different pending intent
    /// refuses RecoveryRequired. The receipt is returned only after the head
    /// slot is durable — cleanup-before-ack is the head commit itself.
    pub fn append(
        &mut self,
        author: [u8; 32],
        sequence: u64,
        payload: &[u8],
    ) -> Result<Entry, Error> {
        if self.torn_tail {
            return Err(Error::RecoveryRequired);
        }
        if let Some((_, entry, _)) = &self.pending {
            if entry.author == author && entry.sequence == sequence && entry.payload == payload {
                return self.finish();
            }
            return Err(Error::RecoveryRequired);
        }
        if let Some(ordinal) = self.sequences.get(&(author, sequence)) {
            let stored = self.read_entry(*ordinal)?;
            if stored.payload != payload {
                return Err(Error::Conflict);
            }
            return Ok(stored);
        }
        let expect = self
            .authors
            .get(&author)
            .map(|a| a.sequence + 1)
            .unwrap_or(1);
        if sequence != expect {
            return Err(Error::Gap);
        }
        if self.authors.len() >= MAX_AUTHORS && !self.authors.contains_key(&author) {
            return Err(Error::Capacity);
        }
        if payload.len() > MAX_PAYLOAD {
            return Err(Error::Capacity);
        }
        let ordinal = self.head.count + 1;
        let bytes = self.head.bytes + (ENTRY_OVERHEAD + payload.len()) as u64;
        let frame = encode_frame(ordinal, author, sequence, self.head, bytes, payload);
        self.log.seek(SeekFrom::End(0))?;
        self.log.write_all(&frame)?;
        self.step(Step::EntryWritten)?;
        self.sync(&self.log)?;
        self.step(Step::EntrySynced)?;
        // From here the complete intent is durable; finishing it is exact and
        // idempotent, identical to the retained-intent path after a crash.
        self.pending = Some((
            frame.len() as u64,
            Entry {
                ordinal,
                author,
                sequence,
                bytes,
                payload: payload.to_vec(),
            },
            // Entry digest covers the body only — the same bytes decode_body
            // hashes when it re-verifies the frame at open.
            Sha256::digest(&frame[4..frame.len() - 32]).into(),
        ));
        self.finish()
    }

    /// Complete the retained intent exactly once, or discard a demonstrably
    /// torn tail (a partial frame can never be a valid intent — the v1 store
    /// removes a torn intent.tmp the same way). Returns what it reconciled.
    pub fn recover(&mut self) -> Result<Option<Entry>, Error> {
        if self.pending.is_some() {
            return self.finish().map(Some);
        }
        if self.torn_tail {
            self.log.set_len(self.head.log_len)?;
            self.sync(&self.log)?;
            self.torn_tail = false;
        }
        Ok(None)
    }

    /// Bounded random-access page: at most MAX_PAGE records by ordinal, read
    /// through the rebuilt/verified index — never a full-log enumeration.
    pub fn read_page(&self, after: u64, limit: usize) -> Result<Vec<Entry>, Error> {
        if limit == 0 || limit > MAX_PAGE {
            return Err(Error::Capacity);
        }
        if after > self.head.count || self.pending.is_some() || self.torn_tail {
            return Err(Error::RecoveryRequired);
        }
        let mut out = Vec::new();
        let mut cursor = after;
        while out.len() < limit && cursor < self.head.count {
            cursor += 1;
            out.push(self.read_entry(cursor)?);
        }
        Ok(out)
    }

    fn read_entry(&self, ordinal: u64) -> Result<Entry, Error> {
        let offset = *self
            .offsets
            .get((ordinal - 1) as usize)
            .ok_or(Error::Corrupt)?;
        let mut len = [0u8; 4];
        self.log.read_exact_at(&mut len, offset)?;
        let len = u32::from_le_bytes(len) as usize;
        let mut body = vec![0u8; len];
        self.log.read_exact_at(&mut body, offset + 4)?;
        let (entry, digest) = decode_body(&body)?;
        if entry.ordinal != ordinal {
            return Err(Error::Corrupt);
        }
        if ordinal == self.head.count && digest != self.head.tail {
            return Err(Error::Corrupt);
        }
        Ok(entry)
    }

    /// Finish the durable intent: index write (no barrier — derived cache),
    /// then the alternating head slot and its single barrier. The pending
    /// intent is retained in memory until every fallible step has passed —
    /// a fault mid-finish must leave exactly the evidence a crash would.
    fn finish(&mut self) -> Result<Entry, Error> {
        let (frame_len, entry, digest) = self.pending.clone().ok_or(Error::Corrupt)?;
        // Index entry for this ordinal; synced only as a side effect of the
        // HEAD barrier, and rebuilt at open regardless — never authority.
        let mut record = [0u8; INDEX_ENTRY as usize];
        record[..8].copy_from_slice(&self.head.log_len.to_le_bytes());
        record[8..].copy_from_slice(&frame_len.to_le_bytes());
        self.index.seek(SeekFrom::End(0))?;
        self.index.write_all(&record)?;
        self.step(Step::IndexWritten)?;
        let mut authors = self.authors.clone();
        authors.insert(
            entry.author,
            AuthorHead {
                sequence: entry.sequence,
                ordinal: entry.ordinal,
            },
        );
        let head = Head {
            generation: self.head.generation + 1,
            count: entry.ordinal,
            bytes: entry.bytes,
            tail: digest,
            log_len: self.head.log_len + frame_len,
        };
        let slot = encode_slot(&head, &authors);
        let at = (head.generation % 2) * SLOT_BYTES as u64;
        self.head_file.write_all_at(&slot, at)?;
        self.step(Step::HeadSlotWritten)?;
        self.sync(&self.head_file)?;
        self.step(Step::HeadSlotSynced)?;
        // The head is durable; in-memory state now commits the same evidence.
        self.pending = None;
        self.sequences
            .insert((entry.author, entry.sequence), entry.ordinal);
        self.authors = authors;
        self.offsets.push(self.head.log_len);
        self.head = head;
        Ok(entry)
    }

    /// Re-verify and rewrite the derived index file against the authoritative
    /// prefix; a torn or stale tail index entry is simply not authority.
    fn rebuild_index(&mut self) -> Result<(), Error> {
        let len = self.index.metadata()?.len();
        let want = self.head.count * INDEX_ENTRY;
        if len != want {
            self.index.set_len(0)?;
            let mut raw = Vec::with_capacity(want as usize);
            for offset in &self.offsets {
                let next = offsets_entry(*offset);
                raw.extend_from_slice(&next);
            }
            self.index.write_all(&raw)?;
            return Ok(());
        }
        let mut raw = vec![0u8; len as usize];
        self.index.read_exact_at(&mut raw, 0)?;
        for (i, offset) in self.offsets.iter().enumerate() {
            let at = i * INDEX_ENTRY as usize;
            if u64::from_le_bytes(raw[at..at + 8].try_into().unwrap()) != *offset {
                return Err(Error::Corrupt);
            }
        }
        Ok(())
    }
}

fn offsets_entry(offset: u64) -> [u8; INDEX_ENTRY as usize] {
    let mut record = [0u8; INDEX_ENTRY as usize];
    record[..8].copy_from_slice(&offset.to_le_bytes());
    record
}

fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn encode_frame(
    ordinal: u64,
    author: [u8; 32],
    sequence: u64,
    expected: Head,
    bytes: u64,
    payload: &[u8],
) -> Vec<u8> {
    let body_len = ENTRY_OVERHEAD - 4 + payload.len();
    let mut frame = Vec::with_capacity(4 + body_len);
    frame.extend_from_slice(&(body_len as u32).to_le_bytes());
    frame.push(1u8);
    frame.extend_from_slice(&ordinal.to_le_bytes());
    frame.extend_from_slice(&author);
    frame.extend_from_slice(&sequence.to_le_bytes());
    frame.extend_from_slice(&expected.count.to_le_bytes());
    frame.extend_from_slice(&expected.tail);
    frame.extend_from_slice(&bytes.to_le_bytes());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(payload);
    let digest = sha(&frame[4..]);
    frame.extend_from_slice(&digest);
    frame
}

fn decode_body(body: &[u8]) -> Result<(Entry, [u8; 32]), Error> {
    if body.len() < ENTRY_OVERHEAD - 4 {
        return Err(Error::Corrupt);
    }
    let expected: [u8; 32] = body[body.len() - 32..].try_into().unwrap();
    if sha(&body[..body.len() - 32]) != expected {
        return Err(Error::Corrupt);
    }
    let take = |at: usize, n: usize| -> Result<&[u8], Error> {
        body.get(at..at + n).ok_or(Error::Corrupt)
    };
    if take(0, 1)? != [1] {
        return Err(Error::Corrupt);
    }
    let ordinal = u64::from_le_bytes(take(1, 8)?.try_into().unwrap());
    let author: [u8; 32] = take(9, 32)?.try_into().unwrap();
    let sequence = u64::from_le_bytes(take(41, 8)?.try_into().unwrap());
    let bytes = u64::from_le_bytes(take(89, 8)?.try_into().unwrap());
    let payload_len = u32::from_le_bytes(take(97, 4)?.try_into().unwrap()) as usize;
    if payload_len > MAX_PAYLOAD || 101 + payload_len + 32 != body.len() {
        return Err(Error::Corrupt);
    }
    Ok((
        Entry {
            ordinal,
            author,
            sequence,
            bytes,
            payload: take(101, payload_len)?.to_vec(),
        },
        sha(&body[..body.len() - 32]),
    ))
}

/// Parse one frame at the start of `raw`; returns (frame_len, entry, digest).
fn parse_frame(raw: &[u8]) -> Result<(usize, Entry, [u8; 32]), Error> {
    if raw.len() < 4 {
        return Err(Error::Corrupt);
    }
    let len = u32::from_le_bytes(raw[..4].try_into().unwrap()) as usize;
    if !(ENTRY_OVERHEAD - 4..=ENTRY_OVERHEAD - 4 + MAX_PAYLOAD).contains(&len) {
        return Err(Error::Corrupt);
    }
    let body = raw.get(4..4 + len).ok_or(Error::Corrupt)?;
    let (entry, digest) = decode_body(body)?;
    Ok((4 + len, entry, digest))
}

fn encode_slot(head: &Head, authors: &BTreeMap<[u8; 32], AuthorHead>) -> [u8; SLOT_BYTES] {
    let mut slot = [0u8; SLOT_BYTES];
    slot[0..8].copy_from_slice(&head.generation.to_le_bytes());
    slot[8..16].copy_from_slice(&head.count.to_le_bytes());
    slot[16..24].copy_from_slice(&head.bytes.to_le_bytes());
    slot[24..56].copy_from_slice(&head.tail);
    slot[56..64].copy_from_slice(&head.log_len.to_le_bytes());
    slot[64..66].copy_from_slice(&(authors.len() as u16).to_le_bytes());
    for (i, (author, head)) in authors.iter().enumerate() {
        let at = HEAD_PREFIX + i * AUTHOR_SLOT;
        slot[at..at + 32].copy_from_slice(author);
        slot[at + 32..at + 40].copy_from_slice(&head.sequence.to_le_bytes());
        slot[at + 40..at + 48].copy_from_slice(&head.ordinal.to_le_bytes());
    }
    let digest = sha(&slot[..SLOT_HASH_AT]);
    slot[SLOT_HASH_AT..].copy_from_slice(&digest);
    slot
}

fn decode_slot(slot: &[u8]) -> Option<(Head, BTreeMap<[u8; 32], AuthorHead>)> {
    if slot.len() != SLOT_BYTES {
        return None;
    }
    let expected: [u8; 32] = slot[SLOT_HASH_AT..].try_into().unwrap();
    if sha(&slot[..SLOT_HASH_AT]) != expected {
        return None;
    }
    let count = u64::from_le_bytes(slot[8..16].try_into().unwrap());
    let n = u16::from_le_bytes(slot[64..66].try_into().unwrap()) as usize;
    if HEAD_PREFIX + n * AUTHOR_SLOT > SLOT_HASH_AT {
        return None;
    }
    let mut authors = BTreeMap::new();
    for i in 0..n {
        let at = HEAD_PREFIX + i * AUTHOR_SLOT;
        let author: [u8; 32] = slot[at..at + 32].try_into().unwrap();
        authors.insert(
            author,
            AuthorHead {
                sequence: u64::from_le_bytes(slot[at + 32..at + 40].try_into().unwrap()),
                ordinal: u64::from_le_bytes(slot[at + 40..at + 48].try_into().unwrap()),
            },
        );
    }
    Some((
        Head {
            generation: u64::from_le_bytes(slot[0..8].try_into().unwrap()),
            count,
            bytes: u64::from_le_bytes(slot[16..24].try_into().unwrap()),
            tail: slot[24..56].try_into().unwrap(),
            log_len: u64::from_le_bytes(slot[56..64].try_into().unwrap()),
        },
        authors,
    ))
}

fn read_head(file: &File) -> Result<(Head, BTreeMap<[u8; 32], AuthorHead>), Error> {
    let mut best: Option<(Head, BTreeMap<[u8; 32], AuthorHead>)> = None;
    for slot_index in 0..2u64 {
        let mut slot = [0u8; SLOT_BYTES];
        file.read_exact_at(&mut slot, slot_index * SLOT_BYTES as u64)?;
        if let Some((head, authors)) = decode_slot(&slot) {
            if best
                .as_ref()
                .map(|(h, _)| head.generation > h.generation)
                .unwrap_or(true)
            {
                best = Some((head, authors));
            }
        }
    }
    Ok(best.unwrap_or_default())
}

#[cfg(test)]
mod tests;
