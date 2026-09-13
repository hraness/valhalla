#![no_std]
#![forbid(unsafe_code)]
//! Disposable attention model. The caller, not this model, verifies social facts
//! and proves filesystem durability. No wire signatures or native journal exist here.

extern crate alloc;

use alloc::{collections::BTreeSet, vec::Vec};
use sha2::{Digest, Sha256};

pub type Id = [u8; 32];
pub const MAX_INPUTS: usize = 256;
pub const MAX_PAGE: usize = 64;
pub const MAX_MARKS: usize = 256;
pub const MAX_BYTES: usize = 100_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Bounds,
    Encoding,
    Namespace,
    MissingDurableSource,
    ConflictingInput,
}

/// Explicit local selection; a remote record never supplies this namespace.
/// Namespace partitioning is not protection against another same-OS-user process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reader {
    pub realm: Id,
    pub owner: Id,
    pub agent: Option<Id>,
    pub profile: Id,
    pub device: Id,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u8)]
pub enum Reason {
    Mention = 0,
    Reply = 1,
    Follow = 2,
    Reaction = 3,
    Repost = 4,
    Quote = 5,
    WatchedThread = 6,
}

/// Mentions use original post as target; repeated preferences use their target
/// slot. Agents of one owner do not multiply this group. Original recipient-agent
/// routes belong in presentation provenance, not its priority identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Group {
    pub recipient: Id,
    pub source_owner: Id,
    pub target: Id,
    pub reason: Reason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Update {
    pub group: Group,
    pub event: Id,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Committed,
    Provisional,
    Pending,
    Invalid,
}

/// Current derived view row, not a raw remote event. The social adapter is
/// responsible for recipient binding, causal resolution and control validity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fact {
    pub update: Update,
    pub state: State,
    pub active: bool,
    /// Local selected-source/positive-interaction policy. Negative reactions and
    /// unfollows can appear as activity without urgent priority.
    pub priority: bool,
}

/// Model stand-in for a native store's durable-source receipt. Construction only
/// checks its size; production must mint this only after canonical commit/readback.
#[derive(Clone, Debug)]
pub struct Durable {
    realm: Id,
    basis: Id,
    ids: BTreeSet<Id>,
}

impl Durable {
    pub fn model_fixture(realm: Id, basis: Id, ids: &[Id]) -> Result<Self, Error> {
        if ids.len() > MAX_INPUTS {
            return Err(Error::Bounds);
        }
        Ok(Self {
            realm,
            basis,
            ids: ids.iter().copied().collect(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Read {
    Unread,
    Read,
    /// The bounded local journal no longer proves an exact answer.
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Entry {
    pub update: Update,
    pub state: State,
    pub priority: Option<Read>,
    pub revision: Read,
}

/// Exact entry IDs issued by this local API. It contains no remote timestamps,
/// high-water marks or executable data. Fields deliberately remain private.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    reader: Reader,
    basis: Id,
    entries: Vec<Entry>,
    total: usize,
}

impl Snapshot {
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }
    pub fn total(&self) -> usize {
        self.total
    }
    pub fn basis(&self) -> Id {
        self.basis
    }
    pub fn reader(&self) -> Reader {
        self.reader
    }

    /// Counts the shown page only. Group priority is deduplicated independently
    /// of exact revision alternatives. Unknown is never silently counted as zero.
    pub fn counts(&self) -> Counts {
        let mut unread = 0;
        let mut unknown = 0;
        let mut priority_unread = BTreeSet::new();
        let mut priority_unknown = BTreeSet::new();
        for entry in &self.entries {
            match entry.revision {
                Read::Unread => unread += 1,
                Read::Unknown => unknown += 1,
                Read::Read => {}
            }
            match entry.priority {
                Some(Read::Unread) => {
                    priority_unread.insert(entry.update.group);
                }
                Some(Read::Unknown) => {
                    priority_unknown.insert(entry.update.group);
                }
                Some(Read::Read) | None => {}
            }
        }
        Counts {
            unread_revisions: unread,
            unknown_revisions: unknown,
            unread_groups: priority_unread.len(),
            unknown_groups: priority_unknown.len(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Counts {
    pub unread_revisions: usize,
    pub unknown_revisions: usize,
    pub unread_groups: usize,
    pub unknown_groups: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attention {
    reader: Reader,
    capacity: usize,
    read_groups: BTreeSet<Group>,
    read_updates: BTreeSet<Update>,
    groups_unknown: bool,
    updates_unknown: bool,
}

impl Attention {
    pub fn new(reader: Reader, capacity: usize) -> Result<Self, Error> {
        if capacity == 0 || capacity > MAX_MARKS {
            return Err(Error::Bounds);
        }
        Ok(Self {
            reader,
            capacity,
            read_groups: BTreeSet::new(),
            read_updates: BTreeSet::new(),
            groups_unknown: false,
            updates_unknown: false,
        })
    }

    /// Bounded deterministic projection: input order/duplication is immaterial.
    /// No state changes merely because an agent queried or prefetched an inbox.
    pub fn snapshot(
        &self,
        durable: &Durable,
        facts: &[Fact],
        live: bool,
        offset: usize,
        limit: usize,
    ) -> Result<Snapshot, Error> {
        if facts.len() > MAX_INPUTS || limit == 0 || limit > MAX_PAGE {
            return Err(Error::Bounds);
        }
        if durable.realm != self.reader.realm {
            return Err(Error::Namespace);
        }
        let mut unique = alloc::collections::BTreeMap::new();
        for fact in facts {
            if let Some(old) = unique.insert(fact.update, *fact) {
                if old != *fact {
                    return Err(Error::ConflictingInput);
                }
            }
        }
        let mut entries = Vec::new();
        let mut total = 0;
        for fact in unique.values() {
            if fact.update.group.recipient != self.reader.owner
                || !fact.active
                || !(fact.state == State::Committed || (live && fact.state == State::Provisional))
            {
                continue;
            }
            if !durable.ids.contains(&fact.update.event) {
                return Err(Error::MissingDurableSource);
            }
            if total >= offset && entries.len() < limit {
                entries.push(Entry {
                    update: fact.update,
                    state: fact.state,
                    priority: fact.priority.then(|| {
                        status(
                            self.read_groups.contains(&fact.update.group),
                            self.groups_unknown,
                        )
                    }),
                    revision: status(
                        self.read_updates.contains(&fact.update),
                        self.updates_unknown,
                    ),
                });
            }
            total += 1;
        }
        Ok(Snapshot {
            reader: self.reader,
            basis: durable.basis,
            entries,
            total,
        })
    }

    /// Construct a candidate private state only. The caller must persist it in
    /// its own atomic journal before claiming the acknowledgement succeeded.
    /// Later source additions are allowed; every exact acknowledged source must
    /// still be present. This is not a cross-store transaction or rollback proof.
    pub fn acknowledge(&self, shown: &Snapshot, current: &Durable) -> Result<Self, Error> {
        if shown.reader != self.reader || current.realm != self.reader.realm {
            return Err(Error::Namespace);
        }
        if shown
            .entries
            .iter()
            .any(|entry| !current.ids.contains(&entry.update.event))
        {
            return Err(Error::MissingDurableSource);
        }
        let mut next = self.clone();
        for entry in &shown.entries {
            if next.read_groups.len() < next.capacity
                || next.read_groups.contains(&entry.update.group)
            {
                next.read_groups.insert(entry.update.group);
            } else {
                next.groups_unknown = true;
            }
            if next.read_updates.len() < next.capacity || next.read_updates.contains(&entry.update)
            {
                next.read_updates.insert(entry.update);
            } else {
                next.updates_unknown = true;
            }
        }
        Ok(next)
    }

    /// Explicit bounded-retention operation. Missing history becomes Unknown;
    /// clearing exact marks never resurrects previously acknowledged revisions.
    pub fn forget_exact_marks(&mut self) {
        self.read_updates.clear();
        self.updates_unknown = true;
    }

    /// Retain orphaned marks after partial source restore. These count unresolved,
    /// not as proof of receipt/delivery and never match a different source ID.
    pub fn unresolved_marks(&self, current: &Durable) -> usize {
        self.read_updates
            .iter()
            .filter(|update| !current.ids.contains(&update.event))
            .count()
    }

    pub fn retained(&self) -> (usize, usize) {
        (self.read_groups.len(), self.read_updates.len())
    }

    /// Canonical private-only format, bounded before decoding/allocation. Its
    /// checksum catches damage but is neither authentication nor a freshness pin.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"VHATTN01");
        put_reader(&mut bytes, self.reader);
        put_u16(&mut bytes, self.capacity);
        bytes.push(u8::from(self.groups_unknown));
        bytes.push(u8::from(self.updates_unknown));
        put_u16(&mut bytes, self.read_groups.len());
        for group in &self.read_groups {
            put_group(&mut bytes, *group);
        }
        put_u16(&mut bytes, self.read_updates.len());
        for update in &self.read_updates {
            put_group(&mut bytes, update.group);
            bytes.extend_from_slice(&update.event);
        }
        let checksum = Sha256::digest(&bytes);
        bytes.extend_from_slice(&checksum);
        assert!(bytes.len() <= MAX_BYTES);
        bytes
    }

    pub fn decode(bytes: &[u8], expected_reader: Reader) -> Result<Self, Error> {
        if bytes.len() > MAX_BYTES || bytes.len() < 32 {
            return Err(Error::Bounds);
        }
        let (body, checksum) = bytes.split_at(bytes.len() - 32);
        if Sha256::digest(body).as_slice() != checksum {
            return Err(Error::Encoding);
        }
        let mut input = Input { bytes: body, at: 0 };
        if input.take(8)? != b"VHATTN01" {
            return Err(Error::Encoding);
        }
        let reader = input.reader()?;
        if reader != expected_reader {
            return Err(Error::Namespace);
        }
        let mut result = Self::new(reader, input.u16()?)?;
        result.groups_unknown = input.boolean()?;
        result.updates_unknown = input.boolean()?;
        let count = input.u16()?;
        if count > result.capacity {
            return Err(Error::Bounds);
        }
        let mut previous = None;
        for _ in 0..count {
            let group = input.group()?;
            if group.recipient != reader.owner || previous.is_some_and(|old| old >= group) {
                return Err(Error::Encoding);
            }
            previous = Some(group);
            result.read_groups.insert(group);
        }
        let count = input.u16()?;
        if count > result.capacity {
            return Err(Error::Bounds);
        }
        let mut previous = None;
        for _ in 0..count {
            let update = Update {
                group: input.group()?,
                event: input.id()?,
            };
            if update.group.recipient != reader.owner || previous.is_some_and(|old| old >= update) {
                return Err(Error::Encoding);
            }
            if !result.groups_unknown && !result.read_groups.contains(&update.group) {
                return Err(Error::Encoding);
            }
            previous = Some(update);
            result.read_updates.insert(update);
        }
        if input.at != body.len() {
            return Err(Error::Encoding);
        }
        Ok(result)
    }
}

fn status(present: bool, unknown: bool) -> Read {
    if present {
        Read::Read
    } else if unknown {
        Read::Unknown
    } else {
        Read::Unread
    }
}

fn put_u16(bytes: &mut Vec<u8>, value: usize) {
    bytes.extend_from_slice(&u16::try_from(value).expect("bounded count").to_le_bytes());
}
fn put_reader(bytes: &mut Vec<u8>, reader: Reader) {
    bytes.extend_from_slice(&reader.realm);
    bytes.extend_from_slice(&reader.owner);
    bytes.push(u8::from(reader.agent.is_some()));
    if let Some(agent) = reader.agent {
        bytes.extend_from_slice(&agent);
    }
    bytes.extend_from_slice(&reader.profile);
    bytes.extend_from_slice(&reader.device);
}
fn put_group(bytes: &mut Vec<u8>, group: Group) {
    bytes.extend_from_slice(&group.recipient);
    bytes.extend_from_slice(&group.source_owner);
    bytes.extend_from_slice(&group.target);
    bytes.push(group.reason as u8);
}

struct Input<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Input<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(count).ok_or(Error::Bounds)?;
        let result = self.bytes.get(self.at..end).ok_or(Error::Encoding)?;
        self.at = end;
        Ok(result)
    }
    fn id(&mut self) -> Result<Id, Error> {
        self.take(32)?.try_into().map_err(|_| Error::Encoding)
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn boolean(&mut self) -> Result<bool, Error> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Encoding),
        }
    }
    fn u16(&mut self) -> Result<usize, Error> {
        Ok(usize::from(u16::from_le_bytes(
            self.take(2)?.try_into().map_err(|_| Error::Encoding)?,
        )))
    }
    fn reader(&mut self) -> Result<Reader, Error> {
        Ok(Reader {
            realm: self.id()?,
            owner: self.id()?,
            agent: if self.boolean()? {
                Some(self.id()?)
            } else {
                None
            },
            profile: self.id()?,
            device: self.id()?,
        })
    }
    fn group(&mut self) -> Result<Group, Error> {
        Ok(Group {
            recipient: self.id()?,
            source_owner: self.id()?,
            target: self.id()?,
            reason: match self.byte()? {
                0 => Reason::Mention,
                1 => Reason::Reply,
                2 => Reason::Follow,
                3 => Reason::Reaction,
                4 => Reason::Repost,
                5 => Reason::Quote,
                6 => Reason::WatchedThread,
                _ => return Err(Error::Encoding),
            },
        })
    }
}
