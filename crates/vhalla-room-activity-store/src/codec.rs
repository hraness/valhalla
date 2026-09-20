use crate::Error;
use sha2::{Digest, Sha256};
use vhalla_core::RealmId;
use vhalla_room_activity::{EventId, RoomScope, SignedEvent, VerifiedEvent, MAX_EVENT_BYTES};
use vhalla_rooms::{DirectoryId, RoomGenesisId};

const PIN_MAGIC: &[u8; 8] = b"VRAP\0\0\0\x01";
const FORMAT_MAGIC: &[u8; 8] = b"VRAF\0\0\0\x01";
const RECORD_MAGIC: &[u8; 8] = b"VRAR\0\0\0\x01";
const INDEX_MAGIC: &[u8; 8] = b"VRAX\0\0\0\x01";
const INTENT_MAGIC: &[u8; 8] = b"VRAI\0\0\0\x01";
/// Exact encoded local pin size. Authenticity depends on independent retention.
pub const PIN_BYTES: usize = 88;
pub(crate) const FORMAT_BYTES: usize = 168;
pub(crate) const INDEX_BYTES: usize = 120;
pub(crate) const RECORD_OVERHEAD: usize = 124;
pub(crate) const MAX_RECORD_BYTES: usize = RECORD_OVERHEAD + MAX_EVENT_BYTES;
pub(crate) const MAX_INTENT_BYTES: usize =
    8 + 2 * PIN_BYTES + 1 + INDEX_BYTES + 4 + MAX_RECORD_BYTES + 32;

/// Immutable local resource budget, not a protocol lifetime limit or entitlement.
/// Exhaustion refuses new admission; it never prunes old signed history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum locally stored records, including all application authors.
    pub max_events: u64,
    /// Maximum exact immutable receipt and sequence-index bytes. Directory,
    /// author-head and bounded transaction overhead need additional disk space.
    pub max_history_bytes: u64,
}
impl Limits {
    pub(crate) fn check(self) -> Result<(), Error> {
        if self.max_events == 0 || self.max_history_bytes == 0 {
            return Err(Error::Capacity);
        }
        Ok(())
    }
}

/// Local publication anchor, not a certificate or proof of global freshness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pin {
    pub(crate) count: u64,
    pub(crate) bytes: u64,
    pub(crate) tail: [u8; 32],
}
impl Pin {
    pub(crate) const EMPTY: Self = Self {
        count: 0,
        bytes: 0,
        tail: [0; 32],
    };
    /// Number of published local records; also the latest local paging cursor.
    pub const fn count(self) -> u64 {
        self.count
    }
    /// Exact accounted immutable receipt and sequence-index bytes.
    pub const fn history_bytes(self) -> u64 {
        self.bytes
    }
    /// Exact last local receipt digest, zero for an empty store.
    pub const fn tail(self) -> [u8; 32] {
        self.tail
    }
    /// Encode for caller-managed independent retention; includes no secret.
    pub fn encode(self) -> [u8; PIN_BYTES] {
        let mut raw = Vec::with_capacity(PIN_BYTES);
        raw.extend_from_slice(PIN_MAGIC);
        put_u64(&mut raw, self.count);
        put_u64(&mut raw, self.bytes);
        raw.extend_from_slice(&self.tail);
        finish(&mut raw);
        raw.try_into().expect("fixed pin layout")
    }
    /// Decode canonical local metadata. Checksums are not network authentication.
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() != PIN_BYTES {
            return Err(Error::Corrupt);
        }
        let mut r = checked(raw, PIN_MAGIC)?;
        let pin = Self {
            count: r.u64()?,
            bytes: r.u64()?,
            tail: r.array()?,
        };
        r.end()?;
        if (pin.count == 0) != (pin.bytes == 0) || (pin.count == 0) != (pin.tail == [0; 32]) {
            return Err(Error::Corrupt);
        }
        Ok(pin)
    }
}

pub(crate) fn format(scope: RoomScope, limits: Limits) -> Vec<u8> {
    let mut raw = Vec::with_capacity(FORMAT_BYTES);
    raw.extend_from_slice(FORMAT_MAGIC);
    raw.extend_from_slice(&scope.network);
    raw.extend_from_slice(&scope.realm.0.to_be_bytes());
    raw.extend_from_slice(scope.directory.as_bytes());
    raw.extend_from_slice(scope.room.as_bytes());
    put_u64(&mut raw, limits.max_events);
    put_u64(&mut raw, limits.max_history_bytes);
    finish(&mut raw);
    raw
}
pub(crate) fn decode_format(raw: &[u8]) -> Result<(RoomScope, Limits), Error> {
    if raw.len() != FORMAT_BYTES {
        return Err(Error::Corrupt);
    }
    let mut r = checked(raw, FORMAT_MAGIC)?;
    let scope = RoomScope {
        network: r.array()?,
        realm: RealmId(u128::from_be_bytes(r.array()?)),
        directory: DirectoryId::from_bytes(r.array()?),
        room: RoomGenesisId::from_bytes(r.array()?),
    };
    let limits = Limits {
        max_events: r.u64()?,
        max_history_bytes: r.u64()?,
    };
    r.end()?;
    limits.check()?;
    if scope.network == [0; 32] {
        return Err(Error::Corrupt);
    }
    Ok((scope, limits))
}

#[derive(Clone, Debug)]
pub(crate) struct Record {
    pub ordinal: u64,
    pub bytes: u64,
    pub previous: [u8; 32],
    pub registry: [u8; 32],
    pub event: VerifiedEvent,
}
impl Record {
    pub fn encode(&self) -> Vec<u8> {
        let event = self.event.encode();
        let mut raw = Vec::with_capacity(RECORD_OVERHEAD + event.len());
        raw.extend_from_slice(RECORD_MAGIC);
        put_u64(&mut raw, self.ordinal);
        put_u64(&mut raw, self.bytes);
        raw.extend_from_slice(&self.previous);
        raw.extend_from_slice(&self.registry);
        raw.extend_from_slice(&(event.len() as u32).to_be_bytes());
        raw.extend_from_slice(&event);
        finish(&mut raw);
        raw
    }
    pub fn decode(raw: &[u8], scope: RoomScope) -> Result<Self, Error> {
        if raw.len() > MAX_RECORD_BYTES || raw.len() < RECORD_OVERHEAD {
            return Err(Error::Corrupt);
        }
        let mut r = checked(raw, RECORD_MAGIC)?;
        let ordinal = r.u64()?;
        let bytes = r.u64()?;
        let previous = r.array()?;
        let registry = r.array()?;
        let length = u32::from_be_bytes(r.array()?) as usize;
        if length > MAX_EVENT_BYTES {
            return Err(Error::Corrupt);
        }
        let event = SignedEvent::decode(r.take(length)?)
            .map_err(Error::Activity)?
            .verify()
            .map_err(Error::Activity)?;
        r.end()?;
        if event.claims().scope != scope
            || ordinal == 0
            || (ordinal == 1) != (previous == [0; 32])
            || bytes < (raw.len() + INDEX_BYTES) as u64
        {
            return Err(Error::Corrupt);
        }
        if ordinal == 1 && bytes != (raw.len() + INDEX_BYTES) as u64 {
            return Err(Error::Corrupt);
        }
        Ok(Self {
            ordinal,
            bytes,
            previous,
            registry,
            event,
        })
    }
    pub fn digest(&self) -> [u8; 32] {
        checksum(&self.encode())
    }
    pub fn pin(&self) -> Pin {
        Pin {
            count: self.ordinal,
            bytes: self.bytes,
            tail: self.digest(),
        }
    }
    pub fn index(&self) -> Index {
        Index {
            ordinal: self.ordinal,
            sequence: self.event.claims().sequence,
            id: self.event.id(),
            receipt: self.digest(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Index {
    pub ordinal: u64,
    pub sequence: u64,
    pub id: EventId,
    pub receipt: [u8; 32],
}
impl Index {
    pub fn encode(self) -> Vec<u8> {
        let mut raw = Vec::with_capacity(INDEX_BYTES);
        raw.extend_from_slice(INDEX_MAGIC);
        put_u64(&mut raw, self.ordinal);
        put_u64(&mut raw, self.sequence);
        raw.extend_from_slice(self.id.as_bytes());
        raw.extend_from_slice(&self.receipt);
        finish(&mut raw);
        raw
    }
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() != INDEX_BYTES {
            return Err(Error::Corrupt);
        }
        let mut r = checked(raw, INDEX_MAGIC)?;
        let x = Self {
            ordinal: r.u64()?,
            sequence: r.u64()?,
            id: EventId::from_bytes(r.array()?),
            receipt: r.array()?,
        };
        r.end()?;
        if x.ordinal == 0 || x.sequence == 0 {
            return Err(Error::Corrupt);
        }
        Ok(x)
    }
}

pub(crate) struct Intent {
    pub expected: Pin,
    pub next: Pin,
    pub old: Option<Index>,
    pub record: Record,
}
impl Intent {
    pub fn encode(&self) -> Vec<u8> {
        let record = self.record.encode();
        let mut raw = Vec::new();
        raw.extend_from_slice(INTENT_MAGIC);
        raw.extend_from_slice(&self.expected.encode());
        raw.extend_from_slice(&self.next.encode());
        raw.push(u8::from(self.old.is_some()));
        raw.extend_from_slice(
            &self
                .old
                .map(Index::encode)
                .unwrap_or_else(|| vec![0; INDEX_BYTES]),
        );
        raw.extend_from_slice(&(record.len() as u32).to_be_bytes());
        raw.extend_from_slice(&record);
        finish(&mut raw);
        raw
    }
    pub fn decode(raw: &[u8], scope: RoomScope, limits: Limits) -> Result<Self, Error> {
        if raw.len() > MAX_INTENT_BYTES {
            return Err(Error::Corrupt);
        }
        let mut r = checked(raw, INTENT_MAGIC)?;
        let expected = Pin::decode(r.take(PIN_BYTES)?)?;
        let next = Pin::decode(r.take(PIN_BYTES)?)?;
        let flag = r.take(1)?[0];
        let old_raw = r.take(INDEX_BYTES)?;
        let old = match flag {
            0 if old_raw == [0; INDEX_BYTES] => None,
            1 => Some(Index::decode(old_raw)?),
            _ => return Err(Error::Corrupt),
        };
        let length = u32::from_be_bytes(r.array()?) as usize;
        if length > MAX_RECORD_BYTES {
            return Err(Error::Corrupt);
        }
        let record = Record::decode(r.take(length)?, scope)?;
        r.end()?;
        if expected.count.checked_add(1) != Some(next.count)
            || record.pin() != next
            || record.previous != expected.tail
            || expected.bytes.checked_add((length + INDEX_BYTES) as u64) != Some(next.bytes)
            || next.count > limits.max_events
            || next.bytes > limits.max_history_bytes
        {
            return Err(Error::Corrupt);
        }
        let claims = record.event.claims();
        match old {
            None if claims.sequence == 1 && claims.previous == EventId::ZERO => {}
            Some(old)
                if old.sequence.checked_add(1) == Some(claims.sequence)
                    && claims.previous == old.id
                    && old.ordinal <= expected.count => {}
            _ => return Err(Error::Corrupt),
        }
        Ok(Self {
            expected,
            next,
            old,
            record,
        })
    }
}

fn put_u64(raw: &mut Vec<u8>, value: u64) {
    raw.extend_from_slice(&value.to_be_bytes());
}
fn finish(raw: &mut Vec<u8>) {
    raw.extend_from_slice(&checksum(raw));
}
fn checksum(raw: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"vhalla/room-activity/store/v1\0");
    h.update(raw);
    h.finalize().into()
}
fn checked<'a>(raw: &'a [u8], magic: &[u8; 8]) -> Result<Reader<'a>, Error> {
    if raw.len() < 40
        || raw.get(..8) != Some(magic.as_slice())
        || checksum(&raw[..raw.len() - 32]) != raw[raw.len() - 32..]
    {
        return Err(Error::Corrupt);
    }
    Ok(Reader(&raw[8..raw.len() - 32]))
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let out = self.0.get(..n).ok_or(Error::Corrupt)?;
        self.0 = &self.0[n..];
        Ok(out)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Corrupt)
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn end(self) -> Result<(), Error> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Corrupt)
        }
    }
}
