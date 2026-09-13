//! Disposable bounded, stop-and-wait transfer. Bytes and acknowledgments confer no authority.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
use alloc::vec::Vec;
use sha2::{Digest, Sha256};

pub const MAX_OBJECT: usize = 65_536;
pub const CHUNK: usize = 4_096;
pub const HEADER: usize = 44;
pub const MAX_RECORD: usize = HEADER + CHUNK;
pub const TRANSFER_MS: u64 = 10_000;
const MAGIC: &[u8; 4] = b"VR01";

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Format,
    Order,
    Digest,
    Acknowledgment,
    Closed,
    Clock,
}

struct Clock {
    last: u64,
    deadline: u64,
}
impl Clock {
    fn new(now: u64) -> Result<Self, Error> {
        Ok(Self {
            last: now,
            deadline: now.checked_add(TRANSFER_MS).ok_or(Error::Clock)?,
        })
    }
    fn check(&mut self, now: u64) -> Result<(), Error> {
        if now < self.last || now >= self.deadline {
            return Err(Error::Clock);
        }
        self.last = now;
        Ok(())
    }
}

struct Record<'a> {
    total: usize,
    offset: usize,
    digest: [u8; 32],
    body: &'a [u8],
}
impl<'a> Record<'a> {
    fn decode(raw: &'a [u8]) -> Result<Self, Error> {
        if !(HEADER..=MAX_RECORD).contains(&raw.len()) {
            return Err(Error::Length);
        }
        if &raw[..4] != MAGIC {
            return Err(Error::Format);
        }
        let total = u32::from_be_bytes(raw[4..8].try_into().unwrap()) as usize;
        let offset = u32::from_be_bytes(raw[8..12].try_into().unwrap()) as usize;
        // Validate every untrusted bound before allocating or indexing the object.
        if total > MAX_OBJECT || offset > total || !offset.is_multiple_of(CHUNK) {
            return Err(Error::Length);
        }
        if total != 0 && offset == total {
            return Err(Error::Order);
        }
        if raw.len() - HEADER != CHUNK.min(total - offset) {
            return Err(Error::Length);
        }
        Ok(Self {
            total,
            offset,
            digest: raw[12..HEADER].try_into().unwrap(),
            body: &raw[HEADER..],
        })
    }
}

fn encode(body: &[u8], digest: &[u8; 32], offset: usize) -> Vec<u8> {
    let end = body.len().min(offset + CHUNK);
    let mut out = Vec::with_capacity(HEADER + end - offset);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&(offset as u32).to_be_bytes());
    out.extend_from_slice(digest);
    out.extend_from_slice(&body[offset..end]);
    out
}

/// One object and one outstanding record, owned by one connection driver.
/// A retry requires a fresh instance and fresh application session.
pub struct Sender {
    body: Vec<u8>,
    digest: [u8; 32],
    offset: usize,
    waiting: bool,
    closed: bool,
    clock: Clock,
}
impl Sender {
    pub fn new(body: Vec<u8>, now_ms: u64) -> Result<Self, Error> {
        if body.len() > MAX_OBJECT {
            return Err(Error::Length);
        }
        Ok(Self {
            digest: Sha256::digest(&body).into(),
            body,
            offset: 0,
            waiting: false,
            closed: false,
            clock: Clock::new(now_ms)?,
        })
    }

    pub fn next_record(&mut self, now_ms: u64) -> Result<Vec<u8>, Error> {
        let result = (|| {
            if self.closed {
                return Err(Error::Closed);
            }
            self.clock.check(now_ms)?;
            if self.waiting {
                return Err(Error::Order);
            }
            self.waiting = true;
            Ok(encode(&self.body, &self.digest, self.offset))
        })();
        if result.is_err() {
            self.closed = true;
        }
        result
    }

    /// Echo of the exact record, after bounded acceptance. `true` means complete.
    /// This is flow control, not a signed or durable application receipt.
    pub fn acknowledge(&mut self, raw: &[u8], now_ms: u64) -> Result<bool, Error> {
        let result = (|| {
            if self.closed {
                return Err(Error::Closed);
            }
            self.clock.check(now_ms)?;
            if !self.waiting || raw != encode(&self.body, &self.digest, self.offset) {
                return Err(Error::Acknowledgment);
            }
            self.offset = self.body.len().min(self.offset + CHUNK);
            self.waiting = false;
            self.closed = self.offset == self.body.len();
            Ok(self.closed)
        })();
        if result.is_err() {
            self.closed = true;
        }
        result
    }
}

/// Untrusted assembled bytes. The caller must verify the complete signed envelope
/// before applying application policy; the record digest is not a signature.
pub struct Accepted {
    pub acknowledgment: Vec<u8>,
    pub complete: Option<Vec<u8>>,
}
struct Object {
    total: usize,
    digest: [u8; 32],
    body: Vec<u8>,
}
/// At most one 64 KiB object, sixteen nonempty records, one connection lifetime.
/// Bind this owner to an authenticated connection; never key it by claimed digest.
pub struct Receiver {
    object: Option<Object>,
    closed: bool,
    clock: Clock,
}
impl Receiver {
    pub fn new(now_ms: u64) -> Result<Self, Error> {
        Ok(Self {
            object: None,
            closed: false,
            clock: Clock::new(now_ms)?,
        })
    }
    pub fn accept(&mut self, raw: &[u8], now_ms: u64) -> Result<Accepted, Error> {
        let result = self.accept_inner(raw, now_ms);
        if result.is_err() {
            self.closed = true;
            self.object = None;
        }
        result
    }
    fn accept_inner(&mut self, raw: &[u8], now_ms: u64) -> Result<Accepted, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        self.clock.check(now_ms)?;
        let record = Record::decode(raw)?;
        if self.object.is_none() {
            if record.offset != 0 {
                return Err(Error::Order);
            }
            self.object = Some(Object {
                total: record.total,
                digest: record.digest,
                body: Vec::with_capacity(record.total),
            });
        }
        let object = self.object.as_mut().unwrap();
        if record.total != object.total
            || record.digest != object.digest
            || record.offset != object.body.len()
        {
            return Err(Error::Order);
        }
        object.body.extend_from_slice(record.body);
        let complete = if object.body.len() == object.total {
            if <[u8; 32]>::from(Sha256::digest(&object.body)) != object.digest {
                return Err(Error::Digest);
            }
            self.closed = true;
            Some(self.object.take().unwrap().body)
        } else {
            None
        };
        Ok(Accepted {
            acknowledgment: raw.to_vec(),
            complete,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use proptest::prelude::*;

    fn roundtrip(body: Vec<u8>) {
        let mut sender = Sender::new(body.clone(), 0).unwrap();
        let mut receiver = Receiver::new(0).unwrap();
        let mut records = 0;
        loop {
            let record = sender.next_record(records * 100).unwrap();
            assert!(record.len() <= MAX_RECORD);
            let accepted = receiver.accept(&record, records * 100 + 100).unwrap();
            let complete = sender
                .acknowledge(&accepted.acknowledgment, records * 100 + 100)
                .unwrap();
            records += 1;
            if complete {
                assert_eq!(accepted.complete.unwrap(), body);
                break;
            }
            assert!(accepted.complete.is_none());
        }
        assert_eq!(records as usize, body.len().div_ceil(CHUNK).max(1));
        assert_eq!(sender.next_record(2_000), Err(Error::Closed));
        assert!(matches!(receiver.accept(&[], 2_000), Err(Error::Closed)));
    }

    #[test]
    fn boundaries_and_paused_reader_budget() {
        for size in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, MAX_OBJECT] {
            roundtrip(vec![9; size]);
        }
        assert!(matches!(
            Sender::new(vec![0; MAX_OBJECT + 1], 0),
            Err(Error::Length)
        ));
    }

    #[test]
    fn fixed_wire_vector_from_sha256_abc() {
        // Independent SHA-256("abc") vector and literal big-endian header.
        let expected = [
            0x56, 0x52, 0x30, 0x31, 0, 0, 0, 3, 0, 0, 0, 0, 0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01,
            0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3,
            0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad, b'a', b'b',
            b'c',
        ];
        let mut sender = Sender::new(b"abc".to_vec(), 0).unwrap();
        assert_eq!(sender.next_record(0).unwrap(), expected);
        let mut receiver = Receiver::new(0).unwrap();
        assert_eq!(
            receiver.accept(&expected, 0).unwrap().complete.unwrap(),
            b"abc"
        );
    }

    #[test]
    fn duplicate_and_reordered_records_close_and_release_receiver() {
        let mut sender = Sender::new(vec![4; CHUNK + 1], 0).unwrap();
        let first = sender.next_record(0).unwrap();
        sender.acknowledge(&first, 0).unwrap();
        let second = sender.next_record(0).unwrap();
        let mut receiver = Receiver::new(0).unwrap();
        assert!(matches!(receiver.accept(&second, 0), Err(Error::Order)));
        assert!(receiver.object.is_none());
        assert!(matches!(receiver.accept(&first, 0), Err(Error::Closed)));
        let mut receiver = Receiver::new(0).unwrap();
        receiver.accept(&first, 0).unwrap();
        assert!(matches!(receiver.accept(&first, 0), Err(Error::Order)));
        assert!(receiver.object.is_none());
    }

    #[test]
    fn foreign_or_corrupt_records_never_complete() {
        let body = vec![1; CHUNK + 1];
        let mut sender = Sender::new(body, 0).unwrap();
        let first = sender.next_record(0).unwrap();
        sender.acknowledge(&first, 0).unwrap();
        let second = sender.next_record(0).unwrap();
        for index in [4, 8, 12, HEADER] {
            let mut receiver = Receiver::new(0).unwrap();
            receiver.accept(&first, 0).unwrap();
            let mut changed = second.clone();
            changed[index] ^= 1;
            assert!(receiver.accept(&changed, 0).is_err());
            assert!(receiver.object.is_none());
        }
    }

    #[test]
    fn acknowledgments_cannot_advance_without_exact_current_record() {
        let mut sender = Sender::new(vec![3; CHUNK + 1], 0).unwrap();
        let first = sender.next_record(0).unwrap();
        sender.acknowledge(&first, 0).unwrap();
        let _ = sender.next_record(0).unwrap();
        assert_eq!(sender.acknowledge(&first, 0), Err(Error::Acknowledgment));
        assert_eq!(sender.next_record(0), Err(Error::Closed));
        let mut sender = Sender::new(vec![], 0).unwrap();
        assert_eq!(sender.acknowledge(&[], 0), Err(Error::Acknowledgment));
        let mut sender = Sender::new(vec![], 0).unwrap();
        sender.next_record(0).unwrap();
        assert_eq!(sender.next_record(0), Err(Error::Order));
    }

    #[test]
    fn expiry_rollback_overflow_and_malformed_frames_fail_closed() {
        assert!(matches!(Receiver::new(u64::MAX), Err(Error::Clock)));
        for now in [9, 10 + TRANSFER_MS] {
            let mut sender = Sender::new(vec![1], 10).unwrap();
            let raw = sender.next_record(10).unwrap();
            let mut receiver = Receiver::new(10).unwrap();
            assert!(matches!(receiver.accept(&raw, now), Err(Error::Clock)));
            assert_eq!(sender.acknowledge(&raw, now), Err(Error::Clock));
        }
        let mut sender = Sender::new(vec![1], 0).unwrap();
        let raw = sender.next_record(0).unwrap();
        for size in 0..raw.len() {
            let mut receiver = Receiver::new(0).unwrap();
            assert!(receiver.accept(&raw[..size], 0).is_err());
            assert!(receiver.object.is_none());
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        #[test]
        fn arbitrary_objects_roundtrip(body in prop::collection::vec(any::<u8>(), 0..=MAX_OBJECT)) {
            roundtrip(body);
        }
        #[test]
        fn arbitrary_frames_are_bounded(raw in prop::collection::vec(any::<u8>(), 0..MAX_RECORD+100)) {
            let mut receiver = Receiver::new(0).unwrap();
            let _ = receiver.accept(&raw, 0);
            prop_assert!(receiver.object.as_ref().is_none_or(|o|o.body.len()<=o.total && o.total<=MAX_OBJECT));
        }
        #[test]
        fn tampered_payload_never_completes(body in prop::collection::vec(any::<u8>(), 1..=CHUNK), index in any::<usize>()) {
            let mut sender = Sender::new(body, 0).unwrap();
            let mut raw = sender.next_record(0).unwrap();
            let index = HEADER + index % (raw.len() - HEADER);
            raw[index] ^= 1;
            let mut receiver = Receiver::new(0).unwrap();
            prop_assert!(matches!(receiver.accept(&raw,0),Err(Error::Digest)));
        }
    }
}
