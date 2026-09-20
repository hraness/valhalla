//! Internal canonical v2 disk frames. Checksums detect corruption, not authority.
use crate::Error;
use sha2::{Digest, Sha256};
use vhalla_room_activity::{
    continuity::EvidenceRole, EventId, RoomScope, SignedEvent, VerifiedEvent, MAX_EVENT_BYTES,
};

pub(super) const SEGMENT_EVENTS: usize = 32;
pub(super) const STAGE_PAGE_OVERHEAD: usize = 5 + 32 + 4 + 32 + 32 + 1 + 32;
pub(super) const MAX_STAGE_PAGE_BYTES: usize =
    STAGE_PAGE_OVERHEAD + SEGMENT_EVENTS * (2 + MAX_EVENT_BYTES);
pub(super) const MAX_EVIDENCE_BYTES: usize = 5 + 1 + 8 + 32 + 2 + MAX_EVENT_BYTES + 32;
pub(super) const MAX_TERMINAL_BYTES: usize = 5 + 8 + 32 + 32 + 32 + 2 + MAX_EVENT_BYTES + 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Position {
    pub sequence: u64,
    pub id: EventId,
}
impl Position {
    pub const EMPTY: Self = Self {
        sequence: 0,
        id: EventId::ZERO,
    };
    pub fn of(event: &VerifiedEvent) -> Self {
        Self {
            sequence: event.claims().sequence,
            id: event.id(),
        }
    }
    pub fn write(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(self.id.as_bytes());
    }
    pub fn read(input: &mut Reader<'_>) -> Result<Self, Error> {
        let position = Self {
            sequence: input.u64()?,
            id: EventId::from_bytes(input.array()?),
        };
        if (position.sequence == 0) != (position.id == EventId::ZERO) {
            return Err(Error::Corrupt);
        }
        Ok(position)
    }
    pub fn extends(self, prior: Self, event: &VerifiedEvent) -> bool {
        prior.sequence.checked_add(1) == Some(self.sequence)
            && event.claims().previous == prior.id
            && self == Self::of(event)
    }
}

#[derive(Clone, Debug)]
pub(super) struct StagePage {
    pub id: [u8; 32],
    pub number: u32,
    pub previous: [u8; 32],
    pub registry: [u8; 32],
    pub events: Vec<VerifiedEvent>,
}
impl StagePage {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"VHSP2");
        out.extend_from_slice(&self.id);
        out.extend_from_slice(&self.number.to_be_bytes());
        out.extend_from_slice(&self.previous);
        out.extend_from_slice(&self.registry);
        out.push(self.events.len() as u8);
        for event in &self.events {
            event_write(&mut out, event);
        }
        checksum(out)
    }
    pub fn decode(raw: &[u8], scope: RoomScope, author: [u8; 32]) -> Result<Self, Error> {
        let mut input = Reader::checked(raw, b"VHSP2", MAX_STAGE_PAGE_BYTES)?;
        let id = input.array()?;
        let number = input.u32()?;
        let previous = input.array()?;
        let registry = input.array()?;
        if id == [0; 32]
            || (number == 0) != (previous == [0; 32])
            || usize::from(input.byte()?) != SEGMENT_EVENTS
        {
            return Err(Error::Corrupt);
        }
        let mut events = Vec::with_capacity(SEGMENT_EVENTS);
        let mut prior = None;
        for _ in 0..SEGMENT_EVENTS {
            let event = event_read(&mut input, scope, Some(author))?;
            if prior.is_some_and(|previous| !Position::of(&event).extends(previous, &event)) {
                return Err(Error::Corrupt);
            }
            prior = Some(Position::of(&event));
            events.push(event);
        }
        input.finish()?;
        Ok(Self {
            id,
            number,
            previous,
            registry,
            events,
        })
    }
    pub fn digest(&self) -> [u8; 32] {
        digest(&self.encode())
    }
    pub fn tail(&self) -> Position {
        Position::of(self.events.last().expect("nonempty validated stage page"))
    }
    pub fn event_bytes(&self) -> u64 {
        self.events
            .iter()
            .map(|event| event.encode().len() as u64)
            .sum()
    }
}

#[derive(Clone, Debug)]
pub(super) struct Evidence {
    pub role: EvidenceRole,
    pub committed_by: u64,
    pub registry: [u8; 32],
    pub event: VerifiedEvent,
}
impl Evidence {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"VHCE2");
        out.push(match self.role {
            EvidenceRole::HistoricalContinuity => 0,
            EvidenceRole::CurrentAdmission => 1,
        });
        out.extend_from_slice(&self.committed_by.to_be_bytes());
        out.extend_from_slice(&self.registry);
        event_write(&mut out, &self.event);
        checksum(out)
    }
    pub fn decode(raw: &[u8], scope: RoomScope, author: [u8; 32]) -> Result<Self, Error> {
        let mut input = Reader::checked(raw, b"VHCE2", MAX_EVIDENCE_BYTES)?;
        let role = match input.byte()? {
            0 => EvidenceRole::HistoricalContinuity,
            1 => EvidenceRole::CurrentAdmission,
            _ => return Err(Error::Corrupt),
        };
        let committed_by = input.u64()?;
        if committed_by == 0 {
            return Err(Error::Corrupt);
        }
        let registry = input.array()?;
        let event = event_read(&mut input, scope, Some(author))?;
        input.finish()?;
        Ok(Self {
            role,
            committed_by,
            registry,
            event,
        })
    }
}

#[derive(Clone, Debug)]
pub(super) struct Terminal {
    pub ordinal: u64,
    pub previous: [u8; 32],
    pub registry: [u8; 32],
    pub prefix: [u8; 32],
    pub event: VerifiedEvent,
}
impl Terminal {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"VHCT2");
        out.extend_from_slice(&self.ordinal.to_be_bytes());
        out.extend_from_slice(&self.previous);
        out.extend_from_slice(&self.registry);
        out.extend_from_slice(&self.prefix);
        event_write(&mut out, &self.event);
        checksum(out)
    }
    pub fn decode(raw: &[u8], scope: RoomScope) -> Result<Self, Error> {
        let mut input = Reader::checked(raw, b"VHCT2", MAX_TERMINAL_BYTES)?;
        let ordinal = input.u64()?;
        let previous = input.array()?;
        let registry = input.array()?;
        let prefix = input.array()?;
        if ordinal == 0 || (ordinal == 1) != (previous == [0; 32]) {
            return Err(Error::Corrupt);
        }
        let event = event_read(&mut input, scope, None)?;
        input.finish()?;
        Ok(Self {
            ordinal,
            previous,
            registry,
            prefix,
            event,
        })
    }
    pub fn digest(&self) -> [u8; 32] {
        digest(&self.encode())
    }
}

pub(super) fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
pub(super) fn checksum(mut bytes: Vec<u8>) -> Vec<u8> {
    let hash = digest(&bytes);
    bytes.extend_from_slice(&hash);
    bytes
}
pub(super) fn event_write(out: &mut Vec<u8>, event: &VerifiedEvent) {
    let raw = event.encode();
    out.extend_from_slice(&(raw.len() as u16).to_be_bytes());
    out.extend_from_slice(&raw);
}
pub(super) fn event_read(
    input: &mut Reader<'_>,
    scope: RoomScope,
    author: Option<[u8; 32]>,
) -> Result<VerifiedEvent, Error> {
    let length = usize::from(input.u16()?);
    if length == 0 || length > MAX_EVENT_BYTES {
        return Err(Error::Corrupt);
    }
    let raw = input.take(length)?;
    let event = SignedEvent::decode(raw)?.verify()?;
    if event.claims().scope != scope
        || author.is_some_and(|author| event.claims().author != author)
        || event.encode() != raw
    {
        return Err(Error::Corrupt);
    }
    Ok(event)
}
pub(super) struct Reader<'a> {
    remaining: &'a [u8],
}
impl<'a> Reader<'a> {
    pub fn checked(raw: &'a [u8], magic: &[u8], max: usize) -> Result<Self, Error> {
        if raw.len() < magic.len() + 32 || raw.len() > max || !raw.starts_with(magic) {
            return Err(Error::Corrupt);
        }
        let (body, hash) = raw.split_at(raw.len() - 32);
        if digest(body).as_slice() != hash {
            return Err(Error::Corrupt);
        }
        Ok(Self {
            remaining: &body[magic.len()..],
        })
    }
    pub fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        if count > self.remaining.len() {
            return Err(Error::Corrupt);
        }
        let (value, remaining) = self.remaining.split_at(count);
        self.remaining = remaining;
        Ok(value)
    }
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Corrupt)
    }
    pub fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.array::<1>()?[0])
    }
    pub fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    pub fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    pub fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    pub fn finish(self) -> Result<(), Error> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(Error::Corrupt)
        }
    }
}
