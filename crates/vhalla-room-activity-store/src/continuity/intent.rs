//! A complete intent precedes every multi-file effect. Recovery consumes exact
//! retained images, never reinterpreting history as a new policy decision.
use super::{
    catalogue::{Catalogue, MAX_CATALOGUE_BYTES},
    frames::{
        checksum, event_read, event_write, Reader, StagePage, Terminal, MAX_STAGE_PAGE_BYTES,
        MAX_TERMINAL_BYTES, SEGMENT_EVENTS,
    },
    pin::{ContinuityPin, CONTINUITY_PIN_BYTES},
    ContinuityLimits,
};
use crate::Error;
use vhalla_room_activity::{RoomScope, VerifiedEvent};

#[derive(Clone, Debug)]
pub(super) enum Operation {
    Clock,
    Stage(StagePage),
    Cleanup(StagePage),
    Commit {
        base: Option<Box<Terminal>>,
        inline: Vec<VerifiedEvent>,
        terminal: Box<Terminal>,
    },
}
#[derive(Clone, Debug)]
pub(super) struct Intent {
    pub before: Catalogue,
    pub after: Catalogue,
    pub pin: ContinuityPin,
    pub next_pin: ContinuityPin,
    pub operation: Operation,
}
impl Intent {
    pub fn encode(&self) -> Vec<u8> {
        let mut raw = Vec::new();
        raw.extend_from_slice(b"VHCI2");
        field(&mut raw, &self.before.encode());
        field(&mut raw, &self.after.encode());
        raw.extend_from_slice(&self.pin.encode());
        raw.extend_from_slice(&self.next_pin.encode());
        match &self.operation {
            Operation::Clock => raw.push(0),
            Operation::Stage(page) => {
                raw.push(1);
                raw.extend_from_slice(&page.events[0].claims().author);
                field(&mut raw, &page.encode());
            }
            Operation::Cleanup(page) => {
                raw.push(2);
                raw.extend_from_slice(&page.events[0].claims().author);
                field(&mut raw, &page.encode());
            }
            Operation::Commit {
                base,
                inline,
                terminal,
            } => {
                raw.push(3);
                match base {
                    Some(base) => {
                        raw.push(1);
                        field(&mut raw, &base.encode());
                    }
                    None => raw.push(0),
                }
                raw.push(inline.len() as u8);
                for event in inline {
                    event_write(&mut raw, event);
                }
                field(&mut raw, &terminal.encode());
            }
        }
        checksum(raw)
    }
    pub fn decode(
        raw: &[u8],
        scope: RoomScope,
        limits: ContinuityLimits,
        scope_id: [u8; 32],
    ) -> Result<Self, Error> {
        let mut input = Reader::checked(raw, b"VHCI2", super::disk::MAX_TRANSACTION_BYTES)?;
        let before = Catalogue::decode(
            read_field(&mut input, MAX_CATALOGUE_BYTES)?,
            scope_id,
            scope,
            limits,
        )?;
        let after = Catalogue::decode(
            read_field(&mut input, MAX_CATALOGUE_BYTES)?,
            scope_id,
            scope,
            limits,
        )?;
        let pin = ContinuityPin::decode(input.take(CONTINUITY_PIN_BYTES)?)?;
        let next_pin = ContinuityPin::decode(input.take(CONTINUITY_PIN_BYTES)?)?;
        if pin.scope != scope_id
            || next_pin.scope != scope_id
            || before.generation.checked_add(1) != Some(after.generation)
            || after.clock < before.clock
        {
            return Err(Error::Corrupt);
        }
        let operation = match input.byte()? {
            0 => Operation::Clock,
            kind @ (1 | 2) => {
                let author = input.array()?;
                let page = StagePage::decode(
                    read_field(&mut input, MAX_STAGE_PAGE_BYTES)?,
                    scope,
                    author,
                )?;
                if kind == 1 {
                    Operation::Stage(page)
                } else {
                    Operation::Cleanup(page)
                }
            }
            3 => {
                let base = match input.byte()? {
                    0 => None,
                    1 => Some(Box::new(Terminal::decode(
                        read_field(&mut input, MAX_TERMINAL_BYTES)?,
                        scope,
                    )?)),
                    _ => return Err(Error::Corrupt),
                };
                let count = usize::from(input.byte()?);
                if count > SEGMENT_EVENTS {
                    return Err(Error::Corrupt);
                }
                let mut inline = Vec::with_capacity(count);
                for _ in 0..count {
                    inline.push(event_read(&mut input, scope, None)?);
                }
                let terminal = Box::new(Terminal::decode(
                    read_field(&mut input, MAX_TERMINAL_BYTES)?,
                    scope,
                )?);
                Operation::Commit {
                    base,
                    inline,
                    terminal,
                }
            }
            _ => return Err(Error::Corrupt),
        };
        input.finish()?;
        let value = Self {
            before,
            after,
            pin,
            next_pin,
            operation,
        };
        if value.encode() != raw {
            return Err(Error::Corrupt);
        }
        Ok(value)
    }
}
fn field(raw: &mut Vec<u8>, bytes: &[u8]) {
    raw.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    raw.extend_from_slice(bytes);
}
fn read_field<'a>(input: &mut Reader<'a>, maximum: usize) -> Result<&'a [u8], Error> {
    let length = input.u32()?;
    if u64::from(length) > maximum as u64 {
        return Err(Error::Corrupt);
    }
    input.take(usize::try_from(length).map_err(|_| Error::Corrupt)?)
}
