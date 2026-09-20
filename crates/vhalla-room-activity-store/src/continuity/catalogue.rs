//! Finite temporary staging metadata, independent of permanent author floors.
use super::frames::{checksum, Position, Reader, SEGMENT_EVENTS, STAGE_PAGE_OVERHEAD};
use super::ContinuityLimits;
use crate::Error;
use std::collections::BTreeMap;
use vhalla_room_activity::{AuthorChain, RoomScope, MAX_EVENT_BYTES, MAX_TEXT_BYTES};

pub(super) const MAX_STAGE_SLOTS: usize = 64;
pub(super) const MAX_STAGE_EVENTS: u64 = 4096;
pub(super) const MAX_STAGE_STORAGE_BYTES: u64 = 32 * 1024 * 1024;
pub(super) const MAX_CATALOGUE_BYTES: usize =
    5 + 32 + 8 + 8 + 2 + MAX_STAGE_SLOTS * (32 + 32 + 40 + 40 + 4 + 8 * 5 + 32 + 4 + 1 + 8) + 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StageState {
    Active,
    ExpiredCleanup,
    PublishedCleanup(u64),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Stage {
    pub id: [u8; 32],
    pub author: [u8; 32],
    pub base: Position,
    pub tail: Position,
    pub pages: u32,
    pub event_bytes: u64,
    pub remaining_bytes: u64,
    pub created: u64,
    pub expires: u64,
    pub generation: u64,
    pub root: [u8; 32],
    pub cleaned: u32,
    pub state: StageState,
}
impl Stage {
    pub fn remaining_events(&self) -> Result<u64, Error> {
        u64::from(self.pages.checked_sub(self.cleaned).ok_or(Error::Corrupt)?)
            .checked_mul(SEGMENT_EVENTS as u64)
            .ok_or(Error::Corrupt)
    }
    pub fn total_events(&self) -> Result<u64, Error> {
        u64::from(self.pages)
            .checked_mul(SEGMENT_EVENTS as u64)
            .ok_or(Error::Corrupt)
    }
    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.id);
        out.extend_from_slice(&self.author);
        self.base.write(out);
        self.tail.write(out);
        out.extend_from_slice(&self.pages.to_be_bytes());
        for value in [
            self.event_bytes,
            self.remaining_bytes,
            self.created,
            self.expires,
            self.generation,
        ] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        out.extend_from_slice(&self.root);
        out.extend_from_slice(&self.cleaned.to_be_bytes());
        let (kind, commit) = match self.state {
            StageState::Active => (0, 0u64),
            StageState::ExpiredCleanup => (1, 0),
            StageState::PublishedCleanup(commit) => (2, commit),
        };
        out.push(kind);
        out.extend_from_slice(&commit.to_be_bytes());
    }
    fn read(input: &mut Reader<'_>, scope: RoomScope) -> Result<Self, Error> {
        let id = input.array()?;
        let author = input.array()?;
        AuthorChain::new(scope, author)?;
        let base = Position::read(input)?;
        let tail = Position::read(input)?;
        let pages = input.u32()?;
        let event_bytes = input.u64()?;
        let remaining_bytes = input.u64()?;
        let created = input.u64()?;
        let expires = input.u64()?;
        let generation = input.u64()?;
        let root = input.array()?;
        let cleaned = input.u32()?;
        let kind = input.byte()?;
        let commit = input.u64()?;
        let state = match (kind, commit) {
            (0, 0) => StageState::Active,
            (1, 0) => StageState::ExpiredCleanup,
            (2, value) if value != 0 => StageState::PublishedCleanup(value),
            _ => return Err(Error::Corrupt),
        };
        let result = Self {
            id,
            author,
            base,
            tail,
            pages,
            event_bytes,
            remaining_bytes,
            created,
            expires,
            generation,
            root,
            cleaned,
            state,
        };
        let complete_bytes = u64::from(pages)
            .checked_mul(STAGE_PAGE_OVERHEAD as u64)
            .and_then(|n| n.checked_add(result.total_events().ok()?.checked_mul(2)?))
            .and_then(|n| n.checked_add(event_bytes))
            .ok_or(Error::Corrupt)?;
        let min_event = (MAX_EVENT_BYTES - MAX_TEXT_BYTES + 1) as u64;
        let max_event = MAX_EVENT_BYTES as u64;
        let remaining_pages = u64::from(pages.checked_sub(cleaned).ok_or(Error::Corrupt)?);
        let min_page = STAGE_PAGE_OVERHEAD as u64 + SEGMENT_EVENTS as u64 * (2 + min_event);
        let max_page = STAGE_PAGE_OVERHEAD as u64 + SEGMENT_EVENTS as u64 * (2 + max_event);
        if event_bytes
            < result
                .total_events()?
                .checked_mul(min_event)
                .ok_or(Error::Corrupt)?
            || event_bytes
                > result
                    .total_events()?
                    .checked_mul(max_event)
                    .ok_or(Error::Corrupt)?
            || remaining_bytes
                < remaining_pages
                    .checked_mul(min_page)
                    .ok_or(Error::Corrupt)?
            || remaining_bytes
                > remaining_pages
                    .checked_mul(max_page)
                    .ok_or(Error::Corrupt)?
        {
            return Err(Error::Corrupt);
        }
        if result.id == [0; 32]
            || result.root == [0; 32]
            || result.pages == 0
            || result.total_events()? > MAX_STAGE_EVENTS
            || result.base.sequence.checked_add(result.total_events()?)
                != Some(result.tail.sequence)
            || result.cleaned > result.pages
            || result.remaining_bytes > MAX_STAGE_STORAGE_BYTES
            || result.event_bytes > MAX_STAGE_STORAGE_BYTES
            || result.remaining_bytes > complete_bytes
            || (result.cleaned == 0 && result.remaining_bytes != complete_bytes)
            || (result.cleaned == result.pages) != (result.remaining_bytes == 0)
            || (result.state == StageState::Active && result.cleaned != 0)
        {
            return Err(Error::Corrupt);
        }
        Ok(result)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Catalogue {
    pub scope: [u8; 32],
    pub generation: u64,
    pub clock: u64,
    pub stages: BTreeMap<[u8; 32], Stage>,
}
impl Catalogue {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"VHSC2");
        out.extend_from_slice(&self.scope);
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&self.clock.to_be_bytes());
        out.extend_from_slice(&(self.stages.len() as u16).to_be_bytes());
        for stage in self.stages.values() {
            stage.write(&mut out);
        }
        checksum(out)
    }
    pub fn decode(
        raw: &[u8],
        scope_id: [u8; 32],
        scope: RoomScope,
        limits: ContinuityLimits,
    ) -> Result<Self, Error> {
        let mut input = Reader::checked(raw, b"VHSC2", MAX_CATALOGUE_BYTES)?;
        if input.array::<32>()? != scope_id {
            return Err(Error::Conflict);
        }
        let generation = input.u64()?;
        let clock = input.u64()?;
        let count = usize::from(input.u16()?);
        if generation == 0 || count > MAX_STAGE_SLOTS || count > usize::from(limits.max_stage_slots)
        {
            return Err(Error::Corrupt);
        }
        let mut stages = BTreeMap::new();
        let mut last = None;
        for _ in 0..count {
            let stage = Stage::read(&mut input, scope)?;
            if last.is_some_and(|key| key >= stage.author)
                || stage.created > clock
                || stage.created.checked_add(limits.stage_ttl_seconds) != Some(stage.expires)
                || stage.generation == 0
                || stage.generation > generation
                || (stage.state == StageState::ExpiredCleanup && clock < stage.expires)
            {
                return Err(Error::Corrupt);
            }
            last = Some(stage.author);
            stages.insert(stage.author, stage);
        }
        input.finish()?;
        let result = Self {
            scope: scope_id,
            generation,
            clock,
            stages,
        };
        result.check_capacity(limits)?;
        Ok(result)
    }
    pub fn check_capacity(&self, limits: ContinuityLimits) -> Result<(), Error> {
        if self.stages.len() > usize::from(limits.max_stage_slots) {
            return Err(Error::Capacity);
        }
        let mut events = 0u64;
        let mut bytes = 0u64;
        for stage in self.stages.values() {
            events = events
                .checked_add(stage.remaining_events()?)
                .ok_or(Error::Capacity)?;
            bytes = bytes
                .checked_add(stage.remaining_bytes)
                .ok_or(Error::Capacity)?;
        }
        if events > limits.max_stage_events || bytes > limits.max_stage_bytes {
            return Err(Error::Capacity);
        }
        Ok(())
    }
    pub fn next(&self, now: u64) -> Result<Self, Error> {
        if now < self.clock {
            return Err(Error::Conflict);
        }
        let mut next = self.clone();
        next.generation = next.generation.checked_add(1).ok_or(Error::Capacity)?;
        next.clock = now;
        Ok(next)
    }
}
