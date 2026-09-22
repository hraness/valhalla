use super::{
    frames::{checksum, digest, Reader},
    ContinuityLimits,
};
use crate::{Error, Limits};
use vhalla_core::RealmId;
use vhalla_room_activity::RoomScope;
use vhalla_rooms::{DirectoryId, RoomGenesisId};

pub(super) const FORMAT_BYTES: usize = 5 + 112 + 16 + 2 + 24 + 32;
/// Exact canonical independently retainable v2 local publication pin size.
pub const CONTINUITY_PIN_BYTES: usize = 5 + 32 + 24 + 32 + 32;

/// Exact local publication anchor. Checksums are not certificates. Independent
/// retention can detect a different local image, not hostile coherent rollback
/// when both the store and the retained pin are rolled back together.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContinuityPin {
    pub(super) scope: [u8; 32],
    pub(super) feed: u64,
    pub(super) events: u64,
    pub(super) bytes: u64,
    pub(super) tail: [u8; 32],
}
impl ContinuityPin {
    pub(super) const fn empty(scope: [u8; 32]) -> Self {
        Self {
            scope,
            feed: 0,
            events: 0,
            bytes: 0,
            tail: [0; 32],
        }
    }
    /// Number of locally published current-admission terminal records.
    pub const fn feed_count(&self) -> u64 {
        self.feed
    }
    /// Number of permanent signed records, including historical continuity.
    pub const fn evidence_count(&self) -> u64 {
        self.events
    }
    /// Accounted immutable evidence, indices and receipt bytes.
    pub const fn history_bytes(&self) -> u64 {
        self.bytes
    }
    /// Exact last terminal receipt digest, zero only for an empty store.
    pub const fn tail(&self) -> [u8; 32] {
        self.tail
    }
    /// Canonical bounded bytes for independently managed retention.
    pub fn encode(&self) -> [u8; CONTINUITY_PIN_BYTES] {
        let mut raw = Vec::new();
        raw.extend_from_slice(b"VHCP2");
        raw.extend_from_slice(&self.scope);
        for value in [self.feed, self.events, self.bytes] {
            raw.extend_from_slice(&value.to_be_bytes());
        }
        raw.extend_from_slice(&self.tail);
        checksum(raw)
            .try_into()
            .expect("fixed continuity pin layout")
    }
    /// Decode untrusted pin metadata without accepting any store or author state.
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        let mut input = Reader::checked(raw, b"VHCP2", CONTINUITY_PIN_BYTES)?;
        let pin = Self {
            scope: input.array()?,
            feed: input.u64()?,
            events: input.u64()?,
            bytes: input.u64()?,
            tail: input.array()?,
        };
        input.finish()?;
        if pin.scope == [0; 32]
            || pin.feed > pin.events
            || (pin.feed == 0) != (pin.events == 0)
            || (pin.feed == 0) != (pin.bytes == 0)
            || (pin.feed == 0) != (pin.tail == [0; 32])
        {
            return Err(Error::Corrupt);
        }
        Ok(pin)
    }
    pub(super) fn next(
        self,
        events: u64,
        bytes: u64,
        tail: [u8; 32],
        limits: Limits,
    ) -> Result<Self, Error> {
        if events == 0 || bytes == 0 || tail == [0; 32] {
            return Err(Error::Corrupt);
        }
        let pin = Self {
            scope: self.scope,
            feed: self.feed.checked_add(1).ok_or(Error::Capacity)?,
            events: self.events.checked_add(events).ok_or(Error::Capacity)?,
            bytes: self.bytes.checked_add(bytes).ok_or(Error::Capacity)?,
            tail,
        };
        if pin.events > limits.max_events || pin.bytes > limits.max_history_bytes {
            return Err(Error::Capacity);
        }
        Ok(pin)
    }
}

pub(super) fn format(scope: RoomScope, limits: ContinuityLimits) -> Result<Vec<u8>, Error> {
    limits.check()?;
    if scope.network == [0; 32] {
        return Err(Error::Conflict);
    }
    let mut raw = Vec::new();
    raw.extend_from_slice(b"VHCF2");
    raw.extend_from_slice(&scope.network);
    raw.extend_from_slice(&scope.realm.0.to_be_bytes());
    raw.extend_from_slice(scope.directory.as_bytes());
    raw.extend_from_slice(scope.room.as_bytes());
    raw.extend_from_slice(&limits.history.max_events.to_be_bytes());
    raw.extend_from_slice(&limits.history.max_history_bytes.to_be_bytes());
    raw.extend_from_slice(&limits.max_stage_slots.to_be_bytes());
    raw.extend_from_slice(&limits.max_stage_events.to_be_bytes());
    raw.extend_from_slice(&limits.max_stage_bytes.to_be_bytes());
    raw.extend_from_slice(&limits.stage_ttl_seconds.to_be_bytes());
    Ok(checksum(raw))
}
pub(super) fn decode_format(raw: &[u8]) -> Result<(RoomScope, ContinuityLimits, [u8; 32]), Error> {
    let mut input = Reader::checked(raw, b"VHCF2", FORMAT_BYTES)?;
    let scope = RoomScope {
        network: input.array()?,
        realm: RealmId(u128::from_be_bytes(input.array()?)),
        directory: DirectoryId::from_bytes(input.array()?),
        room: RoomGenesisId::from_bytes(input.array()?),
    };
    let limits = ContinuityLimits {
        history: Limits {
            max_events: input.u64()?,
            max_history_bytes: input.u64()?,
        },
        max_stage_slots: input.u16()?,
        max_stage_events: input.u64()?,
        max_stage_bytes: input.u64()?,
        stage_ttl_seconds: input.u64()?,
    };
    input.finish()?;
    if format(scope, limits)? != raw {
        return Err(Error::Corrupt);
    }
    Ok((scope, limits, digest(raw)))
}
