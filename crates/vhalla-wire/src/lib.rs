#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! A small, deterministic wire envelope for the vhalla (valhalla) steel thread.
//!
//! This crate only authenticates structure. It does not verify signatures,
//! assign authority, or execute a request. Every decoded envelope remains data
//! until a later policy layer explicitly authorizes it.

extern crate alloc;

use alloc::vec::Vec;
use vhalla_core::{EventId, ParseError, PeerId, RealmId, RoomId, Sequence};

/// The only wire version currently understood by this prototype.
pub const WIRE_VERSION: u8 = 1;
/// A chat message, useful for the initial end-to-end path.
pub const KIND_CHAT: u8 = 1;
/// Bytes occupied by the fixed envelope header.
pub const HEADER_BYTES: usize = 78;
/// Maximum body size accepted by this envelope.
pub const MAX_BODY_BYTES: usize = vhalla_core::MAX_ENVELOPE_BYTES - HEADER_BYTES;

/// A structurally valid, still-untrusted envelope.
///
/// Construction and decoding enforce the size and kind invariants. Fields have
/// no mutable projections, so encoding cannot serialize a subsequently enlarged
/// or invalid body.
///
/// ```compile_fail
/// use vhalla_wire::Envelope;
/// fn enlarge(envelope: &mut Envelope) { envelope.body.push(0); }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Envelope {
    /// Application-defined message kind.
    kind: u8,
    /// The peer that authored the event (signature verification is separate).
    author: PeerId,
    /// Realm namespace containing the room.
    realm: RealmId,
    /// Room namespace containing the event.
    room: RoomId,
    /// Unique event identifier.
    event: EventId,
    /// Sender sequence used for ordering and replay policy.
    sequence: Sequence,
    /// Opaque message body. It is never interpreted by this crate.
    body: Vec<u8>,
}

/// Stable failures from the bounded wire decoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// The input exceeded the core byte bound.
    TooLarge {
        /// Number of bytes supplied by the caller.
        actual: usize,
        /// Maximum accepted byte count.
        limit: usize,
    },
    /// The input ended before the named field was complete.
    Truncated {
        /// Field that could not be read completely.
        field: DecodeField,
    },
    /// The version byte is not understood.
    UnsupportedVersion {
        /// Version byte received on the wire.
        found: u8,
    },
    /// The kind byte is zero, which is reserved and cannot be routed.
    InvalidKind,
    /// The declared body exceeds the bounded body limit.
    BodyTooLarge {
        /// Declared body size.
        actual: usize,
        /// Maximum accepted body size.
        limit: usize,
    },
    /// Bytes after the declared body are not permitted in canonical encoding.
    TrailingBytes {
        /// Number of bytes after the declared body.
        count: usize,
    },
}

/// Header fields that can be missing from a truncated input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeField {
    /// The one-byte version.
    Version,
    /// The one-byte kind.
    Kind,
    /// The author identifier.
    Author,
    /// The realm identifier.
    Realm,
    /// The room identifier.
    Room,
    /// The event identifier.
    Event,
    /// The sender sequence.
    Sequence,
    /// The four-byte body length.
    BodyLength,
    /// The opaque body bytes.
    Body,
}

impl From<ParseError> for DecodeError {
    fn from(error: ParseError) -> Self {
        match error {
            ParseError::TooLarge { actual, limit } => Self::TooLarge { actual, limit },
        }
    }
}

impl Envelope {
    /// Application-defined, nonzero message kind.
    #[must_use]
    pub fn kind(&self) -> u8 {
        self.kind
    }
    /// Claimed author handle; this getter grants no authentication.
    #[must_use]
    pub fn author(&self) -> PeerId {
        self.author
    }
    /// Realm namespace.
    #[must_use]
    pub fn realm(&self) -> RealmId {
        self.realm
    }
    /// Room namespace.
    #[must_use]
    pub fn room(&self) -> RoomId {
        self.room
    }
    /// Claimed event identifier.
    #[must_use]
    pub fn event(&self) -> EventId {
        self.event
    }
    /// Claimed sender sequence.
    #[must_use]
    pub fn sequence(&self) -> Sequence {
        self.sequence
    }
    /// Opaque, immutable content bytes.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    /// Exact canonical byte count, without allocating an encoding.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        HEADER_BYTES + self.body.len()
    }
    /// Build a chat envelope for the initial steel thread.
    #[must_use]
    pub fn chat(
        author: PeerId,
        realm: RealmId,
        room: RoomId,
        event: EventId,
        sequence: Sequence,
        body: &[u8],
    ) -> Option<Self> {
        Self::new(KIND_CHAT, author, realm, room, event, sequence, body)
    }

    /// Build an envelope when the caller owns a valid non-zero kind.
    #[must_use]
    pub fn new(
        kind: u8,
        author: PeerId,
        realm: RealmId,
        room: RoomId,
        event: EventId,
        sequence: Sequence,
        body: &[u8],
    ) -> Option<Self> {
        if kind == 0 || body.len() > MAX_BODY_BYTES {
            return None;
        }
        Some(Self {
            kind,
            author,
            realm,
            room,
            event,
            sequence,
            body: body.to_vec(),
        })
    }

    /// Encode this envelope in canonical big-endian form.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_BYTES + self.body.len());
        out.push(WIRE_VERSION);
        out.push(self.kind);
        out.extend_from_slice(&self.author.0.to_be_bytes());
        out.extend_from_slice(&self.realm.0.to_be_bytes());
        out.extend_from_slice(&self.room.0.to_be_bytes());
        out.extend_from_slice(&self.event.0.to_be_bytes());
        out.extend_from_slice(&self.sequence.0.to_be_bytes());
        out.extend_from_slice(&(self.body.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.body);
        out
    }

    /// Decode a bounded byte slice into an untrusted envelope.
    pub fn decode(raw: &[u8]) -> Result<Self, DecodeError> {
        if raw.len() > vhalla_core::MAX_ENVELOPE_BYTES {
            return Err(DecodeError::TooLarge {
                actual: raw.len(),
                limit: vhalla_core::MAX_ENVELOPE_BYTES,
            });
        }
        Self::decode_bounded(raw)
    }

    fn decode_bounded(raw: &[u8]) -> Result<Self, DecodeError> {
        if raw.is_empty() {
            return Err(DecodeError::Truncated {
                field: DecodeField::Version,
            });
        }
        if raw[0] != WIRE_VERSION {
            return Err(DecodeError::UnsupportedVersion { found: raw[0] });
        }
        if raw.len() < 2 {
            return Err(DecodeError::Truncated {
                field: DecodeField::Kind,
            });
        }
        let kind = raw[1];
        if kind == 0 {
            return Err(DecodeError::InvalidKind);
        }
        let author = read_u128(raw, 2, DecodeField::Author)?;
        let realm = read_u128(raw, 18, DecodeField::Realm)?;
        let room = read_u128(raw, 34, DecodeField::Room)?;
        let event = read_u128(raw, 50, DecodeField::Event)?;
        let sequence = read_u64(raw, 66, DecodeField::Sequence)?;
        let body_len = read_u32(raw, 74, DecodeField::BodyLength)? as usize;
        if body_len > MAX_BODY_BYTES {
            return Err(DecodeError::BodyTooLarge {
                actual: body_len,
                limit: MAX_BODY_BYTES,
            });
        }
        let end = HEADER_BYTES
            .checked_add(body_len)
            .ok_or(DecodeError::BodyTooLarge {
                actual: body_len,
                limit: MAX_BODY_BYTES,
            })?;
        if raw.len() < end {
            return Err(DecodeError::Truncated {
                field: DecodeField::Body,
            });
        }
        if raw.len() > end {
            return Err(DecodeError::TrailingBytes {
                count: raw.len() - end,
            });
        }
        Ok(Self {
            kind,
            author: PeerId(author),
            realm: RealmId(realm),
            room: RoomId(room),
            event: EventId(event),
            sequence: Sequence(sequence),
            body: raw[HEADER_BYTES..end].to_vec(),
        })
    }
}

fn read_u128(raw: &[u8], start: usize, field: DecodeField) -> Result<u128, DecodeError> {
    let end = start + 16;
    let bytes = raw
        .get(start..end)
        .ok_or(DecodeError::Truncated { field })?;
    let mut value = [0_u8; 16];
    value.copy_from_slice(bytes);
    Ok(u128::from_be_bytes(value))
}

fn read_u64(raw: &[u8], start: usize, field: DecodeField) -> Result<u64, DecodeError> {
    let end = start + 8;
    let bytes = raw
        .get(start..end)
        .ok_or(DecodeError::Truncated { field })?;
    let mut value = [0_u8; 8];
    value.copy_from_slice(bytes);
    Ok(u64::from_be_bytes(value))
}

fn read_u32(raw: &[u8], start: usize, field: DecodeField) -> Result<u32, DecodeError> {
    let end = start + 4;
    let bytes = raw
        .get(start..end)
        .ok_or(DecodeError::Truncated { field })?;
    let mut value = [0_u8; 4];
    value.copy_from_slice(bytes);
    Ok(u32::from_be_bytes(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use proptest::prelude::*;

    fn sample(body: &[u8]) -> Envelope {
        Envelope::chat(
            PeerId(1),
            RealmId(2),
            RoomId(3),
            EventId(4),
            Sequence(5),
            body,
        )
        .expect("sample is bounded")
    }

    #[test]
    fn canonical_encoding_is_stable() {
        assert_eq!(
            sample(b"hello").encode(),
            [
                vec![1, 1],
                1_u128.to_be_bytes().to_vec(),
                2_u128.to_be_bytes().to_vec(),
                3_u128.to_be_bytes().to_vec(),
                4_u128.to_be_bytes().to_vec(),
                5_u64.to_be_bytes().to_vec(),
                5_u32.to_be_bytes().to_vec(),
                b"hello".to_vec(),
            ]
            .concat()
        );
    }

    #[test]
    fn round_trip_preserves_all_fields() {
        let original = sample(b"peer content remains data");
        assert_eq!(Envelope::decode(&original.encode()), Ok(original));
    }

    #[test]
    fn malformed_inputs_have_stable_errors() {
        assert_eq!(
            Envelope::decode(&[]),
            Err(DecodeError::Truncated {
                field: DecodeField::Version
            })
        );
        assert_eq!(
            Envelope::decode(&[WIRE_VERSION]),
            Err(DecodeError::Truncated {
                field: DecodeField::Kind
            })
        );
        assert_eq!(
            Envelope::decode(&[WIRE_VERSION, 0]),
            Err(DecodeError::InvalidKind)
        );
        assert_eq!(
            Envelope::decode(&[2, 1]),
            Err(DecodeError::UnsupportedVersion { found: 2 })
        );
    }

    proptest! {
        #[test]
        fn bounded_body_round_trips(body in proptest::collection::vec(any::<u8>(), 0..=MAX_BODY_BYTES)) {
            let envelope = sample(&body);
            prop_assert_eq!(Envelope::decode(&envelope.encode()), Ok(envelope));
        }
    }
}
