//! Closed, bounded administration requests. No caller-controlled paths.

use super::*;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

pub(super) const MAX_ARTIFACT: usize = 192 * 1024;
pub(super) const MAX_RESPONSE: usize = 960 * 1024;

/// Private bootstrap artifacts can contain one-use secrets. Do not derive Debug.
pub(super) struct Artifact(pub(super) Zeroizing<Vec<u8>>);

impl<'de> Deserialize<'de> for Artifact {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Zeroizing::new(String::deserialize(deserializer)?);
        if value.is_empty() || value.len() > 2 * MAX_ARTIFACT || value.len() % 2 != 0 {
            return Err(D::Error::custom("invalid artifact length"));
        }
        let digit = |byte| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        let mut bytes = Zeroizing::new(Vec::with_capacity(value.len() / 2));
        for pair in value.as_bytes().as_chunks::<2>().0 {
            let high = digit(pair[0]).ok_or_else(|| D::Error::custom("invalid artifact"))?;
            let low = digit(pair[1]).ok_or_else(|| D::Error::custom("invalid artifact"))?;
            bytes.push(high * 16 + low);
        }
        Ok(Self(bytes))
    }
}

impl Serialize for Artifact {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&Zeroizing::new(hex(&self.0)))
    }
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Limits {
    pub(super) max_records: u64,
    pub(super) max_record_bytes: u64,
}

impl Limits {
    pub(super) fn check(self, kind: Kind) -> Result<(), ErrorBody> {
        let minimum_records = match kind {
            Kind::Public => vhalla_direct_native::CONTROL_RESERVED_RECORDS + 8,
            Kind::Private => 0,
        };
        let minimum_bytes = match kind {
            Kind::Public => vhalla_direct_native::CONTROL_RESERVED_BYTES + 32 * 1024,
            Kind::Private => 39,
        };
        if self.max_records <= minimum_records
            || self.max_records > 1_000_000
            || self.max_record_bytes <= minimum_bytes
            || self.max_record_bytes > 8 * 1024 * 1024 * 1024
        {
            return Err(usage(
                "The selected room limits are outside the supported range.",
            ));
        }
        Ok(())
    }

    pub(super) fn public(self) -> vhalla_direct_native::Limits {
        vhalla_direct_native::Limits {
            max_records: self.max_records,
            max_record_bytes: self.max_record_bytes,
        }
    }

    pub(super) fn private(self) -> vhalla_private_native::private_rooms::Limits {
        vhalla_private_native::private_rooms::Limits {
            max_records: self.max_records,
            max_record_bytes: self.max_record_bytes,
        }
    }
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Interval {
    pub(super) not_before: u64,
    pub(super) expires_at: u64,
}

impl Interval {
    pub(super) fn native(self) -> Result<Validity, ErrorBody> {
        Validity::new(self.not_before, self.expires_at)
            .map_err(|_| usage("The validity interval must end after it starts."))
    }
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "op", deny_unknown_fields)]
pub(super) enum Request {
    #[serde(rename = "service.status")]
    ServiceStatus {},
    #[serde(rename = "service.expand_limits")]
    ExpandService { limits: Limits },
    #[serde(rename = "room.list")]
    RoomList {},
    #[serde(rename = "room.create")]
    Create {
        operation: Id,
        kind: Kind,
        limits: Limits,
        validity: Option<Interval>,
    },
    #[serde(rename = "room.join_public")]
    JoinPublic {
        operation: Id,
        genesis: Artifact,
        pin: Hash,
        limits: Limits,
    },
    #[serde(rename = "room.join_private")]
    JoinPrivate {
        operation: Id,
        offer: Artifact,
        expected_owner: Hash,
        validity: Interval,
        limits: Limits,
    },
    #[serde(rename = "room.status")]
    Status { room: Id },
    #[serde(rename = "room.reopen")]
    Reopen { room: Id },
    #[serde(rename = "room.send")]
    Send {
        room: Id,
        operation: Id,
        body: String,
        epoch: Option<u64>,
        roster: Option<Hash>,
    },
    #[serde(rename = "room.messages")]
    Messages { room: Id, after: u64, limit: usize },
    #[serde(rename = "room.outbox_status")]
    Outbox { room: Id, after: u64, limit: usize },
    #[serde(rename = "public.set_writers")]
    SetWriters {
        room: Id,
        operation: Id,
        writers: Vec<Hash>,
    },
    #[serde(rename = "public.expand_limits")]
    ExpandPublic { room: Id, limits: Limits },
    #[serde(rename = "public.reconcile")]
    ReconcilePublic { room: Id },
    #[serde(rename = "private.offer")]
    Offer {
        room: Id,
        operation: Id,
        recipient: Hash,
        validity: Interval,
    },
    #[serde(rename = "private.accept_contact")]
    AcceptContact {
        room: Id,
        operation: Id,
        request: Artifact,
        validity: Interval,
    },
    #[serde(rename = "private.join_contact")]
    JoinContact { room: Id, response: Artifact },
    #[serde(rename = "private.remove")]
    Remove {
        room: Id,
        operation: Id,
        device: Hash,
    },
}

impl Request {
    pub(super) fn room_id(&self) -> Option<Id> {
        match self {
            Self::ServiceStatus {} | Self::RoomList {} | Self::ExpandService { .. } => None,
            Self::Create { operation, .. }
            | Self::JoinPublic { operation, .. }
            | Self::JoinPrivate { operation, .. } => Some(*operation),
            Self::Status { room }
            | Self::Reopen { room }
            | Self::Send { room, .. }
            | Self::Messages { room, .. }
            | Self::Outbox { room, .. }
            | Self::SetWriters { room, .. }
            | Self::ExpandPublic { room, .. }
            | Self::ReconcilePublic { room }
            | Self::Offer { room, .. }
            | Self::AcceptContact { room, .. }
            | Self::JoinContact { room, .. }
            | Self::Remove { room, .. } => Some(*room),
        }
    }

    pub(super) fn creation_intent(&self) -> Result<Option<Hash>, ErrorBody> {
        if !matches!(
            self,
            Self::Create { .. } | Self::JoinPublic { .. } | Self::JoinPrivate { .. }
        ) {
            return Ok(None);
        }
        // Struct/enum field order, parsed IDs and decoded blobs make this stable
        // across JSON key order and irrelevant whitespace. Only its hash persists.
        let encoded = Zeroizing::new(serde_json::to_vec(self).map_err(|_| internal())?);
        Ok(Some(commitment(b"room-creation", &encoded)))
    }
}

pub(super) fn hex(raw: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    let mut value = String::with_capacity(raw.len() * 2);
    for byte in raw {
        value.push(char::from(DIGITS[usize::from(byte >> 4)]));
        value.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    value
}

pub(super) fn artifact(raw: &[u8]) -> Result<String, ErrorBody> {
    if raw.is_empty() || raw.len() > MAX_ARTIFACT {
        return Err(usage("The private artifact exceeds the supported size."));
    }
    Ok(hex(raw))
}

pub(super) fn bound_response(value: &Value) -> Result<(), ErrorBody> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > MAX_RESPONSE.saturating_sub(self.0) {
                return Err(std::io::Error::other("response limit"));
            }
            self.0 += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Counter(0), value)
        .map_err(|_| usage("The response exceeds the supported page size."))
}
