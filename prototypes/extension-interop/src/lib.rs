//! Opaque extension forwarding and explicit protocol negotiation.
//!
//! This is a small reference model. Unknown data is retained for forwarding,
//! while authority is granted only for a locally registered kind, version, and
//! capability set inside the expected realm and owner epoch.

use std::collections::{BTreeMap, BTreeSet};

pub type RealmId = u64;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Version(pub u16);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionRange {
    pub min: Version,
    pub max: Version,
}

impl VersionRange {
    pub fn new(min: Version, max: Version) -> Option<Self> {
        (min <= max).then_some(Self { min, max })
    }

    fn contains(self, version: Version) -> bool {
        self.min <= version && version <= self.max
    }

    fn intersect(self, other: Self) -> Option<Self> {
        Self::new(self.min.max(other.min), self.max.min(other.max))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Envelope {
    pub id: u64,
    pub realm: RealmId,
    pub owner_epoch: u64,
    pub kind: String,
    pub version: Version,
    pub min_reader: Version,
    pub required_capabilities: BTreeSet<String>,
    pub fields: BTreeMap<String, Vec<u8>>,
    pub body: Vec<u8>,
    pub forwardable: bool,
}

impl Envelope {
    pub fn new(id: u64, realm: RealmId, owner_epoch: u64, kind: &str, version: Version) -> Self {
        Self {
            id,
            realm,
            owner_epoch,
            kind: kind.into(),
            version,
            min_reader: Version(0),
            required_capabilities: BTreeSet::new(),
            fields: BTreeMap::new(),
            body: Vec::new(),
            forwardable: true,
        }
    }

    pub fn require_capability(mut self, capability: &str) -> Self {
        self.required_capabilities.insert(capability.into());
        self
    }

    pub fn with_field(mut self, name: &str, value: impl Into<Vec<u8>>) -> Self {
        self.fields.insert(name.into(), value.into());
        self
    }

    pub fn with_min_reader(mut self, version: Version) -> Self {
        self.min_reader = version;
        self
    }

    pub fn non_forwardable(mut self) -> Self {
        self.forwardable = false;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hello {
    pub protocol: VersionRange,
    pub kinds: BTreeMap<String, VersionRange>,
    pub capabilities: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Negotiated {
    pub protocol: VersionRange,
    pub kinds: BTreeMap<String, VersionRange>,
    pub capabilities: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reject {
    InvalidRange,
    Realm,
    OwnerEpoch,
    TooLarge,
    UnknownKind,
    UnsupportedVersion,
    Downgrade,
    IncompatibleSchema,
    MissingCapability,
    UnknownAuthority,
    NoProtocolOverlap,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Admission {
    Known(Envelope),
    Opaque(Envelope),
    Rejected(Reject),
}

pub struct Peer {
    realm: RealmId,
    owner_epoch: u64,
    protocol: Version,
    max_fields: usize,
    max_body: usize,
    kinds: BTreeMap<String, VersionRange>,
    capabilities: BTreeSet<String>,
}

impl Peer {
    pub fn new(realm: RealmId, owner_epoch: u64, protocol: Version) -> Self {
        Self {
            realm,
            owner_epoch,
            protocol,
            max_fields: 64,
            max_body: 64 * 1024,
            kinds: BTreeMap::new(),
            capabilities: BTreeSet::new(),
        }
    }

    pub fn with_limits(mut self, max_fields: usize, max_body: usize) -> Self {
        self.max_fields = max_fields;
        self.max_body = max_body;
        self
    }

    pub fn register_kind(mut self, kind: &str, range: VersionRange) -> Self {
        self.kinds.insert(kind.into(), range);
        self
    }

    pub fn enable_capability(mut self, capability: &str) -> Self {
        self.capabilities.insert(capability.into());
        self
    }

    pub fn hello(&self) -> Hello {
        Hello {
            protocol: VersionRange {
                min: self.protocol,
                max: self.protocol,
            },
            kinds: self.kinds.clone(),
            capabilities: self.capabilities.clone(),
        }
    }

    pub fn negotiate(&self, remote: &Hello) -> Result<Negotiated, Reject> {
        let protocol = self
            .hello()
            .protocol
            .intersect(remote.protocol)
            .ok_or(Reject::NoProtocolOverlap)?;
        let kinds = self
            .kinds
            .iter()
            .filter_map(|(kind, local)| {
                remote
                    .kinds
                    .get(kind)
                    .and_then(|other| local.intersect(*other))
                    .map(|range| (kind.clone(), range))
            })
            .collect();
        let capabilities = self
            .capabilities
            .intersection(&remote.capabilities)
            .cloned()
            .collect();
        Ok(Negotiated {
            protocol,
            kinds,
            capabilities,
        })
    }

    pub fn admit(&self, envelope: Envelope) -> Admission {
        if envelope.realm != self.realm {
            return Admission::Rejected(Reject::Realm);
        }
        if envelope.owner_epoch != self.owner_epoch {
            return Admission::Rejected(Reject::OwnerEpoch);
        }
        let field_bytes = envelope.fields.iter().fold(0usize, |size, (name, value)| {
            size.saturating_add(name.len()).saturating_add(value.len())
        });
        if envelope.kind.len() > 256
            || envelope.fields.len() > self.max_fields
            || envelope.required_capabilities.len() > self.max_fields
            || field_bytes.saturating_add(envelope.body.len()) > self.max_body
        {
            return Admission::Rejected(Reject::TooLarge);
        }
        if self.protocol < envelope.min_reader {
            return Admission::Rejected(Reject::IncompatibleSchema);
        }
        let Some(range) = self.kinds.get(&envelope.kind).copied() else {
            return if envelope.forwardable {
                Admission::Opaque(envelope)
            } else {
                Admission::Rejected(Reject::UnknownKind)
            };
        };
        if envelope.version < range.min {
            return Admission::Rejected(Reject::Downgrade);
        }
        if !range.contains(envelope.version) {
            return if envelope.forwardable {
                Admission::Opaque(envelope)
            } else {
                Admission::Rejected(Reject::UnsupportedVersion)
            };
        }
        if !envelope.required_capabilities.is_subset(&self.capabilities) {
            return Admission::Rejected(Reject::MissingCapability);
        }
        if envelope
            .fields
            .keys()
            .any(|field| field.starts_with("authority:"))
        {
            return Admission::Rejected(Reject::UnknownAuthority);
        }
        Admission::Known(envelope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(min: u16, max: u16) -> VersionRange {
        VersionRange::new(Version(min), Version(max)).unwrap()
    }

    fn old_peer() -> Peer {
        Peer::new(7, 3, Version(1)).with_limits(4, 32)
    }

    #[test]
    fn old_peer_preserves_and_forwards_future_object() {
        let peer = old_peer().register_kind("chat", range(1, 1));
        let future =
            Envelope::new(1, 7, 3, "game.v2", Version(2)).with_field("future", b"opaque".to_vec());
        let copy = future.clone();
        assert_eq!(peer.admit(future), Admission::Opaque(copy));
    }

    #[test]
    fn unknown_fields_never_grant_authority() {
        let peer = old_peer().register_kind("chat", range(1, 1));
        let envelope = Envelope::new(1, 7, 3, "chat", Version(1))
            .with_field("authority:admin", b"true".to_vec());
        assert_eq!(
            peer.admit(envelope),
            Admission::Rejected(Reject::UnknownAuthority)
        );
    }

    #[test]
    fn schema_explains_old_peer_and_downgrade_fails_closed() {
        let peer = old_peer().register_kind("game", range(2, 3));
        assert_eq!(
            peer.admit(Envelope::new(1, 7, 3, "game", Version(1))),
            Admission::Rejected(Reject::Downgrade)
        );
        assert_eq!(
            peer.admit(Envelope::new(2, 7, 3, "game", Version(2)).with_min_reader(Version(2))),
            Admission::Rejected(Reject::IncompatibleSchema)
        );
    }

    #[test]
    fn realm_epoch_and_capability_are_required() {
        let peer = old_peer()
            .register_kind("tool", range(1, 1))
            .enable_capability("read");
        assert_eq!(
            peer.admit(Envelope::new(1, 8, 3, "tool", Version(1))),
            Admission::Rejected(Reject::Realm)
        );
        assert_eq!(
            peer.admit(Envelope::new(2, 7, 4, "tool", Version(1))),
            Admission::Rejected(Reject::OwnerEpoch)
        );
        assert_eq!(
            peer.admit(Envelope::new(3, 7, 3, "tool", Version(1)).require_capability("write")),
            Admission::Rejected(Reject::MissingCapability)
        );
    }

    #[test]
    fn negotiation_intersects_ranges_and_capabilities() {
        let local = old_peer()
            .register_kind("game", range(1, 3))
            .enable_capability("read");
        let remote = Hello {
            protocol: range(1, 2),
            kinds: [("game".into(), range(2, 4))].into(),
            capabilities: ["read".into(), "write".into()].into(),
        };
        let result = local.negotiate(&remote).unwrap();
        assert_eq!(result.protocol, range(1, 1));
        assert_eq!(result.kinds.get("game"), Some(&range(2, 3)));
        assert_eq!(result.capabilities, ["read".into()].into());
    }

    #[test]
    fn limits_reject_oversized_opaque_data() {
        let peer = old_peer();
        let envelope = Envelope {
            body: vec![0; 33],
            ..Envelope::new(1, 7, 3, "future", Version(9))
        };
        assert_eq!(peer.admit(envelope), Admission::Rejected(Reject::TooLarge));
    }
}
