//! Portable canonical opaque relay items. No filesystem, database or sockets.
#![forbid(unsafe_code)]
use sha2::{Digest, Sha256};
use vhalla_private_kernel::{CommittedEncryptedControl, CommittedOutbox, OperationId, OutboxKind};
/// Shared bounded transport framing.
pub mod codec;
/// Exact HTTPS origins shared by browser profiles and hosted gateways.
pub mod http_origin;
/// Canonical item magic and version.
pub const MAGIC: &[u8] = b"VHPRELAY\x01";
const DIGEST_DOMAIN: &[u8] = b"vhalla/private/relay-item/v1";
/// Maximum ciphertext payload in one relay item.
pub const MAX_RELAY_PAYLOAD: usize = 2 * 128 * 1024 + 4096;
/// Maximum items returned by one relay page.
pub const MAX_RELAY_PAGE: usize = 64;
/// Maximum retained items in one immutable mailbox and catch-up directory.
pub const MAX_RELAY_ITEMS: usize = 4096;

/// Transport streams are independent: control floors are not outbox positions.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum RelayKind {
    /// An ordinary encrypted kernel outbox artifact.
    Outbox(OutboxKind),
    /// An exact committed encrypted owner control, including member admission.
    Control,
}
// Keep the established CLI metadata names for tags 1..8. The new stream must
// not turn an existing `Application` report into `Outbox(Application)`.
impl core::fmt::Debug for RelayKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Outbox(kind) => core::fmt::Debug::fmt(kind, f),
            Self::Control => f.write_str("Control"),
        }
    }
}
impl From<OutboxKind> for RelayKind {
    fn from(kind: OutboxKind) -> Self {
        Self::Outbox(kind)
    }
}
impl PartialEq<OutboxKind> for RelayKind {
    fn eq(&self, other: &OutboxKind) -> bool {
        *self == Self::Outbox(*other)
    }
}

/// Closed failures. No error includes ciphertext, room metadata, or a path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Input is malformed, noncanonical, or exceeds a fixed bound.
    Bounds,
    /// The item belongs to another opaque relay namespace.
    Scope,
    /// The same operation was presented with different bytes.
    Conflict,
    /// The selected artifact kind cannot be put on a generic relay.
    Confidential,
    /// The relay quota is full; it never prunes older items automatically.
    Capacity,
    /// A durable adapter could not read, write or validate its store.
    Storage,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}

type Result<T> = std::result::Result<T, Error>;

/// An opaque, out-of-band rendezvous namespace. It is not a room ID or key.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RelayNamespace([u8; 32]);

impl RelayNamespace {
    /// Construct a nonzero namespace supplied by the application out of band.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        if bytes == [0; 32] {
            return Err(Error::Bounds);
        }
        Ok(Self(bytes))
    }

    /// Borrow the exact namespace bytes for an adapter.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The only receipt a relay may issue: local retention of an opaque item.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayReceipt {
    /// Mailbox-assigned retention position; never the sender-local sequence.
    /// It acknowledges retention only, never delivery or member acceptance.
    pub position: u64,
    /// Exact item commitment retained by the relay.
    pub digest: [u8; 32],
    /// True when identical bytes were already retained at this position.
    pub duplicate: bool,
}

/// One complete encrypted outbox/control artifact and its opaque relay binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayItem {
    namespace: RelayNamespace,
    sequence: u64,
    operation: OperationId,
    kind: RelayKind,
    payload: Vec<u8>,
    digest: [u8; 32],
}

impl RelayItem {
    /// Carry the original retained control without encrypting again. The opaque
    /// operation commitment exposes no room or account identifier. Its sequence
    /// is a control floor, independent of the outbox stream.
    pub fn from_control(
        namespace: RelayNamespace,
        control: &CommittedEncryptedControl,
    ) -> Result<Self> {
        let mut hash = Sha256::new();
        hash.update(b"vhalla/private/relay-control-operation/v1\0");
        hash.update(control.bytes());
        let digest: [u8; 32] = hash.finalize().into();
        let operation =
            OperationId::from_bytes(digest[..16].try_into().map_err(|_| Error::Bounds)?)
                .map_err(|_| Error::Bounds)?;
        Self::new(
            namespace,
            control.floor().sequence(),
            operation,
            RelayKind::Control,
            control.bytes(),
        )
    }
    /// Convert a committed ordinary artifact into an opaque relay item.
    /// Confidential offers and legacy plaintext bootstrap artifacts are refused.
    pub fn from_artifact(namespace: RelayNamespace, artifact: &CommittedOutbox) -> Result<Self> {
        if !relay_kind(artifact.kind().into()) {
            return Err(Error::Confidential);
        }
        Self::new(
            namespace,
            artifact.sequence(),
            artifact.operation(),
            artifact.kind(),
            artifact.bytes(),
        )
    }

    /// Validate and construct an item received from a transport adapter.
    pub fn new(
        namespace: RelayNamespace,
        sequence: u64,
        operation: OperationId,
        kind: impl Into<RelayKind>,
        payload: &[u8],
    ) -> Result<Self> {
        let kind = kind.into();
        if sequence == 0
            || !relay_kind(kind)
            || payload.is_empty()
            || payload.len() > MAX_RELAY_PAYLOAD
        {
            return Err(if relay_kind(kind) {
                Error::Bounds
            } else {
                Error::Confidential
            });
        }
        let digest = digest(namespace, sequence, operation, kind, payload);
        Ok(Self {
            namespace,
            sequence,
            operation,
            kind,
            payload: payload.to_vec(),
            digest,
        })
    }

    /// Opaque namespace used to select one relay mailbox.
    pub fn namespace(&self) -> RelayNamespace {
        self.namespace
    }

    /// Original outbox position or control floor, selected by [`Self::kind`].
    /// It is committed metadata only; the mailbox never orders or deduplicates on it.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Original operation identity for idempotent retry.
    pub fn operation(&self) -> OperationId {
        self.operation
    }

    /// Closed artifact classification.
    pub fn kind(&self) -> RelayKind {
        self.kind
    }

    /// Borrow the complete encrypted payload. It is never plaintext.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Exact commitment over namespace, metadata, kind, and ciphertext.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Canonical bounded wire representation for an interchangeable adapter.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let payload_len = u32::try_from(self.payload.len()).map_err(|_| Error::Bounds)?;
        let mut out = Vec::with_capacity(
            MAGIC.len() + 32 + 8 + 16 + 1 + 4 + self.payload.len() + self.digest.len(),
        );
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(self.namespace.as_bytes());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(self.operation.as_bytes());
        out.push(kind_byte(self.kind));
        out.extend_from_slice(&payload_len.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out.extend_from_slice(&self.digest);
        Ok(out)
    }

    /// Decode and authenticate a canonical relay item without decrypting it.
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let header = MAGIC.len() + 32 + 8 + 16 + 1 + 4;
        if raw.len() < header + 32 || &raw[..MAGIC.len()] != MAGIC {
            return Err(Error::Bounds);
        }
        let mut cursor = MAGIC.len();
        let namespace = RelayNamespace::from_bytes(take::<32>(raw, &mut cursor)?)?;
        let sequence = u64::from_be_bytes(take::<8>(raw, &mut cursor)?);
        let operation =
            OperationId::from_bytes(take::<16>(raw, &mut cursor)?).map_err(|_| Error::Bounds)?;
        let kind = kind_from_byte(byte(raw, &mut cursor)?)?;
        let length = usize::try_from(u32::from_be_bytes(take::<4>(raw, &mut cursor)?))
            .map_err(|_| Error::Bounds)?;
        if length == 0 || length > MAX_RELAY_PAYLOAD {
            return Err(Error::Bounds);
        }
        let end = cursor
            .checked_add(length)
            .and_then(|n| n.checked_add(32))
            .ok_or(Error::Bounds)?;
        if end != raw.len() {
            return Err(Error::Bounds);
        }
        let payload = &raw[cursor..cursor + length];
        cursor += length;
        let expected = take::<32>(raw, &mut cursor)?;
        let item = Self::new(namespace, sequence, operation, kind, payload)?;
        if item.digest != expected {
            return Err(Error::Conflict);
        }
        Ok(item)
    }
}

/// One retained item at its relay-assigned position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PositionedItem {
    /// Mailbox-assigned position; it totally orders every sender's items in
    /// one namespace and is the only paging/cursor unit the relay defines.
    pub position: u64,
    /// The retained canonical item; its `sequence` remains sender-local
    /// metadata and does not order the mailbox.
    pub item: RelayItem,
}

/// Immutable bounded relay page.
pub struct RelayPage {
    /// Highest retained relay position observed before the page read.
    pub head: u64,
    /// Exclusive position cursor for another page, if more items exist.
    pub next: Option<u64>,
    /// Items in ascending relay position.
    pub records: Vec<PositionedItem>,
}

fn relay_kind(kind: RelayKind) -> bool {
    matches!(
        kind,
        RelayKind::Control
            | RelayKind::Outbox(
                OutboxKind::ContactRequest
                    | OutboxKind::ContactInvitation
                    | OutboxKind::Application
                    | OutboxKind::Removal
                    | OutboxKind::OwnerUpdate
                    | OutboxKind::Succession
            )
    )
}

/// Stable wire tag for a committed outbox kind.
pub fn kind_byte(kind: impl Into<RelayKind>) -> u8 {
    let RelayKind::Outbox(kind) = kind.into() else {
        return 9;
    };
    match kind {
        OutboxKind::ContactOffer => 0,
        OutboxKind::ContactRequest => 1,
        OutboxKind::ContactInvitation => 2,
        OutboxKind::KeyPackage => 3,
        OutboxKind::Invitation => 4,
        OutboxKind::Application => 5,
        OutboxKind::Removal => 6,
        OutboxKind::OwnerUpdate => 7,
        OutboxKind::Succession => 8,
    }
}

/// Parse the historical wire kind; item admission separately refuses bootstrap.
pub fn kind_from_byte(byte: u8) -> Result<RelayKind> {
    if byte == 9 {
        return Ok(RelayKind::Control);
    }
    match byte {
        1 => Ok(OutboxKind::ContactRequest),
        2 => Ok(OutboxKind::ContactInvitation),
        3 => Ok(OutboxKind::KeyPackage),
        4 => Ok(OutboxKind::Invitation),
        5 => Ok(OutboxKind::Application),
        6 => Ok(OutboxKind::Removal),
        7 => Ok(OutboxKind::OwnerUpdate),
        8 => Ok(OutboxKind::Succession),
        _ => Err(Error::Confidential),
    }
    .map(RelayKind::Outbox)
}

fn digest(
    namespace: RelayNamespace,
    sequence: u64,
    operation: OperationId,
    kind: RelayKind,
    payload: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update(namespace.as_bytes());
    hasher.update(sequence.to_be_bytes());
    hasher.update(operation.as_bytes());
    hasher.update([kind_byte(kind)]);
    hasher.update(payload);
    hasher.finalize().into()
}

fn byte(raw: &[u8], cursor: &mut usize) -> Result<u8> {
    let value = *raw.get(*cursor).ok_or(Error::Bounds)?;
    *cursor += 1;
    Ok(value)
}

fn take<const N: usize>(raw: &[u8], cursor: &mut usize) -> Result<[u8; N]> {
    let end = cursor.checked_add(N).ok_or(Error::Bounds)?;
    let value = raw.get(*cursor..end).ok_or(Error::Bounds)?;
    *cursor = end;
    value.try_into().map_err(|_| Error::Bounds)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn namespace() -> RelayNamespace {
        RelayNamespace::from_bytes([9; 32]).unwrap()
    }

    fn operation(value: u8) -> OperationId {
        OperationId::from_bytes([value; 16]).unwrap()
    }

    fn item(sequence: u64, kind: OutboxKind) -> RelayItem {
        RelayItem::new(
            namespace(),
            sequence,
            operation(sequence as u8),
            kind,
            b"ciphertext",
        )
        .unwrap()
    }

    #[test]
    fn canonical_roundtrip_binds_ciphertext_and_namespace() {
        let original = item(1, OutboxKind::Application);
        let encoded = original.encode().unwrap();
        assert_eq!(RelayItem::decode(&encoded).unwrap(), original);
        let mut changed = encoded;
        *changed.last_mut().unwrap() ^= 1;
        assert_eq!(RelayItem::decode(&changed), Err(Error::Conflict));
    }

    #[test]
    fn legacy_plaintext_bootstrap_is_refused_by_construction_and_decode() {
        for kind in [OutboxKind::KeyPackage, OutboxKind::Invitation] {
            assert_eq!(
                RelayItem::new(namespace(), 1, operation(1), kind, b"private metadata"),
                Err(Error::Confidential)
            );
            // Encode an old-format object directly to exercise the decoder's
            // admission path, including a correct digest for the forbidden kind.
            let old = RelayItem {
                namespace: namespace(),
                sequence: 1,
                operation: operation(1),
                kind: kind.into(),
                payload: b"private metadata".to_vec(),
                digest: digest(
                    namespace(),
                    1,
                    operation(1),
                    kind.into(),
                    b"private metadata",
                ),
            };
            assert_eq!(
                RelayItem::decode(&old.encode().unwrap()),
                Err(Error::Confidential)
            );
        }
    }

    #[test]
    fn control_tag_is_distinct_and_preserves_existing_wire_tags() {
        assert_eq!(
            format!("{:?}", RelayKind::Outbox(OutboxKind::Application)),
            "Application"
        );
        assert_eq!(format!("{:?}", RelayKind::Control), "Control");
        for byte in 1..=8 {
            assert!(matches!(
                kind_from_byte(byte).unwrap(),
                RelayKind::Outbox(_)
            ));
            assert_eq!(kind_byte(kind_from_byte(byte).unwrap()), byte);
        }
        assert_eq!(kind_from_byte(9).unwrap(), RelayKind::Control);
        assert!(kind_from_byte(10).is_err());
        let control = RelayItem::new(
            namespace(),
            1,
            operation(1),
            RelayKind::Control,
            b"opaque encrypted control",
        )
        .unwrap();
        assert_eq!(
            RelayItem::decode(&control.encode().unwrap()).unwrap(),
            control
        );
        let application = RelayItem::new(
            namespace(),
            1,
            operation(1),
            OutboxKind::Application,
            control.payload(),
        )
        .unwrap();
        assert_ne!(control.digest(), application.digest());
    }
}

#[cfg(test)]
mod wire_tests;
