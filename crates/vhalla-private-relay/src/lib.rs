//! Portable canonical opaque relay items. No filesystem, database or sockets.
#![forbid(unsafe_code)]
use sha2::{Digest, Sha256};
use vhalla_private_kernel::{CommittedOutbox, OperationId, OutboxKind};
/// Shared bounded transport framing.
pub mod codec;
/// Canonical item magic and version.
pub const MAGIC: &[u8] = b"VHPRELAY\x01";
const DIGEST_DOMAIN: &[u8] = b"vhalla/private/relay-item/v1";
/// Maximum ciphertext payload in one relay item.
pub const MAX_RELAY_PAYLOAD: usize = 2 * 128 * 1024 + 4096;
/// Maximum items returned by one relay page.
pub const MAX_RELAY_PAGE: usize = 64;
/// Maximum retained items in one immutable mailbox and catch-up directory.
pub const MAX_RELAY_ITEMS: usize = 4096;

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

/// One complete encrypted outbox artifact and its opaque relay binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayItem {
    namespace: RelayNamespace,
    sequence: u64,
    operation: OperationId,
    kind: OutboxKind,
    payload: Vec<u8>,
    digest: [u8; 32],
}

impl RelayItem {
    /// Convert a committed ordinary artifact into an opaque relay item.
    /// Confidential offers and legacy plaintext bootstrap artifacts are refused.
    pub fn from_artifact(namespace: RelayNamespace, artifact: &CommittedOutbox) -> Result<Self> {
        if !relay_kind(artifact.kind()) {
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
        kind: OutboxKind,
        payload: &[u8],
    ) -> Result<Self> {
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

    /// Original sender-local outbox sequence. It is committed metadata only;
    /// the mailbox never orders or deduplicates on it.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Original operation identity for idempotent retry.
    pub fn operation(&self) -> OperationId {
        self.operation
    }

    /// Closed artifact classification.
    pub fn kind(&self) -> OutboxKind {
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

fn relay_kind(kind: OutboxKind) -> bool {
    matches!(
        kind,
        OutboxKind::ContactRequest
            | OutboxKind::ContactInvitation
            | OutboxKind::Application
            | OutboxKind::Removal
            | OutboxKind::OwnerUpdate
            | OutboxKind::Succession
    )
}

/// Stable wire tag for a committed outbox kind.
pub fn kind_byte(kind: OutboxKind) -> u8 {
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
pub fn kind_from_byte(byte: u8) -> Result<OutboxKind> {
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
}

fn digest(
    namespace: RelayNamespace,
    sequence: u64,
    operation: OperationId,
    kind: OutboxKind,
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
                kind,
                payload: b"private metadata".to_vec(),
                digest: digest(namespace(), 1, operation(1), kind, b"private metadata"),
            };
            assert_eq!(
                RelayItem::decode(&old.encode().unwrap()),
                Err(Error::Confidential)
            );
        }
    }
}

#[cfg(test)]
mod wire_tests;
