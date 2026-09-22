//! Bounded opaque relay records for private-room ciphertext.
//!
//! A relay stores already-encrypted room artifacts. It never receives an MLS
//! key, room/anchor/account identity, plaintext, or a recipient acceptance
//! claim. The namespace is an out-of-band rendezvous token; callers must not
//! derive it from private room metadata. One mailbox serves every sender in
//! the namespace: retained items are ordered by the mailbox's own assigned
//! position, while each item keeps its sender-local outbox sequence only as
//! committed metadata. This module is transport agnostic so an HTTP, QUIC, or
//! file-backed adapter can implement the same contract.

use rusqlite::{params, Connection, OptionalExtension, Row};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs::File, path::Path};
use vhalla_custody as custody;
use vhalla_private_kernel::{CommittedOutbox, OperationId, OutboxKind};

/// Authenticated socket adapter and durable cursor catch-up for this boundary.
pub mod net;

const MAGIC: &[u8] = b"VHPRELAY\x01";
const DIGEST_DOMAIN: &[u8] = b"vhalla/private/relay-item/v1";
/// Maximum ciphertext payload in one relay item.
pub const MAX_RELAY_PAYLOAD: usize = 2 * 128 * 1024 + 4096;
/// Maximum items returned by one relay page.
pub const MAX_RELAY_PAGE: usize = 64;
/// Maximum retained items in one immutable mailbox and catch-up directory.
pub const MAX_RELAY_ITEMS: usize = 4096;
const MAX_RELAY_DB_BYTES: usize = 2 * 1024 * 1024 * 1024;

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

/// Fixed relay storage limits. Reaching a limit preserves all retained items.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum retained item count.
    pub max_items: usize,
    /// Maximum retained ciphertext bytes.
    pub max_bytes: usize,
}

impl Limits {
    fn check(self) -> Result<()> {
        if self.max_items == 0 || self.max_items > MAX_RELAY_ITEMS || self.max_bytes == 0 {
            return Err(Error::Bounds);
        }
        Ok(())
    }
}

/// An in-process reference relay with the same retention semantics as a remote
/// adapter. It is useful for tests and local development, not a global server.
pub struct Store {
    namespace: RelayNamespace,
    limits: Limits,
    bytes: usize,
    /// Retained items keyed by mailbox-assigned position, not sender sequence.
    items: BTreeMap<u64, RelayItem>,
}

impl Store {
    /// Create an empty mailbox for one opaque namespace.
    pub fn new(namespace: RelayNamespace, limits: Limits) -> Result<Self> {
        limits.check()?;
        Ok(Self {
            namespace,
            limits,
            bytes: 0,
            items: BTreeMap::new(),
        })
    }

    /// Retention-only namespace; it is never a room authorization claim.
    pub fn namespace(&self) -> RelayNamespace {
        self.namespace
    }

    /// Store an item idempotently at the next mailbox-assigned position. An
    /// identical item returns its existing position; the same operation with
    /// different bytes conflicts. One mailbox serves every sender, so sender
    /// sequences may overlap and never order or collide. The receipt says only
    /// that this relay retained bytes.
    pub fn put(&mut self, item: RelayItem) -> Result<RelayReceipt> {
        if item.namespace != self.namespace {
            return Err(Error::Scope);
        }
        if let Some((&position, _)) = self
            .items
            .iter()
            .find(|(_, previous)| previous.digest == item.digest)
        {
            return Ok(RelayReceipt {
                position,
                digest: item.digest,
                duplicate: true,
            });
        }
        if self
            .items
            .values()
            .any(|previous| previous.operation == item.operation)
        {
            return Err(Error::Conflict);
        }
        if self.items.len() >= self.limits.max_items
            || self
                .bytes
                .checked_add(item.payload.len())
                .ok_or(Error::Capacity)?
                > self.limits.max_bytes
        {
            return Err(Error::Capacity);
        }
        let position = self
            .items
            .keys()
            .next_back()
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(Error::Bounds)?;
        self.bytes += item.payload.len();
        let digest = item.digest;
        self.items.insert(position, item);
        Ok(RelayReceipt {
            position,
            digest,
            duplicate: false,
        })
    }

    /// Read a bounded immutable page in ascending relay position. This is a
    /// retention view, not a member acknowledgment and not proof that any
    /// recipient processed the item.
    pub fn page(&self, after: u64, limit: usize) -> Result<RelayPage> {
        if limit == 0 || limit > MAX_RELAY_PAGE {
            return Err(Error::Bounds);
        }
        let start = after.checked_add(1).ok_or(Error::Bounds)?;
        let mut iter = self.items.range(start..);
        let mut records = Vec::new();
        for _ in 0..limit {
            match iter.next() {
                Some((&position, item)) => records.push(PositionedItem {
                    position,
                    item: item.clone(),
                }),
                None => break,
            }
        }
        let next = records
            .last()
            .and_then(|last| iter.next().map(|_| last.position));
        Ok(RelayPage {
            head: self.items.last_key_value().map_or(0, |(key, _)| *key),
            next,
            records,
        })
    }
}

/// A durable single-process file-backed relay mailbox.
///
/// The directory contains only an SQLite database, a persistent lock file and
/// no room/account metadata. The lock is advisory and held for the lifetime of
/// this value, so callers must open one mailbox handle per process. SQLite is
/// kept in rollback-journal mode and every successful mutation is synchronized
/// before the receipt is returned. A crash leaves the database for explicit
/// reopen/reconciliation; it never prunes or rewrites retained items.
pub struct FileStore {
    conn: Connection,
    directory: File,
    db_guard: File,
    _lock: File,
    namespace: RelayNamespace,
    limits: Limits,
}

impl FileStore {
    /// Create a new 0700 relay directory and mailbox. Existing paths refuse;
    /// there is no reset or implicit namespace replacement.
    pub fn create_new(
        path: impl AsRef<Path>,
        namespace: RelayNamespace,
        limits: Limits,
    ) -> Result<Self> {
        limits.check()?;
        let path = custody::absolute(path.as_ref()).map_err(|_| Error::Storage)?;
        let (directory, _uid) =
            custody::create_private_directory(&path).map_err(|_| Error::Storage)?;
        let lock = custody::create_private_file(&path.join("lock")).map_err(|_| Error::Storage)?;
        custody::acquire_exclusive(&lock).map_err(|_| Error::Storage)?;
        let db_guard =
            custody::create_private_file(&path.join("relay.db")).map_err(|_| Error::Storage)?;
        let conn = Connection::open(path.join("relay.db")).map_err(|_| Error::Storage)?;
        configure_database(&conn)?;
        conn.execute_batch(
            "CREATE TABLE meta (id INTEGER PRIMARY KEY CHECK (id = 1), format INTEGER NOT NULL CHECK (format = 2), namespace BLOB NOT NULL, max_items INTEGER NOT NULL, max_bytes INTEGER NOT NULL);
             CREATE TABLE items (position INTEGER PRIMARY KEY, sequence BLOB NOT NULL, operation BLOB NOT NULL UNIQUE, kind INTEGER NOT NULL, payload BLOB NOT NULL, digest BLOB NOT NULL UNIQUE);",
        )
        .map_err(|_| Error::Storage)?;
        conn.execute(
            "INSERT INTO meta VALUES (1, 2, ?1, ?2, ?3)",
            params![
                namespace.as_bytes().as_slice(),
                i64::try_from(limits.max_items).map_err(|_| Error::Bounds)?,
                i64::try_from(limits.max_bytes).map_err(|_| Error::Bounds)?,
            ],
        )
        .map_err(|_| Error::Storage)?;
        db_guard.sync_all().map_err(|_| Error::Storage)?;
        directory.sync_all().map_err(|_| Error::Storage)?;
        let out = Self {
            conn,
            directory,
            db_guard,
            _lock: lock,
            namespace,
            limits,
        };
        out.validate()?;
        Ok(out)
    }

    /// Reopen an existing mailbox after a clean or interrupted process.
    /// Namespace and immutable quotas must match the caller's explicit choice.
    pub fn open(path: impl AsRef<Path>, namespace: RelayNamespace) -> Result<Self> {
        let path = custody::absolute(path.as_ref()).map_err(|_| Error::Storage)?;
        let (directory, uid) =
            custody::open_private_directory(&path).map_err(|_| Error::Storage)?;
        let lock =
            custody::open_private_file(&path.join("lock"), uid, 0).map_err(|_| Error::Storage)?;
        custody::acquire_exclusive(&lock).map_err(|_| Error::Storage)?;
        let db_guard = custody::open_private_file(&path.join("relay.db"), uid, MAX_RELAY_DB_BYTES)
            .map_err(|_| Error::Storage)?;
        let conn = Connection::open(path.join("relay.db")).map_err(|_| Error::Storage)?;
        configure_database(&conn)?;
        let limits = read_meta(&conn, namespace)?;
        let out = Self {
            conn,
            directory,
            db_guard,
            _lock: lock,
            namespace,
            limits,
        };
        out.validate()?;
        Ok(out)
    }

    /// Exact mailbox namespace, retained only for adapter routing.
    pub fn namespace(&self) -> RelayNamespace {
        self.namespace
    }

    /// Store one item durably and idempotently at the next mailbox-assigned
    /// position. Identical bytes return their existing position; the same
    /// operation with different bytes conflicts. One mailbox serves every
    /// sender in the namespace: sender sequences are metadata, never keys.
    /// A receipt means only that this mailbox committed the bytes locally;
    /// it is not recipient acceptance.
    pub fn put(&mut self, item: RelayItem) -> Result<RelayReceipt> {
        if item.namespace != self.namespace {
            return Err(Error::Scope);
        }
        let existing: Option<i64> = self
            .conn
            .query_row(
                "SELECT position FROM items WHERE digest = ?1",
                params![item.digest.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| Error::Storage)?;
        if let Some(position) = existing {
            return Ok(RelayReceipt {
                position: u64::try_from(position).map_err(|_| Error::Storage)?,
                digest: item.digest,
                duplicate: true,
            });
        }
        let operation_exists: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT sequence FROM items WHERE operation = ?1",
                params![item.operation.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| Error::Storage)?;
        if operation_exists.is_some() {
            return Err(Error::Conflict);
        }
        let (count, bytes): (i64, i64) = self
            .conn
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(length(payload)), 0) FROM items",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| Error::Storage)?;
        let payload_len = i64::try_from(item.payload.len()).map_err(|_| Error::Bounds)?;
        if usize::try_from(count).map_err(|_| Error::Storage)? >= self.limits.max_items
            || bytes.checked_add(payload_len).is_none_or(|total| {
                usize::try_from(total).map_or(true, |value| value > self.limits.max_bytes)
            })
        {
            return Err(Error::Capacity);
        }
        let position: i64 = self
            .conn
            .query_row(
                "SELECT COALESCE(MAX(position), 0) + 1 FROM items",
                [],
                |row| row.get(0),
            )
            .map_err(|_| Error::Storage)?;
        if position <= 0 {
            return Err(Error::Bounds);
        }
        self.conn
            .execute(
                "INSERT INTO items(position, sequence, operation, kind, payload, digest) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    position,
                    item.sequence.to_be_bytes().as_slice(),
                    item.operation.as_bytes().as_slice(),
                    i64::from(kind_byte(item.kind)),
                    item.payload.as_slice(),
                    item.digest.as_slice(),
                ],
            )
            .map_err(|_| Error::Storage)?;
        self.sync()?;
        Ok(RelayReceipt {
            position: u64::try_from(position).map_err(|_| Error::Storage)?,
            digest: item.digest,
            duplicate: false,
        })
    }

    /// Read a bounded immutable page in ascending relay position.
    pub fn page(&self, after: u64, limit: usize) -> Result<RelayPage> {
        if limit == 0 || limit > MAX_RELAY_PAGE {
            return Err(Error::Bounds);
        }
        let start =
            i64::try_from(after.checked_add(1).ok_or(Error::Bounds)?).map_err(|_| Error::Bounds)?;
        let mut statement = self
            .conn
            .prepare(
                "SELECT position, sequence, operation, kind, payload, digest FROM items WHERE position >= ?1 ORDER BY position LIMIT ?2",
            )
            .map_err(|_| Error::Storage)?;
        let rows = statement
            .query_map(
                params![start, i64::try_from(limit + 1).map_err(|_| Error::Bounds)?],
                |row| decode_row(row, self.namespace),
            )
            .map_err(|_| Error::Storage)?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row.map_err(|_| Error::Storage)?);
        }
        let next = if records.len() > limit {
            records.pop();
            records.last().map(|record| record.position)
        } else {
            None
        };
        let head = self
            .conn
            .query_row(
                "SELECT position FROM items ORDER BY position DESC LIMIT 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|_| Error::Storage)?
            .map(|value| u64::try_from(value).map_err(|_| Error::Storage))
            .transpose()?
            .unwrap_or(0);
        Ok(RelayPage {
            head,
            next,
            records,
        })
    }

    fn sync(&self) -> Result<()> {
        self.db_guard.sync_all().map_err(|_| Error::Storage)?;
        self.directory.sync_all().map_err(|_| Error::Storage)?;
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        let (count, bytes): (i64, i64) = self
            .conn
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(length(payload)), 0) FROM items",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| Error::Storage)?;
        if count < 0
            || usize::try_from(count).map_err(|_| Error::Storage)? > self.limits.max_items
            || bytes < 0
            || usize::try_from(bytes).map_err(|_| Error::Storage)? > self.limits.max_bytes
        {
            return Err(Error::Storage);
        }
        let mut statement = self
            .conn
            .prepare("SELECT position, sequence, operation, kind, payload, digest FROM items")
            .map_err(|_| Error::Storage)?;
        let rows = statement
            .query_map([], |row| decode_row(row, self.namespace))
            .map_err(|_| Error::Storage)?;
        for row in rows {
            row.map_err(|_| Error::Storage)?;
        }
        Ok(())
    }
}

fn configure_database(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;",
    )
    .map_err(|_| Error::Storage)
}

fn read_meta(conn: &Connection, expected: RelayNamespace) -> Result<Limits> {
    // Format 2 orders items by mailbox-assigned position; a v1 sequence-keyed
    // database lacks this column and refuses rather than migrating.
    let (format, namespace, max_items, max_bytes): (i64, Vec<u8>, i64, i64) = conn
        .query_row(
            "SELECT format, namespace, max_items, max_bytes FROM meta WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|_| Error::Storage)?;
    if format != 2 {
        return Err(Error::Scope);
    }
    if namespace.as_slice() != expected.as_bytes() || max_items <= 0 || max_bytes <= 0 {
        return Err(Error::Scope);
    }
    let limits = Limits {
        max_items: usize::try_from(max_items).map_err(|_| Error::Bounds)?,
        max_bytes: usize::try_from(max_bytes).map_err(|_| Error::Bounds)?,
    };
    limits.check()?;
    Ok(limits)
}

fn decode_row(row: &Row<'_>, namespace: RelayNamespace) -> rusqlite::Result<PositionedItem> {
    let position: i64 = row.get(0)?;
    let sequence: Vec<u8> = row.get(1)?;
    let operation: Vec<u8> = row.get(2)?;
    let kind: i64 = row.get(3)?;
    let payload: Vec<u8> = row.get(4)?;
    let digest: Vec<u8> = row.get(5)?;
    let sequence: [u8; 8] = sequence
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let operation: [u8; 16] = operation
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let digest: [u8; 32] = digest
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let kind = kind_from_byte(u8::try_from(kind).map_err(|_| rusqlite::Error::InvalidQuery)?)
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let item = RelayItem::new(
        namespace,
        u64::from_be_bytes(sequence),
        OperationId::from_bytes(operation).map_err(|_| rusqlite::Error::InvalidQuery)?,
        kind,
        &payload,
    )
    .map_err(|_| rusqlite::Error::InvalidQuery)?;
    if item.digest != digest || position <= 0 {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(PositionedItem {
        position: u64::try_from(position).map_err(|_| rusqlite::Error::InvalidQuery)?,
        item,
    })
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

fn kind_byte(kind: OutboxKind) -> u8 {
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

fn kind_from_byte(byte: u8) -> Result<OutboxKind> {
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

    fn positioned(position: u64, item: RelayItem) -> PositionedItem {
        PositionedItem { position, item }
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

    #[test]
    fn secret_offer_and_wrong_scope_are_refused() {
        assert_eq!(
            RelayItem::new(
                namespace(),
                1,
                operation(1),
                OutboxKind::ContactOffer,
                b"secret"
            ),
            Err(Error::Confidential)
        );
        let other = RelayNamespace::from_bytes([8; 32]).unwrap();
        let mut store = Store::new(
            namespace(),
            Limits {
                max_items: 2,
                max_bytes: 128,
            },
        )
        .unwrap();
        assert_eq!(
            store.put(
                RelayItem::new(other, 1, operation(1), OutboxKind::Application, b"x").unwrap()
            ),
            Err(Error::Scope)
        );
    }

    #[test]
    fn retries_are_idempotent_and_capacity_never_prunes() {
        let first = item(1, OutboxKind::Application);
        let mut store = Store::new(
            namespace(),
            Limits {
                max_items: 1,
                max_bytes: 32,
            },
        )
        .unwrap();
        assert!(!store.put(first.clone()).unwrap().duplicate);
        assert!(store.put(first).unwrap().duplicate);
        assert_eq!(
            store.put(item(2, OutboxKind::Application)),
            Err(Error::Capacity)
        );
        let page = store.page(0, 1).unwrap();
        assert_eq!(page.head, 1);
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.next, None);
    }

    #[test]
    fn operation_cannot_move_to_a_second_sequence() {
        let mut store = Store::new(
            namespace(),
            Limits {
                max_items: 4,
                max_bytes: 128,
            },
        )
        .unwrap();
        let first = item(1, OutboxKind::Application);
        assert!(!store.put(first.clone()).unwrap().duplicate);
        let moved = RelayItem::new(
            namespace(),
            2,
            first.operation(),
            OutboxKind::Application,
            b"different-ciphertext",
        )
        .unwrap();
        assert_eq!(store.put(moved), Err(Error::Conflict));
    }

    #[test]
    fn senders_share_one_mailbox_at_independent_positions() {
        let mut store = Store::new(
            namespace(),
            Limits {
                max_items: 8,
                max_bytes: 4096,
            },
        )
        .unwrap();
        // Two senders each own outbox sequences 1 and 2; every submission lands
        // at a distinct relay position and pages return insertion order.
        let a1 = item(1, OutboxKind::Application);
        let b1 = RelayItem::new(
            namespace(),
            1,
            operation(200),
            OutboxKind::Application,
            b"member-ciphertext",
        )
        .unwrap();
        let b2 = RelayItem::new(
            namespace(),
            2,
            operation(201),
            OutboxKind::Application,
            b"member-ciphertext-2",
        )
        .unwrap();
        let a2 = item(2, OutboxKind::Removal);
        assert_eq!(store.put(a1.clone()).unwrap().position, 1);
        assert_eq!(store.put(b1.clone()).unwrap().position, 2);
        assert_eq!(store.put(b2.clone()).unwrap().position, 3);
        assert_eq!(store.put(a2.clone()).unwrap().position, 4);
        // Exact resubmission returns the retained position, not a new entry.
        let retry = store.put(b1.clone()).unwrap();
        assert!(retry.duplicate);
        assert_eq!(retry.position, 2);
        let page = store.page(0, MAX_RELAY_PAGE).unwrap();
        assert_eq!(page.head, 4);
        assert_eq!(
            page.records,
            vec![
                positioned(1, a1),
                positioned(2, b1),
                positioned(3, b2),
                positioned(4, a2)
            ]
        );
        // Position cursors page mid-stream across sender boundaries.
        let rest = store.page(2, MAX_RELAY_PAGE).unwrap();
        assert_eq!(rest.records.len(), 2);
        assert_eq!(rest.records[0].position, 3);
    }

    fn home() -> std::path::PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "vhalla-relay-{}-{stamp}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))
    }

    fn file_limits() -> Limits {
        Limits {
            max_items: 8,
            max_bytes: 4096,
        }
    }

    #[test]
    fn file_store_retains_items_across_reopen() {
        let path = home();
        {
            let mut store = FileStore::create_new(&path, namespace(), file_limits()).unwrap();
            assert!(
                !store
                    .put(item(1, OutboxKind::Application))
                    .unwrap()
                    .duplicate
            );
            assert!(
                !store
                    .put(item(2, OutboxKind::ContactRequest))
                    .unwrap()
                    .duplicate
            );
        }
        let store = FileStore::open(&path, namespace()).unwrap();
        assert_eq!(store.namespace(), namespace());
        let page = store.page(0, MAX_RELAY_PAGE).unwrap();
        assert_eq!(page.head, 2);
        assert_eq!(page.next, None);
        assert_eq!(
            page.records,
            vec![
                positioned(1, item(1, OutboxKind::Application)),
                positioned(2, item(2, OutboxKind::ContactRequest))
            ]
        );
        let page = store.page(1, 1).unwrap();
        assert_eq!(
            page.records,
            vec![positioned(2, item(2, OutboxKind::ContactRequest))]
        );
        assert_eq!(page.next, None);
        std::fs::remove_dir_all(&path).unwrap();
    }

    #[test]
    fn file_store_refuses_existing_path_foreign_namespace_and_second_handle() {
        let path = home();
        let mut store = FileStore::create_new(&path, namespace(), file_limits()).unwrap();
        assert_eq!(
            FileStore::create_new(&path, namespace(), file_limits()).map(|_| ()),
            Err(Error::Storage)
        );
        let other = RelayNamespace::from_bytes([8; 32]).unwrap();
        assert_eq!(
            FileStore::open(&path, other).map(|_| ()),
            Err(Error::Storage)
        );
        assert_eq!(
            FileStore::open(&path, namespace()).map(|_| ()),
            Err(Error::Storage)
        );
        assert_eq!(
            store.put(
                RelayItem::new(other, 1, operation(1), OutboxKind::Application, b"x").unwrap()
            ),
            Err(Error::Scope)
        );
        drop(store);
        assert_eq!(FileStore::open(&path, other).map(|_| ()), Err(Error::Scope));
        let reopened = FileStore::open(&path, namespace()).unwrap();
        assert_eq!(
            FileStore::open(&path, namespace()).map(|_| ()),
            Err(Error::Storage)
        );
        drop(reopened);
        std::fs::remove_dir_all(&path).unwrap();
    }

    #[test]
    fn file_store_retries_are_idempotent_and_capacity_never_prunes() {
        let path = home();
        let mut store = FileStore::create_new(
            &path,
            namespace(),
            Limits {
                max_items: 1,
                max_bytes: 128,
            },
        )
        .unwrap();
        let first = item(1, OutboxKind::Application);
        assert!(!store.put(first.clone()).unwrap().duplicate);
        assert!(store.put(first.clone()).unwrap().duplicate);
        assert_eq!(
            store.put(item(2, OutboxKind::Application)),
            Err(Error::Capacity)
        );
        let moved = RelayItem::new(
            namespace(),
            2,
            first.operation(),
            OutboxKind::Application,
            b"different-ciphertext",
        )
        .unwrap();
        assert_eq!(store.put(moved), Err(Error::Conflict));
        drop(store);
        let store = FileStore::open(&path, namespace()).unwrap();
        let page = store.page(0, MAX_RELAY_PAGE).unwrap();
        assert_eq!(page.records, vec![positioned(1, first)]);
        std::fs::remove_dir_all(&path).unwrap();
    }

    #[test]
    fn file_store_refuses_a_v1_sequence_keyed_database() {
        // A v1 mailbox keyed items by sender sequence and has no format column;
        // opening must refuse rather than reinterpret or migrate it.
        let path = home();
        custody::create_private_directory(&path).unwrap();
        custody::create_private_file(&path.join("lock")).unwrap();
        let conn = Connection::open(path.join("relay.db")).unwrap();
        conn.execute_batch(
            "CREATE TABLE meta (id INTEGER PRIMARY KEY CHECK (id = 1), namespace BLOB NOT NULL, max_items INTEGER NOT NULL, max_bytes INTEGER NOT NULL);
             CREATE TABLE items (sequence BLOB PRIMARY KEY, operation BLOB NOT NULL UNIQUE, kind INTEGER NOT NULL, payload BLOB NOT NULL, digest BLOB NOT NULL);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO meta VALUES (1, ?1, 8, 4096)",
            params![namespace().as_bytes().as_slice()],
        )
        .unwrap();
        drop(conn);
        assert!(FileStore::open(&path, namespace()).is_err());
        std::fs::remove_dir_all(&path).unwrap();
    }
}
