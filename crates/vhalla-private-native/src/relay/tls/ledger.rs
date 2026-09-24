//! Cumulative credential accounting across an explicitly fenced predecessor.
use super::{NetError, Result, Service};
use crate::relay::{Error, FileStore, GenerationFence, Limits, MAX_RELAY_ITEMS};
use rusqlite::params;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Additional finite retained-ciphertext authority explicitly selected by the
/// operator. Omitted credential IDs receive no increase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialAllowance {
    /// Existing opaque credential identity, never a room/member identity.
    pub id: [u8; 16],
    /// Additional cumulative item allowance.
    pub additional_items: u64,
    /// Additional cumulative payload-byte allowance.
    pub additional_bytes: u64,
}

/// Checked cumulative spend for one stable identity, including inactive keys.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialSpend {
    id: [u8; 16],
    limits: Limits,
    spent_items: u64,
    spent_bytes: u64,
    authorized_items: u64,
    authorized_bytes: u64,
}
impl CredentialSpend {
    /// Stable opaque credential identity.
    pub fn id(&self) -> [u8; 16] {
        self.id
    }
    /// Immutable maximum retained in any single generation.
    pub fn limits(&self) -> Limits {
        self.limits
    }
    /// Retained item charges across this generation and all predecessors.
    pub fn spent_items(&self) -> u64 {
        self.spent_items
    }
    /// Retained payload-byte charges across all generations.
    pub fn spent_bytes(&self) -> u64 {
        self.spent_bytes
    }
    /// Total explicitly authorized item allowance.
    pub fn authorized_items(&self) -> u64 {
        self.authorized_items
    }
    /// Total explicitly authorized payload-byte allowance.
    pub fn authorized_bytes(&self) -> u64 {
        self.authorized_bytes
    }
}

/// Exact checked quota snapshot from a fenced predecessor. Obtain it again
/// from that store after interruption; arbitrary serialized input cannot mint it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FencedQuotaSnapshot {
    fence: GenerationFence,
    credentials: Vec<CredentialSpend>,
    lineage: [u8; 32],
}
impl FencedQuotaSnapshot {
    /// Exact fence whose retained items supplied this ledger.
    pub fn fence(&self) -> GenerationFence {
        self.fence
    }
    /// All retained identities in ascending order, including revoked keys.
    pub fn credentials(&self) -> &[CredentialSpend] {
        &self.credentials
    }
    /// Commitment to the fence, ancestry and every identity's caps and spend.
    pub fn commitment(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"vhalla/private/relay-fenced-quota/v1\0");
        hash.update(self.fence.commitment());
        hash.update(self.lineage);
        hash.update((self.credentials.len() as u64).to_be_bytes());
        for c in &self.credentials {
            hash.update(c.id);
            for n in [
                c.limits.max_items as u64,
                c.limits.max_bytes as u64,
                c.spent_items,
                c.spent_bytes,
                c.authorized_items,
                c.authorized_bytes,
            ] {
                hash.update(n.to_be_bytes());
            }
        }
        hash.finalize().into()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Entry {
    id: [u8; 16],
    limits: Limits,
    prior_items: u64,
    prior_bytes: u64,
    authorized_items: u64,
    authorized_bytes: u64,
    current_items: u64,
    current_bytes: u64,
    seeded: bool,
}
impl Entry {
    fn spend(&self) -> Result<CredentialSpend> {
        Ok(CredentialSpend {
            id: self.id,
            limits: self.limits,
            spent_items: self
                .prior_items
                .checked_add(self.current_items)
                .ok_or(NetError::Unavailable)?,
            spent_bytes: self
                .prior_bytes
                .checked_add(self.current_bytes)
                .ok_or(NetError::Unavailable)?,
            authorized_items: self.authorized_items,
            authorized_bytes: self.authorized_bytes,
        })
    }
}

const TABLES: &str = "
 CREATE TABLE tls_budget (key_id BLOB PRIMARY KEY REFERENCES tls_keys(id), prior_items INTEGER NOT NULL CHECK(prior_items>=0), prior_bytes INTEGER NOT NULL CHECK(prior_bytes>=0), authorized_items INTEGER NOT NULL CHECK(authorized_items>=0), authorized_bytes INTEGER NOT NULL CHECK(authorized_bytes>=0), seeded INTEGER NOT NULL CHECK(seeded IN (0,1)));
 CREATE TABLE tls_generation (id INTEGER PRIMARY KEY CHECK(id=1), source_snapshot BLOB NOT NULL CHECK(length(source_snapshot)=32), source_fence BLOB NOT NULL CHECK(length(source_fence)=32), seed BLOB NOT NULL CHECK(length(seed)=32));";

fn storage(_: rusqlite::Error) -> NetError {
    NetError::Unavailable
}
fn relay(error: Error) -> NetError {
    match error {
        Error::Bounds | Error::Confidential => NetError::Bounds,
        Error::Scope => NetError::Scope,
        Error::Conflict => NetError::Conflict,
        Error::Capacity => NetError::Capacity,
        Error::Storage => NetError::Unavailable,
    }
}
fn integer(n: i64) -> Result<u64> {
    u64::try_from(n).map_err(|_| NetError::Unavailable)
}

fn seed_commitment(
    store: &FileStore,
    snapshot: [u8; 32],
    fence: [u8; 32],
    entries: &[Entry],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"vhalla/private/relay-successor-quota/v1\0");
    hash.update(store.namespace().as_bytes());
    hash.update(snapshot);
    hash.update(fence);
    hash.update((entries.iter().filter(|e| e.seeded).count() as u64).to_be_bytes());
    for e in entries.iter().filter(|e| e.seeded) {
        hash.update(e.id);
        for n in [
            e.limits.max_items as u64,
            e.limits.max_bytes as u64,
            e.prior_items,
            e.prior_bytes,
            e.authorized_items,
            e.authorized_bytes,
        ] {
            hash.update(n.to_be_bytes());
        }
    }
    hash.finalize().into()
}

/// Validate both the historic charge ledger and its optional cumulative basis.
fn read(store: &FileStore) -> Result<(u8, Vec<Entry>, [u8; 32])> {
    store.live().map_err(relay)?;
    let format: u8 = store
        .conn
        .query_row("SELECT format FROM tls_meta WHERE id=1", [], |r| r.get(0))
        .map_err(storage)?;
    if ![1, 2].contains(&format) || (format == 2 && store.format != 3) {
        return Err(NetError::Unavailable);
    }
    let bad: i64 = store.conn.query_row("SELECT (SELECT COUNT(*) FROM items LEFT JOIN tls_charges ON items.digest=tls_charges.digest WHERE tls_charges.digest IS NULL OR tls_charges.bytes != length(items.payload)) + (SELECT COUNT(*) FROM tls_charges LEFT JOIN items ON items.digest=tls_charges.digest WHERE items.digest IS NULL) + (SELECT COUNT(*) FROM tls_charges LEFT JOIN tls_keys ON tls_charges.key_id=tls_keys.id WHERE tls_keys.id IS NULL OR tls_charges.bytes<1)", [], |r| r.get(0)).map_err(storage)?;
    if bad != 0 {
        return Err(NetError::Unavailable);
    }
    let mut query = store.conn.prepare("SELECT k.id,k.max_items,k.max_bytes,(SELECT COUNT(*) FROM tls_charges c WHERE c.key_id=k.id),(SELECT COALESCE(SUM(bytes),0) FROM tls_charges c WHERE c.key_id=k.id) FROM tls_keys k ORDER BY k.id LIMIT 65").map_err(storage)?;
    let rows = query
        .query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
            ))
        })
        .map_err(storage)?;
    let mut entries = Vec::new();
    for row in rows {
        let (id, max_items, max_bytes, current_items, current_bytes) = row.map_err(storage)?;
        let id: [u8; 16] = id.try_into().map_err(|_| NetError::Unavailable)?;
        let limits = Limits {
            max_items: usize::try_from(max_items).map_err(|_| NetError::Unavailable)?,
            max_bytes: usize::try_from(max_bytes).map_err(|_| NetError::Unavailable)?,
        };
        if id == [0; 16]
            || limits.max_items == 0
            || limits.max_items > MAX_RELAY_ITEMS
            || limits.max_bytes == 0
        {
            return Err(NetError::Unavailable);
        }
        let (prior_items, prior_bytes, authorized_items, authorized_bytes, seeded) = if format == 2
        {
            store.conn.query_row("SELECT prior_items,prior_bytes,authorized_items,authorized_bytes,seeded FROM tls_budget WHERE key_id=?1", params![id.as_slice()], |r| Ok((r.get::<_,i64>(0)?,r.get::<_,i64>(1)?,r.get::<_,i64>(2)?,r.get::<_,i64>(3)?,r.get::<_,i64>(4)?))).map_err(storage)?
        } else {
            (0, 0, max_items, max_bytes, 0)
        };
        if ![0, 1].contains(&seeded) {
            return Err(NetError::Unavailable);
        }
        let entry = Entry {
            id,
            limits,
            prior_items: integer(prior_items)?,
            prior_bytes: integer(prior_bytes)?,
            authorized_items: integer(authorized_items)?,
            authorized_bytes: integer(authorized_bytes)?,
            current_items: integer(current_items)?,
            current_bytes: integer(current_bytes)?,
            seeded: seeded == 1,
        };
        let total = entry.spend()?;
        if entry.current_items > limits.max_items as u64
            || entry.current_bytes > limits.max_bytes as u64
            || total.spent_items > entry.authorized_items
            || total.spent_bytes > entry.authorized_bytes
            || (!entry.seeded
                && (entry.prior_items != 0
                    || entry.prior_bytes != 0
                    || entry.authorized_items != limits.max_items as u64
                    || entry.authorized_bytes != limits.max_bytes as u64))
        {
            return Err(NetError::Unavailable);
        }
        entries.push(entry);
    }
    if entries.len() > 64 {
        return Err(NetError::Unavailable);
    }
    if format == 1 {
        return Ok((format, entries, [0; 32]));
    }
    let count: i64 = store
        .conn
        .query_row("SELECT COUNT(*) FROM tls_budget", [], |r| r.get(0))
        .map_err(storage)?;
    if count != entries.len() as i64 {
        return Err(NetError::Unavailable);
    }
    let (snapshot, fence, seed): (Vec<u8>, Vec<u8>, Vec<u8>) = store
        .conn
        .query_row(
            "SELECT source_snapshot,source_fence,seed FROM tls_generation WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .map_err(storage)?;
    let snapshot: [u8; 32] = snapshot.try_into().map_err(|_| NetError::Unavailable)?;
    let fence: [u8; 32] = fence.try_into().map_err(|_| NetError::Unavailable)?;
    let seed: [u8; 32] = seed.try_into().map_err(|_| NetError::Unavailable)?;
    if seed == [0; 32] {
        if snapshot != [0; 32] || fence != [0; 32] || entries.iter().any(|e| e.seeded) {
            return Err(NetError::Unavailable);
        }
    } else if snapshot == [0; 32]
        || fence == [0; 32]
        || seed_commitment(store, snapshot, fence, &entries) != seed
    {
        return Err(NetError::Unavailable);
    }
    Ok((format, entries, seed))
}

pub(super) fn validate(store: &FileStore) -> Result<u8> {
    read(store).map(|(format, _, _)| format)
}

impl Service {
    /// Inspect all enrolled stable identities and cumulative spend without
    /// migration or enrollment. Host preflight uses this before any fence.
    pub fn credential_spend(store: &FileStore) -> Result<Vec<CredentialSpend>> {
        let (_, entries, _) = read(store)?;
        entries.iter().map(Entry::spend).collect()
    }

    /// Explicitly carry an existing TLS ledger into cumulative format 2. The
    /// mailbox must first have opted into generation format 3. Retained charges
    /// and existing immutable allowances are preserved, never inferred anew.
    pub fn upgrade_ledger(store: &mut FileStore) -> Result<()> {
        let (format, _, _) = read(store)?;
        if store.format != 3 {
            return Err(NetError::Bounds);
        }
        if format == 2 {
            return Ok(());
        }
        store.maintenance(|store| {
            store.conn.execute_batch(TABLES).map_err(|_| Error::Storage)?;
            store.conn.execute_batch("INSERT INTO tls_budget SELECT id,0,0,max_items,max_bytes,0 FROM tls_keys;
                INSERT INTO tls_generation VALUES(1,zeroblob(32),zeroblob(32),zeroblob(32));
                CREATE TABLE tls_meta_v2 (id INTEGER PRIMARY KEY CHECK(id=1),format INTEGER NOT NULL CHECK(format=2));
                INSERT INTO tls_meta_v2 VALUES(1,2);
                DROP TABLE tls_meta;
                ALTER TABLE tls_meta_v2 RENAME TO tls_meta;").map_err(|_| Error::Storage)
        }).map_err(relay)?;
        let result = validate(store).map(|_| ());
        if result.is_err() {
            store.needs_reopen = true;
        }
        result
    }

    /// Export all stable identity spend only after the old head is permanently
    /// fenced. Existing credential tokens may still perform PAGE and exact PUT.
    pub fn fenced_spend(store: &FileStore) -> Result<FencedQuotaSnapshot> {
        let fence = store
            .generation_fence()
            .map_err(relay)?
            .ok_or(NetError::Conflict)?;
        let (format, entries, lineage) = read(store)?;
        if format != 2 {
            return Err(NetError::Bounds);
        }
        let credentials = entries
            .iter()
            .map(Entry::spend)
            .collect::<Result<Vec<_>>>()?;
        Ok(FencedQuotaSnapshot {
            fence,
            credentials,
            lineage,
        })
    }

    /// Enroll a fresh successor with the exact predecessor's cumulative spend.
    /// Explicit additions increase only the named stable identities. Repeating
    /// this call checks its immutable seed even after new charges; it never
    /// clears a ledger or resets any allowance.
    pub fn initialize_successor(
        store: &mut FileStore,
        predecessor: &FencedQuotaSnapshot,
        allowances: &[CredentialAllowance],
    ) -> Result<()> {
        store.live().map_err(relay)?;
        if store.format != 3 || store.namespace() != predecessor.fence.successor() {
            return Err(NetError::Scope);
        }
        if allowances.len() > 64 {
            return Err(NetError::Bounds);
        }
        let mut additions = BTreeMap::new();
        for allowance in allowances {
            if allowance.id == [0; 16]
                || additions.insert(allowance.id, allowance).is_some()
                || !predecessor.credentials.iter().any(|c| c.id == allowance.id)
            {
                return Err(NetError::Bounds);
            }
        }
        let mut entries = Vec::new();
        for c in &predecessor.credentials {
            let addition = additions.get(&c.id);
            let authorized_items = c
                .authorized_items
                .checked_add(addition.map_or(0, |a| a.additional_items))
                .filter(|n| *n <= i64::MAX as u64)
                .ok_or(NetError::Bounds)?;
            let authorized_bytes = c
                .authorized_bytes
                .checked_add(addition.map_or(0, |a| a.additional_bytes))
                .filter(|n| *n <= i64::MAX as u64)
                .ok_or(NetError::Bounds)?;
            if c.limits.max_items > store.limits.max_items / 2
                || c.limits.max_bytes > store.limits.max_bytes / 2
            {
                return Err(NetError::Bounds);
            }
            entries.push(Entry {
                id: c.id,
                limits: c.limits,
                prior_items: c.spent_items,
                prior_bytes: c.spent_bytes,
                authorized_items,
                authorized_bytes,
                current_items: 0,
                current_bytes: 0,
                seeded: true,
            });
        }
        let snapshot = predecessor.commitment();
        let fence = predecessor.fence.commitment();
        let seed = seed_commitment(store, snapshot, fence, &entries);
        let existing: bool = store
            .conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='tls_meta')",
                [],
                |r| r.get(0),
            )
            .map_err(storage)?;
        if existing {
            let (format, _, actual) = read(store)?;
            return if format == 2 && actual == seed {
                Ok(())
            } else {
                Err(NetError::Conflict)
            };
        }
        if store.generation_fence().map_err(relay)?.is_some()
            || store.page(0, 1).map_err(relay)?.head != 0
        {
            return Err(NetError::Conflict);
        }
        store.maintenance(|store| {
            store.conn.execute_batch("CREATE TABLE tls_keys (id BLOB PRIMARY KEY CHECK(length(id)=16),max_items INTEGER NOT NULL,max_bytes INTEGER NOT NULL);
                CREATE TABLE tls_charges (digest BLOB PRIMARY KEY CHECK(length(digest)=32),key_id BLOB NOT NULL REFERENCES tls_keys(id),bytes INTEGER NOT NULL);
                CREATE INDEX tls_charges_by_key ON tls_charges(key_id);
                CREATE TABLE tls_meta (id INTEGER PRIMARY KEY CHECK(id=1),format INTEGER NOT NULL CHECK(format=2));
                INSERT INTO tls_meta VALUES(1,2);").map_err(|_| Error::Storage)?;
            store.conn.execute_batch(TABLES).map_err(|_| Error::Storage)?;
            for e in &entries {
                store.conn.execute("INSERT INTO tls_keys VALUES(?1,?2,?3)",params![e.id.as_slice(),e.limits.max_items as i64,e.limits.max_bytes as i64]).map_err(|_| Error::Storage)?;
                store.conn.execute("INSERT INTO tls_budget VALUES(?1,?2,?3,?4,?5,1)",params![e.id.as_slice(),e.prior_items as i64,e.prior_bytes as i64,e.authorized_items as i64,e.authorized_bytes as i64]).map_err(|_| Error::Storage)?;
            }
            store.conn.execute("INSERT INTO tls_generation VALUES(1,?1,?2,?3)",params![snapshot.as_slice(),fence.as_slice(),seed.as_slice()]).map_err(|_| Error::Storage)?;
            Ok(())
        }).map_err(relay)?;
        let result = validate(store).map(|_| ());
        if result.is_err() {
            store.needs_reopen = true;
        }
        result
    }
}

pub(super) fn charge(
    store: &FileStore,
    format: u8,
    id: [u8; 16],
    size: i64,
) -> std::result::Result<(), Error> {
    let (count,bytes,max_count,max_bytes): (i64,i64,i64,i64) = store.conn.query_row("SELECT (SELECT COUNT(*) FROM tls_charges WHERE key_id=?1),(SELECT COALESCE(SUM(bytes),0) FROM tls_charges WHERE key_id=?1),max_items,max_bytes FROM tls_keys WHERE id=?1", params![id.as_slice()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).map_err(|_| Error::Storage)?;
    if count >= max_count || bytes.checked_add(size).is_none_or(|n| n > max_bytes) {
        return Err(Error::Capacity);
    }
    if format == 2 {
        let (prior_items,prior_bytes,authorized_items,authorized_bytes): (i64,i64,i64,i64) = store.conn.query_row("SELECT prior_items,prior_bytes,authorized_items,authorized_bytes FROM tls_budget WHERE key_id=?1",params![id.as_slice()],|r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).map_err(|_| Error::Storage)?;
        if prior_items
            .checked_add(count)
            .and_then(|n| n.checked_add(1))
            .is_none_or(|n| n > authorized_items)
            || prior_bytes
                .checked_add(bytes)
                .and_then(|n| n.checked_add(size))
                .is_none_or(|n| n > authorized_bytes)
        {
            return Err(Error::Capacity);
        }
    }
    Ok(())
}
