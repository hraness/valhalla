//! Opaque native private-room transactions. No MLS, keys, plaintext or networking.
//!
//! The caller supplies encrypted images/records and authenticates them after
//! reloading. One SQLite transaction owns the current image and its durable key
//! index; an absent indexed key means never published under the cooperating-owner
//! contract. This does not detect valid hostile SQL edits, coherent rollback,
//! cloned custody or hardware that lies about sync. Open explicitly recovers;
//! load/read never repair. No complete-history scan or in-memory history map.

use rusqlite::{config::DbConfig, limits::Limit, params, types::ValueRef, Connection, OpenFlags};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use vhalla_custody::{self as custody, Owner};

/// Maximum encrypted whole-state image, including 40-byte AEAD overhead.
pub const MAX_IMAGE_BYTES: usize = 4 * 1024 * 1024 + 40;
/// Maximum encrypted immutable record accepted before copying.
pub const MAX_RECORD_BYTES: usize = 2 * 128 * 1024 + 4096 + 40;
/// Maximum atomic image-associated immutable records, including owner control.
pub const MAX_TRANSACTION_RECORDS: usize = 3;
const DB: &str = "private.sqlite";
const JOURNAL: &str = "private.sqlite-journal";
const FORMAT_MAGIC: &[u8; 8] = b"VHPNS001";
const FORMAT_BYTES: usize = 8 + 128 + 16 + 32;
const APPLICATION_ID: i64 = 0x56485052;
mod generation;
const META_SQL: &str = "CREATE TABLE meta (id INTEGER PRIMARY KEY CHECK(id=1), context BLOB NOT NULL CHECK(length(context)=128), generation INTEGER NOT NULL CHECK(generation>=0), records INTEGER NOT NULL CHECK(records>=0), bytes INTEGER NOT NULL CHECK(bytes>=0), image BLOB CHECK(image IS NULL OR length(image) BETWEEN 40 AND 4194344), digest BLOB NOT NULL CHECK(length(digest)=32)) STRICT";
const RECORD_SQL: &str = "CREATE TABLE records (key BLOB PRIMARY KEY NOT NULL CHECK(length(key) IN (9,17,33)), data BLOB NOT NULL CHECK(length(data) BETWEEN 40 AND 266280), digest BLOB NOT NULL CHECK(length(digest)=32)) WITHOUT ROWID, STRICT";

/// Persistence outcome; uncertainty never grants permission to initialize again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Exact image/immutable-key comparison refused without effects.
    Conflict,
    /// Input, custody lock or capacity refused without publication.
    Refused,
    /// Effects may have committed; explicitly reopen the same store.
    Uncertain,
    /// Damaged, foreign or missing required state; preserve all evidence.
    Corrupt,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;

/// Exact private custody namespace, never a public route or authorization claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Context([u8; 128]);
impl Context {
    /// Construct a full nonzero namespace; cryptographic key validation is external.
    pub fn new(
        room: [u8; 32],
        anchor: [u8; 32],
        account: [u8; 32],
        device: [u8; 32],
    ) -> Result<Self> {
        if [room, anchor, account, device].contains(&[0; 32]) {
            return Err(Error::Refused);
        }
        let mut out = [0; 128];
        for (chunk, field) in out
            .as_chunks_mut::<32>()
            .0
            .iter_mut()
            .zip([room, anchor, account, device])
        {
            chunk.copy_from_slice(&field);
        }
        Ok(Self(out))
    }
    /// Borrow all four canonical full 32-byte fields.
    pub fn as_bytes(&self) -> &[u8; 128] {
        &self.0
    }
}

/// Immutable local retained-data ceilings; reaching them never prunes history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Retained immutable records, from 1 through 1,000,000.
    pub max_records: u64,
    /// Sum of encrypted record payload bytes, at most 8 GiB; database overhead is additional.
    pub max_record_bytes: u64,
}
impl Limits {
    fn check(self) -> Result<()> {
        if self.max_records == 0
            || self.max_records > 1_000_000
            || self.max_record_bytes < 40
            || self.max_record_bytes > 8 * 1024 * 1024 * 1024
        {
            return Err(Error::Refused);
        }
        if usize::try_from(2 * self.max_record_bytes + self.max_records * 512 + 64 * 1024 * 1024)
            .is_err()
        {
            return Err(Error::Refused);
        }
        Ok(())
    }
    // Includes conservative database/index/free-page overhead, not just payload.
    fn database_bytes(self) -> usize {
        (2 * self.max_record_bytes + self.max_records * 512 + 64 * 1024 * 1024) as usize
    }
}

/// Closed durable index key; no untrusted pathname is accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordKey {
    /// Nonzero local outbox position.
    Outbox(u64),
    /// Nonzero local inbox position.
    Inbox(u64),
    /// Full nonzero caller operation ID.
    Operation([u8; 16]),
    /// Full nonzero received-wire digest.
    Received([u8; 32]),
    /// Nonzero immutable owner control-history sequence.
    Control(u64),
    /// Full nonzero committed application ciphertext hash to its outbox index.
    Sent([u8; 32]),
    /// Verified member receipt for one exact outbox position and recipient
    /// device; the payload is the receipt's nonzero inbox index.
    Acceptance {
        /// Committed local outbox position the receipt acknowledges.
        outbox: u64,
        /// Member device that produced the verified receipt.
        recipient: [u8; 32],
    },
}
impl RecordKey {
    fn encode(self) -> Result<Vec<u8>> {
        let (tag, rest) = match self {
            Self::Outbox(n) | Self::Inbox(n) | Self::Control(n) if n == 0 => {
                return Err(Error::Refused);
            }
            Self::Outbox(n) => (1, n.to_be_bytes().to_vec()),
            Self::Inbox(n) => (2, n.to_be_bytes().to_vec()),
            Self::Control(n) => (5, n.to_be_bytes().to_vec()),
            Self::Operation(id) if id != [0; 16] => (3, id.to_vec()),
            Self::Received(hash) if hash != [0; 32] => (4, hash.to_vec()),
            Self::Sent(hash) if hash != [0; 32] => (6, hash.to_vec()),
            Self::Acceptance { outbox, recipient } if outbox != 0 && recipient != [0; 32] => {
                // The records table admits only 9/17/33-byte keys, so the pair
                // is committed under one domain-separated 32-byte digest.
                (
                    7,
                    digest(
                        b"vhalla/private-native/acceptance-key/v1",
                        &[&outbox.to_be_bytes(), &recipient],
                    )
                    .to_vec(),
                )
            }
            _ => return Err(Error::Refused),
        };
        let mut raw = vec![tag];
        raw.extend(rest);
        Ok(raw)
    }
}
/// One bounded opaque encrypted immutable record.
#[derive(Clone, Eq, PartialEq)]
pub struct Record {
    key: RecordKey,
    bytes: Vec<u8>,
}
impl Record {
    /// Check key/byte bounds before copying; authentication belongs to the kernel.
    pub fn new(key: RecordKey, encrypted: &[u8]) -> Result<Self> {
        key.encode()?;
        bounds(encrypted, MAX_RECORD_BYTES)?;
        Ok(Self {
            key,
            bytes: encrypted.to_vec(),
        })
    }
    /// Exact immutable index key.
    pub fn key(&self) -> RecordKey {
        self.key
    }
    /// Borrow only the encrypted stored bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

struct Meta {
    generation: u64,
    records: u64,
    bytes: u64,
    image: Option<Vec<u8>>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Point {
    Begun,
    RecordInserted,
    StateUpdated,
    Committed,
    Checked,
}

/// Atomic image and accounting snapshot for explicit bounded archive work.
/// It grants no decryption, completeness or live-restore authority.
pub struct Accounting {
    /// Exact opaque current image.
    pub image: Option<Vec<u8>>,
    /// Retained immutable-record count.
    pub records: u64,
    /// Exact sum of encrypted record payload lengths.
    pub bytes: u64,
    /// Immutable operator-selected capacity.
    pub limits: Limits,
}

/// One exclusive native backend. Reopen is required after uncertain I/O.
pub struct NativePrivateStore {
    conn: Connection,
    path: PathBuf,
    directory: File,
    db_guard: File,
    _lock: File,
    owner: Owner,
    context: Context,
    limits: Limits,
    poisoned: bool,
    #[cfg(test)]
    fault: Option<Point>,
    #[cfg(test)]
    crash: Option<(Point, PathBuf)>,
}
impl NativePrivateStore {
    /// Never-existing directory only. Failure preserves partial initialization;
    /// no existing FORMAT/database is silently treated as a fresh namespace.
    pub fn create_new(path: impl AsRef<Path>, context: Context, limits: Limits) -> Result<Self> {
        limits.check()?;
        let path = resolved_parent(path.as_ref()).map_err(|_| Error::Refused)?;
        let (directory, owner) =
            custody::create_private_directory(&path).map_err(|_| Error::Refused)?;
        // Once the directory exists, initialization errors are uncertain. It may
        // not be reused/reset; open either validates the complete store or refuses.
        let create = || -> Result<Self> {
            let lock =
                custody::create_private_file(&path.join("lock")).map_err(|_| Error::Uncertain)?;
            custody::acquire_exclusive(&lock).map_err(|_| Error::Uncertain)?;
            lock.sync_all().map_err(|_| Error::Uncertain)?;
            let mut marker = custody::create_private_file(&path.join("FORMAT.tmp"))
                .map_err(|_| Error::Uncertain)?;
            marker
                .write_all(&format(context, limits))
                .and_then(|_| marker.sync_all())
                .map_err(|_| Error::Uncertain)?;
            directory.sync_all().map_err(|_| Error::Uncertain)?;
            let db_guard =
                custody::create_private_file(&path.join(DB)).map_err(|_| Error::Uncertain)?;
            let conn = connect(&path, limits).map_err(|_| Error::Uncertain)?;
            configure(&conn, limits).map_err(|_| Error::Uncertain)?;
            conn.execute_batch("PRAGMA page_size=4096; BEGIN IMMEDIATE")
                .map_err(|_| Error::Uncertain)?;
            conn.execute_batch(META_SQL)
                .and_then(|_| conn.execute_batch(RECORD_SQL))
                .map_err(|_| Error::Uncertain)?;
            conn.pragma_update(None, "application_id", APPLICATION_ID)
                .and_then(|_| conn.pragma_update(None, "user_version", 1))
                .map_err(|_| Error::Uncertain)?;
            let initial = Meta {
                generation: 0,
                records: 0,
                bytes: 0,
                image: None,
            };
            conn.execute(
                "INSERT INTO meta VALUES (1,?1,0,0,0,NULL,?2)",
                params![
                    context.0.as_slice(),
                    meta_digest(context, &initial).as_slice()
                ],
            )
            .map_err(|_| Error::Uncertain)?;
            conn.execute_batch("COMMIT").map_err(|_| Error::Uncertain)?;
            db_guard
                .sync_all()
                .and_then(|_| directory.sync_all())
                .map_err(|_| Error::Uncertain)?;
            fs::rename(path.join("FORMAT.tmp"), path.join("FORMAT"))
                .map_err(|_| Error::Uncertain)?;
            directory.sync_all().map_err(|_| Error::Uncertain)?;
            File::open(path.parent().ok_or(Error::Uncertain)?)
                .and_then(|f| f.sync_all())
                .map_err(|_| Error::Uncertain)?;
            let mut out = Self {
                conn,
                path: path.clone(),
                directory,
                db_guard,
                _lock: lock,
                owner,
                context,
                limits,
                poisoned: true,
                #[cfg(test)]
                fault: None,
                #[cfg(test)]
                crash: None,
            };
            out.validate().map_err(|_| Error::Uncertain)?;
            out.poisoned = false;
            Ok(out)
        };
        create()
    }

    /// Read the bounded full-context locator from existing owner-private FORMAT.
    /// This checksum is NOT authentication or membership evidence. The caller must
    /// pin the selected account and authenticate the complete image through the
    /// kernel before exposing room data or performing an action. This method
    /// opens no database, takes no writer lock, repairs nothing and never creates.
    /// Missing, partial and foreign markers remain intact and are refused.
    pub fn locate_context(path: impl AsRef<Path>) -> Result<Context> {
        let path = resolved_parent(path.as_ref()).map_err(|_| Error::Corrupt)?;
        let (_directory, owner) =
            custody::open_private_directory(&path).map_err(|_| Error::Corrupt)?;
        let raw = custody::read_private_file(&path.join("FORMAT"), owner, FORMAT_BYTES)
            .map_err(|_| Error::Corrupt)?;
        if raw.len() != FORMAT_BYTES {
            return Err(Error::Corrupt);
        }
        let field = |start: usize| {
            raw[start..start + 32]
                .try_into()
                .map_err(|_| Error::Corrupt)
        };
        let context = Context::new(field(8)?, field(40)?, field(72)?, field(104)?)
            .map_err(|_| Error::Corrupt)?;
        parse_format(&raw, context)?;
        Ok(context)
    }

    /// Explicit writer recovery. Exact external context and immutable FORMAT are
    /// checked before SQLite can recover its rollback journal. No CREATE flag.
    pub fn open(path: impl AsRef<Path>, expected: Context) -> Result<Self> {
        let path = resolved_parent(path.as_ref()).map_err(|_| Error::Corrupt)?;
        let (directory, owner) =
            custody::open_private_directory(&path).map_err(|_| Error::Corrupt)?;
        let lock =
            custody::open_private_file(&path.join("lock"), owner, 0).map_err(|_| Error::Corrupt)?;
        custody::acquire_exclusive(&lock).map_err(|_| Error::Refused)?;
        let raw = custody::read_private_file(&path.join("FORMAT"), owner, FORMAT_BYTES)
            .map_err(|_| Error::Corrupt)?;
        let limits = parse_format(&raw, expected)?;
        inventory(&path, owner, limits)?;
        let db_guard = custody::open_private_file(&path.join(DB), owner, limits.database_bytes())
            .map_err(|_| Error::Corrupt)?;
        if db_guard.metadata().map_err(|_| Error::Corrupt)?.len() < 4096 {
            return Err(Error::Corrupt);
        }
        let mut header = [0; 100];
        db_guard
            .try_clone()
            .and_then(|mut file| file.read_exact(&mut header))
            .map_err(|_| Error::Corrupt)?;
        // This format uses rollback journals only. Reject WAL/foreign databases
        // before SQLite can create auxiliary files or recover them.
        if &header[..16] != b"SQLite format 3\0" || header[18] != 1 || header[19] != 1 {
            return Err(Error::Corrupt);
        }
        let conn = connect(&path, limits)?;
        configure(&conn, limits)?;
        let mut out = Self {
            conn,
            path,
            directory,
            db_guard,
            _lock: lock,
            owner,
            context: expected,
            limits,
            poisoned: true,
            #[cfg(test)]
            fault: None,
            #[cfg(test)]
            crash: None,
        };
        out.validate()?;
        // Reassert completed recovery/previous commit before publishing a usable
        // handle, including a prior COMMIT whose post-transaction state this
        // caller could not observe. This is the one code-level re-sync the store
        // keeps: it runs once per open, never per publish.
        out.sync().map_err(|_| Error::Uncertain)?;
        out.poisoned = false;
        Ok(out)
    }

    /// Read the current opaque image without recovery; None means the unused state.
    pub fn load(&mut self, context: Context) -> Result<Option<Vec<u8>>> {
        self.ready(context)?;
        let result = self
            .check_files()
            .and_then(|_| self.meta())
            .map(|m| m.image);
        self.finish_read(result)
    }
    /// Read image, counters and configured budgets under this exclusive owner.
    /// No repair, history enumeration, or new database transaction occurs.
    pub fn accounting(&mut self, context: Context) -> Result<Accounting> {
        self.ready(context)?;
        let result = self
            .check_files()
            .and_then(|_| self.meta())
            .map(|m| Accounting {
                image: m.image,
                records: m.records,
                bytes: m.bytes,
                limits: self.limits,
            });
        self.finish_read(result)
    }
    /// Read one indexed immutable record without recovery or a history scan.
    pub fn read(&mut self, context: Context, key: RecordKey) -> Result<Option<Vec<u8>>> {
        self.ready(context)?;
        let key = key.encode()?;
        let result = self.check_files().and_then(|_| self.record(&key));
        self.finish_read(result)
    }

    /// Exact encrypted image CAS and at most three immutable records. Semantic
    /// conflict/refusal rolls back without effects; any uncertain transaction or
    /// post-COMMIT failure poisons this handle. Success includes readback; the
    /// transaction's own `synchronous=EXTRA` + `fullfsync=ON` barriers inside
    /// COMMIT (journal, database pages and the journal-unlink directory sync,
    /// each an `F_FULLFSYNC`) already made every byte this commit wrote durable,
    /// so no code-level device sync follows COMMIT.
    pub fn publish(
        &mut self,
        context: Context,
        expected: Option<&[u8]>,
        next: &[u8],
        records: &[Record],
    ) -> Result<()> {
        self.ready(context)?;
        if self.delivery_is_paused()? {
            return Err(Error::Refused);
        }
        bounds(next, MAX_IMAGE_BYTES)?;
        if let Some(raw) = expected {
            bounds(raw, MAX_IMAGE_BYTES)?;
        }
        if records.len() > MAX_TRANSACTION_RECORDS
            || records
                .iter()
                .enumerate()
                .any(|(i, record)| records[i + 1..].iter().any(|other| other.key == record.key))
        {
            return Err(Error::Refused);
        }
        for record in records {
            record.key.encode()?;
            bounds(&record.bytes, MAX_RECORD_BYTES)?;
        }
        self.check_files().inspect_err(|_| {
            self.poisoned = true;
        })?;
        self.poisoned = true;
        self.conn
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|_| Error::Uncertain)?;
        self.hit(Point::Begun)?;
        let prepared = self.prepare(expected, next, records);
        let (after, new) = match prepared {
            Ok(value) => value,
            Err(error) => {
                if self.conn.execute_batch("ROLLBACK").is_err() || !self.conn.is_autocommit() {
                    return Err(Error::Uncertain);
                }
                if matches!(error, Error::Conflict | Error::Refused) {
                    self.poisoned = false;
                }
                return Err(error);
            }
        };
        for record in new {
            let key = record.key.encode().map_err(|_| Error::Uncertain)?;
            self.conn
                .execute(
                    "INSERT INTO records(key,data,digest) VALUES (?1,?2,?3)",
                    params![
                        key,
                        record.bytes,
                        record_digest(context, &key, &record.bytes).as_slice()
                    ],
                )
                .map_err(|_| Error::Uncertain)?;
            self.hit(Point::RecordInserted)?;
        }
        let changed = self
            .conn
            .execute(
                "UPDATE meta SET generation=?1,records=?2,bytes=?3,image=?4,digest=?5 WHERE id=1",
                params![
                    after.generation as i64,
                    after.records as i64,
                    after.bytes as i64,
                    next,
                    meta_digest(context, &after).as_slice()
                ],
            )
            .map_err(|_| Error::Uncertain)?;
        if changed != 1 {
            return Err(Error::Uncertain);
        }
        self.hit(Point::StateUpdated)?;
        self.conn
            .execute_batch("COMMIT")
            .map_err(|_| Error::Uncertain)?;
        self.hit(Point::Committed)?;
        // COMMIT already issued every F_FULLFSYNC this transaction needs under
        // EXTRA + fullfsync (verified in `configure`); the removed code-level
        // `db_guard`/`directory` syncs repeated the same inode and directory.
        // Custody is still reasserted and the committed state is read back.
        self.check_files().map_err(|_| Error::Uncertain)?;
        self.hit(Point::Checked)?;
        if self.meta().map_err(|_| Error::Uncertain)?.image.as_deref() != Some(next) {
            return Err(Error::Uncertain);
        }
        for record in records {
            if self
                .record(&record.key.encode()?)
                .map_err(|_| Error::Uncertain)?
                .as_deref()
                != Some(record.as_bytes())
            {
                return Err(Error::Uncertain);
            }
        }
        self.poisoned = false;
        Ok(())
    }

    fn ready(&self, context: Context) -> Result<()> {
        if self.poisoned {
            Err(Error::Uncertain)
        } else if context != self.context {
            Err(Error::Refused)
        } else {
            Ok(())
        }
    }
    fn finish_read<T>(&mut self, value: Result<T>) -> Result<T> {
        if value.is_err() {
            self.poisoned = true;
        }
        value
    }
    fn check_files(&self) -> Result<()> {
        inventory(&self.path, self.owner, self.limits)?;
        let current = custody::open_private_file(
            &self.path.join(DB),
            self.owner,
            self.limits.database_bytes(),
        )
        .map_err(|_| Error::Corrupt)?;
        if !custody::same_open_file(&current, &self.db_guard).map_err(|_| Error::Corrupt)? {
            return Err(Error::Corrupt);
        }
        if custody::read_private_file(&self.path.join("FORMAT"), self.owner, FORMAT_BYTES)
            .map_err(|_| Error::Corrupt)?
            != format(self.context, self.limits)
        {
            return Err(Error::Corrupt);
        }
        Ok(())
    }
    fn sync(&self) -> Result<()> {
        self.check_files()?;
        self.db_guard
            .sync_all()
            .and_then(|_| self.directory.sync_all())
            .map_err(|_| Error::Uncertain)
    }
    fn validate(&mut self) -> Result<()> {
        self.check_files()?;
        for (name, expected) in [
            ("application_id", APPLICATION_ID),
            ("user_version", 1),
            ("page_size", 4096),
        ] {
            let actual: i64 = self
                .conn
                .pragma_query_value(None, name, |row| row.get(0))
                .map_err(|_| Error::Corrupt)?;
            if actual != expected {
                return Err(Error::Corrupt);
            }
        }
        let mut stmt = self
            .conn
            .prepare("SELECT type,name,sql FROM sqlite_schema ORDER BY name LIMIT 3")
            .map_err(|_| Error::Corrupt)?;
        let mut rows = stmt.query([]).map_err(|_| Error::Corrupt)?;
        for (name, sql) in [("meta", META_SQL), ("records", RECORD_SQL)] {
            let row = rows
                .next()
                .map_err(|_| Error::Corrupt)?
                .ok_or(Error::Corrupt)?;
            if row.get_ref(0).map_err(|_| Error::Corrupt)? != ValueRef::Text(b"table")
                || row.get_ref(1).map_err(|_| Error::Corrupt)? != ValueRef::Text(name.as_bytes())
                || row.get_ref(2).map_err(|_| Error::Corrupt)? != ValueRef::Text(sql.as_bytes())
            {
                return Err(Error::Corrupt);
            }
        }
        if rows.next().map_err(|_| Error::Corrupt)?.is_some() {
            return Err(Error::Corrupt);
        }
        self.meta()?;
        Ok(())
    }
    fn meta(&self) -> Result<Meta> {
        let mut stmt = self.conn.prepare("SELECT id,context,generation,records,bytes,length(image),CASE WHEN length(image) BETWEEN 40 AND 4194344 THEN image END,digest FROM meta LIMIT 2").map_err(|_| Error::Corrupt)?;
        let mut rows = stmt.query([]).map_err(|_| Error::Corrupt)?;
        let row = rows
            .next()
            .map_err(|_| Error::Corrupt)?
            .ok_or(Error::Corrupt)?;
        if row.get::<_, i64>(0).map_err(|_| Error::Corrupt)? != 1
            || row.get_ref(1).map_err(|_| Error::Corrupt)? != ValueRef::Blob(&self.context.0)
        {
            return Err(Error::Corrupt);
        }
        let generation = integer(row, 2)?;
        let records = integer(row, 3)?;
        let bytes = integer(row, 4)?;
        let length: Option<i64> = row.get(5).map_err(|_| Error::Corrupt)?;
        let image = match length {
            None if generation == 0 && records == 0 && bytes == 0 => None,
            Some(len) if generation > 0 && (40..=MAX_IMAGE_BYTES as i64).contains(&len) => {
                Some(blob(row, 6, len as usize)?.to_vec())
            }
            _ => return Err(Error::Corrupt),
        };
        let result = Meta {
            generation,
            records,
            bytes,
            image,
        };
        if records > self.limits.max_records
            || bytes > self.limits.max_record_bytes
            || (records == 0) != (bytes == 0)
            || row.get_ref(7).map_err(|_| Error::Corrupt)?
                != ValueRef::Blob(&meta_digest(self.context, &result))
        {
            return Err(Error::Corrupt);
        }
        if rows.next().map_err(|_| Error::Corrupt)?.is_some() {
            return Err(Error::Corrupt);
        }
        if result.image.is_none()
            && self
                .conn
                .query_row("SELECT EXISTS(SELECT 1 FROM records LIMIT 1)", [], |r| {
                    r.get::<_, bool>(0)
                })
                .map_err(|_| Error::Corrupt)?
        {
            return Err(Error::Corrupt);
        }
        Ok(result)
    }
    fn record(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut stmt = self.conn.prepare("SELECT length(data),CASE WHEN length(data) BETWEEN 40 AND 266280 THEN data END,digest FROM records WHERE key=?1").map_err(|_| Error::Corrupt)?;
        let mut rows = stmt.query([key]).map_err(|_| Error::Corrupt)?;
        let Some(row) = rows.next().map_err(|_| Error::Corrupt)? else {
            return Ok(None);
        };
        let len = integer(row, 0)?;
        if !(40..=MAX_RECORD_BYTES as u64).contains(&len) {
            return Err(Error::Corrupt);
        }
        let data = blob(row, 1, len as usize)?;
        if row.get_ref(2).map_err(|_| Error::Corrupt)?
            != ValueRef::Blob(&record_digest(self.context, key, data))
        {
            return Err(Error::Corrupt);
        }
        Ok(Some(data.to_vec()))
    }
    fn prepare<'a>(
        &self,
        expected: Option<&[u8]>,
        next: &[u8],
        records: &'a [Record],
    ) -> Result<(Meta, Vec<&'a Record>)> {
        let mut after = self.meta()?;
        if after.image.as_deref() != expected {
            return Err(Error::Conflict);
        }
        let mut new = Vec::with_capacity(MAX_TRANSACTION_RECORDS);
        for record in records {
            match self.record(&record.key.encode()?)? {
                Some(_) => return Err(Error::Conflict),
                None => {
                    new.push(record);
                    after.records = after.records.checked_add(1).ok_or(Error::Refused)?;
                    after.bytes = after
                        .bytes
                        .checked_add(record.bytes.len() as u64)
                        .ok_or(Error::Refused)?;
                }
            }
        }
        if after.records > self.limits.max_records || after.bytes > self.limits.max_record_bytes {
            return Err(Error::Refused);
        }
        after.generation = after
            .generation
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or(Error::Refused)?;
        after.image = Some(next.to_vec());
        Ok((after, new))
    }
    fn hit(&mut self, point: Point) -> Result<()> {
        #[cfg(test)]
        {
            if self.fault == Some(point) {
                self.fault = None;
                return Err(Error::Uncertain);
            }
            if let Some((at, ref marker)) = self.crash {
                if point == at {
                    let mut f = File::create(marker).map_err(|_| Error::Uncertain)?;
                    f.write_all(b"ready")
                        .and_then(|_| f.sync_all())
                        .map_err(|_| Error::Uncertain)?;
                    loop {
                        std::thread::park_timeout(std::time::Duration::from_secs(1));
                    }
                }
            }
        }
        let _ = point;
        Ok(())
    }
}

// Resolve only the selected existing parent, including macOS /var aliases.
// Never canonicalize the store leaf or database: their no-follow checks remain.
fn resolved_parent(path: &Path) -> std::io::Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("missing parent"))?
        .canonicalize()?;
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("missing store name"))?;
    Ok(parent.join(name))
}

fn bounds(raw: &[u8], max: usize) -> Result<()> {
    if !(40..=max).contains(&raw.len()) {
        Err(Error::Refused)
    } else {
        Ok(())
    }
}
fn integer(row: &rusqlite::Row<'_>, index: usize) -> Result<u64> {
    u64::try_from(row.get::<_, i64>(index).map_err(|_| Error::Corrupt)?).map_err(|_| Error::Corrupt)
}
fn blob<'a>(row: &'a rusqlite::Row<'_>, index: usize, len: usize) -> Result<&'a [u8]> {
    match row.get_ref(index).map_err(|_| Error::Corrupt)? {
        ValueRef::Blob(raw) if raw.len() == len => Ok(raw),
        _ => Err(Error::Corrupt),
    }
}
fn digest(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    for part in parts {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    hash.finalize().into()
}
fn meta_digest(context: Context, meta: &Meta) -> [u8; 32] {
    digest(
        b"vhalla/private-native/meta/v1",
        &[
            &context.0,
            &meta.generation.to_be_bytes(),
            &meta.records.to_be_bytes(),
            &meta.bytes.to_be_bytes(),
            meta.image.as_deref().unwrap_or(&[]),
        ],
    )
}
fn record_digest(context: Context, key: &[u8], bytes: &[u8]) -> [u8; 32] {
    digest(
        b"vhalla/private-native/record/v1",
        &[&context.0, key, bytes],
    )
}
fn format(context: Context, limits: Limits) -> Vec<u8> {
    let mut raw = FORMAT_MAGIC.to_vec();
    raw.extend(context.0);
    raw.extend(limits.max_records.to_be_bytes());
    raw.extend(limits.max_record_bytes.to_be_bytes());
    raw.extend(digest(b"vhalla/private-native/format/v1", &[&raw]));
    raw
}
fn parse_format(raw: &[u8], context: Context) -> Result<Limits> {
    if raw.len() != FORMAT_BYTES || raw[..8] != *FORMAT_MAGIC || raw[8..136] != context.0 {
        return Err(Error::Corrupt);
    }
    let limits = Limits {
        max_records: u64::from_be_bytes(raw[136..144].try_into().map_err(|_| Error::Corrupt)?),
        max_record_bytes: u64::from_be_bytes(raw[144..152].try_into().map_err(|_| Error::Corrupt)?),
    };
    limits.check().map_err(|_| Error::Corrupt)?;
    if format(context, limits) != raw {
        return Err(Error::Corrupt);
    }
    Ok(limits)
}
fn inventory(path: &Path, owner: Owner, limits: Limits) -> Result<()> {
    let mut count = 0;
    for entry in fs::read_dir(path).map_err(|_| Error::Corrupt)? {
        count += 1;
        if count > 5 {
            return Err(Error::Corrupt);
        }
        let entry = entry.map_err(|_| Error::Corrupt)?;
        let name = entry.file_name();
        let name = name.to_str().ok_or(Error::Corrupt)?;
        if name == "delivery-generations" {
            generation::inventory(&entry.path(), owner)?;
            continue;
        }
        let max = match name {
            "lock" => 0,
            "FORMAT" => FORMAT_BYTES,
            DB => limits.database_bytes(),
            JOURNAL => limits.database_bytes() + 32 * 1024 * 1024,
            _ => return Err(Error::Corrupt),
        };
        custody::open_private_file(&entry.path(), owner, max).map_err(|_| Error::Corrupt)?;
    }
    if count < 3 {
        return Err(Error::Corrupt);
    }
    Ok(())
}
fn connect(path: &Path, _limits: Limits) -> Result<Connection> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let conn = Connection::open_with_flags(path.join(DB), flags).map_err(|_| Error::Corrupt)?;
    for (limit, value) in [
        (Limit::SQLITE_LIMIT_LENGTH, (MAX_IMAGE_BYTES + 1024) as i32),
        (Limit::SQLITE_LIMIT_SQL_LENGTH, 8192),
        (Limit::SQLITE_LIMIT_COLUMN, 16),
        (Limit::SQLITE_LIMIT_ATTACHED, 0),
        (Limit::SQLITE_LIMIT_VARIABLE_NUMBER, 16),
        (Limit::SQLITE_LIMIT_TRIGGER_DEPTH, 0),
        (Limit::SQLITE_LIMIT_WORKER_THREADS, 0),
    ] {
        conn.set_limit(limit, value).map_err(|_| Error::Corrupt)?;
    }
    for (setting, value) in [
        (DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true),
        (DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false),
        (DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false),
    ] {
        if conn
            .set_db_config(setting, value)
            .map_err(|_| Error::Corrupt)?
            != value
        {
            return Err(Error::Corrupt);
        }
    }
    conn.busy_timeout(std::time::Duration::ZERO)
        .map_err(|_| Error::Corrupt)?;
    Ok(conn)
}
fn configure(conn: &Connection, limits: Limits) -> Result<()> {
    conn.execute_batch("PRAGMA synchronous=EXTRA; PRAGMA fullfsync=ON; PRAGMA temp_store=MEMORY; PRAGMA cache_size=-2048; PRAGMA mmap_size=0; PRAGMA cell_size_check=ON").map_err(|_| Error::Corrupt)?;
    conn.pragma_update(
        None,
        "max_page_count",
        (limits.database_bytes() / 4096) as i64,
    )
    .map_err(|_| Error::Corrupt)?;
    let pages: i64 = conn
        .pragma_query_value(None, "max_page_count", |r| r.get(0))
        .map_err(|_| Error::Corrupt)?;
    if pages <= 0 || pages > (limits.database_bytes() / 4096) as i64 {
        return Err(Error::Corrupt);
    }
    let mode: String = conn
        .pragma_query_value(None, "journal_mode", |r| r.get(0))
        .map_err(|_| Error::Corrupt)?;
    if mode != "delete" {
        return Err(Error::Corrupt);
    }
    for (name, expected) in [
        ("synchronous", 3),
        ("fullfsync", 1),
        ("temp_store", 2),
        ("mmap_size", 0),
        ("cell_size_check", 1),
    ] {
        if conn
            .pragma_query_value(None, name, |r| r.get::<_, i64>(0))
            .map_err(|_| Error::Corrupt)?
            != expected
        {
            return Err(Error::Corrupt);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
