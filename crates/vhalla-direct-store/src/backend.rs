use crate::{
    bounds, check_key,
    format::{
        self, Meta, APPLICATION_ID, DB, FORMAT_BYTES, INDEX_SQL, JOURNAL, META_SQL, RECORD_SQL,
        VERSION,
    },
    Accounting, Context, Entry, Error, Limits, Page, Record, Result, MAX_PAGE_RECORDS,
    MAX_RECORD_BYTES, MAX_STATE_BYTES, MAX_TRANSACTION_RECORDS,
};
use rusqlite::{params, types::ValueRef, Connection, OptionalExtension};
use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};
use vhalla_custody::{self as custody, Owner};

const ENTRY_COLUMNS: &str = "cursor,length(key),CASE WHEN length(key)=33 THEN key END,length(data),CASE WHEN length(data) BETWEEN 1 AND 16384 THEN data END,digest";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Point {
    Begun,
    BoundRaised,
    JournalPrepared,
    RecordInserted,
    StateUpdated,
    LimitsUpdated,
    Committed,
    Checked,
}

/// One exclusive local store. An uncertain result requires dropping this handle
/// and explicitly reopening the same path and context before any further use.
pub struct Store {
    // Close SQLite and its transaction before releasing any filesystem custody.
    conn: Connection,
    path: PathBuf,
    directory: File,
    db_guard: File,
    owner: Owner,
    context: Context,
    limits: Limits,
    poisoned: bool,
    #[cfg(test)]
    fault: Option<Point>,
    #[cfg(test)]
    crash: Option<(Point, PathBuf)>,
    // This lock is dropped last, including after failed publication.
    lock: File,
}

impl Store {
    /// Create a never-existing private directory. Partial initialization is
    /// preserved and must never be reset or silently treated as an empty store.
    pub fn create_new(path: impl AsRef<Path>, context: Context, limits: Limits) -> Result<Self> {
        limits.check()?;
        let path = format::resolved_parent(path.as_ref()).map_err(|_| Error::Refused)?;
        let (directory, owner) =
            custody::create_private_directory(&path).map_err(|_| Error::Refused)?;
        let create = || -> Result<Self> {
            let lock =
                custody::create_private_file(&path.join("lock")).map_err(|_| Error::Uncertain)?;
            custody::acquire_exclusive(&lock).map_err(|_| Error::Uncertain)?;
            lock.sync_all().map_err(|_| Error::Uncertain)?;
            let mut marker = custody::create_private_file(&path.join("FORMAT.tmp"))
                .map_err(|_| Error::Uncertain)?;
            marker
                .write_all(&format::marker(context))
                .and_then(|_| marker.sync_all())
                .map_err(|_| Error::Uncertain)?;
            directory.sync_all().map_err(|_| Error::Uncertain)?;
            let db_guard =
                custody::create_private_file(&path.join(DB)).map_err(|_| Error::Uncertain)?;
            let conn = initialization("connect", format::connect(&path))?;
            initialization("configure", format::configure(&conn))?;
            initialization(
                "database bound",
                format::set_database_bound(&conn, limits.database_bytes()),
            )?;
            // BEGIN initializes page one of a fresh empty database and may
            // open its journal immediately. Establish private file ownership
            // first; later publications preflight before preparing a journal.
            initialization("journal", format::prepare_journal(&path, &directory, owner))?;
            initialization(
                "begin",
                conn.execute_batch("PRAGMA page_size=4096; BEGIN IMMEDIATE"),
            )?;
            initialization(
                "schema",
                conn.execute_batch(META_SQL)
                    .and_then(|_| conn.execute_batch(RECORD_SQL))
                    .and_then(|_| conn.execute_batch(INDEX_SQL)),
            )?;
            initialization(
                "header",
                conn.pragma_update(None, "application_id", APPLICATION_ID)
                    .and_then(|_| conn.pragma_update(None, "user_version", VERSION)),
            )?;
            let initial = Meta {
                generation: 0,
                records: 0,
                bytes: 0,
                image: None,
                limits,
            };
            initialization(
                "meta",
                conn.execute(
                    "INSERT INTO meta VALUES (1,?1,0,0,0,NULL,?2,?3,?4)",
                    params![
                        context.0.as_slice(),
                        limits.max_records as i64,
                        limits.max_record_bytes as i64,
                        format::meta_digest(context, &initial).as_slice()
                    ],
                ),
            )?;
            initialization("commit", conn.execute_batch("COMMIT"))?;
            initialization(
                "database sync",
                db_guard.sync_all().and_then(|_| directory.sync_all()),
            )?;
            initialization(
                "marker",
                fs::rename(path.join("FORMAT.tmp"), path.join("FORMAT")),
            )?;
            initialization("marker sync", directory.sync_all())?;
            initialization(
                "parent sync",
                custody::sync_directory(path.parent().ok_or(Error::Uncertain)?),
            )?;
            let mut store = Self {
                conn,
                path: path.clone(),
                directory,
                db_guard,
                owner,
                context,
                limits,
                poisoned: true,
                #[cfg(test)]
                fault: None,
                #[cfg(test)]
                crash: None,
                lock,
            };
            initialization("validate", store.validate())?;
            store.poisoned = false;
            Ok(store)
        };
        create()
    }

    /// Read only the bounded existing FORMAT marker as an unauthenticated local
    /// locator. This opens no SQLite database, repairs nothing and grants no room
    /// authority. The caller must pin the account and verify signed room data
    /// before exposing content or allowing any action.
    pub fn locate_context(path: impl AsRef<Path>) -> Result<Context> {
        let path = format::resolved_parent(path.as_ref()).map_err(|_| Error::Corrupt)?;
        let (directory, owner) = private_directory(&path)?;
        let raw = custody::read_private_file(&path.join("FORMAT"), owner, FORMAT_BYTES)
            .map_err(|_| Error::Corrupt)?;
        if raw.len() != FORMAT_BYTES {
            return Err(Error::Corrupt);
        }
        let context = Context::new(
            raw[8..40].try_into().map_err(|_| Error::Corrupt)?,
            raw[40..72].try_into().map_err(|_| Error::Corrupt)?,
        )
        .map_err(|_| Error::Corrupt)?;
        format::parse_marker(&raw, context)?;
        if !custody::same_file(&path, &directory).map_err(|_| Error::Corrupt)? {
            return Err(Error::Corrupt);
        }
        Ok(context)
    }

    /// Reopen the same namespace for explicit writer recovery. Exact FORMAT and
    /// rollback-only SQLite header checks precede SQLite recovery. This never
    /// creates a missing database or replaces partial/foreign state.
    pub fn open(path: impl AsRef<Path>, context: Context) -> Result<Self> {
        let path = format::resolved_parent(path.as_ref()).map_err(|_| Error::Corrupt)?;
        let (directory, owner) = private_directory(&path)?;
        let lock =
            custody::open_private_file(&path.join("lock"), owner, 0).map_err(|_| Error::Corrupt)?;
        custody::acquire_exclusive(&lock).map_err(|_| Error::Refused)?;
        let raw = custody::read_private_file(&path.join("FORMAT"), owner, FORMAT_BYTES)
            .map_err(|_| Error::Corrupt)?;
        format::parse_marker(&raw, context)?;
        // Limits live in the transaction that may need recovery. The immutable
        // format ceiling bounds bootstrap; verified metadata then narrows it.
        let absolute_bound = Limits::absolute_database_bytes();
        format::inventory(&path, owner, absolute_bound)?;
        let db_guard = custody::open_private_file(&path.join(DB), owner, absolute_bound)
            .map_err(|_| Error::Corrupt)?;
        format::check_header(&db_guard)?;
        let cold_journal = format::check_journal(&path, owner, absolute_bound)?;
        if !custody::same_file(&path, &directory).map_err(|_| Error::Corrupt)? {
            return Err(Error::Corrupt);
        }
        let conn = format::connect(&path)?;
        format::configure(&conn)?;
        format::set_database_bound(&conn, absolute_bound)?;
        Self::validate_schema(&conn)?;
        let limits = Self::read_meta(&conn, context)?.limits;
        format::set_database_bound(&conn, limits.database_bytes())?;
        let mut store = Self {
            conn,
            path,
            directory,
            db_guard,
            owner,
            context,
            limits,
            poisoned: true,
            #[cfg(test)]
            fault: None,
            #[cfg(test)]
            crash: None,
            lock,
        };
        store.check_files()?;
        if cold_journal && store.check_idle_journal().is_err() {
            store.finish_cold_recovery()?;
        }
        // An unexpected journal not consumed by explicit recovery remains
        // evidence, never something an ordinary publication may overwrite.
        store.check_idle_journal()?;
        store.sync()?;
        store.poisoned = false;
        Ok(store)
    }

    /// Load the exact current opaque state without recovery. None means that no
    /// publication has yet committed in this store.
    pub fn load(&mut self) -> Result<Option<Vec<u8>>> {
        self.ready()?;
        let result = self.check_read().and_then(|_| self.meta()).map(|m| m.image);
        self.finish_read(result)
    }

    /// Read one immutable local key without recovery. Absence is only a local
    /// lookup result, never evidence that a remote record does not exist.
    pub fn read(&mut self, key: [u8; 33]) -> Result<Option<Vec<u8>>> {
        self.ready()?;
        check_key(&key)?;
        let result = self.check_read().and_then(|_| {
            let meta = self.meta()?;
            self.record(&key, meta.records)
                .map(|entry| entry.map(|entry| entry.data))
        });
        self.finish_read(result)
    }

    /// Read at most 32 records after a local cursor. Every returned cursor must
    /// be contiguous within the observed tip. Later calls may observe a newer
    /// tip; callers needing a fixed range must retain their original stop cursor.
    pub fn page(&mut self, after: u64, limit: usize) -> Result<Page> {
        self.ready()?;
        if limit == 0 || limit > MAX_PAGE_RECORDS || after > self.limits.max_records {
            return Err(Error::Refused);
        }
        let result = self
            .check_read()
            .and_then(|_| self.page_inner(after, limit));
        self.finish_read(result)
    }

    /// Read current generation and retained usage without a history scan or repair.
    pub fn accounting(&mut self) -> Result<Accounting> {
        self.ready()?;
        let result = self.check_read().and_then(|_| self.meta()).map(accounting);
        self.finish_read(result)
    }

    /// Grow either retained-data limit in one SQLite transaction, without
    /// changing state bytes, publication generation, records or local cursors.
    /// Both fields must be at least their current values; an equal target is a
    /// verified no-op. Limits still obey the format's absolute bounds.
    ///
    /// This neither clears an application recovery fence nor adds physical disk
    /// space. Any uncertain mutation poisons the handle; explicitly reopen the
    /// same store to learn whether the old or target limits committed.
    pub fn expand_limits(&mut self, target: Limits) -> Result<Accounting> {
        self.ready()?;
        target.check()?;
        self.check_read().inspect_err(|_| self.poisoned = true)?;
        self.poisoned = true;
        self.conn
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|_| Error::Uncertain)?;
        self.hit(Point::Begun)?;
        let mut after = self.meta()?;
        if target.max_records < after.limits.max_records
            || target.max_record_bytes < after.limits.max_record_bytes
            || target == after.limits
        {
            self.conn
                .execute_batch("ROLLBACK")
                .map_err(|_| Error::Uncertain)?;
            if !self.conn.is_autocommit() {
                return Err(Error::Uncertain);
            }
            self.check_read()?;
            self.poisoned = false;
            return if target == after.limits {
                Ok(accounting(after))
            } else {
                Err(Error::Refused)
            };
        }
        format::set_database_bound(&self.conn, target.database_bytes())
            .map_err(|_| Error::Uncertain)?;
        self.hit(Point::BoundRaised)?;
        format::prepare_journal(&self.path, &self.directory, self.owner)
            .map_err(|_| Error::Uncertain)?;
        self.hit(Point::JournalPrepared)?;
        after.limits = target;
        let changed = self
            .conn
            .execute(
                "UPDATE meta SET max_records=?1,max_record_bytes=?2,digest=?3 WHERE id=1",
                params![
                    target.max_records as i64,
                    target.max_record_bytes as i64,
                    format::meta_digest(self.context, &after).as_slice()
                ],
            )
            .map_err(|_| Error::Uncertain)?;
        if changed != 1 {
            return Err(Error::Uncertain);
        }
        self.hit(Point::LimitsUpdated)?;
        self.conn
            .execute_batch("COMMIT")
            .map_err(|_| Error::Uncertain)?;
        self.hit(Point::Committed)?;
        self.check_files_with_bound(target.database_bytes())
            .map_err(|_| Error::Uncertain)?;
        self.check_idle_journal().map_err(|_| Error::Uncertain)?;
        self.hit(Point::Checked)?;
        if Self::read_meta(&self.conn, self.context).map_err(|_| Error::Uncertain)? != after {
            return Err(Error::Uncertain);
        }
        self.limits = target;
        self.poisoned = false;
        Ok(accounting(after))
    }

    /// Atomically compare the complete current state, publish the next state,
    /// and retain up to eight offered records. Identical keys/bytes are harmless
    /// duplicates; conflicting bytes refuse the whole transaction. Every success
    /// increments the state generation, even if no distinct records were added.
    ///
    /// Stale expectations and capacity refusals roll back without publication.
    /// Any uncertain write/commit/readback poisons this handle. SQLite's checked
    /// EXTRA/fullfsync commit barriers precede exact local readback and success.
    pub fn publish(
        &mut self,
        expected: Option<&[u8]>,
        next: &[u8],
        records: &[Record],
    ) -> Result<()> {
        self.ready()?;
        bounds(next, MAX_STATE_BYTES)?;
        if let Some(expected) = expected {
            bounds(expected, MAX_STATE_BYTES)?;
        }
        if records.len() > MAX_TRANSACTION_RECORDS {
            return Err(Error::Refused);
        }
        for record in records {
            check_key(&record.key)?;
            bounds(&record.data, MAX_RECORD_BYTES)?;
        }
        self.check_files().inspect_err(|_| self.poisoned = true)?;
        self.check_idle_journal()
            .inspect_err(|_| self.poisoned = true)?;
        self.poisoned = true;
        self.conn
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|_| Error::Uncertain)?;
        self.hit(Point::Begun)?;
        let (after, new) = match self.prepare(expected, next, records) {
            Ok(prepared) => prepared,
            Err(error) => {
                if self.conn.execute_batch("ROLLBACK").is_err() || !self.conn.is_autocommit() {
                    return Err(Error::Uncertain);
                }
                if matches!(error, Error::Conflict | Error::Refused) {
                    self.check_files()?;
                    self.check_idle_journal()?;
                    self.poisoned = false;
                }
                return Err(error);
            }
        };
        // Semantic refusal has already returned. From this point onward an
        // incomplete journal or transaction requires explicit same-store reopen.
        format::prepare_journal(&self.path, &self.directory, self.owner)
            .map_err(|_| Error::Uncertain)?;
        self.hit(Point::JournalPrepared)?;
        for (cursor, record) in new {
            self.conn
                .execute(
                    "INSERT INTO records(cursor,key,data,digest) VALUES (?1,?2,?3,?4)",
                    params![
                        cursor as i64,
                        record.key.as_slice(),
                        record.data,
                        format::record_digest(self.context, cursor, &record.key, &record.data)
                            .as_slice()
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
                    format::meta_digest(self.context, &after).as_slice()
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
        self.check_files().map_err(|_| Error::Uncertain)?;
        self.check_idle_journal().map_err(|_| Error::Uncertain)?;
        self.hit(Point::Checked)?;
        if self.meta().map_err(|_| Error::Uncertain)? != after {
            return Err(Error::Uncertain);
        }
        for record in records {
            if self
                .record(&record.key, after.records)
                .map_err(|_| Error::Uncertain)?
                .as_ref()
                .map(|entry| entry.data.as_slice())
                != Some(record.as_bytes())
            {
                return Err(Error::Uncertain);
            }
        }
        self.poisoned = false;
        Ok(())
    }

    fn ready(&self) -> Result<()> {
        if self.poisoned {
            Err(Error::Uncertain)
        } else {
            Ok(())
        }
    }

    fn finish_read<T>(&mut self, result: Result<T>) -> Result<T> {
        if matches!(result, Err(Error::Corrupt | Error::Uncertain)) {
            self.poisoned = true;
        }
        result
    }

    fn check_files(&self) -> Result<()> {
        self.check_files_with_bound(self.limits.database_bytes())
    }

    fn check_files_with_bound(&self, database_bytes: usize) -> Result<()> {
        let (directory, owner) = private_directory(&self.path)?;
        if owner != self.owner
            || !custody::same_open_file(&directory, &self.directory).map_err(|_| Error::Corrupt)?
            || !custody::same_file(&self.path, &self.directory).map_err(|_| Error::Corrupt)?
        {
            return Err(Error::Corrupt);
        }
        format::inventory(&self.path, self.owner, database_bytes)?;
        for (name, held, max) in [
            (DB, &self.db_guard, database_bytes),
            ("lock", &self.lock, 0),
        ] {
            let current = custody::open_private_file(&self.path.join(name), self.owner, max)
                .map_err(|_| Error::Corrupt)?;
            if !custody::same_open_file(&current, held).map_err(|_| Error::Corrupt)? {
                return Err(Error::Corrupt);
            }
        }
        // The held inode can still be edited in place. Refuse an unexpected
        // database format before any SQLite query can switch modes or recover.
        format::check_header(&self.db_guard)?;
        if custody::read_private_file(&self.path.join("FORMAT"), self.owner, FORMAT_BYTES)
            .map_err(|_| Error::Corrupt)?
            != format::marker(self.context)
        {
            return Err(Error::Corrupt);
        }
        Ok(())
    }

    fn check_idle_journal(&self) -> Result<()> {
        match fs::symlink_metadata(self.path.join(JOURNAL)) {
            Ok(_) => {
                custody::open_private_file(&self.path.join(JOURNAL), self.owner, 0)
                    .map_err(|_| Error::Corrupt)?;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(Error::Corrupt),
        }
    }

    fn check_read(&self) -> Result<()> {
        self.check_files()?;
        // SQLite can discover and replay a newly present hot journal on its
        // first query. Ordinary reads must refuse before issuing that query.
        self.check_idle_journal()
    }

    fn sync(&self) -> Result<()> {
        self.check_files()?;
        self.db_guard
            .sync_all()
            .and_then(|_| self.directory.sync_all())
            .map_err(|_| Error::Uncertain)
    }

    fn finish_cold_recovery(&mut self) -> Result<()> {
        // A valid unsealed SQLite journal precedes database-page writes. SQLite
        // ignores it on read. An explicit writer-open completes a header-only
        // transaction to let SQLite retire it using its normal sync barriers.
        // This does not publish an application state or advance its generation.
        self.check_files()?;
        if !format::check_journal(&self.path, self.owner, self.limits.database_bytes())? {
            return Err(Error::Corrupt);
        }
        let before = self.meta()?;
        self.conn
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|_| Error::Uncertain)?;
        self.conn
            .pragma_update(None, "user_version", VERSION)
            .map_err(|_| Error::Uncertain)?;
        self.conn
            .execute_batch("COMMIT")
            .map_err(|_| Error::Uncertain)?;
        self.check_files().map_err(|_| Error::Uncertain)?;
        self.check_idle_journal().map_err(|_| Error::Uncertain)?;
        if self.meta().map_err(|_| Error::Uncertain)? != before {
            return Err(Error::Uncertain);
        }
        Ok(())
    }

    fn validate(&mut self) -> Result<()> {
        self.check_files()?;
        Self::validate_schema(&self.conn)?;
        self.meta()?;
        Ok(())
    }

    fn validate_schema(conn: &Connection) -> Result<()> {
        for (name, expected) in [
            ("application_id", APPLICATION_ID),
            ("user_version", VERSION),
            ("page_size", 4096),
        ] {
            let actual: i64 = conn
                .pragma_query_value(None, name, |row| row.get(0))
                .map_err(|_| Error::Corrupt)?;
            if actual != expected {
                return Err(Error::Corrupt);
            }
        }
        let mut statement = conn
            .prepare("SELECT type,name,sql FROM sqlite_schema ORDER BY name LIMIT 4")
            .map_err(|_| Error::Corrupt)?;
        let mut rows = statement.query([]).map_err(|_| Error::Corrupt)?;
        for (kind, name, sql) in [
            ("table", "meta", META_SQL),
            ("index", "record_keys", INDEX_SQL),
            ("table", "records", RECORD_SQL),
        ] {
            let row = rows
                .next()
                .map_err(|_| Error::Corrupt)?
                .ok_or(Error::Corrupt)?;
            if row.get_ref(0).map_err(|_| Error::Corrupt)? != ValueRef::Text(kind.as_bytes())
                || row.get_ref(1).map_err(|_| Error::Corrupt)? != ValueRef::Text(name.as_bytes())
                || row.get_ref(2).map_err(|_| Error::Corrupt)? != ValueRef::Text(sql.as_bytes())
            {
                return Err(Error::Corrupt);
            }
        }
        if rows.next().map_err(|_| Error::Corrupt)?.is_some() {
            return Err(Error::Corrupt);
        }
        Ok(())
    }

    fn meta(&self) -> Result<Meta> {
        let meta = Self::read_meta(&self.conn, self.context)?;
        if meta.limits != self.limits {
            return Err(Error::Corrupt);
        }
        Ok(meta)
    }

    fn read_meta(conn: &Connection, context: Context) -> Result<Meta> {
        let mut statement = conn.prepare("SELECT id,context,generation,records,bytes,length(image),CASE WHEN length(image) BETWEEN 1 AND 4194304 THEN image END,max_records,max_record_bytes,digest FROM meta LIMIT 2")
            .map_err(|_| Error::Corrupt)?;
        let mut rows = statement.query([]).map_err(|_| Error::Corrupt)?;
        let row = rows
            .next()
            .map_err(|_| Error::Corrupt)?
            .ok_or(Error::Corrupt)?;
        if row.get::<_, i64>(0).map_err(|_| Error::Corrupt)? != 1
            || row.get_ref(1).map_err(|_| Error::Corrupt)? != ValueRef::Blob(&context.0)
        {
            return Err(Error::Corrupt);
        }
        let generation = integer(row, 2)?;
        let records = integer(row, 3)?;
        let bytes = integer(row, 4)?;
        let length: Option<i64> = row.get(5).map_err(|_| Error::Corrupt)?;
        let image = match length {
            None if generation == 0 && records == 0 && bytes == 0 => None,
            Some(length) if generation > 0 && (1..=MAX_STATE_BYTES as i64).contains(&length) => {
                Some(blob(row, 6, length as usize)?.to_vec())
            }
            _ => return Err(Error::Corrupt),
        };
        let limits = Limits {
            max_records: integer(row, 7)?,
            max_record_bytes: integer(row, 8)?,
        };
        limits.check().map_err(|_| Error::Corrupt)?;
        let meta = Meta {
            generation,
            records,
            bytes,
            image,
            limits,
        };
        if records > limits.max_records
            || bytes > limits.max_record_bytes
            || (records == 0) != (bytes == 0)
            || bytes < records
            || bytes > records.saturating_mul(MAX_RECORD_BYTES as u64)
            || records > generation.saturating_mul(MAX_TRANSACTION_RECORDS as u64)
            || row.get_ref(9).map_err(|_| Error::Corrupt)?
                != ValueRef::Blob(&format::meta_digest(context, &meta))
            || rows.next().map_err(|_| Error::Corrupt)?.is_some()
        {
            return Err(Error::Corrupt);
        }
        // Two indexed endpoints, not a count/scan of the entire retained history.
        let first: Option<i64> = conn
            .query_row(
                "SELECT cursor FROM records ORDER BY cursor LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| Error::Corrupt)?;
        let last: Option<i64> = conn
            .query_row(
                "SELECT cursor FROM records ORDER BY cursor DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| Error::Corrupt)?;
        if (records == 0 && (first.is_some() || last.is_some()))
            || (records != 0 && (first != Some(1) || last != Some(records as i64)))
        {
            return Err(Error::Corrupt);
        }
        Ok(meta)
    }

    fn record(&self, key: &[u8; 33], tip: u64) -> Result<Option<Entry>> {
        let query = format!("SELECT {ENTRY_COLUMNS} FROM records WHERE key=?1 LIMIT 2");
        let mut statement = self.conn.prepare(&query).map_err(|_| Error::Corrupt)?;
        let mut rows = statement
            .query([key.as_slice()])
            .map_err(|_| Error::Corrupt)?;
        let Some(row) = rows.next().map_err(|_| Error::Corrupt)? else {
            return Ok(None);
        };
        let entry = self.entry(row, tip)?;
        if entry.key != *key || rows.next().map_err(|_| Error::Corrupt)?.is_some() {
            return Err(Error::Corrupt);
        }
        Ok(Some(entry))
    }

    fn entry(&self, row: &rusqlite::Row<'_>, tip: u64) -> Result<Entry> {
        let cursor = integer(row, 0)?;
        if cursor == 0 || cursor > tip || integer(row, 1)? != 33 {
            return Err(Error::Corrupt);
        }
        let key: [u8; 33] = blob(row, 2, 33)?.try_into().map_err(|_| Error::Corrupt)?;
        check_key(&key).map_err(|_| Error::Corrupt)?;
        let length = integer(row, 3)?;
        if !(1..=MAX_RECORD_BYTES as u64).contains(&length) {
            return Err(Error::Corrupt);
        }
        let data = blob(row, 4, length as usize)?;
        if row.get_ref(5).map_err(|_| Error::Corrupt)?
            != ValueRef::Blob(&format::record_digest(self.context, cursor, &key, data))
        {
            return Err(Error::Corrupt);
        }
        Ok(Entry {
            cursor,
            key,
            data: data.to_vec(),
        })
    }

    fn page_inner(&self, after: u64, limit: usize) -> Result<Page> {
        let meta = self.meta()?;
        if after > meta.records {
            return Err(Error::Refused);
        }
        let query =
            format!("SELECT {ENTRY_COLUMNS} FROM records WHERE cursor>?1 ORDER BY cursor LIMIT ?2");
        let mut statement = self.conn.prepare(&query).map_err(|_| Error::Corrupt)?;
        let mut rows = statement
            .query(params![after as i64, limit as i64])
            .map_err(|_| Error::Corrupt)?;
        let count = (meta.records - after).min(limit as u64) as usize;
        let mut records = Vec::with_capacity(count);
        for offset in 0..count {
            let row = rows
                .next()
                .map_err(|_| Error::Corrupt)?
                .ok_or(Error::Corrupt)?;
            let entry = self.entry(row, meta.records)?;
            if entry.cursor != after + offset as u64 + 1 {
                return Err(Error::Corrupt);
            }
            records.push(entry);
        }
        if rows.next().map_err(|_| Error::Corrupt)?.is_some() {
            return Err(Error::Corrupt);
        }
        let last = after + count as u64;
        Ok(Page {
            tip: meta.records,
            records,
            next: (last < meta.records).then_some(last),
        })
    }

    fn prepare<'a>(
        &self,
        expected: Option<&[u8]>,
        next: &[u8],
        records: &'a [Record],
    ) -> Result<(Meta, Vec<(u64, &'a Record)>)> {
        let mut after = self.meta()?;
        if after.image.as_deref() != expected {
            return Err(Error::Conflict);
        }
        let previous_tip = after.records;
        let mut new: Vec<(u64, &Record)> = Vec::with_capacity(MAX_TRANSACTION_RECORDS);
        for record in records {
            if let Some((_, earlier)) = new.iter().find(|(_, earlier)| earlier.key == record.key) {
                if earlier.data != record.data {
                    return Err(Error::Conflict);
                }
                continue;
            }
            match self.record(&record.key, previous_tip)? {
                Some(existing) if existing.data == record.data => continue,
                Some(_) => return Err(Error::Conflict),
                None => {
                    after.records = after.records.checked_add(1).ok_or(Error::Refused)?;
                    after.bytes = after
                        .bytes
                        .checked_add(record.data.len() as u64)
                        .ok_or(Error::Refused)?;
                    new.push((after.records, record));
                }
            }
        }
        if after.records > self.limits.max_records || after.bytes > self.limits.max_record_bytes {
            return Err(Error::Refused);
        }
        after.generation = after
            .generation
            .checked_add(1)
            .filter(|value| *value <= i64::MAX as u64)
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
                    let mut file = File::create(marker).map_err(|_| Error::Uncertain)?;
                    file.write_all(b"ready")
                        .and_then(|_| file.sync_all())
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

fn initialization<T, E: std::fmt::Debug>(
    step: &str,
    result: std::result::Result<T, E>,
) -> Result<T> {
    result.map_err(|error| {
        #[cfg(test)]
        eprintln!("direct-store initialization {step}: {error:?}");
        let _ = (step, error);
        Error::Uncertain
    })
}

fn accounting(meta: Meta) -> Accounting {
    Accounting {
        generation: meta.generation,
        tip: meta.records,
        records: meta.records,
        bytes: meta.bytes,
        limits: meta.limits,
    }
}

fn private_directory(path: &Path) -> Result<(File, Owner)> {
    let (directory, owner) = custody::open_private_directory(path).map_err(|_| Error::Corrupt)?;
    if owner != Owner::current().map_err(|_| Error::Corrupt)? {
        return Err(Error::Corrupt);
    }
    Ok((directory, owner))
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

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
