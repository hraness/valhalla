//! Finish only a successor selected by an already retained host intent.
use super::*;
use rusqlite::OpenFlags;
use std::{
    collections::BTreeSet,
    fs,
    io::{Seek, SeekFrom, Write},
};

const CREATION: &str = "creation";
const MARKER_LIMIT: usize = 256;

#[cfg(test)]
thread_local! {
    static CREATION_FAULT: std::cell::Cell<Option<u8>> = const { std::cell::Cell::new(None) };
}
fn boundary(point: u8) -> Result<()> {
    #[cfg(test)]
    if CREATION_FAULT.with(|fault| fault.get() == Some(point)) {
        return Err(Error::Storage);
    }
    let _ = point;
    Ok(())
}

fn binding(limits: Limits, fence: GenerationFence, intent: [u8; 32]) -> Result<Vec<u8>> {
    limits.check()?;
    if intent == [0; 32] {
        return Err(Error::Bounds);
    }
    let mut raw = b"VHRELAYNEW\x01".to_vec();
    raw.extend(fence.successor().as_bytes());
    for value in [limits.max_items, limits.max_bytes] {
        raw.extend(
            i64::try_from(value)
                .map_err(|_| Error::Bounds)?
                .to_be_bytes(),
        );
    }
    raw.extend(intent);
    raw.extend(fence.commitment());
    Ok(raw)
}

fn present(path: &Path, owner: Owner, limit: usize) -> Result<bool> {
    custody::private_file_present(path, owner, limit).map_err(|_| Error::Storage)
}

fn inventory(path: &Path, owner: Owner) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(path).map_err(|_| Error::Storage)? {
        let entry = entry.map_err(|_| Error::Storage)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| Error::Storage)?;
        let limit = match name.as_str() {
            CREATION => MARKER_LIMIT,
            "lock" => 0,
            "relay.db" | "relay.db-journal" => MAX_RELAY_DB_BYTES,
            _ => return Err(Error::Storage),
        };
        if !present(&entry.path(), owner, limit)? || !names.insert(name) {
            return Err(Error::Storage);
        }
    }
    Ok(names)
}

fn schema(conn: &Connection) -> Result<BTreeSet<(String, String)>> {
    let mut statement = conn
        .prepare("SELECT substr(type,1,16),substr(name,1,128) FROM sqlite_schema WHERE substr(name,1,7) != 'sqlite_' LIMIT 11")
        .map_err(|_| Error::Storage)?;
    let rows = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(|_| Error::Storage)?;
    let mut objects = BTreeSet::new();
    for row in rows {
        if objects.len() >= 10 {
            return Err(Error::Storage);
        }
        objects.insert(row.map_err(|_| Error::Storage)?);
    }
    Ok(objects)
}

fn validate_schema(objects: &BTreeSet<(String, String)>) -> Result<()> {
    let tables = |names: &[&str]| -> BTreeSet<(String, String)> {
        names
            .iter()
            .map(|name| ("table".into(), (*name).into()))
            .collect()
    };
    let base = tables(&["meta", "items", "generation_state"]);
    let mut seeded = base.clone();
    seeded.extend(tables(&[
        "tls_keys",
        "tls_charges",
        "tls_meta",
        "tls_budget",
        "tls_generation",
    ]));
    seeded.insert(("index".into(), "tls_charges_by_key".into()));
    if objects != &base && objects != &seeded {
        return Err(Error::Storage);
    }
    Ok(())
}

impl FileStore {
    /// Create or finish the exact successor authorized by a durable host intent.
    ///
    /// The caller must first retain that intent, including this path, namespace,
    /// limits and fence, under exclusive host maintenance custody. An empty or
    /// lock-only directory is the pre-marker interruption prefix of that intent;
    /// this method cannot independently authenticate an unwritten binding.
    /// Once present, the private creation marker may only finish its matching
    /// prefix before any database exists. Schema and namespace publish together
    /// in one transaction. Existing stores without this exact marker, unknown
    /// schema, changed limits and changed selections refuse without a reset.
    pub fn create_successor(
        path: impl AsRef<Path>,
        limits: Limits,
        fence: GenerationFence,
        host_intent: [u8; 32],
    ) -> Result<Self> {
        let expected = binding(limits, fence, host_intent)?;
        let requested = custody::absolute(path.as_ref()).map_err(|_| Error::Storage)?;
        // Resolve macOS /var aliases only in the selected existing parent.
        // The store leaf, creation marker and database keep no-follow checks.
        let parent = requested
            .parent()
            .ok_or(Error::Storage)?
            .canonicalize()
            .map_err(|_| Error::Storage)?;
        let path = parent.join(requested.file_name().ok_or(Error::Storage)?);
        let (parent_directory, parent_uid) =
            custody::open_private_directory(&parent).map_err(|_| Error::Storage)?;
        let (directory, owner) = match fs::symlink_metadata(&path) {
            Ok(_) => custody::open_private_directory(&path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                custody::create_private_directory(&path)
            }
            Err(_) => return Err(Error::Storage),
        }
        .map_err(|_| Error::Storage)?;
        if owner != parent_uid {
            return Err(Error::Storage);
        }
        boundary(0)?;
        let names = inventory(&path, owner)?;
        let marker = path.join(CREATION);
        let prior = if names.contains(CREATION) {
            custody::read_private_file(&marker, owner, MARKER_LIMIT).map_err(|_| Error::Storage)?
        } else {
            Vec::new()
        };
        if !expected.starts_with(&prior)
            || (names.contains("relay.db") && (prior != expected || !names.contains("lock")))
            || (names.contains("relay.db-journal") && !names.contains("relay.db"))
        {
            return Err(Error::Conflict);
        }
        let lock_path = path.join("lock");
        let lock = if names.contains("lock") {
            custody::open_private_file(&lock_path, owner, 0)
        } else {
            custody::create_private_file(&lock_path)
        }
        .map_err(|_| Error::Storage)?;
        custody::acquire_exclusive(&lock).map_err(|_| Error::Storage)?;
        boundary(1)?;
        // Re-read under mailbox custody before appending any known prefix.
        let mut marker_file = if names.contains(CREATION) {
            custody::open_private_file(&marker, owner, MARKER_LIMIT)
        } else {
            custody::create_private_file(&marker)
        }
        .map_err(|_| Error::Storage)?;
        let held =
            custody::read_private_file(&marker, owner, MARKER_LIMIT).map_err(|_| Error::Storage)?;
        if held != prior {
            return Err(Error::Conflict);
        }
        boundary(2)?;
        marker_file
            .seek(SeekFrom::End(0))
            .map_err(|_| Error::Storage)?;
        let remaining = &expected[prior.len()..];
        let half = remaining.len() / 2;
        marker_file
            .write_all(&remaining[..half])
            .map_err(|_| Error::Storage)?;
        boundary(3)?;
        marker_file
            .write_all(&remaining[half..])
            .and_then(|()| marker_file.sync_all())
            .and_then(|()| directory.sync_all())
            .map_err(|_| Error::Storage)?;
        if custody::read_private_file(&marker, owner, MARKER_LIMIT).map_err(|_| Error::Storage)?
            != expected
        {
            return Err(Error::Storage);
        }
        boundary(4)?;
        let db_path = path.join("relay.db");
        let db_guard = if names.contains("relay.db") {
            custody::open_private_file(&db_path, owner, MAX_RELAY_DB_BYTES)
        } else {
            custody::create_private_file(&db_path)
        }
        .map_err(|_| Error::Storage)?;
        boundary(5)?;
        let conn = Connection::open_with_flags(
            &db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| Error::Storage)?;
        configure_database(&conn)?;
        let objects = schema(&conn)?;
        if objects.is_empty() {
            for (name, maximum) in [
                ("page_count", 1),
                ("freelist_count", 0),
                ("application_id", 0),
                ("user_version", 0),
            ] {
                let value: i64 = conn
                    .pragma_query_value(None, name, |row| row.get(0))
                    .map_err(|_| Error::Storage)?;
                if value < 0 || value > maximum {
                    return Err(Error::Storage);
                }
            }
            if db_guard.metadata().map_err(|_| Error::Storage)?.len() > 4096 {
                return Err(Error::Storage);
            }
            conn.execute_batch("BEGIN IMMEDIATE;
                CREATE TABLE meta (id INTEGER PRIMARY KEY CHECK(id=1), format INTEGER NOT NULL CHECK(format=3), namespace BLOB NOT NULL, max_items INTEGER NOT NULL, max_bytes INTEGER NOT NULL);
                CREATE TABLE items (position INTEGER PRIMARY KEY, sequence BLOB NOT NULL, operation BLOB NOT NULL UNIQUE, kind INTEGER NOT NULL, payload BLOB NOT NULL, digest BLOB NOT NULL UNIQUE);
                CREATE TABLE generation_state (id INTEGER PRIMARY KEY CHECK(id=1), transition BLOB, successor BLOB, head INTEGER, items BLOB,
                  CHECK((transition IS NULL AND successor IS NULL AND head IS NULL AND items IS NULL) OR
                        (transition IS NOT NULL AND length(transition)=32 AND transition!=zeroblob(32) AND
                         successor IS NOT NULL AND length(successor)=32 AND successor!=zeroblob(32) AND
                         head IS NOT NULL AND head>=0 AND items IS NOT NULL AND length(items)=32)));")
                .map_err(|_| Error::Storage)?;
            boundary(6)?;
            conn.execute(
                "INSERT INTO meta VALUES(1,3,?1,?2,?3)",
                params![
                    fence.successor().as_bytes().as_slice(),
                    limits.max_items as i64,
                    limits.max_bytes as i64
                ],
            )
            .map_err(|_| Error::Storage)?;
            conn.execute_batch("INSERT INTO generation_state VALUES(1,NULL,NULL,NULL,NULL)")
                .map_err(|_| Error::Storage)?;
            boundary(7)?;
            conn.execute_batch("COMMIT").map_err(|_| Error::Storage)?;
            boundary(8)?;
        }
        validate_schema(&schema(&conn)?)?;
        let (actual_limits, format) = read_meta(&conn, fence.successor())?;
        if actual_limits != limits || format != 3 {
            return Err(Error::Conflict);
        }
        let out = Self {
            conn,
            directory,
            db_guard,
            _lock: lock,
            namespace: fence.successor(),
            limits,
            format,
            needs_reopen: false,
            #[cfg(test)]
            maintenance_fault: None,
        };
        out.validate()?;
        out.sync()?;
        boundary(9)?;
        parent_directory.sync_all().map_err(|_| Error::Storage)?;
        boundary(10)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests;
