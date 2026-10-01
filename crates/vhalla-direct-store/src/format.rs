use crate::{Context, Error, Limits, Result, JOURNAL_ALLOWANCE, MAX_STATE_BYTES};
use rusqlite::{config::DbConfig, limits::Limit, Connection, OpenFlags};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};
use vhalla_custody::{self as custody, Owner};

pub(crate) const DB: &str = "direct.sqlite";
pub(crate) const JOURNAL: &str = "direct.sqlite-journal";
pub(crate) const FORMAT_MAGIC: &[u8; 8] = b"VHDS0002";
pub(crate) const FORMAT_BYTES: usize = 8 + 64 + 32;
pub(crate) const VERSION: i64 = 2;
pub(crate) const APPLICATION_ID: i64 = 0x56484453;
pub(crate) const META_SQL: &str = "CREATE TABLE meta (id INTEGER PRIMARY KEY CHECK(id=1), context BLOB NOT NULL CHECK(length(context)=64), generation INTEGER NOT NULL CHECK(generation>=0), records INTEGER NOT NULL CHECK(records>=0), bytes INTEGER NOT NULL CHECK(bytes>=0), image BLOB CHECK(image IS NULL OR length(image) BETWEEN 1 AND 4194304), max_records INTEGER NOT NULL CHECK(max_records BETWEEN 1 AND 1000000), max_record_bytes INTEGER NOT NULL CHECK(max_record_bytes BETWEEN 1 AND 8589934592), digest BLOB NOT NULL CHECK(length(digest)=32)) STRICT";
pub(crate) const RECORD_SQL: &str = "CREATE TABLE records (cursor INTEGER PRIMARY KEY CHECK(cursor>0), key BLOB NOT NULL CHECK(length(key)=33), data BLOB NOT NULL CHECK(length(data) BETWEEN 1 AND 16384), digest BLOB NOT NULL CHECK(length(digest)=32)) STRICT";
pub(crate) const INDEX_SQL: &str = "CREATE UNIQUE INDEX record_keys ON records(key)";

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Meta {
    pub generation: u64,
    pub records: u64,
    pub bytes: u64,
    pub image: Option<Vec<u8>>,
    pub limits: Limits,
}

pub(crate) fn digest(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    for part in parts {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    hash.finalize().into()
}

pub(crate) fn meta_digest(context: Context, meta: &Meta) -> [u8; 32] {
    digest(
        b"vhalla/direct-store/meta/v2",
        &[
            &context.0,
            &meta.limits.max_records.to_be_bytes(),
            &meta.limits.max_record_bytes.to_be_bytes(),
            &meta.generation.to_be_bytes(),
            &meta.records.to_be_bytes(),
            &meta.bytes.to_be_bytes(),
            meta.image.as_deref().unwrap_or(&[]),
        ],
    )
}

pub(crate) fn record_digest(
    context: Context,
    cursor: u64,
    key: &[u8; 33],
    data: &[u8],
) -> [u8; 32] {
    digest(
        b"vhalla/direct-store/record/v1",
        &[&context.0, &cursor.to_be_bytes(), key, data],
    )
}

pub(crate) fn marker(context: Context) -> Vec<u8> {
    let mut raw = FORMAT_MAGIC.to_vec();
    raw.extend(context.0);
    raw.extend(digest(b"vhalla/direct-store/format/v2", &[&raw]));
    raw
}

pub(crate) fn parse_marker(raw: &[u8], context: Context) -> Result<()> {
    if marker(context) != raw {
        return Err(Error::Corrupt);
    }
    Ok(())
}

// Resolve an existing parent (including macOS /var aliases), never a store leaf.
pub(crate) fn resolved_parent(path: &Path) -> std::io::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let parent = absolute
        .parent()
        .ok_or_else(|| std::io::Error::other("missing parent"))?
        .canonicalize()?;
    let name = absolute
        .file_name()
        .ok_or_else(|| std::io::Error::other("missing store name"))?;
    Ok(parent.join(name))
}

pub(crate) fn inventory(path: &Path, owner: Owner, database_bytes: usize) -> Result<()> {
    let mut count = 0;
    let mut required = 0;
    for entry in fs::read_dir(path).map_err(|_| Error::Corrupt)? {
        count += 1;
        if count > 4 {
            return Err(Error::Corrupt);
        }
        let entry = entry.map_err(|_| Error::Corrupt)?;
        let name = entry.file_name();
        let (max, present) = match name.to_str().ok_or(Error::Corrupt)? {
            "lock" => (0, 1),
            "FORMAT" => (FORMAT_BYTES, 2),
            DB => (database_bytes, 4),
            JOURNAL => (database_bytes + JOURNAL_ALLOWANCE, 0),
            _ => return Err(Error::Corrupt),
        };
        required |= present;
        custody::open_private_file(&entry.path(), owner, max).map_err(|_| Error::Corrupt)?;
    }
    if required != 7 {
        return Err(Error::Corrupt);
    }
    Ok(())
}

pub(crate) fn check_header(file: &File) -> Result<()> {
    let length = file.metadata().map_err(|_| Error::Corrupt)?.len();
    if length < 4096 || length % 4096 != 0 {
        return Err(Error::Corrupt);
    }
    let mut header = [0; 100];
    file.try_clone()
        .and_then(|mut file| {
            file.seek(SeekFrom::Start(0))?;
            file.read_exact(&mut header)
        })
        .map_err(|_| Error::Corrupt)?;
    // Inspect immutable format fields before SQLite can replay a hot journal.
    if &header[..16] != b"SQLite format 3\0"
        || header[16..18] != 4096_u16.to_be_bytes()
        || header[18] != 1
        || header[19] != 1
        || header[60..64] != (VERSION as u32).to_be_bytes()
        || header[68..72] != (APPLICATION_ID as u32).to_be_bytes()
    {
        return Err(Error::Corrupt);
    }
    Ok(())
}

// Return true only for a complete SQLite header that has not yet been sealed
// for hot-journal rollback. It precedes any database-page writes under EXTRA.
// Unknown or partial files are retained and refused before SQLite touches them.
pub(crate) fn check_journal(path: &Path, owner: Owner, database_bytes: usize) -> Result<bool> {
    let path = path.join(JOURNAL);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(Error::Corrupt),
        Ok(_) => {}
    }
    let mut file = custody::open_private_file(&path, owner, database_bytes + JOURNAL_ALLOWANCE)
        .map_err(|_| Error::Corrupt)?;
    let length = file.metadata().map_err(|_| Error::Corrupt)?.len();
    if length == 0 {
        return Ok(false);
    }
    if length < 28 {
        return Err(Error::Corrupt);
    }
    let mut header = [0; 28];
    file.read_exact(&mut header).map_err(|_| Error::Corrupt)?;
    let magic = [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7];
    let cold = header[..8] == [0; 8];
    let field = |start| {
        u32::from_be_bytes(
            header[start..start + 4]
                .try_into()
                .expect("fixed header field"),
        )
    };
    let count = field(8);
    let pages = field(16);
    let sector = field(20);
    let page_size = field(24);
    if (!cold && header[..8] != magic)
        || (cold && count != 0)
        || pages == 0
        || pages as u64 > (database_bytes / 4096) as u64
        || !(512..=65536).contains(&sector)
        || !sector.is_power_of_two()
        || page_size != 4096
        || length < sector as u64
        || (!cold && count != u32::MAX && sector as u64 + count as u64 * 4104 > length)
    {
        return Err(Error::Corrupt);
    }
    Ok(cold)
}

pub(crate) fn connect(path: &Path) -> Result<Connection> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let conn = Connection::open_with_flags(path.join(DB), flags).map_err(|_| Error::Corrupt)?;
    for (limit, value) in [
        (Limit::SQLITE_LIMIT_LENGTH, (MAX_STATE_BYTES + 1024) as i32),
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

pub(crate) fn configure(conn: &Connection) -> Result<()> {
    conn.execute_batch("PRAGMA synchronous=EXTRA; PRAGMA fullfsync=ON; PRAGMA temp_store=MEMORY; PRAGMA cache_size=-2048; PRAGMA mmap_size=0; PRAGMA cell_size_check=ON").map_err(|_| Error::Corrupt)?;
    let mode: String = conn
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
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
            .pragma_query_value(None, name, |row| row.get::<_, i64>(0))
            .map_err(|_| Error::Corrupt)?
            != expected
        {
            return Err(Error::Corrupt);
        }
    }
    Ok(())
}

// This is a connection safeguard. Committed SQLite metadata is the authority
// for quotas; reopen reconstructs this setting only after transaction recovery.
pub(crate) fn set_database_bound(conn: &Connection, database_bytes: usize) -> Result<()> {
    let expected = (database_bytes / 4096) as i64;
    conn.pragma_update(None, "max_page_count", expected)
        .map_err(|_| Error::Corrupt)?;
    let pages: i64 = conn
        .pragma_query_value(None, "max_page_count", |row| row.get(0))
        .map_err(|_| Error::Corrupt)?;
    if expected <= 0 || pages != expected {
        return Err(Error::Corrupt);
    }
    Ok(())
}

// SQLite opens an already-existing empty journal instead of creating a file
// under a platform's default ACL. After each DELETE-journal commit, create the
// next one privately before SQLite needs it. Never replace a retained journal.
pub(crate) fn prepare_journal(path: &Path, directory: &File, owner: Owner) -> Result<()> {
    let journal_path = path.join(JOURNAL);
    let file = match fs::symlink_metadata(&journal_path) {
        Ok(_) => custody::open_private_file(&journal_path, owner, 0).map_err(|_| Error::Corrupt)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            custody::create_private_file(&journal_path).map_err(|_| Error::Uncertain)?
        }
        Err(_) => return Err(Error::Corrupt),
    };
    file.sync_all()
        .and_then(|_| directory.sync_all())
        .map_err(|_| Error::Uncertain)
}
