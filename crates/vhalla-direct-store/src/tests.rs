use super::*;
use hegel::HealthCheck;
use std::{
    io::{Read, Seek, SeekFrom},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct Temp(PathBuf);

impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "vhalla-direct-store-{}-{stamp}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        custody::create_private_directory(&path).unwrap();
        Self(path)
    }

    fn store(&self) -> PathBuf {
        self.0.join("store")
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn context() -> Context {
    Context::new([1; 32], [2; 32]).unwrap()
}
fn limits() -> Limits {
    Limits {
        max_records: 128,
        max_record_bytes: 4 * 1024 * 1024,
    }
}
fn expanded_limits() -> Limits {
    Limits {
        max_records: 256,
        max_record_bytes: 8 * 1024 * 1024,
    }
}
fn key(id: u64) -> [u8; 33] {
    let mut key = [0; 33];
    key[0] = 1;
    key[25..].copy_from_slice(&id.to_be_bytes());
    key
}
fn record(id: u64, byte: u8) -> Record {
    Record::new(key(id), &[byte; 8]).unwrap()
}
fn private_file(path: &Path, bytes: &[u8]) {
    let mut file = custody::create_private_file(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

#[test]
fn validates_all_public_bounds_before_creation_or_publication() {
    assert_eq!(Context::new([0; 32], [1; 32]), Err(Error::Refused));
    assert_eq!(Context::new([1; 32], [0; 32]), Err(Error::Refused));
    assert_eq!(Record::new([0; 33], b"x"), Err(Error::Refused));
    let mut no_id = [0; 33];
    no_id[0] = 2;
    assert_eq!(Record::new(no_id, b"x"), Err(Error::Refused));
    assert_eq!(Record::new(key(1), b""), Err(Error::Refused));
    assert!(Record::new(key(1), &vec![0; MAX_RECORD_BYTES]).is_ok());
    assert_eq!(
        Record::new(key(1), &vec![0; MAX_RECORD_BYTES + 1]),
        Err(Error::Refused)
    );
    for invalid in [
        Limits {
            max_records: 0,
            ..limits()
        },
        Limits {
            max_records: 1_000_001,
            ..limits()
        },
        Limits {
            max_record_bytes: 0,
            ..limits()
        },
        Limits {
            max_record_bytes: 8 * 1024 * 1024 * 1024 + 1,
            ..limits()
        },
        Limits {
            max_records: u64::MAX,
            max_record_bytes: u64::MAX,
        },
    ] {
        let temp = Temp::new();
        assert!(matches!(
            Store::create_new(temp.store(), context(), invalid),
            Err(Error::Refused)
        ));
        assert!(!temp.store().exists());
    }
    let temp = Temp::new();
    let mut store = Store::create_new(temp.store(), context(), limits()).unwrap();
    assert_eq!(store.publish(None, b"", &[]), Err(Error::Refused));
    assert_eq!(
        store.publish(None, &vec![0; MAX_STATE_BYTES + 1], &[]),
        Err(Error::Refused)
    );
    assert_eq!(store.publish(Some(b""), b"next", &[]), Err(Error::Refused));
    assert_eq!(
        store.publish(None, b"next", &vec![record(1, 1); 9]),
        Err(Error::Refused)
    );
    assert_eq!(store.page(0, 0), Err(Error::Refused));
    assert_eq!(store.page(0, 33), Err(Error::Refused));
    assert_eq!(store.page(1, 1), Err(Error::Refused));
    assert_eq!(store.read([0; 33]), Err(Error::Refused));
    assert_eq!(store.load().unwrap(), None);
    assert_eq!(store.accounting().unwrap().generation, 0);
}

#[test]
fn exclusive_lock_exact_namespace_and_locator_preserve_state() {
    let temp = Temp::new();
    let mut store = Store::create_new(temp.store(), context(), limits()).unwrap();
    store.publish(None, b"state", &[record(1, 5)]).unwrap();
    assert_eq!(Store::locate_context(temp.store()).unwrap(), context());
    assert!(matches!(
        Store::open(temp.store(), context()),
        Err(Error::Refused)
    ));
    assert!(matches!(
        Store::create_new(temp.store(), context(), limits()),
        Err(Error::Refused)
    ));
    drop(store);
    for wrong in [
        Context::new([9; 32], [2; 32]).unwrap(),
        Context::new([1; 32], [9; 32]).unwrap(),
    ] {
        let before = fs::read(temp.store().join(DB)).unwrap();
        assert!(matches!(
            Store::open(temp.store(), wrong),
            Err(Error::Corrupt)
        ));
        assert_eq!(fs::read(temp.store().join(DB)).unwrap(), before);
    }
    let mut reopened = Store::open(temp.store(), context()).unwrap();
    assert_eq!(reopened.load().unwrap(), Some(b"state".to_vec()));
    assert_eq!(reopened.read(key(1)).unwrap(), Some(vec![5; 8]));
    assert_eq!(reopened.accounting().unwrap().limits, limits());
}

#[test]
fn exact_record_retries_deduplicate_and_conflicts_are_atomic() {
    let temp = Temp::new();
    let mut store = Store::create_new(temp.store(), context(), limits()).unwrap();
    let first = record(1, 7);
    store
        .publish(None, b"one", &[first.clone(), first.clone()])
        .unwrap();
    let first_accounting = store.accounting().unwrap();
    assert_eq!(
        (
            first_accounting.records,
            first_accounting.bytes,
            first_accounting.generation
        ),
        (1, 8, 1)
    );
    store
        .publish(Some(b"one"), b"two", std::slice::from_ref(&first))
        .unwrap();
    let second = store.accounting().unwrap();
    assert_eq!((second.records, second.bytes, second.generation), (1, 8, 2));
    assert_eq!(
        store.publish(Some(b"one"), b"two", &[first]),
        Err(Error::Conflict)
    );
    assert_eq!(
        store.publish(Some(b"two"), b"bad", &[record(2, 3), record(1, 9)]),
        Err(Error::Conflict)
    );
    assert_eq!(
        store.publish(Some(b"two"), b"bad", &[record(2, 3), record(2, 4)]),
        Err(Error::Conflict)
    );
    assert_eq!(store.read(key(2)).unwrap(), None);
    assert_eq!(store.load().unwrap(), Some(b"two".to_vec()));
    assert_eq!(store.accounting().unwrap(), second);
    assert!(!temp.store().join(JOURNAL).exists());
    store
        .publish(Some(b"two"), b"three", &[record(2, 3), record(3, 4)])
        .unwrap();
    assert_eq!(
        store
            .page(0, 32)
            .unwrap()
            .records
            .iter()
            .map(|entry| entry.cursor)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
}

#[test]
fn full_capacity_preserves_reads_and_allows_durable_state_fences() {
    let temp = Temp::new();
    let selected = Limits {
        max_records: 1,
        max_record_bytes: 8,
    };
    let mut store = Store::create_new(temp.store(), context(), selected).unwrap();
    store.publish(None, b"ready", &[record(1, 1)]).unwrap();
    assert_eq!(
        store.publish(Some(b"ready"), b"extra", &[record(2, 2)]),
        Err(Error::Refused)
    );
    assert_eq!(store.read(key(1)).unwrap(), Some(vec![1; 8]));
    assert_eq!(store.load().unwrap(), Some(b"ready".to_vec()));
    store.publish(Some(b"ready"), b"fenced", &[]).unwrap();
    store
        .publish(Some(b"fenced"), b"fenced", &[record(1, 1)])
        .unwrap();
    drop(store);
    let mut store = Store::open(temp.store(), context()).unwrap();
    assert_eq!(store.load().unwrap(), Some(b"fenced".to_vec()));
    assert_eq!(store.page(0, 1).unwrap().records[0].data, vec![1; 8]);
    let accounting = store.accounting().unwrap();
    assert_eq!(
        (accounting.generation, accounting.records, accounting.bytes),
        (3, 1, 8)
    );
    assert_eq!(accounting.limits, selected);
}

#[test]
fn expansion_preserves_full_history_state_cursors_and_generation() {
    let temp = Temp::new();
    let initial = Limits {
        max_records: 2,
        max_record_bytes: 16,
    };
    let mut store = Store::create_new(temp.store(), context(), initial).unwrap();
    store
        .publish(None, b"application fence", &[record(1, 1), record(2, 2)])
        .unwrap();
    let before = store.accounting().unwrap();
    let history = store.page(0, 32).unwrap();
    let marker = fs::read(temp.store().join("FORMAT")).unwrap();
    assert_eq!(marker.len(), 104);
    assert_eq!(&marker[..8], b"VHDS0002");
    let more_records = Limits {
        max_records: 4,
        ..initial
    };
    assert_eq!(
        store.expand_limits(more_records).unwrap(),
        Accounting {
            limits: more_records,
            ..before
        }
    );
    assert_eq!(store.page(0, 32).unwrap(), history);
    assert_eq!(store.load().unwrap(), Some(b"application fence".to_vec()));
    assert_eq!(
        store.publish(Some(b"application fence"), b"extra", &[record(3, 3)]),
        Err(Error::Refused)
    );
    let expanded = Limits {
        max_record_bytes: 32,
        ..more_records
    };
    assert_eq!(
        store.expand_limits(expanded).unwrap(),
        Accounting {
            limits: expanded,
            ..before
        }
    );
    assert_eq!(store.page(0, 32).unwrap(), history);
    let database = fs::read(temp.store().join(DB)).unwrap();
    assert_eq!(
        store.expand_limits(expanded).unwrap(),
        Accounting {
            limits: expanded,
            ..before
        }
    );
    assert_eq!(fs::read(temp.store().join(DB)).unwrap(), database);
    assert_eq!(fs::read(temp.store().join("FORMAT")).unwrap(), marker);
    assert!(!temp.store().join(JOURNAL).exists());
    drop(store);
    let mut store = Store::open(temp.store(), context()).unwrap();
    assert_eq!(
        store.accounting().unwrap(),
        Accounting {
            limits: expanded,
            ..before
        }
    );
    let configured: i64 = store
        .conn
        .pragma_query_value(None, "max_page_count", |row| row.get(0))
        .unwrap();
    assert_eq!(configured, (expanded.database_bytes() / 4096) as i64);
    assert_eq!(store.page(0, 32).unwrap(), history);
    store
        .publish(
            Some(b"application fence"),
            b"next",
            &[record(3, 3), record(4, 4)],
        )
        .unwrap();
    let after = store.accounting().unwrap();
    assert_eq!(
        (after.generation, after.tip, after.records, after.bytes),
        (2, 4, 4, 32)
    );
    for id in 1..=4 {
        assert_eq!(store.read(key(id)).unwrap(), Some(vec![id as u8; 8]));
    }
    assert_eq!(fs::read(temp.store().join("FORMAT")).unwrap(), marker);
}

#[test]
fn expansion_refuses_decreases_and_invalid_targets_without_effects() {
    let temp = Temp::new();
    let selected = Limits {
        max_records: 4,
        max_record_bytes: 32,
    };
    let mut store = Store::create_new(temp.store(), context(), selected).unwrap();
    store
        .publish(
            None,
            b"state",
            &[record(1, 1), record(2, 2), record(3, 3), record(4, 4)],
        )
        .unwrap();
    let before = store.accounting().unwrap();
    let database = fs::read(temp.store().join(DB)).unwrap();
    let marker = fs::read(temp.store().join("FORMAT")).unwrap();
    for target in [
        Limits {
            max_records: 3,
            ..selected
        },
        Limits {
            max_record_bytes: 31,
            ..selected
        },
        Limits {
            max_records: 8,
            max_record_bytes: 31,
        },
        Limits {
            max_records: 3,
            max_record_bytes: 64,
        },
        Limits {
            max_records: 0,
            ..selected
        },
        Limits {
            max_record_bytes: 0,
            ..selected
        },
        Limits {
            max_records: 1_000_001,
            ..selected
        },
        Limits {
            max_record_bytes: 8 * 1024 * 1024 * 1024 + 1,
            ..selected
        },
        Limits {
            max_records: u64::MAX,
            max_record_bytes: u64::MAX,
        },
    ] {
        assert_eq!(store.expand_limits(target), Err(Error::Refused));
        assert_eq!(store.accounting().unwrap(), before);
        assert_eq!(fs::read(temp.store().join(DB)).unwrap(), database);
        assert_eq!(fs::read(temp.store().join("FORMAT")).unwrap(), marker);
        assert!(!temp.store().join(JOURNAL).exists());
    }
    assert_eq!(store.load().unwrap(), Some(b"state".to_vec()));
}

#[test]
fn empty_store_expansion_preserves_unpublished_state() {
    let temp = Temp::new();
    let mut store = Store::create_new(
        temp.store(),
        context(),
        Limits {
            max_records: 1,
            max_record_bytes: 1,
        },
    )
    .unwrap();
    let expanded = store.expand_limits(limits()).unwrap();
    assert_eq!(
        (
            expanded.generation,
            expanded.records,
            expanded.bytes,
            expanded.limits
        ),
        (0, 0, 0, limits())
    );
    assert_eq!(store.load().unwrap(), None);
    assert!(store.page(0, 32).unwrap().records.is_empty());
    drop(store);
    let mut store = Store::open(temp.store(), context()).unwrap();
    assert_eq!(store.accounting().unwrap(), expanded);
    assert_eq!(store.load().unwrap(), None);
    store.publish(None, b"first", &[record(1, 1)]).unwrap();
    assert_eq!(store.accounting().unwrap().generation, 1);
}

#[test]
fn pages_have_local_tips_contiguous_cursors_and_detect_internal_gaps() {
    let temp = Temp::new();
    let mut store = Store::create_new(temp.store(), context(), limits()).unwrap();
    store
        .publish(None, b"first", &[record(1, 1), record(2, 2), record(3, 3)])
        .unwrap();
    let first = store.page(0, 2).unwrap();
    assert_eq!((first.tip, first.next), (3, Some(2)));
    assert_eq!(
        first
            .records
            .iter()
            .map(|entry| entry.key)
            .collect::<Vec<_>>(),
        vec![key(1), key(2)]
    );
    store
        .publish(Some(b"first"), b"second", &[record(4, 4)])
        .unwrap();
    let rest = store.page(2, 32).unwrap();
    assert_eq!((rest.tip, rest.next), (4, None));
    assert_eq!(
        rest.records
            .iter()
            .map(|entry| entry.cursor)
            .collect::<Vec<_>>(),
        vec![3, 4]
    );
    assert!(store.page(4, 1).unwrap().records.is_empty());
    assert_eq!(store.page(5, 1), Err(Error::Refused));
    store
        .conn
        .execute("DELETE FROM records WHERE cursor=2", [])
        .unwrap();
    assert_eq!(store.page(1, 2), Err(Error::Corrupt));
    assert_eq!(store.load(), Err(Error::Uncertain));
    drop(store);
    let mut store = Store::open(temp.store(), context()).unwrap();
    assert_eq!(store.page(0, 32), Err(Error::Corrupt));
}

#[test]
fn record_and_metadata_damage_never_becomes_a_successful_read() {
    for sql in [
        "UPDATE records SET data=x'0808080808080808' WHERE cursor=2",
        "UPDATE records SET cursor=5 WHERE cursor=2",
        "UPDATE records SET digest=zeroblob(32) WHERE cursor=2",
        "UPDATE records SET key=zeroblob(33) WHERE cursor=2",
        "UPDATE meta SET bytes=bytes+1 WHERE id=1",
        "UPDATE meta SET context=zeroblob(64) WHERE id=1",
        "UPDATE meta SET image=x'78' WHERE id=1",
        "UPDATE meta SET max_records=max_records+1 WHERE id=1",
        "UPDATE meta SET max_record_bytes=max_record_bytes+1 WHERE id=1",
    ] {
        let temp = Temp::new();
        let mut store = Store::create_new(temp.store(), context(), limits()).unwrap();
        store
            .publish(None, b"state", &[record(1, 1), record(2, 2), record(3, 3)])
            .unwrap();
        store.conn.execute(sql, []).unwrap();
        assert_eq!(store.page(0, 32), Err(Error::Corrupt), "{sql}");
        assert_eq!(store.accounting(), Err(Error::Uncertain));
        assert_eq!(
            store.publish(Some(b"state"), b"changed", &[]),
            Err(Error::Uncertain)
        );
    }
}

#[test]
fn point_reads_authenticate_key_cursor_context_and_payload() {
    for change in 0..4 {
        let temp = Temp::new();
        let mut store = Store::create_new(temp.store(), context(), limits()).unwrap();
        store
            .publish(None, b"state", &[record(1, 1), record(2, 2), record(3, 3)])
            .unwrap();
        let selected = match change {
            0 => {
                store
                    .conn
                    .execute(
                        "UPDATE records SET data=x'0909090909090909' WHERE cursor=2",
                        [],
                    )
                    .unwrap();
                key(2)
            }
            1 => {
                store
                    .conn
                    .execute(
                        "UPDATE records SET key=?1 WHERE cursor=2",
                        [key(9).as_slice()],
                    )
                    .unwrap();
                key(9)
            }
            2 => {
                store.conn.execute_batch("UPDATE records SET cursor=4 WHERE cursor=1; UPDATE records SET cursor=1 WHERE cursor=2; UPDATE records SET cursor=2 WHERE cursor=4").unwrap();
                key(1)
            }
            _ => {
                let foreign = Context::new([9; 32], [2; 32]).unwrap();
                let digest = format::record_digest(foreign, 2, &key(2), &[2; 8]);
                store
                    .conn
                    .execute(
                        "UPDATE records SET digest=?1 WHERE cursor=2",
                        [digest.as_slice()],
                    )
                    .unwrap();
                key(2)
            }
        };
        assert_eq!(store.read(selected), Err(Error::Corrupt));
        assert_eq!(store.read(key(3)), Err(Error::Uncertain));
    }
}

#[test]
fn legacy_v1_marker_database_and_recovery_evidence_are_refused_intact() {
    // Construct the exact prior schema, marker and digests independently of v2
    // creation. A legacy namespace must never enter SQLite recovery or migrate.
    const LEGACY_META: &str = "CREATE TABLE meta (id INTEGER PRIMARY KEY CHECK(id=1), context BLOB NOT NULL CHECK(length(context)=64), generation INTEGER NOT NULL CHECK(generation>=0), records INTEGER NOT NULL CHECK(records>=0), bytes INTEGER NOT NULL CHECK(bytes>=0), image BLOB CHECK(image IS NULL OR length(image) BETWEEN 1 AND 4194304), digest BLOB NOT NULL CHECK(length(digest)=32)) STRICT";
    let temp = Temp::new();
    let (directory, owner) = custody::create_private_directory(&temp.store()).unwrap();
    private_file(&temp.store().join("lock"), &[]);
    let mut marker = b"VHDS0001".to_vec();
    marker.extend_from_slice(context().as_bytes());
    marker.extend_from_slice(&limits().max_records.to_be_bytes());
    marker.extend_from_slice(&limits().max_record_bytes.to_be_bytes());
    marker.extend_from_slice(&format::digest(
        b"vhalla/direct-store/format/v1",
        &[&marker],
    ));
    private_file(&temp.store().join("FORMAT"), &marker);
    private_file(&temp.store().join(DB), &[]);
    let conn = format::connect(&temp.store().canonicalize().unwrap()).unwrap();
    format::configure(&conn).unwrap();
    format::prepare_journal(&temp.store(), &directory, owner).unwrap();
    conn.execute_batch("PRAGMA page_size=4096; BEGIN IMMEDIATE")
        .unwrap();
    conn.execute_batch(LEGACY_META).unwrap();
    conn.execute_batch(RECORD_SQL).unwrap();
    conn.execute_batch(INDEX_SQL).unwrap();
    conn.pragma_update(None, "application_id", APPLICATION_ID)
        .unwrap();
    conn.pragma_update(None, "user_version", 1).unwrap();
    let retained = record(1, 7);
    conn.execute(
        "INSERT INTO records VALUES (1,?1,?2,?3)",
        params![
            retained.key.as_slice(),
            retained.data,
            format::record_digest(context(), 1, &retained.key, &retained.data).as_slice()
        ],
    )
    .unwrap();
    let state = b"retained legacy state";
    let digest = format::digest(
        b"vhalla/direct-store/meta/v1",
        &[
            context().as_bytes(),
            &limits().max_records.to_be_bytes(),
            &limits().max_record_bytes.to_be_bytes(),
            &1_u64.to_be_bytes(),
            &1_u64.to_be_bytes(),
            &8_u64.to_be_bytes(),
            state,
        ],
    );
    conn.execute(
        "INSERT INTO meta VALUES (1,?1,1,1,8,?2,?3)",
        params![
            context().as_bytes().as_slice(),
            state.as_slice(),
            digest.as_slice()
        ],
    )
    .unwrap();
    conn.execute_batch("COMMIT").unwrap();
    drop(conn);
    private_file(
        &temp.store().join(JOURNAL),
        b"preserve legacy recovery evidence",
    );
    let database = fs::read(temp.store().join(DB)).unwrap();
    let journal = fs::read(temp.store().join(JOURNAL)).unwrap();
    assert_eq!(Store::locate_context(temp.store()), Err(Error::Corrupt));
    assert!(matches!(
        Store::open(temp.store(), context()),
        Err(Error::Corrupt)
    ));
    assert!(matches!(
        Store::create_new(temp.store(), context(), limits()),
        Err(Error::Refused)
    ));
    assert_eq!(fs::read(temp.store().join("FORMAT")).unwrap(), marker);
    assert_eq!(fs::read(temp.store().join(DB)).unwrap(), database);
    assert_eq!(fs::read(temp.store().join(JOURNAL)).unwrap(), journal);
}

#[test]
fn schema_changes_foreign_headers_and_wal_files_refuse_intact() {
    let temp = Temp::new();
    let store = Store::create_new(temp.store(), context(), limits()).unwrap();
    store
        .conn
        .execute_batch("CREATE TABLE foreign_state (n INTEGER)")
        .unwrap();
    drop(store);
    let original = fs::read(temp.store().join(DB)).unwrap();
    assert!(matches!(
        Store::open(temp.store(), context()),
        Err(Error::Corrupt)
    ));
    assert_eq!(fs::read(temp.store().join(DB)).unwrap(), original);

    for (offset, bytes) in [
        (18, vec![2, 2]),
        (60, vec![0; 4]),
        (60, 1_u32.to_be_bytes().to_vec()),
        (68, vec![0; 4]),
    ] {
        let temp = Temp::new();
        drop(Store::create_new(temp.store(), context(), limits()).unwrap());
        let mut file = custody::open_private_file(
            &temp.store().join(DB),
            Owner::current().unwrap(),
            limits().database_bytes(),
        )
        .unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(&bytes).unwrap();
        file.sync_all().unwrap();
        drop(file);
        private_file(
            &temp.store().join(JOURNAL),
            b"do not recover this foreign file",
        );
        let database = fs::read(temp.store().join(DB)).unwrap();
        assert!(matches!(
            Store::open(temp.store(), context()),
            Err(Error::Corrupt)
        ));
        assert_eq!(fs::read(temp.store().join(DB)).unwrap(), database);
        assert_eq!(
            fs::read(temp.store().join(JOURNAL)).unwrap(),
            b"do not recover this foreign file"
        );
    }
    let temp = Temp::new();
    drop(Store::create_new(temp.store(), context(), limits()).unwrap());
    private_file(&temp.store().join("direct.sqlite-wal"), b"retained");
    assert!(matches!(
        Store::open(temp.store(), context()),
        Err(Error::Corrupt)
    ));
    assert_eq!(
        fs::read(temp.store().join("direct.sqlite-wal")).unwrap(),
        b"retained"
    );
}

#[test]
fn live_header_changes_refuse_before_read_or_publication() {
    for (offset, bytes) in [
        (18, vec![2, 2]),
        (60, vec![0; 4]),
        (60, 1_u32.to_be_bytes().to_vec()),
        (68, vec![0; 4]),
    ] {
        for operation in 0..6 {
            let temp = Temp::new();
            let mut store = Store::create_new(temp.store(), context(), limits()).unwrap();
            store.publish(None, b"state", &[record(1, 1)]).unwrap();
            let mut file = custody::open_private_file(
                &temp.store().join(DB),
                Owner::current().unwrap(),
                limits().database_bytes(),
            )
            .unwrap();
            file.seek(SeekFrom::Start(offset)).unwrap();
            file.write_all(&bytes).unwrap();
            file.sync_all().unwrap();
            let database = fs::read(temp.store().join(DB)).unwrap();
            match operation {
                0 => assert_eq!(store.load(), Err(Error::Corrupt)),
                1 => assert_eq!(store.read(key(1)), Err(Error::Corrupt)),
                2 => assert_eq!(store.page(0, 1), Err(Error::Corrupt)),
                3 => assert_eq!(store.accounting(), Err(Error::Corrupt)),
                4 => assert_eq!(
                    store.publish(Some(b"state"), b"changed", &[]),
                    Err(Error::Corrupt)
                ),
                _ => assert_eq!(store.expand_limits(limits()), Err(Error::Corrupt)),
            }
            assert_eq!(store.load(), Err(Error::Uncertain));
            assert_eq!(fs::read(temp.store().join(DB)).unwrap(), database);
            assert!(!temp.store().join(JOURNAL).exists());
            assert!(!temp.store().join("direct.sqlite-wal").exists());
            assert!(!temp.store().join("direct.sqlite-shm").exists());
        }
    }
}

#[test]
fn unknown_and_hardlinked_files_poison_without_removing_evidence() {
    for name in ["unknown", "FORMAT.tmp", "direct.sqlite-shm"] {
        let temp = Temp::new();
        let mut store = Store::create_new(temp.store(), context(), limits()).unwrap();
        private_file(&temp.store().join(name), b"keep");
        assert_eq!(store.load(), Err(Error::Corrupt));
        assert_eq!(store.load(), Err(Error::Uncertain));
        drop(store);
        assert!(matches!(
            Store::open(temp.store(), context()),
            Err(Error::Corrupt)
        ));
        assert_eq!(fs::read(temp.store().join(name)).unwrap(), b"keep");
    }
    let temp = Temp::new();
    let mut store = Store::create_new(temp.store(), context(), limits()).unwrap();
    fs::hard_link(temp.store().join("FORMAT"), temp.0.join("marker-link")).unwrap();
    assert_eq!(store.load(), Err(Error::Corrupt));
    assert!(temp.0.join("marker-link").exists());
}

#[cfg(unix)]
#[test]
fn symlinks_and_replaced_directory_database_and_lock_are_refused() {
    use std::os::unix::fs::symlink;
    for name in ["FORMAT", "lock", DB] {
        let temp = Temp::new();
        drop(Store::create_new(temp.store(), context(), limits()).unwrap());
        let saved = temp.0.join("saved");
        fs::rename(temp.store().join(name), &saved).unwrap();
        symlink(&saved, temp.store().join(name)).unwrap();
        assert!(matches!(
            Store::open(temp.store(), context()),
            Err(Error::Corrupt)
        ));
        assert!(saved.exists());
    }
    for name in [DB, "lock"] {
        let temp = Temp::new();
        let mut store = Store::create_new(temp.store(), context(), limits()).unwrap();
        let saved = temp.0.join("saved");
        fs::rename(temp.store().join(name), &saved).unwrap();
        private_file(&temp.store().join(name), &fs::read(&saved).unwrap());
        assert_eq!(store.load(), Err(Error::Corrupt));
    }
    let temp = Temp::new();
    let mut store = Store::create_new(temp.store(), context(), limits()).unwrap();
    let moved = temp.0.join("moved");
    fs::rename(temp.store(), &moved).unwrap();
    drop(Store::create_new(temp.store(), context(), limits()).unwrap());
    assert_eq!(store.load(), Err(Error::Corrupt));
    let leaf_link = temp.0.join("link");
    symlink(temp.store(), &leaf_link).unwrap();
    assert!(matches!(
        Store::open(leaf_link, context()),
        Err(Error::Corrupt)
    ));
}

#[test]
fn locator_never_creates_repairs_or_accepts_partial_markers() {
    let temp = Temp::new();
    assert_eq!(Store::locate_context(temp.store()), Err(Error::Corrupt));
    assert!(!temp.store().exists());
    let store = Store::create_new(temp.store(), context(), limits()).unwrap();
    let database = fs::read(temp.store().join(DB)).unwrap();
    let marker = fs::read(temp.store().join("FORMAT")).unwrap();
    fs::rename(temp.store().join("FORMAT"), temp.store().join("FORMAT.tmp")).unwrap();
    assert_eq!(Store::locate_context(temp.store()), Err(Error::Corrupt));
    assert_eq!(fs::read(temp.store().join("FORMAT.tmp")).unwrap(), marker);
    fs::rename(temp.store().join("FORMAT.tmp"), temp.store().join("FORMAT")).unwrap();
    for invalid in [
        Vec::new(),
        marker[..marker.len() - 1].to_vec(),
        vec![0; FORMAT_BYTES],
    ] {
        fs::write(temp.store().join("FORMAT"), &invalid).unwrap();
        assert_eq!(Store::locate_context(temp.store()), Err(Error::Corrupt));
        assert_eq!(fs::read(temp.store().join("FORMAT")).unwrap(), invalid);
        assert_eq!(fs::read(temp.store().join(DB)).unwrap(), database);
    }
    drop(store);
}

#[test]
fn empty_and_unsealed_journals_recover_but_foreign_partial_files_stay_intact() {
    for cold in [false, true] {
        let temp = Temp::new();
        let mut store = Store::create_new(temp.store(), context(), limits()).unwrap();
        store.publish(None, b"state", &[record(1, 1)]).unwrap();
        let accounting = store.accounting().unwrap();
        drop(store);
        let mut journal = if cold { vec![0; 512] } else { Vec::new() };
        if cold {
            let pages = (fs::metadata(temp.store().join(DB)).unwrap().len() / 4096) as u32;
            journal[16..20].copy_from_slice(&pages.to_be_bytes());
            journal[20..24].copy_from_slice(&512_u32.to_be_bytes());
            journal[24..28].copy_from_slice(&4096_u32.to_be_bytes());
        }
        private_file(&temp.store().join(JOURNAL), &journal);
        let mut store = Store::open(temp.store(), context()).unwrap();
        assert_eq!(store.accounting().unwrap(), accounting);
        assert_eq!(store.load().unwrap(), Some(b"state".to_vec()));
        store.publish(Some(b"state"), b"next", &[]).unwrap();
        assert!(!temp.store().join(JOURNAL).exists());
    }
    for journal in [vec![0; 8], b"foreign journal".to_vec(), vec![5; 512]] {
        let temp = Temp::new();
        drop(Store::create_new(temp.store(), context(), limits()).unwrap());
        private_file(&temp.store().join(JOURNAL), &journal);
        let database = fs::read(temp.store().join(DB)).unwrap();
        assert!(matches!(
            Store::open(temp.store(), context()),
            Err(Error::Corrupt)
        ));
        assert_eq!(fs::read(temp.store().join(JOURNAL)).unwrap(), journal);
        assert_eq!(fs::read(temp.store().join(DB)).unwrap(), database);
    }
}

#[test]
fn ordinary_readers_refuse_new_journals_before_sqlite_can_recover_them() {
    for operation in 0..8 {
        let temp = Temp::new();
        let mut store = Store::create_new(temp.store(), context(), limits()).unwrap();
        store.publish(None, b"state", &[record(1, 1)]).unwrap();
        let database = fs::read(temp.store().join(DB)).unwrap();
        let mut journal = vec![0; 512];
        if operation >= 4 {
            journal[..8].copy_from_slice(&[0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7]);
        }
        journal[16..20].copy_from_slice(&((database.len() / 4096) as u32).to_be_bytes());
        journal[20..24].copy_from_slice(&512_u32.to_be_bytes());
        journal[24..28].copy_from_slice(&4096_u32.to_be_bytes());
        private_file(&temp.store().join(JOURNAL), &journal);
        match operation % 4 {
            0 => assert_eq!(store.load(), Err(Error::Corrupt)),
            1 => assert_eq!(store.read(key(1)), Err(Error::Corrupt)),
            2 => assert_eq!(store.page(0, 1), Err(Error::Corrupt)),
            _ => assert_eq!(store.accounting(), Err(Error::Corrupt)),
        }
        assert_eq!(store.load(), Err(Error::Uncertain));
        assert_eq!(fs::read(temp.store().join(JOURNAL)).unwrap(), journal);
        assert_eq!(fs::read(temp.store().join(DB)).unwrap(), database);
    }
}

#[test]
fn injected_uncertainty_stays_poisoned_until_exact_reopen() {
    for point in [
        Point::Begun,
        Point::JournalPrepared,
        Point::RecordInserted,
        Point::StateUpdated,
        Point::Committed,
        Point::Checked,
    ] {
        let temp = Temp::new();
        let mut store = Store::create_new(temp.store(), context(), limits()).unwrap();
        store.publish(None, b"old", &[record(1, 1)]).unwrap();
        store.fault = Some(point);
        assert_eq!(
            store.publish(Some(b"old"), b"new", &[record(2, 2)]),
            Err(Error::Uncertain)
        );
        assert_eq!(store.load(), Err(Error::Uncertain));
        assert_eq!(store.read(key(1)), Err(Error::Uncertain));
        assert_eq!(store.page(0, 1), Err(Error::Uncertain));
        assert_eq!(store.accounting(), Err(Error::Uncertain));
        assert_eq!(
            store.publish(Some(b"old"), b"third", &[]),
            Err(Error::Uncertain)
        );
        drop(store);
        let mut store = Store::open(temp.store(), context()).unwrap();
        let committed = matches!(point, Point::Committed | Point::Checked);
        assert_eq!(
            store.load().unwrap(),
            Some(if committed {
                b"new".to_vec()
            } else {
                b"old".to_vec()
            })
        );
        assert_eq!(store.read(key(2)).unwrap(), committed.then_some(vec![2; 8]));
        assert_eq!(
            store.accounting().unwrap().generation,
            if committed { 2 } else { 1 }
        );
    }
}

#[test]
fn expansion_uncertainty_requires_reopen_before_an_exact_target_retry() {
    for point in [
        Point::Begun,
        Point::BoundRaised,
        Point::JournalPrepared,
        Point::LimitsUpdated,
        Point::Committed,
        Point::Checked,
    ] {
        let temp = Temp::new();
        let mut store = Store::create_new(temp.store(), context(), limits()).unwrap();
        store
            .publish(None, b"exact state", &[record(1, 1), record(2, 2)])
            .unwrap();
        let before = store.accounting().unwrap();
        let history = store.page(0, 32).unwrap();
        let marker = fs::read(temp.store().join("FORMAT")).unwrap();
        store.fault = Some(point);
        assert_eq!(
            store.expand_limits(expanded_limits()),
            Err(Error::Uncertain),
            "{point:?}"
        );
        assert_eq!(store.load(), Err(Error::Uncertain));
        assert_eq!(store.read(key(1)), Err(Error::Uncertain));
        assert_eq!(store.page(0, 32), Err(Error::Uncertain));
        assert_eq!(store.accounting(), Err(Error::Uncertain));
        assert_eq!(
            store.publish(Some(b"exact state"), b"changed", &[]),
            Err(Error::Uncertain)
        );
        assert_eq!(
            store.expand_limits(expanded_limits()),
            Err(Error::Uncertain)
        );
        drop(store);
        let mut store = Store::open(temp.store(), context()).unwrap();
        let committed = matches!(point, Point::Committed | Point::Checked);
        let expected_limits = if committed {
            expanded_limits()
        } else {
            limits()
        };
        assert_eq!(
            store.accounting().unwrap(),
            Accounting {
                limits: expected_limits,
                ..before
            }
        );
        let configured: i64 = store
            .conn
            .pragma_query_value(None, "max_page_count", |row| row.get(0))
            .unwrap();
        assert_eq!(configured, (expected_limits.database_bytes() / 4096) as i64);
        assert_eq!(store.page(0, 32).unwrap(), history);
        assert_eq!(store.load().unwrap(), Some(b"exact state".to_vec()));
        assert_eq!(
            store.expand_limits(expanded_limits()).unwrap(),
            Accounting {
                limits: expanded_limits(),
                ..before
            }
        );
        assert_eq!(fs::read(temp.store().join("FORMAT")).unwrap(), marker);
    }
}

#[test]
fn crash_child() {
    let Some(path) = std::env::var_os("VHALLA_DIRECT_STORE_CRASH_HOME") else {
        return;
    };
    let marker = PathBuf::from(std::env::var_os("VHALLA_DIRECT_STORE_CRASH_MARKER").unwrap());
    let point = match std::env::var("VHALLA_DIRECT_STORE_CRASH_POINT")
        .unwrap()
        .as_str()
    {
        "bound" => Point::BoundRaised,
        "journal" => Point::JournalPrepared,
        "record" => Point::RecordInserted,
        "state" => Point::StateUpdated,
        "limits" => Point::LimitsUpdated,
        "commit" => Point::Committed,
        "checked" => Point::Checked,
        _ => panic!("unknown fixture boundary"),
    };
    let mut store = Store::open(path, context()).unwrap();
    store.conn.execute_batch("PRAGMA cache_size=-64").unwrap();
    store.crash = Some((point, marker));
    if std::env::var_os("VHALLA_DIRECT_STORE_CRASH_EXPAND").is_some() {
        store.expand_limits(expanded_limits()).unwrap();
        panic!("expansion crash boundary not reached");
    }
    let records: Vec<_> = (1..=8)
        .map(|id| Record::new(key(id), &vec![id as u8; MAX_RECORD_BYTES]).unwrap())
        .collect();
    store
        .publish(
            Some(&vec![1; MAX_STATE_BYTES]),
            &vec![2; MAX_STATE_BYTES],
            &records,
        )
        .unwrap();
    panic!("crash boundary not reached");
}

#[test]
fn killed_transactions_recover_an_entire_old_or_new_publication() {
    for point in ["journal", "record", "state", "commit"] {
        let temp = Temp::new();
        let mut store = Store::create_new(temp.store(), context(), limits()).unwrap();
        store.publish(None, &vec![1; MAX_STATE_BYTES], &[]).unwrap();
        drop(store);
        let marker = temp.0.join("ready");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "backend::tests::crash_child", "--nocapture"])
            .env("VHALLA_DIRECT_STORE_CRASH_HOME", temp.store())
            .env("VHALLA_DIRECT_STORE_CRASH_MARKER", &marker)
            .env("VHALLA_DIRECT_STORE_CRASH_POINT", point)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while !marker.exists() {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("child failed at {point}: {status}");
            }
            if Instant::now() > deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("child timeout at {point}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        child.kill().unwrap();
        child.wait().unwrap();
        // Observe the real retained journal after abrupt process death and
        // before opening SQLite. This proves which recovery path is exercised.
        let journal = temp.store().join(JOURNAL);
        match point {
            "journal" => assert_eq!(fs::metadata(&journal).unwrap().len(), 0),
            "record" | "state" => {
                let mut header = [0; 8];
                File::open(&journal)
                    .unwrap()
                    .read_exact(&mut header)
                    .unwrap();
                let expected = if point == "record" {
                    [0; 8]
                } else {
                    [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7]
                };
                assert_eq!(header, expected, "journal at {point}");
            }
            "commit" => assert!(!journal.exists()),
            _ => unreachable!(),
        }
        let mut store = Store::open(temp.store(), context()).unwrap();
        let committed = point == "commit";
        assert_eq!(
            store.load().unwrap(),
            Some(vec![if committed { 2 } else { 1 }; MAX_STATE_BYTES])
        );
        assert_eq!(
            store.accounting().unwrap().records,
            if committed { 8 } else { 0 }
        );
        for id in 1..=8 {
            assert_eq!(
                store.read(key(id)).unwrap(),
                committed.then_some(vec![id as u8; MAX_RECORD_BYTES])
            );
        }
    }
}

#[hegel::test(test_cases = 64, suppress_health_check = [HealthCheck::TooSlow])]
fn stateful_cas_retries_capacity_and_reopen_match_the_model(tc: hegel::TestCase) {
    use hegel::generators as gs;
    let temp = Temp::new();
    let mut selected = Limits {
        max_records: 4,
        max_record_bytes: 32,
    };
    let mut store = Store::create_new(temp.store(), context(), selected).unwrap();
    let mut model: Vec<Record> = Vec::new();
    let mut state: Option<Vec<u8>> = None;
    let mut generation = 0;
    let steps = tc.draw(gs::integers::<usize>().min_value(4).max_value(14));
    for step in 0..steps {
        match tc.draw(gs::integers::<u8>().max_value(5)) {
            0 | 1 => {
                let id = tc.draw(gs::integers::<u64>().min_value(1).max_value(6));
                let byte = tc.draw(gs::integers::<u8>().max_value(2));
                let candidate = record(id, byte);
                let expected = state.as_deref();
                let next = vec![step as u8 + 1];
                let existing = model.iter().find(|old| old.key == candidate.key);
                let outcome = store.publish(expected, &next, std::slice::from_ref(&candidate));
                if existing.is_some_and(|old| old.data != candidate.data) {
                    assert_eq!(outcome, Err(Error::Conflict));
                } else if existing.is_none()
                    && (model.len() as u64 + 1 > selected.max_records
                        || (model.len() as u64 + 1) * 8 > selected.max_record_bytes)
                {
                    assert_eq!(outcome, Err(Error::Refused));
                } else {
                    outcome.unwrap();
                    if existing.is_none() {
                        model.push(candidate);
                    }
                    state = Some(next);
                    generation += 1;
                }
            }
            2 => {
                assert_eq!(
                    store.publish(Some(b"never current"), b"bad", &[]),
                    Err(Error::Conflict)
                );
            }
            3 => {
                drop(store);
                store = Store::open(temp.store(), context()).unwrap();
            }
            4 => {
                let next = vec![step as u8 + 1];
                store.publish(state.as_deref(), &next, &[]).unwrap();
                state = Some(next);
                generation += 1;
            }
            _ => {
                let target = Limits {
                    max_records: tc.draw(gs::integers::<u64>().min_value(1).max_value(6)),
                    max_record_bytes: tc.draw(gs::integers::<u64>().min_value(8).max_value(48)),
                };
                let outcome = store.expand_limits(target);
                if target.max_records < selected.max_records
                    || target.max_record_bytes < selected.max_record_bytes
                {
                    assert_eq!(outcome, Err(Error::Refused));
                } else {
                    assert_eq!(outcome.unwrap().limits, target);
                    selected = target;
                }
            }
        }
        assert_eq!(store.load().unwrap(), state);
        let accounting = store.accounting().unwrap();
        assert_eq!(accounting.limits, selected);
        assert_eq!(
            (accounting.generation, accounting.records, accounting.bytes),
            (generation, model.len() as u64, model.len() as u64 * 8)
        );
        let page = store.page(0, 32).unwrap();
        assert_eq!(page.tip, model.len() as u64);
        assert_eq!(page.records.len(), model.len());
        assert_eq!(page.next, None);
        for (offset, (entry, expected)) in page.records.iter().zip(&model).enumerate() {
            assert_eq!(
                (entry.cursor, entry.key, entry.data.as_slice()),
                (offset as u64 + 1, expected.key, expected.as_bytes())
            );
        }
    }
}

#[test]
fn killed_expansion_recovers_entire_old_or_new_limits_without_touching_history() {
    for point in ["bound", "journal", "limits", "commit", "checked"] {
        let temp = Temp::new();
        let mut store = Store::create_new(temp.store(), context(), limits()).unwrap();
        store
            .publish(
                None,
                &vec![1; MAX_STATE_BYTES],
                &[record(1, 1), record(2, 2)],
            )
            .unwrap();
        let before = store.accounting().unwrap();
        let history = store.page(0, 32).unwrap();
        let format = fs::read(temp.store().join("FORMAT")).unwrap();
        drop(store);
        let marker = temp.0.join("ready");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "backend::tests::crash_child", "--nocapture"])
            .env("VHALLA_DIRECT_STORE_CRASH_HOME", temp.store())
            .env("VHALLA_DIRECT_STORE_CRASH_MARKER", &marker)
            .env("VHALLA_DIRECT_STORE_CRASH_POINT", point)
            .env("VHALLA_DIRECT_STORE_CRASH_EXPAND", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while !marker.exists() {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("expansion child failed at {point}: {status}");
            }
            if Instant::now() > deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("expansion child timeout at {point}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        child.kill().unwrap();
        child.wait().unwrap();
        let journal = temp.store().join(JOURNAL);
        match point {
            "journal" => assert_eq!(fs::metadata(&journal).unwrap().len(), 0),
            "limits" => {
                let mut header = [0; 8];
                File::open(&journal)
                    .unwrap()
                    .read_exact(&mut header)
                    .unwrap();
                assert_eq!(header, [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7]);
            }
            _ => assert!(!journal.exists()),
        }
        let mut store = Store::open(temp.store(), context()).unwrap();
        let committed = matches!(point, "commit" | "checked");
        let recovered = if committed {
            expanded_limits()
        } else {
            limits()
        };
        assert_eq!(
            store.accounting().unwrap(),
            Accounting {
                limits: recovered,
                ..before
            }
        );
        assert_eq!(store.load().unwrap(), Some(vec![1; MAX_STATE_BYTES]));
        assert_eq!(store.page(0, 32).unwrap(), history);
        assert_eq!(fs::read(temp.store().join("FORMAT")).unwrap(), format);
        assert_eq!(
            store.expand_limits(expanded_limits()).unwrap(),
            Accounting {
                limits: expanded_limits(),
                ..before
            }
        );
    }
}
