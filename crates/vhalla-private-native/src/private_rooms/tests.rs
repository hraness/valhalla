use super::*;
use std::{
    os::unix::fs::{symlink, PermissionsExt},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

fn context() -> Context {
    Context::new([1; 32], [2; 32], [3; 32], [4; 32]).unwrap()
}
fn limits() -> Limits {
    Limits {
        max_records: 1000,
        max_record_bytes: 16 * 1024 * 1024,
    }
}
fn home() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "vhalla-private-native-{}-{stamp}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}
fn record(key: RecordKey, n: u8) -> Record {
    Record::new(key, &[n; 80]).unwrap()
}

#[test]
fn whole_image_cas_indexed_reads_and_immutable_collisions() {
    let path = home();
    let ctx = context();
    let mut store = NativePrivateStore::create_new(&path, ctx, limits()).unwrap();
    assert_eq!(store.load(ctx).unwrap(), None);
    assert_eq!(
        store.read(ctx, RecordKey::Operation([9; 16])).unwrap(),
        None
    );
    store.publish(ctx, None, &[5; 40], &[]).unwrap();
    let first = record(RecordKey::Outbox(1), 7);
    let index = record(RecordKey::Operation([9; 16]), 8);
    store
        .publish(
            ctx,
            Some(&[5; 40]),
            &[6; 40],
            &[first.clone(), index.clone()],
        )
        .unwrap();
    assert_eq!(store.load(ctx).unwrap(), Some(vec![6; 40]));
    assert_eq!(
        store.read(ctx, first.key).unwrap(),
        Some(first.bytes.clone())
    );
    assert_eq!(
        store.read(ctx, index.key).unwrap(),
        Some(index.bytes.clone())
    );
    assert_eq!(
        store.publish(ctx, Some(&[5; 40]), &[8; 40], &[]),
        Err(Error::Conflict)
    );
    // Preflight every collision before inserting even the first offered record.
    let new = record(RecordKey::Outbox(2), 5);
    let collision = record(index.key, 4);
    assert_eq!(
        store.publish(ctx, Some(&[6; 40]), &[8; 40], &[new.clone(), collision]),
        Err(Error::Conflict)
    );
    assert_eq!(store.read(ctx, new.key).unwrap(), None);
    assert_eq!(store.load(ctx).unwrap(), Some(vec![6; 40]));
    drop(store);
    let mut reopened = NativePrivateStore::open(&path, ctx).unwrap();
    assert_eq!(reopened.read(ctx, index.key).unwrap(), Some(index.bytes));
    assert_eq!(
        reopened.publish(ctx, None, &[3; 40], &[]),
        Err(Error::Conflict)
    );
}

#[test]
fn three_record_control_transaction_preflights_all_keys_and_preserves_old_encoding() {
    assert!(Record::new(RecordKey::Control(0), &[3; 40]).is_err());
    assert_eq!(
        RecordKey::Control(1).encode().unwrap(),
        vec![5, 0, 0, 0, 0, 0, 0, 0, 1]
    );
    assert_eq!(
        RecordKey::Outbox(1).encode().unwrap(),
        vec![1, 0, 0, 0, 0, 0, 0, 0, 1]
    );
    assert_eq!(
        RecordKey::Sent([9; 32]).encode().unwrap(),
        [vec![6], vec![9; 32]].concat()
    );
    assert!(RecordKey::Sent([0; 32]).encode().is_err());
    let acceptance = RecordKey::Acceptance {
        outbox: 1,
        recipient: [7; 32],
    }
    .encode()
    .unwrap();
    assert_eq!(acceptance.len(), 33);
    assert_eq!(acceptance[0], 7);
    assert_ne!(acceptance[1..], [0; 32]);
    assert_ne!(
        RecordKey::Acceptance {
            outbox: 2,
            recipient: [7; 32],
        }
        .encode()
        .unwrap(),
        acceptance
    );
    assert_ne!(
        RecordKey::Acceptance {
            outbox: 1,
            recipient: [8; 32],
        }
        .encode()
        .unwrap(),
        acceptance
    );
    assert!(RecordKey::Acceptance {
        outbox: 0,
        recipient: [7; 32],
    }
    .encode()
    .is_err());
    assert!(RecordKey::Acceptance {
        outbox: 1,
        recipient: [0; 32],
    }
    .encode()
    .is_err());
    let path = home();
    let ctx = context();
    let mut store = NativePrivateStore::create_new(&path, ctx, limits()).unwrap();
    store.publish(ctx, None, &[1; 40], &[]).unwrap();
    let records = [
        record(RecordKey::Control(1), 3),
        record(RecordKey::Outbox(1), 4),
        record(RecordKey::Operation([8; 16]), 5),
    ];
    for duplicate in [0, 1] {
        let offered = [
            records[0].clone(),
            records[1].clone(),
            records[duplicate].clone(),
        ];
        assert_eq!(
            store.publish(ctx, Some(&[1; 40]), &[2; 40], &offered),
            Err(Error::Refused)
        );
        assert_eq!(store.load(ctx).unwrap(), Some(vec![1; 40]));
        for record in &records {
            assert_eq!(store.read(ctx, record.key()).unwrap(), None);
        }
    }
    let mut four = records.to_vec();
    four.push(record(RecordKey::Inbox(1), 6));
    assert_eq!(
        store.publish(ctx, Some(&[1; 40]), &[2; 40], &four),
        Err(Error::Refused)
    );
    store
        .publish(ctx, Some(&[1; 40]), &[2; 40], &records)
        .unwrap();
    drop(store);
    let mut store = NativePrivateStore::open(&path, ctx).unwrap();
    for record in &records {
        assert_eq!(
            store.read(ctx, record.key()).unwrap().as_deref(),
            Some(record.as_bytes())
        );
    }
    let equal_third = [
        record(RecordKey::Control(2), 7),
        record(RecordKey::Outbox(2), 8),
        records[2].clone(),
    ];
    assert_eq!(
        store.publish(ctx, Some(&[2; 40]), &[3; 40], &equal_third),
        Err(Error::Conflict)
    );
    assert_eq!(store.read(ctx, RecordKey::Control(2)).unwrap(), None);
    assert_eq!(store.read(ctx, RecordKey::Outbox(2)).unwrap(), None);
    assert_eq!(store.load(ctx).unwrap(), Some(vec![2; 40]));
    let collision = [
        record(RecordKey::Control(2), 7),
        record(RecordKey::Outbox(2), 8),
        record(RecordKey::Operation([8; 16]), 9),
    ];
    assert_eq!(
        store.publish(ctx, Some(&[2; 40]), &[3; 40], &collision),
        Err(Error::Conflict)
    );
    assert_eq!(store.read(ctx, RecordKey::Control(2)).unwrap(), None);
    assert_eq!(store.read(ctx, RecordKey::Outbox(2)).unwrap(), None);
    assert_eq!(store.load(ctx).unwrap(), Some(vec![2; 40]));
}

#[test]
fn bounds_capacity_and_full_scope_refuse_without_effects() {
    let path = home();
    let ctx = context();
    let mut store = NativePrivateStore::create_new(
        &path,
        ctx,
        Limits {
            max_records: 1,
            max_record_bytes: 80,
        },
    )
    .unwrap();
    assert!(Context::new([0; 32], [2; 32], [3; 32], [4; 32]).is_err());
    assert!(Record::new(RecordKey::Inbox(0), &[3; 40]).is_err());
    assert!(Record::new(RecordKey::Operation([0; 16]), &[3; 40]).is_err());
    assert!(Record::new(RecordKey::Received([0; 32]), &[3; 40]).is_err());
    assert!(Record::new(RecordKey::Inbox(1), &vec![3; MAX_RECORD_BYTES + 1]).is_err());
    assert_eq!(store.publish(ctx, None, &[1; 39], &[]), Err(Error::Refused));
    assert_eq!(
        store.publish(ctx, None, &vec![1; MAX_IMAGE_BYTES + 1], &[]),
        Err(Error::Refused)
    );
    assert_eq!(
        store.publish(
            ctx,
            None,
            &[1; 40],
            &[
                record(RecordKey::Inbox(1), 3),
                record(RecordKey::Inbox(2), 4)
            ]
        ),
        Err(Error::Refused)
    );
    assert_eq!(store.load(ctx).unwrap(), None);
    let foreign = Context::new([1; 32], [2; 32], [3; 32], [5; 32]).unwrap();
    assert_eq!(
        store.publish(foreign, None, &[1; 40], &[]),
        Err(Error::Refused)
    );
    store
        .publish(ctx, None, &[1; 40], &[record(RecordKey::Inbox(1), 3)])
        .unwrap();
    assert_eq!(
        store.publish(
            ctx,
            Some(&[1; 40]),
            &[2; 40],
            &[record(RecordKey::Inbox(2), 4)]
        ),
        Err(Error::Refused)
    );
    assert_eq!(store.load(ctx).unwrap(), Some(vec![1; 40]));
    drop(store);
    let old = fs::read(path.join(DB)).unwrap();
    assert!(matches!(
        NativePrivateStore::open(&path, foreign),
        Err(Error::Corrupt)
    ));
    assert_eq!(fs::read(path.join(DB)).unwrap(), old);
}

#[test]
fn errors_before_and_after_commit_latch_then_reopen_exact_state() {
    for point in [
        Point::Begun,
        Point::RecordInserted,
        Point::StateUpdated,
        Point::Committed,
        Point::Checked,
    ] {
        let path = home();
        let ctx = context();
        let mut store = NativePrivateStore::create_new(&path, ctx, limits()).unwrap();
        store.publish(ctx, None, &[1; 40], &[]).unwrap();
        store.fault = Some(point);
        let data = record(RecordKey::Outbox(1), 3);
        let index = record(RecordKey::Operation([8; 16]), 4);
        assert_eq!(
            store.publish(
                ctx,
                Some(&[1; 40]),
                &[2; 40],
                &[data.clone(), index.clone()]
            ),
            Err(Error::Uncertain)
        );
        assert_eq!(store.load(ctx), Err(Error::Uncertain));
        assert_eq!(store.read(ctx, data.key), Err(Error::Uncertain));
        drop(store);
        let mut reopened = NativePrivateStore::open(&path, ctx).unwrap();
        let committed = matches!(point, Point::Committed | Point::Checked);
        assert_eq!(
            reopened.load(ctx).unwrap(),
            Some(vec![if committed { 2 } else { 1 }; 40])
        );
        assert_eq!(
            reopened.read(ctx, data.key).unwrap(),
            committed.then_some(data.bytes)
        );
        assert_eq!(
            reopened.read(ctx, index.key).unwrap(),
            committed.then_some(index.bytes)
        );
    }
}

#[test]
fn custody_missing_database_foreign_schema_and_corrupt_record_fail_closed() {
    let path = home();
    let ctx = context();
    let mut store = NativePrivateStore::create_new(&path, ctx, limits()).unwrap();
    assert!(matches!(
        NativePrivateStore::open(&path, ctx),
        Err(Error::Refused)
    ));
    store
        .publish(
            ctx,
            None,
            &[1; 40],
            &[record(RecordKey::Received([7; 32]), 4)],
        )
        .unwrap();
    store
        .conn
        .execute("UPDATE records SET data=?1", [&[9u8; 80][..]])
        .unwrap();
    assert_eq!(
        store.read(ctx, RecordKey::Received([7; 32])),
        Err(Error::Corrupt)
    );
    assert_eq!(store.load(ctx), Err(Error::Uncertain));
    drop(store);
    let mut store = NativePrivateStore::open(&path, ctx).unwrap();
    assert_eq!(
        store.read(ctx, RecordKey::Received([7; 32])),
        Err(Error::Corrupt)
    );
    drop(store);
    fs::rename(path.join(DB), path.with_extension("preserved-db")).unwrap();
    assert!(matches!(
        NativePrivateStore::open(&path, ctx),
        Err(Error::Corrupt)
    ));
    assert!(NativePrivateStore::create_new(&path, ctx, limits()).is_err());
    assert!(!path.join(DB).exists());

    let path = home();
    let store = NativePrivateStore::create_new(&path, ctx, limits()).unwrap();
    store
        .conn
        .execute_batch("CREATE TABLE foreign_table (a BLOB)")
        .unwrap();
    drop(store);
    assert!(matches!(
        NativePrivateStore::open(&path, ctx),
        Err(Error::Corrupt)
    ));
}

#[test]
fn path_permissions_symlinks_partial_initialization_and_database_header_refuse() {
    let ctx = context();
    let path = home();
    let store = NativePrivateStore::create_new(&path, ctx, limits()).unwrap();
    drop(store);
    let saved = path.with_extension("target");
    fs::rename(path.join(DB), &saved).unwrap();
    symlink(&saved, path.join(DB)).unwrap();
    let exact = fs::read(&saved).unwrap();
    assert!(NativePrivateStore::open(&path, ctx).is_err());
    assert_eq!(fs::read(&saved).unwrap(), exact);
    let path = home();
    let store = NativePrivateStore::create_new(&path, ctx, limits()).unwrap();
    drop(store);
    fs::set_permissions(path.join(DB), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(NativePrivateStore::open(&path, ctx).is_err());
    let path = home();
    let store = NativePrivateStore::create_new(&path, ctx, limits()).unwrap();
    drop(store);
    fs::write(path.join(DB), [0u8; 4096]).unwrap();
    assert!(NativePrivateStore::open(&path, ctx).is_err());
    assert_eq!(fs::read(path.join(DB)).unwrap(), vec![0; 4096]);
    let path = home();
    let store = NativePrivateStore::create_new(&path, ctx, limits()).unwrap();
    drop(store);
    fs::rename(path.join("FORMAT"), path.join("FORMAT.tmp")).unwrap();
    assert!(NativePrivateStore::open(&path, ctx).is_err());
    assert!(path.join("FORMAT.tmp").exists());
}

#[test]
fn metadata_and_blob_shape_checks_precede_cloning() {
    let path = home();
    let ctx = context();
    let mut store = NativePrivateStore::create_new(&path, ctx, limits()).unwrap();
    store.publish(ctx, None, &[1; 40], &[]).unwrap();
    store
        .conn
        .execute("UPDATE meta SET image=?1", [&[2u8; 40][..]])
        .unwrap();
    assert_eq!(store.load(ctx), Err(Error::Corrupt));
    drop(store);
    assert!(matches!(
        NativePrivateStore::open(&path, ctx),
        Err(Error::Corrupt)
    ));
}

#[test]
fn orphan_record_never_turns_an_empty_image_into_fresh_permission() {
    let path = home();
    let ctx = context();
    let store = NativePrivateStore::create_new(&path, ctx, limits()).unwrap();
    let key = RecordKey::Operation([7; 16]).encode().unwrap();
    let data = [3; 40];
    store
        .conn
        .execute(
            "INSERT INTO records VALUES (?1,?2,?3)",
            params![
                key,
                data.as_slice(),
                record_digest(ctx, &key, &data).as_slice()
            ],
        )
        .unwrap();
    drop(store);
    let preserved = fs::read(path.join(DB)).unwrap();
    assert!(matches!(
        NativePrivateStore::open(&path, ctx),
        Err(Error::Corrupt)
    ));
    assert_eq!(fs::read(path.join(DB)).unwrap(), preserved);
}

#[test]
fn oversized_stored_blob_is_rejected_before_rust_copy() {
    let path = home();
    let ctx = context();
    let mut store = NativePrivateStore::create_new(&path, ctx, limits()).unwrap();
    store
        .publish(ctx, None, &[1; 40], &[record(RecordKey::Inbox(1), 3)])
        .unwrap();
    // Simulate invalid stored bytes without claiming protection against valid
    // malicious SQL changes; this specifically qualifies bounded read decoding.
    store
        .conn
        .execute_batch("PRAGMA ignore_check_constraints=ON")
        .unwrap();
    store
        .conn
        .execute(
            "UPDATE records SET data=?1",
            [vec![0; MAX_RECORD_BYTES + 1]],
        )
        .unwrap();
    assert_eq!(store.read(ctx, RecordKey::Inbox(1)), Err(Error::Corrupt));
    assert_eq!(store.load(ctx), Err(Error::Uncertain));
}

#[test]
fn indexed_history_survives_many_operations_without_lifetime_memory_map() {
    let path = home();
    let ctx = context();
    let mut store = NativePrivateStore::create_new(&path, ctx, limits()).unwrap();
    let mut image = vec![1; 40];
    store.publish(ctx, None, &image, &[]).unwrap();
    for n in 1..=80u64 {
        let mut next = vec![2; 40];
        next[..8].copy_from_slice(&n.to_be_bytes());
        store
            .publish(
                ctx,
                Some(&image),
                &next,
                &[record(RecordKey::Outbox(n), n as u8)],
            )
            .unwrap();
        image = next;
    }
    drop(store);
    let mut store = NativePrivateStore::open(&path, ctx).unwrap();
    for n in [80, 1, 40, 79] {
        assert_eq!(
            store.read(ctx, RecordKey::Outbox(n)).unwrap(),
            Some(vec![n as u8; 80])
        );
    }
    assert_eq!(store.read(ctx, RecordKey::Outbox(81)).unwrap(), None);
    assert_eq!(store.load(ctx).unwrap(), Some(image));
}

#[test]
fn crash_child() {
    let Some(path) = std::env::var_os("VHALLA_PRIVATE_TEST_HOME") else {
        return;
    };
    let marker = PathBuf::from(std::env::var_os("VHALLA_PRIVATE_TEST_MARKER").unwrap());
    let point = match std::env::var("VHALLA_PRIVATE_TEST_POINT").unwrap().as_str() {
        "begin" => Point::Begun,
        "record" => Point::RecordInserted,
        "state" => Point::StateUpdated,
        "commit" => Point::Committed,
        "checked" => Point::Checked,
        _ => panic!("invalid fixture"),
    };
    let ctx = context();
    let mut store = NativePrivateStore::open(path, ctx).unwrap();
    // Force actual rollback-journal/database page spills before COMMIT.
    store.conn.execute_batch("PRAGMA cache_size=-64").unwrap();
    store.crash = Some((point, marker));
    let records = [
        Record::new(RecordKey::Inbox(1), &vec![3; MAX_RECORD_BYTES]).unwrap(),
        Record::new(RecordKey::Received([9; 32]), &vec![4; MAX_RECORD_BYTES]).unwrap(),
        Record::new(RecordKey::Control(1), &vec![5; MAX_RECORD_BYTES]).unwrap(),
    ];
    store
        .publish(
            ctx,
            Some(&vec![1; MAX_IMAGE_BYTES]),
            &vec![2; MAX_IMAGE_BYTES],
            &records,
        )
        .unwrap();
    panic!("selected crash boundary was not reached");
}

#[test]
fn sigkill_transaction_boundaries_recover_all_or_nothing() {
    for point in ["begin", "record", "state", "commit", "checked"] {
        let path = home();
        let ctx = context();
        let mut store = NativePrivateStore::create_new(&path, ctx, limits()).unwrap();
        store
            .publish(ctx, None, &vec![1; MAX_IMAGE_BYTES], &[])
            .unwrap();
        drop(store);
        let marker = path.with_extension("ready");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "private_rooms::tests::crash_child",
                "--nocapture",
            ])
            .env("VHALLA_PRIVATE_TEST_HOME", &path)
            .env("VHALLA_PRIVATE_TEST_MARKER", &marker)
            .env("VHALLA_PRIVATE_TEST_POINT", point)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        while !marker.exists() {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("fixture child failed before {point}: {status}");
            }
            if Instant::now() > deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("fixture deadline {point}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        child.kill().unwrap();
        child.wait().unwrap();
        let mut store = NativePrivateStore::open(&path, ctx).unwrap();
        let committed = matches!(point, "commit" | "checked");
        assert_eq!(
            store.load(ctx).unwrap(),
            Some(vec![if committed { 2 } else { 1 }; MAX_IMAGE_BYTES])
        );
        assert_eq!(
            store.read(ctx, RecordKey::Inbox(1)).unwrap(),
            committed.then_some(vec![3; MAX_RECORD_BYTES])
        );
        assert_eq!(
            store.read(ctx, RecordKey::Received([9; 32])).unwrap(),
            committed.then_some(vec![4; MAX_RECORD_BYTES])
        );
        assert_eq!(
            store.read(ctx, RecordKey::Control(1)).unwrap(),
            committed.then_some(vec![5; MAX_RECORD_BYTES])
        );
    }
}

#[test]
fn locator_is_only_a_bounded_hint_and_never_repairs_partial_state() {
    let path = home();
    let ctx = context();
    let store = NativePrivateStore::create_new(&path, ctx, limits()).unwrap();
    // Even while the writer is held and no kernel image exists, this is merely
    // a FORMAT hint. It neither claims initialization nor acquires/recover SQLite.
    assert_eq!(NativePrivateStore::locate_context(&path).unwrap(), ctx);
    let original = fs::read(path.join("FORMAT")).unwrap();
    let database = fs::read(path.join(DB)).unwrap();
    fs::rename(path.join("FORMAT"), path.join("FORMAT.tmp")).unwrap();
    assert!(NativePrivateStore::locate_context(&path).is_err());
    assert_eq!(fs::read(path.join("FORMAT.tmp")).unwrap(), original);
    assert_eq!(fs::read(path.join(DB)).unwrap(), database);
    fs::rename(path.join("FORMAT.tmp"), path.join("FORMAT")).unwrap();
    for raw in [&original[..0], &original[..original.len() - 1]] {
        fs::write(path.join("FORMAT"), raw).unwrap();
        assert!(NativePrivateStore::locate_context(&path).is_err());
        assert_eq!(fs::read(path.join("FORMAT")).unwrap(), raw);
    }
    fs::write(path.join("FORMAT"), &original).unwrap();
    let mut changed = original.clone();
    changed[8] ^= 1;
    fs::write(path.join("FORMAT"), &changed).unwrap();
    assert!(NativePrivateStore::locate_context(&path).is_err());
    assert_eq!(fs::read(path.join("FORMAT")).unwrap(), changed);
    fs::remove_file(path.join("FORMAT")).unwrap();
    fs::write(path.join("retained-marker"), &original).unwrap();
    symlink(path.join("retained-marker"), path.join("FORMAT")).unwrap();
    assert!(NativePrivateStore::locate_context(&path).is_err());
    assert_eq!(fs::read(path.join("retained-marker")).unwrap(), original);
    drop(store);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn archive_accounting_is_exact_bounded_and_preserves_failed_read_evidence() {
    let path = home();
    let ctx = context();
    let mut store = NativePrivateStore::create_new(&path, ctx, limits()).unwrap();
    let pristine = store.accounting(ctx).unwrap();
    assert!(pristine.image.is_none());
    assert_eq!((pristine.records, pristine.bytes), (0, 0));
    assert_eq!(pristine.limits, limits());
    let records = [
        record(RecordKey::Outbox(1), 7),
        record(RecordKey::Operation([5; 16]), 8),
    ];
    store.publish(ctx, None, &[3; 40], &records).unwrap();
    let snapshot = store.accounting(ctx).unwrap();
    assert_eq!(snapshot.image.as_deref(), Some(&[3; 40][..]));
    assert_eq!((snapshot.records, snapshot.bytes), (2, 160));
    drop(store);
    let mut store = NativePrivateStore::open(&path, ctx).unwrap();
    let reopened = store.accounting(ctx).unwrap();
    assert_eq!(reopened.image, snapshot.image);
    assert_eq!(
        (reopened.records, reopened.bytes),
        (snapshot.records, snapshot.bytes)
    );
    // A mismatched metadata digest must not be repaired or presented as a smaller
    // complete archive; the failed read latches this owner just like load().
    store
        .conn
        .execute("UPDATE meta SET bytes=bytes+1 WHERE id=1", [])
        .unwrap();
    assert!(matches!(store.accounting(ctx), Err(Error::Corrupt)));
    assert!(matches!(store.load(ctx), Err(Error::Uncertain)));
    let retained: i64 = store
        .conn
        .query_row("SELECT bytes FROM meta WHERE id=1", [], |r| r.get(0))
        .unwrap();
    assert_eq!(retained, 161);
}
