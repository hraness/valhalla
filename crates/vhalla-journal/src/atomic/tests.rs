use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::sync::atomic::{AtomicUsize, Ordering};

fn fixture() -> PathBuf {
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "journal-atomic-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&dir).unwrap();
    dir
}

fn bundle(predecessor: [u8; 32], height: u64) -> Bundle {
    Bundle::new(BundleParts {
        certificate: vec![height as u8; 97],
        predecessor,
        next: [height as u8; 32],
        batch: vec![3; 71],
        value: vec![4; 32],
        configuration: vec![],
        control_record: vec![],
        debit_marker: vec![],
        height,
    })
    .unwrap()
}

#[test]
fn atomic_bundle_faults_never_expose_partial_final_or_advance_head() {
    for fault in [
        BundleWriteStep::Created,
        BundleWriteStep::Partial,
        BundleWriteStep::Written,
        BundleWriteStep::Synced,
        BundleWriteStep::Published,
        BundleWriteStep::Removed,
    ] {
        let dir = fixture();
        let journal = Journal::new(&dir, FsStore);
        let first = bundle(GENESIS_NEXT, 1);
        journal.commit(&first).unwrap();
        let old_head = fs::read(dir.join(HEAD_FILE)).unwrap();
        let next = bundle(first.next(), 2);
        {
            let _lock = FsStore.lock(&dir, false).unwrap();
            let result = create_bundle(&dir, next.id(), next.bytes(), |point| {
                if point == fault {
                    Err(JournalError::Crashed)
                } else {
                    Ok(())
                }
            });
            assert!(matches!(result, Err(JournalError::Crashed)), "{fault:?}");
        }
        assert_eq!(fs::read(dir.join(HEAD_FILE)).unwrap(), old_head);
        let final_bytes =
            read_opt(&FsStore::bundle_path(&dir, next.id()), MAX_BUNDLE_BYTES).unwrap();
        if matches!(fault, BundleWriteStep::Published | BundleWriteStep::Removed) {
            assert_eq!(final_bytes.as_deref(), Some(next.bytes()));
        } else {
            assert!(final_bytes.is_none());
        }
        let scratch = dir.join(BUNDLES).join(SCRATCH);
        if fault == BundleWriteStep::Created {
            assert_eq!(fs::metadata(&scratch).unwrap().len(), 0);
        }
        if fault == BundleWriteStep::Partial {
            assert_eq!(
                fs::read(&scratch).unwrap(),
                &next.bytes()[..next.bytes().len() / 2]
            );
        }
        assert_eq!(journal.recover().unwrap().pin.bundle, first.id());
        assert_eq!(journal.commit(&next).unwrap(), Outcome::Committed);
        assert_eq!(journal.commit(&next).unwrap(), Outcome::AlreadyCommitted);
        // A leftover scratch hard link from the Published fault must only be
        // unlinked, never truncated, by the following distinct publication.
        let third = bundle(next.next(), 3);
        assert_eq!(journal.commit(&third).unwrap(), Outcome::Committed);
        assert_eq!(
            FsStore.read_bundle(&dir, first.id()).unwrap(),
            first.bytes()
        );
        assert_eq!(FsStore.read_bundle(&dir, next.id()).unwrap(), next.bytes());
        assert_eq!(journal.at_height(1).unwrap(), Some(first.id()));
        assert_eq!(journal.at_height(2).unwrap(), Some(next.id()));
        assert!(!scratch.exists());
        fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn atomic_bundle_existing_corrupt_final_is_never_repaired_or_overwritten() {
    for bad in [vec![], vec![1, 2], vec![9; 200]] {
        let dir = fixture();
        let value = bundle(GENESIS_NEXT, 1);
        {
            let _lock = FsStore.lock(&dir, false).unwrap();
            fs::write(FsStore::bundle_path(&dir, value.id()), &bad).unwrap();
        }
        let scratch = dir.join(BUNDLES).join(SCRATCH);
        fs::write(&scratch, b"preserve unrelated scratch").unwrap();
        assert!(matches!(
            Journal::new(&dir, FsStore).commit(&value),
            Err(JournalError::Corrupt)
        ));
        assert_eq!(
            fs::read(FsStore::bundle_path(&dir, value.id())).unwrap(),
            bad
        );
        assert_eq!(fs::read(&scratch).unwrap(), b"preserve unrelated scratch");
        assert!(!dir.join(HEAD_FILE).exists());
        fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn atomic_bundle_unknown_scratch_kinds_and_custody_are_preserved() {
    for case in 0..5 {
        let dir = fixture();
        let value = bundle(GENESIS_NEXT, 1);
        let _lock = FsStore.lock(&dir, false).unwrap();
        let scratch = dir.join(BUNDLES).join(SCRATCH);
        let target = dir.join("unrelated");
        fs::write(&target, b"keep").unwrap();
        match case {
            0 => symlink(&target, &scratch).unwrap(),
            1 => fs::create_dir(&scratch).unwrap(),
            2 => {
                fs::write(&scratch, b"unknown permissions").unwrap();
                fs::set_permissions(&scratch, fs::Permissions::from_mode(0o644)).unwrap();
            }
            3 | 4 => {
                let file = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .open(&scratch)
                    .unwrap();
                if case == 3 {
                    fs::hard_link(&scratch, dir.join("link-a")).unwrap();
                    fs::hard_link(&scratch, dir.join("link-b")).unwrap();
                } else {
                    file.set_len(MAX_BUNDLE_BYTES as u64 + 1).unwrap();
                }
            }
            _ => unreachable!(),
        }
        let before = fs::symlink_metadata(&scratch).unwrap();
        assert!(matches!(
            create_bundle(&dir, value.id(), value.bytes(), |_| Ok(())),
            Err(JournalError::Corrupt)
        ));
        let after = fs::symlink_metadata(&scratch).unwrap();
        assert_eq!(before.ino(), after.ino());
        assert_eq!(before.len(), after.len());
        assert_eq!(before.mode(), after.mode());
        assert_eq!(fs::read(&target).unwrap(), b"keep");
        assert!(!FsStore::bundle_path(&dir, value.id()).exists());
        fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn atomic_bundle_conflict_or_corrupt_head_never_cleans_scratch() {
    let dir = fixture();
    let journal = Journal::new(&dir, FsStore);
    let first = bundle(GENESIS_NEXT, 1);
    journal.commit(&first).unwrap();
    let next = bundle(first.next(), 2);
    {
        let _lock = FsStore.lock(&dir, false).unwrap();
        assert!(matches!(
            create_bundle(&dir, next.id(), next.bytes(), |point| {
                if point == BundleWriteStep::Partial {
                    Err(JournalError::Crashed)
                } else {
                    Ok(())
                }
            }),
            Err(JournalError::Crashed)
        ));
    }
    let scratch = dir.join(BUNDLES).join(SCRATCH);
    let original = fs::read(&scratch).unwrap();
    let conflicting = bundle([99; 32], 2);
    assert!(matches!(
        journal.commit(&conflicting),
        Err(JournalError::Conflict { .. })
    ));
    assert_eq!(fs::read(&scratch).unwrap(), original);
    fs::write(dir.join(HEAD_FILE), b"bad HEAD").unwrap();
    assert!(matches!(journal.commit(&next), Err(JournalError::Corrupt)));
    assert_eq!(fs::read(&scratch).unwrap(), original);
    assert_eq!(
        FsStore.read_bundle(&dir, first.id()).unwrap(),
        first.bytes()
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn atomic_bundle_size_rejection_precedes_scratch_mutation() {
    let dir = fixture();
    let _lock = FsStore.lock(&dir, false).unwrap();
    let scratch = dir.join(BUNDLES).join(SCRATCH);
    fs::write(&scratch, b"unchanged").unwrap();
    assert!(matches!(
        create_bundle(&dir, [1; 32], &vec![0; MAX_BUNDLE_BYTES + 1], |_| Ok(())),
        Err(JournalError::Oversized)
    ));
    assert_eq!(fs::read(&scratch).unwrap(), b"unchanged");
    fs::remove_dir_all(dir).unwrap();
}
