use super::*;
use crate::relay::Limits;
use std::{
    cell::Cell,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    thread,
};
use vhalla_private_kernel::{OperationId, OutboxKind};

fn namespace() -> RelayNamespace {
    RelayNamespace::from_bytes([9; 32]).unwrap()
}
fn item(position: u64) -> RelayItem {
    RelayItem::new(
        namespace(),
        position,
        OperationId::from_bytes([position as u8; 16]).unwrap(),
        OutboxKind::Application,
        b"opaque ciphertext",
    )
    .unwrap()
}
fn page(head: u64, positions: &[u64], next: Option<u64>) -> RelayPage {
    RelayPage {
        head,
        next,
        records: positions
            .iter()
            .map(|position| PositionedItem {
                position: *position,
                item: item(*position),
            })
            .collect(),
    }
}
fn store(count: u64) -> Store {
    let mut store = Store::new(
        namespace(),
        Limits {
            max_items: 8,
            max_bytes: 4096,
        },
    )
    .unwrap();
    for position in 1..=count {
        store.put(item(position)).unwrap();
    }
    store
}
fn directory(name: &str) -> PathBuf {
    super::tests::tempdir(name)
}

#[test]
fn trusted_admission_cursor_excludes_only_bound_prejoin_history_and_resumes() {
    let path = directory("admission-checkpoint");
    let source = store(6);
    {
        let mut scan = ScanDirectory::open_from(&path, namespace(), 4).unwrap();
        assert!(scan.positions().unwrap().is_empty());
        assert_eq!(scan.read(4), Err(ScanFailure::Corrupt));
        let report = scan
            .scan_page_until(&source, 1, Instant::now() + IO_TIMEOUT)
            .unwrap();
        assert_eq!((report.head, report.cursor, report.scanned), (6, 5, 1));
        assert_eq!(scan.positions().unwrap(), vec![5]);
        assert_eq!(scan.read(5).unwrap(), item(5));
    }
    let binding = fs::read(path.join("namespace")).unwrap();
    assert!(ScanDirectory::open(&path, namespace()).is_err());
    assert!(ScanDirectory::open_from(&path, namespace(), 5).is_err());
    assert_eq!(fs::read(path.join("namespace")).unwrap(), binding);
    {
        let mut scan = ScanDirectory::open_from(&path, namespace(), 4).unwrap();
        let report = scan
            .scan_page_until(&source, 8, Instant::now() + IO_TIMEOUT)
            .unwrap();
        assert_eq!((report.head, report.cursor, report.scanned), (6, 6, 1));
        assert_eq!(scan.positions().unwrap(), vec![5, 6]);
    }
    // A removed accepted suffix is corruption, not permission to restart at
    // the trusted floor and refetch with a fresh interpretation.
    fs::remove_file(path.join("items/0000000000000006.vhrelay")).unwrap();
    assert!(matches!(
        ScanDirectory::open_from(&path, namespace(), 4),
        Err(ScanFailure::Corrupt)
    ));
}

#[test]
fn admission_cursor_refuses_relay_rollback_and_recovers_exact_pending_suffix() {
    let path = directory("admission-interruption");
    {
        let mut scan = ScanDirectory::open_from(&path, namespace(), 4).unwrap();
        assert!(scan
            .scan_page_until(&store(3), 8, Instant::now() + IO_TIMEOUT)
            .is_err());
        scan.fault = Some(PublicationFault::ItemPublished);
        assert_eq!(
            scan.scan_page_until(&store(5), 8, Instant::now() + IO_TIMEOUT),
            Err(ScanFailure::Storage)
        );
    }
    let retained = fs::read(path.join("items/0000000000000005.vhrelay")).unwrap();
    let mut scan = ScanDirectory::open_from(&path, namespace(), 4).unwrap();
    assert!(scan.positions().unwrap().is_empty());
    let report = scan
        .scan_page_until(&store(5), 8, Instant::now() + IO_TIMEOUT)
        .unwrap();
    assert_eq!((report.cursor, report.scanned), (5, 0));
    assert_eq!(scan.positions().unwrap(), vec![5]);
    assert_eq!(
        fs::read(path.join("items/0000000000000005.vhrelay")).unwrap(),
        retained
    );
}

#[test]
fn page_contract_rejects_gaps_regression_oversized_and_false_completion() {
    for (page, after, limit) in [
        (page(2, &[2], None), 0, 2),
        (page(2, &[1], Some(1)), 1, 2),
        (page(2, &[1, 2], None), 0, 1),
        (page(1, &[1, 2], None), 0, 2),
        (page(2, &[1], None), 0, 2),
        (page(2, &[], Some(1)), 0, 2),
        (page(2, &[1], Some(2)), 0, 2),
        (page(1, &[1], Some(1)), 0, 2),
    ] {
        assert_eq!(validate_page(&page, after, limit), Err(NetError::Malformed));
    }
    assert!(validate_page(&page(2, &[1], Some(1)), 0, 2).is_ok());
    assert!(validate_page(&page(2, &[], None), 2, 2).is_ok());
    assert!(validate_page(&page(2, &[], None), 3, 2).is_ok());
}

struct Hostile {
    calls: Cell<usize>,
    wrong_namespace: bool,
}
impl PageSource for Hostile {
    fn source_page(
        &self,
        after: u64,
        _: usize,
        _: Instant,
    ) -> std::result::Result<RelayPage, ScanFailure> {
        self.calls.set(self.calls.get() + 1);
        if self.wrong_namespace {
            let mut page = page(2, &[1, 2], None);
            page.records[1].item = RelayItem::new(
                RelayNamespace::from_bytes([8; 32]).unwrap(),
                2,
                item(2).operation(),
                OutboxKind::Application,
                b"foreign",
            )
            .unwrap();
            return Ok(page);
        }
        assert_eq!(after, 0);
        Ok(page(2, &[2], None))
    }
}
#[test]
fn invalid_page_or_namespace_is_refused_before_any_item_is_written() {
    for wrong_namespace in [false, true] {
        let dir = directory("hostile");
        let source = Hostile {
            calls: Cell::new(0),
            wrong_namespace,
        };
        assert_eq!(
            scan(&dir, namespace(), &source, 8),
            Err(if wrong_namespace {
                ScanFailure::Scope
            } else {
                ScanFailure::Net(NetError::Malformed)
            })
        );
        assert_eq!(source.calls.get(), 1);
        assert!(!dir.join("cursor").exists());
        assert_eq!(fs::read_dir(dir.join("items")).unwrap().count(), 0);
        fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn publication_faults_reconcile_without_overwriting_committed_evidence() {
    for fault in [
        PublicationFault::PartialItem,
        PublicationFault::ItemSynced,
        PublicationFault::ItemPublished,
        PublicationFault::ItemsSynced,
        PublicationFault::CursorPublished,
    ] {
        let dir = directory("publication");
        let source = store(2);
        let mut guard = ScanDirectory::open(&dir, namespace()).unwrap();
        guard.fault = Some(fault);
        assert_eq!(guard.scan(&source, 8), Err(ScanFailure::Storage));
        drop(guard);
        let mut reopened = ScanDirectory::open(&dir, namespace()).unwrap();
        assert_eq!(reopened.scan(&source, 8).unwrap().cursor, 2);
        assert_eq!(reopened.positions().unwrap(), vec![1, 2]);
        assert_eq!(reopened.read(1).unwrap(), item(1));
        assert_eq!(reopened.read(2).unwrap(), item(2));
        assert_eq!(fs::read(dir.join("cursor")).unwrap(), 2u64.to_be_bytes());
        drop(reopened);
        fs::remove_dir_all(dir).unwrap();
    }
    let dir = directory("conflict");
    let mut guard = ScanDirectory::open(&dir, namespace()).unwrap();
    let target = item_path(&dir.join("items"), 1);
    let conflicting = item(2).encode().unwrap();
    let mut file = custody::create_private_file(&target).unwrap();
    file.write_all(&conflicting).unwrap();
    drop(file);
    assert_eq!(guard.scan(&store(1), 8), Err(ScanFailure::Corrupt));
    assert_eq!(fs::read(&target).unwrap(), conflicting);
    assert!(!dir.join("cursor").exists());
    drop(guard);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn legacy_directories_are_preserved_and_namespace_reuse_refuses() {
    let dir = directory("legacy");
    fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    let mut cursor = custody::create_private_file(&dir.join("cursor")).unwrap();
    cursor.write_all(&2u64.to_be_bytes()).unwrap();
    drop(cursor);
    assert_eq!(
        ScanDirectory::open(&dir, namespace()).err(),
        Some(ScanFailure::Legacy)
    );
    assert_eq!(fs::read(dir.join("cursor")).unwrap(), 2u64.to_be_bytes());
    assert!(!dir.join("namespace").exists());
    assert!(!dir.join("lock").exists());
    fs::remove_dir_all(dir).unwrap();
    let dir = directory("bound");
    scan(&dir, namespace(), &store(2), 8).unwrap();
    let foreign = RelayNamespace::from_bytes([8; 32]).unwrap();
    assert_eq!(
        ScanDirectory::open(&dir, foreign).err(),
        Some(ScanFailure::Scope)
    );
    assert_eq!(scan(&dir, namespace(), &store(2), 8).unwrap().scanned, 0);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn custody_survives_scan_until_consumption_ends_and_reads_are_bounded() {
    let dir = directory("custody");
    let mut guard = ScanDirectory::open(&dir, namespace()).unwrap();
    guard.scan(&store(1), 8).unwrap();
    assert_eq!(
        ScanDirectory::open(&dir, namespace()).err(),
        Some(ScanFailure::Busy)
    );
    assert_eq!(guard.read(1).unwrap(), item(1));
    let file = item_path(&dir.join("items"), 1);
    fs::OpenOptions::new()
        .write(true)
        .open(&file)
        .unwrap()
        .set_len(MAX_ITEM_BYTES as u64 + 1)
        .unwrap();
    assert_eq!(guard.read(1), Err(ScanFailure::Storage));
    assert_eq!(guard.positions(), Err(ScanFailure::Storage));
    fs::remove_file(&file).unwrap();
    std::os::unix::fs::symlink("/dev/zero", &file).unwrap();
    assert_eq!(guard.read(1), Err(ScanFailure::Storage));
    fs::remove_file(&file).unwrap();
    fs::DirBuilder::new().mode(0o700).create(&file).unwrap();
    assert_eq!(guard.read(1), Err(ScanFailure::Storage));
    fs::remove_dir(&file).unwrap();
    fs::write(&file, item(1).encode().unwrap()).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    drop(guard);
    assert!(ScanDirectory::open(&dir, namespace()).is_ok());
    fs::remove_dir_all(dir).unwrap();
}

struct Growing {
    calls: Cell<usize>,
}
impl PageSource for Growing {
    fn source_page(
        &self,
        after: u64,
        _: usize,
        _: Instant,
    ) -> std::result::Result<RelayPage, ScanFailure> {
        self.calls.set(self.calls.get() + 1);
        match after {
            0 => Ok(page(2, &[1], Some(1))),
            1 => Ok(page(3, &[2], Some(2))),
            _ => panic!("scan chased an item beyond its initial head"),
        }
    }
}
#[test]
fn scan_freezes_head_and_preserves_progress_on_deadline() {
    let dir = directory("growing");
    let source = Growing {
        calls: Cell::new(0),
    };
    let mut guard = ScanDirectory::open(&dir, namespace()).unwrap();
    assert_eq!(
        guard.scan(&source, 1).unwrap(),
        ScanReport {
            head: 2,
            cursor: 2,
            scanned: 2
        }
    );
    assert_eq!(source.calls.get(), 2);
    guard.deadline = Instant::now();
    assert_eq!(guard.scan(&source, 1), Err(ScanFailure::Timeout));
    assert_eq!(guard.read(1), Err(ScanFailure::Timeout));
    assert_eq!(fs::read(dir.join("cursor")).unwrap(), 2u64.to_be_bytes());
    drop(guard);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn unauthenticated_trickling_connection_expires_and_next_client_succeeds() {
    let token = RelayToken::from_bytes([7; 32]).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        serve_with_timeout(
            listener,
            store(0),
            token,
            Some(2),
            Duration::from_millis(150),
        )
    });
    let mut attacker = TcpStream::connect(address).unwrap();
    attacker.write_all(&1000u32.to_be_bytes()).unwrap();
    let trickle = thread::spawn(move || {
        for _ in 0..100 {
            if attacker.write_all(&[0]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
    });
    let start = Instant::now();
    let client = SocketRelay::new(address, token);
    assert!(client
        .submit_until(&item(1), Instant::now() + Duration::from_secs(3))
        .is_ok());
    assert!(start.elapsed() < Duration::from_secs(3));
    trickle.join().unwrap();
    server.join().unwrap().unwrap();
}

#[test]
fn wire_page_cannot_exceed_requested_limit() {
    let token = RelayToken::from_bytes([7; 32]).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        read_frame(&mut stream, MAX_REQUEST, deadline).unwrap();
        let mut body = Vec::from(2u64.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        for position in 1u64..=2 {
            let encoded = item(position).encode().unwrap();
            body.extend_from_slice(&position.to_be_bytes());
            body.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
            body.extend_from_slice(&encoded);
        }
        write_frame(&mut stream, STATUS_OK, &body, deadline).unwrap();
    });
    assert_eq!(
        SocketRelay::new(address, token).page(0, 1).err(),
        Some(NetError::Malformed)
    );
    server.join().unwrap();
}

struct BeyondBudget;
impl PageSource for BeyondBudget {
    fn source_page(
        &self,
        _: u64,
        _: usize,
        _: Instant,
    ) -> std::result::Result<RelayPage, ScanFailure> {
        Ok(page(MAX_RELAY_ITEMS as u64 + 1, &[1], Some(1)))
    }
}
#[test]
fn scan_refuses_resource_exhaustion_and_source_rollback_without_losing_cursor() {
    let dir = directory("budget");
    assert_eq!(
        scan(&dir, namespace(), &BeyondBudget, 8),
        Err(ScanFailure::Capacity)
    );
    assert!(!dir.join("cursor").exists());
    scan(&dir, namespace(), &store(2), 8).unwrap();
    assert_eq!(
        scan(&dir, namespace(), &store(1), 8),
        Err(ScanFailure::Net(NetError::Malformed))
    );
    assert_eq!(fs::read(dir.join("cursor")).unwrap(), 2u64.to_be_bytes());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn relay_token_debug_never_formats_the_credential() {
    let token = RelayToken::from_bytes([7; 32]).unwrap();
    assert_eq!(format!("{token:?}"), "RelayToken([REDACTED])");
}

#[test]
fn bound_directory_never_recreates_a_removed_live_lock() {
    let dir = directory("missing-lock");
    let guard = ScanDirectory::open(&dir, namespace()).unwrap();
    fs::remove_file(dir.join("lock")).unwrap();
    assert_eq!(
        ScanDirectory::open(&dir, namespace()).err(),
        Some(ScanFailure::Storage)
    );
    assert!(!dir.join("lock").exists());
    drop(guard);
    fs::remove_dir_all(dir).unwrap();
}

struct CountedPage {
    store: Store,
    calls: Cell<usize>,
    expected_deadline: Instant,
}
impl PageSource for CountedPage {
    fn source_page(
        &self,
        after: u64,
        limit: usize,
        deadline: Instant,
    ) -> std::result::Result<RelayPage, ScanFailure> {
        self.calls.set(self.calls.get() + 1);
        assert_eq!(deadline, self.expected_deadline);
        self.store
            .page(after, limit)
            .map_err(|_| ScanFailure::Source)
    }
}
#[test]
fn single_page_tick_resumes_once_and_preserves_interrupted_publication() {
    let dir = directory("one-page-tick");
    let deadline = Instant::now() + Duration::from_secs(5);
    let source = CountedPage {
        store: store(5),
        calls: Cell::new(0),
        expected_deadline: deadline,
    };
    let mut scan = ScanDirectory::open(&dir, namespace()).unwrap();
    let first = scan.scan_page_until(&source, 2, deadline).unwrap();
    assert_eq!((first.head, first.cursor, first.scanned), (5, 2, 2));
    assert_eq!(source.calls.get(), 1);
    drop(scan);
    let mut scan = ScanDirectory::open(&dir, namespace()).unwrap();
    scan.fault = Some(PublicationFault::ItemPublished);
    assert_eq!(
        scan.scan_page_until(&source, 2, deadline),
        Err(ScanFailure::Storage)
    );
    assert_eq!(source.calls.get(), 2);
    drop(scan);
    let mut scan = ScanDirectory::open(&dir, namespace()).unwrap();
    assert_eq!(scan.cursor, 2);
    assert!(item_path(&dir.join("items"), 3).exists());
    let resumed = scan.scan_page_until(&source, 2, deadline).unwrap();
    assert_eq!((resumed.head, resumed.cursor, resumed.scanned), (5, 4, 1));
    assert_eq!(source.calls.get(), 3);
    let last = scan.scan_page_until(&source, 2, deadline).unwrap();
    assert_eq!((last.head, last.cursor, last.scanned), (5, 5, 1));
    assert_eq!(source.calls.get(), 4);
    drop(scan);
    fs::remove_dir_all(dir).unwrap();
}
#[test]
fn single_page_tick_rejects_expired_budget_and_whole_hostile_page_before_effects() {
    let dir = directory("one-page-expired");
    let deadline = Instant::now();
    let source = CountedPage {
        store: store(2),
        calls: Cell::new(0),
        expected_deadline: deadline,
    };
    let mut scan = ScanDirectory::open(&dir, namespace()).unwrap();
    assert_eq!(
        scan.scan_page_until(&source, 2, deadline),
        Err(ScanFailure::Timeout)
    );
    assert_eq!(source.calls.get(), 0);
    drop(scan);
    let mut scan = ScanDirectory::open(&dir, namespace()).unwrap();
    let source = Hostile {
        calls: Cell::new(0),
        wrong_namespace: true,
    };
    assert_eq!(
        scan.scan_page_until(&source, 2, Instant::now() + Duration::from_secs(5)),
        Err(ScanFailure::Scope)
    );
    assert!(!dir.join("cursor").exists());
    assert!(scan.positions().unwrap().is_empty());
    drop(scan);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn admission_cursor_preserves_foreign_or_orphan_pending_cursor_evidence() {
    for foreign in [false, true] {
        let path = directory("admission-pending-cursor-refuse");
        {
            let mut scan = ScanDirectory::open_from(&path, namespace(), 4).unwrap();
            if foreign {
                scan.fault = Some(PublicationFault::ItemPublished);
                assert!(scan.scan(&store(5), 8).is_err());
            }
        }
        let pending = if foreign { 6u64 } else { 5u64 }.to_be_bytes();
        let mut file = custody::create_private_file(&path.join("cursor.tmp")).unwrap();
        file.write_all(&pending).unwrap();
        file.sync_all().unwrap();
        assert!(matches!(
            ScanDirectory::open_from(&path, namespace(), 4),
            Err(ScanFailure::Corrupt)
        ));
        assert_eq!(fs::read(path.join("cursor.tmp")).unwrap(), pending);
        assert!(!path.join("cursor").exists());
        fs::remove_dir_all(path).unwrap();
    }
}
#[test]
fn admission_cursor_reconciles_every_exact_pending_cursor_prefix() {
    for length in 0..=8 {
        let path = directory("admission-pending-cursor-exact");
        {
            let mut scan = ScanDirectory::open_from(&path, namespace(), 4).unwrap();
            scan.fault = Some(PublicationFault::ItemPublished);
            assert!(scan.scan(&store(5), 8).is_err());
        }
        let bytes = 5u64.to_be_bytes();
        let mut file = custody::create_private_file(&path.join("cursor.tmp")).unwrap();
        file.write_all(&bytes[..length]).unwrap();
        file.sync_all().unwrap();
        let mut scan = ScanDirectory::open_from(&path, namespace(), 4).unwrap();
        let report = scan.scan(&store(5), 8).unwrap();
        assert_eq!(report.cursor, 5);
        assert_eq!(report.scanned, 0);
        assert_eq!(scan.positions().unwrap(), vec![5]);
        assert_eq!(fs::read(path.join("cursor")).unwrap(), bytes);
        assert!(!path.join("cursor.tmp").exists());
        drop(scan);
        fs::remove_dir_all(path).unwrap();
    }
}

#[test]
fn idle_reopen_uses_the_validated_signature_without_reopening_items() {
    let dir = directory("idle-rescan");
    let mut source = Store::new(
        namespace(),
        Limits {
            max_items: MAX_RELAY_ITEMS,
            max_bytes: 64 * 1024 * 1024,
        },
    )
    .unwrap();
    for position in 1..=600u64 {
        let mut operation = [0u8; 16];
        operation[8..].copy_from_slice(&position.to_be_bytes());
        source
            .put(
                RelayItem::new(
                    namespace(),
                    position,
                    OperationId::from_bytes(operation).unwrap(),
                    OutboxKind::Application,
                    b"opaque ciphertext",
                )
                .unwrap(),
            )
            .unwrap();
    }
    {
        let mut scan = ScanDirectory::open(&dir, namespace()).unwrap();
        scan.scan(&source, MAX_RELAY_PAGE).unwrap();
    }
    // The first reopen after publication performs the complete custody sweep
    // and publishes the validated snapshot for later idle reopens.
    let started = Instant::now();
    let scan = ScanDirectory::open(&dir, namespace()).unwrap();
    let full_sweep = started.elapsed();
    assert_eq!(scan.positions().unwrap().len(), 600);
    assert_eq!(
        fs::metadata(dir.join("signature"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
    drop(scan);
    // In-place custody drift never touches the directory, so the exact
    // signature derives positions; read() keeps the deferred custody refusal.
    let file = item_path(&dir.join("items"), 1);
    fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).unwrap();
    let started = Instant::now();
    let scan = ScanDirectory::open(&dir, namespace()).unwrap();
    assert_eq!(scan.positions().unwrap().len(), 600);
    let idle_open = started.elapsed();
    assert_eq!(scan.read(1), Err(ScanFailure::Storage));
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    // Any committed-directory change invalidates the snapshot: a removal is
    // corruption evidence, never silently rederived positions.
    fs::remove_file(&file).unwrap();
    assert_eq!(scan.positions(), Err(ScanFailure::Corrupt));
    drop(scan);
    eprintln!("idle-rescan 600 items: full sweep {full_sweep:?}, signed idle open {idle_open:?}");
    fs::remove_dir_all(dir).unwrap();
}
