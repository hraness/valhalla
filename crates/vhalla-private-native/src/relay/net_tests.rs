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
