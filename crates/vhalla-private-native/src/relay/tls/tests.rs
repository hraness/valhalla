use super::super::{FileStore, Limits, Store, MAX_RELAY_PAYLOAD};
use super::*;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use std::{
    net::TcpListener,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    thread,
};
use vhalla_private_kernel::{OperationId, OutboxKind};
const NAME: &str = "relay.production-test.invalid";
fn ns() -> RelayNamespace {
    RelayNamespace::from_bytes([9; 32]).unwrap()
}
fn token(n: u8) -> RelayToken {
    RelayToken::from_bytes([n; 32]).unwrap()
}
fn item(n: u8) -> RelayItem {
    RelayItem::new(
        ns(),
        n as u64,
        OperationId::from_bytes([n; 16]).unwrap(),
        OutboxKind::Application,
        b"committed ciphertext",
    )
    .unwrap()
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn credential(id: u8, key: u8) -> Credential {
    Credential {
        id: [id; 16],
        tokens: vec![token(key)],
        namespace: ns(),
        permissions: Permissions {
            put: true,
            page: true,
        },
        storage: Limits {
            max_items: 8,
            max_bytes: 1024 * 1024,
        },
        max_inflight: 1,
        requests_per_window: 64,
        bytes_per_window: 32 * 1024 * 1024,
    }
}
struct Certificates {
    root: Vec<u8>,
    config: Arc<ServerConfig>,
}
fn certificates() -> Certificates {
    let issuer_key = KeyPair::generate().unwrap();
    let mut issuer = CertificateParams::new(Vec::<String>::new()).unwrap();
    issuer.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    issuer.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::CrlSign,
    ];
    let issuer = issuer.self_signed(&issuer_key).unwrap();
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![NAME.to_owned()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf = params.signed_by(&key, &issuer, &issuer_key).unwrap();
    Certificates {
        root: issuer.der().to_vec(),
        config: server_config(vec![leaf.der().to_vec()], key.serialize_der()).unwrap(),
    }
}
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "valhalla-production-tls-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let store = FileStore::create_new(
            &path,
            ns(),
            Limits {
                max_items: 32,
                max_bytes: 8 * 1024 * 1024,
            },
        )
        .unwrap();
        Service::initialize(store).unwrap();
        Self(path)
    }
    fn open(&self) -> FileStore {
        FileStore::open(&self.0, ns()).unwrap()
    }
    fn serve(
        &self,
        cert: &Certificates,
        credentials: Vec<Credential>,
        limits: ServiceLimits,
        count: u64,
    ) -> (SocketAddr, thread::JoinHandle<()>) {
        let service = Service::new(self.open(), cert.config.clone(), credentials, limits).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || service.serve(listener, Some(count)).unwrap());
        (address, worker)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
fn client(addr: SocketAddr, cert: &Certificates, key: u8) -> TlsRelay {
    TlsRelay::new(addr, NAME, cert.root.clone(), token(key), ns()).unwrap()
}

#[test]
fn tls_retention_retry_namespace_scan_and_canonical_absence() {
    let f = Fixture::new();
    let cert = certificates();
    let (addr, worker) = f.serve(&cert, vec![credential(1, 7)], ServiceLimits::default(), 4);
    let c = client(addr, &cert, 7);
    let first = c.submit(&item(1)).unwrap();
    assert_eq!(first.position, 1);
    assert!(!first.duplicate);
    let retry = c.submit(&item(1)).unwrap();
    assert!(retry.duplicate);
    assert_eq!(first.digest, retry.digest);
    let page = PageSource::source_page(&c, 0, 64, deadline()).unwrap();
    assert_eq!(page.records[0].item, item(1));
    let absent = c.page(50, 1).unwrap();
    assert_eq!(absent.head, 1);
    assert!(absent.records.is_empty());
    assert!(absent.next.is_none());
    worker.join().unwrap();
    assert_eq!(f.open().page(0, 64).unwrap().head, 1);
}
#[test]
fn wrong_ca_name_and_namespace_never_send_application_credentials() {
    let cert = certificates();
    let other = certificates();
    for (root, name, namespace) in [
        (other.root.clone(), NAME, ns()),
        (cert.root.clone(), "wrong.invalid", ns()),
        (
            cert.root.clone(),
            NAME,
            RelayNamespace::from_bytes([8; 32]).unwrap(),
        ),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut config = (*cert.config).clone();
        config.alpn_protocols = vec![protocol(ns())];
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut tls = StreamOwned::new(
                rustls::ServerConnection::new(Arc::new(config)).unwrap(),
                DeadlineSocket {
                    stream,
                    deadline: deadline(),
                },
            );
            let mut bytes = [0; 64];
            let read = tls.read(&mut bytes);
            assert!(read.is_err() || read.unwrap() == 0);
        });
        let c = TlsRelay::new(addr, name, root, token(7), namespace).unwrap();
        assert!(c.page(0, 1).is_err());
        worker.join().unwrap();
    }
}
#[test]
fn permissions_wrong_token_and_rotation_preserve_durable_quota() {
    let f = Fixture::new();
    let cert = certificates();
    let mut owner = credential(1, 7);
    owner.storage.max_items = 1;
    let mut reader = credential(2, 8);
    reader.permissions.put = false;
    let (addr, worker) = f.serve(&cert, vec![owner, reader], ServiceLimits::default(), 4);
    assert_eq!(
        client(addr, &cert, 6).submit(&item(1)),
        Err(NetError::Denied)
    );
    assert_eq!(
        client(addr, &cert, 8).submit(&item(1)),
        Err(NetError::Denied)
    );
    client(addr, &cert, 7).submit(&item(1)).unwrap();
    assert_eq!(
        client(addr, &cert, 7).submit(&item(2)),
        Err(NetError::Capacity)
    );
    worker.join().unwrap();
    let mut rotated = credential(1, 9);
    rotated.storage.max_items = 1;
    let (addr, worker) = f.serve(&cert, vec![rotated], ServiceLimits::default(), 3);
    assert_eq!(
        client(addr, &cert, 7).page(0, 1).err(),
        Some(NetError::Denied)
    );
    assert!(client(addr, &cert, 9).submit(&item(1)).unwrap().duplicate);
    assert_eq!(
        client(addr, &cert, 9).submit(&item(2)),
        Err(NetError::Capacity)
    );
    worker.join().unwrap();
    assert!(matches!(
        Service::new(
            f.open(),
            cert.config,
            vec![credential(1, 9)],
            ServiceLimits::default()
        ),
        Err(NetError::Conflict)
    ));
}
#[test]
fn key_work_exhaustion_and_slow_unauthenticated_clients_leave_healthy_progress() {
    let f = Fixture::new();
    let cert = certificates();
    let mut limited = credential(1, 7);
    limited.requests_per_window = 1;
    let limits = ServiceLimits {
        max_connections: 4,
        request_timeout: Duration::from_millis(700),
        window: Duration::from_secs(60),
        ..ServiceLimits::default()
    };
    let (addr, worker) = f.serve(&cert, vec![limited, credential(2, 8)], limits, 5);
    let slow1 = TcpStream::connect(addr).unwrap();
    let slow2 = TcpStream::connect(addr).unwrap();
    client(addr, &cert, 7).submit(&item(1)).unwrap();
    assert_eq!(
        client(addr, &cert, 7).submit(&item(2)),
        Err(NetError::Capacity)
    );
    client(addr, &cert, 8).submit(&item(2)).unwrap();
    drop((slow1, slow2));
    worker.join().unwrap();
    assert_eq!(f.open().page(0, 64).unwrap().head, 2);
}
#[test]
fn lost_receipt_reopen_retries_exact_ciphertext_at_original_position() {
    let f = Fixture::new();
    let cert = certificates();
    let (addr, worker) = f.serve(&cert, vec![credential(1, 7)], ServiceLimits::default(), 1);
    let c = client(addr, &cert, 7);
    let mut tls = c.connect(deadline()).unwrap();
    let mut raw = token(7).as_bytes().to_vec();
    raw.extend(item(1).encode().unwrap());
    write_frame(&mut tls, OP_PUT, &raw, deadline()).unwrap();
    drop(tls);
    worker.join().unwrap();
    assert_eq!(f.open().page(0, 64).unwrap().head, 1);
    let (addr, worker) = f.serve(&cert, vec![credential(1, 7)], ServiceLimits::default(), 1);
    let retry = client(addr, &cert, 7).submit(&item(1)).unwrap();
    assert!(retry.duplicate);
    assert_eq!(retry.position, 1);
    worker.join().unwrap();
}
#[test]
fn malformed_frames_and_foreign_items_do_not_mutate_or_poison_healthy_service() {
    let f = Fixture::new();
    let cert = certificates();
    let (addr, worker) = f.serve(&cert, vec![credential(1, 7)], ServiceLimits::default(), 4);
    let c = client(addr, &cert, 7);
    let mut tls = c.connect(deadline()).unwrap();
    tls.write_all(&u32::MAX.to_be_bytes()).unwrap();
    tls.flush().unwrap();
    drop(tls);
    assert_eq!(c.exchange(99, &[], deadline()), Err(NetError::Bounds));
    let foreign = RelayItem::new(
        RelayNamespace::from_bytes([3; 32]).unwrap(),
        1,
        OperationId::from_bytes([1; 16]).unwrap(),
        OutboxKind::Application,
        b"x",
    )
    .unwrap();
    assert_eq!(
        c.exchange(OP_PUT, &foreign.encode().unwrap(), deadline()),
        Err(NetError::Scope)
    );
    c.submit(&item(1)).unwrap();
    worker.join().unwrap();
    assert_eq!(f.open().page(0, 64).unwrap().head, 1);
}
#[test]
fn publication_failure_rolls_back_quota_and_poisoned_service_requires_reopen() {
    let f = Fixture::new();
    let cert = certificates();
    {
        let store = f.open();
        store.conn.execute_batch("CREATE TRIGGER fail_item BEFORE INSERT ON items BEGIN SELECT RAISE(ABORT, 'injected'); END;").unwrap();
    }
    let service = Service::new(
        f.open(),
        cert.config.clone(),
        vec![credential(1, 7)],
        ServiceLimits::default(),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let worker = thread::spawn(move || service.serve(listener, Some(1)));
    assert!(client(addr, &cert, 7).submit(&item(1)).is_err());
    assert_eq!(worker.join().unwrap(), Err(NetError::Unavailable));
    {
        let store = f.open();
        assert_eq!(store.page(0, 1).unwrap().head, 0);
        let charges: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM tls_charges", [], |r| r.get(0))
            .unwrap();
        assert_eq!(charges, 0);
        store.conn.execute_batch("DROP TRIGGER fail_item").unwrap();
    }
    let (addr, worker) = f.serve(&cert, vec![credential(1, 7)], ServiceLimits::default(), 1);
    assert!(!client(addr, &cert, 7).submit(&item(1)).unwrap().duplicate);
    worker.join().unwrap();
}
#[test]
fn existing_used_mailbox_and_uncharged_compatibility_writes_refuse_enrollment() {
    let f = Fixture::new();
    let cert = certificates();
    assert!(Service::initialize(f.open()).is_err());
    {
        let mut store = f.open();
        store.put(item(1)).unwrap();
    }
    assert!(matches!(
        Service::new(
            f.open(),
            cert.config,
            vec![credential(1, 7)],
            ServiceLimits::default()
        ),
        Err(NetError::Unavailable)
    ));
}
#[test]
fn shared_codec_retains_tcp_frame_and_large_page_contract() {
    assert_eq!(frame(OP_PAGE, &[1, 2]), vec![0, 0, 0, 3, 2, 1, 2]);
    let mut store = Store::new(
        ns(),
        Limits {
            max_items: 32,
            max_bytes: 32 * MAX_RELAY_PAYLOAD,
        },
    )
    .unwrap();
    for n in 1..=20 {
        store
            .put(
                RelayItem::new(
                    ns(),
                    n,
                    OperationId::from_bytes([n as u8; 16]).unwrap(),
                    OutboxKind::Application,
                    &vec![5; MAX_RELAY_PAYLOAD],
                )
                .unwrap(),
            )
            .unwrap();
    }
    let (code, raw) = dispatch(&mut store, OP_PAGE, &page_request(0, 64).unwrap()).unwrap();
    assert_eq!(code, STATUS_OK);
    assert!(raw.len() <= MAX_PAGE_BODY);
    let page = decode_page(&raw, 0, 64).unwrap();
    assert!(page.next.is_some());
    assert!(page.records.len() < 20);
    let after = page.next.unwrap();
    let (_, raw) = dispatch(&mut store, OP_PAGE, &page_request(after, 64).unwrap()).unwrap();
    assert_eq!(decode_page(&raw, after, 64).unwrap().next, None);
}

#[test]
fn credential_cannot_claim_all_capacity_and_corrupt_quota_ownership_refuses() {
    let f = Fixture::new();
    let cert = certificates();
    let mut excessive = credential(1, 7);
    excessive.storage.max_items = 32;
    assert!(matches!(
        Service::new(
            f.open(),
            cert.config.clone(),
            vec![excessive],
            ServiceLimits::default()
        ),
        Err(NetError::Bounds)
    ));
    let (addr, worker) = f.serve(&cert, vec![credential(1, 7)], ServiceLimits::default(), 1);
    client(addr, &cert, 7).submit(&item(1)).unwrap();
    worker.join().unwrap();
    {
        let store = f.open();
        store
            .conn
            .execute_batch("PRAGMA foreign_keys=OFF; UPDATE tls_charges SET key_id=zeroblob(16);")
            .unwrap();
    }
    assert!(matches!(
        Service::new(
            f.open(),
            cert.config,
            vec![credential(1, 7)],
            ServiceLimits::default()
        ),
        Err(NetError::Unavailable)
    ));
}

#[test]
fn production_tls_transport_completes_a_durable_bound_delivery_job() {
    use crate::relay::delivery::{self, DeliveryStore, JobState, RetryPolicy, TickBudget};
    use vhalla_private_kernel::{
        protocol::{AnchorId, Key, PrivateRoomScope, RoomId},
        Context,
    };
    let f = Fixture::new();
    let cert = certificates();
    let (addr, worker) = f.serve(&cert, vec![credential(1, 7)], ServiceLimits::default(), 1);
    let mut transport = client(addr, &cert, 7);
    let context = Context {
        scope: PrivateRoomScope {
            room: RoomId::from_bytes([1; 32]).unwrap(),
            anchor: AnchorId::from_bytes([2; 32]).unwrap(),
        },
        account: Key::from_bytes(
            ed25519_dalek::SigningKey::from_bytes(&[3; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap(),
        device: Key::from_bytes(
            ed25519_dalek::SigningKey::from_bytes(&[4; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap(),
    };
    let path = f.0.join("delivery");
    let mut jobs = DeliveryStore::create_new(
        &path,
        context,
        ns(),
        transport.endpoint_id(),
        delivery::Limits {
            max_jobs: 4,
            max_bytes: 1024 * 1024,
        },
        RetryPolicy {
            max_attempts: 3,
            initial_backoff_secs: 1,
            max_backoff_secs: 8,
        },
    )
    .unwrap();
    jobs.enqueue(&item(1), 100).unwrap();
    let result = jobs
        .tick(
            &mut transport,
            100,
            TickBudget {
                max_jobs: 4,
                max_bytes: 1024 * 1024,
                deadline: deadline(),
            },
        )
        .unwrap();
    assert_eq!(result.jobs[0].state, JobState::Retained);
    assert_eq!(result.jobs[0].position, Some(1));
    worker.join().unwrap();
    drop(jobs);
    let reopened = DeliveryStore::open(&path, context, ns(), transport.endpoint_id()).unwrap();
    assert_eq!(reopened.statuses(0, 4).unwrap(), result.jobs);
}

#[test]
fn poisoned_storage_stops_supervision_without_waiting_for_another_client() {
    let f = Fixture::new();
    let cert = certificates();
    {
        let store = f.open();
        store.conn.execute_batch("CREATE TRIGGER fail_item BEFORE INSERT ON items BEGIN SELECT RAISE(ABORT, 'injected'); END;").unwrap();
    }
    let service = Service::new(
        f.open(),
        cert.config.clone(),
        vec![credential(1, 7)],
        ServiceLimits {
            request_timeout: Duration::from_millis(500),
            ..ServiceLimits::default()
        },
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        let result = service.serve(listener, Some(2));
        let _ = send.send(result);
        result
    });
    assert!(client(addr, &cert, 7).submit(&item(1)).is_err());
    let result = receive.recv_timeout(Duration::from_secs(2));
    // The second connection only cleans up the previous broken implementation
    // when this regression fails; success must never need this external wakeup.
    if result.is_err() {
        let _ = TcpStream::connect_timeout(&addr, Duration::from_millis(500));
    }
    let joined = worker.join().unwrap();
    assert_eq!(result, Ok(Err(NetError::Unavailable)));
    assert_eq!(joined, Err(NetError::Unavailable));
    assert!(TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_err());
    let store = f.open();
    assert_eq!(store.page(0, 1).unwrap().head, 0);
    let charged: i64 = store
        .conn
        .query_row("SELECT COUNT(*) FROM tls_charges", [], |row| row.get(0))
        .unwrap();
    assert_eq!(charged, 0);
}

#[test]
fn explicit_stop_drains_admitted_handshake_and_releases_exact_custody() {
    let fixture = Fixture::new();
    let cert = certificates();
    let service = Service::new(
        fixture.open(),
        cert.config.clone(),
        vec![credential(1, 2)],
        ServiceLimits {
            request_timeout: Duration::from_millis(250),
            ..ServiceLimits::default()
        },
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let selected = stop.clone();
    let (send, receive) = std::sync::mpsc::channel();
    let worker = thread::spawn(move || {
        let result = service.serve_until(listener, None, selected);
        send.send(result).unwrap();
    });
    // Completed TLS proves admission; withholding the request frame then stalls
    // an actual owned worker under its original absolute request deadline.
    let stalled = client(address, &cert, 2).connect(deadline()).unwrap();
    stop.store(true, std::sync::atomic::Ordering::Release);
    receive
        .recv_timeout(Duration::from_secs(2))
        .unwrap()
        .unwrap();
    worker.join().unwrap();
    assert!(TcpStream::connect(address).is_err());
    drop(stalled);
    let reopened = fixture.open();
    assert_eq!(
        reopened
            .conn
            .query_row("SELECT COUNT(*) FROM items", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        reopened
            .conn
            .query_row("SELECT COUNT(*) FROM tls_charges", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}
