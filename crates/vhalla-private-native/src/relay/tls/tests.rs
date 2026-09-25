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
fn formal_relay_lost_receipt_resume_preserves_custody_and_quota() {
    use crate::relay::delivery::{self, DeliveryStore, JobState, RetryPolicy, TickBudget};
    use vhalla_private_kernel::{
        protocol::{AnchorId, Key, PrivateRoomScope, RoomId},
        Context,
    };

    // Only the completion is lost: the real TLS client verifies a real receipt
    // from the production service before this test seam returns a timeout.
    struct LoseReceipt {
        inner: TlsRelay,
        queue: PathBuf,
        retained: Option<RelayReceipt>,
        sent: Vec<u8>,
    }
    impl delivery::Transport for LoseReceipt {
        fn endpoint_id(&self) -> delivery::EndpointId {
            self.inner.endpoint_id()
        }
        fn namespace(&self) -> RelayNamespace {
            ns()
        }
        fn submit_until(
            &mut self,
            item: &RelayItem,
            until: Instant,
        ) -> std::result::Result<RelayReceipt, NetError> {
            assert!(
                self.retained.is_none(),
                "only one lost completion is injected"
            );
            let reader = rusqlite::Connection::open_with_flags(
                self.queue.join("delivery.db"),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .unwrap();
            let (state, attempts, uncertain, raw): (i64, i64, i64, Vec<u8>) = reader
                .query_row(
                    "SELECT state,attempts,uncertain,item FROM jobs WHERE id=?1",
                    rusqlite::params![item.digest().as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .unwrap();
            assert_eq!((state, attempts, uncertain), (1, 1, 1));
            assert_eq!(raw, item.encode().unwrap());
            self.sent = raw;
            self.retained = Some(self.inner.submit_until(item, until)?);
            Err(NetError::Timeout)
        }
    }

    fn assert_mailbox(fixture: &Fixture, exact: &RelayItem) {
        let store = fixture.open();
        let page = store.page(0, 4).unwrap();
        assert_eq!(page.head, 1);
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.records[0].item, *exact);
        let (count, bytes): (i64, i64) = store
            .conn
            .query_row("SELECT COUNT(*), SUM(bytes) FROM tls_charges", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(bytes as usize, exact.payload().len());
        let (digest, owner): (Vec<u8>, Vec<u8>) = store
            .conn
            .query_row("SELECT digest,key_id FROM tls_charges", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!(digest, exact.digest());
        assert_eq!(owner, [1; 16]);
    }

    let f = Fixture::new();
    let cert = certificates();
    // Keep the selected endpoint unchanged across service restarts. Neither
    // the queue nor its transport profile is relabeled to a new test port.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let mut owner = credential(1, 7);
    owner.storage.max_items = 1;
    let first = Service::new(
        f.open(),
        cert.config.clone(),
        vec![owner],
        ServiceLimits::default(),
    )
    .unwrap();
    let first_listener = listener.try_clone().unwrap();
    let first_worker = thread::spawn(move || first.serve(first_listener, Some(1)).unwrap());
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
    let queue = f.0.join("formal-delivery");
    let profile = client(address, &cert, 7).endpoint_id();
    let mut jobs = DeliveryStore::create_new(
        &queue,
        context,
        ns(),
        profile,
        delivery::Limits {
            max_jobs: 2,
            max_bytes: 1024 * 1024,
        },
        RetryPolicy {
            max_attempts: 2,
            initial_backoff_secs: 1,
            max_backoff_secs: 8,
        },
    )
    .unwrap();
    let budget = || TickBudget {
        max_jobs: 2,
        max_bytes: 1024 * 1024,
        deadline: deadline(),
    };
    let exact = item(1);
    let queued = jobs.enqueue(&exact, 100).unwrap();
    let mut lost = LoseReceipt {
        inner: client(address, &cert, 7),
        queue: queue.clone(),
        retained: None,
        sent: Vec::new(),
    };
    let uncertain = jobs.tick(&mut lost, 100, budget()).unwrap().jobs.remove(0);
    assert_eq!(uncertain.state, JobState::Uncertain);
    assert_eq!(
        uncertain.attempts, 0,
        "a committed outage restores its charge"
    );
    assert!(uncertain.uncertain);
    assert_eq!(jobs.evidence(queued.id).unwrap().outages, 1);
    let receipt = lost.retained.unwrap();
    assert_eq!(receipt.digest, queued.id);
    assert_eq!(receipt.position, 1);
    assert!(!receipt.duplicate);
    assert_eq!(lost.sent, exact.encode().unwrap());
    first_worker.join().unwrap();
    drop(jobs);
    assert_mailbox(&f, &exact);

    let mut replacement = credential(1, 9);
    replacement.storage.max_items = 1;
    let second = Service::new(
        f.open(),
        cert.config.clone(),
        vec![replacement],
        ServiceLimits::default(),
    )
    .unwrap();
    let second_listener = listener.try_clone().unwrap();
    let second_worker = thread::spawn(move || second.serve(second_listener, Some(4)).unwrap());
    let mut jobs = DeliveryStore::open(&queue, context, ns(), profile).unwrap();
    assert_eq!(jobs.job(queued.id).unwrap(), Some(uncertain.clone()));
    let mut old_token = client(address, &cert, 7);
    let mut new_token = client(address, &cert, 9);
    assert_eq!(old_token.endpoint_id(), new_token.endpoint_id());
    let denied = jobs
        .tick(&mut old_token, uncertain.next_due, budget())
        .unwrap()
        .jobs
        .remove(0);
    assert_eq!(denied.state, JobState::Uncertain);
    assert_eq!(denied.attempts, 1);
    assert_eq!(denied.last_error, Some(NetError::Denied));
    assert!(denied.uncertain);
    drop(jobs);
    let mut jobs = DeliveryStore::open(&queue, context, ns(), profile).unwrap();
    let stopped = jobs
        .tick(&mut old_token, denied.next_due, budget())
        .unwrap()
        .jobs
        .remove(0);
    assert_eq!(stopped.state, JobState::Stopped);
    assert_eq!(stopped.attempts, 2);
    assert!(stopped.uncertain);
    drop(jobs);
    let mut jobs = DeliveryStore::open(&queue, context, ns(), profile).unwrap();
    assert!(jobs
        .tick(&mut new_token, stopped.next_due, budget())
        .unwrap()
        .jobs
        .is_empty());
    let resumed = jobs.resume(Some(queued.id), stopped.next_due).unwrap();
    assert_eq!(resumed.len(), 1);
    assert_eq!(resumed[0].state, JobState::Uncertain);
    assert!(resumed[0].uncertain);
    assert_eq!(resumed[0].attempts, 0);
    assert_eq!(resumed[0].id, queued.id);
    assert_eq!(resumed[0].operation, queued.operation);
    assert_eq!(resumed[0].sequence, queued.sequence);
    let evidence = jobs.evidence(queued.id).unwrap();
    assert_eq!(
        (evidence.outages, evidence.resumes, evidence.spent_attempts),
        (1, 1, 2)
    );
    assert!(jobs
        .resume(Some(queued.id), stopped.next_due)
        .unwrap()
        .is_empty());
    assert_eq!(jobs.evidence(queued.id).unwrap(), evidence);
    assert_eq!(jobs.enqueue(&exact, stopped.next_due).unwrap(), resumed[0]);
    drop(jobs);
    let mut jobs = DeliveryStore::open(&queue, context, ns(), profile).unwrap();
    let retained = jobs
        .tick(&mut new_token, stopped.next_due, budget())
        .unwrap()
        .jobs
        .remove(0);
    assert_eq!(retained.state, JobState::Retained);
    assert_eq!(retained.position, Some(receipt.position));
    assert_eq!(retained.attempts, 1);
    assert!(!retained.uncertain);
    assert_eq!(jobs.evidence(queued.id).unwrap(), evidence);

    // Token replacement did not renew the stable identity's retained quota.
    let second_job = jobs.enqueue(&item(2), stopped.next_due + 1).unwrap();
    let full = jobs
        .tick(&mut new_token, stopped.next_due + 1, budget())
        .unwrap()
        .jobs
        .remove(0);
    assert_eq!(full.id, second_job.id);
    assert_eq!(full.last_error, Some(NetError::Capacity));
    assert_eq!(full.state, JobState::Pending);
    assert_eq!(full.attempts, 1);
    assert!(!full.uncertain);
    second_worker.join().unwrap();
    drop(jobs);
    assert_mailbox(&f, &exact);
    let jobs = DeliveryStore::open(&queue, context, ns(), profile).unwrap();
    assert_eq!(jobs.job(queued.id).unwrap(), Some(retained));
    assert_eq!(jobs.job(second_job.id).unwrap(), Some(full));
    assert_eq!(jobs.evidence(queued.id).unwrap(), evidence);
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
fn page_window_bills_actual_response_bytes_not_worst_case() {
    let f = Fixture::new();
    let cert = certificates();
    // item(1) encodes to 122 bytes: PUT bills 155+4 request + 46 response.
    // Each one-record PAGE bills 43+4 request + 150 actual response bytes.
    let mut limited = credential(1, 7);
    limited.bytes_per_window = 800;
    let limits = ServiceLimits {
        bytes_per_window: 1600,
        window: Duration::from_secs(60),
        ..ServiceLimits::default()
    };
    let (addr, worker) = f.serve(&cert, vec![limited], limits, 5);
    let c = client(addr, &cert, 7);
    c.submit(&item(1)).unwrap();
    for _ in 0..3 {
        assert_eq!(c.page(0, 64).unwrap().records.len(), 1);
    }
    // Worst-case reservation (4 MiB per PAGE) could never admit even the first
    // page under an 800-byte window; actual billing admits real work and then
    // reports an explicit retryable capacity once the true budget is spent.
    assert_eq!(c.page(0, 64).err(), Some(NetError::Capacity));
    worker.join().unwrap();
}
#[test]
fn over_limit_pre_auth_sockets_get_an_alert_and_progress_resumes() {
    let f = Fixture::new();
    let cert = certificates();
    let limits = ServiceLimits {
        max_connections: 2,
        request_timeout: Duration::from_millis(800),
        window: Duration::from_secs(60),
        ..ServiceLimits::default()
    };
    let (addr, worker) = f.serve(&cert, vec![credential(1, 7)], limits, 4);
    // Two unauthenticated sockets occupy every worker slot.
    let _hold1 = TcpStream::connect(addr).unwrap();
    let _hold2 = TcpStream::connect(addr).unwrap();
    thread::sleep(Duration::from_millis(150));
    // The next socket is answered, not silently dropped: the pre-handshake
    // fatal internal_error alert is the only refusal a TLS client can read.
    let mut refused = TcpStream::connect(addr).unwrap();
    refused
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut alert = [0; 7];
    refused.read_exact(&mut alert).unwrap();
    assert_eq!(alert, [0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x50]);
    // Held sockets expire at their bounded handshake deadline; an admitted
    // authenticated request then completes normally.
    thread::sleep(Duration::from_millis(1300));
    client(addr, &cert, 7).submit(&item(1)).unwrap();
    worker.join().unwrap();
    assert_eq!(f.open().page(0, 64).unwrap().head, 1);
}
fn read_alert(stream: &mut TcpStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut alert = [0; 7];
    stream.read_exact(&mut alert).unwrap();
    assert_eq!(alert, [0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x50]);
}
fn awaits_client_hello(stream: &TcpStream) -> bool {
    stream
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let mut byte = [0; 1];
    matches!(
        (&mut &*stream).read(&mut byte).map_err(|e| e.kind()),
        Err(std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)
    )
}
#[test]
fn loopback_peers_share_only_the_global_connection_bound() {
    let f = Fixture::new();
    let cert = certificates();
    // Eight slots would give a remote source two. Loopback peers, which
    // include an overlay forward carrying several clients, may use them all.
    let limits = ServiceLimits {
        max_connections: 8,
        request_timeout: Duration::from_secs(3),
        window: Duration::from_secs(60),
        ..ServiceLimits::default()
    };
    let (addr, worker) = f.serve(&cert, vec![credential(1, 7)], limits, 4);
    let held: Vec<TcpStream> = (0..3).map(|_| TcpStream::connect(addr).unwrap()).collect();
    thread::sleep(Duration::from_millis(150));
    assert!(
        awaits_client_hello(&held[2]),
        "third loopback socket refused"
    );
    client(addr, &cert, 7).submit(&item(1)).unwrap();
    drop(held);
    worker.join().unwrap();
    assert_eq!(f.open().page(0, 64).unwrap().head, 1);
}
/// The routed source address of this host, found by connecting a UDP socket
/// (which sends nothing) toward a documentation address, provided the host
/// also accepts its own TCP connections on it.
#[cfg(target_os = "linux")]
fn routed_address() -> Option<std::net::IpAddr> {
    let probe = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    probe.connect("192.0.2.1:9").ok()?;
    let ip = probe.local_addr().ok()?.ip();
    if ip.is_loopback() || ip.is_unspecified() {
        return None;
    }
    let listener = TcpListener::bind((ip, 0)).ok()?;
    TcpStream::connect_timeout(&listener.local_addr().ok()?, Duration::from_secs(2)).ok()?;
    Some(ip)
}
#[cfg(target_os = "linux")]
#[test]
fn a_remote_source_is_held_to_its_share_while_other_peers_progress() {
    let Some(ip) = routed_address() else {
        eprintln!("skipped: this host has no routed non-loopback IPv4 address");
        return;
    };
    let f = Fixture::new();
    let cert = certificates();
    // Eight slots and 16 handshakes per window give each remote source two
    // live connections and four handshakes per window. Held sockets end when
    // dropped, so the long deadline only removes timing sensitivity.
    let limits = ServiceLimits {
        max_connections: 8,
        request_timeout: Duration::from_secs(3),
        window: Duration::from_secs(60),
        requests_per_window: 8,
        ..ServiceLimits::default()
    };
    let key = Credential {
        requests_per_window: 4,
        ..credential(1, 7)
    };
    let service = Service::new(f.open(), cert.config.clone(), vec![key], limits).unwrap();
    // A wildcard test listener lets this host dial itself both as a remote
    // source (its routed address) and as a loopback peer.
    let listener = TcpListener::bind("0.0.0.0:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (remote, local) = (
        SocketAddr::new(ip, port),
        SocketAddr::from(([127, 0, 0, 1], port)),
    );
    let worker = thread::spawn(move || service.serve(listener, Some(7)).unwrap());
    let held = [
        TcpStream::connect(remote).unwrap(),
        TcpStream::connect(remote).unwrap(),
    ];
    assert!(held.iter().all(awaits_client_hello));
    read_alert(&mut TcpStream::connect(remote).unwrap());
    drop(held);
    thread::sleep(Duration::from_millis(300));
    // Released slots return: the third handshake in this window completes.
    client(remote, &cert, 7).submit(&item(1)).unwrap();
    drop(TcpStream::connect(remote).unwrap());
    // The fifth handshake exceeds the source's window share...
    read_alert(&mut TcpStream::connect(remote).unwrap());
    // ...while a loopback peer still has the global allowance.
    client(local, &cert, 7).submit(&item(2)).unwrap();
    worker.join().unwrap();
    assert_eq!(f.open().page(0, 64).unwrap().head, 2);
}
#[test]
fn per_key_charge_index_is_created_and_repaired_idempotently() {
    let f = Fixture::new();
    let cert = certificates();
    let present = |store: &FileStore| {
        store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='tls_charges_by_key'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap()
    };
    assert_eq!(present(&f.open()), 1);
    f.open()
        .conn
        .execute_batch("DROP INDEX tls_charges_by_key")
        .unwrap();
    assert_eq!(present(&f.open()), 0);
    // A store enrolled before the index existed is repaired once at open.
    let service = Service::new(
        f.open(),
        cert.config.clone(),
        vec![credential(1, 7)],
        ServiceLimits::default(),
    )
    .unwrap();
    drop(service);
    assert_eq!(present(&f.open()), 1);
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
