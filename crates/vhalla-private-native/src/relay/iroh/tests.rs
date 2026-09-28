use super::*;
use crate::relay::{
    tls::{Credential, Permissions, ServiceLimits},
    FileStore, Limits,
};
use vhalla_private_kernel::{OperationId, OutboxKind};
fn namespace() -> RelayNamespace {
    RelayNamespace::from_bytes([9; 32]).unwrap()
}
fn token(value: u8) -> RelayToken {
    RelayToken::from_bytes([value; 32]).unwrap()
}
fn item(value: u8) -> RelayItem {
    RelayItem::new(
        namespace(),
        u64::from(value),
        OperationId::from_bytes([value; 16]).unwrap(),
        OutboxKind::Application,
        b"already encrypted",
    )
    .unwrap()
}
fn credential() -> Credential {
    Credential {
        id: [1; 16],
        tokens: vec![token(7)],
        namespace: namespace(),
        permissions: Permissions {
            put: true,
            page: true,
        },
        storage: Limits {
            max_items: 2,
            max_bytes: 4096,
        },
        max_inflight: 2,
        requests_per_window: 64,
        bytes_per_window: 32 * 1024 * 1024,
    }
}
struct Fixture {
    path: std::path::PathBuf,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<Result<()>>>,
    endpoint: IrohEndpoint,
}
impl Fixture {
    fn new() -> Self {
        Self::with_relay(None)
    }
    fn with_relay(relay: Option<&str>) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "vhalla-iroh-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let store = FileStore::create_new(
            &path,
            namespace(),
            Limits {
                max_items: 16,
                max_bytes: 1024 * 1024,
            },
        )
        .unwrap();
        Service::initialize(store).unwrap();
        let store = FileStore::open(&path, namespace()).unwrap();
        let service =
            Service::new_iroh(store, vec![credential()], ServiceLimits::default()).unwrap();
        let listener = IrohListener::bind([2; 32], "127.0.0.1:0".parse().unwrap(), relay).unwrap();
        listener.set_namespace(namespace());
        let endpoint = listener.endpoint();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let worker = thread::spawn(move || service.serve_iroh_until(listener, None, stopped));
        let fixture = Self {
            path,
            stop,
            worker: Some(worker),
            endpoint,
        };
        // A bounded readiness probe avoids depending on thread scheduling.
        let client = fixture.client(7);
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            if client.page_until(0, 1, until).is_ok() {
                break;
            }
            assert!(Instant::now() < until);
            thread::sleep(Duration::from_millis(10));
        }
        fixture
    }
    fn client(&self, key: u8) -> IrohRelay {
        IrohRelay::new(self.endpoint.clone(), token(key), namespace()).unwrap()
    }
    fn stop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap().unwrap();
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let result = self
            .worker
            .take()
            .map(|worker| {
                worker
                    .join()
                    .map_err(|_| NetError::Unavailable)
                    .and_then(|result| result)
            })
            .unwrap_or(Ok(()));
        if thread::panicking() || result.is_err() {
            eprintln!("iroh test evidence retained at {}", self.path.display());
            if !thread::panicking() {
                panic!("iroh fixture shutdown failed: {result:?}");
            }
            return;
        }
        std::fs::remove_dir_all(&self.path).unwrap();
    }
}
#[test]
fn authenticated_quic_retains_canonical_bytes_and_durable_quota() {
    let mut fixture = Fixture::new();
    let client = fixture.client(7);
    let receipt = client.submit(&item(1)).unwrap();
    assert_eq!(receipt.position, 1);
    assert!(!receipt.duplicate);
    assert!(client.submit(&item(1)).unwrap().duplicate);
    assert_eq!(client.page(0, 64).unwrap().records[0].item, item(1));
    assert_eq!(fixture.client(8).page(0, 1).err(), Some(NetError::Denied));
    client.submit(&item(2)).unwrap();
    assert_eq!(client.submit(&item(3)), Err(NetError::Capacity));
    fixture.stop();
    let store = FileStore::open(&fixture.path, namespace()).unwrap();
    assert_eq!(store.page(0, 64).unwrap().head, 2);
    let service = Service::new_iroh(store, vec![credential()], ServiceLimits::default()).unwrap();
    let listener = IrohListener::bind([2; 32], "127.0.0.1:0".parse().unwrap(), None).unwrap();
    listener.set_namespace(namespace());
    let reopened = IrohRelay::new(listener.endpoint(), token(7), namespace()).unwrap();
    fixture.stop.store(false, Ordering::Release);
    let stop = fixture.stop.clone();
    fixture.worker = Some(thread::spawn(move || {
        service.serve_iroh_until(listener, None, stop)
    }));
    assert_eq!(reopened.submit(&item(3)), Err(NetError::Capacity));
}
#[test]
fn held_page_and_sync_client_inside_async_runtime() {
    let fixture = Fixture::new();
    let client = fixture.client(7);
    let held = client.clone();
    let waiter = thread::spawn(move || {
        held.page_wait_until(
            0,
            1,
            Duration::from_secs(3),
            Instant::now() + Duration::from_secs(5),
        )
    });
    let runtime = runtime().unwrap();
    runtime.block_on(async {
        assert_eq!(client.submit(&item(1)).unwrap().position, 1);
    });
    assert_eq!(waiter.join().unwrap().unwrap().records[0].item, item(1));
    // Dropping the final synchronous client on a runtime thread must not panic.
    runtime.block_on(async {
        drop(client);
    });
}
#[test]
fn wrong_identity_and_namespace_do_not_reach_admission() {
    let fixture = Fixture::new();
    let mut wrong = fixture.endpoint.clone();
    wrong.endpoint_id = endpoint_id_from_secret(&[3; 32]);
    let client = IrohRelay::new(wrong, token(7), namespace()).unwrap();
    assert_eq!(
        client
            .page_until(0, 1, Instant::now() + Duration::from_secs(2))
            .err(),
        Some(NetError::Connect)
    );
    let client = IrohRelay::new(
        fixture.endpoint.clone(),
        token(7),
        RelayNamespace::from_bytes([8; 32]).unwrap(),
    )
    .unwrap();
    assert!(client
        .page_until(0, 1, Instant::now() + Duration::from_secs(2))
        .is_err());
    assert_eq!(fixture.client(7).page(0, 1).unwrap().head, 0);
}
#[test]
fn endpoint_validation_and_delivery_identity_ignore_only_routing_hints() {
    let endpoint = IrohEndpoint {
        endpoint_id: endpoint_id_from_secret(&[2; 32]),
        relay_url: None,
        addresses: vec!["127.0.0.1:1234".parse().unwrap()],
    };
    endpoint.validate().unwrap();
    let identity = endpoint.delivery_endpoint_id(namespace()).unwrap();
    let mut changed = endpoint.clone();
    changed.addresses = vec!["127.0.0.1:9876".parse().unwrap()];
    assert_eq!(identity, changed.delivery_endpoint_id(namespace()).unwrap());
    changed.endpoint_id = endpoint_id_from_secret(&[3; 32]);
    assert_ne!(identity, changed.delivery_endpoint_id(namespace()).unwrap());
    let mut invalid = endpoint;
    invalid.addresses = vec!["0.0.0.0:1234".parse().unwrap()];
    assert_eq!(invalid.validate(), Err(NetError::Bounds));
    assert_eq!(checked_relay("http://example.com"), Err(NetError::Bounds));
    assert_eq!(
        checked_relay("https://user:password@example.com"),
        Err(NetError::Bounds)
    );
}

#[test]
fn client_construction_is_pure_and_scope_refusals_do_not_start_network() {
    let endpoint = IrohEndpoint {
        endpoint_id: endpoint_id_from_secret(&[2; 32]),
        relay_url: Some(DEFAULT_RELAY_URL.into()),
        addresses: Vec::new(),
    };
    let client = IrohRelay::new(endpoint, token(7), namespace()).unwrap();
    assert!(client.worker.lock().unwrap().is_none());
    assert_eq!(
        client.page_until(0, 1, Instant::now()).err(),
        Some(NetError::Timeout)
    );
    assert!(client.worker.lock().unwrap().is_none());
    let wrong = RelayItem::new(
        RelayNamespace::from_bytes([8; 32]).unwrap(),
        1,
        OperationId::from_bytes([1; 16]).unwrap(),
        OutboxKind::Application,
        b"encrypted",
    )
    .unwrap();
    assert_eq!(client.submit(&wrong), Err(NetError::Scope));
    assert!(client.worker.lock().unwrap().is_none());
}

/// Explicit network qualification: only synthetic ciphertext leaves this host.
/// Two local endpoints exercise the public relay, not independent NAT networks.
#[test]
#[ignore = "contacts the public iroh relay; run explicitly with network access"]
fn public_relay_only_retains_and_reads_synthetic_ciphertext() {
    let fixture = Fixture::with_relay(Some(DEFAULT_RELAY_URL));
    let addr = fixture.endpoint.address().unwrap();
    runtime().unwrap().block_on(async {
        let endpoint = builder(Some(DEFAULT_RELAY_URL))
            .unwrap()
            .clear_ip_transports()
            .bind()
            .await
            .unwrap();
        tokio::time::timeout(STARTUP_TIMEOUT, endpoint.online())
            .await
            .unwrap();
        for op in [OP_PUT, OP_PAGE] {
            let connection = tokio::time::timeout(
                STARTUP_TIMEOUT,
                endpoint.connect(addr.clone(), &protocol(namespace())),
            )
            .await
            .unwrap()
            .unwrap();
            let paths = connection.paths();
            assert!(!paths.is_empty());
            assert!(
                paths.iter().all(|path| path.is_relay()),
                "UDP is disabled: every path must be relayed"
            );
            let (mut send, mut recv) = connection.open_bi().await.unwrap();
            let mut payload = token(7).as_bytes().to_vec();
            if op == OP_PUT {
                payload.extend_from_slice(&item(1).encode().unwrap());
            } else {
                payload.extend_from_slice(&page_request(0, 1).unwrap());
            }
            send.write_all(&frame(op, &payload)).await.unwrap();
            send.finish().unwrap();
            let raw = tokio::time::timeout(STARTUP_TIMEOUT, recv.read_to_end(MAX_RESPONSE + 4))
                .await
                .unwrap()
                .unwrap();
            let (status, body) = decode_frame(&raw, MAX_RESPONSE).unwrap();
            let body = decode_status(status, body).unwrap();
            if op == OP_PUT {
                assert_eq!(decode_receipt(&body, &item(1)).unwrap().position, 1);
            } else {
                assert_eq!(decode_page(&body, 0, 1).unwrap().records[0].item, item(1));
            }
            connection.close(0u32.into(), b"done");
        }
        endpoint.close().await;
    });
}

#[test]
fn malformed_and_oversized_streams_never_reach_storage() {
    let fixture = Fixture::new();
    runtime().unwrap().block_on(async {
        tokio::time::timeout(Duration::from_secs(20), async {
            let endpoint = builder(None).unwrap().bind().await.unwrap();
            for raw in [vec![0, 0, 0, 0], vec![0; MAX_REQUEST + 5]] {
                let connection = endpoint
                    .connect(fixture.endpoint.address().unwrap(), &protocol(namespace()))
                    .await
                    .unwrap();
                let (mut send, mut recv) = connection.open_bi().await.unwrap();
                let _ = send.write_all(&raw).await;
                let _ = send.finish();
                let result = tokio::time::timeout(
                    Duration::from_secs(5),
                    recv.read_to_end(MAX_RESPONSE + 4),
                )
                .await
                .unwrap();
                assert!(result.is_err() || result.is_ok_and(|bytes| bytes.is_empty()));
                connection.close(0u32.into(), b"done");
            }
            endpoint.close().await;
        })
        .await
        .expect("hostile exchange exceeded its deadline");
    });
    let client = fixture.client(7);
    assert_eq!(client.page(0, 1).unwrap().head, 0);
    assert_eq!(client.submit(&item(1)).unwrap().position, 1);
    assert_eq!(client.page(0, 1).unwrap().records[0].item, item(1));
}

#[test]
fn shutdown_does_not_inherit_an_abandoned_page_wait_deadline() {
    let mut fixture = Fixture::new();
    let address = fixture.endpoint.address().unwrap();
    let (ready_tx, ready_rx) = sync_mpsc::sync_channel(1);
    let (resume_tx, resume_rx) = sync_mpsc::sync_channel(1);
    let peer = thread::spawn(move || {
        // Stop polling this runtime after transmitting the long-page request.
        // The server cannot receive an acknowledgement for its response.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (endpoint, connection, send, recv) = runtime.block_on(async {
            let endpoint = builder(None).unwrap().bind().await.unwrap();
            let connection = endpoint
                .connect(address, &protocol(namespace()))
                .await
                .unwrap();
            let (mut send, recv) = connection.open_bi().await.unwrap();
            let mut request = token(7).as_bytes().to_vec();
            request.extend_from_slice(&page_wait_request(0, 1, Duration::from_secs(60)).unwrap());
            send.write_all(&frame(OP_PAGE, &request)).await.unwrap();
            send.finish().unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
            (endpoint, connection, send, recv)
        });
        ready_tx.send(()).unwrap();
        let _ = resume_rx.recv_timeout(Duration::from_secs(30));
        drop((send, recv));
        connection.close(0u32.into(), b"done");
        runtime.block_on(endpoint.close());
    });
    ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let started = Instant::now();
    fixture.stop();
    let elapsed = started.elapsed();
    resume_tx.send(()).unwrap();
    peer.join().unwrap();
    assert!(
        elapsed < Duration::from_secs(15),
        "shutdown took {elapsed:?}"
    );
}
