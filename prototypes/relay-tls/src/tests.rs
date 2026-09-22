use crate::adapter::*;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    ServerConfig,
};
use std::{
    io::Write,
    net::{SocketAddr, TcpListener, TcpStream},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};
use vhalla_private_kernel::{OperationId, OutboxKind};
use vhalla_private_native::relay::{
    net::{Mailbox, RelayToken, SocketRelay},
    FileStore, Limits, RelayItem, RelayNamespace, Store, MAX_RELAY_PAGE, MAX_RELAY_PAYLOAD,
};

const NAME: &str = "relay.qualification.invalid";
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn token() -> RelayToken {
    RelayToken::from_bytes([7; 32]).unwrap()
}
fn namespace() -> RelayNamespace {
    RelayNamespace::from_bytes([9; 32]).unwrap()
}
fn item(sequence: u64) -> RelayItem {
    RelayItem::new(
        namespace(),
        sequence,
        OperationId::from_bytes([sequence as u8; 16]).unwrap(),
        OutboxKind::Application,
        b"already committed opaque ciphertext",
    )
    .unwrap()
}
fn store(max_items: usize) -> Store {
    Store::new(
        namespace(),
        Limits {
            max_items,
            max_bytes: 16 * MAX_RELAY_PAYLOAD,
        },
    )
    .unwrap()
}
struct Credentials {
    root: CertificateDer<'static>,
    server: Arc<ServerConfig>,
}
fn credentials() -> Credentials {
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
    let server =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap();
    assert_eq!(server.max_early_data_size, 0);
    Credentials {
        root: issuer.der().clone(),
        server: Arc::new(server),
    }
}
struct Outcome<S> {
    store: S,
    observed: Observation,
    failures: Vec<Failure>,
}
fn serve<S: Mailbox + Send + 'static>(
    credentials: &Credentials,
    mut store: S,
    connections: usize,
    timeout: Duration,
) -> (SocketAddr, thread::JoinHandle<Outcome<S>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let config = credentials.server.clone();
    let worker = thread::spawn(move || {
        let mut observed = Observation::default();
        let mut failures = Vec::new();
        for _ in 0..connections {
            let (stream, _) = listener.accept().unwrap();
            if let Err(error) = serve_one(
                stream,
                config.clone(),
                &mut store,
                token(),
                Instant::now() + timeout,
                &mut observed,
            ) {
                failures.push(error);
            }
        }
        Outcome {
            store,
            observed,
            failures,
        }
    });
    (address, worker)
}
fn client(address: SocketAddr, credentials: &Credentials) -> Client {
    Client::new(
        address,
        NAME,
        credentials.root.clone(),
        token(),
        namespace(),
    )
}

#[test]
fn real_tls_retains_exact_items_pages_and_retries_without_acceptance_claims() {
    let credentials = credentials();
    let (address, worker) = serve(&credentials, store(4), 4, Duration::from_secs(5));
    let client = client(address, &credentials);
    let first = client.submit(&item(1), deadline()).unwrap();
    assert_eq!(first.position, 1);
    assert!(!first.duplicate);
    assert_eq!(
        client.submit(&item(1), deadline()).unwrap().digest,
        first.digest
    );
    assert!(client.submit(&item(1), deadline()).unwrap().duplicate);
    let page = client.page(0, 2, deadline()).unwrap();
    assert_eq!(page.head, 1);
    assert_eq!(page.next, None);
    assert_eq!(page.records[0].item, item(1));
    let outcome = worker.join().unwrap();
    assert_eq!(outcome.store.page(0, 2).unwrap().records.len(), 1);
    assert!(outcome.failures.is_empty());
}

#[test]
fn wrong_ca_and_wrong_name_send_zero_decrypted_application_bytes() {
    let trusted = credentials();
    let impostor = credentials();
    for wrong_name in [false, true] {
        let serving = if wrong_name { &trusted } else { &impostor };
        let (address, worker) = serve(serving, store(2), 1, Duration::from_secs(5));
        let client = Client::new(
            address,
            if wrong_name {
                "other.qualification.invalid"
            } else {
                NAME
            },
            trusted.root.clone(),
            token(),
            namespace(),
        );
        assert_eq!(client.submit(&item(1), deadline()), Err(Failure::Transport));
        let outcome = worker.join().unwrap();
        assert_eq!(outcome.observed.application_bytes, 0);
        assert!(outcome.observed.frames.is_empty());
        assert_eq!(outcome.store.page(0, 1).unwrap().head, 0);
    }
}

#[test]
fn wrong_token_foreign_namespace_and_capacity_fail_without_new_retention() {
    let credentials = credentials();
    let (address, worker) = serve(&credentials, store(1), 4, Duration::from_secs(5));
    let wrong_token = Client::new(
        address,
        NAME,
        credentials.root.clone(),
        RelayToken::from_bytes([8; 32]).unwrap(),
        namespace(),
    );
    assert_eq!(
        wrong_token.submit(&item(1), deadline()),
        Err(Failure::Denied)
    );
    let client = client(address, &credentials);
    let foreign = RelayItem::new(
        RelayNamespace::from_bytes([8; 32]).unwrap(),
        1,
        item(1).operation(),
        OutboxKind::Application,
        b"foreign",
    )
    .unwrap();
    // Exercise server scope admission, bypassing the client's earlier check.
    assert_eq!(
        client.exchange(PUT, &foreign.encode().unwrap(), deadline()),
        Err(Failure::Scope)
    );
    client.submit(&item(1), deadline()).unwrap();
    assert_eq!(client.submit(&item(2), deadline()), Err(Failure::Capacity));
    let outcome = worker.join().unwrap();
    assert_eq!(outcome.store.page(0, 2).unwrap().head, 1);
    assert_eq!(outcome.observed.frames.len(), 4);
}

#[test]
fn malformed_and_oversized_requests_do_not_prevent_next_verified_client() {
    let credentials = credentials();
    let (address, worker) = serve(&credentials, store(2), 3, Duration::from_secs(5));
    let client = client(address, &credentials);
    assert_eq!(
        client.exchange(PUT, b"not a canonical relay item", deadline()),
        Err(Failure::Protocol)
    );
    client.oversized_frame(deadline()).unwrap();
    assert!(client.submit(&item(1), deadline()).is_ok());
    let outcome = worker.join().unwrap();
    assert_eq!(outcome.store.page(0, 1).unwrap().head, 1);
    assert_eq!(outcome.failures, vec![Failure::Protocol]);
}

#[test]
fn unauthenticated_slow_handshake_expires_before_next_client_is_served() {
    let credentials = credentials();
    let (address, worker) = serve(&credentials, store(2), 2, Duration::from_millis(250));
    let mut attacker = TcpStream::connect(address).unwrap();
    // Valid TLS handshake record header claiming an incomplete 100-byte body.
    attacker.write_all(&[0x16, 0x03, 0x03, 0, 100]).unwrap();
    let trickle = thread::spawn(move || {
        for _ in 0..40 {
            if attacker.write_all(&[0]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(30));
        }
    });
    assert!(client(address, &credentials)
        .submit(&item(1), deadline())
        .is_ok());
    trickle.join().unwrap();
    let outcome = worker.join().unwrap();
    assert_eq!(outcome.failures, vec![Failure::Timeout]);
    assert_eq!(outcome.observed.frames.len(), 1);
    assert_eq!(outcome.store.page(0, 1).unwrap().head, 1);
}

#[test]
fn lost_receipt_retries_exact_ciphertext_after_durable_mailbox_reopen() {
    let credentials = credentials();
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "valhalla-tls-mailbox-{}-{stamp}",
        std::process::id()
    ));
    let limits = Limits {
        max_items: 4,
        max_bytes: 4096,
    };
    let mailbox = FileStore::create_new(&path, namespace(), limits).unwrap();
    let (address, worker) = serve(&credentials, mailbox, 1, Duration::from_secs(5));
    client(address, &credentials)
        .lose_receipt(&item(1), deadline())
        .unwrap();
    let outcome = worker.join().unwrap();
    assert_eq!(outcome.store.page(0, 1).unwrap().head, 1);
    drop(outcome);
    let mailbox = FileStore::open(&path, namespace()).unwrap();
    let (address, worker) = serve(&credentials, mailbox, 1, Duration::from_secs(5));
    let receipt = client(address, &credentials)
        .submit(&item(1), deadline())
        .unwrap();
    assert!(receipt.duplicate);
    assert_eq!(receipt.position, 1);
    assert_eq!(receipt.digest, item(1).digest());
    drop(worker.join().unwrap());
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn put_and_page_frames_match_production_socket_bytes_exactly() {
    let credentials = credentials();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let capture = thread::spawn(move || {
        let mut frames = Vec::new();
        for request_index in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            frames.push(read_frame(&mut stream, MAX_RELAY_PAYLOAD + 256, deadline()).unwrap());
            let mut response = Vec::new();
            if request_index == 0 {
                response.extend_from_slice(&1u64.to_be_bytes());
                response.extend_from_slice(&item(1).digest());
                response.push(0);
            } else {
                response.extend_from_slice(&1u64.to_be_bytes());
                response.push(0);
                response.extend_from_slice(&1u16.to_be_bytes());
                response.extend_from_slice(&1u64.to_be_bytes());
                let encoded = item(1).encode().unwrap();
                response.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
                response.extend_from_slice(&encoded);
            }
            stream.write_all(&frame(0, &response)).unwrap();
        }
        frames
    });
    let production = SocketRelay::new(address, token());
    production.submit(&item(1)).unwrap();
    let expected_page = production.page(0, 2).unwrap();
    let expected_frames = capture.join().unwrap();
    let (address, worker) = serve(&credentials, store(2), 2, Duration::from_secs(5));
    let client = client(address, &credentials);
    client.submit(&item(1), deadline()).unwrap();
    let actual_page = client.page(0, 2, deadline()).unwrap();
    assert_eq!(actual_page.records, expected_page.records);
    assert_eq!(actual_page.head, expected_page.head);
    assert_eq!(actual_page.next, expected_page.next);
    assert_eq!(worker.join().unwrap().observed.frames, expected_frames);
}

#[test]
fn maximum_items_page_truncates_at_wire_budget_and_resumes() {
    let credentials = credentials();
    let mut mailbox = Store::new(
        namespace(),
        Limits {
            max_items: 32,
            max_bytes: 20 * MAX_RELAY_PAYLOAD,
        },
    )
    .unwrap();
    for sequence in 1..=20 {
        mailbox
            .put(
                RelayItem::new(
                    namespace(),
                    sequence,
                    OperationId::from_bytes([sequence as u8; 16]).unwrap(),
                    OutboxKind::Application,
                    &vec![sequence as u8; MAX_RELAY_PAYLOAD],
                )
                .unwrap(),
            )
            .unwrap();
    }
    let (address, worker) = serve(&credentials, mailbox, 2, Duration::from_secs(5));
    let client = client(address, &credentials);
    let first = client.page(0, MAX_RELAY_PAGE, deadline()).unwrap();
    let next = first.next.unwrap();
    assert!(first.records.len() < 20);
    let second = client.page(next, MAX_RELAY_PAGE, deadline()).unwrap();
    assert_eq!(first.records.len() + second.records.len(), 20);
    assert_eq!(second.next, None);
    assert_eq!(second.head, 20);
    assert!(worker.join().unwrap().failures.is_empty());
}

#[test]
fn canonical_empty_absence_beyond_head_matches_the_production_page_contract() {
    let credentials = credentials();
    let mut native_store = store(2);
    native_store.put(item(1)).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let native = thread::spawn(move || {
        vhalla_private_native::relay::net::serve(listener, native_store, token(), Some(1))
    });
    let expected = SocketRelay::new(address, token()).page(4, 2).unwrap();
    native.join().unwrap().unwrap();
    let mut tls_store = store(2);
    tls_store.put(item(1)).unwrap();
    let (address, worker) = serve(&credentials, tls_store, 1, Duration::from_secs(5));
    let actual = client(address, &credentials)
        .page(4, 2, deadline())
        .unwrap();
    assert_eq!(actual.head, expected.head);
    assert_eq!(actual.next, expected.next);
    assert_eq!(actual.records, expected.records);
    assert!(worker.join().unwrap().failures.is_empty());
}
