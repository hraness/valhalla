use super::*;
use ed25519_dalek::SigningKey;
use std::{
    fs,
    sync::atomic::{AtomicU64, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vhalla_core::RealmId;
use vhalla_journal::{Bundle, BundleParts};
use vhalla_public_client::{Validator, ValidatorActivation};
use vhalla_public_protocol::{
    response::proof_from_hex, AdvertisementClaims, UnsignedAdvertisement, PROTOCOL_VERSION,
};
use vhalla_rooms::{registry::DirectoryPolicy, DirectoryId};
use vhalla_rooms_consensus::Genesis;
use vhalla_social::archive::{Archive, Limits};

static SERIAL: AtomicU64 = AtomicU64::new(0);
pub(super) struct Fixture {
    pub(super) dir: PathBuf,
    pub(super) config: Config,
    pub(super) frontier: [u8; 32],
}
impl Fixture {
    pub(super) fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "vhalla-public-peer-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        let realm = RealmId(77);
        let limits = Limits::default();
        let genesis = Genesis {
            directory: DirectoryId::from_bytes([8; 32]),
            realm,
            policy: DirectoryPolicy {
                base_cost: 1,
                window_seconds: 86400,
                max_in_window: 8,
                support_epoch_seconds: 86400,
                max_lifetime_rooms: 16,
            },
            eligible: vec![],
            limits,
            archive: Archive::new(realm, limits).unwrap(),
        };
        let key = SigningKey::from_bytes(&[17; 32]);
        let bootstrap = Bootstrap::from_genesis(
            genesis,
            vec![ValidatorActivation {
                from: 1,
                validators: vec![Validator {
                    public_key: key.verifying_key().to_bytes(),
                    power: 1,
                }],
            }],
        )
        .unwrap();
        let pin = bootstrap.pin();
        let network = bootstrap.network_id();
        let raw = bootstrap.encode();
        let frontier = CertifiedClient::new(bootstrap, pin)
            .unwrap()
            .frontier()
            .commitment();
        let identity_dir = dir.join("identity");
        let identity = Identity::create_new(&identity_dir).unwrap();
        let endpoint = Endpoint::parse("https://peer.vhalla.dev:443/vhalla/v1").unwrap();
        let advertisement = sign_ad(
            &identity,
            network,
            endpoint.clone(),
            1,
            now().unwrap() + 3600,
        );
        let config = Config {
            bootstrap_file: dir.join("bootstrap"),
            bootstrap_pin: pin,
            identity_dir,
            journal_dir: dir.join("journal"),
            advertisement_file: dir.join("advertisement"),
            public_endpoint: endpoint,
            allowed_origin: CorsOrigin::https("https://app.vhalla.dev").unwrap(),
            listen: "127.0.0.1:0".parse().unwrap(),
        };
        fs::write(&config.bootstrap_file, raw).unwrap();
        fs::write(&config.advertisement_file, advertisement).unwrap();
        Self {
            dir,
            config,
            frontier,
        }
    }
    fn peer(&self) -> Peer {
        Peer::open(self.config.clone()).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}
fn sign_ad(
    identity: &Identity,
    network: [u8; 32],
    endpoint: Endpoint,
    sequence: u64,
    expires: u64,
) -> Vec<u8> {
    identity
        .sign_public_advertisement(
            UnsignedAdvertisement::new(AdvertisementClaims {
                network,
                application_key: identity.public_key(),
                sequence,
                issued_at: expires - 3600,
                expires_at: expires,
                protocol: PROTOCOL_VERSION,
                capabilities: Capabilities::READ,
                endpoints: vec![endpoint],
            })
            .unwrap(),
        )
        .unwrap()
        .encode()
}
fn request(kind: ReadKind) -> ReadRequest {
    ReadRequest::new([7; 32], kind).unwrap()
}
fn http(request: ReadRequest) -> Request<()> {
    Request::builder()
        .uri(request.target())
        .header("host", "peer.vhalla.dev")
        .header("origin", "https://app.vhalla.dev")
        .body(())
        .unwrap()
}
fn bundle(predecessor: [u8; 32], next: [u8; 32], height: u64) -> Bundle {
    Bundle::new(BundleParts {
        certificate: b"opaque certificate; client still verifies".to_vec(),
        predecessor,
        next,
        batch: vec![1],
        value: vec![2],
        configuration: vec![3],
        control_record: vec![4],
        debit_marker: vec![5],
        height,
    })
    .unwrap()
}
#[test]
fn startup_binds_pin_key_route_and_loopback_without_creating_journal() {
    let fixture = Fixture::new();
    let mut config = fixture.config.clone();
    config.listen = "0.0.0.0:9790".parse().unwrap();
    assert!(matches!(Peer::open(config), Err(Error::Config)));
    let mut config = fixture.config.clone();
    config.bootstrap_pin[0] ^= 1;
    assert!(matches!(Peer::open(config), Err(Error::Bootstrap)));
    let mut config = fixture.config.clone();
    config.public_endpoint = Endpoint::parse("https://other.vhalla.dev:443/vhalla/v1").unwrap();
    assert!(matches!(Peer::open(config), Err(Error::Advertisement)));
    let peer = fixture.peer();
    assert!(!fixture.config.journal_dir.exists());
    assert_eq!(peer.application_key().len(), 32);
}
#[test]
fn header_method_body_origin_and_exact_target_boundaries() {
    let fixture = Fixture::new();
    let peer = fixture.peer();
    let typed = request(ReadKind::Bootstrap);
    assert_eq!(peer.check_request(&http(typed)), Ok(typed));
    for (name, value) in [
        ("cookie", "ambient=1"),
        ("authorization", "Bearer x"),
        ("transfer-encoding", "chunked"),
        ("content-length", "1"),
        ("expect", "100-continue"),
        ("upgrade", "websocket"),
        ("origin", "https://evil.vhalla.dev"),
        ("host", "localhost:9790"),
    ] {
        let mut req = http(typed);
        req.headers_mut().insert(name, value.parse().unwrap());
        assert!(peer.check_request(&req).is_err(), "{name}");
    }
    let mut req = http(typed);
    *req.method_mut() = Method::POST;
    assert_eq!(
        peer.check_request(&req),
        Err(StatusCode::METHOD_NOT_ALLOWED)
    );
    let mut req = http(typed);
    req.headers_mut()
        .append("origin", "https://app.vhalla.dev".parse().unwrap());
    assert!(peer.check_request(&req).is_err());
    let mut req = http(typed);
    req.headers_mut().remove("host");
    assert!(peer.check_request(&req).is_err());
    let mut req = http(typed);
    *req.uri_mut() = "/vhalla/v1/bootstrap?nonce=00".parse().unwrap();
    assert!(peer.check_request(&req).is_err());
    let mut req = http(typed);
    *req.uri_mut() = format!("/{}", "x".repeat(513)).parse().unwrap();
    assert!(peer.check_request(&req).is_err());
    assert!(CorsOrigin::https("https://app.vhalla.dev/path").is_err());
    assert!(CorsOrigin::https("http://app.vhalla.dev").is_err());
    assert!(CorsOrigin::loopback_development("192.0.2.1:3000".parse().unwrap()).is_err());
}
#[test]
fn page_serves_only_published_head_and_proofs_bind_exact_bytes() {
    let fixture = Fixture::new();
    let journal = Journal::with_genesis(&fixture.config.journal_dir, FsStore, fixture.frontier);
    let first = bundle(fixture.frontier, [1; 32], 1);
    journal.commit(&first).unwrap();
    let unpublished = bundle([1; 32], [2; 32], 2);
    fs::write(
        fixture
            .config
            .journal_dir
            .join("bundles")
            .join(hex(&unpublished.id())),
        unpublished.bytes(),
    )
    .unwrap();
    fs::write(
        fixture.config.journal_dir.join("heights/0000000000000002"),
        unpublished.id(),
    )
    .unwrap();
    let peer = fixture.peer();
    let typed = request(ReadKind::Bundles {
        after: 0,
        frontier: fixture.frontier,
        count: 32,
        bytes: 2 * 1024 * 1024,
    });
    let (raw, proof) = peer.answer(typed).unwrap();
    proof_from_hex(&proof)
        .unwrap()
        .verify(peer.network_id(), peer.application_key(), &typed, &raw)
        .unwrap();
    let page = BundlePage::decode(&raw, &typed).unwrap();
    assert_eq!(page.observed_height(), 1);
    assert_eq!(page.bundles(), &[first.bytes().to_vec()]);
    assert!(!page.has_more());
    let ahead = request(ReadKind::Bundles {
        after: 2,
        frontier: [2; 32],
        count: 1,
        bytes: 4096,
    });
    assert_eq!(peer.answer(ahead), Err(StatusCode::CONFLICT));
    let wrong = request(ReadKind::Bundles {
        after: 0,
        frontier: [4; 32],
        count: 1,
        bytes: 4096,
    });
    assert_eq!(peer.answer(wrong), Err(StatusCode::CONFLICT));
    assert!(fixture
        .config
        .journal_dir
        .join("heights/0000000000000002")
        .exists());
}
#[test]
fn advertisement_reload_is_monotone_and_expiry_fails_closed() {
    let fixture = Fixture::new();
    let peer = fixture.peer();
    let typed = request(ReadKind::Advertisement);
    let old = peer.answer(typed).unwrap().0;
    let issued = now().unwrap();
    let renewed = peer
        .sign_advertisement(2, issued, issued + 3600)
        .unwrap()
        .encode();
    fs::write(&fixture.config.advertisement_file, &renewed).unwrap();
    assert_eq!(peer.answer(typed).unwrap().0.as_ref(), renewed);
    fs::write(&fixture.config.advertisement_file, old).unwrap();
    assert_eq!(peer.answer(typed), Err(StatusCode::SERVICE_UNAVAILABLE));
    fs::write(&fixture.config.advertisement_file, &renewed).unwrap();
    assert!(peer.answer(typed).is_ok());
    let expired = sign_ad(
        &peer.identity,
        peer.network_id(),
        fixture.config.public_endpoint.clone(),
        3,
        now().unwrap() - 1,
    );
    fs::write(&fixture.config.advertisement_file, expired).unwrap();
    assert_eq!(peer.answer(typed), Err(StatusCode::SERVICE_UNAVAILABLE));
    assert!(peer.answer(request(ReadKind::Bootstrap)).is_ok());
}
#[test]
fn active_ip_map_and_connection_work_permits_are_bounded_and_reclaimed() {
    let admission = Arc::new(Admission::default());
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let mut permits = Vec::new();
    for _ in 0..MAX_CONNECTIONS_PER_IP {
        permits.push(admission.acquire(ip).unwrap());
    }
    assert!(admission.acquire(ip).is_none());
    let retained_by_job = permits.pop().unwrap();
    let second_owner = retained_by_job.clone();
    drop(retained_by_job);
    assert!(admission.acquire(ip).is_none());
    drop(second_owner);
    assert!(admission.acquire(ip).is_some());
    drop(permits);
    assert!(admission.active.lock().unwrap().is_empty());
    let mut permits = Vec::new();
    for index in 0..MAX_CONNECTIONS {
        permits.push(
            admission
                .acquire(IpAddr::from([10, 0, 0, index as u8]))
                .unwrap(),
        );
    }
    assert!(admission.acquire(ip).is_none());
    assert_eq!(admission.active.lock().unwrap().len(), MAX_CONNECTIONS);
    drop(permits);
    assert!(admission.active.lock().unwrap().is_empty());
}
#[test]
fn bounded_regular_reads_reject_symlink_oversize_and_directory() {
    let fixture = Fixture::new();
    let link = fixture.dir.join("link");
    std::os::unix::fs::symlink(&fixture.config.bootstrap_file, &link).unwrap();
    assert!(read_regular(&link, MAX_BOOTSTRAP_BYTES).is_err());
    assert!(read_regular(&fixture.config.bootstrap_file, 1).is_err());
    assert!(read_regular(&fixture.dir, 4096).is_err());
}
#[tokio::test]
async fn local_socket_bootstrap_has_verifiable_proof_and_rejects_post() {
    let fixture = Fixture::new();
    let peer = Arc::new(fixture.peer());
    let server = peer.clone().bind().await.unwrap();
    let address = server.local_addr().unwrap();
    assert!(address.ip().is_loopback());
    let (shutdown, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(server.run(async {
        let _ = stopped.await;
    }));
    let typed = request(ReadKind::Bootstrap);
    let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
    socket.write_all(format!("GET {} HTTP/1.1\r\nHost: peer.vhalla.dev\r\nOrigin: https://app.vhalla.dev\r\nConnection: close\r\n\r\n", typed.target()).as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    timeout(Duration::from_secs(3), socket.read_to_end(&mut raw))
        .await
        .unwrap()
        .unwrap();
    let end = raw.windows(4).position(|v| v == b"\r\n\r\n").unwrap();
    let headers = std::str::from_utf8(&raw[..end]).unwrap();
    let body = &raw[end + 4..];
    assert!(headers.starts_with("HTTP/1.1 200"));
    assert!(headers.contains("access-control-allow-origin: https://app.vhalla.dev"));
    assert!(!headers.contains("allow-credentials"));
    let proof = headers
        .lines()
        .find_map(|line| line.strip_prefix("x-vhalla-proof: "))
        .unwrap();
    proof_from_hex(proof)
        .unwrap()
        .verify(peer.network_id(), peer.application_key(), &typed, body)
        .unwrap();
    assert_eq!(body, fs::read(&fixture.config.bootstrap_file).unwrap());
    let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
    socket
        .write_all(
            b"POST /vhalla/v1 HTTP/1.1\r\nHost: peer.vhalla.dev\r\nContent-Length: 0\r\n\r\n",
        )
        .await
        .unwrap();
    let mut raw = Vec::new();
    timeout(Duration::from_secs(3), socket.read_to_end(&mut raw))
        .await
        .unwrap()
        .unwrap();
    assert!(raw.starts_with(b"HTTP/1.1 405"));
    shutdown.send(()).unwrap();
    task.await.unwrap().unwrap();
}
