use super::*;
use crate::unix::tests::Fixture;
use ed25519_dalek::SigningKey;
use std::sync::OnceLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vhalla_public_protocol::discovery::{
    DiscoveryResponseProof, RegistrationChallenge, UnsignedRegistration, MAX_SOLVE_ATTEMPTS,
};
use vhalla_public_protocol::{AdvertisementClaims, UnsignedAdvertisement, PROTOCOL_VERSION};

fn ad(key: &SigningKey, sequence: u64, issued: u64, expires: u64) -> PeerAdvertisement {
    UnsignedAdvertisement::new(AdvertisementClaims {
        network: [4; 32],
        application_key: key.verifying_key().to_bytes(),
        sequence,
        issued_at: issued,
        expires_at: expires,
        protocol: PROTOCOL_VERSION,
        capabilities: Capabilities::READ,
        endpoints: vec![Endpoint::parse("https://candidate.vhalla.dev:443/vhalla/v1").unwrap()],
    })
    .unwrap()
    .sign_with_key(key)
    .unwrap()
}
fn registration(ad: PeerAdvertisement, key: &SigningKey, now: u64, known: bool) -> Registration {
    let receiver = SigningKey::from_bytes(&[8; 32]);
    let request = DiscoveryRequest::new(
        [7; 32],
        DiscoveryKind::Challenge {
            publisher: key.verifying_key().to_bytes(),
            advertisement: Sha256::digest(ad.encode()).into(),
        },
    )
    .unwrap();
    let challenge = UnsignedRegistrationChallenge::new(
        [4; 32],
        receiver.verifying_key().to_bytes(),
        request,
        now,
        known,
    )
    .unwrap()
    .sign_with_key(&receiver)
    .unwrap();
    let verified = challenge
        .verify([4; 32], receiver.verifying_key().to_bytes(), request, now)
        .unwrap();
    let nonce = verified.solve(MAX_SOLVE_ATTEMPTS).unwrap();
    UnsignedRegistration::new(ad, verified, nonce)
        .unwrap()
        .sign_with_key(key)
        .unwrap()
}
fn first() -> Registration {
    static FIRST: OnceLock<Registration> = OnceLock::new();
    FIRST
        .get_or_init(|| {
            let key = SigningKey::from_bytes(&[3; 32]);
            registration(ad(&key, 1, 1000, 4600), &key, 1000, false)
        })
        .clone()
}
fn config(base: &Fixture, new: bool) -> DiscoveryConfig {
    DiscoveryConfig {
        directory: base.dir.join("discovery"),
        create_new: new,
    }
}
fn open(base: &Fixture, new: bool, clock: u64) -> Registry {
    Registry::start(
        config(base, new),
        [4; 32],
        SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes(),
        clock,
    )
    .unwrap()
}
fn list(generation: u64, after: [u8; 32], count: u8) -> DiscoveryRequest {
    DiscoveryRequest::new(
        [9; 32],
        DiscoveryKind::List {
            generation,
            after,
            count,
        },
    )
    .unwrap()
}

#[test]
fn discovery_publication_faults_reconcile_without_reusing_or_extending_admission() {
    let registration = first();
    let key = registration
        .advertisement()
        .unverified_claims()
        .application_key;
    for fault in [
        Fault::Write,
        Fault::FileSync,
        Fault::Rename,
        Fault::DirectorySync,
    ] {
        let base = Fixture::new();
        let mut registry = open(&base, true, 1000);
        assert!(registry
            .register(registration.clone(), Some(fault))
            .is_err());
        assert!(registry.poisoned);
        assert!(registry.page(list(0, [0; 32], 16)).is_err());
        assert!(registry.register(registration.clone(), None).is_err());
        drop(registry);
        let mut registry = open(&base, false, 1000);
        assert_eq!(registry.state.entries.len(), 1);
        let before = registry.state.entries[&key].clone();
        let receipt = registry.register(registration.clone(), None).unwrap();
        assert_eq!(receipt.sequence(), 1);
        assert_eq!(registry.state.entries[&key], before);
        assert_eq!(registry.state.generation, 2);
    }
}
#[test]
fn discovery_retains_cooling_floors_reclaims_after_exact_horizon_and_persists_cutoff() {
    let base = Fixture::new();
    let mut registry = open(&base, true, 1000);
    let receipt = registry.register(first(), None).unwrap();
    let key = receipt.publisher();
    let horizon = 1000 + MAX_CLOCK_SKEW_SECONDS + MAX_TTL_SECONDS;
    registry.advance(4600).unwrap();
    assert!(registry
        .page(list(0, [0; 32], 16))
        .unwrap()
        .advertisements()
        .is_empty());
    assert!(registry.state.entries.contains_key(&key));
    registry.advance(horizon - 1).unwrap();
    assert!(registry.state.entries.contains_key(&key));
    registry.advance(horizon).unwrap();
    assert!(registry.state.entries.is_empty());
    assert_eq!(registry.state.cutoff, 1300);
    drop(registry);
    assert!(Registry::start(
        config(&base, false),
        [4; 32],
        SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes(),
        horizon - 1
    )
    .is_err());
    let mut registry = open(&base, false, horizon);
    assert_eq!(registry.state.cutoff, 1300);
    assert!(registry.register(first(), None).is_err());
    let publisher = SigningKey::from_bytes(&[3; 32]);
    let fresh = registration(
        ad(&publisher, 2, horizon, horizon + 3600),
        &publisher,
        horizon,
        false,
    );
    assert_eq!(registry.register(fresh, None).unwrap().sequence(), 2);
}
#[test]
fn discovery_capacity_cursor_and_clock_changes_are_bounded() {
    let base = Fixture::new();
    let mut registry = open(&base, true, 1000);
    let mut next = registry.state.clone();
    next.bump().unwrap();
    for i in 0..MAX_DISCOVERY_PEERS {
        let mut seed = [0; 32];
        seed[..8].copy_from_slice(&(i as u64 + 1).to_be_bytes());
        let key = SigningKey::from_bytes(&seed);
        let ad = ad(&key, 1, 1300, 1300 + MAX_TTL_SECONDS);
        next.entries.insert(
            key.verifying_key().to_bytes(),
            Entry {
                accepted_at: 1000,
                generation: next.generation,
                advertisement: ad,
            },
        );
    }
    registry.persist(next, None).unwrap();
    assert_eq!(registry.state.entries.len(), MAX_DISCOVERY_PEERS);
    assert_eq!(
        registry.register(first(), None).unwrap_err(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let first = registry.page(list(0, [0; 32], 16)).unwrap();
    assert_eq!(first.advertisements().len(), 16);
    assert!(first.has_more());
    let second = registry
        .page(list(first.generation(), first.next_after(), 16))
        .unwrap();
    assert!(
        second.advertisements()[0]
            .unverified_claims()
            .application_key
            > first.next_after()
    );
    registry.advance(1001).unwrap();
    assert_eq!(
        registry.state.generation,
        first.generation(),
        "clock-only persistence does not break pagination"
    );
    registry.advance(1300 + MAX_TTL_SECONDS).unwrap();
    assert_eq!(
        registry
            .page(list(first.generation(), first.next_after(), 16))
            .unwrap_err(),
        StatusCode::CONFLICT
    );
    assert!(registry.state.entries.is_empty());
    assert_eq!(registry.state.cutoff, 1300);
}
#[test]
fn discovery_corrupt_snapshot_and_pending_floor_rollback_fail_closed() {
    let base = Fixture::new();
    let mut registry = open(&base, true, 1000);
    registry.register(first(), None).unwrap();
    registry
        .advance(1000 + MAX_CLOCK_SKEW_SECONDS + MAX_TTL_SECONDS)
        .unwrap();
    let mut pending = registry.state.clone();
    pending.generation += 1;
    pending.cutoff -= 1;
    let stable = fs::read(registry.path.join(SNAPSHOT)).unwrap();
    let mut f = custody::create_private_file(&registry.path.join(TEMP)).unwrap();
    f.write_all(&pending.encode()).unwrap();
    f.sync_all().unwrap();
    drop(f);
    drop(registry);
    assert!(Registry::start(
        config(&base, false),
        [4; 32],
        SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes(),
        90000
    )
    .is_err());
    assert_eq!(
        fs::read(base.dir.join("discovery/registry")).unwrap(),
        stable
    );
    assert!(base.dir.join("discovery/registry.tmp").exists());
    let base = Fixture::new();
    let registry = open(&base, true, 1000);
    let path = registry.path.join(SNAPSHOT);
    drop(registry);
    fs::write(&path, b"corrupt").unwrap();
    assert!(Registry::start(
        config(&base, false),
        [4; 32],
        SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes(),
        1000
    )
    .is_err());
    assert_eq!(fs::read(path).unwrap(), b"corrupt");
}
#[test]
fn discovery_rate_and_http_framing_fail_before_registration() {
    let mut rate = Rate::new();
    let at = Instant::now();
    let ip = "127.0.0.1".parse().unwrap();
    for _ in 0..IP_REQUESTS {
        assert!(rate.admit(ip, at));
    }
    assert!(!rate.admit(ip, at));
    assert!(rate.admit(ip, at + RATE_WINDOW));
    assert!(rate.ips.len() <= RATE_IPS);
    let fixture = Fixture::new();
    let peer = Peer::open(fixture.config.clone()).unwrap();
    let req = list(0, [0; 32], 16);
    let get = Request::builder()
        .uri(req.target())
        .header("host", "peer.vhalla.dev:443")
        .body(())
        .unwrap();
    assert!(peer.check_discovery_request(&get).is_ok());
    let bad = Request::builder()
        .uri(req.target())
        .header("host", "peer.vhalla.dev:443")
        .header("cookie", "secret=x")
        .body(())
        .unwrap();
    assert_eq!(
        peer.check_discovery_request(&bad).unwrap_err(),
        StatusCode::BAD_REQUEST
    );
    let post = DiscoveryRequest::new(
        [1; 32],
        DiscoveryKind::Register {
            registration: [2; 32],
        },
    )
    .unwrap();
    let bad = Request::builder()
        .method(Method::POST)
        .uri(post.target())
        .header("host", "peer.vhalla.dev:443")
        .header("content-type", "application/octet-stream")
        .header("content-length", MAX_REGISTRATION_BYTES + 1)
        .body(())
        .unwrap();
    assert_eq!(
        peer.check_discovery_request(&bad).unwrap_err(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
}
#[tokio::test]
async fn discovery_socket_listing_and_native_registration_are_peer_proved() {
    let fixture = Fixture::new();
    let peer = Arc::new(Peer::open(fixture.config.clone()).unwrap());
    peer.enable_discovery(config(&fixture, true)).unwrap();
    let publisher = SigningKey::from_bytes(&[3; 32]);
    let clock = now().unwrap();
    let advertisement = UnsignedAdvertisement::new(AdvertisementClaims {
        network: peer.network_id(),
        application_key: publisher.verifying_key().to_bytes(),
        sequence: 1,
        issued_at: clock,
        expires_at: clock + 3600,
        protocol: PROTOCOL_VERSION,
        capabilities: Capabilities::READ,
        endpoints: vec![Endpoint::parse("https://candidate.vhalla.dev:443/vhalla/v1").unwrap()],
    })
    .unwrap()
    .sign_with_key(&publisher)
    .unwrap();
    let challenge_req = DiscoveryRequest::new(
        [7; 32],
        DiscoveryKind::Challenge {
            publisher: publisher.verifying_key().to_bytes(),
            advertisement: Sha256::digest(advertisement.encode()).into(),
        },
    )
    .unwrap();
    let (raw, proof) = peer.discovery_exchange(challenge_req, &[]).unwrap();
    vhalla_public_protocol::discovery::proof_from_hex(&proof)
        .unwrap()
        .verify(
            peer.network_id(),
            peer.application_key(),
            challenge_req,
            &raw,
        )
        .unwrap();
    let challenge = RegistrationChallenge::decode(&raw)
        .unwrap()
        .verify(
            peer.network_id(),
            peer.application_key(),
            challenge_req,
            now().unwrap(),
        )
        .unwrap();
    let nonce = challenge.solve(MAX_SOLVE_ATTEMPTS).unwrap();
    let registration = UnsignedRegistration::new(advertisement, challenge, nonce)
        .unwrap()
        .sign_with_key(&publisher)
        .unwrap();
    let raw = registration.encode();
    let post = DiscoveryRequest::new(
        [8; 32],
        DiscoveryKind::Register {
            registration: Sha256::digest(&raw).into(),
        },
    )
    .unwrap();
    let (body, proof) = peer.discovery_exchange(post, &raw).unwrap();
    vhalla_public_protocol::discovery::proof_from_hex(&proof)
        .unwrap()
        .verify(peer.network_id(), peer.application_key(), post, &body)
        .unwrap();
    assert_eq!(RegistrationReceipt::decode(&body).unwrap().sequence(), 1);
    let bound = peer.clone().bind().await.unwrap();
    let address = bound.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(bound.run(async {
        let _ = rx.await;
    }));
    let req = list(0, [0; 32], 16);
    let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
    socket
        .write_all(
            format!(
                "GET {} HTTP/1.1\r\nHost: peer.vhalla.dev:443\r\nConnection: close\r\n\r\n",
                req.target()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut raw = Vec::new();
    socket.read_to_end(&mut raw).await.unwrap();
    let split = raw.windows(4).position(|v| v == b"\r\n\r\n").unwrap();
    let headers = std::str::from_utf8(&raw[..split]).unwrap();
    assert!(headers.starts_with("HTTP/1.1 200"));
    let header = headers
        .lines()
        .find_map(|l| l.strip_prefix("x-vhalla-proof: "))
        .unwrap();
    let body = &raw[split + 4..];
    let proof: DiscoveryResponseProof =
        vhalla_public_protocol::discovery::proof_from_hex(header).unwrap();
    proof
        .verify(peer.network_id(), peer.application_key(), req, body)
        .unwrap();
    let page = PeerPage::decode(body).unwrap();
    page.check_request(peer.network_id(), req).unwrap();
    assert_eq!(page.advertisements().len(), 1);
    assert_eq!(
        page.advertisements()[0].unverified_claims().application_key,
        publisher.verifying_key().to_bytes()
    );
    tx.send(()).unwrap();
    task.await.unwrap().unwrap();
}
