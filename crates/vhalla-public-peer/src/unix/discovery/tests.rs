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
        Fault::Create,
        Fault::PartialWrite,
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
        if matches!(fault, Fault::Create | Fault::PartialWrite) {
            assert!(registry.state.entries.is_empty());
            assert_eq!(registry.state.generation, 1);
            assert!(!registry.path.join(TEMP).exists());
            registry.register(registration.clone(), None).unwrap();
        }
        assert_eq!(registry.state.entries.len(), 1);
        let before = registry.state.entries[&key].clone();
        let receipt = registry.register(registration.clone(), None).unwrap();
        assert_eq!(receipt.sequence(), 1);
        assert_eq!(registry.state.entries[&key], before);
        assert_eq!(registry.state.generation, 2);
    }
}

fn successor(old: &Snapshot) -> Snapshot {
    let mut next = old.clone();
    next.bump().unwrap();
    next.clock += 10;
    for seed in [3, 5] {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let sequence = if seed == 3 { 2 } else { 1 };
        next.entries.insert(
            key.verifying_key().to_bytes(),
            Entry {
                accepted_at: next.clock,
                generation: next.generation,
                advertisement: ad(&key, sequence, next.clock, next.clock + 3600),
            },
        );
    }
    next
}

#[test]
fn discovery_every_successor_truncation_checks_before_discarding_only_scratch() {
    let base = Fixture::new();
    let mut registry = open(&base, true, 1000);
    registry.register(first(), None).unwrap();
    let old = registry.state.clone();
    let next = successor(&old);
    next.succeeds(&old).unwrap();
    let raw = next.encode();
    for end in 0..raw.len() {
        old.check_incomplete(&raw[..end], next.clock)
            .unwrap_or_else(|e| panic!("prefix {end}: {e:?}"));
    }
    assert!(old.check_incomplete(&raw, next.clock).is_err());
    assert!(old.check_incomplete(&[], old.clock - 1).is_err());
    // Reopen at the same clock discards a valid incomplete preparation while
    // retaining exact stable bytes and every previously admitted sequence floor.
    let mut next = old.clone();
    next.bump().unwrap();
    let raw = next.encode();
    let stable = fs::read(registry.path.join(SNAPSHOT)).unwrap();
    let mut f = custody::create_private_file(&registry.path.join(TEMP)).unwrap();
    f.write_all(&raw[..raw.len() - 1]).unwrap();
    f.sync_all().unwrap();
    drop(f);
    drop(registry);
    let reopened = open(&base, false, old.clock);
    assert_eq!(reopened.state, old);
    assert_eq!(fs::read(reopened.path.join(SNAPSHOT)).unwrap(), stable);
    assert!(!reopened.path.join(TEMP).exists());
}

#[test]
fn discovery_malformed_prefixes_completed_entries_and_clock_rollback_are_preserved() {
    for mutation in 0..15 {
        let base = Fixture::new();
        let mut registry = open(&base, true, 1000);
        registry.register(first(), None).unwrap();
        let old = registry.state.clone();
        let mut next = successor(&old);
        let mut raw = next.encode();
        let mut clock = next.clock;
        match mutation {
            0 => {
                raw[5] ^= 1;
                raw.truncate(20);
            }
            1 => {
                raw[37] ^= 1;
                raw.truncate(50);
            }
            2 => {
                raw[69..77].copy_from_slice(&(old.generation - 1).to_be_bytes());
                raw.truncate(77);
            }
            3 => {
                raw[77..85].copy_from_slice(&(old.clock - 1).to_be_bytes());
                raw.truncate(85);
            }
            4 => {
                clock = next.clock - 1;
                raw.truncate(85);
            }
            5 => {
                raw[93..95].copy_from_slice(&513u16.to_be_bytes());
                raw.truncate(95);
            }
            6 => {
                *raw.last_mut().unwrap() ^= 1;
            }
            7 => {
                raw.push(0);
            }
            8 => {
                raw.clear();
                clock = old.clock - 1;
            }
            9 => {
                next.entries.clear();
                raw = next.encode();
                raw.truncate(raw.len() - 1);
            }
            10 => {
                let e = next.entries.values_mut().next().unwrap();
                let mut ad = e.advertisement.encode();
                *ad.last_mut().unwrap() ^= 1;
                e.advertisement = PeerAdvertisement::decode(&ad).unwrap();
                raw = next.encode();
                raw.truncate(raw.len() - 1);
            }
            11 => {
                // Completed first advertisement is malformed even though a
                // later entry/checksum is still incomplete.
                raw[145] ^= 1;
                raw.truncate(raw.len() - 33);
            }
            12 => {
                raw[150] ^= 1;
                raw.truncate(165);
            }
            13 => {
                assert!(old.entries.keys().next().unwrap()[0] < 255);
                raw.truncate(95);
                raw[93..95].copy_from_slice(&1u16.to_be_bytes());
                // Even this one available key byte proves the old live key
                // was skipped in the canonical increasing entry order.
                raw.push(255);
            }
            14 => {
                next.entries = old.entries.clone();
                let entry = next.entries.values_mut().next().unwrap();
                entry.accepted_at = next.clock;
                entry.generation = next.generation;
                raw = next.encode();
                // Same advertisement sequence cannot change either already
                // complete metadata field, even before its signature arrives.
                raw.truncate(95 + 50 + 77);
            }
            _ => unreachable!(),
        }
        let stable = fs::read(registry.path.join(SNAPSHOT)).unwrap();
        let mut f = custody::create_private_file(&registry.path.join(TEMP)).unwrap();
        f.write_all(&raw).unwrap();
        f.sync_all().unwrap();
        drop(f);
        drop(registry);
        assert!(
            Registry::start(config(&base, false), old.network, old.receiver, clock).is_err(),
            "mutation {mutation}"
        );
        assert_eq!(
            fs::read(base.dir.join("discovery/registry")).unwrap(),
            stable
        );
        assert_eq!(
            fs::read(base.dir.join("discovery/registry.tmp")).unwrap(),
            raw
        );
    }
}

#[test]
fn discovery_reopen_resyncs_stable_before_same_clock_retry_or_scratch_cleanup() {
    for partial in [false, true] {
        for fault in [Fault::StableFileSync, Fault::StableDirectorySync] {
            let base = Fixture::new();
            let mut registry = open(&base, true, 1000);
            assert!(registry.register(first(), Some(Fault::Rename)).is_err());
            let stable = fs::read(registry.path.join(SNAPSHOT)).unwrap();
            let state =
                Snapshot::decode(&stable, registry.state.network, registry.state.receiver).unwrap();
            if partial {
                drop(custody::create_private_file(&registry.path.join(TEMP)).unwrap());
            }
            drop(registry);
            assert!(Registry::start_with_fault(
                config(&base, false),
                state.network,
                state.receiver,
                1000,
                Some(fault)
            )
            .is_err());
            assert_eq!(
                fs::read(base.dir.join("discovery/registry")).unwrap(),
                stable
            );
            assert_eq!(base.dir.join("discovery/registry.tmp").exists(), partial);
            let mut registry = open(&base, false, 1000);
            let receipt = registry.register(first(), None).unwrap();
            assert_eq!(receipt.sequence(), 1);
            assert_eq!(registry.state, state);
            assert!(!registry.path.join(TEMP).exists());
        }
    }
}

#[test]
fn discovery_incomplete_initial_creation_or_corrupt_stable_is_not_reset() {
    for corrupt_stable in [false, true] {
        let base = Fixture::new();
        let registry = open(&base, true, 1000);
        let path = registry.path.clone();
        let network = registry.state.network;
        let receiver = registry.state.receiver;
        drop(custody::create_private_file(&path.join(TEMP)).unwrap());
        drop(registry);
        if corrupt_stable {
            fs::write(path.join(SNAPSHOT), b"corrupt").unwrap();
        } else {
            fs::remove_file(path.join(SNAPSHOT)).unwrap();
        }
        assert!(Registry::start(config(&base, false), network, receiver, 1000).is_err());
        assert_eq!(fs::read(path.join(TEMP)).unwrap(), b"");
        if corrupt_stable {
            assert_eq!(fs::read(path.join(SNAPSHOT)).unwrap(), b"corrupt");
        } else {
            assert!(!path.join(SNAPSHOT).exists());
        }
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
