use super::*;
use crate::unix::tests::Fixture;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vhalla_public_protocol::response::{proof_from_hex, BundlePage, ReadKind, ReadRequest};

fn managed_fixture() -> (Fixture, PathBuf, Config) {
    let fixture = Fixture::new();
    let state = fixture.dir.join("peer-state");
    let mut config = fixture.config.clone();
    config.advertisement_file = state.join(ADVERTISEMENT);
    (fixture, state, config)
}
fn ad_request() -> ReadRequest {
    ReadRequest::new([7; 32], ReadKind::Advertisement).unwrap()
}
#[test]
fn create_restart_and_renew_preserve_monotone_scope_and_expiry() {
    let (_fixture, state, config) = managed_fixture();
    assert!(ManagedPeer::open(config.clone(), &state).is_err());
    let peer = ManagedPeer::create(config.clone(), &state).unwrap();
    assert_eq!(peer.advertisement_sequence().unwrap(), 1);
    assert!(ManagedPeer::create(config.clone(), &state).is_err());
    let raw = peer.peer.answer(ad_request()).unwrap().0;
    let ad = PeerAdvertisement::decode(&raw).unwrap();
    let issued = ad.unverified_claims().issued_at;
    assert_eq!(
        ad.unverified_claims().expires_at - issued,
        ADVERTISEMENT_LIFETIME_SECONDS
    );
    assert_eq!(
        peer.renew_at(issued + RENEW_MARGIN - 1, true, None)
            .unwrap(),
        1
    );
    assert_eq!(peer.renew_at(issued, false, None).unwrap(), 2);
    let key = peer.application_key();
    let network = peer.network_id();
    drop(peer);
    let reopened = ManagedPeer::open(config, &state).unwrap();
    assert_eq!(reopened.advertisement_sequence().unwrap(), 3);
    let raw = reopened.peer.answer(ad_request()).unwrap().0;
    let fresh = PeerAdvertisement::decode(&raw).unwrap();
    let verified = fresh
        .verify(
            &VerificationPolicy {
                network,
                now: now().unwrap(),
                max_clock_skew_seconds: 0,
                max_ttl_seconds: MAX_TTL_SECONDS,
            },
            Some(&ad.restore_sequence_anchor(network).unwrap()),
        )
        .unwrap();
    assert_eq!(verified.claims().application_key, key);
}
#[test]
fn every_uncertain_publication_boundary_recovers_by_skipping_reserved_sequence() {
    for fault in [
        Fault::ReserveFileSync,
        Fault::ReserveRename,
        Fault::ReserveDirSync,
        Fault::AdvertisementFileSync,
        Fault::AdvertisementRename,
        Fault::AdvertisementDirSync,
    ] {
        let (_fixture, state, config) = managed_fixture();
        let peer = ManagedPeer::create(config.clone(), &state).unwrap();
        let before = fs::read(state.join(ADVERTISEMENT)).unwrap();
        let issued = peer.publisher.lock().unwrap().reservation.issued;
        assert!(
            peer.renew_at(issued, false, Some(fault)).is_err(),
            "{fault:?}"
        );
        assert_eq!(
            peer.peer.answer(ad_request()),
            Err(StatusCode::SERVICE_UNAVAILABLE)
        );
        assert!(peer.renew().is_err());
        if matches!(
            fault,
            Fault::ReserveFileSync
                | Fault::ReserveRename
                | Fault::ReserveDirSync
                | Fault::AdvertisementFileSync
        ) {
            assert_eq!(fs::read(state.join(ADVERTISEMENT)).unwrap(), before);
        }
        drop(peer);
        let reopened = ManagedPeer::open(config, &state).unwrap();
        assert_eq!(reopened.advertisement_sequence().unwrap(), 3, "{fault:?}");
        let fresh =
            PeerAdvertisement::decode(&reopened.peer.answer(ad_request()).unwrap().0).unwrap();
        assert_eq!(fresh.unverified_claims().sequence, 3);
        assert!(!state.join("sequence.tmp").exists());
        assert!(!state.join("advertisement.tmp").exists());
    }
}
#[test]
fn interrupted_first_reservation_and_initial_advertisement_are_recoverable() {
    for fault in [
        Fault::ReserveFileSync,
        Fault::ReserveRename,
        Fault::AdvertisementFileSync,
        Fault::AdvertisementRename,
    ] {
        let (_fixture, state, config) = managed_fixture();
        let loaded = Peer::load(&config).unwrap();
        let identity = Identity::open(&config.identity_dir).unwrap();
        let scope = Scope {
            network: loaded.network,
            key: identity.public_key(),
            endpoint: config.public_endpoint.clone(),
        };
        let clock = now().unwrap();
        let mut publisher = Publisher::create(&state, scope, clock).unwrap();
        assert!(publisher.publish(&identity, clock, Some(fault)).is_err());
        drop(publisher);
        drop(identity);
        let reopened = ManagedPeer::open(config, &state).unwrap();
        assert_eq!(reopened.advertisement_sequence().unwrap(), 2);
    }
}
#[test]
fn missing_corrupt_foreign_and_truncated_state_never_resets_or_repairs() {
    for case in 0..5 {
        let (_fixture, state, mut config) = managed_fixture();
        let peer = ManagedPeer::create(config.clone(), &state).unwrap();
        drop(peer);
        let ad = fs::read(state.join(ADVERTISEMENT)).unwrap();
        match case {
            0 => fs::remove_file(state.join(SEQUENCE)).unwrap(),
            1 => fs::write(state.join(SEQUENCE), b"corrupt").unwrap(),
            2 => {
                let mut file = custody::create_private_file(&state.join("sequence.tmp")).unwrap();
                file.write_all(b"torn").unwrap();
                file.sync_all().unwrap();
            }
            3 => {
                config.public_endpoint =
                    Endpoint::parse("https://different.vhalla.dev:443/vhalla/v1").unwrap()
            }
            4 => {
                let mut file = custody::create_private_file(&state.join("unknown")).unwrap();
                file.write_all(b"preserve").unwrap();
            }
            _ => unreachable!(),
        }
        assert!(ManagedPeer::open(config, &state).is_err());
        assert_eq!(fs::read(state.join(ADVERTISEMENT)).unwrap(), ad);
        if case == 2 {
            assert_eq!(fs::read(state.join("sequence.tmp")).unwrap(), b"torn");
        }
    }
}
#[test]
fn future_signed_ad_and_clock_rollback_fail_closed_without_reset() {
    let (_fixture, state, config) = managed_fixture();
    let peer = ManagedPeer::create(config.clone(), &state).unwrap();
    let issued = peer.publisher.lock().unwrap().reservation.issued;
    assert!(matches!(
        peer.renew_at(issued - 1, false, None),
        Err(Error::ClockRollback)
    ));
    assert_eq!(
        peer.peer.answer(ad_request()),
        Err(StatusCode::SERVICE_UNAVAILABLE)
    );
    drop(peer);
    let peer = ManagedPeer::open(config.clone(), &state).unwrap();
    let reservation = peer.advertisement_sequence().unwrap();
    let signed = peer
        .peer
        .sign_advertisement(reservation + 1, issued, issued + 3600)
        .unwrap()
        .encode();
    fs::write(state.join(ADVERTISEMENT), &signed).unwrap();
    drop(peer);
    assert!(ManagedPeer::open(config, &state).is_err());
    assert_eq!(fs::read(state.join(ADVERTISEMENT)).unwrap(), signed);
}
#[test]
fn expired_advertisement_is_reopened_from_signed_evidence_and_renewed_fresh() {
    let (_fixture, state, config) = managed_fixture();
    let loaded = Peer::load(&config).unwrap();
    let identity = Identity::open(&config.identity_dir).unwrap();
    let scope = Scope {
        network: loaded.network,
        key: identity.public_key(),
        endpoint: config.public_endpoint.clone(),
    };
    let old_clock = now().unwrap() - ADVERTISEMENT_LIFETIME_SECONDS - 1;
    let mut publisher = Publisher::create(&state, scope, old_clock).unwrap();
    let old = publisher.publish(&identity, old_clock, None).unwrap();
    drop(publisher);
    drop(identity);
    let parsed = PeerAdvertisement::decode(&old).unwrap();
    assert!(parsed
        .verify(
            &VerificationPolicy {
                network: loaded.network,
                now: now().unwrap(),
                max_clock_skew_seconds: 0,
                max_ttl_seconds: MAX_TTL_SECONDS
            },
            None
        )
        .is_err());
    let managed = ManagedPeer::open(config, &state).unwrap();
    assert_eq!(managed.advertisement_sequence().unwrap(), 2);
    assert!(managed.peer.answer(ad_request()).is_ok());
}
#[tokio::test]
async fn managed_socket_discovery_bootstrap_and_empty_page_survive_restart() {
    let (fixture, state, config) = managed_fixture();
    let owner = Arc::new(ManagedPeer::create(config.clone(), &state).unwrap());
    let bound = owner.clone().bind().await.unwrap();
    let address = bound.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let running = tokio::spawn(bound.run(async {
        let _ = stopped.await;
    }));
    for (index, kind) in [
        ReadKind::Advertisement,
        ReadKind::Bootstrap,
        ReadKind::Bundles {
            after: 0,
            frontier: fixture.frontier,
            count: 32,
            bytes: 2 * 1024 * 1024,
        },
    ]
    .into_iter()
    .enumerate()
    {
        let request = ReadRequest::new([index as u8 + 1; 32], kind).unwrap();
        let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
        socket.write_all(format!("GET {} HTTP/1.1\r\nHost: peer.vhalla.dev\r\nOrigin: https://app.vhalla.dev\r\n\r\n", request.target()).as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        timeout(Duration::from_secs(3), socket.read_to_end(&mut raw))
            .await
            .unwrap()
            .unwrap();
        let split = raw.windows(4).position(|v| v == b"\r\n\r\n").unwrap();
        let headers = std::str::from_utf8(&raw[..split]).unwrap();
        let body = &raw[split + 4..];
        assert!(headers.starts_with("HTTP/1.1 200"));
        let proof = headers
            .lines()
            .find_map(|v| v.strip_prefix("x-vhalla-proof: "))
            .unwrap();
        proof_from_hex(proof)
            .unwrap()
            .verify(owner.network_id(), owner.application_key(), &request, body)
            .unwrap();
        match kind {
            ReadKind::Advertisement => {
                assert_eq!(
                    PeerAdvertisement::decode(body)
                        .unwrap()
                        .unverified_claims()
                        .sequence,
                    1
                );
            }
            ReadKind::Bootstrap => {
                Bootstrap::decode(body, config.bootstrap_pin).unwrap();
            }
            ReadKind::Bundles { .. } => {
                assert!(BundlePage::decode(body, &request)
                    .unwrap()
                    .bundles()
                    .is_empty());
            }
        }
    }
    stop.send(()).unwrap();
    running.await.unwrap().unwrap();
    drop(owner);
    let restarted = ManagedPeer::open(config, &state).unwrap();
    assert_eq!(restarted.advertisement_sequence().unwrap(), 2);
}
