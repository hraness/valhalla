use super::*;
use crate::unix::tests::Fixture;
use ed25519_dalek::{Signer, SigningKey};
use std::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vhalla_journal::{Bundle, BundleParts};
use vhalla_public_client::{Validator, ValidatorActivation};
use vhalla_public_protocol::activity::proof_from_hex;
use vhalla_room_activity::{Content, EventClaims, EventId, Text, UnsignedEvent};
use vhalla_rooms::{RoomRecordId, RoomUpdate, Slug, UpdateAction};
use vhalla_rooms_consensus::fixture;

struct ActivityFixture {
    base: Fixture,
    scenario: fixture::Scenario,
    validators: Vec<SigningKey>,
    room: RoomGenesisId,
    policy: RoomRecordId,
    network: [u8; 32],
    genesis: [u8; 32],
    config: ActivityConfig,
}
impl ActivityFixture {
    fn new() -> Self {
        let mut base = Fixture::new();
        let scenario = fixture::scenario(1, 1);
        let validators = (101..=104)
            .map(|seed| SigningKey::from_bytes(&[seed; 32]))
            .collect::<Vec<_>>();
        let bootstrap = Bootstrap::from_genesis(
            scenario.genesis.clone(),
            vec![ValidatorActivation {
                from: 1,
                validators: validators
                    .iter()
                    .map(|key| Validator {
                        public_key: key.verifying_key().to_bytes(),
                        power: 1,
                    })
                    .collect(),
            }],
        )
        .unwrap();
        let network = bootstrap.network_id();
        base.config.bootstrap_pin = bootstrap.pin();
        let raw = bootstrap.encode();
        let genesis = CertifiedClient::new(bootstrap, base.config.bootstrap_pin)
            .unwrap()
            .frontier()
            .commitment();
        fs::write(&base.config.bootstrap_file, raw).unwrap();
        let identity = Identity::open(&base.config.identity_dir).unwrap();
        let unsigned = vhalla_public_protocol::UnsignedAdvertisement::new(
            vhalla_public_protocol::AdvertisementClaims {
                network,
                application_key: identity.public_key(),
                sequence: 1,
                issued_at: now().unwrap(),
                expires_at: now().unwrap() + 3600,
                protocol: 1,
                capabilities: Capabilities::READ,
                endpoints: vec![base.config.public_endpoint.clone()],
            },
        )
        .unwrap();
        fs::write(
            &base.config.advertisement_file,
            identity
                .sign_public_advertisement(unsigned)
                .unwrap()
                .encode(),
        )
        .unwrap();
        drop(identity);
        let mut out = Self {
            base,
            scenario,
            validators,
            room: RoomGenesisId::from_bytes([0; 32]),
            policy: RoomRecordId::from_bytes([0; 32]),
            network,
            genesis,
            config: ActivityConfig { rooms: vec![] },
        };
        let mut cursor = 0;
        let (evidence, records, _) = fixture::first_create(
            &out.scenario.app,
            &out.scenario.owners[0],
            &mut out.scenario.sources,
            &mut cursor,
            "public-lobby",
            1,
        );
        out.commit(100, evidence, records);
        out.room = out
            .scenario
            .app
            .registry()
            .room(&Slug::new("public-lobby").unwrap())
            .unwrap()
            .genesis();
        out.set_policy(true);
        let limits = Limits {
            max_events: 100,
            max_history_bytes: 1_000_000,
        };
        let directory = out.base.dir.join("activity");
        drop(Store::create(&directory, out.scope(), limits).unwrap());
        out.config.rooms.push(ActivityRoomConfig {
            room: out.room,
            directory,
            limits,
        });
        out
    }
    fn scope(&self) -> RoomScope {
        RoomScope {
            network: self.network,
            realm: self.scenario.genesis.realm,
            directory: self.scenario.genesis.directory,
            room: self.room,
        }
    }
    fn commit(&mut self, at: u64, evidence: Vec<Vec<u8>>, records: Vec<Vec<u8>>) {
        let checked = self
            .scenario
            .app
            .prepare(at, evidence, records, None)
            .unwrap();
        let next = checked.next();
        let batch = checked.batch();
        let value = batch.value_id();
        let mut certificate = b"VC2".to_vec();
        certificate.extend_from_slice(&next.height.to_be_bytes());
        certificate.extend_from_slice(&0u32.to_be_bytes());
        certificate.extend_from_slice(&value);
        certificate.extend_from_slice(&3u16.to_be_bytes());
        for key in &self.validators[..3] {
            let public =
                vhalla_rooms_node::PublicKey::from_bytes(key.verifying_key().to_bytes()).unwrap();
            let address = vhalla_rooms_node::Address::from_public_key(&public).into_inner();
            let mut vote = b"RV1".to_vec();
            vote.push(1);
            vote.extend_from_slice(&next.height.to_be_bytes());
            vote.extend_from_slice(&0u32.to_be_bytes());
            vote.push(1);
            vote.extend_from_slice(&value);
            vote.extend_from_slice(&address);
            certificate.extend_from_slice(&address);
            certificate.extend_from_slice(&key.sign(&vote).to_bytes());
        }
        let bundle = Bundle::new(BundleParts {
            certificate,
            predecessor: batch.parent.commitment(),
            next: next.commitment(),
            batch: batch.encode(),
            value: value.to_vec(),
            configuration: self.scenario.genesis.policy.id().as_bytes().to_vec(),
            control_record: next.control.to_vec(),
            debit_marker: next.value.to_vec(),
            height: next.height,
        })
        .unwrap();
        Journal::with_genesis(&self.base.config.journal_dir, FsStore, self.genesis)
            .commit(&bundle)
            .unwrap();
        self.scenario.app.apply_locally(checked);
    }
    fn set_policy(&mut self, enabled: bool) {
        let room = self
            .scenario
            .app
            .registry()
            .room_by_genesis(self.room)
            .unwrap();
        let owner = &self.scenario.owners[0];
        let height = self.scenario.app.frontier().height + 1;
        let update = RoomUpdate {
            directory: self.scenario.genesis.directory,
            realm: self.scenario.genesis.realm,
            genesis: self.room,
            previous: room.head(),
            owner: owner.id,
            social_control: owner.head,
            controller_key: owner.key.verifying_key().to_bytes(),
            expires_at: 1_000_000,
            nonce: [height as u8; 32],
            action: UpdateAction::SetPublicActivityPolicy {
                network: self.network,
                enabled,
            },
        }
        .sign_with_key(&owner.key)
        .unwrap();
        self.policy = update.id();
        self.commit(height * 100, vec![], vec![update.encode()]);
    }
    fn peer(&self) -> Arc<Peer> {
        let peer = Peer::open(self.base.config.clone()).unwrap();
        // Direct test-only initialization: production READ startup never activates
        // activity until the separately reviewed opt-in publisher API is wired.
        let service = ActivityService::open(
            &peer.bootstrap,
            peer.config.bootstrap_pin,
            self.config.clone(),
        )
        .unwrap();
        *peer.activity.lock().unwrap() = Some(service);
        Arc::new(peer)
    }
    fn event(&self, sequence: u64, previous: EventId, text: &str) -> Vec<u8> {
        let key = SigningKey::from_bytes(&[49; 32]);
        UnsignedEvent::new(EventClaims {
            scope: self.scope(),
            policy: self.policy,
            author: key.verifying_key().to_bytes(),
            sequence,
            previous,
            created_at: 123,
            content: Content::Text(Text::new(text).unwrap()),
        })
        .unwrap()
        .sign_with_key(&key)
        .unwrap()
        .encode()
    }
}
fn post(peer: &Peer, raw: &[u8], room: RoomGenesisId) -> Result<LocalReceipt, StatusCode> {
    let request = ActivityRequest::post([7; 32], *room.as_bytes(), raw).unwrap();
    let (body, proof) = peer.activity_answer(request, raw, "127.0.0.1".parse().unwrap())?;
    proof_from_hex(&proof)
        .unwrap()
        .verify(peer.network, peer.application_key(), &request, &body)
        .unwrap();
    Ok(LocalReceipt::decode(&body).unwrap())
}

#[test]
fn activity_post_retry_restart_page_and_revocation_keep_original_admission() {
    let mut fixture = ActivityFixture::new();
    let peer = fixture.peer();
    let raw = fixture.event(1, EventId::ZERO, "hello");
    let stored = post(&peer, &raw, fixture.room).unwrap();
    assert_eq!(stored.local_cursor(), 1);
    assert_eq!(stored.observed_height(), 2);
    assert!(!stored.reconciled());
    let duplicate = post(&peer, &raw, fixture.room).unwrap();
    assert!(duplicate.reconciled());
    assert_eq!(duplicate.event_id(), stored.event_id());
    fixture.set_policy(false);
    let next = fixture.event(2, stored.event_id(), "closed");
    assert_eq!(post(&peer, &next, fixture.room), Err(StatusCode::FORBIDDEN));
    drop(peer);
    let peer = fixture.peer();
    let duplicate = post(&peer, &raw, fixture.room).unwrap();
    assert!(duplicate.reconciled());
    assert_eq!(duplicate.observed_height(), 3);
    assert_eq!(duplicate.registry_digest(), stored.registry_digest());
    let request = ActivityRequest::page([8; 32], *fixture.room.as_bytes(), 0, 32).unwrap();
    let (body, proof) = peer
        .activity_answer(request, &[], "127.0.0.1".parse().unwrap())
        .unwrap();
    proof_from_hex(&proof)
        .unwrap()
        .verify(fixture.network, peer.application_key(), &request, &body)
        .unwrap();
    let page = ActivityPage::decode(&body, &request).unwrap();
    assert_eq!(page.local_tip(), 1);
    assert_eq!(page.entries()[0].event().encode(), raw);
}

#[test]
fn activity_forks_gaps_bad_signatures_and_current_policy_change_do_not_append() {
    let mut fixture = ActivityFixture::new();
    let peer = fixture.peer();
    let raw = fixture.event(1, EventId::ZERO, "first");
    let receipt = post(&peer, &raw, fixture.room).unwrap();
    assert_eq!(
        post(
            &peer,
            &fixture.event(1, EventId::ZERO, "fork"),
            fixture.room
        ),
        Err(StatusCode::CONFLICT)
    );
    assert_eq!(
        post(
            &peer,
            &fixture.event(3, receipt.event_id(), "gap"),
            fixture.room
        ),
        Err(StatusCode::CONFLICT)
    );
    let mut corrupt = fixture.event(2, receipt.event_id(), "second");
    *corrupt.last_mut().unwrap() ^= 1;
    assert_eq!(
        post(&peer, &corrupt, fixture.room),
        Err(StatusCode::BAD_REQUEST)
    );
    let pending = fixture.event(2, receipt.event_id(), "pending before revoke");
    fixture.set_policy(false);
    assert_eq!(
        post(&peer, &pending, fixture.room),
        Err(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        peer.activity.lock().unwrap().as_ref().unwrap().stores[fixture.room.as_bytes()]
            .pin()
            .count(),
        1
    );
}

#[test]
fn activity_advancing_journal_after_replay_refuses_stale_admission() {
    let fixture = ActivityFixture::new();
    let peer = fixture.peer();
    let room = fixture.room;
    let raw = fixture.event(1, EventId::ZERO, "raced policy");
    let fixture = Arc::new(Mutex::new(fixture));
    let writer = fixture.clone();
    peer.activity
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .after_refresh = Some(Box::new(move || writer.lock().unwrap().set_policy(false)));
    assert_eq!(
        post(&peer, &raw, room),
        Err(StatusCode::SERVICE_UNAVAILABLE)
    );
    assert_eq!(
        peer.activity.lock().unwrap().as_ref().unwrap().stores[room.as_bytes()]
            .pin()
            .count(),
        0
    );
}

#[test]
fn activity_certified_catchup_is_bounded_and_resumes_without_stale_admission() {
    let mut fixture = ActivityFixture::new();
    for _ in 0..33 {
        fixture.set_policy(true);
    }
    let peer = fixture.peer();
    let raw = fixture.event(1, EventId::ZERO, "after bounded catchup");
    assert_eq!(
        post(&peer, &raw, fixture.room),
        Err(StatusCode::SERVICE_UNAVAILABLE)
    );
    {
        let guard = peer.activity.lock().unwrap();
        let service = guard.as_ref().unwrap();
        assert_eq!(
            service.client.frontier().height,
            ACTIVITY_REPLAY_BUDGET as u64
        );
        assert_eq!(service.stores[fixture.room.as_bytes()].pin().count(), 0);
    }
    let receipt = post(&peer, &raw, fixture.room).unwrap();
    assert_eq!(receipt.observed_height(), 35);
    assert_eq!(receipt.local_cursor(), 1);
}

#[test]
fn activity_concurrent_identical_requests_publish_once_and_reconcile() {
    let fixture = ActivityFixture::new();
    let peer = fixture.peer();
    let raw = fixture.event(1, EventId::ZERO, "once");
    let barrier = Arc::new(std::sync::Barrier::new(3));
    std::thread::scope(|scope| {
        let mut workers = Vec::new();
        for _ in 0..2 {
            let peer = peer.clone();
            let raw = &raw;
            let barrier = barrier.clone();
            let room = fixture.room;
            workers.push(scope.spawn(move || {
                barrier.wait();
                post(&peer, raw, room)
            }));
        }
        barrier.wait();
        let mut success = 0;
        for worker in workers {
            match worker.join().unwrap() {
                Ok(receipt) => {
                    success += 1;
                    assert_eq!(receipt.local_cursor(), 1);
                }
                Err(status) => assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE),
            }
        }
        assert!(success >= 1);
    });
    assert!(post(&peer, &raw, fixture.room).unwrap().reconciled());
    assert_eq!(
        peer.activity.lock().unwrap().as_ref().unwrap().stores[fixture.room.as_bytes()]
            .pin()
            .count(),
        1
    );
}

#[test]
fn activity_request_framing_cors_and_per_ip_limits_are_bounded() {
    let fixture = ActivityFixture::new();
    let peer = fixture.peer();
    let raw = fixture.event(1, EventId::ZERO, "bounds");
    let request = ActivityRequest::post([1; 32], *fixture.room.as_bytes(), &raw).unwrap();
    let http = || {
        Request::builder()
            .method(Method::POST)
            .uri(request.target())
            .header("host", "peer.vhalla.dev")
            .header("origin", "https://app.vhalla.dev")
            .header("content-type", "application/octet-stream")
            .header("content-length", raw.len())
            .body(())
            .unwrap()
    };
    assert!(peer.check_activity_request(&http()).is_ok());
    for (name, value) in [
        ("content-length", "4393"),
        ("content-length", "01"),
        ("transfer-encoding", "chunked"),
        ("content-encoding", "gzip"),
        ("origin", "https://evil.example"),
        ("cookie", "secret=x"),
    ] {
        let mut req = http();
        req.headers_mut().insert(name, value.parse().unwrap());
        assert!(peer.check_activity_request(&req).is_err(), "{name}");
    }
    let mut rate = PostRate::new();
    let at = Instant::now();
    let ip = "127.0.0.1".parse().unwrap();
    for _ in 0..IP_POSTS {
        assert!(rate.admit(ip, at));
    }
    assert!(!rate.admit(ip, at));
    assert!(rate.admit("127.0.0.2".parse().unwrap(), at));
    assert!(rate.admit(ip, at + RATE_WINDOW));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn activity_http_chunked_size_and_slow_body_have_deadlines() {
    let fixture = ActivityFixture::new();
    let peer = fixture.peer();
    let request = ActivityRequest::post([1; 32], *fixture.room.as_bytes(), b"x").unwrap();
    let peer_key = peer.application_key();
    let bound = peer.bind().await.unwrap();
    let address = bound.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(bound.run(async {
        let _ = stopped.await;
    }));
    let raw = fixture.event(1, EventId::ZERO, "over real HTTP");
    let valid = ActivityRequest::post([9; 32], *fixture.room.as_bytes(), &raw).unwrap();
    let mut wire = format!("POST {} HTTP/1.1\r\nHost: peer.vhalla.dev\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n", valid.target(), raw.len()).into_bytes();
    wire.extend_from_slice(&raw);
    let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
    socket.write_all(&wire).await.unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(10), socket.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    let headers = std::str::from_utf8(&response[..split]).unwrap();
    let proof = headers
        .lines()
        .find_map(|line| line.strip_prefix("x-vhalla-proof: "))
        .unwrap()
        .trim();
    let body = &response[split + 4..];
    proof_from_hex(proof)
        .unwrap()
        .verify(fixture.network, peer_key, &valid, body)
        .unwrap();
    assert_eq!(LocalReceipt::decode(body).unwrap().local_cursor(), 1);

    let prefix = format!("POST {} HTTP/1.1\r\nHost: peer.vhalla.dev\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n", request.target());
    let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
    socket
        .write_all(
            format!(
                "{prefix}{:x}\r\n{}\r\n0\r\n\r\n",
                MAX_EVENT_BYTES + 1,
                "x".repeat(MAX_EVENT_BYTES + 1)
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(10), socket.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 413"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
    socket.write_all(prefix.as_bytes()).await.unwrap();
    let start = Instant::now();
    let mut response = Vec::new();
    timeout(Duration::from_secs(9), socket.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 408"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    assert!(start.elapsed() < Duration::from_secs(9));
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}
