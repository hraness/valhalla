use super::*;
use ed25519_dalek::SigningKey;
use std::{collections::BTreeSet, path::PathBuf, sync::atomic::AtomicU64};
use vhalla_browser_storage::{
    history::{HistoryFrontier, HistoryHead},
    native::Limits,
    outbox::{AuthorHead, ReservedDraft},
};
use vhalla_public_protocol::{
    activity::{ActivityEntry, ActivityKind, LocalReceipt, UnsignedActivityResponse},
    response::UnsignedResponse,
    AdvertisementClaims, UnsignedAdvertisement, PROTOCOL_VERSION,
};
use vhalla_room_activity::{EventId, SignedEvent, UnsignedEvent, VerifiedEvent};

static SERIAL: AtomicU64 = AtomicU64::new(0);
struct Home(PathBuf);
impl Home {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "vhalla-native-controller-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn peer(&self) -> PathBuf {
        self.0.join("peer")
    }
    fn outbox(&self) -> PathBuf {
        self.0.join("outbox")
    }
    fn session(&self) -> NativePeerSession {
        NativePeerSession::create_new(
            self.peer(),
            history().scope(),
            peer_key().verifying_key().to_bytes(),
            route(),
            &advertisement(1, 1000, 1100, 3, false),
            1000,
        )
        .unwrap()
    }
    fn reopen(&self) -> NativePeerSession {
        NativePeerSession::open(
            self.peer(),
            history().scope(),
            peer_key().verifying_key().to_bytes(),
            &route(),
        )
        .unwrap()
    }
    fn create_outbox(&self, count: usize) -> NativeOutbox {
        let first = event(1, EventId::ZERO);
        let mut store = NativeOutbox::create_new(
            self.outbox(),
            AuthorHead::fresh_scope_authorized(AuthorScope::new(
                first.claims().scope,
                first.claims().author,
            )),
            history(),
            Limits::default(),
        )
        .unwrap();
        for _ in 0..count {
            let head = store.head().unwrap();
            let e = event(head.sequence() + 1, head.event_id());
            let draft = ReservedDraft::new(
                head,
                history(),
                UnsignedEvent::new(e.claims().clone()).unwrap(),
            )
            .unwrap();
            store.reserve(&draft).unwrap();
            store.finalize(&draft, &e).unwrap();
        }
        store
    }
    fn reopen_outbox(&self) -> NativeOutbox {
        let first = event(1, EventId::ZERO);
        NativeOutbox::open(
            self.outbox(),
            AuthorScope::new(first.claims().scope, first.claims().author),
            history().scope(),
        )
        .unwrap()
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn peer_key() -> SigningKey {
    SigningKey::from_bytes(&[55; 32])
}
fn route() -> Endpoint {
    Endpoint::parse("https://selected.vhalla.dev:443/vhalla/v1").unwrap()
}
fn history() -> HistoryHead {
    HistoryHead::new(
        HistoryScope::new([7; 32], [10; 32]),
        HistoryFrontier {
            height: 1,
            value: [1; 32],
            registry: [2; 32],
            social: [3; 32],
            control: [4; 32],
            time: 1,
        },
        [5; 32],
    )
    .unwrap()
}
fn advertisement(seq: u64, issued: u64, expires: u64, caps: u32, changed_route: bool) -> Vec<u8> {
    UnsignedAdvertisement::new(AdvertisementClaims {
        network: [7; 32],
        application_key: peer_key().verifying_key().to_bytes(),
        sequence: seq,
        issued_at: issued,
        expires_at: expires,
        protocol: PROTOCOL_VERSION,
        capabilities: Capabilities::from_bits(caps).unwrap(),
        endpoints: vec![if changed_route {
            Endpoint::parse("https://changed.vhalla.dev:443/vhalla/v1").unwrap()
        } else {
            route()
        }],
    })
    .unwrap()
    .sign_with_key(&peer_key())
    .unwrap()
    .encode()
}
fn event(sequence: u64, previous: EventId) -> VerifiedEvent {
    let key = SigningKey::from_bytes(&[3; 32]);
    let mut raw = b"VHRA\x01".to_vec();
    raw.extend([7; 32]);
    raw.extend(77u128.to_be_bytes());
    raw.extend([5; 32]);
    raw.extend([8; 32]);
    raw.extend([9; 32]);
    raw.extend(key.verifying_key().to_bytes());
    raw.extend(sequence.to_be_bytes());
    raw.extend(previous.as_bytes());
    raw.extend(1000u64.to_be_bytes());
    raw.push(0);
    raw.extend(7u16.to_be_bytes());
    raw.extend(b"fixture");
    UnsignedEvent::decode(&raw)
        .unwrap()
        .sign_with_key(&key)
        .unwrap()
        .verify()
        .unwrap()
}
#[derive(Clone, Copy, Default)]
enum Fault {
    #[default]
    None,
    Network,
    Peer,
    Nonce,
    Body,
}
struct Synthetic {
    advertisement: Vec<u8>,
    ad_fault: Fault,
    activity_fault: Fault,
    sent: Vec<Vec<u8>>,
    nonces: BTreeSet<[u8; 32]>,
    refreshes: usize,
    reads: usize,
    fail_after: Option<usize>,
    cancel_on_reply: bool,
    obstruct_intent: Option<PathBuf>,
    page_events: Vec<VerifiedEvent>,
}
impl Synthetic {
    fn new() -> Self {
        Self {
            advertisement: advertisement(2, 1000, 2000, 3, false),
            ad_fault: Fault::None,
            activity_fault: Fault::None,
            sent: vec![],
            nonces: BTreeSet::new(),
            refreshes: 0,
            reads: 0,
            fail_after: None,
            cancel_on_reply: false,
            obstruct_intent: None,
            page_events: vec![event(1, EventId::ZERO)],
        }
    }
    fn key(&self, fault: Fault) -> SigningKey {
        if matches!(fault, Fault::Peer) {
            SigningKey::from_bytes(&[56; 32])
        } else {
            peer_key()
        }
    }
    fn network(&self, fault: Fault) -> [u8; 32] {
        if matches!(fault, Fault::Network) {
            [6; 32]
        } else {
            [7; 32]
        }
    }
}
impl Transport for Synthetic {
    fn advertisement(
        &mut self,
        selected: &Endpoint,
        request: &ReadRequest,
        cancel: &AtomicBool,
    ) -> Result<(Vec<u8>, String), String> {
        cancelled(cancel)?;
        assert_eq!(selected, &route());
        self.refreshes += 1;
        assert!(self.nonces.insert(request.nonce()));
        let key = self.key(self.ad_fault);
        let bound = if matches!(self.ad_fault, Fault::Nonce) {
            ReadRequest::new([93; 32], ReadKind::Advertisement).unwrap()
        } else {
            *request
        };
        let proof = UnsignedResponse::new(
            self.network(self.ad_fault),
            key.verifying_key().to_bytes(),
            bound,
            &self.advertisement,
        )
        .unwrap()
        .sign_with_key(&key)
        .unwrap();
        let mut raw = self.advertisement.clone();
        if matches!(self.ad_fault, Fault::Body) {
            *raw.last_mut().unwrap() ^= 1;
        }
        Ok((raw, response::hex(&proof.encode())))
    }
    fn activity(
        &mut self,
        selected: &Endpoint,
        request: &ActivityRequest,
        body: Option<&[u8]>,
        cancel: &AtomicBool,
    ) -> Result<(Vec<u8>, String), String> {
        cancelled(cancel)?;
        assert_eq!(selected, &route());
        assert!(self.nonces.insert(request.nonce()));
        if self
            .fail_after
            .is_some_and(|limit| self.sent.len() >= limit)
        {
            return Err("synthetic response loss".into());
        }
        let mut raw = match request.kind() {
            ActivityKind::Post { .. } => {
                let bytes = body.unwrap();
                request.check_body(bytes).unwrap();
                let event = SignedEvent::decode(bytes).unwrap().verify().unwrap();
                let duplicate = self.sent.iter().any(|old| old == bytes);
                self.sent.push(bytes.to_vec());
                LocalReceipt::new(
                    &event,
                    100 + event.claims().sequence,
                    [9; 32],
                    5,
                    [6; 32],
                    duplicate,
                )
                .unwrap()
                .encode()
            }
            ActivityKind::Page { after, .. } => {
                assert!(body.is_none());
                self.reads += 1;
                ActivityPage::new(
                    request,
                    after + self.page_events.len() as u64,
                    5,
                    [6; 32],
                    self.page_events
                        .iter()
                        .enumerate()
                        .map(|(i, event)| {
                            ActivityEntry::new(after + i as u64 + 1, [9; 32], event.clone())
                                .unwrap()
                        })
                        .collect(),
                )
                .unwrap()
                .encode()
            }
        };
        let key = self.key(self.activity_fault);
        let bound = if matches!(self.activity_fault, Fault::Nonce) {
            match request.kind() {
                ActivityKind::Post { .. } => {
                    ActivityRequest::post([93; 32], request.room(), body.unwrap()).unwrap()
                }
                ActivityKind::Page { after, count } => {
                    ActivityRequest::page([93; 32], request.room(), after, count).unwrap()
                }
            }
        } else {
            *request
        };
        let proof = UnsignedActivityResponse::new(
            self.network(self.activity_fault),
            key.verifying_key().to_bytes(),
            bound,
            &raw,
        )
        .unwrap()
        .sign_with_key(&key)
        .unwrap();
        if matches!(self.activity_fault, Fault::Body) {
            *raw.last_mut().unwrap() ^= 1;
        }
        if let Some(path) = self.obstruct_intent.take() {
            fs::write(path, b"").unwrap();
        }
        if self.cancel_on_reply {
            cancel.store(true, Ordering::Relaxed);
        }
        Ok((raw, response::hex(&proof.encode())))
    }
}
fn quiet() -> AtomicBool {
    AtomicBool::new(false)
}

#[test]
fn native_controller_send_is_three_exact_retained_events_and_restarts_from_receipts() {
    let home = Home::new();
    let mut session = home.session();
    let mut store = home.create_outbox(5);
    let mut transport = Synthetic::new();
    let room = event(1, EventId::ZERO).claims().scope;
    let retained = store
        .read_page(0, 16)
        .unwrap()
        .events
        .iter()
        .map(VerifiedEvent::encode)
        .collect::<Vec<_>>();
    let outcome = send(
        &mut session,
        &mut store,
        room,
        &mut transport,
        &|| Ok(1000),
        &quiet(),
    )
    .unwrap();
    assert!(outcome.error.is_none());
    assert_eq!(outcome.report["confirmed"].as_array().unwrap().len(), 3);
    assert_eq!(outcome.report["remaining"], "2");
    assert_eq!(transport.sent, retained[..3]);
    drop(store);
    drop(session);
    let mut store = home.reopen_outbox();
    let mut session = home.reopen();
    let outcome = send(
        &mut session,
        &mut store,
        room,
        &mut transport,
        &|| Ok(1000),
        &quiet(),
    )
    .unwrap();
    assert!(outcome.error.is_none());
    assert_eq!(outcome.report["peerAcknowledgedThrough"], "5");
    assert_eq!(transport.sent, retained);
    assert_eq!(
        store
            .read_page(0, 16)
            .unwrap()
            .events
            .iter()
            .map(VerifiedEvent::encode)
            .collect::<Vec<_>>(),
        retained
    );
    let outcome = send(
        &mut session,
        &mut store,
        room,
        &mut transport,
        &|| Ok(1000),
        &quiet(),
    )
    .unwrap();
    assert_eq!(outcome.report["status"], "already-acknowledged");
    assert_eq!(transport.sent.len(), 5);
}

#[test]
fn native_controller_partial_success_keeps_confirmed_prefix_and_stops() {
    let home = Home::new();
    let mut session = home.session();
    let mut store = home.create_outbox(3);
    let mut transport = Synthetic::new();
    transport.fail_after = Some(1);
    let room = event(1, EventId::ZERO).claims().scope;
    let outcome = send(
        &mut session,
        &mut store,
        room,
        &mut transport,
        &|| Ok(1000),
        &quiet(),
    )
    .unwrap();
    assert!(outcome.error.is_some());
    assert_eq!(outcome.report["peerAcknowledgedThrough"], "1");
    assert_eq!(outcome.report["confirmed"].as_array().unwrap().len(), 1);
    drop(store);
    drop(session);
    let mut store = home.reopen_outbox();
    let mut session = home.reopen();
    transport.fail_after = None;
    let outcome = send(
        &mut session,
        &mut store,
        room,
        &mut transport,
        &|| Ok(1000),
        &quiet(),
    )
    .unwrap();
    assert!(outcome.error.is_none());
    assert_eq!(outcome.report["peerAcknowledgedThrough"], "3");
    assert_eq!(transport.sent.len(), 3);
}

#[test]
fn native_controller_retains_newer_withdrawal_or_route_removal_and_rejects_old_replay() {
    for changed_route in [false, true] {
        let home = Home::new();
        let mut session = home.session();
        let mut store = home.create_outbox(1);
        let mut transport = Synthetic::new();
        transport.advertisement = advertisement(
            2,
            1000,
            2000,
            if changed_route { 3 } else { 1 },
            changed_route,
        );
        let room = event(1, EventId::ZERO).claims().scope;
        let outcome = send(
            &mut session,
            &mut store,
            room,
            &mut transport,
            &|| Ok(1000),
            &quiet(),
        )
        .unwrap();
        assert!(outcome.error.is_some());
        assert!(transport.sent.is_empty());
        assert_eq!(
            session
                .selection()
                .unwrap()
                .advertisement()
                .unverified_claims()
                .sequence,
            2
        );
        drop(session);
        let mut session = home.reopen();
        transport.advertisement = advertisement(1, 1000, 1100, 3, false);
        assert!(send(
            &mut session,
            &mut store,
            room,
            &mut transport,
            &|| Ok(1000),
            &quiet()
        )
        .unwrap()
        .error
        .is_some());
        assert_eq!(
            session
                .selection()
                .unwrap()
                .advertisement()
                .unverified_claims()
                .sequence,
            2
        );
        assert!(transport.sent.is_empty());
    }
}

#[test]
fn native_controller_expired_peer_can_only_refresh_and_clock_rollback_dials_nothing() {
    let home = Home::new();
    let mut session = home.session();
    let mut transport = Synthetic::new();
    transport.advertisement = advertisement(2, 1200, 2000, 3, false);
    assert!(refresh(&mut session, &mut transport, &|| Ok(1200), true, &quiet()).is_ok());
    assert_eq!(transport.refreshes, 1);
    assert!(transport.sent.is_empty());
    assert!(refresh(&mut session, &mut transport, &|| Ok(1199), true, &quiet()).is_err());
    assert_eq!(transport.refreshes, 1);
    drop(session);
    assert_eq!(home.reopen().selection().unwrap().clock_floor(), 1200);
}

#[test]
fn native_controller_refresh_and_post_proofs_require_exact_network_peer_nonce_and_body() {
    for fault in [Fault::Network, Fault::Peer, Fault::Nonce, Fault::Body] {
        for at_refresh in [true, false] {
            let home = Home::new();
            let mut session = home.session();
            let mut store = home.create_outbox(1);
            let mut transport = Synthetic::new();
            if at_refresh {
                transport.ad_fault = fault;
            } else {
                transport.activity_fault = fault;
            }
            let outcome = send(
                &mut session,
                &mut store,
                event(1, EventId::ZERO).claims().scope,
                &mut transport,
                &|| Ok(1000),
                &quiet(),
            )
            .unwrap();
            assert!(outcome.error.is_some());
            assert_eq!(outcome.report["confirmed"], json!([]));
            assert!(store
                .load_delivery(peer_key().verifying_key().to_bytes())
                .unwrap()
                .is_none());
            assert_eq!(transport.sent.len(), usize::from(!at_refresh));
        }
    }
}

#[test]
fn native_controller_cancelled_reply_is_not_acknowledged_and_retry_keeps_exact_bytes() {
    let home = Home::new();
    let mut session = home.session();
    let mut store = home.create_outbox(1);
    let mut transport = Synthetic::new();
    transport.cancel_on_reply = true;
    let room = event(1, EventId::ZERO).claims().scope;
    let result = send(
        &mut session,
        &mut store,
        room,
        &mut transport,
        &|| Ok(1000),
        &quiet(),
    )
    .unwrap();
    assert!(result.error.is_some());
    assert_eq!(result.report["confirmed"], json!([]));
    let bytes = transport.sent[0].clone();
    drop(store);
    drop(session);
    let mut store = home.reopen_outbox();
    let mut session = home.reopen();
    transport.cancel_on_reply = false;
    let result = send(
        &mut session,
        &mut store,
        room,
        &mut transport,
        &|| Ok(1000),
        &quiet(),
    )
    .unwrap();
    assert!(result.error.is_none());
    assert_eq!(transport.sent, vec![bytes.clone(), bytes]);
}

#[test]
fn native_controller_receipt_write_uncertainty_never_reports_success_and_reconciles() {
    use std::os::unix::fs::PermissionsExt;
    let home = Home::new();
    let mut session = home.session();
    let mut store = home.create_outbox(1);
    let mut transport = Synthetic::new();
    let room = event(1, EventId::ZERO).claims().scope;
    transport.obstruct_intent = Some(home.outbox().join("INTENT.tmp"));
    let result = send(
        &mut session,
        &mut store,
        room,
        &mut transport,
        &|| Ok(1000),
        &quiet(),
    )
    .unwrap();
    assert!(result.error.is_some());
    assert_eq!(result.report["confirmed"], json!([]));
    assert!(store.needs_reopen());
    let bytes = transport.sent[0].clone();
    fs::set_permissions(
        home.outbox().join("INTENT.tmp"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    drop(store);
    drop(session);
    let mut store = home.reopen_outbox();
    let mut session = home.reopen();
    assert!(store
        .load_delivery(peer_key().verifying_key().to_bytes())
        .unwrap()
        .is_none());
    let result = send(
        &mut session,
        &mut store,
        room,
        &mut transport,
        &|| Ok(1000),
        &quiet(),
    )
    .unwrap();
    assert!(result.error.is_none());
    assert_eq!(transport.sent, vec![bytes.clone(), bytes]);
}

#[test]
fn native_controller_read_exports_exact_evidence_and_never_overwrites() {
    let home = Home::new();
    let mut session = home.session();
    let mut transport = Synthetic::new();
    let output = home.0.join("export");
    let room = event(1, EventId::ZERO).claims().scope;
    let manifest = read(
        &mut session,
        room,
        0,
        &output,
        &mut transport,
        &|| Ok(1000),
        &quiet(),
    )
    .unwrap();
    assert_eq!(manifest["nextAfter"], "1");
    assert_eq!(manifest["authorContinuity"], "not-independently-verified");
    let raw = fs::read(output.join("response.vhactivity-page")).unwrap();
    let target = fs::read_to_string(output.join("request.txt")).unwrap();
    let request = ActivityRequest::parse_target(&target).unwrap();
    let proof =
        ActivityResponseProof::decode(&fs::read(output.join("response.vhproof")).unwrap()).unwrap();
    proof
        .verify(
            [7; 32],
            peer_key().verifying_key().to_bytes(),
            &request,
            &raw,
        )
        .unwrap();
    let record = manifest["records"][0]["file"].as_str().unwrap();
    assert_eq!(
        fs::read(output.join(record)).unwrap(),
        transport.page_events[0].encode()
    );
    let refreshes = transport.refreshes;
    assert!(read(
        &mut session,
        room,
        0,
        &output,
        &mut transport,
        &|| Ok(1000),
        &quiet()
    )
    .is_err());
    assert_eq!(transport.refreshes, refreshes);
    assert_eq!(
        fs::read(output.join("response.vhactivity-page")).unwrap(),
        raw
    );
}

#[test]
fn native_controller_foreign_full_scope_or_bad_page_proof_creates_no_export() {
    for change in 0..4 {
        let home = Home::new();
        let mut session = home.session();
        let mut transport = Synthetic::new();
        let output = home.0.join("refused");
        let room = event(1, EventId::ZERO).claims().scope;
        if change < 2 {
            let mut claims = transport.page_events[0].claims().clone();
            if change == 0 {
                claims.scope.realm.0 += 1;
            } else {
                claims.scope.directory = vhalla_rooms::DirectoryId::from_bytes([77; 32]);
            }
            transport.page_events[0] = UnsignedEvent::new(claims)
                .unwrap()
                .sign_with_key(&SigningKey::from_bytes(&[3; 32]))
                .unwrap()
                .verify()
                .unwrap();
        } else {
            transport.activity_fault = if change == 2 {
                Fault::Nonce
            } else {
                Fault::Body
            };
        }
        assert!(read(
            &mut session,
            room,
            0,
            &output,
            &mut transport,
            &|| Ok(1000),
            &quiet()
        )
        .is_err());
        assert!(!output.exists());
    }
}

#[test]
fn native_controller_deadline_drains_owned_work_and_pre_cancel_dials_nothing() {
    let completed = Arc::new(AtomicBool::new(false));
    let worker = completed.clone();
    let result = supervised(Duration::from_millis(20), move |cancel| {
        while !cancel.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(1));
        }
        worker.store(true, Ordering::Relaxed);
        Err("cancelled synthetic transport".into())
    });
    assert!(result.unwrap_err().contains("deadline"));
    assert!(completed.load(Ordering::Relaxed));
    let home = Home::new();
    let mut session = home.session();
    let mut transport = Synthetic::new();
    assert!(refresh(
        &mut session,
        &mut transport,
        &|| Ok(1000),
        true,
        &AtomicBool::new(true)
    )
    .is_err());
    assert_eq!(transport.refreshes, 0);
}
