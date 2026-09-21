use super::*;
use ed25519_dalek::SigningKey;
use std::{cell::Cell, collections::BTreeSet, path::PathBuf, sync::atomic::AtomicU64};
use vhalla_browser_storage::{
    history::{HistoryFrontier, HistoryHead},
    outbox::{AuthorHead, ReservedDraft},
};
use vhalla_public_protocol::{AdvertisementClaims, UnsignedAdvertisement, PROTOCOL_VERSION};
use vhalla_room_activity::EventId;

static SERIAL: AtomicU64 = AtomicU64::new(0);
fn peer_key() -> SigningKey {
    SigningKey::from_bytes(&[55; 32])
}
fn route() -> Endpoint {
    Endpoint::parse("https://selected.vhalla.dev:443/vhalla/v1").unwrap()
}
fn floor() -> wire::Observed {
    wire::Observed {
        height: 7,
        frontier: [6; 32],
    }
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
            time: 1000,
        },
        [5; 32],
    )
    .unwrap()
}
fn ad(sequence: u64, caps: u32) -> Vec<u8> {
    UnsignedAdvertisement::new(AdvertisementClaims {
        network: [7; 32],
        application_key: peer_key().verifying_key().to_bytes(),
        sequence,
        issued_at: 1000,
        expires_at: 4000,
        protocol: PROTOCOL_VERSION,
        capabilities: Capabilities::from_bits(caps).unwrap(),
        endpoints: vec![route()],
    })
    .unwrap()
    .sign_with_key(&peer_key())
    .unwrap()
    .encode()
}
fn frame(sequence: u64, previous: EventId) -> VerifiedEvent {
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
struct Home {
    path: PathBuf,
    events: Vec<VerifiedEvent>,
    scope: SessionScope,
    limits: Limits,
}
impl Home {
    fn new(count: usize) -> Self {
        let path = std::env::temp_dir().join(format!(
            "vhalla-continuity-controller-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        let mut events = Vec::new();
        let mut previous = EventId::ZERO;
        for n in 1..=count {
            let e = frame(n as u64, previous);
            previous = e.id();
            events.push(e);
        }
        let scope = SessionScope::new(
            AuthorScope::new(events[0].claims().scope, events[0].claims().author),
            history().scope(),
            peer_key().verifying_key().to_bytes(),
            route(),
        )
        .unwrap();
        Self {
            path,
            events,
            scope,
            limits: Limits {
                max_records: 32,
                max_bytes: 4 * 1024 * 1024,
            },
        }
    }
    fn peer(&self, create: bool) -> NativePeerSession {
        if create {
            NativePeerSession::create_new(
                self.path.join("peer"),
                history().scope(),
                self.scope.peer(),
                route(),
                &ad(1, 3),
                1000,
            )
            .unwrap()
        } else {
            NativePeerSession::open(
                self.path.join("peer"),
                history().scope(),
                self.scope.peer(),
                &route(),
            )
            .unwrap()
        }
    }
    fn source(&self, create: bool) -> NativeOutbox {
        if !create {
            return NativeOutbox::open(
                self.path.join("source"),
                self.scope.author(),
                history().scope(),
            )
            .unwrap();
        }
        let mut store = NativeOutbox::create_new(
            self.path.join("source"),
            AuthorHead::fresh_scope_authorized(self.scope.author()),
            history(),
            vhalla_browser_storage::native::Limits::default(),
        )
        .unwrap();
        for event in &self.events {
            let draft = ReservedDraft::new(
                store.head().unwrap(),
                history(),
                UnsignedEvent::new(event.claims().clone()).unwrap(),
            )
            .unwrap();
            store.reserve(&draft).unwrap();
            store.finalize(&draft, event).unwrap();
        }
        store
    }
    fn receipts(&self, source: &NativeOutbox, create: bool) -> NativeContinuity {
        if !create {
            return NativeContinuity::open(
                &self.path.join("receipts"),
                self.scope.clone(),
                self.limits,
                source,
            )
            .unwrap();
        }
        let mut store = NativeContinuity::create_new(
            &self.path.join("receipts"),
            self.scope.clone(),
            self.limits,
            source,
        )
        .unwrap();
        select(source, &mut store, self.events.last().unwrap()).unwrap();
        store
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
struct Gate {
    available: usize,
    checks: Cell<usize>,
}
impl Gate {
    fn open() -> Self {
        Self {
            available: usize::MAX,
            checks: Cell::new(0),
        }
    }
    fn closed() -> Self {
        Self {
            available: 0,
            checks: Cell::new(0),
        }
    }
}
impl Policy for Gate {
    fn floor(&self) -> wire::Observed {
        floor()
    }
    fn permit(&self, _: &VerifiedEvent) -> Result<(), String> {
        self.checks.set(self.checks.get() + 1);
        if self.checks.get() <= self.available {
            Ok(())
        } else {
            Err("synthetic current-journal/policy refusal".into())
        }
    }
}
#[derive(Clone, Copy, Default)]
enum Fault {
    #[default]
    None,
    Nonce,
    Peer,
    Scope,
    Body,
    Network,
    Cancel,
    Fork,
    StopAfterCommit,
}
struct Server {
    events: Vec<VerifiedEvent>,
    published: usize,
    cursor: u64,
    admitted_by: Vec<u64>,
    stage: Option<wire::StageRef>,
    observed: wire::Observed,
    requests: Vec<wire::Request>,
    nonces: BTreeSet<[u8; 32]>,
    refreshes: usize,
    caps: u32,
    closed: bool,
    fault: Fault,
    obstruct: Option<PathBuf>,
}
impl Server {
    fn new(home: &Home) -> Self {
        Self {
            published: 0,
            cursor: 0,
            admitted_by: vec![0; home.events.len()],
            events: home.events.clone(),
            stage: None,
            observed: floor(),
            requests: vec![],
            nonces: BTreeSet::new(),
            refreshes: 0,
            caps: 3,
            closed: false,
            fault: Fault::None,
            obstruct: None,
        }
    }
    fn point(&self, n: usize) -> wire::Position {
        if n == 0 {
            wire::Position::EMPTY
        } else {
            wire::Position::of(&self.events[n - 1])
        }
    }
}
impl Transport for Server {
    fn advertisement(
        &mut self,
        endpoint: &Endpoint,
        request: &ReadRequest,
        _: &AtomicBool,
    ) -> Result<(Vec<u8>, String), String> {
        assert_eq!(endpoint, &route());
        self.refreshes += 1;
        assert!(self.nonces.insert(request.nonce()));
        let raw = ad(2, self.caps);
        let proof = response::UnsignedResponse::new(
            [7; 32],
            peer_key().verifying_key().to_bytes(),
            *request,
            &raw,
        )
        .unwrap()
        .sign_with_key(&peer_key())
        .unwrap();
        Ok((raw, hex(&proof.encode())))
    }
    fn activity(
        &mut self,
        _: &Endpoint,
        _: &ActivityRequest,
        _: Option<&[u8]>,
        _: &AtomicBool,
    ) -> Result<(Vec<u8>, String), String> {
        panic!("continuity must never fall back to v1")
    }
}
impl ContinuityTransport for Server {
    fn continuity(
        &mut self,
        endpoint: &Endpoint,
        request: &wire::Request,
        body: Option<&[u8]>,
        cancel: &AtomicBool,
    ) -> Result<(Vec<u8>, String), String> {
        assert_eq!(endpoint, &route());
        assert!(self.nonces.insert(request.context().nonce));
        self.requests.push(*request);
        if matches!(self.fault, Fault::Network) {
            return Err("synthetic HTTP429/503/404 refusal".into());
        }
        let reply = match request.kind() {
            wire::Kind::Status { .. } => {
                assert!(body.is_none());
                wire::Reply::Status(wire::Status {
                    observed: self.observed,
                    published: if matches!(self.fault, Fault::Fork) {
                        wire::Position::new(1, EventId::from_bytes([98; 32])).unwrap()
                    } else {
                        self.point(self.published)
                    },
                    stage: self.stage,
                })
            }
            wire::Kind::Stage {
                base,
                prior,
                end,
                body: hash,
            } => {
                let frames = request.check_body(body.unwrap()).unwrap();
                assert_eq!(frames.history().len(), 32);
                assert_eq!(base, self.point(self.published));
                assert_eq!(prior, self.stage);
                let offset = prior.map_or(base, |p| p.tail()).sequence() as usize;
                assert_eq!(
                    frames
                        .history()
                        .iter()
                        .map(VerifiedEvent::encode)
                        .collect::<Vec<_>>(),
                    self.events[offset..offset + 32]
                        .iter()
                        .map(VerifiedEvent::encode)
                        .collect::<Vec<_>>()
                );
                let ticket = wire::StageRef::new(
                    [4; 32],
                    base,
                    end,
                    prior.map_or(1, |p| p.pages() + 1),
                    2000,
                )
                .unwrap();
                self.stage = Some(ticket);
                wire::Reply::Staged(wire::StageAck {
                    observed: self.observed,
                    base,
                    ticket,
                    submitted_end: end,
                    submitted_body: hash,
                })
            }
            wire::Kind::Commit { terminal, .. } => {
                let frames = request.check_body(body.unwrap()).unwrap();
                let frame = frames.terminal().unwrap();
                assert_eq!(wire::Position::of(frame), terminal);
                assert_eq!(
                    frame.encode(),
                    self.events[terminal.sequence() as usize - 1].encode()
                );
                let reconciled = self.published >= terminal.sequence() as usize;
                if !reconciled {
                    assert!(!self.closed, "closed peer admitted fresh terminal");
                    self.cursor += 1;
                    for slot in &mut self.admitted_by[self.published..terminal.sequence() as usize]
                    {
                        *slot = self.cursor;
                    }
                    self.published = terminal.sequence() as usize;
                    self.stage = None;
                }
                if matches!(self.fault, Fault::StopAfterCommit) {
                    self.fault = Fault::None;
                    return Err("connection lost after actual synthetic peer decision".into());
                }
                wire::Reply::Committed(Box::new(wire::TerminalReceipt {
                    observed: self.observed,
                    event: frame.clone(),
                    cursor: self.admitted_by[terminal.sequence() as usize - 1],
                    registry: [9; 32],
                    reconciled,
                }))
            }
            wire::Kind::Evidence { after, count } => {
                assert!(body.is_none());
                let end = self
                    .published
                    .min(after.sequence() as usize + usize::from(count));
                let entries = self.events[after.sequence() as usize..end]
                    .iter()
                    .map(|e| wire::Entry {
                        role: if e.claims().sequence as usize == self.published {
                            wire::EvidenceRole::CurrentAdmission
                        } else {
                            wire::EvidenceRole::HistoricalContinuity
                        },
                        committed_by: self.admitted_by[e.claims().sequence as usize - 1],
                        registry: [9; 32],
                        event: e.clone(),
                    })
                    .collect();
                wire::Reply::Evidence(wire::EvidencePage {
                    observed: self.observed,
                    tip: self.point(self.published),
                    entries,
                })
            }
            wire::Kind::Feed { .. } => panic!("controller cannot issue all-author feed"),
        };
        let mut bound = *request;
        let mut context = bound.context();
        if matches!(self.fault, Fault::Nonce) {
            context.nonce = [91; 32];
        }
        if matches!(self.fault, Fault::Scope) {
            context.scope.room[0] ^= 1;
        }
        bound = wire::Request::new(context, bound.selection(), bound.kind()).unwrap();
        let mut raw = reply.encode(&bound).unwrap();
        let key = if matches!(self.fault, Fault::Peer) {
            SigningKey::from_bytes(&[56; 32])
        } else {
            peer_key()
        };
        let proof = wire::UnsignedResponse::new(key.verifying_key().to_bytes(), bound, &raw)
            .unwrap()
            .sign_with_key(&key)
            .unwrap();
        if matches!(self.fault, Fault::Body) {
            *raw.last_mut().unwrap() ^= 1;
        }
        if matches!(self.fault, Fault::Cancel) {
            cancel.store(true, Ordering::Relaxed);
        }
        if let Some(path) = self.obstruct.take() {
            fs::create_dir(path).unwrap();
        }
        Ok((raw, hex(&proof.encode())))
    }
}
fn step(home: &Home, create: bool, server: &mut Server, gate: &Gate) -> (SendOutcome, Snapshot) {
    step_bounded(home, create, server, gate, MAX_ANCESTORS)
}
fn step_bounded(
    home: &Home,
    create: bool,
    server: &mut Server,
    gate: &Gate,
    bound: u64,
) -> (SendOutcome, Snapshot) {
    let mut peer = home.peer(create);
    let source = home.source(create);
    let mut receipts = home.receipts(&source, create);
    let outcome = Controller {
        peer: &mut peer,
        source: &source,
        receipts: &mut receipts,
        policy: gate,
        bound,
    }
    .step(server, &|| Ok(1001), &AtomicBool::new(false))
    .unwrap();
    let state = receipts.snapshot(&source).unwrap();
    assert!(source.load_delivery(home.scope.peer()).unwrap().is_none());
    (outcome, state)
}
#[test]
fn continuity_controller_stages_then_commits_then_persists_exact_evidence_across_restarts() {
    let h = Home::new(65);
    let mut server = Server::new(&h);
    let gate = Gate::open();
    let (outcome, state) = step(&h, true, &mut server, &gate);
    assert!(outcome.error.is_none());
    assert_eq!(server.requests.len(), 3);
    assert!(matches!(
        server.requests[1].kind(),
        wire::Kind::Stage { .. }
    ));
    assert!(matches!(
        server.requests[2].kind(),
        wire::Kind::Commit { .. }
    ));
    assert!(state.terminal().is_some());
    assert_eq!(state.retention().position(), wire::Position::EMPTY);
    assert!(!state.complete());
    let author_before = fs::read(h.path.join("source/STATE")).unwrap();
    let (outcome, state) = step(&h, false, &mut server, &gate);
    assert!(outcome.error.is_none());
    assert_eq!(state.retention().position().sequence(), 64);
    assert!(!state.complete());
    let (outcome, state) = step(&h, false, &mut server, &gate);
    assert!(outcome.error.is_none());
    assert!(state.complete());
    assert_eq!(state.record_count(), 8);
    assert_eq!(server.refreshes, 3);
    assert_eq!(
        fs::read(h.path.join("source/STATE")).unwrap(),
        author_before
    );
    let prior = server.requests.len();
    let (_, again) = step(&h, false, &mut server, &gate);
    assert_eq!(again, state);
    assert_eq!(server.requests.len(), prior);
    assert_eq!(server.refreshes, 3);
}
#[test]
fn continuity_controller_intermediate_admissions_reach_one_fixed_target() {
    // Bound 5 mirrors a peer admitting at most 5 staged+inline ancestors per
    // terminal: the fixed target 16 advances through ordered phases 6, 12, 16.
    let h = Home::new(16);
    let mut server = Server::new(&h);
    let gate = Gate::open();
    let (outcome, state) = step_bounded(&h, true, &mut server, &gate, 5);
    assert!(outcome.error.is_none());
    assert_eq!(server.requests.len(), 3);
    assert!(matches!(
        server.requests[1].kind(),
        wire::Kind::Commit { terminal, .. } if terminal.sequence() == 6
    ));
    assert_eq!(state.retention().position().sequence(), 6);
    assert!(!state.complete());
    let (outcome, state) = step_bounded(&h, false, &mut server, &gate, 5);
    assert!(outcome.error.is_none());
    assert!(matches!(
        server.requests[4].kind(),
        wire::Kind::Commit { terminal, .. } if terminal.sequence() == 12
    ));
    assert_eq!(state.retention().position().sequence(), 12);
    assert!(!state.complete());
    let (outcome, state) = step_bounded(&h, false, &mut server, &gate, 5);
    assert!(outcome.error.is_none());
    assert!(matches!(
        server.requests[7].kind(),
        wire::Kind::Commit { terminal, .. } if terminal.sequence() == 16
    ));
    assert!(state.complete());
    assert_eq!(state.terminal().unwrap().position().sequence(), 16);
    assert_eq!(
        server
            .requests
            .iter()
            .filter_map(|r| match r.kind() {
                wire::Kind::Commit { terminal, .. } => Some(terminal.sequence()),
                _ => None,
            })
            .collect::<Vec<_>>(),
        vec![6, 12, 16]
    );
    assert_eq!(server.published, 16);
    assert_eq!(server.refreshes, 3);
    let prior = server.requests.len();
    let (_, again) = step_bounded(&h, false, &mut server, &gate, 5);
    assert_eq!(again, state);
    assert_eq!(server.requests.len(), prior);
}
#[test]
fn continuity_controller_existing_terminal_reconciles_after_revocation_without_fresh_permission() {
    let h = Home::new(33);
    let mut server = Server::new(&h);
    server.published = 33;
    server.cursor = 1;
    server.admitted_by[..33].fill(1);
    server.closed = true;
    let gate = Gate::closed();
    let (_, state) = step(&h, true, &mut server, &gate);
    assert_eq!(state.retention().position().sequence(), 33);
    assert!(state.terminal().is_none());
    assert!(!state.complete());
    let (outcome, state) = step(&h, false, &mut server, &gate);
    assert!(outcome.error.is_none());
    assert!(state.complete());
    assert_eq!(gate.checks.get(), 0);
    assert!(server
        .requests
        .iter()
        .filter(|r| matches!(r.kind(), wire::Kind::Commit { .. }))
        .all(|r| matches!(r.kind(),wire::Kind::Commit{base,stage:None,..} if base.sequence()==32)));
}
#[test]
fn continuity_controller_lost_commit_reply_uses_evidence_not_a_new_old_policy_post() {
    let h = Home::new(1);
    let mut server = Server::new(&h);
    server.fault = Fault::StopAfterCommit;
    let (outcome, state) = step(&h, true, &mut server, &Gate::open());
    assert!(outcome.error.is_some());
    assert_eq!(server.published, 1);
    assert!(state.terminal().is_none());
    assert!(state.attempt().is_some());
    server.closed = true;
    let (outcome, state) = step(&h, false, &mut server, &Gate::closed());
    assert!(outcome.error.is_none());
    assert!(state.complete());
}
#[test]
fn continuity_controller_closed_or_advanced_journal_never_sends_fresh_after_saved_attempt() {
    for available in [0, 2] {
        let h = Home::new(1);
        let mut server = Server::new(&h);
        let gate = Gate {
            available,
            checks: Cell::new(0),
        };
        let (outcome, state) = step(&h, true, &mut server, &gate);
        assert!(outcome.error.is_some());
        assert_eq!(server.requests.len(), 1);
        assert_eq!(server.published, 0);
        assert_eq!(state.record_count(), 1);
        assert_eq!(state.retention().position(), wire::Position::EMPTY);
        if available == 2 {
            assert!(matches!(
                state.attempt().unwrap().request().kind(),
                wire::Kind::Commit { .. }
            ));
        }
    }
}
#[test]
fn continuity_controller_wrong_reply_cancel_and_http_refusals_cannot_install() {
    for fault in [
        Fault::Nonce,
        Fault::Peer,
        Fault::Scope,
        Fault::Body,
        Fault::Network,
        Fault::Cancel,
        Fault::Fork,
    ] {
        let h = Home::new(1);
        let mut server = Server::new(&h);
        server.fault = fault;
        let (outcome, state) = step(&h, true, &mut server, &Gate::open());
        assert!(outcome.error.is_some());
        assert_eq!(state.record_count(), 0);
        assert!(state.attempt().is_some());
        assert_eq!(state.retention().position(), wire::Position::EMPTY);
        assert_eq!(server.requests.len(), 1);
        assert_eq!(server.refreshes, 1);
    }
}
#[test]
fn continuity_controller_withdrawal_is_retained_before_publication_refusal() {
    let h = Home::new(1);
    let mut server = Server::new(&h);
    server.caps = 1;
    let (outcome, state) = step(&h, true, &mut server, &Gate::open());
    assert!(outcome.error.is_some());
    assert_eq!(server.requests.len(), 1);
    assert_eq!(state.record_count(), 1);
    let peer = h.peer(false);
    let selection = peer.selection().unwrap();
    assert_eq!(selection.advertisement().unverified_claims().sequence, 2);
    assert!(!selection
        .advertisement()
        .unverified_claims()
        .capabilities
        .contains(Capabilities::PUBLISH));
}
#[test]
fn continuity_controller_expired_stage_and_newer_unverified_frontier_stop_fresh_work() {
    for newer in [false, true] {
        let h = Home::new(65);
        let mut server = Server::new(&h);
        if newer {
            server.observed = wire::Observed {
                height: 8,
                frontier: [8; 32],
            };
        } else {
            server.stage = Some(
                wire::StageRef::new([4; 32], wire::Position::EMPTY, server.point(32), 1, 1001)
                    .unwrap(),
            );
        }
        let (outcome, state) = step(&h, true, &mut server, &Gate::open());
        assert!(outcome.error.is_some());
        assert_eq!(server.requests.len(), 1);
        assert_eq!(state.retention().position(), wire::Position::EMPTY);
    }
}
#[test]
fn continuity_controller_uncertain_receipt_write_has_no_success_or_v1_mutation() {
    let h = Home::new(1);
    let mut peer = h.peer(true);
    let source = h.source(true);
    let mut receipts = h.receipts(&source, true);
    let author = fs::read(h.path.join("source/STATE")).unwrap();
    let mut server = Server::new(&h);
    server.obstruct = Some(h.path.join("receipts/INTENT.tmp"));
    let outcome = Controller {
        peer: &mut peer,
        source: &source,
        receipts: &mut receipts,
        policy: &Gate::open(),
        bound: MAX_ANCESTORS,
    }
    .step(&mut server, &|| Ok(1001), &AtomicBool::new(false))
    .unwrap();
    assert!(outcome.error.is_some());
    assert!(receipts.needs_reopen());
    assert_eq!(outcome.report["records"], "0");
    assert_eq!(outcome.report["needsReopen"], true);
    assert_eq!(fs::read(h.path.join("source/STATE")).unwrap(), author);
    assert!(h.path.join("receipts/INTENT.tmp").is_dir());
}
#[test]
fn continuity_controller_fixed_quota_does_not_reset_receipts_or_author() {
    let mut h = Home::new(1);
    h.limits.max_records = 1;
    let mut server = Server::new(&h);
    let (outcome, state) = step(&h, true, &mut server, &Gate::open());
    assert!(outcome.error.is_some());
    assert_eq!(state.record_count(), 1);
    assert_eq!(state.retention().position(), wire::Position::EMPTY);
    assert!(state.attempt().is_some());
    assert_eq!(server.published, 1);
    let source = h.source(false);
    assert!(
        NativeContinuity::open(&h.path.join("absent"), h.scope.clone(), h.limits, &source).is_err()
    );
    assert!(!h.path.join("absent").exists());
}
#[test]
fn continuity_controller_explicit_selection_never_signs_pending_or_follows_later_local_head() {
    let h = Home::new(2);
    let mut source = h.source(true);
    let mut receipts =
        NativeContinuity::create_new(&h.path.join("receipts"), h.scope.clone(), h.limits, &source)
            .unwrap();
    let first = select(&source, &mut receipts, &h.events[0]).unwrap();
    let same = select(&source, &mut receipts, &h.events[0]).unwrap();
    assert_eq!(same.job(), first.job());
    assert_eq!(same.job().unwrap().terminal().sequence(), 1);
    assert_eq!(source.head().unwrap().sequence(), 2);
    let third = frame(3, h.events[1].id());
    let draft = ReservedDraft::new(
        source.head().unwrap(),
        history(),
        UnsignedEvent::new(third.claims().clone()).unwrap(),
    )
    .unwrap();
    source.reserve(&draft).unwrap();
    let before = fs::read(h.path.join("source/STATE")).unwrap();
    assert!(event(&source, 3)
        .unwrap_err()
        .contains("unsigned held draft"));
    assert_eq!(
        source.load_pending().unwrap().unwrap().as_bytes(),
        draft.as_bytes()
    );
    assert_eq!(fs::read(h.path.join("source/STATE")).unwrap(), before);
    let later = select(&source, &mut receipts, &h.events[1]).unwrap();
    assert_ne!(
        later.job().unwrap().operation(),
        same.job().unwrap().operation()
    );
    assert!(select(&source, &mut receipts, &h.events[0]).is_err());
}

#[test]
fn continuity_controller_peer_past_fixed_target_requires_explicit_later_selection() {
    let h = Home::new(2);
    let mut peer = h.peer(true);
    let source = h.source(true);
    let mut receipts =
        NativeContinuity::create_new(&h.path.join("receipts"), h.scope.clone(), h.limits, &source)
            .unwrap();
    select(&source, &mut receipts, &h.events[0]).unwrap();
    let mut server = Server::new(&h);
    server.published = 2;
    let outcome = Controller {
        peer: &mut peer,
        source: &source,
        receipts: &mut receipts,
        policy: &Gate::closed(),
        bound: MAX_ANCESTORS,
    }
    .step(&mut server, &|| Ok(1001), &AtomicBool::new(false))
    .unwrap();
    assert!(outcome.error.unwrap().contains("explicitly select a later"));
    assert_eq!(server.requests.len(), 1);
    let state = receipts.snapshot(&source).unwrap();
    assert_eq!(
        state.job().unwrap().terminal(),
        wire::Position::of(&h.events[0])
    );
    assert_eq!(state.retention().position(), wire::Position::EMPTY);
    assert!(state.terminal().is_none());
    assert!(!state.complete());
    assert_eq!(source.head().unwrap().sequence(), 2);
}
#[test]
fn continuity_controller_canonical_arguments_and_page_bounds_refuse_without_dial() {
    for bad in ["01", "+1", "-1", " 1", "18446744073709551616"] {
        assert!(canonical(bad, "value").is_err());
    }
    assert_eq!(canonical("0", "value").unwrap(), 0);
    assert_eq!(phase_terminal(0, 4129, MAX_ANCESTORS), 4129);
    assert_eq!(phase_terminal(0, 4130, MAX_ANCESTORS), 4129);
    assert_eq!(phase_terminal(4129, 4130, MAX_ANCESTORS), 4130);
    assert_eq!(phase_terminal(0, 16, 5), 6);
    assert_eq!(phase_terminal(6, 16, 5), 12);
    assert_eq!(phase_terminal(12, 16, 5), 16);
    assert_eq!(
        phase_terminal(u64::MAX - 1, u64::MAX, MAX_ANCESTORS),
        u64::MAX
    );
    let h = Home::new(1);
    let source = h.source(true);
    assert!(range(&source, 0, 33).is_err());
    assert!(range(&source, 0, 2).is_err());
    for command in [
        "continuity-init",
        "continuity-select",
        "continuity-status",
        "continuity-step",
    ] {
        assert!(run(&["public".into(), "activity".into(), command.into()], None).is_err());
    }
}
