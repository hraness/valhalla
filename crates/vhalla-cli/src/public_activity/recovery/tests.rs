use super::*;
use ed25519_dalek::SigningKey;
use std::{
    cell::Cell,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use vhalla_rooms::{RoomRecordId, RoomUpdate, Slug, UpdateAction};
use vhalla_rooms_consensus::fixture;

// These unit views contain real admitted registry revisions but deliberately
// do not claim certificate verification. Separate CLI integration tests use
// actual certified journals. The private View seam counts final-HEAD checks.
struct Fixture {
    scenario: fixture::Scenario,
    scope: RoomScope,
}
impl Fixture {
    fn new() -> Self {
        let mut scenario = fixture::scenario(1, 1);
        let mut cursor = 0;
        let (evidence, records, _) = fixture::first_create(
            &scenario.app,
            &scenario.owners[0],
            &mut scenario.sources,
            &mut cursor,
            "held-draft",
            1,
        );
        let checked = scenario.app.prepare(100, evidence, records, None).unwrap();
        scenario.app.apply_locally(checked);
        let room = scenario
            .app
            .registry()
            .room(&Slug::new("held-draft").unwrap())
            .unwrap()
            .genesis();
        let scope = RoomScope {
            network: [7; 32],
            realm: scenario.genesis.realm,
            directory: scenario.genesis.directory,
            room,
        };
        let mut fixture = Self { scenario, scope };
        fixture.policy(true);
        fixture
    }
    fn policy(&mut self, enabled: bool) -> RoomRecordId {
        let room = self
            .scenario
            .app
            .registry()
            .room_by_genesis(self.scope.room)
            .unwrap();
        let owner = &self.scenario.owners[0];
        let height = self.scenario.app.frontier().height + 1;
        let record = RoomUpdate {
            directory: self.scope.directory,
            realm: self.scope.realm,
            genesis: self.scope.room,
            previous: room.head(),
            owner: owner.id,
            social_control: owner.head,
            controller_key: owner.key.verifying_key().to_bytes(),
            expires_at: 1_000_000,
            nonce: [height as u8; 32],
            action: UpdateAction::SetPublicActivityPolicy {
                network: self.scope.network,
                enabled,
            },
        }
        .sign_with_key(&owner.key)
        .unwrap();
        let id = record.id();
        let candidate = self
            .scenario
            .app
            .prepare(height * 100, vec![], vec![record.encode()], None)
            .unwrap();
        self.scenario.app.apply_locally(candidate);
        id
    }
    fn head(&self) -> HistoryHead {
        let f = self.scenario.app.frontier();
        HistoryHead::new(
            HistoryScope::new(self.scope.network, [8; 32]),
            HistoryFrontier {
                height: f.height,
                value: f.value,
                registry: f.registry,
                social: f.social,
                control: f.control,
                time: f.time,
            },
            [f.height as u8; 32],
        )
        .unwrap()
    }
    fn request(&self, sequence: u64, previous: EventId) -> UnsignedEvent {
        let policy = self
            .scenario
            .app
            .registry()
            .room_by_genesis(self.scope.room)
            .unwrap()
            .public_activity_policy()
            .unwrap()
            .record;
        UnsignedEvent::new(EventClaims {
            scope: self.scope,
            policy,
            author: key().verifying_key().to_bytes(),
            sequence,
            previous,
            created_at: 1234,
            content: Content::Text(Text::new("exact held bytes\nremain unchanged").unwrap()),
        })
        .unwrap()
    }
    fn checked(&self, request: UnsignedEvent) -> HistoricalUnsigned {
        AdmissionContext::new(self.scope.network, self.scenario.app.registry())
            .unwrap()
            .check_historical_unsigned(request)
            .unwrap()
    }
}
fn key() -> SigningKey {
    SigningKey::from_bytes(&[42; 32])
}
fn signed(request: UnsignedEvent) -> Result<VerifiedEvent, String> {
    request
        .sign_with_key(&key())
        .and_then(|e| e.verify())
        .map_err(|e| format!("{e:?}"))
}
struct Home(PathBuf);
impl Home {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "vhalla-held-recovery-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn create(
        &self,
        history: HistoryHead,
        request: UnsignedEvent,
    ) -> (NativeOutbox, ReservedDraft) {
        let author = AuthorScope::new(request.claims().scope, request.claims().author);
        let mut store = NativeOutbox::create_new(
            self.0.join("outbox"),
            AuthorHead::fresh_scope_authorized(author),
            history,
            Limits::default(),
        )
        .unwrap();
        let draft = ReservedDraft::new(store.head().unwrap(), history, request).unwrap();
        store.reserve(&draft).unwrap();
        (store, draft)
    }
    fn open(&self, draft: &ReservedDraft) -> NativeOutbox {
        NativeOutbox::open(
            self.0.join("outbox"),
            draft.base().scope(),
            draft.policy_head().scope(),
        )
        .unwrap()
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct Gate<'a> {
    fixture: &'a Fixture,
    fail_at: usize,
    checks: Cell<usize>,
}
impl<'a> Gate<'a> {
    fn new(fixture: &'a Fixture, fail_at: usize) -> Self {
        Self {
            fixture,
            fail_at,
            checks: Cell::new(0),
        }
    }
}
impl View for Gate<'_> {
    fn head(&self) -> HistoryHead {
        self.fixture.head()
    }
    fn historical(&self, request: UnsignedEvent) -> Result<HistoricalUnsigned, String> {
        AdmissionContext::new(
            self.fixture.scope.network,
            self.fixture.scenario.app.registry(),
        )
        .unwrap()
        .check_historical_unsigned(request)
        .map_err(|e| format!("{e:?}"))
    }
    fn check_current(&self) -> Result<(), String> {
        self.checks.set(self.checks.get() + 1);
        if self.fail_at == self.checks.get() {
            Err("synthetic final journal HEAD advanced".into())
        } else {
            Ok(())
        }
    }
}
fn selected(draft: &ReservedDraft) -> Selection {
    Selection {
        sequence: draft.request().claims().sequence,
        event: draft.request().id(),
    }
}

#[test]
fn historical_recovery_draft_basis_preserves_request_and_rejects_substitution() {
    let mut f = Fixture::new();
    let h = Home::new();
    let (_, draft) = h.create(f.head(), f.request(1, EventId::ZERO));
    let checked = f.checked(draft.request().clone());
    assert_eq!(
        draft
            .rebase_historical(f.head(), &checked)
            .unwrap()
            .as_bytes(),
        draft.as_bytes()
    );
    let mut other = draft.request().claims().clone();
    other.content = Content::Text(Text::new("other").unwrap());
    let other = f.checked(UnsignedEvent::new(other).unwrap());
    assert!(draft.rebase_historical(f.head(), &other).is_err());
    f.policy(false);
    let checked = f.checked(draft.request().clone());
    let basis = f.head();
    let next = draft.rebase_historical(basis, &checked).unwrap();
    assert_eq!(next.base(), draft.base());
    assert_eq!(next.request().encode(), draft.request().encode());
    assert_eq!(next.request().id(), draft.request().id());
    assert_eq!(next.policy_head(), basis);
    for bad in 0..6 {
        let mut frontier = basis.frontier();
        let mut scope = basis.scope();
        match bad {
            0 => frontier.registry = [91; 32],
            1 => scope = HistoryScope::new(scope.network(), [91; 32]),
            2 => scope = HistoryScope::new([91; 32], scope.bootstrap_pin()),
            3 => frontier.height = draft.policy_head().frontier().height,
            4 => frontier.height = 0,
            _ => frontier.time = draft.policy_head().frontier().time - 1,
        }
        let wrong = HistoryHead::new(
            scope,
            frontier,
            if frontier.height == 0 {
                [0; 32]
            } else {
                [90; 32]
            },
        )
        .unwrap();
        assert!(draft.rebase_historical(wrong, &checked).is_err());
    }
}

#[test]
fn historical_recovery_wrong_selection_and_policy_have_zero_signer_calls() {
    let mut f = Fixture::new();
    for bad in 0..6 {
        let h = Home::new();
        let mut request = f.request(1, EventId::ZERO);
        if bad == 4 {
            let mut claims = request.claims().clone();
            claims.policy = RoomRecordId::from_bytes([99; 32]);
            request = UnsignedEvent::new(claims).unwrap();
        }
        let (mut store, draft) = h.create(f.head(), request);
        let mut selection = selected(&draft);
        match bad {
            0 => selection.sequence = 2,
            1 => selection.event = EventId::from_bytes([99; 32]),
            _ => {}
        }
        if bad == 3 {
            f.policy(false);
        }
        let gate = Gate::new(&f, if bad == 2 { 1 } else { 0 });
        if bad == 3 {
            fs::write(h.0.join("outbox/STATE"), b"contradictory evidence").unwrap();
        }
        let calls = Cell::new(0);
        let result = recover(&gate, &mut store, selection, |request| {
            calls.set(calls.get() + 1);
            signed(request)
        });
        assert!(result.is_err());
        assert_eq!(calls.get(), 0);
        if bad == 3 {
            assert_eq!(
                fs::read(h.0.join("outbox/STATE")).unwrap(),
                b"contradictory evidence"
            );
        } else {
            assert_eq!(
                store.load_pending().unwrap().unwrap().as_bytes(),
                draft.as_bytes()
            );
        }
    }
}

#[test]
fn historical_recovery_final_head_refusal_after_durable_rebase_is_safe_to_reopen() {
    let mut f = Fixture::new();
    let h = Home::new();
    let (mut store, draft) = h.create(f.head(), f.request(1, EventId::ZERO));
    f.policy(false);
    let gate = Gate::new(&f, 2);
    let calls = Cell::new(0);
    assert!(recover(&gate, &mut store, selected(&draft), |r| {
        calls.set(calls.get() + 1);
        signed(r)
    })
    .is_err());
    assert_eq!(calls.get(), 0);
    assert_eq!(store.head().unwrap(), draft.base());
    let rebased = store.load_pending().unwrap().unwrap();
    assert_eq!(rebased.policy_head(), f.head());
    assert_eq!(rebased.request().encode(), draft.request().encode());
    drop(store);
    let mut store = h.open(&draft);
    let done = recover(&Gate::new(&f, 0), &mut store, selected(&draft), |r| {
        calls.set(calls.get() + 1);
        signed(r)
    })
    .unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(done.event.id(), draft.request().id());
    assert_eq!(done.event.claims(), draft.request().claims());
    assert!(store.load_pending().unwrap().is_none());
}

#[test]
fn historical_recovery_uncertain_pre_sign_storage_never_calls_signer() {
    let mut f = Fixture::new();
    let h = Home::new();
    let (mut store, draft) = h.create(f.head(), f.request(1, EventId::ZERO));
    f.policy(false);
    fs::create_dir(h.0.join("outbox/INTENT.tmp")).unwrap();
    let calls = Cell::new(0);
    assert!(
        recover(&Gate::new(&f, 0), &mut store, selected(&draft), |r| {
            calls.set(calls.get() + 1);
            signed(r)
        })
        .is_err()
    );
    assert_eq!(calls.get(), 0);
    assert!(store.needs_reopen());
    assert!(h.0.join("outbox/INTENT.tmp").is_dir());
}

#[test]
fn historical_recovery_signer_and_post_signature_failure_retain_exact_request() {
    for after_sign in [false, true] {
        let f = Fixture::new();
        let h = Home::new();
        let (mut store, draft) = h.create(f.head(), f.request(1, EventId::ZERO));
        let calls = Cell::new(0);
        let pending = fs::read(h.0.join("outbox/STATE")).unwrap();
        let result = recover(&Gate::new(&f, 0), &mut store, selected(&draft), |request| {
            calls.set(calls.get() + 1);
            if !after_sign {
                return Err("synthetic custody refusal".into());
            }
            let event = signed(request)?;
            fs::create_dir(h.0.join("outbox/INTENT.tmp")).unwrap();
            Ok(event)
        });
        assert!(result.is_err());
        assert_eq!(calls.get(), 1);
        assert_eq!(fs::read(h.0.join("outbox/STATE")).unwrap(), pending);
        assert_eq!(store.needs_reopen(), after_sign);
        if !after_sign {
            assert_eq!(
                store.load_pending().unwrap().unwrap().as_bytes(),
                draft.as_bytes()
            );
        }
    }
}

#[test]
fn historical_recovery_exact_finalized_retry_does_not_touch_newer_pending_or_sign() {
    let mut f = Fixture::new();
    let h = Home::new();
    let (mut store, draft) = h.create(f.head(), f.request(1, EventId::ZERO));
    f.policy(false);
    let first = recover(&Gate::new(&f, 0), &mut store, selected(&draft), signed).unwrap();
    f.policy(true);
    let prior = store.history_head().unwrap();
    store.advance_history(prior, f.head()).unwrap();
    let newer = ReservedDraft::new(
        store.head().unwrap(),
        f.head(),
        f.request(2, first.event.id()),
    )
    .unwrap();
    store.reserve(&newer).unwrap();
    let before = fs::read(h.0.join("outbox/STATE")).unwrap();
    let calls = Cell::new(0);
    let gate = Gate::new(&f, 1);
    let retry = recover(&gate, &mut store, selected(&draft), |r| {
        calls.set(calls.get() + 1);
        signed(r)
    })
    .unwrap();
    assert_eq!(calls.get(), 0);
    assert_eq!(gate.checks.get(), 0);
    assert!(retry.basis.is_none());
    assert_eq!(retry.event.encode(), first.event.encode());
    assert_eq!(
        store.load_pending().unwrap().unwrap().as_bytes(),
        newer.as_bytes()
    );
    assert_eq!(fs::read(h.0.join("outbox/STATE")).unwrap(), before);
    for sequence in ["0", "01", "+1", "-1", "18446744073709551616"] {
        assert!(Selection::parse(
            sequence,
            &crate::public_network::hex(first.event.id().as_bytes())
        )
        .is_err());
    }
    assert!(Selection::parse("1", &crate::public_network::hex(&[0; 32])).is_err());
}
