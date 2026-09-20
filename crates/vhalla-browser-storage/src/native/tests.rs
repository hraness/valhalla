use super::*;
use crate::history::{HistoryFrontier, HistoryScope};
use ed25519_dalek::SigningKey;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use vhalla_public_protocol::activity::{LocalReceipt, UnsignedActivityResponse};
use vhalla_room_activity::UnsignedEvent;

static SERIAL: AtomicU64 = AtomicU64::new(0);
struct Home(PathBuf);
impl Home {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "vhalla-native-author-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn path(&self) -> PathBuf {
        self.0.join("outbox")
    }
    fn create(&self, limits: Limits) -> NativeOutbox {
        NativeOutbox::create_new(self.path(), fresh(), policy(1), limits).unwrap()
    }
    fn open(&self) -> NativeOutbox {
        NativeOutbox::open(self.path(), fresh().scope(), policy(1).scope()).unwrap()
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn policy(height: u64) -> HistoryHead {
    HistoryHead::new(
        HistoryScope::new([7; 32], [10; 32]),
        HistoryFrontier {
            height,
            value: [1; 32],
            registry: [2; 32],
            social: [3; 32],
            control: [4; 32],
            time: height,
        },
        [5; 32],
    )
    .unwrap()
}
fn event(sequence: u64, previous: EventId, text: &str) -> VerifiedEvent {
    let key = SigningKey::from_bytes(&[3; 32]);
    let mut raw = b"VHRA\x01".to_vec();
    raw.extend_from_slice(&[7; 32]);
    raw.extend_from_slice(&77u128.to_be_bytes());
    raw.extend_from_slice(&[5; 32]);
    raw.extend_from_slice(&[8; 32]);
    raw.extend_from_slice(&[9; 32]);
    raw.extend_from_slice(&key.verifying_key().to_bytes());
    raw.extend_from_slice(&sequence.to_be_bytes());
    raw.extend_from_slice(previous.as_bytes());
    raw.extend_from_slice(&1234u64.to_be_bytes());
    raw.push(0);
    raw.extend_from_slice(&(text.len() as u16).to_be_bytes());
    raw.extend_from_slice(text.as_bytes());
    UnsignedEvent::decode(&raw)
        .unwrap()
        .sign_with_key(&key)
        .unwrap()
        .verify()
        .unwrap()
}
fn fresh() -> AuthorHead {
    let e = event(1, EventId::ZERO, "fixture");
    AuthorHead::fresh_scope_authorized(AuthorScope::new(e.claims().scope, e.claims().author))
}
fn draft(store: &NativeOutbox, text: &str) -> (ReservedDraft, VerifiedEvent) {
    let head = store.head().unwrap();
    let e = event(head.sequence() + 1, head.event_id(), text);
    (
        ReservedDraft::new(
            head,
            store.history_head().unwrap(),
            UnsignedEvent::new(e.claims().clone()).unwrap(),
        )
        .unwrap(),
        e,
    )
}
fn finalize(store: &mut NativeOutbox, text: &str) -> VerifiedEvent {
    let (d, e) = draft(store, text);
    store.reserve(&d).unwrap();
    store.finalize(&d, &e).unwrap();
    e
}
fn receipt(e: &VerifiedEvent, seed: u8, nonce: u8, cursor: u64) -> DeliveryRecord {
    let peer = SigningKey::from_bytes(&[seed; 32]);
    let request =
        ActivityRequest::post([nonce; 32], *e.claims().scope.room.as_bytes(), &e.encode()).unwrap();
    let body = LocalReceipt::new(e, cursor, [9; 32], 5, [6; 32], false)
        .unwrap()
        .encode();
    let proof = UnsignedActivityResponse::new(
        e.claims().scope.network,
        peer.verifying_key().to_bytes(),
        request,
        &body,
    )
    .unwrap()
    .sign_with_key(&peer)
    .unwrap();
    DeliveryRecord::new(
        fresh().scope(),
        peer.verifying_key().to_bytes(),
        &request,
        &proof,
        &body,
    )
    .unwrap()
}
fn deliver(
    store: &mut NativeOutbox,
    r: &DeliveryRecord,
    expected: Option<&DeliveryHead>,
) -> Result<DeliveryHead, PublishError> {
    store.record_delivery(
        r.head().peer(),
        expected,
        r.request(),
        r.proof(),
        &r.receipt().encode(),
    )
}

#[test]
fn native_explicit_creation_lock_and_scope_fail_closed() {
    let home = Home::new();
    assert!(NativeOutbox::open(home.path(), fresh().scope(), policy(1).scope()).is_err());
    assert!(!home.path().exists());
    let store = home.create(Limits::default());
    assert!(NativeOutbox::create_new(home.path(), fresh(), policy(1), Limits::default()).is_err());
    assert!(NativeOutbox::open(home.path(), fresh().scope(), policy(1).scope()).is_err());
    drop(store);
    assert!(NativeOutbox::open(
        home.path(),
        fresh().scope(),
        HistoryScope::new([7; 32], [99; 32])
    )
    .is_err());
    let store = home.open();
    assert_eq!(store.head().unwrap(), fresh());
    assert_eq!(
        fs::metadata(home.path()).unwrap().permissions().mode() & 0o777,
        0o700
    );
    for entry in fs::read_dir(home.path()).unwrap() {
        assert_eq!(
            entry.unwrap().metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn native_reservation_survives_signing_crash_and_never_accepts_replacement() {
    let home = Home::new();
    let mut store = home.create(Limits::default());
    let (d, signed) = draft(&store, "possibly signed offline");
    store.reserve(&d).unwrap();
    let generation = store.state.generation;
    store.reserve(&d).unwrap();
    assert_eq!(store.state.generation, generation);
    let (other, _) = draft(&store, "different bytes");
    assert_eq!(
        store.reserve(&other),
        Err(PublishError::Rejected(Error::Stale))
    );
    drop(store);
    let mut store = home.open();
    assert_eq!(store.load_pending().unwrap(), Some(d.clone()));
    store.finalize(&d, &signed).unwrap();
    store.finalize(&d, &signed).unwrap();
    assert_eq!(store.head().unwrap().sequence(), 1);
    assert!(store.load_pending().unwrap().is_none());
    assert_eq!(store.read_page(0, 16).unwrap().events, vec![signed]);
}

#[test]
fn native_reservation_faults_reconcile_exact_bytes_before_any_signing() {
    for point in [
        Point::IntentWritten,
        Point::IntentSynced,
        Point::StateSynced,
        Point::StateRenamed,
        Point::IntentRemoved,
    ] {
        let home = Home::new();
        let mut store = home.create(Limits::default());
        let (d, _) = draft(&store, "exact durable intent");
        store.disk.fault = Some(point);
        assert!(
            matches!(store.reserve(&d), Err(PublishError::ReopenRequired(_))),
            "{point:?}"
        );
        assert!(store.needs_reopen());
        assert_eq!(store.load_pending(), Err(Error::NeedsReopen));
        drop(store);
        let mut reopened = home.open();
        if point == Point::IntentRemoved {
            let syncs = reopened.disk.syncs.borrow();
            assert!(syncs.iter().any(|name| name == "STATE"));
            assert!(syncs.iter().any(|name| name == "directory"));
        }
        assert_eq!(
            reopened.load_pending().unwrap(),
            Some(d.clone()),
            "{point:?}"
        );
        reopened.reserve(&d).unwrap();
        assert!(!home.path().join("INTENT").exists());
    }
}

#[test]
fn native_finalize_faults_recover_without_sequence_reuse_and_resync_evidence() {
    for point in [
        Point::IntentWritten,
        Point::IntentSynced,
        Point::RecordSynced,
        Point::RecordRenamed,
        Point::StateSynced,
        Point::StateRenamed,
        Point::IntentRemoved,
    ] {
        let home = Home::new();
        let mut store = home.create(Limits::default());
        let (d, e) = draft(&store, "signed before local power loss");
        store.reserve(&d).unwrap();
        store.disk.fault = Some(point);
        assert!(
            matches!(store.finalize(&d, &e), Err(PublishError::ReopenRequired(_))),
            "{point:?}"
        );
        drop(store);
        let mut store = home.open();
        assert_eq!(store.head().unwrap().event_id(), e.id(), "{point:?}");
        assert!(store.load_pending().unwrap().is_none());
        assert_eq!(store.read_page(0, 16).unwrap().events, vec![e.clone()]);
        if point == Point::RecordRenamed || point == Point::StateRenamed {
            let syncs = store.disk.syncs.borrow();
            let intent = syncs.iter().position(|s| s == "INTENT").unwrap();
            let event = syncs.iter().position(|s| s == &event_name(1)).unwrap();
            assert!(intent < event, "protected intent must resync before replay");
        }
        store.finalize(&d, &e).unwrap();
        let next = finalize(&mut store, "healthy next event");
        assert_eq!(next.claims().sequence, 2);
        assert_eq!(next.claims().previous, e.id());
    }
}

#[test]
fn native_wrong_pin_never_mutates_recovery_evidence_and_corrupt_intent_is_retained() {
    let home = Home::new();
    let mut store = home.create(Limits::default());
    let (d, _) = draft(&store, "must preserve");
    store.disk.fault = Some(Point::IntentSynced);
    assert!(store.reserve(&d).is_err());
    drop(store);
    let before = fs::read(home.path().join("INTENT")).unwrap();
    let state = fs::read(home.path().join("STATE")).unwrap();
    assert!(NativeOutbox::open(
        home.path(),
        fresh().scope(),
        HistoryScope::new([7; 32], [4; 32])
    )
    .is_err());
    assert_eq!(fs::read(home.path().join("INTENT")).unwrap(), before);
    assert_eq!(fs::read(home.path().join("STATE")).unwrap(), state);
    fs::write(home.path().join("INTENT"), &before[..before.len() / 2]).unwrap();
    assert!(NativeOutbox::open(home.path(), fresh().scope(), policy(1).scope()).is_err());
    assert_eq!(
        fs::read(home.path().join("INTENT")).unwrap(),
        before[..before.len() / 2]
    );
}

#[test]
fn native_policy_cas_rebase_keeps_signed_intent_and_forbids_regression() {
    let home = Home::new();
    let mut store = home.create(Limits::default());
    let (d, e) = draft(&store, "old basis unchanged content");
    store.reserve(&d).unwrap();
    store.advance_history(policy(1), policy(2)).unwrap();
    assert_eq!(store.load_pending().unwrap(), Some(d.clone()));
    assert_eq!(
        store.finalize(&d, &e),
        Err(PublishError::Rejected(Error::Stale))
    );
    assert_eq!(
        store.advance_history(policy(1), policy(3)),
        Err(PublishError::Rejected(Error::Stale))
    );
    assert_eq!(
        store.advance_history(policy(2), policy(1)),
        Err(PublishError::Rejected(Error::Stale))
    );
    let rebased = ReservedDraft::new(d.base(), policy(2), d.request().clone()).unwrap();
    store.rebase_reservation(&d, &rebased).unwrap();
    store.rebase_reservation(&d, &rebased).unwrap();
    store.finalize(&rebased, &e).unwrap();
    drop(store);
    let store = home.open();
    assert_eq!(store.history_head().unwrap(), policy(2));
}

#[test]
fn native_capacity_refuses_before_signing_and_preserves_pending_delivery_budget() {
    let home = Home::new();
    let mut store = home.create(Limits {
        max_events: 1,
        ..Limits::default()
    });
    let first = finalize(&mut store, "last budgeted event");
    let (d, _) = draft(&store, "over capacity");
    assert_eq!(
        store.reserve(&d),
        Err(PublishError::Rejected(Error::Bounds))
    );
    assert!(store.load_pending().unwrap().is_none());
    drop(store);
    assert_eq!(home.open().head().unwrap().event_id(), first.id());
    let home = Home::new();
    let first = event(1, EventId::ZERO, "byte budget");
    let r = receipt(&first, 8, 1, 1);
    let capacity = first.encode().len() as u64 + MAX_EVENT_BYTES as u64;
    let mut store = home.create(Limits {
        max_bytes: capacity,
        ..Limits::default()
    });
    let first = finalize(&mut store, "byte budget");
    let (d, e) = draft(&store, "reserved space cannot be spent on receipts");
    store.reserve(&d).unwrap();
    assert_eq!(
        deliver(&mut store, &r, None),
        Err(PublishError::Rejected(Error::Bounds))
    );
    assert_eq!(store.load_pending().unwrap(), Some(d.clone()));
    store.finalize(&d, &e).unwrap();
    assert_eq!(store.read_page(0, 16).unwrap().events[0], first);
}

#[test]
fn native_delivery_cas_retries_preserve_original_evidence_and_recovery() {
    for point in [
        Point::IntentSynced,
        Point::RecordSynced,
        Point::RecordRenamed,
        Point::StateRenamed,
        Point::IntentRemoved,
    ] {
        let home = Home::new();
        let mut store = home.create(Limits::default());
        let e = finalize(&mut store, "peer local ack");
        let r = receipt(&e, 8, 1, 10);
        store.disk.fault = Some(point);
        assert!(deliver(&mut store, &r, None).is_err());
        drop(store);
        let mut store = home.open();
        let head = store.load_delivery(r.head().peer()).unwrap().unwrap();
        assert_eq!(head, r.head());
        let retry = receipt(&e, 8, 2, 1); // reset cursor cannot replace original
        assert_eq!(deliver(&mut store, &retry, Some(&head)).unwrap(), head);
        assert_eq!(
            store
                .load_delivery_receipt(head.peer(), 1)
                .unwrap()
                .unwrap(),
            r
        );
        assert_eq!(
            deliver(&mut store, &retry, None),
            Err(PublishError::Rejected(Error::Stale))
        );
        let next = finalize(&mut store, "next");
        let next_r = receipt(&next, 8, 3, 11);
        deliver(&mut store, &next_r, Some(&head)).unwrap();
        assert_eq!(
            store
                .load_delivery_receipt(head.peer(), 1)
                .unwrap()
                .unwrap(),
            r
        );
    }
}

#[test]
fn native_bounded_indexed_pages_continue_after_restart_and_fail_on_gap_or_tip_corruption() {
    let home = Home::new();
    let mut store = home.create(Limits::default());
    for _ in 0..35 {
        finalize(&mut store, "retained");
    }
    drop(store);
    let store = home.open();
    assert!(store.read_page(0, 17).is_err());
    assert!(store.read_page(u64::MAX, 1).is_err());
    let mut after = 0;
    for expected in [16, 16, 3] {
        let page = store.read_page(after, 16).unwrap();
        assert_eq!(page.events.len(), expected);
        after = page.events.last().unwrap().claims().sequence;
    }
    assert!(store.read_page(35, 1).unwrap().events.is_empty());
    fs::remove_file(home.path().join(event_name(17))).unwrap();
    assert!(store.read_page(16, 16).is_err());
    drop(store);
    fs::write(home.path().join(event_name(35)), b"corrupt tip").unwrap();
    assert!(NativeOutbox::open(home.path(), fresh().scope(), policy(1).scope()).is_err());
}

#[test]
fn native_existing_conflicting_immutable_file_and_symlink_are_never_overwritten() {
    let home = Home::new();
    let mut store = home.create(Limits::default());
    let (d, e) = draft(&store, "correct");
    store.reserve(&d).unwrap();
    store
        .disk
        .create_file(
            &event_name(1),
            &event(1, EventId::ZERO, "conflict").encode(),
        )
        .unwrap();
    let prior = fs::read(home.path().join(event_name(1))).unwrap();
    assert!(matches!(
        store.finalize(&d, &e),
        Err(PublishError::ReopenRequired(Error::Corrupt))
    ));
    drop(store);
    assert!(NativeOutbox::open(home.path(), fresh().scope(), policy(1).scope()).is_err());
    assert_eq!(fs::read(home.path().join(event_name(1))).unwrap(), prior);
    let home = Home::new();
    let store = home.create(Limits::default());
    drop(store);
    let saved = home.path().join("saved-state");
    fs::rename(home.path().join("STATE"), &saved).unwrap();
    std::os::unix::fs::symlink(&saved, home.path().join("STATE")).unwrap();
    assert!(NativeOutbox::open(home.path(), fresh().scope(), policy(1).scope()).is_err());
}
