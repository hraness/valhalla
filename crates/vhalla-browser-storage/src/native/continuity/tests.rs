use super::*;
use crate::outbox::continuity as model;
use crate::outbox::continuity::tests::Fixture;
use crate::{
    history::{HistoryFrontier, HistoryHead},
    outbox::{AuthorHead, ReservedDraft},
};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use vhalla_public_protocol::continuity as wire;
use vhalla_room_activity::UnsignedEvent;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Home {
    path: PathBuf,
    f: Fixture,
    source: NativeOutbox,
}
impl Home {
    fn new(count: usize) -> Self {
        let path = std::env::temp_dir().join(format!(
            "vhalla-continuity-client-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let f = Fixture::new(count);
        let policy = HistoryHead::new(
            f.scope.history(),
            HistoryFrontier {
                height: 1,
                value: [1; 32],
                registry: [2; 32],
                social: [3; 32],
                control: [4; 32],
                time: 1234,
            },
            [5; 32],
        )
        .unwrap();
        let mut source = NativeOutbox::create_new(
            path.join("author"),
            AuthorHead::fresh_scope_authorized(f.scope.author()),
            policy,
            super::super::Limits::default(),
        )
        .unwrap();
        for e in &f.events {
            let draft = ReservedDraft::new(
                source.head().unwrap(),
                policy,
                UnsignedEvent::new(e.claims().clone()).unwrap(),
            )
            .unwrap();
            source.reserve(&draft).unwrap();
            source.finalize(&draft, e).unwrap();
        }
        Self { path, f, source }
    }
    fn receipt(&self) -> PathBuf {
        self.path.join("receipts")
    }
    fn create(&self) -> NativeContinuity {
        NativeContinuity::create_new(
            &self.receipt(),
            self.f.scope.clone(),
            self.f.limits,
            &self.source,
        )
        .unwrap()
    }
    fn open(&self) -> Result<NativeContinuity, Error> {
        NativeContinuity::open(
            &self.receipt(),
            self.f.scope.clone(),
            self.f.limits,
            &self.source,
        )
    }
    fn selected(&self) -> NativeContinuity {
        let mut store = self.create();
        let change = store
            .snapshot(&self.source)
            .unwrap()
            .prepare_job(model::ContinuityJob::new([1; 16], self.f.events.last().unwrap()).unwrap())
            .unwrap();
        store.publish(&self.source, change).unwrap();
        store
    }
    fn response(&self, store: &mut NativeContinuity) -> Publication {
        let state = store.snapshot(&self.source).unwrap();
        let request = self.f.status(&state, 1);
        let reserved = store
            .publish(&self.source, state.prepare_attempt(request, &[]).unwrap())
            .unwrap();
        let (proof, body) = self.f.proof(
            request,
            &wire::Reply::Status(wire::Status {
                observed: self.f.context(1).floor,
                published: wire::Position::of(self.f.events.last().unwrap()),
                stage: None,
            }),
        );
        reserved.prepare_response(&proof, &body).unwrap()
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
fn write(path: PathBuf, raw: &[u8]) {
    fs::write(&path, raw).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
#[test]
fn continuity_native_exact_attempt_survives_reopen_and_v1_bytes_unchanged() {
    let h = Home::new(1);
    let original = fs::read(h.path.join("author/STATE")).unwrap();
    let mut store = h.selected();
    let change = h.response(&mut store);
    let next = store.publish(&h.source, change).unwrap();
    assert_eq!(next.record_count(), 1);
    assert_eq!(next.retention().position(), wire::Position::EMPTY);
    drop(store);
    let mut store = h.open().unwrap();
    assert_eq!(store.snapshot(&h.source).unwrap(), next);
    assert!(store.read_record(&h.source, 1).unwrap().is_some());
    assert!(store.read_record(&h.source, 2).unwrap().is_none());
    assert_eq!(fs::read(h.path.join("author/STATE")).unwrap(), original);
}
#[test]
fn continuity_native_all_publication_faults_reconcile_without_false_ack() {
    for fault in [
        disk::Point::IntentCreated,
        disk::Point::IntentPartial,
        disk::Point::IntentWritten,
        disk::Point::IntentStageSynced,
        disk::Point::IntentRenamed,
        disk::Point::IntentSynced,
        disk::Point::RecordSynced,
        disk::Point::RecordRenamed,
        disk::Point::StateSynced,
        disk::Point::StateRenamed,
        disk::Point::IntentRemoved,
    ] {
        let h = Home::new(1);
        let mut store = h.selected();
        let change = h.response(&mut store);
        let expected = change.after.clone();
        store.disk.fault = Some(fault);
        assert!(
            matches!(
                store.publish(&h.source, change),
                Err(PublishError::ReopenRequired(_))
            ),
            "{fault:?}"
        );
        assert!(store.needs_reopen());
        assert_eq!(store.snapshot(&h.source), Err(Error::NeedsReopen));
        drop(store);
        let mut recovered = h.open().unwrap_or_else(|e| panic!("{fault:?}: {e:?}"));
        let state = recovered.snapshot(&h.source).unwrap();
        if matches!(
            fault,
            disk::Point::IntentCreated | disk::Point::IntentPartial
        ) {
            assert_eq!(state.record_count(), 0);
            assert!(state.attempt().is_some());
        } else {
            assert_eq!(state, expected);
            assert!(recovered.read_record(&h.source, 1).unwrap().is_some());
        }
        assert_eq!(state.retention().position(), wire::Position::EMPTY);
        assert!(!h.receipt().join("INTENT").exists());
        assert!(!h.receipt().join("INTENT.tmp").exists());
    }
}
#[test]
fn continuity_native_wrong_scope_limits_and_authoritative_partial_preserve_evidence() {
    let h = Home::new(1);
    let mut store = h.selected();
    let change = h.response(&mut store);
    let raw = change.encode();
    drop(store);
    write(h.receipt().join("INTENT.tmp"), &raw);
    let mut wrong = h.f.limits;
    wrong.max_records += 1;
    assert!(NativeContinuity::open(&h.receipt(), h.f.scope.clone(), wrong, &h.source).is_err());
    assert_eq!(fs::read(h.receipt().join("INTENT.tmp")).unwrap(), raw);
    let wrong_scope = model::SessionScope::new(
        h.f.scope.author(),
        h.f.scope.history(),
        [22; 32],
        h.f.scope.endpoint().clone(),
    )
    .unwrap();
    assert!(NativeContinuity::open(&h.receipt(), wrong_scope, h.f.limits, &h.source).is_err());
    assert_eq!(fs::read(h.receipt().join("INTENT.tmp")).unwrap(), raw);
    fs::remove_file(h.receipt().join("INTENT.tmp")).unwrap();
    write(h.receipt().join("INTENT"), &[]);
    assert!(h.open().is_err());
    assert!(fs::read(h.receipt().join("INTENT")).unwrap().is_empty());
}
#[test]
fn continuity_native_incomplete_stage_requires_exact_before_and_no_successor_effects() {
    let h = Home::new(1);
    let mut store = h.selected();
    let change = h.response(&mut store);
    let raw = change.encode();
    let half = raw[..raw.len() / 2].to_vec();
    drop(store);
    write(h.receipt().join("INTENT.tmp"), &half);
    write(h.receipt().join("RECORD.tmp"), b"unexplained");
    assert!(h.open().is_err());
    assert_eq!(fs::read(h.receipt().join("INTENT.tmp")).unwrap(), half);
    fs::remove_file(h.receipt().join("RECORD.tmp")).unwrap();
    let mut mismatch = half.clone();
    mismatch[20] ^= 1;
    write(h.receipt().join("INTENT.tmp"), &mismatch);
    assert!(h.open().is_err());
    assert_eq!(fs::read(h.receipt().join("INTENT.tmp")).unwrap(), mismatch);
    write(h.receipt().join("INTENT.tmp"), &half);
    write(h.receipt().join(name(1)), b"future effect");
    assert!(h.open().is_err());
    assert_eq!(fs::read(h.receipt().join("INTENT.tmp")).unwrap(), half);
}
#[test]
fn continuity_native_missing_receipt_source_or_session_never_resets() {
    let h = Home::new(1);
    assert!(h.open().is_err());
    let mut store = h.selected();
    let change = h.response(&mut store);
    store.publish(&h.source, change).unwrap();
    drop(store);
    let record = h.receipt().join(name(1));
    let saved = fs::read(&record).unwrap();
    fs::remove_file(&record).unwrap();
    assert!(h.open().is_err());
    write(record, &saved);
    let source = h.path.join("author/event-0000000000000001");
    // Resolve the actual maintained direct-index filename without scanning history.
    let source = if source.exists() {
        source
    } else {
        h.path.join("author").join(super::super::event_name(1))
    };
    let raw = fs::read(&source).unwrap();
    write(source.clone(), b"corrupt signed source");
    assert!(h.open().is_err());
    write(source, &raw);
    let mut reopened = h.open().unwrap();
    assert_eq!(reopened.snapshot(&h.source).unwrap().record_count(), 1);
}

#[test]
fn continuity_native_paged_evidence_and_reconciled_old_terminal_survive_restart() {
    let h = Home::new(33);
    let mut store = h.selected();
    for (nonce, first, last) in [(1, 0, 32), (2, 32, 33)] {
        let state = store.snapshot(&h.source).unwrap();
        let (reserved, change) = h.f.evidence(&state, nonce, first, last, 33, 7);
        let attempt = reserved.attempt().unwrap();
        store
            .publish(
                &h.source,
                state
                    .prepare_attempt(attempt.request(), attempt.body())
                    .unwrap(),
            )
            .unwrap();
        store.publish(&h.source, change).unwrap();
        drop(store);
        store = h.open().unwrap();
        assert!(!store.snapshot(&h.source).unwrap().complete());
    }
    let state = store.snapshot(&h.source).unwrap();
    let ticket = wire::StageRef::new(
        [4; 32],
        wire::Position::EMPTY,
        wire::Position::of(&h.f.events[31]),
        1,
        2000,
    )
    .unwrap();
    let body = wire::Body::commit(vec![], h.f.events[32].clone()).unwrap();
    let request = wire::Request::commit(
        h.f.context(3),
        h.f.scope.author().author(),
        wire::Position::EMPTY,
        Some(ticket),
        &body,
    )
    .unwrap();
    let state = store
        .publish(
            &h.source,
            state.prepare_attempt(request, &body.encode()).unwrap(),
        )
        .unwrap();
    let (proof, raw) = h.f.proof(
        request,
        &wire::Reply::Committed(Box::new(wire::TerminalReceipt {
            observed: h.f.context(3).floor,
            event: h.f.events[32].clone(),
            cursor: 7,
            registry: [9; 32],
            reconciled: true,
        })),
    );
    let done = store
        .publish(&h.source, state.prepare_response(&proof, &raw).unwrap())
        .unwrap();
    assert!(done.complete());
    drop(store);
    let mut reopened = h.open().unwrap();
    assert!(reopened.snapshot(&h.source).unwrap().complete());
    assert_eq!(reopened.snapshot(&h.source).unwrap().record_count(), 3);
}
