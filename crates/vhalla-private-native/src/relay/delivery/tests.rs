use super::*;
use std::{
    collections::VecDeque,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use vhalla_private_kernel::{
    protocol::{AnchorId, Key, PrivateRoomScope, RoomId},
    OutboxKind,
};
fn context() -> Context {
    Context {
        scope: PrivateRoomScope {
            room: RoomId::from_bytes([1; 32]).unwrap(),
            anchor: AnchorId::from_bytes([2; 32]).unwrap(),
        },
        account: Key::from_bytes(
            ed25519_dalek::SigningKey::from_bytes(&[3; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap(),
        device: Key::from_bytes(
            ed25519_dalek::SigningKey::from_bytes(&[4; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap(),
    }
}
fn ns() -> RelayNamespace {
    RelayNamespace::from_bytes([5; 32]).unwrap()
}
fn endpoint() -> EndpointId {
    EndpointId::from_bytes([6; 32]).unwrap()
}
fn item(n: u8) -> RelayItem {
    RelayItem::new(
        ns(),
        n as u64,
        OperationId::from_bytes([n; 16]).unwrap(),
        OutboxKind::Application,
        b"exact retained ciphertext",
    )
    .unwrap()
}
fn limits() -> Limits {
    Limits {
        max_jobs: 4,
        max_bytes: 1024 * 1024,
    }
}
fn policy() -> RetryPolicy {
    RetryPolicy {
        max_attempts: 3,
        initial_backoff_secs: 2,
        max_backoff_secs: 5,
    }
}
fn budget() -> TickBudget {
    TickBudget {
        max_jobs: 4,
        max_bytes: 1024 * 1024,
        deadline: Instant::now() + Duration::from_secs(3),
    }
}
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        Self(std::env::temp_dir().join(format!(
            "valhalla-delivery-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }
    fn create(&self) -> DeliveryStore {
        DeliveryStore::create_new(&self.0, context(), ns(), endpoint(), limits(), policy()).unwrap()
    }
    fn open(&self) -> DeliveryStore {
        DeliveryStore::open(&self.0, context(), ns(), endpoint()).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if self.0.exists() {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
}
struct Fake {
    path: PathBuf,
    endpoint: EndpointId,
    namespace: RelayNamespace,
    outcomes: VecDeque<std::result::Result<RelayReceipt, NetError>>,
    calls: Vec<Vec<u8>>,
    panic: bool,
}
impl Fake {
    fn new(f: &Fixture, outcomes: Vec<std::result::Result<RelayReceipt, NetError>>) -> Self {
        Self {
            path: f.0.clone(),
            endpoint: endpoint(),
            namespace: ns(),
            outcomes: outcomes.into(),
            calls: Vec::new(),
            panic: false,
        }
    }
}
impl Transport for Fake {
    fn endpoint_id(&self) -> EndpointId {
        self.endpoint
    }
    fn namespace(&self) -> RelayNamespace {
        self.namespace
    }
    fn submit_until(
        &mut self,
        item: &RelayItem,
        _deadline: Instant,
    ) -> std::result::Result<RelayReceipt, NetError> {
        // A separate reader sees committed intent before the first transport effect.
        let conn = Connection::open_with_flags(
            self.path.join("delivery.db"),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let (state, attempts, uncertain, bytes): (i64, i64, i64, Vec<u8>) = conn
            .query_row(
                "SELECT state,attempts,uncertain,item FROM jobs WHERE id=?1",
                params![item.digest().as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(state, 1);
        assert!(attempts > 0);
        assert_eq!(uncertain, 1);
        assert_eq!(bytes, item.encode().unwrap());
        self.calls.push(bytes);
        assert!(!self.panic, "injected process loss after durable intent");
        self.outcomes
            .pop_front()
            .expect("unexpected additional transport call")
    }
}
fn receipt(n: u8, duplicate: bool) -> std::result::Result<RelayReceipt, NetError> {
    Ok(RelayReceipt {
        position: n as u64,
        digest: item(n).digest(),
        duplicate,
    })
}

#[test]
fn generation_carries_spend_and_blocks_replaying_predecessor_jobs() {
    let predecessor = Fixture::new();
    let mut old = predecessor.create();
    old.enqueue(&item(1), 100).unwrap();
    assert_eq!(old.drained_snapshot(), Err(Error::Conflict));
    let mut transport = Fake::new(&predecessor, vec![receipt(1, false)]);
    old.tick(&mut transport, 100, budget()).unwrap();
    old.save_driver_checkpoint(1, 7, 101).unwrap();
    let prior = old.drained_snapshot().unwrap();
    assert_eq!(prior.retained_jobs, 1);
    assert_eq!(prior.charged_attempts, 1);
    assert_eq!(
        prior.canonical_bytes,
        item(1).encode().unwrap().len() as u64
    );
    let successor = Fixture::new();
    let mut next = successor.create();
    next.initialize_successor(1, prior, [9; 32], 102).unwrap();
    assert_eq!(next.driver_checkpoint().unwrap(), (1, 0));
    assert_eq!(next.capacity().unwrap().2, prior.canonical_bytes as usize);
    assert_eq!(next.enqueue(&item(1), 102), Err(Error::Conflict));
    next.initialize_successor(1, prior, [9; 32], 102).unwrap();
    assert_eq!(
        next.initialize_successor(1, prior, [10; 32], 102),
        Err(Error::Conflict)
    );
    drop(next);
    let mut next = successor.open();
    let second = next.drained_snapshot().unwrap();
    assert_eq!(second.canonical_bytes, prior.canonical_bytes);
    assert_eq!(second.retained_jobs, prior.retained_jobs);
    assert_eq!(second.charged_attempts, prior.charged_attempts);
    assert_eq!(second.applied, 0);
    next.enqueue(&item(2), 103).unwrap();
    let mut transport = Fake::new(&successor, vec![receipt(2, false)]);
    next.tick(&mut transport, 103, budget()).unwrap();
    next.save_driver_checkpoint(2, 3, 103).unwrap();
    let second = next.drained_snapshot().unwrap();
    assert_eq!(second.retained_jobs, 2);
    assert_eq!(second.charged_attempts, 2);
    let third = Fixture::new();
    let mut third = third.create();
    third
        .initialize_successor(2, second, [11; 32], 104)
        .unwrap();
    assert_eq!(
        third.drained_snapshot().unwrap().canonical_bytes,
        second.canonical_bytes
    );
}
#[test]
fn exact_job_and_attempt_are_durable_before_transport_and_success_survives_reopen() {
    let f = Fixture::new();
    let mut store = f.create();
    let queued = store.enqueue(&item(1), 100).unwrap();
    assert_eq!(queued.state, JobState::Pending);
    let mut transport = Fake::new(&f, vec![receipt(1, false)]);
    let report = store.tick(&mut transport, 100, budget()).unwrap();
    assert_eq!(report.jobs[0].state, JobState::Retained);
    assert_eq!(report.jobs[0].position, Some(1));
    drop(store);
    let mut store = f.open();
    assert_eq!(store.enqueue(&item(1), 101).unwrap(), report.jobs[0]);
    assert!(store
        .tick(&mut transport, 101, budget())
        .unwrap()
        .jobs
        .is_empty());
    assert_eq!(transport.calls.len(), 1);
}
#[test]
fn uncertain_retry_waits_for_backoff_reopens_exact_bytes_and_rejects_clock_rollback() {
    let f = Fixture::new();
    let mut store = f.create();
    store.enqueue(&item(1), 100).unwrap();
    let mut transport = Fake::new(&f, vec![Err(NetError::Timeout), receipt(1, true)]);
    let first = store.tick(&mut transport, 100, budget()).unwrap();
    assert_eq!(first.jobs[0].state, JobState::Uncertain);
    assert_eq!(first.jobs[0].next_due, 102);
    drop(store);
    let mut store = f.open();
    // A bounded step back holds the committed clock; nothing is due yet.
    assert!(store
        .tick(&mut transport, 99, budget())
        .unwrap()
        .jobs
        .is_empty());
    assert!(store
        .tick(&mut transport, 101, budget())
        .unwrap()
        .jobs
        .is_empty());
    let second = store.tick(&mut transport, 102, budget()).unwrap();
    assert_eq!(second.jobs[0].state, JobState::Retained);
    // The timeout was an outage, so only the successful attempt was charged.
    assert_eq!(second.jobs[0].attempts, 1);
    assert_eq!(store.evidence(second.jobs[0].id).unwrap().outages, 1);
    assert_eq!(transport.calls[0], transport.calls[1]);
}
#[test]
fn clock_step_back_holds_committed_clock_and_refuses_beyond_bound() {
    let f = Fixture::new();
    let mut store = f.create();
    store.enqueue(&item(1), 10_000).unwrap();
    let mut transport = Fake::new(&f, vec![Err(NetError::Connect), receipt(1, false)]);
    // Held clock: the attempt is still due because next_due was set at 10_000.
    let held = store.tick(&mut transport, 9_999, budget()).unwrap();
    assert_eq!(held.jobs[0].state, JobState::Uncertain);
    assert_eq!(held.jobs[0].next_due, 10_002);
    assert_eq!(
        store
            .tick(
                &mut transport,
                10_000 - MAX_CLOCK_REGRESSION_SECS - 1,
                budget()
            )
            .err(),
        Some(Error::Clock)
    );
    assert!(store
        .tick(&mut transport, 10_000 - MAX_CLOCK_REGRESSION_SECS, budget())
        .unwrap()
        .jobs
        .is_empty());
    drop(store);
    let mut store = f.open();
    assert_eq!(
        store.tick(&mut transport, 10_002, budget()).unwrap().jobs[0].state,
        JobState::Retained
    );
}
#[test]
fn denied_credential_preserves_exact_retry_and_does_not_spend_other_jobs() {
    let f = Fixture::new();
    let mut store = f.create();
    store.enqueue(&item(1), 100).unwrap();
    store.enqueue(&item(2), 100).unwrap();
    let mut denied = Fake::new(&f, vec![Err(NetError::Denied)]);
    let first = store.tick(&mut denied, 100, budget()).unwrap();
    assert_eq!(first.jobs.len(), 1);
    let status = &first.jobs[0];
    assert_eq!(status.state, JobState::Pending);
    assert_eq!(status.attempts, 1);
    assert_eq!(status.next_due, 102);
    assert_eq!(status.last_error, Some(NetError::Denied));
    assert!(!status.uncertain);
    assert_eq!(store.statuses(1, 1).unwrap()[0].attempts, 0);
    drop(store);
    let mut store = f.open();
    let mut replacement = Fake::new(&f, vec![receipt(2, false), receipt(1, false)]);
    let before_due = store.tick(&mut replacement, 101, budget()).unwrap();
    assert_eq!(before_due.jobs.len(), 1);
    assert_eq!(before_due.jobs[0].sequence, 2);
    assert_eq!(store.statuses(0, 1).unwrap()[0], *status);
    let retained = store.tick(&mut replacement, 102, budget()).unwrap();
    assert_eq!(retained.jobs[0].state, JobState::Retained);
    assert_eq!(retained.jobs[0].attempts, 2);
    assert_eq!(denied.calls[0], replacement.calls[1]);
}

#[test]
fn denial_preserves_prior_uncertainty_and_original_failure_budget_across_reopen() {
    let f = Fixture::new();
    let mut store = f.create();
    store.enqueue(&item(1), 100).unwrap();
    let mut transport = Fake::new(
        &f,
        vec![
            Err(NetError::Timeout),
            Err(NetError::Denied),
            Err(NetError::Denied),
            Err(NetError::Denied),
        ],
    );
    store.tick(&mut transport, 100, budget()).unwrap();
    drop(store);
    let mut store = f.open();
    let denied = store.tick(&mut transport, 102, budget()).unwrap();
    assert_eq!(denied.jobs[0].state, JobState::Uncertain);
    assert!(denied.jobs[0].uncertain);
    // The outage was not charged; the denial is the first spent attempt.
    assert_eq!(denied.jobs[0].attempts, 1);
    assert_eq!(denied.jobs[0].next_due, 106);
    drop(store);
    let mut store = f.open();
    let again = store.tick(&mut transport, 106, budget()).unwrap();
    assert_eq!(again.jobs[0].state, JobState::Uncertain);
    assert_eq!(again.jobs[0].attempts, 2);
    assert_eq!(again.jobs[0].next_due, 111);
    let stopped = store.tick(&mut transport, 111, budget()).unwrap();
    assert_eq!(stopped.jobs[0].state, JobState::Stopped);
    assert!(stopped.jobs[0].uncertain);
    assert_eq!(stopped.jobs[0].attempts, 3);
    assert_eq!(stopped.jobs[0].next_due, 116);
    drop(store);
    let mut store = f.open();
    assert!(store
        .tick(&mut transport, 200, budget())
        .unwrap()
        .jobs
        .is_empty());
    assert_eq!(transport.calls.len(), 4);
    assert!(transport
        .calls
        .iter()
        .all(|raw| *raw == item(1).encode().unwrap()));
}

#[test]
fn finite_failure_budget_preserves_uncertainty_and_known_capacity_refusal() {
    let f = Fixture::new();
    let mut store = f.create();
    store.enqueue(&item(1), 100).unwrap();
    store.enqueue(&item(2), 100).unwrap();
    let mut transport = Fake::new(
        &f,
        vec![
            Err(NetError::Capacity),
            Err(NetError::Timeout),
            Err(NetError::Capacity),
            Err(NetError::Timeout),
            Err(NetError::Capacity),
            Err(NetError::Timeout),
            receipt(2, true),
        ],
    );
    let first = store.tick(&mut transport, 100, budget()).unwrap();
    assert_eq!(first.jobs[0].state, JobState::Pending);
    assert!(!first.jobs[0].uncertain);
    assert!(first.jobs[1].uncertain);
    store.tick(&mut transport, 102, budget()).unwrap();
    let last = store.tick(&mut transport, 106, budget()).unwrap();
    // Definitive refusals spend the budget; outages never do.
    assert_eq!(last.jobs[0].state, JobState::Stopped);
    assert_eq!(last.jobs[0].attempts, 3);
    assert!(!last.jobs[0].uncertain);
    assert_eq!(last.jobs[0].next_due, 111);
    assert_eq!(last.jobs[1].state, JobState::Uncertain);
    assert_eq!(last.jobs[1].attempts, 0);
    assert!(last.jobs[1].uncertain);
    assert_eq!(last.jobs[1].next_due, 111);
    assert_eq!(store.evidence(last.jobs[1].id).unwrap().outages, 3);
    let recovered = store.tick(&mut transport, 200, budget()).unwrap();
    assert_eq!(recovered.jobs.len(), 1);
    assert_eq!(recovered.jobs[0].sequence, 2);
    assert_eq!(recovered.jobs[0].state, JobState::Retained);
    assert_eq!(recovered.jobs[0].attempts, 1);
    assert_eq!(transport.calls.len(), 7);
    drop(store);
    assert_eq!(f.open().evidence(last.jobs[1].id).unwrap().outages, 3);
}
#[test]
fn long_outage_never_stops_a_job_and_backoff_saturates_at_the_ceiling() {
    let f = Fixture::new();
    let mut store = f.create();
    store.enqueue(&item(1), 100).unwrap();
    let mut outcomes: Vec<_> = [NetError::Connect, NetError::Unavailable, NetError::Timeout]
        .iter()
        .cycle()
        .take(12)
        .map(|e| Err(*e))
        .collect();
    outcomes.push(receipt(1, false));
    let mut transport = Fake::new(&f, outcomes);
    let mut now = 100;
    for round in 0..12 {
        let report = store.tick(&mut transport, now, budget()).unwrap();
        assert_eq!(report.jobs.len(), 1, "round {round}");
        assert_eq!(report.jobs[0].state, JobState::Uncertain);
        assert_eq!(report.jobs[0].attempts, 0);
        assert!(report.jobs[0].next_due - now <= policy().max_backoff_secs);
        now = report.jobs[0].next_due;
        // Ticks before the due time perform no transport call.
        assert!(store
            .tick(&mut transport, now - 1, budget())
            .unwrap()
            .jobs
            .is_empty());
    }
    assert_eq!(store.evidence(item(1).digest()).unwrap().outages, 12);
    let recovered = store.tick(&mut transport, now, budget()).unwrap();
    assert_eq!(recovered.jobs[0].state, JobState::Retained);
    assert_eq!(recovered.jobs[0].attempts, 1);
    assert_eq!(transport.calls.len(), 13);
}
#[test]
fn stopped_jobs_resume_in_place_with_spent_attempts_retained_as_evidence() {
    let f = Fixture::new();
    let mut store = f.create();
    store.enqueue(&item(1), 100).unwrap();
    store.enqueue(&item(2), 100).unwrap();
    let mut transport = Fake::new(
        &f,
        vec![
            Err(NetError::Capacity),
            receipt(2, false),
            Err(NetError::Capacity),
            Err(NetError::Capacity),
        ],
    );
    store.tick(&mut transport, 100, budget()).unwrap();
    store.tick(&mut transport, 102, budget()).unwrap();
    let stopped = store.tick(&mut transport, 106, budget()).unwrap();
    assert_eq!(stopped.jobs[0].state, JobState::Stopped);
    assert_eq!(store.resume(None, 106).unwrap().len(), 1);
    let resumed = store.statuses(0, 4).unwrap();
    assert_eq!(resumed[0].state, JobState::Pending);
    assert_eq!(resumed[0].attempts, 0);
    assert_eq!(resumed[0].next_due, 106);
    assert_eq!(resumed[0].last_error, Some(NetError::Capacity));
    assert_eq!(resumed[1].state, JobState::Retained);
    let evidence = store.evidence(resumed[0].id).unwrap();
    assert_eq!(
        (
            evidence.resumes,
            evidence.spent_attempts,
            evidence.resumed_at
        ),
        (1, 3, 106)
    );
    // Nothing else is stopped; an unknown id refuses without effects.
    assert!(store.resume(None, 106).unwrap().is_empty());
    assert_eq!(store.resume(Some([9; 32]), 106).err(), Some(Error::Bounds));
    drop(store);
    let mut store = f.open();
    assert_eq!(store.statuses(0, 1).unwrap()[0].attempts, 0);
    let mut recovery = Fake::new(&f, vec![receipt(1, false)]);
    let retained = store.tick(&mut recovery, 107, budget()).unwrap();
    assert_eq!(retained.jobs[0].state, JobState::Retained);
    assert_eq!(retained.jobs[0].attempts, 1);
    assert_eq!(recovery.calls[0], transport.calls[0]);
}
#[test]
fn retained_jobs_leave_the_live_bound_and_idle_ticks_write_nothing() {
    let f = Fixture::new();
    let mut store = f.create();
    let mut transport = Fake::new(&f, (1..=4).map(|n| receipt(n, false)).collect());
    for n in 1..=4 {
        store.enqueue(&item(n), 100).unwrap();
    }
    assert_eq!(store.enqueue(&item(5), 100).err(), Some(Error::Capacity));
    assert_eq!(
        store.capacity().unwrap(),
        (4, 4, 4 * item(1).encode().unwrap().len(), 1024 * 1024)
    );
    store.tick(&mut transport, 100, budget()).unwrap();
    assert_eq!(store.capacity().unwrap().0, 0);
    for n in 5..=8 {
        store.enqueue(&item(n), 101).unwrap();
    }
    assert_eq!(store.enqueue(&item(9), 101).err(), Some(Error::Capacity));
    let committed = || -> i64 {
        Connection::open_with_flags(f.0.join("delivery.db"), OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap()
            .query_row("SELECT clock FROM meta WHERE id=1", [], |r| r.get(0))
            .unwrap()
    };
    assert_eq!(committed(), 101);
    // Push the live jobs past the window so sixty ticks have nothing due.
    store
        .conn
        .execute("UPDATE jobs SET next_due=500 WHERE state=0", [])
        .unwrap();
    let mut idle = Fake::new(&f, vec![]);
    for now in 200..260 {
        assert!(store
            .tick(&mut idle, now, budget())
            .unwrap()
            .jobs
            .is_empty());
    }
    assert_eq!(committed(), 101, "idle ticks must not commit the clock");
    drop(store);
    assert_eq!(f.open().statuses(0, 8).unwrap().len(), 8);
}
#[test]
fn binding_conflict_limits_and_expired_budget_refuse_before_dial() {
    let f = Fixture::new();
    let mut store = f.create();
    store.enqueue(&item(1), 100).unwrap();
    let conflict = RelayItem::new(
        ns(),
        1,
        item(1).operation(),
        OutboxKind::Application,
        b"new ciphertext",
    )
    .unwrap();
    assert_eq!(store.enqueue(&conflict, 100).err(), Some(Error::Conflict));
    let mut transport = Fake::new(&f, vec![]);
    transport.endpoint = EndpointId::from_bytes([7; 32]).unwrap();
    assert_eq!(
        store.tick(&mut transport, 100, budget()).err(),
        Some(Error::Scope)
    );
    transport.endpoint = endpoint();
    let mut expired = budget();
    expired.deadline = Instant::now();
    assert!(
        store
            .tick(&mut transport, 100, expired)
            .unwrap()
            .budget_exhausted
    );
    let mut tiny = budget();
    tiny.max_bytes = 1;
    assert!(
        store
            .tick(&mut transport, 100, tiny)
            .unwrap()
            .budget_exhausted
    );
    assert!(transport.calls.is_empty());
    assert_eq!(store.statuses(0, 4).unwrap()[0].attempts, 0);
    for n in 2..=4 {
        store.enqueue(&item(n), 100).unwrap();
    }
    assert_eq!(store.enqueue(&item(5), 100).err(), Some(Error::Capacity));
    assert_eq!(store.statuses(0, 4).unwrap().len(), 4);
    drop(store);
    assert!(matches!(
        DeliveryStore::open(
            &f.0,
            context(),
            ns(),
            EndpointId::from_bytes([8; 32]).unwrap()
        ),
        Err(Error::Scope)
    ));
    assert_eq!(f.open().statuses(0, 4).unwrap().len(), 4);
}
#[test]
fn crash_after_attempt_intent_retries_without_reencrypting() {
    let f = Fixture::new();
    let mut store = f.create();
    store.enqueue(&item(1), 100).unwrap();
    let mut transport = Fake::new(&f, vec![receipt(1, true)]);
    transport.panic = true;
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| store.tick(
            &mut transport,
            100,
            budget()
        )))
        .is_err()
    );
    drop(store);
    let mut store = f.open();
    let status = &store.statuses(0, 1).unwrap()[0];
    assert_eq!(status.state, JobState::Uncertain);
    assert_eq!(status.attempts, 1);
    transport.panic = false;
    assert_eq!(
        store.tick(&mut transport, 102, budget()).unwrap().jobs[0].state,
        JobState::Retained
    );
    assert_eq!(transport.calls[0], transport.calls[1]);
}
#[test]
fn failed_receipt_publication_preserves_intent_and_exact_retry() {
    let f = Fixture::new();
    let mut store = f.create();
    store.enqueue(&item(1), 100).unwrap();
    store.conn.execute_batch("CREATE TRIGGER fail_receipt BEFORE UPDATE ON jobs WHEN NEW.state=2 BEGIN SELECT RAISE(ABORT, 'injected'); END;").unwrap();
    let mut transport = Fake::new(&f, vec![receipt(1, false), receipt(1, true)]);
    assert_eq!(
        store.tick(&mut transport, 100, budget()).err(),
        Some(Error::Storage)
    );
    assert_eq!(store.statuses(0, 1).err(), Some(Error::NeedsReopen));
    drop(store);
    let mut store = f.open();
    assert_eq!(store.statuses(0, 1).unwrap()[0].state, JobState::Uncertain);
    store
        .conn
        .execute_batch("DROP TRIGGER fail_receipt")
        .unwrap();
    let result = store.tick(&mut transport, 102, budget()).unwrap();
    assert_eq!(result.jobs[0].position, Some(1));
    assert_eq!(transport.calls[0], transport.calls[1]);
}
#[test]
fn hostile_receipt_stops_without_claiming_retention_and_custody_cannot_split() {
    let f = Fixture::new();
    let mut store = f.create();
    assert!(matches!(
        DeliveryStore::open(&f.0, context(), ns(), endpoint()),
        Err(Error::Busy)
    ));
    store.enqueue(&item(1), 100).unwrap();
    let mut transport = Fake::new(
        &f,
        vec![Ok(RelayReceipt {
            position: 1,
            digest: item(2).digest(),
            duplicate: false,
        })],
    );
    let result = store.tick(&mut transport, 100, budget()).unwrap();
    assert_eq!(result.jobs[0].state, JobState::Stopped);
    assert!(result.jobs[0].uncertain);
    assert_eq!(result.jobs[0].last_error, Some(NetError::Malformed));
    assert_eq!(result.jobs[0].position, None);
}
#[test]
fn item_budget_continues_fair_due_order_and_retained_tampering_refuses() {
    let f = Fixture::new();
    let mut store = f.create();
    store.enqueue(&item(1), 100).unwrap();
    store.enqueue(&item(2), 100).unwrap();
    let mut transport = Fake::new(&f, vec![receipt(1, false), receipt(2, false)]);
    let mut one = budget();
    one.max_jobs = 1;
    assert_eq!(
        store.tick(&mut transport, 100, one).unwrap().jobs[0].sequence,
        1
    );
    assert_eq!(
        store.tick(&mut transport, 100, one).unwrap().jobs[0].sequence,
        2
    );
    store
        .conn
        .execute(
            "UPDATE jobs SET item=?1 WHERE id=?2",
            params![item(2).encode().unwrap(), item(1).digest().as_slice()],
        )
        .unwrap();
    drop(store);
    assert!(matches!(
        DeliveryStore::open(&f.0, context(), ns(), endpoint()),
        Err(Error::Corrupt)
    ));
}

#[test]
fn driver_checkpoint_is_monotone_durable_and_never_regresses() {
    let f = Fixture::new();
    let mut store = f.create();
    assert_eq!(store.driver_checkpoint().unwrap(), (0, 0));
    // A fresh durable queue accepts the first watermarks without a row of its
    // own, and a no-op save stays free of clock writes.
    store.save_driver_checkpoint(3, 2, 100).unwrap();
    assert_eq!(store.driver_checkpoint().unwrap(), (3, 2));
    store.save_driver_checkpoint(3, 2, 100).unwrap();
    assert_eq!(store.driver_checkpoint().unwrap(), (3, 2));
    store.save_driver_checkpoint(5, 4, 101).unwrap();
    assert_eq!(store.driver_checkpoint().unwrap(), (5, 4));
    // Regression is a caller bug, never a state repair.
    assert_eq!(
        store.save_driver_checkpoint(4, 4, 102).err(),
        Some(Error::Bounds)
    );
    assert_eq!(
        store.save_driver_checkpoint(5, 3, 102).err(),
        Some(Error::Bounds)
    );
    assert_eq!(store.driver_checkpoint().unwrap(), (5, 4));
    drop(store);
    // Watermarks survive reopen and resume the driver's outgoing/applied scan.
    let mut store = f.open();
    assert_eq!(store.driver_checkpoint().unwrap(), (5, 4));
    store.save_driver_checkpoint(6, 6, 103).unwrap();
    assert_eq!(store.driver_checkpoint().unwrap(), (6, 6));
}

#[test]
fn high_attempt_backoff_saturates_instead_of_wrapping_to_immediate_retry() {
    let f = Fixture::new();
    let mut retry = policy();
    retry.max_attempts = 100;
    let mut store =
        DeliveryStore::create_new(&f.0, context(), ns(), endpoint(), limits(), retry).unwrap();
    store.enqueue(&item(1), 100).unwrap();
    store
        .conn
        .execute(
            "UPDATE jobs SET attempts=63,state=1,uncertain=1 WHERE id=?1",
            params![item(1).digest().as_slice()],
        )
        .unwrap();
    let mut transport = Fake::new(&f, vec![Err(NetError::Timeout)]);
    let report = store.tick(&mut transport, 100, budget()).unwrap();
    assert_eq!(report.jobs[0].attempts, 63);
    assert_eq!(store.evidence(report.jobs[0].id).unwrap().outages, 1);
    assert_eq!(report.jobs[0].next_due, 105);
    assert!(store
        .tick(&mut transport, 100, budget())
        .unwrap()
        .jobs
        .is_empty());
}
