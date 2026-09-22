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
    assert_eq!(
        store.tick(&mut transport, 99, budget()).err(),
        Some(Error::Clock)
    );
    assert!(store
        .tick(&mut transport, 101, budget())
        .unwrap()
        .jobs
        .is_empty());
    let second = store.tick(&mut transport, 102, budget()).unwrap();
    assert_eq!(second.jobs[0].state, JobState::Retained);
    assert_eq!(second.jobs[0].attempts, 2);
    assert_eq!(transport.calls[0], transport.calls[1]);
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
        ],
    );
    let first = store.tick(&mut transport, 100, budget()).unwrap();
    assert_eq!(first.jobs[0].state, JobState::Pending);
    assert!(!first.jobs[0].uncertain);
    assert!(first.jobs[1].uncertain);
    store.tick(&mut transport, 102, budget()).unwrap();
    let last = store.tick(&mut transport, 106, budget()).unwrap();
    assert!(last
        .jobs
        .iter()
        .all(|j| j.state == JobState::Stopped && j.attempts == 3));
    assert!(!last.jobs[0].uncertain);
    assert!(last.jobs[1].uncertain);
    assert_eq!(last.jobs[0].next_due, 111);
    assert!(store
        .tick(&mut transport, 200, budget())
        .unwrap()
        .jobs
        .is_empty());
    assert_eq!(transport.calls.len(), 6);
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
    assert_eq!(report.jobs[0].attempts, 64);
    assert_eq!(report.jobs[0].next_due, 105);
    assert!(store
        .tick(&mut transport, 100, budget())
        .unwrap()
        .jobs
        .is_empty());
}
