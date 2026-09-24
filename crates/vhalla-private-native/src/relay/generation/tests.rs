use super::*;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        Self(std::env::temp_dir().join(format!(
            "vhalla-relay-generation-{}-{stamp}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }
    fn create(&self) -> FileStore {
        FileStore::create_new(
            &self.0,
            ns(1),
            Limits {
                max_items: 4,
                max_bytes: 1024,
            },
        )
        .unwrap()
    }
    fn open(&self) -> FileStore {
        FileStore::open(&self.0, ns(1)).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
fn ns(n: u8) -> RelayNamespace {
    RelayNamespace::from_bytes([n; 32]).unwrap()
}
fn item(n: u8) -> RelayItem {
    RelayItem::new(
        ns(1),
        u64::from(n),
        OperationId::from_bytes([n; 16]).unwrap(),
        OutboxKind::Application,
        b"exact ciphertext",
    )
    .unwrap()
}

#[test]
fn migration_is_explicit_preserves_items_and_excludes_legacy_writers() {
    let fixture = Fixture::new();
    let mut store = fixture.create();
    store.put(item(1)).unwrap();
    let before = store.page(0, 4).unwrap();
    let retained = store.retained_head().unwrap();
    assert_eq!(retained.0, 1);
    assert_eq!(store.format, 2);
    assert_eq!(store.fence([3; 32], ns(2), 1), Err(Error::Bounds));
    drop(store);
    let mut store = fixture.open();
    assert_eq!(store.format, 2);
    store.upgrade_generation_format().unwrap();
    store.upgrade_generation_format().unwrap();
    assert_eq!(store.retained_head().unwrap(), retained);
    assert_eq!(store.page(0, 4).unwrap().records, before.records);
    assert_eq!(store.generation_fence().unwrap(), None);
    let format: i64 = store
        .conn
        .query_row("SELECT format FROM meta WHERE id=1", [], |r| r.get(0))
        .unwrap();
    assert_eq!(format, 3); // Pre-upgrade readers require this exact field to be 2.
    assert!(store
        .conn
        .execute_batch("UPDATE meta SET format=2")
        .is_err());
    drop(store);
    assert_eq!(fixture.open().page(0, 4).unwrap().records, before.records);
}

#[test]
fn conditional_fence_preserves_original_retries_and_freezes_the_head() {
    let fixture = Fixture::new();
    let mut store = fixture.create();
    store.upgrade_generation_format().unwrap();
    // An admitted write raced the controller's empty-head agreement. Refuse
    // fencing without sealing the mailbox, so a fresh complete drain can run.
    let lost = store.put(item(1)).unwrap();
    let retained = store.retained_head().unwrap();
    assert_eq!(store.fence([3; 32], ns(2), 0), Err(Error::Conflict));
    assert!(!store.needs_reopen());
    assert_eq!(store.generation_fence().unwrap(), None);
    let fence = store.fence([3; 32], ns(2), 1).unwrap();
    assert_eq!(fence.head(), 1);
    assert_eq!(fence.predecessor(), ns(1));
    assert_eq!(fence.successor(), ns(2));
    assert_eq!((fence.head(), fence.items_commitment()), retained);
    assert_eq!(store.fence([3; 32], ns(2), 1).unwrap(), fence);
    for (transition, successor, head) in [
        ([4; 32], ns(2), 1),
        ([3; 32], ns(3), 1),
        ([3; 32], ns(2), 0),
    ] {
        assert_eq!(
            store.fence(transition, successor, head),
            Err(Error::Conflict)
        );
    }
    assert_eq!(store.put(item(2)), Err(Error::Capacity));
    let retried = store.put(item(1)).unwrap();
    assert!(retried.duplicate);
    assert_eq!(
        (retried.position, retried.digest),
        (lost.position, lost.digest)
    );
    assert!(FileStore::open(&fixture.0, ns(1)).is_err());
    drop(store);
    let mut store = fixture.open();
    assert_eq!(store.generation_fence().unwrap(), Some(fence));
    assert_eq!(store.page(0, 4).unwrap().records.len(), 1);
    assert_eq!(store.put(item(2)), Err(Error::Capacity));
    assert!(store.put(item(1)).unwrap().duplicate);
}

#[test]
fn interrupted_migration_reopens_wholly_old_or_new_without_reset() {
    for fault in [
        MaintenanceFault::BeforeCommit,
        MaintenanceFault::AfterCommit,
    ] {
        let fixture = Fixture::new();
        let mut store = fixture.create();
        store.put(item(1)).unwrap();
        store.maintenance_fault = Some(fault);
        assert_eq!(store.upgrade_generation_format(), Err(Error::Storage));
        assert!(store.needs_reopen());
        assert_eq!(store.put(item(2)), Err(Error::Storage));
        assert_eq!(store.page(0, 4).map(|_| ()), Err(Error::Storage));
        assert_eq!(store.retained_head(), Err(Error::Storage));
        drop(store);
        let mut reopened = fixture.open();
        assert_eq!(
            reopened.format,
            if fault == MaintenanceFault::BeforeCommit {
                2
            } else {
                3
            }
        );
        assert_eq!(reopened.page(0, 4).unwrap().records[0].item, item(1));
        reopened.upgrade_generation_format().unwrap();
        assert!(reopened.put(item(1)).unwrap().duplicate);
    }
}

#[test]
fn interrupted_fence_reconciles_without_changing_retention_identity() {
    for fault in [
        MaintenanceFault::BeforeCommit,
        MaintenanceFault::AfterCommit,
    ] {
        let fixture = Fixture::new();
        let mut store = fixture.create();
        store.put(item(1)).unwrap();
        store.upgrade_generation_format().unwrap();
        store.maintenance_fault = Some(fault);
        assert_eq!(store.fence([3; 32], ns(2), 1), Err(Error::Storage));
        assert!(store.needs_reopen());
        drop(store);
        let mut reopened = fixture.open();
        assert_eq!(
            reopened.generation_fence().unwrap().is_some(),
            fault == MaintenanceFault::AfterCommit
        );
        let fence = reopened.fence([3; 32], ns(2), 1).unwrap();
        assert_eq!(fence.head(), 1);
        assert!(reopened.put(item(1)).unwrap().duplicate);
        assert_eq!(reopened.put(item(2)), Err(Error::Capacity));
    }
}

#[test]
fn fence_refuses_invalid_selection_and_reopen_detects_changed_evidence() {
    let fixture = Fixture::new();
    let mut store = fixture.create();
    store.upgrade_generation_format().unwrap();
    assert_eq!(store.fence([0; 32], ns(2), 0), Err(Error::Bounds));
    assert_eq!(store.fence([3; 32], ns(1), 0), Err(Error::Bounds));
    store.put(item(1)).unwrap();
    store.fence([3; 32], ns(2), 1).unwrap();
    store
        .conn
        .execute_batch("UPDATE generation_state SET items=zeroblob(32)")
        .unwrap();
    drop(store);
    assert!(FileStore::open(&fixture.0, ns(1)).is_err());
}
