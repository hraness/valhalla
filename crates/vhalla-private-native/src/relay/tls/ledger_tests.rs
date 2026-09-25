//! Exercise the production TLS PUT transaction and explicit generation APIs.
use super::*;
use crate::relay::{generation::MaintenanceFault, OutboxKind};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use vhalla_private_kernel::OperationId;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "vhalla-relay-ledger-{}-{stamp}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        vhalla_custody::create_private_directory(&path).unwrap();
        let fixture = Self(path);
        Service::initialize(fixture.create("old", ns(1))).unwrap();
        drop(service(
            fixture.old(),
            vec![credential(1, 7, ns(1)), credential(2, 8, ns(1))],
        ));
        fixture
    }
    fn create(&self, name: &str, namespace: RelayNamespace) -> FileStore {
        FileStore::create_new(
            self.0.join(name),
            namespace,
            Limits {
                max_items: 4,
                max_bytes: 4096,
            },
        )
        .unwrap()
    }
    fn old(&self) -> FileStore {
        FileStore::open(self.0.join("old"), ns(1)).unwrap()
    }
    fn successor(&self) -> FileStore {
        let mut store = self.create("next", ns(2));
        store.upgrade_generation_format().unwrap();
        store
    }
    fn seed(&self) -> FencedQuotaSnapshot {
        {
            let service = service(self.old(), vec![credential(1, 7, ns(1))]);
            assert_eq!(submit(&service, 1, item(ns(1), 1)).0, STATUS_OK);
            assert_eq!(submit(&service, 1, item(ns(1), 2)).0, STATUS_OK);
        }
        let mut old = self.old();
        old.upgrade_generation_format().unwrap();
        Service::upgrade_ledger(&mut old).unwrap();
        assert!(Service::fenced_spend(&old).is_err());
        old.fence([9; 32], ns(2), 2).unwrap();
        Service::fenced_spend(&old).unwrap()
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
fn credential(id: u8, token: u8, namespace: RelayNamespace) -> Credential {
    Credential {
        id: [id; 16],
        tokens: vec![RelayToken::from_bytes([token; 32]).unwrap()],
        namespace,
        permissions: Permissions {
            put: true,
            page: true,
        },
        storage: Limits {
            max_items: 2,
            max_bytes: 512,
        },
        max_inflight: 1,
        requests_per_window: 2,
        bytes_per_window: 1024,
    }
}
fn config() -> Arc<ServerConfig> {
    let certificate =
        rcgen::generate_simple_self_signed(vec!["ledger.test.invalid".into()]).unwrap();
    server_config(
        vec![certificate.cert.der().to_vec()],
        certificate.key_pair.serialize_der(),
    )
    .unwrap()
}
fn service(store: FileStore, credentials: Vec<Credential>) -> Service {
    Service::new(store, config(), credentials, ServiceLimits::default()).unwrap()
}
fn item(namespace: RelayNamespace, n: u8) -> RelayItem {
    RelayItem::new(
        namespace,
        u64::from(n),
        OperationId::from_bytes([n; 16]).unwrap(),
        OutboxKind::Application,
        b"ciphertext",
    )
    .unwrap()
}
fn submit(service: &Service, id: u8, item: RelayItem) -> (u8, Vec<u8>) {
    put(
        &mut service.state.lock().unwrap(),
        [id; 16],
        &item.encode().unwrap(),
    )
    .unwrap()
}

#[test]
fn fenced_export_preserves_inactive_identity_spend_and_old_exact_retries() {
    let fixture = Fixture::new();
    let snapshot = fixture.seed();
    assert_eq!(snapshot.credentials().len(), 2);
    assert_eq!(snapshot.credentials()[0].spent_items(), 2);
    assert_eq!(snapshot.credentials()[0].spent_bytes(), 20);
    assert_eq!(snapshot.credentials()[1].spent_items(), 0);
    let original = fixture.old().page(0, 4).unwrap().records;
    // Removing an active token does not remove that stable identity's ledger.
    let old = service(fixture.old(), vec![credential(2, 18, ns(1))]);
    let (code, retry) = submit(&old, 2, item(ns(1), 1));
    assert_eq!(code, STATUS_OK);
    assert_eq!(u64::from_be_bytes(retry[..8].try_into().unwrap()), 1);
    assert_eq!(retry.last(), Some(&1));
    assert_eq!(submit(&old, 2, item(ns(1), 3)).0, STATUS_CAPACITY);
    drop(old);
    assert_eq!(fixture.old().page(0, 4).unwrap().records, original);
    assert_eq!(Service::fenced_spend(&fixture.old()).unwrap(), snapshot);
    assert_eq!(
        Service::new(
            fixture.old(),
            config(),
            vec![credential(3, 9, ns(1))],
            ServiceLimits::default()
        )
        .map(|_| ()),
        Err(NetError::Conflict)
    );
    assert_eq!(Service::fenced_spend(&fixture.old()).unwrap(), snapshot);
}

#[test]
fn successor_enforces_carried_spend_explicit_addition_and_duplicate_ownership() {
    for extra in [0, 1] {
        let fixture = Fixture::new();
        let snapshot = fixture.seed();
        let mut next = fixture.successor();
        let allowances = if extra == 0 {
            vec![]
        } else {
            vec![CredentialAllowance {
                id: [1; 16],
                additional_items: 1,
                additional_bytes: 10,
            }]
        };
        Service::initialize_successor(&mut next, &snapshot, &allowances).unwrap();
        Service::initialize_successor(&mut next, &snapshot, &allowances).unwrap();
        let next = service(
            next,
            vec![credential(1, 17, ns(2)), credential(2, 18, ns(2))],
        );
        assert_eq!(
            submit(&next, 1, item(ns(2), 3)).0,
            if extra == 0 {
                STATUS_CAPACITY
            } else {
                STATUS_OK
            }
        );
        if extra == 1 {
            // Another key's exact retry neither reassigns nor charges the item.
            let (code, retry) = submit(&next, 2, item(ns(2), 3));
            assert_eq!(code, STATUS_OK);
            assert_eq!(retry.last(), Some(&1));
            assert_eq!(submit(&next, 1, item(ns(2), 4)).0, STATUS_CAPACITY);
        }
        drop(next);
        let mut next = FileStore::open(fixture.0.join("next"), ns(2)).unwrap();
        Service::initialize_successor(&mut next, &snapshot, &allowances).unwrap();
        let changed = [CredentialAllowance {
            id: [1; 16],
            additional_items: 2,
            additional_bytes: 20,
        }];
        assert_eq!(
            Service::initialize_successor(&mut next, &snapshot, &changed),
            Err(NetError::Conflict)
        );
        assert!(!next.needs_reopen());
        next.fence([10; 32], ns(3), extra).unwrap();
        let exported = Service::fenced_spend(&next).unwrap();
        assert_eq!(exported.credentials()[0].spent_items(), 2 + extra);
        assert_eq!(exported.credentials()[0].authorized_items(), 2 + extra);
        assert_eq!(exported.credentials()[1].spent_items(), 0);
        assert_eq!(exported.credentials()[1].authorized_items(), 2);
        let mut third = fixture.create("third", ns(3));
        third.upgrade_generation_format().unwrap();
        Service::initialize_successor(&mut third, &exported, &[]).unwrap();
        let third = service(third, vec![credential(1, 27, ns(3))]);
        assert_eq!(submit(&third, 1, item(ns(3), 5)).0, STATUS_CAPACITY);
    }
}

#[test]
fn carried_byte_spend_requires_explicit_byte_authority_independently_of_items() {
    for extra_bytes in [0, 10] {
        let fixture = Fixture::new();
        {
            let old = service(fixture.old(), vec![credential(1, 7, ns(1))]);
            for n in [1, 2] {
                let item = RelayItem::new(
                    ns(1),
                    u64::from(n),
                    OperationId::from_bytes([n; 16]).unwrap(),
                    OutboxKind::Application,
                    &[42; 256],
                )
                .unwrap();
                assert_eq!(submit(&old, 1, item).0, STATUS_OK);
            }
        }
        let mut old = fixture.old();
        old.upgrade_generation_format().unwrap();
        Service::upgrade_ledger(&mut old).unwrap();
        old.fence([9; 32], ns(2), 2).unwrap();
        let snapshot = Service::fenced_spend(&old).unwrap();
        assert_eq!(snapshot.credentials()[0].spent_bytes(), 512);
        let mut next = fixture.successor();
        Service::initialize_successor(
            &mut next,
            &snapshot,
            &[CredentialAllowance {
                id: [1; 16],
                additional_items: 1,
                additional_bytes: extra_bytes,
            }],
        )
        .unwrap();
        let next = service(next, vec![credential(1, 17, ns(2))]);
        assert_eq!(
            submit(&next, 1, item(ns(2), 3)).0,
            if extra_bytes == 0 {
                STATUS_CAPACITY
            } else {
                STATUS_OK
            }
        );
    }
}

#[test]
fn successor_requires_exact_namespace_finite_known_allowances_and_empty_enrollment() {
    let fixture = Fixture::new();
    let snapshot = fixture.seed();
    let mut next = fixture.successor();
    let unknown = CredentialAllowance {
        id: [3; 16],
        additional_items: 1,
        additional_bytes: 1,
    };
    let overflow = CredentialAllowance {
        id: [1; 16],
        additional_items: u64::MAX,
        additional_bytes: 1,
    };
    let known = CredentialAllowance {
        id: [1; 16],
        additional_items: 1,
        additional_bytes: 1,
    };
    for allowances in [
        vec![unknown],
        vec![overflow],
        vec![known, known],
        vec![known; 65],
    ] {
        assert_eq!(
            Service::initialize_successor(&mut next, &snapshot, &allowances),
            Err(NetError::Bounds)
        );
        assert!(!next.needs_reopen());
    }
    let mut wrong = fixture.create("wrong", ns(3));
    wrong.upgrade_generation_format().unwrap();
    assert_eq!(
        Service::initialize_successor(&mut wrong, &snapshot, &[]),
        Err(NetError::Scope)
    );
    next.put(item(ns(2), 3)).unwrap();
    assert_eq!(
        Service::initialize_successor(&mut next, &snapshot, &[]),
        Err(NetError::Conflict)
    );
}

#[test]
fn ledger_upgrade_recovers_whole_before_or_after_commit_and_preserves_charges() {
    for fault in [
        MaintenanceFault::BeforeCommit,
        MaintenanceFault::AfterCommit,
    ] {
        let fixture = Fixture::new();
        {
            let service = service(fixture.old(), vec![credential(1, 7, ns(1))]);
            assert_eq!(submit(&service, 1, item(ns(1), 1)).0, STATUS_OK);
        }
        let mut old = fixture.old();
        old.upgrade_generation_format().unwrap();
        old.maintenance_fault = Some(fault);
        assert_eq!(
            Service::upgrade_ledger(&mut old),
            Err(NetError::Unavailable)
        );
        assert!(old.needs_reopen());
        assert_eq!(
            Service::upgrade_ledger(&mut old),
            Err(NetError::Unavailable)
        );
        drop(old);
        let mut old = fixture.old();
        let format: u8 = old
            .conn
            .query_row("SELECT format FROM tls_meta", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            format,
            if fault == MaintenanceFault::BeforeCommit {
                1
            } else {
                2
            }
        );
        Service::upgrade_ledger(&mut old).unwrap();
        old.fence([9; 32], ns(2), 1).unwrap();
        let snapshot = Service::fenced_spend(&old).unwrap();
        assert_eq!(snapshot.credentials()[0].spent_items(), 1);
        assert_eq!(snapshot.credentials()[0].spent_bytes(), 10);
        assert_eq!(old.page(0, 4).unwrap().records[0].item, item(ns(1), 1));
    }
}

#[test]
fn interrupted_successor_enrollment_reconciles_without_resetting_its_basis() {
    for fault in [
        MaintenanceFault::BeforeCommit,
        MaintenanceFault::AfterCommit,
    ] {
        let fixture = Fixture::new();
        let snapshot = fixture.seed();
        let mut next = fixture.successor();
        next.maintenance_fault = Some(fault);
        assert_eq!(
            Service::initialize_successor(&mut next, &snapshot, &[]),
            Err(NetError::Unavailable)
        );
        assert!(next.needs_reopen());
        drop(next);
        let mut next = FileStore::open(fixture.0.join("next"), ns(2)).unwrap();
        Service::initialize_successor(&mut next, &snapshot, &[]).unwrap();
        let next = service(next, vec![credential(1, 17, ns(2))]);
        assert_eq!(submit(&next, 1, item(ns(2), 3)).0, STATUS_CAPACITY);
    }
}

#[test]
fn successor_rejects_tampered_basis_and_tls_still_rejects_uncharged_items() {
    let fixture = Fixture::new();
    let snapshot = fixture.seed();
    let mut next = fixture.successor();
    Service::initialize_successor(&mut next, &snapshot, &[]).unwrap();
    next.conn
        .execute_batch("UPDATE tls_budget SET authorized_items=authorized_items+1 WHERE seeded=1")
        .unwrap();
    assert_eq!(
        Service::new(
            next,
            config(),
            vec![credential(1, 7, ns(2))],
            ServiceLimits::default()
        )
        .map(|_| ()),
        Err(NetError::Unavailable)
    );
    let mut plain = fixture.create("uncharged", ns(3));
    plain.upgrade_generation_format().unwrap();
    Service::initialize(plain).unwrap();
    let mut plain = FileStore::open(fixture.0.join("uncharged"), ns(3)).unwrap();
    plain.put(item(ns(3), 1)).unwrap();
    assert_eq!(
        Service::upgrade_ledger(&mut plain),
        Err(NetError::Unavailable)
    );
}

#[test]
fn read_only_inventory_includes_inactive_ids_without_migrating() {
    let f = Fixture::new();
    {
        let s = service(f.old(), vec![credential(1, 7, ns(1))]);
        assert_eq!(submit(&s, 1, item(ns(1), 1)).0, STATUS_OK);
    }
    let old = f.old();
    let inventory = Service::credential_spend(&old).unwrap();
    assert_eq!(inventory.len(), 2);
    assert_eq!(inventory[0].spent_items(), 1);
    assert_eq!(inventory[1].spent_items(), 0);
    assert_eq!(inventory[1].id(), [2; 16]);
    assert_eq!(old.format, 2);
    let format: i64 = old
        .conn
        .query_row("SELECT format FROM tls_meta WHERE id=1", [], |r| r.get(0))
        .unwrap();
    assert_eq!(format, 1);
}
