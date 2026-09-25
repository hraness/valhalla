use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use vhalla_private_kernel::protocol::{AnchorId, Key, PrivateRoomScope, RoomId};

struct Home(std::path::PathBuf);
impl Home {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        Self(std::env::temp_dir().join(format!(
            "vhalla-successor-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        if self.0.exists() {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
}
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
fn seed() -> SuccessorSeed {
    SuccessorSeed {
        generation: 1,
        prior: LedgerSnapshot {
            outgoing: 5,
            applied: 7,
            retained_jobs: 3,
            canonical_bytes: 1024,
            charged_attempts: 6,
            outages: 2,
            resumes: 1,
            commitment: [8; 32],
        },
        receipt: [9; 32],
        now: 100,
    }
}
fn create(home: &Home, seed: SuccessorSeed) -> Result<DeliveryStore> {
    DeliveryStore::create_successor(
        &home.0,
        context(),
        RelayNamespace::from_bytes([5; 32]).unwrap(),
        EndpointId::from_bytes([6; 32]).unwrap(),
        Limits {
            max_jobs: 4,
            max_bytes: 8192,
        },
        RetryPolicy {
            max_attempts: 8,
            initial_backoff_secs: 1,
            max_backoff_secs: 30,
        },
        seed,
    )
}

#[test]
fn every_successor_creation_boundary_finishes_exactly_without_resetting_prior_spend() {
    for point in 0..=6 {
        let home = Home::new();
        CREATION_FAULT.with(|fault| fault.set(Some(point)));
        assert!(create(&home, seed()).is_err(), "fault {point}");
        CREATION_FAULT.with(|fault| fault.set(None));
        let store = create(&home, seed()).unwrap();
        assert_eq!(store.driver_checkpoint().unwrap(), (5, 0));
        let snapshot = store.drained_snapshot().unwrap();
        assert_eq!(
            (
                snapshot.canonical_bytes,
                snapshot.charged_attempts,
                snapshot.outages,
                snapshot.resumes
            ),
            (1024, 6, 2, 1)
        );
        drop(store);
        let reopened = create(&home, seed()).unwrap();
        assert_eq!(reopened.drained_snapshot().unwrap(), snapshot);
    }
}

#[test]
fn changed_creation_intent_and_unknown_database_content_are_preserved() {
    let home = Home::new();
    drop(create(&home, seed()).unwrap());
    let before = std::fs::read(home.0.join("delivery.db")).unwrap();
    let mut changed = seed();
    changed.receipt = [10; 32];
    assert!(create(&home, changed).is_err());
    assert_eq!(std::fs::read(home.0.join("delivery.db")).unwrap(), before);
    let conn = Connection::open(home.0.join("delivery.db")).unwrap();
    conn.execute_batch("DROP TABLE job_evidence; DROP TABLE jobs; DROP TABLE driver; DROP TABLE lineage; DROP TABLE meta;").unwrap();
    drop(conn);
    let damaged = std::fs::read(home.0.join("delivery.db")).unwrap();
    assert!(create(&home, seed()).is_err());
    assert_eq!(std::fs::read(home.0.join("delivery.db")).unwrap(), damaged);
}

#[test]
fn parent_alias_resolves_but_successor_leaf_symlink_refuses() {
    let root = Home::new();
    custody::create_private_directory(&root.0).unwrap();
    let real = root.0.join("real");
    custody::create_private_directory(&real).unwrap();
    let alias = root.0.join("alias");
    std::os::unix::fs::symlink(&real, &alias).unwrap();
    let through_alias = Home(alias.join("successor"));
    drop(create(&through_alias, seed()).unwrap());
    let before = std::fs::read(real.join("successor/delivery.db")).unwrap();
    let leaf = Home(root.0.join("linked-successor"));
    std::os::unix::fs::symlink(real.join("successor"), &leaf.0).unwrap();
    assert!(create(&leaf, seed()).is_err());
    assert_eq!(
        std::fs::read(real.join("successor/delivery.db")).unwrap(),
        before
    );
    std::fs::remove_file(&leaf.0).unwrap();
}
