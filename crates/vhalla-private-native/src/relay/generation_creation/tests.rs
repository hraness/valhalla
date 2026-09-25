use super::*;
use std::{
    os::unix::fs::{symlink, PermissionsExt},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

struct Fixture {
    root: PathBuf,
    fence: GenerationFence,
    retained: (u64, [u8; 32]),
}
impl Fixture {
    fn new(transition: u8, successor: u8) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "vhalla-relay-create-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        custody::create_private_directory(&root).unwrap();
        let mut old = FileStore::create_new(root.join("old"), ns(1), limits()).unwrap();
        old.put(item(ns(1), 1)).unwrap();
        let retained = old.retained_head().unwrap();
        old.upgrade_generation_format().unwrap();
        let fence = old
            .fence([transition; 32], ns(successor), retained.0)
            .unwrap();
        drop(old);
        Self {
            root,
            fence,
            retained,
        }
    }
    fn create(&self) -> Result<FileStore> {
        FileStore::create_successor(self.root.join("next"), limits(), self.fence, [9; 32])
    }
    fn check_old(&self) {
        let mut old = FileStore::open(self.root.join("old"), ns(1)).unwrap();
        assert_eq!(old.retained_head().unwrap(), self.retained);
        assert_eq!(old.generation_fence().unwrap(), Some(self.fence));
        assert!(old.put(item(ns(1), 1)).unwrap().duplicate);
        assert_eq!(old.put(item(ns(1), 2)), Err(Error::Capacity));
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
fn ns(value: u8) -> RelayNamespace {
    RelayNamespace::from_bytes([value; 32]).unwrap()
}
fn limits() -> Limits {
    Limits {
        max_items: 4,
        max_bytes: 8192,
    }
}
fn item(namespace: RelayNamespace, sequence: u8) -> RelayItem {
    RelayItem::new(
        namespace,
        u64::from(sequence),
        OperationId::from_bytes([sequence; 16]).unwrap(),
        OutboxKind::Application,
        b"original retained ciphertext",
    )
    .unwrap()
}
fn bytes(path: &Path) -> BTreeMap<String, Vec<u8>> {
    fs::read_dir(path)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (
                entry.file_name().into_string().unwrap(),
                fs::read(entry.path()).unwrap(),
            )
        })
        .collect()
}

#[test]
fn every_successor_creation_publication_reopens_exactly_without_changing_predecessor() {
    for point in 0..=10 {
        let f = Fixture::new(3, 2);
        CREATION_FAULT.with(|fault| fault.set(Some(point)));
        assert!(f.create().is_err(), "fault {point}");
        CREATION_FAULT.with(|fault| fault.set(None));
        let mut next = f.create().unwrap();
        assert_eq!(next.namespace(), ns(2));
        assert_eq!(next.limits, limits());
        assert_eq!(next.format, 3);
        assert_eq!(next.retained_head().unwrap().0, 0);
        assert_eq!(next.generation_fence().unwrap(), None);
        let receipt = next.put(item(ns(2), 2)).unwrap();
        drop(next);
        let mut reopened = f.create().unwrap();
        let retry = reopened.put(item(ns(2), 2)).unwrap();
        assert_eq!(retry.position, receipt.position);
        assert_eq!(retry.digest, receipt.digest);
        assert!(retry.duplicate);
        drop(reopened);
        f.check_old();
    }
}

#[test]
fn complete_binding_refuses_changed_intent_fence_namespace_and_limits_without_writes() {
    let f = Fixture::new(3, 2);
    CREATION_FAULT.with(|fault| fault.set(Some(4)));
    assert!(f.create().is_err());
    CREATION_FAULT.with(|fault| fault.set(None));
    let path = f.root.join("next");
    let before = bytes(&path);
    let other_fence = Fixture::new(4, 2);
    let other_namespace = Fixture::new(3, 5);
    for (policy, fence, intent) in [
        (limits(), f.fence, [8; 32]),
        (limits(), other_fence.fence, [9; 32]),
        (limits(), other_namespace.fence, [9; 32]),
        (
            Limits {
                max_items: 3,
                ..limits()
            },
            f.fence,
            [9; 32],
        ),
        (
            Limits {
                max_bytes: 8191,
                ..limits()
            },
            f.fence,
            [9; 32],
        ),
    ] {
        assert!(FileStore::create_successor(&path, policy, fence, intent).is_err());
        assert_eq!(bytes(&path), before);
    }
    drop(f.create().unwrap());
    f.check_old();
}

#[test]
fn generic_used_mailboxes_and_unknown_or_damaged_creation_state_are_not_adopted() {
    for change in 0..6 {
        let f = Fixture::new(3, 2);
        let path = f.root.join("next");
        if change == 0 {
            let mut ordinary = FileStore::create_new(&path, ns(2), limits()).unwrap();
            ordinary.put(item(ns(2), 2)).unwrap();
            drop(ordinary);
        } else {
            drop(f.create().unwrap());
            match change {
                1 => {
                    let mut file = custody::create_private_file(&path.join("unknown")).unwrap();
                    file.write_all(b"retained unknown evidence").unwrap();
                }
                2 => {
                    Connection::open(path.join("relay.db"))
                        .unwrap()
                        .execute_batch("CREATE TABLE unknown(value BLOB)")
                        .unwrap();
                }
                3 => {
                    Connection::open(path.join("relay.db"))
                        .unwrap()
                        .execute_batch(
                            "DROP TABLE generation_state; DROP TABLE items; DROP TABLE meta",
                        )
                        .unwrap();
                }
                4 => {
                    fs::write(path.join(CREATION), b"VHRELAYNEW\x01different").unwrap();
                }
                _ => {
                    fs::write(path.join(CREATION), b"VHRELAYNEW\x01").unwrap();
                }
            }
        }
        let before = bytes(&path);
        assert!(f.create().is_err(), "case {change}");
        assert_eq!(bytes(&path), before);
        f.check_old();
    }
}

#[test]
fn private_custody_and_leaf_no_follow_checks_survive_recoverable_creation() {
    let f = Fixture::new(3, 2);
    let alias = f.root.join("parent-alias");
    symlink(&f.root, &alias).unwrap();
    drop(FileStore::create_successor(alias.join("next"), limits(), f.fence, [9; 32]).unwrap());
    let path = f.root.join("next");
    let before = bytes(&path);
    let leaf = f.root.join("linked-next");
    symlink(&path, &leaf).unwrap();
    assert!(FileStore::create_successor(&leaf, limits(), f.fence, [9; 32]).is_err());
    assert_eq!(bytes(&path), before);
    fs::set_permissions(path.join(CREATION), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(f.create().is_err());
    fs::set_permissions(path.join(CREATION), fs::Permissions::from_mode(0o600)).unwrap();
    let held = f.create().unwrap();
    assert!(f.create().is_err());
    drop(held);
    assert_eq!(bytes(&path), before);
    f.check_old();
}

#[test]
fn partial_tls_schema_is_preserved_and_refused() {
    let f = Fixture::new(3, 2);
    let next = f.create().unwrap();
    // A foreign partial ledger cannot be accepted as an unseeded constructor.
    next.conn
        .execute_batch("CREATE TABLE tls_keys(id BLOB PRIMARY KEY)")
        .unwrap();
    drop(next);
    let before = bytes(&f.root.join("next"));
    assert!(f.create().is_err());
    assert_eq!(bytes(&f.root.join("next")), before);
    f.check_old();
}
