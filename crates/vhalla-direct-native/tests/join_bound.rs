//! Local join provenance is distinct from the public owner's signed genesis.

use std::sync::Arc;
use tempfile::TempDir;
use vhalla_direct_native::{Error, Limits, RoomSession};
use vhalla_identity::Identity;

fn limits() -> Limits {
    Limits {
        max_records: 256,
        max_record_bytes: 8 * 1024 * 1024,
    }
}

#[test]
fn bound_join_retains_local_nonce_and_fresh_author_without_changing_genesis() {
    let root = TempDir::new().unwrap();
    let account = Arc::new(Identity::create_new(root.path().join("account")).unwrap());
    let owner = RoomSession::create_bound(
        account.clone(),
        root.path().join("owner"),
        [1; 32],
        limits(),
    )
    .unwrap();
    let pin = owner.room_id();
    let raw = owner.genesis().encode();
    let home = root.path().join("joined");
    let mut joined =
        RoomSession::join_bound(account.clone(), &home, &raw, pin, [2; 32], limits()).unwrap();
    let author = joined.author_key();
    assert_eq!(joined.creation_nonce(), [2; 32]);
    assert_eq!(joined.genesis().encode(), raw);
    assert_eq!(joined.genesis().claims().nonce, [1; 32]);
    assert!(!joined.status().unwrap().created_here);
    assert_ne!(author, owner.author_key());
    assert_eq!(
        joined.set_writers([3; 16], vec![account.public_key()]),
        Err(Error::NotOwner)
    );
    drop(joined);
    assert!(matches!(
        RoomSession::join_bound(account.clone(), &home, &raw, pin, [2; 32], limits()),
        Err(Error::Custody)
    ));
    let mut reopened = RoomSession::open(account.clone(), &home, pin).unwrap();
    assert_eq!(reopened.creation_nonce(), [2; 32]);
    assert_eq!(reopened.author_key(), author);
    assert_eq!(reopened.genesis().encode(), raw);
    assert!(!reopened.status().unwrap().created_here);
    let ordinary =
        RoomSession::join(account, root.path().join("ordinary"), &raw, pin, limits()).unwrap();
    assert_ne!(ordinary.creation_nonce(), [0; 32]);
    assert_ne!(ordinary.creation_nonce(), reopened.creation_nonce());
    assert_ne!(ordinary.author_key(), author);
    assert_eq!(ordinary.genesis().encode(), raw);
}

#[test]
fn zero_join_nonce_is_refused_before_creating_a_home() {
    let root = TempDir::new().unwrap();
    let account = Arc::new(Identity::create_new(root.path().join("account")).unwrap());
    let owner = RoomSession::create(account.clone(), root.path().join("owner"), limits()).unwrap();
    let home = root.path().join("joined");
    assert!(matches!(
        RoomSession::join_bound(
            account,
            &home,
            &owner.genesis().encode(),
            owner.room_id(),
            [0; 32],
            limits()
        ),
        Err(Error::Bounds)
    ));
    assert!(!home.exists());
}
