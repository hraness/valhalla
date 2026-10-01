//! A retained creation intent is authenticated by the existing genesis nonce.

use std::{fs, sync::Arc};
use tempfile::TempDir;
use vhalla_direct_native::{Error, Limits, RoomSession};
use vhalla_direct_room::SignedGenesis;
use vhalla_identity::Identity;

fn limits() -> Limits {
    Limits {
        max_records: 256,
        max_record_bytes: 8 * 1024 * 1024,
    }
}

#[test]
fn creation_nonce_is_authenticated_and_retained_across_reopen() {
    let root = TempDir::new().unwrap();
    let account = Arc::new(Identity::create_new(root.path().join("account")).unwrap());
    let home = root.path().join("room");
    let nonce = [7; 32];
    let mut room = RoomSession::create_bound(account.clone(), &home, nonce, limits()).unwrap();
    let pin = room.room_id();
    let author = room.author_key();
    let raw = room.genesis().encode();
    let genesis = SignedGenesis::decode(&raw)
        .unwrap()
        .verify_pin(pin)
        .unwrap();
    assert_eq!(genesis.claims().nonce, nonce);
    assert_eq!(room.creation_nonce(), nonce);
    assert_eq!(genesis.claims().owner, account.public_key());
    assert!(room.status().unwrap().created_here);
    assert_ne!(author, account.public_key());
    drop(room);

    // Retrying creation cannot replace an intact room, even with a new intent.
    for attempted in [nonce, [8; 32]] {
        assert!(matches!(
            RoomSession::create_bound(account.clone(), &home, attempted, limits()),
            Err(Error::Custody)
        ));
    }
    let mut reopened = RoomSession::open(account.clone(), &home, pin).unwrap();
    assert_eq!(reopened.genesis().encode(), raw);
    assert_eq!(reopened.genesis().claims().nonce, nonce);
    assert_eq!(reopened.creation_nonce(), nonce);
    assert_eq!(reopened.author_key(), author);
    assert!(reopened.status().unwrap().created_here);

    // Another locally created room under the same account carries its own intent.
    let other =
        RoomSession::create_bound(account, root.path().join("other-room"), [8; 32], limits())
            .unwrap();
    assert_eq!(other.genesis().claims().owner, genesis.claims().owner);
    assert_ne!(other.genesis().claims().nonce, nonce);
    assert_ne!(other.room_id(), pin);
}

#[test]
fn zero_creation_nonce_refuses_without_creating_or_changing_a_home() {
    let root = TempDir::new().unwrap();
    let account = Arc::new(Identity::create_new(root.path().join("account")).unwrap());
    let absent = root.path().join("absent");
    assert!(matches!(
        RoomSession::create_bound(account.clone(), &absent, [0; 32], limits()),
        Err(Error::Bounds)
    ));
    assert!(!absent.exists());

    let partial = root.path().join("partial");
    fs::create_dir(&partial).unwrap();
    fs::write(partial.join("evidence"), b"retain unchanged").unwrap();
    assert!(matches!(
        RoomSession::create_bound(account.clone(), &partial, [0; 32], limits()),
        Err(Error::Bounds)
    ));
    assert!(matches!(
        RoomSession::create_bound(account, &partial, [1; 32], limits()),
        Err(Error::Custody)
    ));
    assert_eq!(fs::read_dir(&partial).unwrap().count(), 1);
    assert_eq!(
        fs::read(partial.join("evidence")).unwrap(),
        b"retain unchanged"
    );
}

#[test]
fn ordinary_creation_still_generates_fresh_nonces_and_authors() {
    let root = TempDir::new().unwrap();
    let account = Arc::new(Identity::create_new(root.path().join("account")).unwrap());
    let first = RoomSession::create(account.clone(), root.path().join("first"), limits()).unwrap();
    let second = RoomSession::create(account, root.path().join("second"), limits()).unwrap();
    assert_ne!(first.genesis().claims().nonce, [0; 32]);
    assert_ne!(second.genesis().claims().nonce, [0; 32]);
    assert_eq!(first.creation_nonce(), first.genesis().claims().nonce);
    assert_eq!(second.creation_nonce(), second.genesis().claims().nonce);
    assert_ne!(
        first.genesis().claims().nonce,
        second.genesis().claims().nonce
    );
    assert_ne!(first.author_key(), second.author_key());
    assert_ne!(first.room_id(), second.room_id());
}
