#![cfg(all(unix, feature = "direct-rooms"))]
//! Bound public creation preserves the account controller's custody lifetime.

use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use vhalla_direct_native::{Error, Limits};
use vhalla_direct_room::SignedGenesis;
use vhalla_identity::{Identity, IdentityError};
use vhalla_private_native::client::AccountController;

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let path = std::env::temp_dir().join(format!(
            "vhalla-direct-creation-nonce-{}-{}",
            std::process::id(),
            stamp.as_nanos()
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn bound_public_creation_preserves_signed_intent_and_account_custody() {
    let temp = Temp::new();
    let identity_path = temp.0.join("account");
    let account = AccountController::new(Identity::create_new(&identity_path).unwrap());
    let owner = account.public_key();
    let home = temp.0.join("public");
    let limits = Limits {
        max_records: 256,
        max_record_bytes: 8 * 1024 * 1024,
    };
    assert!(matches!(
        account.create_public_room_bound(&home, [0; 32], limits),
        Err(Error::Bounds)
    ));
    assert!(!home.exists());

    let nonce = [9; 32];
    let mut room = account
        .create_public_room_bound(&home, nonce, limits)
        .unwrap();
    let pin = room.room_id();
    let raw = room.genesis().encode();
    let genesis = SignedGenesis::decode(&raw)
        .unwrap()
        .verify_pin(pin)
        .unwrap();
    assert_eq!(genesis.claims().owner, owner);
    assert_eq!(genesis.claims().nonce, nonce);
    assert_eq!(room.creation_nonce(), nonce);
    assert!(room.status().unwrap().created_here);

    drop(account);
    assert!(matches!(
        Identity::open(&identity_path),
        Err(IdentityError::Busy)
    ));
    let sent = room.send([1; 16], "retained account custody", 1).unwrap();
    drop(room);

    let account = AccountController::new(Identity::open(&identity_path).unwrap());
    let mut room = account.open_public_room(&home, pin).unwrap();
    assert_eq!(room.genesis().encode(), raw);
    assert_eq!(room.genesis().claims().nonce, nonce);
    assert_eq!(room.creation_nonce(), nonce);
    let retry = room.send([1; 16], "retained account custody", 2).unwrap();
    assert!(retry.exact_retry);
    assert_eq!(retry.bytes, sent.bytes);
}

#[test]
fn bound_public_join_preserves_local_provenance_and_never_inherits_owner_rights() {
    let temp = Temp::new();
    let identity_path = temp.0.join("account");
    let account = AccountController::new(Identity::create_new(&identity_path).unwrap());
    let limits = Limits {
        max_records: 256,
        max_record_bytes: 8 * 1024 * 1024,
    };
    let owner = account
        .create_public_room_bound(temp.0.join("owner"), [10; 32], limits)
        .unwrap();
    let pin = owner.room_id();
    let raw = owner.genesis().encode();
    let home = temp.0.join("joined");
    assert!(matches!(
        account.join_public_room_bound(&home, &raw, pin, [0; 32], limits),
        Err(Error::Bounds)
    ));
    assert!(!home.exists());
    let mut joined = account
        .join_public_room_bound(&home, &raw, pin, [11; 32], limits)
        .unwrap();
    assert_eq!(joined.creation_nonce(), [11; 32]);
    assert_eq!(joined.genesis().encode(), raw);
    assert!(!joined.status().unwrap().created_here);
    assert_eq!(
        joined.set_writers([2; 16], vec![account.public_key()]),
        Err(Error::NotOwner)
    );
    let author = joined.author_key();
    drop(account);
    drop(owner);
    assert!(matches!(
        Identity::open(&identity_path),
        Err(IdentityError::Busy)
    ));
    drop(joined);
    let account = AccountController::new(Identity::open(&identity_path).unwrap());
    let joined = account.open_public_room(&home, pin).unwrap();
    assert_eq!(joined.creation_nonce(), [11; 32]);
    assert_eq!(joined.author_key(), author);
    assert_eq!(joined.genesis().encode(), raw);
}
