#![cfg(all(unix, feature = "direct-room"))]
//! Typed direct-room signing keeps the existing account custody boundary.
use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf};
use vhalla_direct_room::*;
use vhalla_identity::{Identity, IdentityError};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!(
            "vhalla-direct-identity-{:032x}",
            u128::from_be_bytes(nonce)
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
fn direct_signatures_keep_identity_private_and_exclusively_locked() {
    let temp = Temp::new();
    let path = temp.0.join("owner");
    let identity = Identity::create_new(&path).unwrap();
    let owner = identity.public_key();
    assert!(matches!(Identity::open(&path), Err(IdentityError::Busy)));
    let genesis = identity
        .sign_direct_genesis(
            UnsignedGenesis::new(GenesisClaims {
                owner,
                nonce: [7; 32],
                writers: vec![owner],
            })
            .unwrap(),
        )
        .unwrap();
    let room = genesis.id();
    let mut policy = PolicyState::new(genesis.verify_pin(room).unwrap());
    let request = UnsignedEvent::new(EventClaims {
        room,
        policy: policy.head().id,
        author: owner,
        sequence: 1,
        previous: EventId::ZERO,
        created_at: 100,
        text: Text::new("typed message").unwrap(),
    })
    .unwrap();
    let expected = request.id();
    let event = identity
        .sign_direct_event(request)
        .unwrap()
        .verify()
        .unwrap();
    assert_eq!(event.id(), expected);
    let update = identity
        .sign_direct_policy(
            UnsignedPolicy::new(PolicyClaims {
                room,
                owner,
                revision: 1,
                previous: policy.head().id,
                writers: vec![owner],
                sealed_heads: vec![SealHead {
                    author: owner,
                    sequence: 1,
                    event: event.id(),
                }],
            })
            .unwrap(),
        )
        .unwrap();
    let mut pending = policy.prepare_update(update).unwrap();
    pending
        .push_seal(&owner, std::slice::from_ref(&event))
        .unwrap();
    let closed = policy.commit_after_persist(pending).unwrap();
    let HistoryRequirement::Verify(mut proof) = closed.history_requirement(event.clone()).unwrap()
    else {
        panic!("missing seal");
    };
    proof.push(std::slice::from_ref(&event)).unwrap();
    assert_eq!(proof.finish().unwrap().event(), &event);
    drop(identity);
    assert_eq!(Identity::open(&path).unwrap().public_key(), owner);
    let mut entries: Vec<_> = fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    entries.sort();
    assert_eq!(entries, ["identity", "lock"]);
}

#[test]
fn direct_signers_refuse_foreign_claims_without_rewriting_them() {
    let temp = Temp::new();
    let first = Identity::create_new(temp.0.join("first")).unwrap();
    let other = Identity::create_new(temp.0.join("other")).unwrap();
    let claimed = other.public_key();
    let request = UnsignedGenesis::new(GenesisClaims {
        owner: claimed,
        nonce: [8; 32],
        writers: vec![claimed],
    })
    .unwrap();
    assert_eq!(
        first.sign_direct_genesis(request.clone()),
        Err(Error::Signer)
    );
    let genesis = other.sign_direct_genesis(request).unwrap();
    let room = genesis.id();
    let request = UnsignedPolicy::new(PolicyClaims {
        room,
        owner: claimed,
        revision: 1,
        previous: room.initial_policy(),
        writers: vec![claimed],
        sealed_heads: vec![],
    })
    .unwrap();
    assert_eq!(first.sign_direct_policy(request), Err(Error::Signer));
    let request = UnsignedEvent::new(EventClaims {
        room,
        policy: room.initial_policy(),
        author: claimed,
        sequence: 1,
        previous: EventId::ZERO,
        created_at: 0,
        text: Text::new("foreign author").unwrap(),
    })
    .unwrap();
    assert_eq!(first.sign_direct_event(request), Err(Error::Signer));
}
