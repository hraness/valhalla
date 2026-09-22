#![cfg(all(unix, feature = "room-activity"))]
//! Typed activity signatures retain native custody and exact author attribution.
use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf};
use vhalla_identity::Identity;
use vhalla_room_activity::{Error, SignedEvent, UnsignedEvent};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!(
            "vhalla-identity-activity-{:032x}",
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

fn request(author: [u8; 32]) -> UnsignedEvent {
    // Canonical version-one fixture decoded through the public activity API.
    // No fixture key is imported or exported by the native custodian.
    let text = b"local typed activity signature";
    let mut frame = b"VHRA\x01".to_vec();
    frame.extend([7; 32]); // immutable network
    frame.extend(77u128.to_be_bytes()); // realm
    frame.extend([5; 32]); // directory
    frame.extend([8; 32]); // full room genesis
    frame.extend([9; 32]); // policy record
    frame.extend(author);
    frame.extend(1u64.to_be_bytes());
    frame.extend([0; 32]); // first sequence has no previous event
    frame.extend(1234u64.to_be_bytes());
    frame.push(0); // Text
    frame.extend((text.len() as u16).to_be_bytes());
    frame.extend(text);
    UnsignedEvent::decode(&frame).unwrap()
}

#[test]
fn activity_custodian_signs_exact_request_and_reopens_same_identity() {
    let dir = Temp::new();
    let path = dir.0.join("author");
    let identity = Identity::create_new(&path).unwrap();
    let author = identity.public_key();
    let unsigned = request(author);
    let claims = unsigned.claims().clone();
    let id = unsigned.id();
    let signed = identity.sign_activity(unsigned).unwrap();
    let raw = signed.encode();
    let verified = SignedEvent::decode(&raw).unwrap().verify().unwrap();
    assert_eq!(verified.claims(), &claims);
    assert_eq!(verified.id(), id);
    assert_eq!(verified.encode(), raw);
    let mut tampered = raw.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(matches!(
        SignedEvent::decode(&tampered).unwrap().verify(),
        Err(Error::Signature)
    ));
    drop(identity);
    let reopened = Identity::open(&path).unwrap();
    assert_eq!(reopened.public_key(), author);
    assert_eq!(
        reopened.sign_activity(request(author)).unwrap().encode(),
        raw
    );
    let mut entries: Vec<_> = fs::read_dir(&path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    entries.sort();
    assert_eq!(entries, ["identity", "lock"]);
    assert_eq!(fs::metadata(path.join("identity")).unwrap().len(), 72);
}

#[test]
fn activity_custodian_refuses_another_author_without_rewriting_claims() {
    let dir = Temp::new();
    let first = Identity::create_new(dir.0.join("first")).unwrap();
    let second = Identity::create_new(dir.0.join("second")).unwrap();
    let claimed = second.public_key();
    assert_ne!(first.public_key(), claimed);
    assert!(matches!(
        first.sign_activity(request(claimed)),
        Err(Error::Signer)
    ));
    let accepted = second
        .sign_activity(request(claimed))
        .unwrap()
        .verify()
        .unwrap();
    assert_eq!(accepted.claims().author, claimed);
    // Refusal does not damage the existing custodian's typed signing path.
    assert_eq!(
        first
            .sign_activity(request(first.public_key()))
            .unwrap()
            .verify()
            .unwrap()
            .claims()
            .author,
        first.public_key()
    );
}
