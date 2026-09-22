use super::*;

#[test]
fn actual_two_member_encryption_restart_and_removal() {
    roundtrip().unwrap();
}

#[test]
fn failed_sender_commit_releases_nothing_and_competing_base_loses() {
    let (mut alice, mut bob, _) = two_members().unwrap();
    let before = alice.image.clone();
    let draft = b"private draft must not escape on refusal";
    assert!(matches!(
        alice.send([10; 16], draft, Fault::BeforeCommit),
        Err(Error::CommitRefused)
    ));
    assert!(alice.image == before);
    assert!(
        alice
            .retained([10; 16], digest(Kind::Application, draft))
            .unwrap()
            .is_none()
    );

    let first = alice.stage_send([10; 16], draft).unwrap();
    let second = alice.stage_send([11; 16], b"competing draft").unwrap();
    alice.commit(first, Fault::None).unwrap();
    let committed = alice.image.clone();
    assert!(matches!(
        alice.commit(second, Fault::None),
        Err(Error::Conflict)
    ));
    assert!(alice.image == committed);
    assert!(
        alice
            .retained([11; 16], digest(Kind::Application, b"competing draft"))
            .unwrap()
            .is_none()
    );

    let sent = alice.send([10; 16], draft, Fault::None).unwrap();
    assert_eq!(bob.receive(&sent[0].bytes, Fault::None).unwrap(), draft);
    assert!(matches!(
        alice.send([10; 16], b"changed request", Fault::None),
        Err(Error::Conflict)
    ));
    assert!(alice.image == committed);
}

#[test]
fn uncertain_sender_commit_requires_reopen_then_exact_ciphertext_retry() {
    let (mut alice, mut bob, _) = two_members().unwrap();
    let before = alice.image.clone();
    let draft = b"one committed ciphertext for an uncertain write";
    assert!(matches!(
        alice.send([12; 16], draft, Fault::AfterCommit),
        Err(Error::NeedsReopen)
    ));
    assert!(alice.image != before);
    assert!(matches!(
        alice.send([12; 16], draft, Fault::None),
        Err(Error::NeedsReopen)
    ));
    alice.reopen().unwrap();
    let committed = alice.image.clone();
    let sent = alice.send([12; 16], draft, Fault::None).unwrap();
    assert!(alice.image == committed);
    alice.reopen().unwrap();
    let retry = alice.send([12; 16], draft, Fault::None).unwrap();
    assert_eq!(sent[0].bytes, retry[0].bytes);
    assert_eq!(bob.receive(&retry[0].bytes, Fault::None).unwrap(), draft);
}

#[test]
fn receive_inbox_and_ratchet_commit_together_before_plaintext_release() {
    let (mut alice, mut bob, _) = two_members().unwrap();
    let draft = b"receiver plaintext remains quarantined";
    let sent = alice.send([13; 16], draft, Fault::None).unwrap();
    assert!(!sent[0].bytes.windows(draft.len()).any(|part| part == draft));
    let before = bob.image.clone();
    let hash = Sha256::digest(&sent[0].bytes).into();
    assert!(matches!(
        bob.receive(&sent[0].bytes, Fault::BeforeCommit),
        Err(Error::CommitRefused)
    ));
    assert!(bob.image == before);
    assert!(bob.inbox(hash).unwrap().is_none());

    assert!(matches!(
        bob.receive(&sent[0].bytes, Fault::AfterCommit),
        Err(Error::NeedsReopen)
    ));
    assert!(matches!(bob.inbox(hash), Err(Error::NeedsReopen)));
    bob.reopen().unwrap();
    let committed = bob.image.clone();
    assert_eq!(bob.receive(&sent[0].bytes, Fault::None).unwrap(), draft);
    assert!(bob.image == committed);
    assert!(
        !bob.image
            .ciphertext
            .windows(draft.len())
            .any(|part| part == draft)
    );
    assert_eq!(bob.load().unwrap().state.inbox.len(), 1);
}

#[test]
fn key_package_publication_and_welcome_consumption_are_atomic_and_single_use() {
    let room = random().unwrap();
    let mut alice = Device::fresh(room, b"synthetic-alice").unwrap();
    let mut bob = Device::fresh(room, b"synthetic-bob").unwrap();
    alice.create_group().unwrap();
    let before_package = bob.image.clone();
    assert!(matches!(
        bob.key_package([14; 16], Fault::BeforeCommit),
        Err(Error::CommitRefused)
    ));
    assert!(bob.image == before_package);
    let package = bob.key_package([14; 16], Fault::None).unwrap();
    let parsed = KeyPackageIn::tls_deserialize_exact(&package[0].bytes)
        .unwrap()
        .validate(
            bob.load().unwrap().provider.crypto(),
            ProtocolVersion::Mls10,
        )
        .unwrap();
    let package_ref = parsed
        .hash_ref(bob.load().unwrap().provider.crypto())
        .unwrap();
    let added = alice.add([15; 16], &package[0].bytes).unwrap();
    let welcome = &added
        .iter()
        .find(|item| item.kind == Kind::Welcome)
        .unwrap()
        .bytes;
    let before_join = bob.image.clone();
    assert!(matches!(
        bob.join(welcome, Fault::BeforeCommit),
        Err(Error::CommitRefused)
    ));
    assert!(bob.image == before_join);
    bob.join(welcome, Fault::None).unwrap();
    bob.reopen().unwrap();
    let work = bob.load().unwrap();
    let retained: Option<KeyPackageBundle> = openmls_traits::storage::StorageProvider::key_package(
        work.provider.storage(),
        &package_ref,
    )
    .unwrap();
    assert!(retained.is_none());
    let config = MlsGroupJoinConfig::default();
    assert!(
        StagedWelcome::new_from_welcome(
            &work.provider,
            &config,
            decode_welcome(welcome).unwrap(),
            None
        )
        .is_err()
    );
    let fresh_device = Device::fresh(room, b"same-account-fresh-device").unwrap();
    assert!(
        StagedWelcome::new_from_welcome(
            &fresh_device.load().unwrap().provider,
            &config,
            decode_welcome(welcome).unwrap(),
            None
        )
        .is_err()
    );
}

#[test]
fn encrypted_state_rejects_changed_revision_scope_key_nonce_and_ciphertext() {
    let (alice, _, _) = two_members().unwrap();
    for field in 0..4 {
        let mut modified = alice.image.clone();
        match field {
            0 => modified.revision += 1,
            1 => modified.nonce[0] ^= 1,
            2 => modified.ciphertext[0] ^= 1,
            _ => {
                modified.ciphertext.pop();
            }
        }
        assert!(unseal(&alice.key, &alice.room, &modified).is_err());
    }
    let mut wrong_room = alice.room;
    wrong_room[0] ^= 1;
    assert!(unseal(&alice.key, &wrong_room, &alice.image).is_err());
    let wrong_key = random().unwrap();
    assert!(unseal(&wrong_key, &alice.room, &alice.image).is_err());
    let mut undersized = alice.image.clone();
    undersized.ciphertext.truncate(15);
    assert!(matches!(
        unseal(&alice.key, &alice.room, &undersized),
        Err(Error::Bounds)
    ));
}

#[test]
fn malformed_foreign_or_oversized_wire_preserves_committed_state() {
    let (mut alice, mut bob, _) = two_members().unwrap();
    let (mut foreign, _, _) = two_members().unwrap();
    let sent = alice.send([16; 16], b"valid", Fault::None).unwrap();
    let before = bob.image.clone();
    let mut trailing = sent[0].bytes.clone();
    trailing.push(0);
    assert!(bob.receive(&trailing, Fault::None).is_err());
    let mut forged = sent[0].bytes.clone();
    let last = forged.len() - 1;
    forged[last] ^= 1;
    assert!(bob.receive(&forged, Fault::None).is_err());
    let wrong_group = foreign.send([16; 16], b"other room", Fault::None).unwrap();
    assert!(matches!(
        bob.receive(&wrong_group[0].bytes, Fault::None),
        Err(Error::Scope)
    ));
    assert!(matches!(
        bob.receive(&vec![0; MAX_WIRE + 1], Fault::None),
        Err(Error::Bounds)
    ));
    assert!(bob.image == before);
    assert_eq!(bob.receive(&sent[0].bytes, Fault::None).unwrap(), b"valid");
}
