// Included by tests.rs to keep the native controller's restart regression focused.
#[test]
fn pending_seal_replay_survives_restart_and_bounded_passes() {
    let root = TempDir::new().unwrap();
    let owner_account = account(&root, "owner-account");
    let reader_account = account(&root, "reader-account");
    let mut owner =
        RoomSession::create(owner_account.clone(), root.path().join("owner"), limits()).unwrap();
    let home = root.path().join("reader");
    let pin = owner.room_id();
    let mut reader = RoomSession::join(
        reader_account.clone(),
        &home,
        &owner.genesis().encode(),
        pin,
        limits(),
    )
    .unwrap();
    let writers = vec![
        owner_account.public_key(),
        owner.author_key(),
        reader.author_key(),
    ];
    let admission = owner.set_writers([251; 16], writers.clone()).unwrap();
    reader.observe_policy(&admission.bytes).unwrap();
    let local = reader.send([240; 16], "retained reader operation", 1).unwrap();
    assert_eq!(local.state, OperationState::Provisional);
    owner.receive_event(&local.bytes).unwrap();

    let mut frames = Vec::new();
    for n in 1u16..=160 {
        let mut operation = [0; 16];
        operation[..2].copy_from_slice(&n.to_be_bytes());
        frames.push(
            owner
                .send(operation, "owner chain", u64::from(n))
                .unwrap()
                .bytes,
        );
    }
    for frame in &frames[..3] {
        reader.receive_event(frame).unwrap();
    }
    assert!(reader.status().unwrap().can_send);
    let closing = owner.set_writers([252; 16], writers).unwrap();
    assert_eq!(closing.state, OperationState::PendingHistory);
    let signed_seal = SignedPolicy::decode(&closing.bytes).unwrap().verify().unwrap();
    assert_eq!(signed_seal.claims().revision, 2);
    let owner_terminal = SignedEvent::decode(&frames[159]).unwrap().verify().unwrap();
    let owner_seal = signed_seal
        .claims()
        .sealed_heads
        .iter()
        .find(|seal| seal.author == owner.author_key())
        .unwrap();
    assert_eq!(owner_seal.sequence, 160);
    assert_eq!(owner_seal.event, owner_terminal.id());
    let pending = reader.observe_policy(&closing.bytes).unwrap();
    assert_eq!(pending.current.revision, 1);
    assert_eq!(pending.pending.unwrap().id, signed_seal.id());
    assert_eq!(
        reader
            .store
            .read(raw_key(POLICY, *signed_seal.id().as_bytes()))
            .unwrap()
            .unwrap(),
        closing.bytes
    );

    // The authenticated seal is retained, not admitted on numeric sequence
    // alone. Local exact retries keep their signed bytes while fresh sends stop.
    let check_pending = |reader: &mut RoomSession| {
        let status = reader.status().unwrap();
        assert_eq!(status.policy.revision, 1);
        assert_eq!(status.pending_policy.unwrap().id, signed_seal.id());
        assert!(status.reconciliation_pending);
        assert!(!status.can_send);
        assert_eq!(
            reader.send([241; 16], "must wait", 2),
            Err(Error::Protocol(vhalla_direct_room::Error::PolicyPending))
        );
        let retry = reader.send([240; 16], "retained reader operation", 999).unwrap();
        assert!(retry.exact_retry);
        assert_eq!(retry.bytes, local.bytes);
        assert_eq!(retry.state, OperationState::PendingHistory);
        assert!(all_messages(reader)
            .iter()
            .all(|message| message.visibility == Visibility::Incomplete));
    };
    check_pending(&mut reader);
    drop(reader);
    let mut reader = RoomSession::open(reader_account.clone(), &home, pin).unwrap();
    check_pending(&mut reader);

    // Retain later exact signed frames in bounded input batches, deliberately
    // withholding sequence 4. Neither replay nor reopen can leap the gap.
    for frame in &frames[4..68] {
        let before = reader.frame_reads;
        reader.receive_event(frame).unwrap();
        assert!(reader.frame_reads - before <= MAX_REPLAY_FRAMES + MAX_CACHED_AUTHORS + 4);
    }
    check_pending(&mut reader);
    drop(reader);
    let mut reader = RoomSession::open(reader_account.clone(), &home, pin).unwrap();
    check_pending(&mut reader);
    for batch in frames[68..].chunks(16) {
        for frame in batch {
            let before = reader.frame_reads;
            reader.receive_event(frame).unwrap();
            assert!(reader.frame_reads - before <= MAX_REPLAY_FRAMES + MAX_CACHED_AUTHORS + 4);
        }
        check_pending(&mut reader);
    }
    assert!(reader.indexed_event(owner.author_key(), 4).unwrap().is_none());

    // A corrupted signature is not a signed fork: it must never occupy the
    // missing slot, change the durable accounting or advance the policy.
    let mut bad = frames[3].clone();
    *bad.last_mut().unwrap() ^= 1;
    let before = reader.status().unwrap().storage;
    assert_eq!(
        reader.receive_event(&bad),
        Err(Error::Protocol(vhalla_direct_room::Error::Signature))
    );
    assert_eq!(reader.status().unwrap().storage, before);
    assert!(reader
        .store
        .read(raw_key(
            EVENT,
            *SignedEvent::decode(&frames[3]).unwrap().id().as_bytes()
        ))
        .unwrap()
        .is_none());
    assert!(reader.indexed_event(owner.author_key(), 4).unwrap().is_none());
    check_pending(&mut reader);

    let before = reader.frame_reads;
    reader.receive_event(&frames[3]).unwrap();
    assert!(reader.frame_reads - before <= MAX_REPLAY_FRAMES + MAX_CACHED_AUTHORS + 4);
    // The 157-frame suffix cannot be sealed in the first 128-frame pass.
    assert_eq!(reader.status().unwrap().policy.revision, 1);
    assert!(reader.status().unwrap().pending_policy.is_some());
    let mut passes = 0;
    while reader.status().unwrap().reconciliation_pending {
        let before = reader.frame_reads;
        reader.reconcile().unwrap();
        assert!(reader.frame_reads - before <= MAX_REPLAY_FRAMES + MAX_CACHED_AUTHORS + 4);
        passes += 1;
        assert!(passes <= 5, "bounded reconciliation must converge");
    }
    assert!(passes >= 1);
    let status = reader.status().unwrap();
    assert_eq!(status.policy.revision, 2);
    assert_eq!(status.policy.id, signed_seal.id());
    assert!(status.pending_policy.is_none());
    assert!(status.can_send);
    let messages = all_messages(&mut reader);
    assert_eq!(messages.len(), 161);
    assert!(messages
        .iter()
        .all(|message| message.visibility == Visibility::OwnerSealed));
    let final_retry = reader.send([240; 16], "retained reader operation", 999).unwrap();
    assert_eq!(final_retry.bytes, local.bytes);
    assert_eq!(final_retry.state, OperationState::OwnerSealed);

    drop(reader);
    let mut reader = RoomSession::open(reader_account, &home, pin).unwrap();
    assert_eq!(reader.status().unwrap().policy.id, signed_seal.id());
    assert_eq!(
        reader
            .store
            .read(raw_key(POLICY, *signed_seal.id().as_bytes()))
            .unwrap()
            .unwrap(),
        closing.bytes
    );
    assert_eq!(
        reader
            .store
            .read(raw_key(EVENT, *owner_terminal.id().as_bytes()))
            .unwrap()
            .unwrap(),
        frames[159]
    );
    let retry_after_open = reader.send([240; 16], "retained reader operation", 999).unwrap();
    assert_eq!(retry_after_open.bytes, local.bytes);
    assert_eq!(retry_after_open.state, OperationState::OwnerSealed);
    assert!(all_messages(&mut reader)
        .iter()
        .all(|message| message.visibility == Visibility::OwnerSealed));
}
