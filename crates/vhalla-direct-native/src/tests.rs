use super::{codec::*, *};
use tempfile::TempDir;
use vhalla_direct_room::{
    EventClaims, EventId, PolicyClaims, SignedEvent, SignedPolicy, Text, UnsignedEvent,
    UnsignedPolicy,
};

fn limits() -> Limits {
    Limits {
        max_records: 10_000,
        max_record_bytes: 8 * 1024 * 1024,
    }
}
fn account(root: &TempDir, name: &str) -> Arc<Identity> {
    Arc::new(Identity::create_new(root.path().join(name)).unwrap())
}
fn reserve_event(session: &mut RoomSession, operation: [u8; 16], text: &str) -> Vec<u8> {
    let head = session
        .author_chain(session.author_key(), &session.policy.clone())
        .unwrap()
        .authoring_head(&session.policy)
        .unwrap();
    let unsigned = UnsignedEvent::new(EventClaims {
        room: session.room_id(),
        policy: session.policy.head().id,
        author: session.author_key(),
        sequence: head.sequence + 1,
        previous: head.event,
        created_at: 9,
        text: Text::new(text).unwrap(),
    })
    .unwrap();
    let reservation = Reservation {
        operation,
        kind: EVENT,
        unsigned: unsigned.encode(),
    };
    let mut image = session.image.clone();
    image.pending_event = Some(operation);
    session
        .publish(
            image,
            &[record(operation_key(RESERVATION, operation), &reservation.encode()).unwrap()],
            false,
        )
        .unwrap();
    unsigned.encode()
}
fn all_messages(session: &mut RoomSession) -> Vec<Message> {
    let mut result = Vec::new();
    let mut after = 0;
    loop {
        let page = session.messages(after, 7).unwrap();
        result.extend(page.messages);
        let Some(next) = page.next else {
            break;
        };
        after = next;
    }
    result
}

#[test]
fn create_exact_retry_changed_intent_reopen_and_seals() {
    let root = TempDir::new().unwrap();
    let account = account(&root, "account");
    let home = root.path().join("room");
    let mut room = RoomSession::create(account.clone(), &home, limits()).unwrap();
    let pin = room.room_id();
    let author = room.author_key();
    assert!(room.status().unwrap().can_send);
    let first = room.send([1; 16], "hello", 7).unwrap();
    assert_eq!(first.state, OperationState::Provisional);
    let retry = room.send([1; 16], "hello", 999).unwrap();
    assert!(retry.exact_retry);
    assert_eq!(retry.bytes, first.bytes);
    assert_eq!(
        room.send([1; 16], "different", 7),
        Err(Error::OperationConflict)
    );
    let control = room
        .set_writers([2; 16], vec![account.public_key(), author])
        .unwrap();
    assert_eq!(control.state, OperationState::PolicyApplied);
    assert_eq!(
        room.send([1; 16], "hello", 0).unwrap().state,
        OperationState::OwnerSealed
    );
    drop(room);
    let mut room = RoomSession::open(account, &home, pin).unwrap();
    assert_eq!(room.author_key(), author);
    let second = room.send([3; 16], "after reopen", 8).unwrap();
    let signed = SignedEvent::decode(&second.bytes)
        .unwrap()
        .verify()
        .unwrap();
    assert_eq!(signed.claims().sequence, 2);
    assert_eq!(all_messages(&mut room).len(), 2);
}

#[test]
fn join_admission_exchange_revocation_and_reserved_needs_repost() {
    let root = TempDir::new().unwrap();
    let owner_account = account(&root, "owner-account");
    let member_account = account(&root, "member-account");
    let mut owner =
        RoomSession::create(owner_account.clone(), root.path().join("owner"), limits()).unwrap();
    let mut member = RoomSession::join(
        member_account.clone(),
        root.path().join("member"),
        &owner.genesis().encode(),
        owner.room_id(),
        limits(),
    )
    .unwrap();
    assert!(!member.status().unwrap().can_send);
    assert!(matches!(
        member.send([1; 16], "unadmitted", 1),
        Err(Error::Protocol(vhalla_direct_room::Error::Author))
    ));
    let admission = owner
        .set_writers(
            [1; 16],
            vec![
                owner_account.public_key(),
                owner.author_key(),
                member.author_key(),
            ],
        )
        .unwrap();
    member.observe_policy(&admission.bytes).unwrap();
    assert!(member.status().unwrap().can_send);
    let message = member.send([2; 16], "from member", 2).unwrap();
    assert_eq!(
        owner.receive_event(&message.bytes).unwrap().visibility,
        Visibility::Provisional
    );
    assert!(owner.receive_event(&message.bytes).unwrap().duplicate);
    let response = owner.send([3; 16], "from owner device", 3).unwrap();
    member.receive_event(&response.bytes).unwrap();
    let reserved = reserve_event(&mut member, [4; 16], "offline pending text");
    let removal = owner
        .set_writers(
            [5; 16],
            vec![owner_account.public_key(), owner.author_key()],
        )
        .unwrap();
    member.observe_policy(&removal.bytes).unwrap();
    let old_retry = member.send([4; 16], "offline pending text", 555).unwrap();
    assert_eq!(&old_retry.bytes[..old_retry.bytes.len() - 64], reserved);
    assert_eq!(old_retry.state, OperationState::NeedsRepost);
    assert!(!member.status().unwrap().can_send);
    assert_eq!(
        member.send([4; 16], "changed", 9),
        Err(Error::OperationConflict)
    );
    let pin = member.room_id();
    drop(member);
    let mut member = RoomSession::open(member_account, root.path().join("member"), pin).unwrap();
    assert_eq!(
        member
            .send([4; 16], "offline pending text", 0)
            .unwrap()
            .state,
        OperationState::NeedsRepost
    );
}

#[test]
fn joining_with_owner_account_never_grants_owner_role_or_reuses_author() {
    let root = TempDir::new().unwrap();
    let account = account(&root, "account");
    let owner = RoomSession::create(account.clone(), root.path().join("owner"), limits()).unwrap();
    let mut joined = RoomSession::join(
        account.clone(),
        root.path().join("joined"),
        &owner.genesis().encode(),
        owner.room_id(),
        limits(),
    )
    .unwrap();
    assert_ne!(owner.author_key(), joined.author_key());
    assert!(!joined.status().unwrap().created_here);
    assert_eq!(
        joined.set_writers([1; 16], vec![account.public_key()]),
        Err(Error::NotOwner)
    );
    assert!(!joined.status().unwrap().can_send);
}

#[test]
fn intact_account_author_and_room_custody_locks_are_retained() {
    let root = TempDir::new().unwrap();
    let account = account(&root, "account");
    let home = root.path().join("room");
    let room = RoomSession::create(account.clone(), &home, limits()).unwrap();
    let pin = room.room_id();
    assert!(RoomSession::open(account.clone(), &home, pin).is_err());
    assert!(Identity::open(home.join("author")).is_err());
    assert!(Identity::open(root.path().join("account")).is_err());
    drop(account);
    assert!(Identity::open(root.path().join("account")).is_err());
    drop(room);
    assert!(Identity::open(home.join("author")).is_ok());
    assert!(Identity::open(root.path().join("account")).is_ok());
}

#[test]
fn interruption_after_reservation_reconciles_only_exact_bytes() {
    let root = TempDir::new().unwrap();
    let account = account(&root, "account");
    let home = root.path().join("room");
    let mut room = RoomSession::create(account.clone(), &home, limits()).unwrap();
    let pin = room.room_id();
    let unsigned = reserve_event(&mut room, [7; 16], "reserved before interruption");
    assert_eq!(
        room.send([8; 16], "another", 1),
        Err(Error::OperationPending)
    );
    drop(room);
    let mut room = RoomSession::open(account.clone(), &home, pin).unwrap();
    assert_eq!(
        room.status().unwrap().pending_event_operation,
        Some([7; 16])
    );
    room.reconcile().unwrap();
    let result = room
        .send([7; 16], "reserved before interruption", 999)
        .unwrap();
    assert_eq!(&result.bytes[..result.bytes.len() - 64], unsigned);
    let policy = UnsignedPolicy::new(PolicyClaims {
        room: pin,
        owner: account.public_key(),
        revision: 1,
        previous: room.policy.head().id,
        writers: {
            let mut keys = vec![account.public_key(), room.author_key()];
            keys.sort_unstable();
            keys
        },
        sealed_heads: vec![],
    })
    .unwrap();
    let reservation = Reservation {
        operation: [9; 16],
        kind: POLICY,
        unsigned: policy.encode(),
    };
    let mut image = room.image.clone();
    image.pending_policy = Some([9; 16]);
    room.publish(
        image,
        &[record(operation_key(RESERVATION, [9; 16]), &reservation.encode()).unwrap()],
        true,
    )
    .unwrap();
    drop(room);
    let mut room = RoomSession::open(account, &home, pin).unwrap();
    room.reconcile().unwrap();
    assert_eq!(room.status().unwrap().policy.revision, 1);
    assert_eq!(
        room.send([7; 16], "reserved before interruption", 0)
            .unwrap()
            .state,
        OperationState::NeedsRepost
    );
}

#[test]
fn old_owner_forks_survive_reopen_and_fence_fresh_authoring() {
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
    let first = owner
        .set_writers(
            [1; 16],
            vec![
                owner_account.public_key(),
                owner.author_key(),
                reader.author_key(),
            ],
        )
        .unwrap();
    reader.observe_policy(&first.bytes).unwrap();
    let second = owner
        .set_writers(
            [2; 16],
            vec![
                owner_account.public_key(),
                owner.author_key(),
                reader.author_key(),
            ],
        )
        .unwrap();
    reader.observe_policy(&second.bytes).unwrap();
    let mut fork_claims = SignedPolicy::decode(&first.bytes)
        .unwrap()
        .unverified_claims()
        .clone();
    fork_claims.writers = vec![owner_account.public_key()];
    let fork = owner_account
        .sign_direct_policy(UnsignedPolicy::new(fork_claims).unwrap())
        .unwrap();
    assert!(reader.observe_policy(&fork.encode()).unwrap().forked);
    assert!(!reader.status().unwrap().can_send);
    drop(reader);
    let mut reader = RoomSession::open(reader_account, &home, pin).unwrap();
    assert!(reader.status().unwrap().owner_forked);
    assert!(matches!(
        reader.send([3; 16], "blocked", 0),
        Err(Error::Protocol(vhalla_direct_room::Error::Fork))
    ));
}

#[test]
fn unknown_local_author_signature_fences_author_but_preserves_owner_recovery() {
    let root = TempDir::new().unwrap();
    let account = account(&root, "account");
    let home = root.path().join("room");
    let mut room = RoomSession::create(account.clone(), &home, limits()).unwrap();
    let pin = room.room_id();
    let rogue = room
        .author
        .sign_direct_event(
            UnsignedEvent::new(EventClaims {
                room: pin,
                policy: room.policy.head().id,
                author: room.author_key(),
                sequence: 1,
                previous: EventId::ZERO,
                created_at: 1,
                text: Text::new("unknown publication").unwrap(),
            })
            .unwrap(),
        )
        .unwrap();
    room.receive_event(&rogue.encode()).unwrap();
    assert!(room.status().unwrap().author_custody_lost);
    assert_eq!(room.send([1; 16], "unsafe reset", 2), Err(Error::ReadOnly));
    assert_eq!(
        room.set_writers([2; 16], vec![account.public_key()])
            .unwrap()
            .state,
        OperationState::PolicyApplied
    );
    drop(room);
    let mut room = RoomSession::open(account, &home, pin).unwrap();
    assert!(room.status().unwrap().author_custody_lost);
}

#[test]
fn bounded_pages_replay_and_public_filter_excludes_unsigned_reservations() {
    let root = TempDir::new().unwrap();
    let account = account(&root, "account");
    let home = root.path().join("room");
    let mut room = RoomSession::create(account.clone(), &home, limits()).unwrap();
    let pin = room.room_id();
    for n in 1..=9 {
        room.send([n; 16], &format!("message {n}"), u64::from(n))
            .unwrap();
    }
    reserve_event(&mut room, [10; 16], "unsigned private operation intent");
    let mut cursor = 0;
    let mut public = 0;
    loop {
        let page = room.replicated_records(cursor, 3).unwrap();
        assert!(page.records.len() <= 3);
        for record in page.records {
            assert!(!String::from_utf8_lossy(&record.bytes)
                .contains("unsigned private operation intent"));
            public += 1;
        }
        let Some(next) = page.next else {
            break;
        };
        cursor = next;
    }
    assert_eq!(public, 10); // Genesis and nine signed events.
    drop(room);
    let mut room = RoomSession::open(account, &home, pin).unwrap();
    assert_eq!(all_messages(&mut room).len(), 9);
    assert_eq!(
        room.status().unwrap().pending_event_operation,
        Some([10; 16])
    );
}

#[test]
fn capacity_fence_retains_the_triggering_owner_record_across_restart() {
    let root = TempDir::new().unwrap();
    let owner_account = account(&root, "owner-account");
    let member_account = account(&root, "member-account");
    let mut owner =
        RoomSession::create(owner_account.clone(), root.path().join("owner"), limits()).unwrap();
    let home = root.path().join("member");
    let pin = owner.room_id();
    let small = Limits {
        max_records: 80,
        max_record_bytes: 1024 * 1024,
    };
    let mut member = RoomSession::join(
        member_account.clone(),
        &home,
        &owner.genesis().encode(),
        pin,
        small,
    )
    .unwrap();
    let mut blocked = None;
    for n in 1..=24 {
        let update = owner
            .set_writers(
                [n; 16],
                vec![
                    owner_account.public_key(),
                    owner.author_key(),
                    member.author_key(),
                ],
            )
            .unwrap();
        if member.observe_policy(&update.bytes) == Err(Error::Capacity) {
            blocked = Some(update.bytes);
            break;
        }
    }
    let blocked = blocked.expect("finite capacity must refuse");
    assert_eq!(member.image.blocked.as_ref().unwrap().as_bytes(), blocked);
    assert!(member.status().unwrap().capacity_fenced);
    assert!(!member.status().unwrap().can_send);
    assert_eq!(
        member.observe_policy(b"must not authenticate another observation"),
        Err(Error::Capacity)
    );
    assert_eq!(
        member.receive_event(b"must not authenticate another event"),
        Err(Error::Capacity)
    );
    drop(member);
    let mut member = RoomSession::open(member_account, &home, pin).unwrap();
    assert!(member.status().unwrap().capacity_fenced);
    assert_eq!(member.image.blocked.as_ref().unwrap().as_bytes(), blocked);
    assert!(member.status().unwrap().pending_policy.is_some());
}

#[test]
fn complete_send_capacity_is_checked_before_reservation_and_reported_in_status() {
    let root = TempDir::new().unwrap();
    let account = account(&root, "account");
    let mut count_limited = RoomSession::create(
        account.clone(),
        root.path().join("count-limited"),
        Limits {
            max_records: 80,
            max_record_bytes: 1024 * 1024,
        },
    )
    .unwrap();
    count_limited.send([1; 16], "first", 1).unwrap();
    count_limited.send([2; 16], "second", 2).unwrap();
    let before = count_limited.status().unwrap();
    assert_eq!(before.storage.records, 13);
    assert!(!before.can_send);
    assert_eq!(
        count_limited.send([3; 16], "no remaining complete slot", 3),
        Err(Error::Capacity)
    );
    let after = count_limited.status().unwrap();
    assert_eq!(before.storage, after.storage);
    assert_eq!(after.pending_event_operation, None);
    assert!(
        count_limited
            .send([1; 16], "first", 900)
            .unwrap()
            .exact_retry
    );
    assert_eq!(
        count_limited
            .set_writers(
                [4; 16],
                vec![account.public_key(), count_limited.author_key()]
            )
            .unwrap()
            .state,
        OperationState::PolicyApplied
    );

    let mut byte_limited = RoomSession::create(
        account,
        root.path().join("byte-limited"),
        Limits {
            max_records: 10_000,
            max_record_bytes: CONTROL_RESERVED_BYTES + 32 * 1024 + 1,
        },
    )
    .unwrap();
    let large = "a".repeat(vhalla_direct_room::MAX_TEXT_BYTES);
    for n in 1..=3 {
        byte_limited.send([n; 16], &large, u64::from(n)).unwrap();
    }
    let before = byte_limited.status().unwrap();
    assert!(before.can_send); // A short message still fits.
    assert_eq!(byte_limited.send([4; 16], &large, 4), Err(Error::Capacity));
    let after = byte_limited.status().unwrap();
    assert_eq!(before.storage, after.storage);
    assert_eq!(after.pending_event_operation, None);
    byte_limited.send([4; 16], "short", 4).unwrap();
}

#[test]
fn owner_fork_beyond_observation_budget_never_commits_a_branch() {
    let root = TempDir::new().unwrap();
    let owner_account = account(&root, "owner-account");
    let reader_account = account(&root, "reader-account");
    let owner =
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
    let mut source = PolicyState::new(owner.genesis().clone());
    let mut first = None;
    let mut final_update = None;
    let mut batch = Vec::new();
    // Seed valid immutable observations in bounded transactions to exercise a
    // large restart without repeating a complete replay after every fixture write.
    for revision in 1..=258 {
        let mut writers = vec![owner_account.public_key(), reader.author_key()];
        writers.sort_unstable();
        let unsigned = UnsignedPolicy::new(PolicyClaims {
            room: pin,
            owner: owner_account.public_key(),
            revision,
            previous: source.head().id,
            writers,
            sealed_heads: vec![],
        })
        .unwrap();
        let signed = owner_account.sign_direct_policy(unsigned).unwrap();
        let step = source.prepare_update(signed.clone()).unwrap();
        source.commit_after_persist(step).unwrap();
        if revision == 1 {
            first = Some(signed.clone());
        } else {
            batch.push(record(raw_key(POLICY, *signed.id().as_bytes()), &signed.encode()).unwrap());
            batch.push(
                record(
                    revision_key(OBSERVED, revision),
                    &index_bytes(&revision.to_be_bytes(), *signed.id().as_bytes()),
                )
                .unwrap(),
            );
            if batch.len() == 8 {
                reader.publish(reader.image.clone(), &batch, true).unwrap();
                batch.clear();
            }
        }
        final_update = Some(signed);
    }
    if !batch.is_empty() {
        reader.publish(reader.image.clone(), &batch, true).unwrap();
    }
    reader.reload_model().unwrap();
    assert!(reader.policy.observation_overflow());
    let mut claims = final_update.unwrap().unverified_claims().clone();
    claims.writers = vec![owner_account.public_key()];
    let fork = owner_account
        .sign_direct_policy(UnsignedPolicy::new(claims).unwrap())
        .unwrap();
    assert!(reader.observe_policy(&fork.encode()).unwrap().forked);
    reader.observe_policy(&first.unwrap().encode()).unwrap();
    assert_eq!(reader.status().unwrap().policy.revision, 0);
    assert!(reader.status().unwrap().owner_forked);
    drop(reader);
    let mut reader = RoomSession::open(reader_account, &home, pin).unwrap();
    assert!(reader.status().unwrap().owner_forked);
    assert_eq!(reader.status().unwrap().policy.revision, 0);
    let status = reader
        .expand_limits(Limits {
            max_records: 20_000,
            max_record_bytes: 16 * 1024 * 1024,
        })
        .unwrap();
    assert!(status.capacity_fenced);
    assert!(status.owner_forked);
    assert_eq!(status.policy.revision, 0);
}

#[test]
fn ordinary_ingest_and_historical_reads_do_not_replay_lifetime_history() {
    let root = TempDir::new().unwrap();
    let account = account(&root, "account");
    let mut room =
        RoomSession::create(account.clone(), root.path().join("room"), limits()).unwrap();
    let mut first = None;
    for n in 1u16..=180 {
        let mut operation = [0; 16];
        operation[..2].copy_from_slice(&n.to_be_bytes());
        let before = room.frame_reads;
        let message = room
            .send(operation, "constant work per send", u64::from(n))
            .unwrap();
        assert_eq!(message.state, OperationState::Provisional);
        assert!(room.frame_reads - before <= 8);
        if n == 1 {
            first = Some(operation);
        }
    }
    assert_eq!(room.full_replays, 0);
    let before = room.frame_reads;
    let closing = room
        .set_writers([255; 16], vec![account.public_key(), room.author_key()])
        .unwrap();
    assert_eq!(closing.state, OperationState::PendingHistory);
    assert!(room.frame_reads - before <= MAX_REPLAY_FRAMES);
    assert!(room.status().unwrap().reconciliation_pending);
    let before = room.frame_reads;
    let status = room.reconcile().unwrap();
    assert!(!status.reconciliation_pending);
    assert_eq!(status.policy.revision, 1);
    assert!(room.frame_reads - before <= MAX_REPLAY_FRAMES);
    let before = room.frame_reads;
    let retry = room
        .send(first.unwrap(), "constant work per send", 0)
        .unwrap();
    assert_eq!(retry.state, OperationState::OwnerSealed);
    assert!(room.frame_reads - before <= 3);
    let page = room.messages(0, 7).unwrap();
    assert_eq!(page.messages.len(), 7);
    assert!(page
        .messages
        .iter()
        .all(|message| message.visibility == Visibility::OwnerSealed));
    assert_eq!(room.full_replays, 0);
}

#[test]
fn filtered_pages_fill_the_output_limit_and_advance_through_metadata() {
    let root = TempDir::new().unwrap();
    let account = account(&root, "account");
    let mut room =
        RoomSession::create(account.clone(), root.path().join("room"), limits()).unwrap();
    for n in 1..=24 {
        room.set_writers([n; 16], vec![account.public_key(), room.author_key()])
            .unwrap();
    }
    let empty = room.messages(0, 32).unwrap();
    assert!(empty.messages.is_empty());
    assert_eq!(empty.next, Some(MAX_FILTER_SCAN as u64));
    let rest = room.messages(empty.next.unwrap(), 32).unwrap();
    assert!(rest.messages.is_empty());
    assert_eq!(rest.next, None);
    let page = room.replicated_records(0, 7).unwrap();
    assert_eq!(page.records.len(), 7);
    let cursor = page.next.unwrap();
    assert_eq!(cursor, page.records.last().unwrap().cursor);
    let next = room.replicated_records(cursor, 7).unwrap();
    assert_eq!(next.records.len(), 7);
    assert!(next.records[0].cursor > cursor);
    assert_eq!(room.messages(0, 0), Err(Error::Bounds));
    assert_eq!(room.replicated_records(0, 33), Err(Error::Bounds));
}

#[test]
fn late_seal_reconciles_an_existing_longer_cached_head() {
    let root = TempDir::new().unwrap();
    let owner_account = account(&root, "owner-account");
    let reader_account = account(&root, "reader-account");
    let mut owner =
        RoomSession::create(owner_account.clone(), root.path().join("owner"), limits()).unwrap();
    let mut reader = RoomSession::join(
        reader_account,
        root.path().join("reader"),
        &owner.genesis().encode(),
        owner.room_id(),
        limits(),
    )
    .unwrap();
    let mut events = Vec::new();
    for n in 1..=3 {
        let message = owner
            .send([n; 16], "before late seal", u64::from(n))
            .unwrap();
        reader.receive_event(&message.bytes).unwrap();
        events.push(
            SignedEvent::decode(&message.bytes)
                .unwrap()
                .verify()
                .unwrap(),
        );
    }
    let mut writers = vec![
        owner_account.public_key(),
        owner.author_key(),
        reader.author_key(),
    ];
    writers.sort_unstable();
    let policy = owner_account
        .sign_direct_policy(
            UnsignedPolicy::new(PolicyClaims {
                room: owner.room_id(),
                owner: owner_account.public_key(),
                revision: 1,
                previous: owner.policy.head().id,
                writers,
                sealed_heads: vec![vhalla_direct_room::SealHead {
                    author: owner.author_key(),
                    sequence: 1,
                    event: events[0].id(),
                }],
            })
            .unwrap(),
        )
        .unwrap();
    reader.observe_policy(&policy.encode()).unwrap();
    assert_eq!(reader.policy.head().revision, 1);
    let chain = reader
        .author_chain(owner.author_key(), &reader.policy.clone())
        .unwrap();
    assert_eq!(chain.head().sequence, 3);
    assert!(chain.authoring_head(&reader.policy).is_ok());
    let messages = all_messages(&mut reader);
    assert_eq!(messages[0].visibility, Visibility::OwnerSealed);
    assert_eq!(messages[1].visibility, Visibility::ContinuityOnly);
    assert_eq!(messages[2].visibility, Visibility::ContinuityOnly);
    assert!(reader.status().unwrap().can_send);
}

#[test]
fn author_cache_evicts_removed_nonlocal_writers() {
    let root = TempDir::new().unwrap();
    let account = account(&root, "account");
    let extra = Identity::create_new(root.path().join("extra")).unwrap();
    let mut room =
        RoomSession::create(account.clone(), root.path().join("room"), limits()).unwrap();
    room.set_writers(
        [1; 16],
        vec![account.public_key(), room.author_key(), extra.public_key()],
    )
    .unwrap();
    assert!(room.author_cache.contains_key(&extra.public_key()));
    room.set_writers([2; 16], vec![account.public_key()])
        .unwrap();
    assert!(!room.author_cache.contains_key(&extra.public_key()));
    assert!(room.author_cache.contains_key(&room.author_key()));
    assert_eq!(room.author_cache.len(), 2);
    assert!(room.author_cache.len() <= MAX_CACHED_AUTHORS);
}

#[test]
fn expansion_retains_exact_blocked_policy_until_all_records_fit() {
    let root = TempDir::new().unwrap();
    let owner_account = account(&root, "owner-account");
    let member_account = account(&root, "member-account");
    let mut owner =
        RoomSession::create(owner_account.clone(), root.path().join("owner"), limits()).unwrap();
    let home = root.path().join("member");
    let small = Limits {
        max_records: 80,
        max_record_bytes: 1024 * 1024,
    };
    let mut member = RoomSession::join(
        member_account.clone(),
        &home,
        &owner.genesis().encode(),
        owner.room_id(),
        small,
    )
    .unwrap();
    for n in 1..=24 {
        let update = owner
            .set_writers(
                [n; 16],
                vec![
                    owner_account.public_key(),
                    owner.author_key(),
                    member.author_key(),
                ],
            )
            .unwrap();
        if member.observe_policy(&update.bytes) == Err(Error::Capacity) {
            break;
        }
    }
    let blocked = member.image.blocked.clone().unwrap();
    let before = member.store.accounting().unwrap();
    assert_eq!(member.expand_limits(small), Err(Error::Capacity));
    assert_eq!(
        member.image.blocked.as_ref().unwrap().as_bytes(),
        blocked.as_bytes()
    );
    assert_eq!(member.store.accounting().unwrap(), before);
    let expanded = Limits {
        max_records: 200,
        max_record_bytes: 2 * 1024 * 1024,
    };
    let status = member.expand_limits(expanded).unwrap();
    assert!(!status.capacity_fenced);
    assert!(status.can_send);
    assert_eq!(
        member.store.read(blocked.key()).unwrap().unwrap(),
        blocked.as_bytes()
    );
    assert!(member.image.blocked.is_none());
    let pin = member.room_id();
    drop(member);
    let mut member = RoomSession::open(member_account, &home, pin).unwrap();
    assert_eq!(member.status().unwrap().storage.limits, expanded);
    assert!(member.image.blocked.is_none());
    assert_eq!(
        member.store.read(blocked.key()).unwrap().unwrap(),
        blocked.as_bytes()
    );
}

#[test]
fn expansion_preserves_blocked_lost_author_custody_evidence() {
    let root = TempDir::new().unwrap();
    let account = account(&root, "account");
    let home = root.path().join("room");
    let mut room = RoomSession::create(
        account.clone(),
        &home,
        Limits {
            max_records: 80,
            max_record_bytes: 1024 * 1024,
        },
    )
    .unwrap();
    // Eleven complete policies exactly fill the 80-record hard allowance.
    for n in 1..=11 {
        room.set_writers([n; 16], vec![account.public_key(), room.author_key()])
            .unwrap();
    }
    assert_eq!(room.store.accounting().unwrap().records, 80);
    let rogue = room
        .author
        .sign_direct_event(
            UnsignedEvent::new(EventClaims {
                room: room.room_id(),
                policy: room.policy.head().id,
                author: room.author_key(),
                sequence: 1,
                previous: EventId::ZERO,
                created_at: 1,
                text: Text::new("lost local publication").unwrap(),
            })
            .unwrap(),
        )
        .unwrap();
    assert_eq!(room.receive_event(&rogue.encode()), Err(Error::Capacity));
    assert!(room.image.blocked.is_some());
    let status = room
        .expand_limits(Limits {
            max_records: 200,
            max_record_bytes: 2 * 1024 * 1024,
        })
        .unwrap();
    assert!(status.author_custody_lost);
    assert!(!status.owner_custody_lost);
    assert!(!status.can_send);
    assert!(room
        .store
        .read(raw_key(LOST_AUTHOR, *rogue.id().as_bytes()))
        .unwrap()
        .is_some());
    let pin = room.room_id();
    drop(room);
    let mut room = RoomSession::open(account, &home, pin).unwrap();
    assert!(room.status().unwrap().author_custody_lost);
    assert_eq!(room.send([12; 16], "unsafe", 2), Err(Error::ReadOnly));
}

#[test]
fn expansion_publishes_both_owner_fork_records_without_unfencing() {
    let root = TempDir::new().unwrap();
    let owner_account = account(&root, "owner-account");
    let reader_account = account(&root, "reader-account");
    let mut owner =
        RoomSession::create(owner_account.clone(), root.path().join("owner"), limits()).unwrap();
    let home = root.path().join("reader");
    let mut reader = RoomSession::join(
        reader_account.clone(),
        &home,
        &owner.genesis().encode(),
        owner.room_id(),
        Limits {
            max_records: 80,
            max_record_bytes: 1024 * 1024,
        },
    )
    .unwrap();
    let mut first = None;
    for n in 1..=19 {
        let update = owner
            .set_writers(
                [n; 16],
                vec![
                    owner_account.public_key(),
                    owner.author_key(),
                    reader.author_key(),
                ],
            )
            .unwrap();
        reader.observe_policy(&update.bytes).unwrap();
        if n == 1 {
            first = Some(SignedPolicy::decode(&update.bytes).unwrap());
        }
    }
    assert_eq!(reader.store.accounting().unwrap().records, 79);
    let first = first.unwrap();
    let mut claims = first.unverified_claims().clone();
    claims.writers = vec![owner_account.public_key()];
    let fork = owner_account
        .sign_direct_policy(UnsignedPolicy::new(claims).unwrap())
        .unwrap();
    assert_eq!(reader.observe_policy(&fork.encode()), Err(Error::Capacity));
    assert!(reader.status().unwrap().owner_forked);
    let status = reader
        .expand_limits(Limits {
            max_records: 200,
            max_record_bytes: 2 * 1024 * 1024,
        })
        .unwrap();
    assert!(status.owner_forked);
    assert!(!status.can_send);
    assert!(!status.capacity_fenced);
    assert_eq!(status.policy.revision, 19);
    let mut proof = first.id().as_bytes().to_vec();
    proof.extend_from_slice(fork.id().as_bytes());
    assert_eq!(
        reader.store.read(key(OWNER_FORK, &proof)).unwrap().unwrap(),
        proof
    );
    assert!(reader
        .store
        .read(raw_key(POLICY, *first.id().as_bytes()))
        .unwrap()
        .is_some());
    assert!(reader
        .store
        .read(raw_key(POLICY, *fork.id().as_bytes()))
        .unwrap()
        .is_some());
    let pin = reader.room_id();
    drop(reader);
    let mut reader = RoomSession::open(reader_account, &home, pin).unwrap();
    assert!(reader.status().unwrap().owner_forked);
}

#[test]
fn open_rejects_a_committed_numeric_seal_without_its_exact_ancestry() {
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
    let first = owner.send([1; 16], "first", 1).unwrap();
    reader.receive_event(&first.bytes).unwrap();
    let disconnected = owner
        .author
        .sign_direct_event(
            UnsignedEvent::new(EventClaims {
                room: pin,
                policy: owner.policy.head().id,
                author: owner.author_key(),
                sequence: 2,
                previous: EventId::from_bytes([9; 32]),
                created_at: 2,
                text: Text::new("wrong ancestry").unwrap(),
            })
            .unwrap(),
        )
        .unwrap();
    reader.receive_event(&disconnected.encode()).unwrap();
    let update = owner_account
        .sign_direct_policy(
            UnsignedPolicy::new(PolicyClaims {
                room: pin,
                owner: owner_account.public_key(),
                revision: 1,
                previous: owner.policy.head().id,
                writers: owner.policy.writers().to_vec(),
                sealed_heads: vec![vhalla_direct_room::SealHead {
                    author: owner.author_key(),
                    sequence: 2,
                    event: disconnected.id(),
                }],
            })
            .unwrap(),
        )
        .unwrap();
    let outcome = reader.observe_policy(&update.encode()).unwrap();
    assert_eq!(outcome.current.revision, 0);
    assert!(outcome.pending.is_some());
    assert!(all_messages(&mut reader)
        .iter()
        .all(|message| message.visibility == Visibility::Incomplete));
    // A fabricated durable commit marker must not establish the verified-history
    // invariant on open merely because the candidate is below a numeric cutoff.
    reader
        .publish(
            reader.image.clone(),
            &[
                record(
                    revision_key(COMMITTED, 1),
                    &index_bytes(&1u64.to_be_bytes(), *update.id().as_bytes()),
                )
                .unwrap(),
                record(
                    raw_key(POLICY_INDEX, *update.id().as_bytes()),
                    &1u64.to_be_bytes(),
                )
                .unwrap(),
            ],
            true,
        )
        .unwrap();
    drop(reader);
    assert!(RoomSession::open(reader_account, &home, pin).is_err());
}

#[test]
fn out_of_order_author_catchup_keeps_progress_between_bounded_calls() {
    let root = TempDir::new().unwrap();
    let owner_account = account(&root, "owner-account");
    let reader_account = account(&root, "reader-account");
    let mut owner =
        RoomSession::create(owner_account, root.path().join("owner"), limits()).unwrap();
    let mut reader = RoomSession::join(
        reader_account,
        root.path().join("reader"),
        &owner.genesis().encode(),
        owner.room_id(),
        limits(),
    )
    .unwrap();
    let mut frames = Vec::new();
    for n in 1..=100 {
        frames.push(
            owner
                .send([n; 16], "out of order", u64::from(n))
                .unwrap()
                .bytes,
        );
    }
    for frame in &frames[1..] {
        reader.receive_event(frame).unwrap();
    }
    assert!(reader.status().unwrap().reconciliation_pending);
    reader.receive_event(&frames[0]).unwrap();
    assert!(reader.status().unwrap().reconciliation_pending);
    let mut passes = 0;
    while reader.status().unwrap().reconciliation_pending {
        let before = reader.frame_reads;
        reader.reconcile().unwrap();
        assert!(reader.frame_reads - before <= MAX_REPLAY_FRAMES + MAX_CACHED_AUTHORS);
        passes += 1;
        assert!(passes <= 4);
    }
    assert_eq!(reader.full_replays, 0);
    let messages = all_messages(&mut reader);
    assert_eq!(messages.len(), 100);
    assert!(messages
        .iter()
        .all(|message| message.visibility == Visibility::Provisional));
}
