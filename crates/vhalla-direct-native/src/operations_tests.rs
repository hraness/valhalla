use super::*;
use tempfile::TempDir;
use vhalla_direct_room::{EventClaims, EventId, Text, UnsignedEvent};

fn fixture() -> (TempDir, Arc<Identity>, RoomSession) {
    let root = TempDir::new().unwrap();
    let account = Arc::new(Identity::create_new(root.path().join("account")).unwrap());
    let room = RoomSession::create(
        account.clone(),
        root.path().join("room"),
        Limits {
            max_records: 10_000,
            max_record_bytes: 8 * 1024 * 1024,
        },
    )
    .unwrap();
    (root, account, room)
}

fn collect(room: &mut RoomSession, limit: usize) -> Vec<OperationEntry> {
    let mut after = 0;
    let mut output = Vec::new();
    loop {
        let page = room.operations(after, limit).unwrap();
        output.extend(page.operations);
        match page.next {
            Some(next) => {
                assert!(next > after);
                after = next;
            }
            None => return output,
        }
    }
}

#[test]
fn completions_are_exact_bounded_metadata_across_retry_and_reopen() {
    let (root, account, mut room) = fixture();
    assert!(room.operations(0, 32).unwrap().operations.is_empty());
    let first = room.send([1; 16], "never exposed by this page", 1).unwrap();
    let policy = room
        .set_writers([2; 16], vec![account.public_key(), room.author_key()])
        .unwrap();
    let entries = collect(&mut room, 1);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].kind, OperationKind::Event);
    assert_eq!(entries[0].operation, [1; 16]);
    assert_eq!(
        entries[0].frame_hash,
        <[u8; 32]>::from(Sha256::digest(&first.bytes))
    );
    assert_eq!(entries[1].kind, OperationKind::Policy);
    assert_eq!(
        entries[1].frame_hash,
        <[u8; 32]>::from(Sha256::digest(&policy.bytes))
    );
    room.send([1; 16], "never exposed by this page", 99)
        .unwrap();
    assert_eq!(collect(&mut room, 32), entries);
    let pin = room.room_id();
    drop(room);
    let mut room = RoomSession::open(account, root.path().join("room"), pin).unwrap();
    assert_eq!(collect(&mut room, 1), entries);
    for (after, limit) in [(0, 0), (0, 33), (u64::MAX, 1)] {
        assert_eq!(room.operations(after, limit), Err(Error::Bounds));
    }
    assert_eq!(collect(&mut room, 32), entries);
}

#[test]
fn pending_intent_and_remotely_observed_owner_signatures_are_not_completions() {
    let (root, account, mut room) = fixture();
    let unsigned = UnsignedEvent::new(EventClaims {
        room: room.room_id(),
        policy: room.policy.head().id,
        author: room.author_key(),
        sequence: 1,
        previous: EventId::ZERO,
        created_at: 1,
        text: Text::new("pending").unwrap(),
    })
    .unwrap();
    let reservation = Reservation {
        operation: [3; 16],
        kind: EVENT,
        unsigned: unsigned.encode(),
    };
    let mut image = room.image.clone();
    image.pending_event = Some(reservation.operation);
    room.publish(
        image,
        &[record(
            operation_key(RESERVATION, reservation.operation),
            &reservation.encode(),
        )
        .unwrap()],
        false,
    )
    .unwrap();
    assert!(collect(&mut room, 32).is_empty());
    assert_eq!(
        room.status().unwrap().pending_event_operation,
        Some([3; 16])
    );
    room.send([3; 16], "pending", 2).unwrap();
    let pin = room.room_id();
    let mut observer = RoomSession::join(
        account,
        root.path().join("observer"),
        &room.genesis().encode(),
        pin,
        Limits {
            max_records: 10_000,
            max_record_bytes: 8 * 1024 * 1024,
        },
    )
    .unwrap();
    let policy = room
        .set_writers(
            [4; 16],
            vec![room.genesis().claims().owner, room.author_key()],
        )
        .unwrap();
    observer.observe_policy(&policy.bytes).unwrap();
    assert!(collect(&mut observer, 32).is_empty());
    assert_eq!(collect(&mut room, 32).len(), 2);
}

#[test]
fn empty_filtered_pages_advance_without_scanning_lifetime_history() {
    let (_root, account, mut room) = fixture();
    for sequence in 1..=80 {
        let raw = account
            .sign_direct_event(
                UnsignedEvent::new(EventClaims {
                    room: room.room_id(),
                    policy: room.policy.head().id,
                    author: account.public_key(),
                    sequence,
                    previous: if sequence == 1 {
                        EventId::ZERO
                    } else {
                        EventId::from_bytes([1; 32])
                    },
                    created_at: sequence,
                    text: Text::new("unresolved remote ancestry").unwrap(),
                })
                .unwrap(),
            )
            .unwrap()
            .encode();
        room.receive_event(&raw).unwrap();
    }
    let page = room.operations(0, 32).unwrap();
    assert!(page.operations.is_empty());
    assert_eq!(page.next, Some(MAX_FILTER_SCAN as u64));
    assert!(page.tip > MAX_FILTER_SCAN as u64);
    assert!(room
        .operations(page.next.unwrap(), 32)
        .unwrap()
        .operations
        .is_empty());
}

#[test]
fn changed_live_image_or_inconsistent_completion_refuses_and_poison_latches() {
    let (_root, _account, mut room) = fixture();
    let mut changed = room.image.clone();
    changed.author_lost = true;
    room.store
        .publish(Some(&room.image_bytes), &changed.encode(), &[])
        .unwrap();
    assert_eq!(room.operations(0, 32), Err(Error::Corrupt));
    assert_eq!(room.operations(0, 32), Err(Error::Uncertain));

    let (_other_root, _other_account, mut room) = fixture();
    let operation = [7; 16];
    let mut fake = vec![EVENT];
    fake.extend_from_slice(&operation);
    fake.extend_from_slice(&[8; 32]);
    room.store
        .publish(
            Some(&room.image_bytes),
            &room.image_bytes,
            &[record(operation_key(COMPLETION, operation), &fake).unwrap()],
        )
        .unwrap();
    assert_eq!(room.operations(0, 32), Err(Error::Corrupt));
    assert_eq!(room.operations(0, 32), Err(Error::Uncertain));
}
