//! Scoped sends cannot turn a new authorization into historical signing power.

use crate::{codec::*, *};
use tempfile::TempDir;
use vhalla_direct_room::{EventClaims, SignedEvent, Text, UnsignedEvent};

fn limits() -> Limits {
    Limits {
        max_records: 10_000,
        max_record_bytes: 8 * 1024 * 1024,
    }
}

fn fixture() -> (TempDir, Arc<Identity>, RoomSession) {
    let root = TempDir::new().unwrap();
    let account = Arc::new(Identity::create_new(root.path().join("account")).unwrap());
    let room = RoomSession::create(account.clone(), root.path().join("room"), limits()).unwrap();
    (root, account, room)
}

fn reserve_event(room: &mut RoomSession, operation: [u8; 16], text: &str) -> Vec<u8> {
    let head = room
        .author_chain(room.author_key(), &room.policy.clone())
        .unwrap()
        .authoring_head(&room.policy)
        .unwrap();
    let unsigned = UnsignedEvent::new(EventClaims {
        room: room.room_id(),
        policy: room.policy.head().id,
        author: room.author_key(),
        sequence: head.sequence + 1,
        previous: head.event,
        created_at: 7,
        text: Text::new(text).unwrap(),
    })
    .unwrap();
    let reservation = Reservation {
        operation,
        kind: EVENT,
        unsigned: unsigned.encode(),
    };
    let mut image = room.image.clone();
    image.pending_event = Some(operation);
    room.publish(
        image,
        &[record(operation_key(RESERVATION, operation), &reservation.encode()).unwrap()],
        false,
    )
    .unwrap();
    unsigned.encode()
}

#[test]
fn exact_current_policy_retries_finish_and_preserve_the_original_signature() {
    let (_root, _account, mut room) = fixture();
    let policy = room.policy.head();
    let author = room.author_key();
    let unsigned = reserve_event(&mut room, [1; 16], "same scope");
    let first = room
        .send_scoped(policy, author, [1; 16], "same scope", 99)
        .unwrap();
    assert!(first.exact_retry);
    assert_eq!(&first.bytes[..first.bytes.len() - 64], unsigned);
    let before = room.store.accounting().unwrap();
    assert_eq!(
        room.send_scoped(policy, author, [1; 16], "same scope", 100)
            .unwrap(),
        first
    );
    assert_eq!(room.store.accounting().unwrap(), before);
    assert_eq!(
        room.send_scoped(policy, author, [1; 16], "changed", 101),
        Err(Error::OperationConflict)
    );
    assert_eq!(room.store.accounting().unwrap(), before);
    assert!(room.status().unwrap().can_send);
}

#[test]
fn a_new_policy_cannot_finish_an_old_reservation_after_author_removal() {
    let (root, account, mut owner) = fixture();
    let member_account =
        Arc::new(Identity::create_new(root.path().join("member-account")).unwrap());
    let mut member = RoomSession::join(
        member_account,
        root.path().join("member"),
        &owner.genesis().encode(),
        owner.room_id(),
        limits(),
    )
    .unwrap();
    let author = member.author_key();
    let admission = owner
        .set_writers(
            [10; 16],
            vec![account.public_key(), owner.author_key(), author],
        )
        .unwrap();
    member.observe_policy(&admission.bytes).unwrap();
    let p1 = member.policy.head();
    let unsigned = reserve_event(&mut member, [11; 16], "old pending text");
    let removal = owner
        .set_writers([12; 16], vec![account.public_key(), owner.author_key()])
        .unwrap();
    member.observe_policy(&removal.bytes).unwrap();
    let p2 = member.policy.head();
    assert_ne!(p1, p2);
    let before = member.store.accounting().unwrap();
    let image = member.image_bytes.clone();
    assert_eq!(
        member.send_scoped(p2, author, [11; 16], "old pending text", 50),
        Err(Error::OperationConflict)
    );
    assert_eq!(member.store.accounting().unwrap(), before);
    assert_eq!(member.image_bytes, image);
    assert_eq!(member.image.pending_event, Some([11; 16]));
    assert!(member
        .store
        .read(operation_key(COMPLETION, [11; 16]))
        .unwrap()
        .is_none());
    assert!(member.operations(0, 32).unwrap().operations.is_empty());
    assert_eq!(
        member.send_scoped(p1, author, [11; 16], "old pending text", 51),
        Err(Error::ReadOnly)
    );
    assert_eq!(member.store.accounting().unwrap(), before);
    // Recovery remains an explicit trusted operation, with the original bytes.
    let recovered = member.send([11; 16], "old pending text", 52).unwrap();
    assert_eq!(&recovered.bytes[..recovered.bytes.len() - 64], unsigned);
    assert_eq!(recovered.state, OperationState::NeedsRepost);
}

#[test]
fn an_old_completion_cannot_masquerade_as_a_send_under_a_new_policy() {
    let (root, account, mut room) = fixture();
    let author = room.author_key();
    let p1 = room.policy.head();
    let original = room
        .send_scoped(p1, author, [20; 16], "old completed text", 1)
        .unwrap();
    room.set_writers([21; 16], vec![account.public_key(), author])
        .unwrap();
    let p2 = room.policy.head();
    let before = room.store.accounting().unwrap();
    assert_eq!(
        room.send_scoped(p2, author, [20; 16], "old completed text", 2),
        Err(Error::OperationConflict)
    );
    assert_eq!(room.store.accounting().unwrap(), before);
    assert_eq!(
        room.send([20; 16], "old completed text", 2).unwrap().bytes,
        original.bytes
    );
    let pin = room.room_id();
    drop(room);
    let mut room = RoomSession::open(account, root.path().join("room"), pin).unwrap();
    assert_eq!(
        room.send_scoped(p2, author, [20; 16], "old completed text", 3),
        Err(Error::OperationConflict)
    );
    let current = room
        .send_scoped(p2, author, [22; 16], "current policy", 3)
        .unwrap();
    assert_eq!(
        SignedEvent::decode(&current.bytes)
            .unwrap()
            .verify()
            .unwrap()
            .claims()
            .policy,
        p2.id
    );
}

#[test]
fn current_scope_and_operation_kind_refusals_precede_any_mutation() {
    let (_root, account, mut room) = fixture();
    let author = room.author_key();
    let policy = room.policy.head();
    let before = room.store.accounting().unwrap();
    for (expected, selected_author) in [
        (
            PolicyPosition {
                revision: policy.revision + 1,
                ..policy
            },
            author,
        ),
        (
            PolicyPosition {
                id: vhalla_direct_room::PolicyId::from_bytes([99; 32]),
                ..policy
            },
            author,
        ),
        (policy, account.public_key()),
    ] {
        assert_eq!(
            room.send_scoped(expected, selected_author, [30; 16], "denied", 1),
            Err(Error::ReadOnly)
        );
        assert_eq!(room.store.accounting().unwrap(), before);
    }
    room.set_writers([31; 16], vec![account.public_key(), author])
        .unwrap();
    let current = room.policy.head();
    let before = room.store.accounting().unwrap();
    assert_eq!(
        room.send_scoped(current, author, [31; 16], "not a policy call", 2),
        Err(Error::OperationConflict)
    );
    assert_eq!(room.store.accounting().unwrap(), before);
    assert!(room
        .send_scoped(current, author, [32; 16], "still usable", 2)
        .is_ok());
}
