//! Snapshot binding, bounded page transactions and adversarial source traces.

use ed25519_dalek::SigningKey;
use vhalla_direct_room::{
    EventClaims, EventId, GenesisClaims, PinnedGenesis, PolicyClaims, RoomId, Text, UnsignedEvent,
    UnsignedGenesis, UnsignedPolicy,
};
use vhalla_direct_sync::*;

const SOURCE: [u8; 32] = [7; 32];
const EPOCH: [u8; 32] = [8; 32];
fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}
fn genesis() -> PinnedGenesis {
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).expect("room nonce entropy");
    let owner = key(1).verifying_key().to_bytes();
    let mut writers = vec![owner, key(2).verifying_key().to_bytes()];
    writers.sort_unstable();
    let signed = UnsignedGenesis::new(GenesisClaims {
        owner,
        nonce,
        writers,
    })
    .unwrap()
    .sign_with_key(&key(1))
    .unwrap();
    let pin = signed.id();
    signed.verify_pin(pin).unwrap()
}
fn event(room: &PinnedGenesis, author: u8, text: &str) -> Vec<u8> {
    UnsignedEvent::new(EventClaims {
        room: room.id(),
        policy: room.id().initial_policy(),
        author: key(author).verifying_key().to_bytes(),
        sequence: 1,
        previous: EventId::ZERO,
        created_at: 5,
        text: Text::new(text).unwrap(),
    })
    .unwrap()
    .sign_with_key(&key(author))
    .unwrap()
    .encode()
}
fn policy(room: &PinnedGenesis, owner: u8) -> Vec<u8> {
    let owner_key = key(owner).verifying_key().to_bytes();
    UnsignedPolicy::new(PolicyClaims {
        room: room.id(),
        owner: owner_key,
        revision: 1,
        previous: room.id().initial_policy(),
        writers: vec![owner_key],
        sealed_heads: vec![],
    })
    .unwrap()
    .sign_with_key(&key(owner))
    .unwrap()
    .encode()
}
fn frame(kind: FrameKind, bytes: &[u8]) -> Frame<'_> {
    Frame { kind, bytes }
}
fn snapshot(room: &PinnedGenesis, frames: &[Frame<'_>]) -> Checkpoint {
    let mut source = SourceAccumulator::new(SOURCE, room.clone(), EPOCH).unwrap();
    for frame in frames {
        source.push(*frame).unwrap();
    }
    source.checkpoint().unwrap()
}
fn page<'a>(target: Checkpoint, first: u64, frames: &'a [Frame<'a>]) -> Page<'a> {
    Page {
        checkpoint_id: target.id(),
        first,
        last: first + frames.len() as u64 - 1,
        frames,
    }
}
fn receive(room: PinnedGenesis, target: Checkpoint) -> Receiver {
    Receiver::begin(room, SOURCE, SOURCE, target).unwrap()
}

#[test]
fn exact_pages_own_verified_frames_and_only_final_hash_grants_coverage() {
    let room = genesis();
    let genesis = room.encode();
    let event = event(&room, 2, "hello");
    let policy = policy(&room, 1);
    let frames = [
        frame(FrameKind::Genesis, &genesis),
        frame(FrameKind::Event, &event),
        frame(FrameKind::Policy, &policy),
    ];
    let target = snapshot(&room, &frames);
    let mut receiver = receive(room, target);
    let before = receiver.progress();
    let prepared = receiver
        .prepare_page(page(target, 1, &frames[..2]))
        .unwrap();
    assert_eq!(receiver.progress(), before);
    assert_eq!(prepared.first(), 1);
    assert_eq!(prepared.last(), 2);
    assert_eq!(prepared.frames()[1].encode(), event);
    assert_eq!(prepared.frames()[1].kind(), FrameKind::Event);
    assert_eq!(receiver.coverage(), Coverage::Pending);
    assert_eq!(
        receiver.commit_after_persist(prepared).unwrap(),
        Coverage::Pending
    );
    assert_eq!(receiver.finish(), Err(Error::Truncated));
    let prepared = {
        let owned = policy.clone();
        let inputs = [frame(FrameKind::Policy, &owned)];
        receiver.prepare_page(page(target, 3, &inputs)).unwrap()
    };
    assert_eq!(prepared.frames()[0].encode(), policy);
    assert_eq!(
        receiver.commit_after_persist(prepared).unwrap(),
        Coverage::Complete
    );
    assert_eq!(receiver.finish().unwrap(), target);
}

#[test]
fn page_positions_omissions_reorder_and_invalid_frames_never_advance_on_refusal() {
    let room = genesis();
    let genesis = room.encode();
    let one = event(&room, 2, "one");
    let two = event(&room, 2, "two");
    let frames = [
        frame(FrameKind::Genesis, &genesis),
        frame(FrameKind::Event, &one),
        frame(FrameKind::Event, &two),
    ];
    let target = snapshot(&room, &frames);
    let mut receiver = receive(room, target);
    let before = receiver.progress();
    assert_eq!(
        receiver
            .prepare_page(page(target, 2, &frames[..1]))
            .unwrap_err(),
        Error::Sequence
    );
    let mut wrong_range = page(target, 1, &frames[..2]);
    wrong_range.last = 1;
    assert_eq!(
        receiver.prepare_page(wrong_range).unwrap_err(),
        Error::Sequence
    );
    let mut wrong_checkpoint = page(target, 1, &frames);
    wrong_checkpoint.checkpoint_id[0] ^= 1;
    assert_eq!(
        receiver.prepare_page(wrong_checkpoint).unwrap_err(),
        Error::Checkpoint
    );
    let reordered = [frames[0], frames[2], frames[1]];
    assert_eq!(
        receiver
            .prepare_page(page(target, 1, &reordered))
            .unwrap_err(),
        Error::Digest
    );
    let repeated = [frames[0], frames[1], frames[1]];
    assert_eq!(
        receiver
            .prepare_page(page(target, 1, &repeated))
            .unwrap_err(),
        Error::Digest
    );
    let mut damaged = two.clone();
    *damaged.last_mut().unwrap() ^= 1;
    let invalid = [frames[0], frames[1], frame(FrameKind::Event, &damaged)];
    assert!(matches!(
        receiver.prepare_page(page(target, 1, &invalid)),
        Err(Error::Protocol(_))
    ));
    assert_eq!(receiver.progress(), before);
    let prepared = receiver
        .prepare_page(page(target, 1, &frames[..1]))
        .unwrap();
    receiver.commit_after_persist(prepared).unwrap();
    let before = receiver.progress();
    assert_eq!(
        receiver
            .prepare_page(page(target, 3, &frames[2..]))
            .unwrap_err(),
        Error::Sequence
    );
    assert_eq!(
        receiver
            .prepare_page(page(target, 1, &frames[..1]))
            .unwrap_err(),
        Error::Sequence
    );
    assert_eq!(receiver.finish(), Err(Error::Truncated));
    assert_eq!(receiver.progress(), before);
}

#[test]
fn valid_but_wrong_partial_prefix_stays_pending_and_cannot_excuse_terminal_mismatch() {
    let room = genesis();
    let genesis = room.encode();
    let one = event(&room, 2, "one");
    let two = event(&room, 2, "two");
    let other = event(&room, 2, "bad");
    let frames = [
        frame(FrameKind::Genesis, &genesis),
        frame(FrameKind::Event, &one),
        frame(FrameKind::Event, &two),
    ];
    let target = snapshot(&room, &frames);
    let mut receiver = receive(room, target);
    let prefix = [frames[0], frame(FrameKind::Event, &other)];
    let prepared = receiver.prepare_page(page(target, 1, &prefix)).unwrap();
    assert_eq!(
        receiver.commit_after_persist(prepared).unwrap(),
        Coverage::Pending
    );
    let before = receiver.progress();
    assert_eq!(
        receiver
            .prepare_page(page(target, 3, &frames[2..]))
            .unwrap_err(),
        Error::Digest
    );
    assert_eq!(receiver.progress(), before);
    assert_eq!(receiver.target(), target);
    assert_eq!(receiver.finish(), Err(Error::Truncated));
    assert_eq!(receiver.extend(SOURCE, target), Err(Error::Pending));
}

#[test]
fn source_and_receiver_require_exact_genesis_room_owner_and_canonical_types() {
    let room = genesis();
    let foreign = genesis();
    let raw_genesis = room.encode();
    let foreign_genesis = foreign.encode();
    let foreign_event = event(&foreign, 2, "foreign");
    let impostor = policy(&room, 3);
    let owner_policy = policy(&room, 1);
    let mut source = SourceAccumulator::new(SOURCE, room.clone(), EPOCH).unwrap();
    assert_eq!(source.checkpoint(), Err(Error::Bounds));
    assert_eq!(
        source.push(frame(FrameKind::Policy, &owner_policy)),
        Err(Error::Sequence)
    );
    assert!(source
        .push(frame(FrameKind::Genesis, &foreign_genesis))
        .is_err());
    source
        .push(frame(FrameKind::Genesis, &raw_genesis))
        .unwrap();
    let first = source.checkpoint().unwrap();
    assert_eq!(
        source.push(frame(FrameKind::Genesis, &raw_genesis)),
        Err(Error::Sequence)
    );
    assert_eq!(
        source.push(frame(FrameKind::Event, &foreign_event)),
        Err(Error::Room)
    );
    assert_eq!(
        source.push(frame(FrameKind::Policy, &impostor)),
        Err(Error::Protocol(vhalla_direct_room::Error::Owner))
    );
    assert!(source.push(frame(FrameKind::Event, &owner_policy)).is_err());
    let mut trailing = owner_policy.clone();
    trailing.push(0);
    assert!(source.push(frame(FrameKind::Policy, &trailing)).is_err());
    assert_eq!(source.checkpoint().unwrap(), first);
    source
        .push(frame(FrameKind::Policy, &owner_policy))
        .unwrap();
    let target = source.checkpoint().unwrap();
    for bad in [
        frame(FrameKind::Policy, &impostor),
        frame(FrameKind::Event, &foreign_event),
        frame(FrameKind::Genesis, &raw_genesis),
    ] {
        let receiver = receive(room.clone(), target);
        assert!(receiver
            .prepare_page(page(
                target,
                1,
                &[frame(FrameKind::Genesis, &raw_genesis), bad]
            ))
            .is_err());
        assert_eq!(receiver.progress().records, 0);
    }
}

#[test]
fn sync_preserves_forks_and_unadmitted_events_for_native_classification() {
    let room = genesis();
    let genesis = room.encode();
    let one = event(&room, 2, "fork A");
    let two = event(&room, 2, "fork B");
    let unadmitted = event(&room, 3, "not listed by owner");
    let frames = [
        frame(FrameKind::Genesis, &genesis),
        frame(FrameKind::Event, &one),
        frame(FrameKind::Event, &two),
        frame(FrameKind::Event, &unadmitted),
    ];
    let target = snapshot(&room, &frames);
    let mut receiver = receive(room, target);
    let prepared = receiver.prepare_page(page(target, 1, &frames)).unwrap();
    assert_eq!(prepared.frames().len(), 4);
    assert_eq!(
        receiver.commit_after_persist(prepared).unwrap(),
        Coverage::Complete
    );
}

#[test]
fn configured_source_authentication_epoch_room_and_shape_are_required() {
    let room = genesis();
    let genesis = room.encode();
    let target = snapshot(&room, &[frame(FrameKind::Genesis, &genesis)]);
    assert!(matches!(
        Receiver::begin(room.clone(), [6; 32], SOURCE, target),
        Err(Error::Source)
    ));
    assert!(matches!(
        Receiver::begin(room.clone(), SOURCE, [6; 32], target),
        Err(Error::Source)
    ));
    for (bad, expected) in [
        (
            Checkpoint {
                source: [6; 32],
                ..target
            },
            Error::Source,
        ),
        (
            Checkpoint {
                epoch: [0; 32],
                ..target
            },
            Error::Epoch,
        ),
        (
            Checkpoint {
                room: RoomId::from_bytes([5; 32]),
                ..target
            },
            Error::Room,
        ),
        (
            Checkpoint {
                records: 0,
                ..target
            },
            Error::Bounds,
        ),
        (
            Checkpoint {
                records: MAX_SNAPSHOT_RECORDS + 1,
                ..target
            },
            Error::Bounds,
        ),
        (
            Checkpoint {
                bytes: MAX_SNAPSHOT_BYTES + 1,
                ..target
            },
            Error::Bounds,
        ),
        (
            Checkpoint {
                bytes: target.bytes - 1,
                ..target
            },
            Error::Bounds,
        ),
        (
            Checkpoint {
                bytes: target.bytes + 1,
                ..target
            },
            Error::Bounds,
        ),
        (
            Checkpoint {
                records: 2,
                ..target
            },
            Error::Bounds,
        ),
    ] {
        assert!(
            matches!(Receiver::begin(room.clone(), SOURCE, SOURCE, bad), Err(error) if error == expected)
        );
    }
    assert!(matches!(
        SourceAccumulator::new([0; 32], room.clone(), EPOCH),
        Err(Error::Source)
    ));
    assert!(matches!(
        SourceAccumulator::new(SOURCE, room, [0; 32]),
        Err(Error::Epoch)
    ));
}

#[test]
fn page_and_frame_bounds_are_enforced_before_progress() {
    let room = genesis();
    let genesis = room.encode();
    let message = event(&room, 2, "bounded");
    let mut source = SourceAccumulator::new(SOURCE, room.clone(), EPOCH).unwrap();
    source.push(frame(FrameKind::Genesis, &genesis)).unwrap();
    for _ in 0..64 {
        source.push(frame(FrameKind::Event, &message)).unwrap();
    }
    let target = source.checkpoint().unwrap();
    let mut receiver = receive(room, target);
    let input = vec![frame(FrameKind::Genesis, &genesis); MAX_PAGE_FRAMES + 1];
    assert_eq!(
        receiver.prepare_page(page(target, 1, &input)).unwrap_err(),
        Error::Bounds
    );
    assert_eq!(
        receiver
            .prepare_page(Page {
                checkpoint_id: target.id(),
                first: 1,
                last: 0,
                frames: &[]
            })
            .unwrap_err(),
        Error::Bounds
    );
    let huge = vec![0; vhalla_direct_room::MAX_EVENT_BYTES + 1];
    let inputs = [
        frame(FrameKind::Genesis, &genesis),
        frame(FrameKind::Event, &huge),
    ];
    assert_eq!(
        receiver.prepare_page(page(target, 1, &inputs)).unwrap_err(),
        Error::Bounds
    );
    assert_eq!(receiver.progress().records, 0);
    assert_eq!(
        source.push(frame(FrameKind::Event, &huge)),
        Err(Error::Bounds)
    );
    assert_eq!(source.checkpoint().unwrap(), target);
    let mut valid = vec![frame(FrameKind::Event, &message); MAX_PAGE_FRAMES];
    valid[0] = frame(FrameKind::Genesis, &genesis);
    let step = receiver.prepare_page(page(target, 1, &valid)).unwrap();
    assert_eq!(
        receiver.commit_after_persist(step).unwrap(),
        Coverage::Pending
    );
    valid[0] = frame(FrameKind::Event, &message);
    let step = receiver.prepare_page(page(target, 33, &valid)).unwrap();
    assert_eq!(
        receiver.commit_after_persist(step).unwrap(),
        Coverage::Pending
    );
    let step = receiver
        .prepare_page(page(target, 65, &valid[..1]))
        .unwrap();
    assert_eq!(
        receiver.commit_after_persist(step).unwrap(),
        Coverage::Complete
    );
}

#[test]
fn prepared_tokens_require_the_exact_unchanged_receiver_base_and_target() {
    let room = genesis();
    let genesis = room.encode();
    let message = event(&room, 2, "later");
    let frames = [
        frame(FrameKind::Genesis, &genesis),
        frame(FrameKind::Event, &message),
    ];
    let target = snapshot(&room, &frames);
    let mut receiver = receive(room.clone(), target);
    let one = receiver
        .prepare_page(page(target, 1, &frames[..1]))
        .unwrap();
    let stale = receiver
        .prepare_page(page(target, 1, &frames[..1]))
        .unwrap();
    receiver.commit_after_persist(one).unwrap();
    assert_eq!(receiver.commit_after_persist(stale), Err(Error::StaleBase));
    let token = receiver
        .prepare_page(page(target, 2, &frames[1..]))
        .unwrap();
    let changed = Checkpoint {
        digest: [9; 32],
        ..target
    };
    let mut other = receive(room.clone(), changed);
    let prefix = other.prepare_page(page(changed, 1, &frames[..1])).unwrap();
    other.commit_after_persist(prefix).unwrap();
    assert_eq!(other.commit_after_persist(token), Err(Error::StaleBase));
    let token = receiver
        .prepare_page(page(target, 2, &frames[1..]))
        .unwrap();
    let foreign = Checkpoint {
        source: [6; 32],
        ..target
    };
    let mut other = Receiver::begin(room, [6; 32], [6; 32], foreign).unwrap();
    assert_eq!(other.commit_after_persist(token), Err(Error::StaleBase));
}

#[test]
fn extension_requires_completion_and_same_identity_and_never_rolls_back() {
    let room = genesis();
    let genesis = room.encode();
    let message = event(&room, 2, "extension");
    let frames = [
        frame(FrameKind::Genesis, &genesis),
        frame(FrameKind::Event, &message),
    ];
    let initial = snapshot(&room, &frames[..1]);
    let target = snapshot(&room, &frames);
    let mut receiver = receive(room.clone(), initial);
    assert_eq!(receiver.extend(SOURCE, target), Err(Error::Pending));
    let step = receiver
        .prepare_page(page(initial, 1, &frames[..1]))
        .unwrap();
    receiver.commit_after_persist(step).unwrap();
    let progress = receiver.progress();
    receiver.extend(SOURCE, initial).unwrap();
    assert_eq!(receiver.progress(), progress);
    for (bad, expected) in [
        (
            Checkpoint {
                source: [6; 32],
                ..target
            },
            Error::Source,
        ),
        (
            Checkpoint {
                room: RoomId::from_bytes([6; 32]),
                ..target
            },
            Error::Room,
        ),
        (
            Checkpoint {
                epoch: [9; 32],
                ..target
            },
            Error::Epoch,
        ),
        (
            Checkpoint {
                digest: [9; 32],
                ..initial
            },
            Error::Fork,
        ),
        (
            Checkpoint {
                bytes: initial.bytes + 1,
                ..initial
            },
            Error::Fork,
        ),
        (
            Checkpoint {
                bytes: initial.bytes - 1,
                ..target
            },
            Error::Rollback,
        ),
        (
            Checkpoint {
                bytes: initial.bytes,
                ..target
            },
            Error::Bounds,
        ),
    ] {
        assert_eq!(receiver.extend(SOURCE, bad), Err(expected));
        assert_eq!(receiver.target(), initial);
        assert_eq!(receiver.progress(), progress);
    }
    assert_eq!(receiver.extend([6; 32], target), Err(Error::Source));
    receiver.extend(SOURCE, target).unwrap();
    assert_eq!(receiver.progress(), progress);
    assert_eq!(receiver.coverage(), Coverage::Pending);
    let step = receiver
        .prepare_page(page(target, 2, &frames[1..]))
        .unwrap();
    assert_eq!(
        receiver.commit_after_persist(step).unwrap(),
        Coverage::Complete
    );
    assert_eq!(receiver.extend(SOURCE, initial), Err(Error::Rollback));
    assert_eq!(receiver.finish().unwrap(), target);
}

fn decoded_vector(source: &str, name: &str) -> Vec<u8> {
    let value = source
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}=")))
        .unwrap();
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn deterministic_snapshot_matches_independent_sha256_vector() {
    let room_vectors = include_str!("../../../vectors/direct-room-v1.txt");
    let vectors = include_str!("snapshot-v1.txt");
    let source_key: [u8; 32] = decoded_vector(vectors, "source").try_into().unwrap();
    let epoch: [u8; 32] = decoded_vector(vectors, "epoch").try_into().unwrap();
    let genesis = decoded_vector(room_vectors, "genesis_signed");
    let event = decoded_vector(room_vectors, "event_signed");
    let policy = decoded_vector(room_vectors, "policy_signed");
    let room = RoomId::from_bytes(
        decoded_vector(room_vectors, "genesis_id")
            .try_into()
            .unwrap(),
    );
    let pinned = vhalla_direct_room::SignedGenesis::decode(&genesis)
        .unwrap()
        .verify_pin(room)
        .unwrap();
    let mut source = SourceAccumulator::new(source_key, pinned.clone(), epoch).unwrap();
    let frames = [
        frame(FrameKind::Genesis, &genesis),
        frame(FrameKind::Event, &event),
        frame(FrameKind::Policy, &policy),
    ];
    for (index, frame) in frames.iter().enumerate() {
        source.push(*frame).unwrap();
        assert_eq!(
            source.checkpoint().unwrap().digest.as_slice(),
            decoded_vector(vectors, &format!("prefix_{}", index + 1))
        );
    }
    let target = source.checkpoint().unwrap();
    assert_eq!(
        target.id().as_slice(),
        decoded_vector(vectors, "checkpoint_id")
    );
    let mut receiver = Receiver::begin(pinned, source_key, source_key, target).unwrap();
    assert_eq!(
        receiver.progress().digest.as_slice(),
        decoded_vector(vectors, "seed")
    );
    let step = receiver.prepare_page(page(target, 1, &frames)).unwrap();
    assert_eq!(
        receiver.commit_after_persist(step).unwrap(),
        Coverage::Complete
    );
}
