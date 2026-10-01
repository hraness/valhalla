use super::*;
use hegel::HealthCheck;
use std::{collections::BTreeMap, fs, path::PathBuf};
use tempfile::TempDir;
use vhalla_direct_room::{
    EventClaims, EventId, GenesisClaims, PolicyClaims, Text, UnsignedEvent, UnsignedGenesis,
    UnsignedPolicy,
};
use vhalla_direct_sync::{Coverage, Page as SyncPage, Receiver};
use vhalla_identity::Identity;

const SOURCE: [u8; 32] = [41; 32];

struct Fixture {
    root: TempDir,
    owner: Identity,
    author: Identity,
    genesis: PinnedGenesis,
}
impl Fixture {
    fn new() -> Self {
        let root = TempDir::new().unwrap();
        let owner = Identity::create_new(root.path().join("owner")).unwrap();
        let author = Identity::create_new(root.path().join("author")).unwrap();
        let genesis = pinned(&owner);
        Self {
            root,
            owner,
            author,
            genesis,
        }
    }
    fn path(&self) -> PathBuf {
        self.root.path().join("replica")
    }
    fn create(&self, limits: Limits) -> Replica {
        Replica::create_new(self.path(), self.genesis.clone(), SOURCE, limits).unwrap()
    }
    fn open(&self) -> Replica {
        Replica::open(self.path(), self.genesis.clone(), SOURCE).unwrap()
    }
    fn initial(&self) -> ReplicaFrame {
        ReplicaFrame {
            kind: FrameKind::Genesis,
            bytes: self.genesis.encode(),
        }
    }
    fn event(&self, n: u64) -> ReplicaFrame {
        // These are conflicting sequence-one frames from an unadmitted author.
        // A replica retains that evidence without claiming room admission.
        let signed = self
            .author
            .sign_direct_event(
                UnsignedEvent::new(EventClaims {
                    room: self.genesis.id(),
                    policy: self.genesis.id().initial_policy(),
                    author: self.author.public_key(),
                    sequence: 1,
                    previous: EventId::ZERO,
                    created_at: n,
                    text: Text::new(&format!("retained event {n}")).unwrap(),
                })
                .unwrap(),
            )
            .unwrap();
        ReplicaFrame {
            kind: FrameKind::Event,
            bytes: signed.encode(),
        }
    }
    fn policy(&self, admit: bool) -> ReplicaFrame {
        let mut writers = vec![self.owner.public_key()];
        if admit {
            writers.push(self.author.public_key());
            writers.sort_unstable();
        }
        let signed = self
            .owner
            .sign_direct_policy(
                UnsignedPolicy::new(PolicyClaims {
                    room: self.genesis.id(),
                    owner: self.owner.public_key(),
                    revision: 1,
                    previous: self.genesis.id().initial_policy(),
                    writers,
                    sealed_heads: vec![],
                })
                .unwrap(),
            )
            .unwrap();
        ReplicaFrame {
            kind: FrameKind::Policy,
            bytes: signed.encode(),
        }
    }
}

fn pinned(owner: &Identity) -> PinnedGenesis {
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).expect("room nonce entropy");
    let signed = owner
        .sign_direct_genesis(
            UnsignedGenesis::new(GenesisClaims {
                owner: owner.public_key(),
                nonce,
                writers: vec![owner.public_key()],
            })
            .unwrap(),
        )
        .unwrap();
    let pin = signed.id();
    signed.verify_pin(pin).unwrap()
}

fn limits() -> Limits {
    Limits {
        max_records: 1_000,
        max_record_bytes: 1024 * 1024,
    }
}

fn files(path: &Path) -> BTreeMap<String, Vec<u8>> {
    fs::read_dir(path)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (
                entry.file_name().into_string().unwrap(),
                fs::read(entry.path()).unwrap(),
            )
        })
        .collect()
}

fn check_coverage(replica: &mut Replica, genesis: PinnedGenesis, target: Checkpoint) {
    let mut receiver = Receiver::begin(genesis, SOURCE, SOURCE, target).unwrap();
    let mut after = 0;
    while let Some(page) = replica.page(target, after, 3).unwrap() {
        assert_eq!(page.checkpoint, target);
        assert!(page.last <= target.records);
        let frames: Vec<_> = page.frames.iter().map(ReplicaFrame::as_frame).collect();
        let prepared = receiver
            .prepare_page(SyncPage {
                checkpoint_id: target.id(),
                first: page.first,
                last: page.last,
                frames: &frames,
            })
            .unwrap();
        let coverage = receiver.commit_after_persist(prepared).unwrap();
        assert_eq!(coverage == Coverage::Complete, page.last == target.records);
        after = page.last;
    }
    assert_eq!(receiver.finish().unwrap(), target);
}

#[test]
fn creation_pins_genesis_source_and_random_epoch_without_signing_keys() {
    let fixture = Fixture::new();
    let mut replica = fixture.create(limits());
    let checkpoint = replica.checkpoint().unwrap();
    assert_eq!(checkpoint.source, SOURCE);
    assert_eq!(checkpoint.room, fixture.genesis.id());
    assert_ne!(checkpoint.epoch, [0; 32]);
    assert_eq!(checkpoint.records, 1);
    assert_eq!(checkpoint.bytes, fixture.genesis.encode().len() as u64);
    assert_eq!(replica.accounting().unwrap().generation, 1);
    let page = replica.page(checkpoint, 0, 32).unwrap().unwrap();
    assert_eq!((page.first, page.last), (1, 1));
    assert_eq!(page.frames, vec![fixture.initial()]);
    assert_eq!(replica.page(checkpoint, 1, 1).unwrap(), None);
    assert!(!fixture.path().join("author").exists());
    assert!(!fixture.path().join("identity").exists());
    assert!(Replica::open(fixture.path(), fixture.genesis.clone(), SOURCE).is_err());
    drop(replica);
    let before = files(&fixture.path());
    assert!(Replica::open(fixture.path(), fixture.genesis.clone(), [42; 32]).is_err());
    assert!(Replica::open(fixture.path(), pinned(&fixture.owner), SOURCE).is_err());
    assert!(
        Replica::create_new(fixture.path(), fixture.genesis.clone(), SOURCE, limits()).is_err()
    );
    assert_eq!(files(&fixture.path()), before);
    let mut reopened = fixture.open();
    assert_eq!(reopened.checkpoint().unwrap(), checkpoint);
    let mut other = Replica::create_new(
        fixture.root.path().join("other-replica"),
        fixture.genesis.clone(),
        SOURCE,
        limits(),
    )
    .unwrap();
    assert_ne!(other.checkpoint().unwrap().epoch, checkpoint.epoch);
}

#[test]
fn append_preserves_forks_and_unadmitted_frames_and_deduplicates_exact_retries() {
    let fixture = Fixture::new();
    let mut replica = fixture.create(limits());
    let initial = fixture.initial();
    let event = fixture.event(1);
    let fork = fixture.event(2);
    let policy = fixture.policy(false);
    let policy_fork = fixture.policy(true);
    let offered = [
        initial.as_frame(),
        event.as_frame(),
        event.as_frame(),
        fork.as_frame(),
        policy.as_frame(),
        policy_fork.as_frame(),
    ];
    let checkpoint = replica.append(&offered).unwrap();
    assert_eq!(checkpoint.records, 5);
    let accounting = replica.accounting().unwrap();
    assert_eq!(accounting.generation, 2);
    assert_eq!(
        accounting.bytes,
        checkpoint.bytes + 5 * RECORD_HEADER as u64
    );
    assert_eq!(replica.append(&offered).unwrap(), checkpoint);
    assert_eq!(replica.append(&[]).unwrap(), checkpoint);
    assert_eq!(replica.accounting().unwrap(), accounting);
    assert_eq!(
        replica.page(checkpoint, 0, 32).unwrap().unwrap().frames,
        vec![initial, event, fork, policy, policy_fork]
    );
    check_coverage(&mut replica, fixture.genesis.clone(), checkpoint);
    drop(replica);
    let mut replica = fixture.open();
    assert_eq!(replica.checkpoint().unwrap(), checkpoint);
    assert_eq!(replica.accounting().unwrap(), accounting);
}

#[test]
fn invalid_or_oversized_batches_publish_nothing() {
    let fixture = Fixture::new();
    let mut replica = fixture.create(limits());
    let checkpoint = replica.checkpoint().unwrap();
    let accounting = replica.accounting().unwrap();
    let valid = fixture.event(1);
    let mut damaged = fixture.event(2);
    *damaged.bytes.last_mut().unwrap() ^= 1;
    assert!(matches!(
        replica.append(&[valid.as_frame(), damaged.as_frame()]),
        Err(ReplicaError::Sync(_))
    ));
    let local_metadata = Frame {
        kind: FrameKind::Event,
        bytes: b"unpublished reservation and operation metadata",
    };
    assert!(replica.append(&[local_metadata]).is_err());
    let wrong_kind = Frame {
        kind: FrameKind::Policy,
        bytes: &valid.bytes,
    };
    assert!(replica.append(&[wrong_kind]).is_err());
    let oversized = vec![0; MAX_EVENT_BYTES + 1];
    assert_eq!(
        replica.append(&[Frame {
            kind: FrameKind::Event,
            bytes: &oversized,
        }]),
        Err(vhalla_direct_sync::Error::Bounds.into())
    );
    assert_eq!(
        replica.append(&[valid.as_frame(); 9]),
        Err(vhalla_direct_sync::Error::Bounds.into())
    );
    let foreign = pinned(&fixture.owner);
    let foreign_genesis = foreign.encode();
    assert!(replica
        .append(&[Frame {
            kind: FrameKind::Genesis,
            bytes: &foreign_genesis,
        }])
        .is_err());
    let foreign_event = fixture
        .author
        .sign_direct_event(
            UnsignedEvent::new(EventClaims {
                room: foreign.id(),
                policy: foreign.id().initial_policy(),
                author: fixture.author.public_key(),
                sequence: 1,
                previous: EventId::ZERO,
                created_at: 1,
                text: Text::new("foreign").unwrap(),
            })
            .unwrap(),
        )
        .unwrap()
        .encode();
    assert_eq!(
        replica.append(&[Frame {
            kind: FrameKind::Event,
            bytes: &foreign_event,
        }]),
        Err(vhalla_direct_sync::Error::Room.into())
    );
    let wrong_owner = fixture
        .author
        .sign_direct_policy(
            UnsignedPolicy::new(PolicyClaims {
                room: fixture.genesis.id(),
                owner: fixture.author.public_key(),
                revision: 1,
                previous: fixture.genesis.id().initial_policy(),
                writers: vec![fixture.author.public_key()],
                sealed_heads: vec![],
            })
            .unwrap(),
        )
        .unwrap()
        .encode();
    assert_eq!(
        replica.append(&[Frame {
            kind: FrameKind::Policy,
            bytes: &wrong_owner,
        }]),
        Err(vhalla_direct_sync::Error::Protocol(vhalla_direct_room::Error::Owner).into())
    );
    assert_eq!(replica.checkpoint().unwrap(), checkpoint);
    assert_eq!(replica.accounting().unwrap(), accounting);
    assert_eq!(replica.append(&[valid.as_frame()]).unwrap().records, 2);
}

#[test]
fn old_checkpoint_pages_remain_exact_after_append_and_reopen() {
    let fixture = Fixture::new();
    let mut replica = fixture.create(limits());
    let frames: Vec<_> = (1..=40).map(|n| fixture.event(n)).collect();
    let mut snapshots = vec![replica.checkpoint().unwrap()];
    for chunk in frames.chunks(8) {
        let borrowed: Vec<_> = chunk.iter().map(ReplicaFrame::as_frame).collect();
        snapshots.push(replica.append(&borrowed).unwrap());
    }
    for snapshot in &snapshots {
        check_coverage(&mut replica, fixture.genesis.clone(), *snapshot);
        let page = replica.page(*snapshot, 0, 32).unwrap().unwrap();
        assert_eq!(page.last, snapshot.records.min(32));
        assert!(page.frames.len() <= 32);
    }
    let accounting = replica.accounting().unwrap();
    drop(replica);
    let mut replica = fixture.open();
    for snapshot in snapshots {
        check_coverage(&mut replica, fixture.genesis.clone(), snapshot);
    }
    assert_eq!(replica.accounting().unwrap(), accounting);
}

#[test]
fn forged_checkpoints_and_invalid_ranges_refuse_without_poisoning() {
    let fixture = Fixture::new();
    let mut replica = fixture.create(limits());
    let event = fixture.event(1);
    let checkpoint = replica.append(&[event.as_frame()]).unwrap();
    for change in 0..7 {
        let mut forged = checkpoint;
        match change {
            0 => forged.source[0] ^= 1,
            1 => forged.room = RoomId::from_bytes([9; 32]),
            2 => forged.epoch[0] ^= 1,
            3 => forged.records = 0,
            4 => forged.records += 1,
            5 => forged.bytes ^= 1,
            _ => forged.digest[0] ^= 1,
        }
        assert!(matches!(
            replica.page(forged, 0, 1),
            Err(ReplicaError::Sync(_))
        ));
        assert_eq!(replica.checkpoint().unwrap(), checkpoint);
    }
    assert_eq!(
        replica.page(checkpoint, u64::MAX, 1),
        Err(vhalla_direct_sync::Error::Sequence.into())
    );
    for limit in [0, 33, usize::MAX] {
        assert_eq!(
            replica.page(checkpoint, 0, limit),
            Err(vhalla_direct_sync::Error::Bounds.into())
        );
    }
    assert_eq!(replica.checkpoint().unwrap(), checkpoint);
}

#[test]
fn capacity_refusal_and_growth_preserve_every_prior_checkpoint() {
    let fixture = Fixture::new();
    let first = fixture.event(1);
    let second = fixture.event(2);
    let exact_bytes =
        (fixture.initial().bytes.len() + first.bytes.len() + 2 * RECORD_HEADER) as u64;
    let small = Limits {
        max_records: 2,
        max_record_bytes: exact_bytes,
    };
    let mut replica = fixture.create(small);
    let initial = replica.checkpoint().unwrap();
    assert_eq!(
        replica.append(&[first.as_frame(), second.as_frame()]),
        Err(vhalla_direct_store::Error::Refused.into())
    );
    assert_eq!(replica.checkpoint().unwrap(), initial);
    let full = replica.append(&[first.as_frame()]).unwrap();
    let accounting = replica.accounting().unwrap();
    assert_eq!(accounting.bytes, exact_bytes);
    assert_eq!(
        replica.append(&[second.as_frame()]),
        Err(vhalla_direct_store::Error::Refused.into())
    );
    assert_eq!(replica.append(&[first.as_frame()]).unwrap(), full);
    assert_eq!(replica.expand_limits(small).unwrap(), accounting);
    assert_eq!(
        replica.expand_limits(Limits {
            max_records: 1,
            ..small
        }),
        Err(vhalla_direct_store::Error::Refused.into())
    );
    // Raising only the record allowance still leaves the byte allowance full.
    replica
        .expand_limits(Limits {
            max_records: 4,
            ..small
        })
        .unwrap();
    assert_eq!(
        replica.append(&[second.as_frame()]),
        Err(vhalla_direct_store::Error::Refused.into())
    );
    let larger = Limits {
        max_records: 4,
        max_record_bytes: exact_bytes + 4096,
    };
    let expanded = replica.expand_limits(larger).unwrap();
    assert_eq!(expanded.generation, accounting.generation);
    assert_eq!(replica.checkpoint().unwrap(), full);
    assert_eq!(replica.append(&[second.as_frame()]).unwrap().records, 3);
    check_coverage(&mut replica, fixture.genesis.clone(), full);
    check_coverage(&mut replica, fixture.genesis.clone(), initial);
    drop(replica);
    let mut replica = fixture.open();
    assert_eq!(replica.accounting().unwrap().limits, larger);
    check_coverage(&mut replica, fixture.genesis.clone(), full);
}

#[test]
fn missing_or_foreign_images_preserve_incomplete_creation() {
    for image in [None, Some(b"foreign controller state".as_slice())] {
        let fixture = Fixture::new();
        let context = Context::new(*fixture.genesis.id().as_bytes(), SOURCE).unwrap();
        let mut store = Store::create_new(fixture.path(), context, limits()).unwrap();
        if let Some(image) = image {
            store.publish(None, image, &[]).unwrap();
        }
        drop(store);
        let before = files(&fixture.path());
        assert_eq!(
            Replica::open(fixture.path(), fixture.genesis.clone(), SOURCE).err(),
            Some(corrupt())
        );
        assert!(
            Replica::create_new(fixture.path(), fixture.genesis.clone(), SOURCE, limits()).is_err()
        );
        assert_eq!(files(&fixture.path()), before);
    }
    let fixture = Fixture::new();
    assert!(
        Replica::create_new(fixture.path(), fixture.genesis.clone(), [0; 32], limits()).is_err()
    );
    assert!(!fixture.path().exists());
    assert!(Replica::create_new(
        fixture.path(),
        fixture.genesis.clone(),
        SOURCE,
        Limits {
            max_records: 1,
            max_record_bytes: 1
        },
    )
    .is_err());
    assert!(!fixture.path().exists());
}

#[test]
fn open_replays_interior_digests_signatures_positions_and_the_terminal_image() {
    for corruption in 0..5 {
        let fixture = Fixture::new();
        let frames = [fixture.initial(), fixture.event(1), fixture.event(2)];
        let mut source = SourceAccumulator::new(SOURCE, fixture.genesis.clone(), [7; 32]).unwrap();
        let mut records = Vec::new();
        for frame in &frames {
            source.push(frame.as_frame()).unwrap();
            records.push(encode_record(source.checkpoint().unwrap(), frame.as_frame()).unwrap());
        }
        let mut image = encode_image(source.checkpoint().unwrap());
        if corruption == 4 {
            image[120] ^= 1;
        } else {
            let mut raw = records[1].as_bytes().to_vec();
            let mut key = records[1].key();
            match corruption {
                0 => raw[25] ^= 1,
                1 => raw[16] ^= 1,
                2 => raw[24] ^= 1,
                _ => {
                    *raw.last_mut().unwrap() ^= 1;
                    key = frame_key(Frame {
                        kind: FrameKind::Event,
                        bytes: &raw[RECORD_HEADER..],
                    })
                    .unwrap();
                }
            }
            records[1] = Record::new(key, &raw).unwrap();
        }
        let context = Context::new(*fixture.genesis.id().as_bytes(), SOURCE).unwrap();
        let mut store = Store::create_new(fixture.path(), context, limits()).unwrap();
        store.publish(None, &image, &records).unwrap();
        drop(store);
        let before = files(&fixture.path());
        assert_eq!(
            Replica::open(fixture.path(), fixture.genesis.clone(), SOURCE).err(),
            Some(corrupt())
        );
        assert_eq!(files(&fixture.path()), before);
    }
}

#[test]
fn uncertain_publication_requires_reopen_and_exact_retry_is_idempotent() {
    for point in [
        PublicationPoint::BeforePublish,
        PublicationPoint::AfterPublish,
    ] {
        let fixture = Fixture::new();
        let mut replica = fixture.create(limits());
        let before = replica.checkpoint().unwrap();
        let frames = [fixture.event(1), fixture.event(2)];
        let borrowed: Vec<_> = frames.iter().map(ReplicaFrame::as_frame).collect();
        replica.fault = Some(point);
        assert_eq!(replica.append(&borrowed), Err(uncertain()));
        assert_eq!(replica.checkpoint(), Err(uncertain()));
        assert_eq!(replica.append(&[]), Err(uncertain()));
        assert_eq!(replica.page(before, 0, 1), Err(uncertain()));
        assert_eq!(replica.expand_limits(limits()), Err(uncertain()));
        drop(replica);
        let mut replica = fixture.open();
        let recovered = replica.checkpoint().unwrap();
        assert_eq!(recovered.epoch, before.epoch);
        assert_eq!(
            recovered.records,
            if point == PublicationPoint::BeforePublish {
                1
            } else {
                3
            }
        );
        let final_checkpoint = replica.append(&borrowed).unwrap();
        assert_eq!(final_checkpoint.records, 3);
        assert_eq!(replica.accounting().unwrap().generation, 2);
        assert_eq!(replica.append(&borrowed).unwrap(), final_checkpoint);
        check_coverage(&mut replica, fixture.genesis.clone(), before);
        check_coverage(&mut replica, fixture.genesis.clone(), final_checkpoint);
    }
}

#[test]
fn changed_live_image_poisoning_prevents_cache_reuse() {
    let fixture = Fixture::new();
    let mut replica = fixture.create(limits());
    let checkpoint = replica.checkpoint().unwrap();
    replica
        .store
        .publish(Some(&replica.image), b"different image", &[])
        .unwrap();
    let before = files(&fixture.path());
    assert_eq!(replica.checkpoint(), Err(corrupt()));
    assert_eq!(replica.page(checkpoint, 0, 1), Err(uncertain()));
    assert_eq!(
        replica.append(&[fixture.event(1).as_frame()]),
        Err(uncertain())
    );
    assert_eq!(files(&fixture.path()), before);
}

#[hegel::test(test_cases = 64, suppress_health_check = [HealthCheck::TooSlow])]
fn replica_interleaved_retry_snapshot_fault_capacity_and_reopen_match_model(tc: hegel::TestCase) {
    let fixture = Fixture::new();
    let pool: Vec<_> = (1..=8).map(|n| fixture.event(n)).collect();
    let mut selected = Limits {
        max_records: 3,
        max_record_bytes: 4096,
    };
    let mut replica = fixture.create(selected);
    let initial = replica.checkpoint().unwrap();
    let mut model = vec![fixture.initial()];
    let mut generation = 1;
    let mut snapshots = vec![initial];
    let steps = tc.draw(
        hegel::generators::integers::<usize>()
            .min_value(8)
            .max_value(24),
    );
    for _ in 0..steps {
        match tc.draw(hegel::generators::integers::<u8>().max_value(6)) {
            0 => {
                let count = tc.draw(hegel::generators::integers::<usize>().max_value(8));
                let mut offered = Vec::new();
                let mut expected = model.clone();
                for _ in 0..count {
                    let index =
                        tc.draw(hegel::generators::integers::<usize>().max_value(pool.len() - 1));
                    let frame = &pool[index];
                    offered.push(frame.as_frame());
                    if !expected.contains(frame) {
                        expected.push(frame.clone());
                    }
                }
                let outcome = replica.append(&offered);
                if expected.len() as u64 > selected.max_records {
                    assert_eq!(outcome, Err(vhalla_direct_store::Error::Refused.into()));
                } else {
                    outcome.unwrap();
                    if expected.len() != model.len() {
                        generation += 1;
                    }
                    model = expected;
                }
            }
            1 => {
                drop(replica);
                replica = fixture.open();
            }
            2 => snapshots.push(replica.checkpoint().unwrap()),
            3 => {
                let index =
                    tc.draw(hegel::generators::integers::<usize>().max_value(snapshots.len() - 1));
                let target = snapshots[index];
                let after = tc.draw(hegel::generators::integers::<u64>().max_value(target.records));
                let limit = tc.draw(
                    hegel::generators::integers::<usize>()
                        .min_value(1)
                        .max_value(32),
                );
                let page = replica.page(target, after, limit).unwrap();
                if after == target.records {
                    assert_eq!(page, None);
                } else {
                    let page = page.unwrap();
                    let end = target.records.min(after + limit as u64);
                    assert_eq!((page.first, page.last), (after + 1, end));
                    assert_eq!(page.frames, model[after as usize..end as usize]);
                }
            }
            4 => {
                let growth = tc.draw(hegel::generators::integers::<u64>().max_value(3));
                selected.max_records += growth;
                selected.max_record_bytes += growth * 1024;
                assert_eq!(replica.expand_limits(selected).unwrap().limits, selected);
            }
            5 => {
                let after_publish = tc.draw(hegel::generators::integers::<u8>().max_value(1)) == 1;
                let fresh = pool
                    .iter()
                    .find(|frame| !model.contains(frame))
                    .filter(|_| (model.len() as u64) < selected.max_records);
                if let Some(frame) = fresh {
                    replica.fault = Some(if after_publish {
                        PublicationPoint::AfterPublish
                    } else {
                        PublicationPoint::BeforePublish
                    });
                    assert_eq!(replica.append(&[frame.as_frame()]), Err(uncertain()));
                    drop(replica);
                    replica = fixture.open();
                    if after_publish {
                        model.push(frame.clone());
                        generation += 1;
                    }
                }
            }
            _ => {
                let mut target = replica.checkpoint().unwrap();
                target.digest[0] ^= 1;
                assert_eq!(
                    replica.page(target, 0, 1),
                    Err(vhalla_direct_sync::Error::Checkpoint.into())
                );
            }
        }
        let mut reference =
            SourceAccumulator::new(SOURCE, fixture.genesis.clone(), initial.epoch).unwrap();
        for frame in &model {
            reference.push(frame.as_frame()).unwrap();
        }
        assert_eq!(
            replica.checkpoint().unwrap(),
            reference.checkpoint().unwrap()
        );
        let accounting = replica.accounting().unwrap();
        assert_eq!(accounting.generation, generation);
        assert_eq!(accounting.records, model.len() as u64);
        assert_eq!(accounting.limits, selected);
        assert_eq!(
            accounting.bytes,
            model
                .iter()
                .map(|frame| (frame.bytes.len() + RECORD_HEADER) as u64)
                .sum::<u64>()
        );
    }
}
