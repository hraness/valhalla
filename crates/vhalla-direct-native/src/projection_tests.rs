use super::*;
use hegel::HealthCheck;
use std::{collections::BTreeSet, fs, path::PathBuf, sync::Arc};
use tempfile::TempDir;
use vhalla_direct_room::{EventClaims, EventId, PolicyClaims, Text, UnsignedEvent, UnsignedPolicy};
use vhalla_identity::Identity;

const SOURCE: [u8; 32] = [91; 32];

struct Fixture {
    root: TempDir,
    account: Arc<Identity>,
    room: RoomSession,
    backing: Replica,
}
impl Fixture {
    fn new(native_limits: Limits, replica_limits: Limits) -> Self {
        let root = TempDir::new().unwrap();
        let account = Arc::new(Identity::create_new(root.path().join("account")).unwrap());
        let room =
            RoomSession::create(account.clone(), root.path().join("room"), native_limits).unwrap();
        let backing = Replica::create_new(
            root.path().join("replica"),
            room.genesis().clone(),
            SOURCE,
            replica_limits,
        )
        .unwrap();
        Self {
            root,
            account,
            room,
            backing,
        }
    }
    fn path(&self) -> PathBuf {
        self.root.path().join("projection")
    }
    fn create(&mut self, limits: Limits) -> Projection {
        Projection::create_new(self.path(), &mut self.room, &mut self.backing, limits).unwrap()
    }
    fn open(&mut self) -> Projection {
        Projection::open(self.path(), &mut self.room, &mut self.backing).unwrap()
    }
    fn step(
        &mut self,
        projection: &mut Projection,
        direction: ProjectionDirection,
    ) -> ProjectionResult<ProjectionStep> {
        projection.step(direction, &mut self.room, &mut self.backing)
    }
    fn status(&mut self, projection: &mut Projection) -> ProjectionStatus {
        projection
            .status(&mut self.room, &mut self.backing)
            .unwrap()
    }
    fn send(&mut self, number: u8) {
        self.room
            .send(
                [number; 16],
                &format!("local event {number}"),
                number as u64,
            )
            .unwrap();
    }
    fn remote_chain(&self, count: usize) -> Vec<ReplicaFrame> {
        let mut previous = EventId::ZERO;
        let mut frames = Vec::new();
        for number in 1..=count {
            let signed = self
                .account
                .sign_direct_event(
                    UnsignedEvent::new(EventClaims {
                        room: self.room.room_id(),
                        policy: self.room.room_id().initial_policy(),
                        author: self.account.public_key(),
                        sequence: number as u64,
                        previous,
                        created_at: number as u64,
                        text: Text::new(&format!("remote event {number}")).unwrap(),
                    })
                    .unwrap(),
                )
                .unwrap();
            previous = signed.id();
            frames.push(ReplicaFrame {
                kind: FrameKind::Event,
                bytes: signed.encode(),
            });
        }
        frames
    }
}

fn limits() -> Limits {
    Limits {
        max_records: 10_000,
        max_record_bytes: 8 * 1024 * 1024,
    }
}
fn append(backing: &mut Replica, frames: &[ReplicaFrame]) {
    for chunk in frames.chunks(8) {
        let borrowed: Vec<_> = chunk.iter().map(ReplicaFrame::as_frame).collect();
        backing.append(&borrowed).unwrap();
    }
}
fn outward(fixture: &mut Fixture, projection: &mut Projection) {
    for _ in 0..100 {
        let status = fixture.status(projection);
        if status.outward_cursor == status.native_tip && status.pending.is_none() {
            return;
        }
        let step = fixture
            .step(projection, ProjectionDirection::Outward)
            .unwrap();
        assert!(step.frames <= 8 && step.scanned <= 128);
    }
    panic!("outward local drain did not finish");
}
fn inward(fixture: &mut Fixture, projection: &mut Projection) {
    for _ in 0..100 {
        let status = fixture.status(projection);
        if status.inward_cursor == status.replica_tip && status.pending.is_none() {
            return;
        }
        let step = fixture
            .step(projection, ProjectionDirection::Inward)
            .unwrap();
        assert!(step.frames <= 1);
        assert_eq!(step.scanned, 0);
    }
    panic!("inward local drain did not finish");
}
fn public_frames(room: &mut RoomSession) -> Vec<(u64, ReplicaFrame)> {
    let mut after = 0;
    let mut output = Vec::new();
    loop {
        let page = room.replicated_records(after, 32).unwrap();
        output.extend(page.records.into_iter().map(|record| {
            (
                record.cursor,
                ReplicaFrame {
                    kind: frame_kind(record.kind),
                    bytes: record.bytes,
                },
            )
        }));
        match page.next {
            Some(next) => after = next,
            None => break,
        }
    }
    output
}
fn replica_frames(backing: &mut Replica) -> Vec<ReplicaFrame> {
    let target = backing.checkpoint().unwrap();
    let mut after = 0;
    let mut frames = Vec::new();
    while let Some(page) = backing.page(target, after, 32).unwrap() {
        after = page.last;
        frames.extend(page.frames);
    }
    frames
}

#[test]
fn both_directions_are_bounded_and_reach_only_local_signed_prefixes() {
    let mut fixture = Fixture::new(limits(), limits());
    for number in 1..=17 {
        fixture.send(number);
    }
    let mut projection = fixture.create(limits());
    outward(&mut fixture, &mut projection);
    assert_eq!(fixture.backing.checkpoint().unwrap().records, 18);
    let expected: BTreeSet<_> = public_frames(&mut fixture.room)
        .into_iter()
        .map(|(_, frame)| frame.bytes)
        .collect();
    let copied: BTreeSet<_> = replica_frames(&mut fixture.backing)
        .into_iter()
        .map(|frame| frame.bytes)
        .collect();
    assert_eq!(expected, copied);
    let native_before = fixture.room.status().unwrap();
    inward(&mut fixture, &mut projection);
    let native_after = fixture.room.status().unwrap();
    assert_eq!(native_after.storage, native_before.storage);
    assert!(!native_after.author_custody_lost && !native_after.owner_custody_lost);
    assert_eq!(fixture.room.operations(0, 32).unwrap().operations.len(), 17);
    let status = fixture.status(&mut projection);
    drop(projection);
    let mut projection = fixture.open();
    assert_eq!(fixture.status(&mut projection), status);
    let accounting = projection
        .accounting(&mut fixture.room, &mut fixture.backing)
        .unwrap();
    assert_eq!(
        fixture
            .step(&mut projection, ProjectionDirection::Outward)
            .unwrap()
            .frames,
        0
    );
    assert_eq!(
        fixture
            .step(&mut projection, ProjectionDirection::Inward)
            .unwrap()
            .frames,
        0
    );
    assert_eq!(
        projection
            .accounting(&mut fixture.room, &mut fixture.backing)
            .unwrap(),
        accounting
    );
}

#[test]
fn an_empty_filtered_tail_advances_after_all_its_public_bytes_were_retained() {
    let mut fixture = Fixture::new(limits(), limits());
    for number in 1..=7 {
        fixture.send(number);
    }
    let mut projection = fixture.create(limits());
    let first = fixture
        .step(&mut projection, ProjectionDirection::Outward)
        .unwrap();
    assert_eq!(first.frames, 8);
    assert!(first.status.outward_cursor < first.status.native_tip);
    let checkpoint = fixture.backing.checkpoint().unwrap();
    let tail = fixture
        .step(&mut projection, ProjectionDirection::Outward)
        .unwrap();
    assert_eq!(tail.frames, 0);
    assert!(tail.scanned > 0 && tail.scanned <= 128);
    assert_eq!(tail.status.outward_cursor, tail.status.native_tip);
    assert_eq!(fixture.backing.checkpoint().unwrap(), checkpoint);
    drop(projection);
    let mut projection = fixture.open();
    assert_eq!(
        fixture.status(&mut projection).outward_cursor,
        tail.status.outward_cursor
    );
}

#[test]
fn projection_never_completes_a_pending_native_signing_reservation() {
    let mut fixture = Fixture::new(limits(), limits());
    let operation = [90; 16];
    let unsigned = UnsignedEvent::new(EventClaims {
        room: fixture.room.room_id(),
        policy: fixture.room.room_id().initial_policy(),
        author: fixture.room.author_key(),
        sequence: 1,
        previous: EventId::ZERO,
        created_at: 1,
        text: Text::new("reserved content must stay local and unsigned").unwrap(),
    })
    .unwrap();
    let reservation = codec::Reservation {
        operation,
        kind: codec::EVENT,
        unsigned: unsigned.encode(),
    };
    let mut image = fixture.room.image.clone();
    image.pending_event = Some(operation);
    fixture
        .room
        .publish(
            image,
            &[Record::new(
                codec::operation_key(codec::RESERVATION, operation),
                &reservation.encode(),
            )
            .unwrap()],
            false,
        )
        .unwrap();
    let before = fixture.room.status().unwrap().storage;
    let mut projection = fixture.create(limits());
    outward(&mut fixture, &mut projection);
    inward(&mut fixture, &mut projection);
    let after = fixture.room.status().unwrap();
    assert_eq!(after.storage, before);
    assert_eq!(after.pending_event_operation, Some(operation));
    assert!(fixture
        .room
        .operations(0, 32)
        .unwrap()
        .operations
        .is_empty());
    assert_eq!(fixture.backing.checkpoint().unwrap().records, 1);
}

#[test]
fn outward_crash_boundaries_preserve_intent_and_exact_bytes_after_native_growth() {
    for point in [
        FaultPoint::AfterIntent,
        FaultPoint::AfterDestination,
        FaultPoint::BeforeComplete,
        FaultPoint::AfterComplete,
    ] {
        let mut fixture = Fixture::new(limits(), limits());
        fixture.send(1);
        fixture.send(2);
        let mut projection = fixture.create(limits());
        let old_tip = fixture.room.status().unwrap().storage.tip;
        projection.fault = Some(point);
        assert_eq!(
            fixture.step(&mut projection, ProjectionDirection::Outward),
            Err(uncertain())
        );
        assert_eq!(
            projection.status(&mut fixture.room, &mut fixture.backing),
            Err(uncertain())
        );
        assert_eq!(
            fixture.backing.checkpoint().unwrap().records,
            if point == FaultPoint::AfterIntent {
                1
            } else {
                3
            }
        );
        drop(projection);
        fixture.send(3);
        let mut projection = fixture.open();
        let status = fixture.status(&mut projection);
        if point == FaultPoint::AfterComplete {
            assert_eq!(status.outward_cursor, old_tip);
            assert_eq!(status.pending, None);
        } else {
            assert_eq!(status.outward_cursor, 0);
            assert_eq!(status.pending, Some(ProjectionDirection::Outward));
            assert_eq!(
                fixture.step(&mut projection, ProjectionDirection::Inward),
                Err(ProjectionError::Pending(ProjectionDirection::Outward))
            );
            let resumed = fixture
                .step(&mut projection, ProjectionDirection::Outward)
                .unwrap();
            assert!(resumed.resumed);
            assert_eq!(resumed.status.outward_cursor, old_tip);
        }
        assert_eq!(fixture.backing.checkpoint().unwrap().records, 3);
        outward(&mut fixture, &mut projection);
        assert_eq!(fixture.backing.checkpoint().unwrap().records, 4);
    }
}

#[test]
fn inward_crash_boundaries_never_advance_before_durable_native_retention() {
    for point in [
        FaultPoint::AfterIntent,
        FaultPoint::AfterDestination,
        FaultPoint::BeforeComplete,
        FaultPoint::AfterComplete,
    ] {
        let mut fixture = Fixture::new(limits(), limits());
        let frames = fixture.remote_chain(1);
        append(&mut fixture.backing, &frames);
        let mut projection = fixture.create(limits());
        fixture
            .step(&mut projection, ProjectionDirection::Inward)
            .unwrap();
        projection.fault = Some(point);
        assert_eq!(
            fixture.step(&mut projection, ProjectionDirection::Inward),
            Err(uncertain())
        );
        let retained = public_frames(&mut fixture.room)
            .into_iter()
            .any(|(_, frame)| frame == frames[0]);
        assert_eq!(retained, point != FaultPoint::AfterIntent);
        drop(projection);
        let mut projection = fixture.open();
        let status = fixture.status(&mut projection);
        assert_eq!(
            status.inward_cursor,
            if point == FaultPoint::AfterComplete {
                2
            } else {
                1
            }
        );
        if point != FaultPoint::AfterComplete {
            assert!(
                fixture
                    .step(&mut projection, ProjectionDirection::Inward)
                    .unwrap()
                    .resumed
            );
        }
        assert_eq!(fixture.status(&mut projection).inward_cursor, 2);
        assert_eq!(fixture.room.messages(0, 32).unwrap().messages.len(), 1);
        assert!(fixture
            .room
            .operations(0, 32)
            .unwrap()
            .operations
            .is_empty());
    }
}

#[test]
fn incomplete_history_and_owner_forks_remain_native_evidence_without_signing_reconcile() {
    let mut fixture = Fixture::new(limits(), limits());
    let gap = fixture
        .account
        .sign_direct_event(
            UnsignedEvent::new(EventClaims {
                room: fixture.room.room_id(),
                policy: fixture.room.room_id().initial_policy(),
                author: fixture.account.public_key(),
                sequence: 2,
                previous: EventId::from_bytes([92; 32]),
                created_at: 2,
                text: Text::new("missing ancestry").unwrap(),
            })
            .unwrap(),
        )
        .unwrap();
    append(
        &mut fixture.backing,
        &[ReplicaFrame {
            kind: FrameKind::Event,
            bytes: gap.encode(),
        }],
    );
    let mut projection = fixture.create(limits());
    inward(&mut fixture, &mut projection);
    assert_eq!(
        fixture.room.messages(0, 32).unwrap().messages[0].visibility,
        crate::Visibility::Incomplete
    );
    let mut policies = Vec::new();
    for writers in [
        vec![fixture.account.public_key()],
        fixture.room.genesis().claims().writers.clone(),
    ] {
        let policy = fixture
            .account
            .sign_direct_policy(
                UnsignedPolicy::new(PolicyClaims {
                    room: fixture.room.room_id(),
                    owner: fixture.account.public_key(),
                    revision: 1,
                    previous: fixture.room.room_id().initial_policy(),
                    writers,
                    sealed_heads: vec![],
                })
                .unwrap(),
            )
            .unwrap();
        policies.push(ReplicaFrame {
            kind: FrameKind::Policy,
            bytes: policy.encode(),
        });
    }
    append(&mut fixture.backing, &policies);
    inward(&mut fixture, &mut projection);
    let status = fixture.room.status().unwrap();
    assert!(status.owner_forked && status.owner_custody_lost);
    assert!(!status.can_send);
    assert_eq!(fixture.room.operations(0, 32).unwrap().operations.len(), 0);
    assert_eq!(fixture.status(&mut projection).inward_cursor, 4);
    drop(projection);
    let mut projection = fixture.open();
    assert_eq!(fixture.status(&mut projection).inward_cursor, 4);
}

#[test]
fn native_capacity_failure_keeps_the_exact_pending_frame_for_explicit_growth() {
    let mut fixture = Fixture::new(
        Limits {
            max_records: 75,
            ..limits()
        },
        limits(),
    );
    let frames = fixture.remote_chain(5);
    append(&mut fixture.backing, &frames);
    let mut projection = fixture.create(limits());
    for _ in 0..5 {
        fixture
            .step(&mut projection, ProjectionDirection::Inward)
            .unwrap();
    }
    assert_eq!(
        fixture.step(&mut projection, ProjectionDirection::Inward),
        Err(ProjectionError::Native(crate::Error::Capacity))
    );
    assert_eq!(
        projection.status(&mut fixture.room, &mut fixture.backing),
        Err(uncertain())
    );
    drop(projection);
    let mut projection = fixture.open();
    assert_eq!(fixture.status(&mut projection).inward_cursor, 5);
    assert_eq!(
        fixture.status(&mut projection).pending,
        Some(ProjectionDirection::Inward)
    );
    fixture.room.expand_limits(limits()).unwrap();
    let result = fixture
        .step(&mut projection, ProjectionDirection::Inward)
        .unwrap();
    assert!(result.resumed);
    assert_eq!(result.status.inward_cursor, 6);
    assert_eq!(fixture.room.messages(0, 32).unwrap().messages.len(), 5);
}

#[test]
fn ledger_and_replica_quota_refusals_do_not_discard_durable_intent() {
    let mut fixture = Fixture::new(
        limits(),
        Limits {
            max_records: 1,
            ..limits()
        },
    );
    fixture.send(1);
    let mut projection = fixture.create(Limits {
        max_records: 2,
        ..limits()
    });
    assert_eq!(
        fixture.step(&mut projection, ProjectionDirection::Outward),
        Err(vhalla_direct_store::Error::Refused.into())
    );
    assert_eq!(fixture.status(&mut projection).pending, None);
    assert_eq!(
        projection
            .accounting(&mut fixture.room, &mut fixture.backing)
            .unwrap()
            .records,
        1
    );
    projection
        .expand_limits(limits(), &mut fixture.room, &mut fixture.backing)
        .unwrap();
    assert_eq!(
        fixture.step(&mut projection, ProjectionDirection::Outward),
        Err(ProjectionError::Replica(ReplicaError::Store(
            vhalla_direct_store::Error::Refused
        )))
    );
    assert_eq!(
        fixture.status(&mut projection).pending,
        Some(ProjectionDirection::Outward)
    );
    assert_eq!(fixture.status(&mut projection).outward_cursor, 0);
    fixture.backing.expand_limits(limits()).unwrap();
    assert!(
        fixture
            .step(&mut projection, ProjectionDirection::Outward)
            .unwrap()
            .resumed
    );
    let accounting = projection
        .accounting(&mut fixture.room, &mut fixture.backing)
        .unwrap();
    assert_eq!(accounting.records, 3);
    let status = fixture.status(&mut projection);
    assert!(projection
        .expand_limits(
            Limits {
                max_records: 3,
                ..limits()
            },
            &mut fixture.room,
            &mut fixture.backing
        )
        .is_err());
    assert_eq!(fixture.status(&mut projection), status);
}

#[test]
fn room_author_nonce_mode_and_replica_incarnation_are_bound() {
    let mut fixture = Fixture::new(limits(), limits());
    let mut projection = fixture.create(limits());
    assert!(Projection::open(fixture.path(), &mut fixture.room, &mut fixture.backing).is_err());
    let actual = fixture.room.creation_nonce;
    fixture.room.creation_nonce = [93; 32];
    assert_eq!(
        projection.status(&mut fixture.room, &mut fixture.backing),
        Err(ProjectionError::Binding)
    );
    fixture.room.creation_nonce = actual;
    drop(projection);
    let mut projection = fixture.open();
    fixture.room.created_here = false;
    assert_eq!(
        projection.status(&mut fixture.room, &mut fixture.backing),
        Err(ProjectionError::Binding)
    );
    fixture.room.created_here = true;
    drop(projection);
    let mut joined = RoomSession::join(
        fixture.account.clone(),
        fixture.root.path().join("joined"),
        &fixture.room.genesis().encode(),
        fixture.room.room_id(),
        limits(),
    )
    .unwrap();
    assert!(Projection::open(fixture.path(), &mut joined, &mut fixture.backing).is_err());
    let mut projection = fixture.open();
    let mut other = Replica::create_new(
        fixture.root.path().join("other-replica"),
        fixture.room.genesis().clone(),
        SOURCE,
        limits(),
    )
    .unwrap();
    assert_eq!(
        projection.status(&mut fixture.room, &mut other),
        Err(ProjectionError::Binding)
    );
    assert_eq!(
        projection.status(&mut fixture.room, &mut fixture.backing),
        Err(uncertain())
    );
}

#[test]
fn live_directory_replacement_and_same_epoch_replica_rollback_cannot_reuse_cursors() {
    let mut fixture = Fixture::new(limits(), limits());
    let rollback_path = fixture.root.path().join("old-replica");
    vhalla_custody::create_private_directory(&rollback_path).unwrap();
    // This owned test store is idle and fully published. Copy only the public
    // replica's files, never controller signing custody, to model an old cache.
    for entry in fs::read_dir(fixture.root.path().join("replica")).unwrap() {
        let entry = entry.unwrap();
        assert!(entry.file_type().unwrap().is_file());
        fs::copy(entry.path(), rollback_path.join(entry.file_name())).unwrap();
    }
    fixture.send(1);
    let mut projection = fixture.create(limits());
    outward(&mut fixture, &mut projection);
    let mut rollback =
        Replica::open(rollback_path, fixture.room.genesis().clone(), SOURCE).unwrap();
    assert_eq!(
        rollback.checkpoint().unwrap().epoch,
        fixture.backing.checkpoint().unwrap().epoch
    );
    assert_eq!(
        projection.status(&mut fixture.room, &mut rollback),
        Err(ProjectionError::Binding)
    );
    drop(projection);
    assert!(Projection::open(fixture.path(), &mut fixture.room, &mut rollback).is_err());
    let mut projection = fixture.open();
    let unrelated =
        vhalla_custody::create_private_directory(&fixture.root.path().join("unrelated-directory"))
            .unwrap()
            .0;
    let original = std::mem::replace(&mut fixture.room.directory, unrelated);
    assert_eq!(
        projection.status(&mut fixture.room, &mut fixture.backing),
        Err(ProjectionError::Binding)
    );
    fixture.room.directory = original;
    assert_eq!(
        projection.status(&mut fixture.room, &mut fixture.backing),
        Err(uncertain())
    );
}

fn install(path: &Path, mut state: State, records: Vec<Record>) {
    let mut store = Store::create_new(path, context(state.binding).unwrap(), limits()).unwrap();
    let mut old = None;
    state.events = 0;
    state.bytes = 0;
    for record in records {
        state.events += 1;
        state.bytes += record.as_bytes().len() as u64;
        let image = encode_state(state);
        store.publish(old.as_deref(), &image, &[record]).unwrap();
        old = Some(image);
    }
}

#[test]
fn matching_first_eight_references_cannot_skip_an_unscanned_ninth_frame() {
    let mut fixture = Fixture::new(limits(), limits());
    for number in 1..=8 {
        fixture.send(number);
    }
    let first = fixture.room.replicated_records(0, 8).unwrap();
    let frames: Vec<_> = first
        .records
        .into_iter()
        .map(|record| ReplicaFrame {
            kind: frame_kind(record.kind),
            bytes: record.bytes,
        })
        .collect();
    append(&mut fixture.backing, &frames);
    assert_eq!(fixture.backing.checkpoint().unwrap().records, 8);
    let native = native_live(&mut fixture.room).unwrap();
    let checkpoint = fixture.backing.checkpoint().unwrap();
    let initial = State {
        binding: Binding::from_room(&fixture.room),
        backing: checkpoint,
        outward: 0,
        inward: 0,
        native_floor: native.tip,
        pending: None,
        events: 1,
        bytes: 0,
    };
    let (mut intent, _) = prepare_outward(initial, &mut fixture.room, checkpoint)
        .unwrap()
        .unwrap();
    assert!(intent.through < native.tip);
    intent.through = native.tip;
    assert!(intent.through - intent.from <= 128);
    let mut forged = initial;
    forged.outward = intent.through;
    let path = fixture.root.path().join("forged-through");
    install(
        &path,
        forged,
        vec![
            init_record(initial.binding, checkpoint, native.tip).unwrap(),
            intent_record(&intent).unwrap(),
            done_record(intent.id(), checkpoint, native.tip).unwrap(),
        ],
    );
    assert!(matches!(
        Projection::open(&path, &mut fixture.room, &mut fixture.backing),
        Err(ProjectionError::Binding)
    ));
    assert!(path.join("FORMAT").exists());
}

fn copy_store(from: &Path, to: &Path) {
    vhalla_custody::create_private_directory(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        assert!(entry.file_type().unwrap().is_file());
        fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
    }
}

#[test]
fn status_observed_backing_growth_pins_a_stronger_floor_before_any_step() {
    let mut fixture = Fixture::new(limits(), limits());
    let old_path = fixture.root.path().join("before-observation");
    copy_store(&fixture.root.path().join("replica"), &old_path);
    let mut projection = fixture.create(limits());
    let frames = fixture.remote_chain(1);
    append(&mut fixture.backing, &frames);
    let observed = fixture.status(&mut projection);
    assert_eq!(observed.backing_floor.records, 2);
    assert_eq!(observed.inward_cursor, 0);
    let mut earlier = Replica::open(old_path, fixture.room.genesis().clone(), SOURCE).unwrap();
    assert_eq!(
        projection.status(&mut fixture.room, &mut earlier),
        Err(ProjectionError::Binding)
    );
    assert_eq!(
        projection.status(&mut fixture.room, &mut fixture.backing),
        Err(uncertain())
    );
}

#[test]
fn status_observed_native_tip_cannot_be_rolled_back_under_the_same_directory() {
    let mut fixture = Fixture::new(limits(), limits());
    let old_path = fixture.root.path().join("before-native-observation");
    copy_store(&fixture.root.path().join("room/store"), &old_path);
    let mut projection = fixture.create(limits());
    let original_tip = fixture.status(&mut projection).native_tip;
    fixture.send(1);
    assert!(fixture.status(&mut projection).native_tip > original_tip);
    let context = Context::new(
        *fixture.room.room_id().as_bytes(),
        fixture.account.public_key(),
    )
    .unwrap();
    let earlier = Store::open(old_path, context).unwrap();
    let actual = std::mem::replace(&mut fixture.room.store, earlier);
    assert_eq!(
        projection.status(&mut fixture.room, &mut fixture.backing),
        Err(ProjectionError::Binding)
    );
    fixture.room.store = actual;
    assert_eq!(
        projection.status(&mut fixture.room, &mut fixture.backing),
        Err(uncertain())
    );
}

#[test]
fn forged_cursors_omitted_frames_missing_destinations_and_completion_ids_are_refused() {
    let mut fixture = Fixture::new(limits(), limits());
    fixture.send(1);
    let native = native_live(&mut fixture.room).unwrap();
    let checkpoint = fixture.backing.checkpoint().unwrap();
    let initial = State {
        binding: Binding::from_room(&fixture.room),
        backing: checkpoint,
        outward: 0,
        inward: 0,
        native_floor: native.tip,
        pending: None,
        events: 1,
        bytes: 0,
    };
    let (original, _) = prepare_outward(initial, &mut fixture.room, checkpoint)
        .unwrap()
        .unwrap();
    for case in 0..4 {
        let mut state = initial;
        let mut intent = original.clone();
        let mut done_id = intent.id();
        match case {
            0 => {
                intent.frames.clear();
                done_id = intent.id();
            }
            1 => {}
            2 => {
                intent.from = 1;
                done_id = intent.id();
            }
            3 => done_id = [94; 32],
            _ => unreachable!(),
        }
        state.outward = intent.through;
        let path = fixture.root.path().join(format!("forged-{case}"));
        install(
            &path,
            state,
            vec![
                init_record(initial.binding, checkpoint, native.tip).unwrap(),
                intent_record(&intent).unwrap(),
                done_record(done_id, checkpoint, native.tip).unwrap(),
            ],
        );
        assert!(Projection::open(&path, &mut fixture.room, &mut fixture.backing).is_err());
        assert!(path.join("FORMAT").exists());
    }
    // Valid source reference and numeric cursor still cannot prove native receipt.
    let frames = fixture.remote_chain(1);
    append(&mut fixture.backing, &frames);
    let checkpoint = fixture.backing.checkpoint().unwrap();
    let mut state = initial;
    state.backing = checkpoint;
    state.inward = 2;
    let first = Intent {
        direction: ProjectionDirection::Inward,
        from: 0,
        through: 1,
        native_tip: native.tip,
        backing: checkpoint,
        frames: vec![reference(
            1,
            &ReplicaFrame {
                kind: FrameKind::Genesis,
                bytes: fixture.room.genesis().encode(),
            },
        )],
    };
    let second = Intent {
        direction: ProjectionDirection::Inward,
        from: 1,
        through: 2,
        native_tip: native.tip,
        backing: checkpoint,
        frames: vec![reference(2, &frames[0])],
    };
    let path = fixture.root.path().join("missing-native");
    install(
        &path,
        state,
        vec![
            init_record(state.binding, checkpoint, native.tip).unwrap(),
            intent_record(&first).unwrap(),
            done_record(first.id(), checkpoint, native.tip).unwrap(),
            intent_record(&second).unwrap(),
            done_record(second.id(), checkpoint, native.tip).unwrap(),
        ],
    );
    assert!(Projection::open(path, &mut fixture.room, &mut fixture.backing).is_err());
}

#[test]
fn missing_image_and_changed_live_progress_are_preserved_and_fenced() {
    let mut fixture = Fixture::new(limits(), limits());
    let absent = fixture.root.path().join("missing-image");
    drop(
        Store::create_new(
            &absent,
            context(Binding::from_room(&fixture.room)).unwrap(),
            limits(),
        )
        .unwrap(),
    );
    assert!(Projection::open(&absent, &mut fixture.room, &mut fixture.backing).is_err());
    assert!(absent.join("FORMAT").exists());
    let mut projection = fixture.create(limits());
    let mut changed = projection.state;
    changed.inward = 1;
    projection
        .store
        .publish(Some(&projection.image), &encode_state(changed), &[])
        .unwrap();
    assert_eq!(
        projection.status(&mut fixture.room, &mut fixture.backing),
        Err(corrupt())
    );
    assert_eq!(
        projection.status(&mut fixture.room, &mut fixture.backing),
        Err(uncertain())
    );
    drop(projection);
    assert!(Projection::open(fixture.path(), &mut fixture.room, &mut fixture.backing).is_err());
}

fn assert_progress(fixture: &mut Fixture, projection: &mut Projection) {
    let status = fixture.status(projection);
    let native = public_frames(&mut fixture.room);
    let replicated = replica_frames(&mut fixture.backing);
    let native_set: BTreeSet<_> = native
        .iter()
        .map(|(_, frame)| frame.bytes.clone())
        .collect();
    let replica_set: BTreeSet<_> = replicated.iter().map(|frame| frame.bytes.clone()).collect();
    for (cursor, frame) in &native {
        if *cursor <= status.outward_cursor {
            assert!(replica_set.contains(&frame.bytes));
        }
    }
    for frame in replicated.iter().take(status.inward_cursor as usize) {
        assert!(native_set.contains(&frame.bytes));
    }
}

#[hegel::test(test_cases=64,suppress_health_check=[HealthCheck::TooSlow])]
fn interleaved_local_sends_remote_frames_transfer_faults_growth_and_reopen(tc: hegel::TestCase) {
    let mut fixture = Fixture::new(limits(), limits());
    let mut projection = fixture.create(limits());
    let remote = fixture.remote_chain(6);
    let mut remote_next = 0;
    let mut local_next = 1u8;
    let mut selected = limits();
    let steps = tc.draw(
        hegel::generators::integers::<usize>()
            .min_value(6)
            .max_value(16),
    );
    for _ in 0..steps {
        let action = tc.draw(hegel::generators::integers::<u8>().max_value(6));
        match action {
            0 => {
                fixture.send(local_next);
                local_next += 1;
            }
            1 if remote_next < remote.len() => {
                append(&mut fixture.backing, &remote[remote_next..remote_next + 1]);
                remote_next += 1;
            }
            2 | 3 => {
                let pending = fixture.status(&mut projection).pending;
                let direction = pending.unwrap_or(if action == 2 {
                    ProjectionDirection::Outward
                } else {
                    ProjectionDirection::Inward
                });
                fixture.step(&mut projection, direction).unwrap();
            }
            4 => {
                drop(projection);
                projection = fixture.open();
            }
            5 => {
                let pending = fixture.status(&mut projection).pending;
                let direction = pending.unwrap_or(if tc.draw(hegel::generators::booleans()) {
                    ProjectionDirection::Outward
                } else {
                    ProjectionDirection::Inward
                });
                let index = tc.draw(hegel::generators::integers::<usize>().max_value(3));
                projection.fault = Some(
                    [
                        FaultPoint::AfterIntent,
                        FaultPoint::AfterDestination,
                        FaultPoint::BeforeComplete,
                        FaultPoint::AfterComplete,
                    ][index],
                );
                let result = fixture.step(&mut projection, direction);
                if result.is_err() {
                    assert_eq!(result, Err(uncertain()));
                    drop(projection);
                    projection = fixture.open();
                } else {
                    projection.fault = None;
                }
            }
            _ => {
                selected.max_records += 10;
                projection
                    .expand_limits(selected, &mut fixture.room, &mut fixture.backing)
                    .unwrap();
            }
        }
        assert_progress(&mut fixture, &mut projection);
    }
    drop(projection);
    let mut projection = fixture.open();
    assert_progress(&mut fixture, &mut projection);
    // Keep this property tied to signed-only content; no local journal metadata
    // ever appears as an additional frame in the shared replica.
    assert!(replica_frames(&mut fixture.backing)
        .iter()
        .all(|frame| match frame.kind {
            FrameKind::Genesis => frame.bytes == fixture.room.genesis().encode(),
            FrameKind::Event => fixture.room.event_raw(&frame.bytes).is_ok(),
            FrameKind::Policy => fixture.room.policy_raw(&frame.bytes).is_ok(),
        }));
}
