//! Codec laws over every game object, and the bound tests the plan requires:
//! the widest `Seal` and the widest `Reveal` against `MAX_GAME_EVENT_BYTES`,
//! and every other object against its bound.

use vhalla_core::{Epoch, RealmId, RoomId, Sequence};
use vhalla_game_platonik::ids::{
    CheckpointHash, GameEventDigest, GameManifestHash, InnerArtifactId, InnerKind, RulesetId,
    SessionKey,
};
use vhalla_game_platonik::manifest::{
    GameManifest, GameSlot, MissingMember, SessionKind, SessionLimits, SlotRole,
    VerificationAllowance, MAX_ARTIFACT_BYTES,
};
use vhalla_game_platonik::wire::{self, *};
use vhalla_ledger::{Checkpoint as LedgerCheckpoint, EventDigest, StateRoot};
use vhalla_witness::bounds::MAX_CELLS;
use vhalla_witness::codec::{self, MAX_CASES, MAX_MANIFEST_BYTES};
use vhalla_witness::hash::{ManifestHash, OutputHash, ProgramHash, StateHash};
use vhalla_witness::manifest::{ProgramSlot, TaskManifest, WorkContract};
use vhalla_witness::model::{
    Action, BitSource, Condition, MemoryWrite, Port, Program, Rule, Slot, ValveId,
};
use vhalla_witness::platform::{ClaimedReceipt, WorkAllowance};
use vhalla_witness::vm::RunStatus;
use vhalla_witness::world::{
    Beacon, CaseSpec, CellBody, Event, EventKind, Point, Source, Spark, WorldSpec,
};

fn widest_program() -> Program {
    let slot = Slot::new(3).unwrap();
    let port = Port::new(3).unwrap();
    let cond = Condition::Memory { slot, value: 255 };
    let rule = Rule::new(
        vec![cond; 8],
        Action::Route {
            valve: ValveId::new(65_535),
            bit: BitSource::Message { port },
        },
        Some(MemoryWrite::new(slot, 255)),
    )
    .unwrap();
    Program::new(vec![rule; 32]).unwrap()
}

fn widest_manifest() -> GameManifest {
    GameManifest {
        ruleset: RulesetId::V1,
        world: ManifestHash([1; 32]),
        slots: (0..MAX_CELLS as u16)
            .map(|cell| GameSlot {
                cell,
                role: SlotRole::Open {
                    fallback: Some(ProgramHash([2; 32])),
                },
            })
            .collect(),
        contract: WorkContract {
            useful_floor: u64::MAX,
            total_ceiling: u64::MAX,
            require_passed: true,
        },
        loading_work: vec![u64::MAX; MAX_CASES],
        artifacts: vec![
            InnerArtifactId {
                kind: InnerKind::PlatonikExperimentV1,
                sha256: [3; 32],
            },
            InnerArtifactId {
                kind: InnerKind::PlatonikResultV1,
                sha256: [4; 32],
            },
            InnerArtifactId {
                kind: InnerKind::PlatonikReceiptV1,
                sha256: [5; 32],
            },
            InnerArtifactId {
                kind: InnerKind::FrameTraceV1,
                sha256: [6; 32],
            },
        ],
        limits: SessionLimits {
            max_events: 1024,
            max_segments: 8,
            replay: WorkAllowance {
                max_total: u64::MAX,
            },
            verification: VerificationAllowance {
                max_replays: 64,
                max_work: u64::MAX,
                max_event_bytes: 1024 * 24_576,
                max_artifact_bytes: MAX_ARTIFACT_BYTES,
            },
            missing_member: MissingMember::Fill,
            kind: SessionKind::Live,
        },
        publisher: [7; 32],
    }
}

fn header(body: EventBody) -> GameEvent {
    GameEvent {
        session: SessionKey([9; 32]),
        epoch: Epoch(u64::MAX),
        author: [8; 32],
        sequence: Sequence(u64::MAX),
        parents: (0..MAX_PARENTS as u8)
            .map(|i| GameEventDigest([i; 32]))
            .collect(),
        body,
    }
}

/// A task manifest near the witness bound: 16 cells with the widest programs
/// fixed, 8 cases each with 64 events.
fn widest_task() -> TaskManifest {
    let world = WorldSpec {
        width: 32,
        height: 32,
        walls: (0..512u16)
            .map(|i| Point {
                x: (i % 32) as u8,
                y: 16 + (i / 32) as u8,
            })
            .collect(),
        sources: vec![Source {
            id: 1,
            position: Point { x: 0, y: 0 },
            sparks: (0..128)
                .map(|i| Spark {
                    id: i,
                    bit: i % 2 == 0,
                })
                .collect(),
        }],
        depots: vec![],
        beacons: vec![Beacon {
            id: 2,
            position: Point { x: 31, y: 0 },
            accepts: true,
            initial_charge: 10_000,
            drain_every: 128,
            drain_amount: 1,
            spark_charge: 1,
            required_deliveries: 0,
        }],
        valves: vec![],
        cells: (0..16u16)
            .map(|i| CellBody {
                id: 10 + i,
                position: Point {
                    x: 1 + i as u8,
                    y: 2,
                },
                heading: vhalla_witness::model::Direction::East,
                mobile: true,
                memory: [0; 4],
            })
            .collect(),
        links: vec![],
    };
    let program = widest_program();
    TaskManifest {
        world,
        slots: (0..16u16)
            .map(|i| ProgramSlot {
                cell: 10 + i,
                fixed: Some(program.clone()),
            })
            .collect(),
        cases: (0..8)
            .map(|_| CaseSpec {
                seed: 1,
                ticks: 128,
                fuel: 2_000_000,
                activation_fuel: 1024,
                events: (0..64)
                    .map(|t| Event {
                        tick: 1 + t,
                        event: EventKind::ClearMemory { cell: 10 },
                    })
                    .collect(),
                loading_work: 65_536,
            })
            .collect(),
        contract: WorkContract {
            useful_floor: 0,
            total_ceiling: 16_000_000,
            require_passed: false,
        },
    }
}

#[test]
fn every_object_round_trips_and_fits_its_bound() {
    let manifest = widest_manifest();
    manifest.validate().unwrap();
    let raw = encode_game_manifest(&manifest);
    assert!(raw.len() <= MAX_GAME_MANIFEST_BYTES, "{}", raw.len());
    assert_eq!(decode_game_manifest(&raw).unwrap(), manifest);
    assert_eq!(
        encode_game_manifest(&decode_game_manifest(&raw).unwrap()),
        raw
    );
    assert_eq!(manifest.hash(), GameManifestHash::of(&raw));

    let open = SessionOpen {
        realm: RealmId(u128::MAX),
        room: RoomId(u128::MAX),
        manifest: manifest.hash(),
        ruleset: RulesetId::V1,
        seed_commitment: [1; 32],
        authority: Authority::Host { key: [2; 32] },
        players: (0..MAX_PLAYERS as u8)
            .map(|i| Player {
                key: [i + 1; 32],
                slots: (0..MAX_CELLS as u16).collect(),
            })
            .collect(),
        epoch: Epoch(0),
        nonce: [3; 32],
    };
    let raw = encode_session_open(&open);
    assert!(raw.len() <= MAX_SESSION_OPEN_BYTES, "{}", raw.len());
    assert_eq!(decode_session_open(&raw).unwrap(), open);
    assert_eq!(open.key(), SessionKey::of(&raw));

    let seal = header(EventBody::Seal {
        segment: 255,
        through_tick: u32::MAX,
        order: (0..MAX_SEAL_ORDER)
            .map(|i| GameEventDigest([(i % 251) as u8; 32]))
            .collect(),
        checkpoint: CheckpointHash([4; 32]),
    });
    let seal_raw = encode_game_event(&seal);
    assert!(
        seal_raw.len() <= MAX_GAME_EVENT_BYTES,
        "seal {}",
        seal_raw.len()
    );
    assert_eq!(decode_game_event(&seal_raw).unwrap(), seal);
    let task = widest_task();
    let task_len = codec::encode_manifest(&task).len();
    assert!(task_len <= MAX_MANIFEST_BYTES, "{task_len}");
    let reveal = header(EventBody::Reveal {
        task,
        host_salt: [5; 32],
    });
    let reveal_raw = encode_game_event(&reveal);
    assert!(
        reveal_raw.len() <= MAX_GAME_EVENT_BYTES,
        "reveal {}",
        reveal_raw.len()
    );
    assert_eq!(decode_game_event(&reveal_raw).unwrap(), reveal);
    println!(
        "widest seal {} bytes, widest reveal {} bytes (task {task_len}), bound {MAX_GAME_EVENT_BYTES}",
        seal_raw.len(),
        reveal_raw.len()
    );
    let bind = header(EventBody::BindReveal {
        slot: 65_535,
        program: widest_program(),
        salt: [6; 32],
    });
    let raw = encode_game_event(&bind);
    assert!(raw.len() <= MAX_GAME_EVENT_BYTES);
    assert_eq!(decode_game_event(&raw).unwrap(), bind);
    for body in [
        EventBody::BindCommit {
            slot: 1,
            commit: [1; 32],
        },
        EventBody::BindClose {
            commits: (0..MAX_CELLS as u16).map(|s| (s, [s as u8; 32])).collect(),
        },
        EventBody::Input {
            case: 7,
            tick: 128,
            kind: EventKind::LinkEnabled {
                id: 1,
                enabled: true,
            },
        },
        EventBody::Replace {
            slot: 1,
            old: [1; 32],
            new: [2; 32],
        },
        EventBody::Fill {
            slot: 1,
            program_hash: ProgramHash([3; 32]),
            evidence: FillEvidence {
                author: [4; 32],
                sequence: Sequence(9),
                segment: 2,
            },
        },
    ] {
        let event = header(body);
        let raw = encode_game_event(&event);
        assert_eq!(decode_game_event(&raw).unwrap(), event);
        assert_eq!(event.digest(), GameEventDigest::of(&raw));
    }

    let checkpoint = Checkpoint {
        session: SessionKey([9; 32]),
        ledger: LedgerCheckpoint {
            realm: RealmId(u128::MAX),
            epoch: Epoch(u64::MAX),
            head: EventDigest([1; 32]),
            state_root: StateRoot([2; 32]),
            height: u64::MAX,
        },
        parent: [3; 32],
        segment: 255,
        segment_manifest: ManifestHash([4; 32]),
        program: ProgramHash([5; 32]),
        through_tick: u32::MAX,
        cases: (0..MAX_CASES)
            .map(|i| CaseCheckpoint {
                state: StateHash([i as u8; 32]),
                trace: [6; 32],
                ledger_total: u64::MAX,
                status: RunStatus::ActivationLimit,
            })
            .collect(),
        work: WorkSummary {
            useful: u64::MAX,
            total: u64::MAX,
        },
    };
    let raw = encode_checkpoint(&checkpoint);
    assert!(raw.len() <= MAX_CHECKPOINT_BYTES, "{}", raw.len());
    assert_eq!(decode_checkpoint(&raw).unwrap(), checkpoint);
    assert_eq!(checkpoint.hash(), CheckpointHash::of(&raw));

    let result = Settlement::Result {
        session: SessionKey([9; 32]),
        epoch: Epoch(1),
        checkpoint: CheckpointHash([1; 32]),
        receipt: ClaimedReceipt {
            challenge_id: [9; 32],
            subject_key: [2; 32],
            manifest: ManifestHash([3; 32]),
            program: ProgramHash([4; 32]),
            output: OutputHash([5; 32]),
            useful: 1,
            total: 2,
            passed: true,
            case_count: 8,
        },
        passed: true,
    };
    let raw = encode_settlement(&result);
    assert!(raw.len() <= MAX_SETTLEMENT_BYTES);
    assert_eq!(decode_settlement(&raw).unwrap(), result);
    let unresolved = Settlement::Unresolved {
        session: SessionKey([9; 32]),
        epoch: Epoch(1),
        reason: ForkReason::CompetingSeals,
        heads: vec![[1; 32]; MAX_FORK_HEADS],
        evidence: vec![[2; 32]; MAX_FORK_EVIDENCE],
    };
    let raw = encode_settlement(&unresolved);
    assert!(raw.len() <= MAX_SETTLEMENT_BYTES);
    assert_eq!(decode_settlement(&raw).unwrap(), unresolved);

    let request = ArtifactRequest {
        session: SessionKey([9; 32]),
        id: InnerArtifactId {
            kind: InnerKind::FrameTraceV1,
            sha256: [1; 32],
        },
        max_bytes: MAX_ARTIFACT_BYTES,
        nonce: [2; 32],
    };
    let raw = encode_artifact_request(&request);
    assert!(raw.len() <= MAX_ARTIFACT_REQUEST_BYTES);
    assert_eq!(decode_artifact_request(&raw).unwrap(), request);
    let artifact = ArtifactManifest {
        id: request.id,
        total_len: 8 << 20,
        block_len: BLOCK_LEN,
        blocks: vec![[3; 32]; MAX_BLOCKS],
        decompressed_len: 8 << 20,
    };
    let raw = encode_artifact_manifest(&artifact);
    assert!(raw.len() <= MAX_ARTIFACT_MANIFEST_BYTES);
    assert_eq!(decode_artifact_manifest(&raw).unwrap(), artifact);
    let block = Block {
        manifest: artifact.hash(),
        index: 127,
        offset: 127 * u64::from(BLOCK_LEN),
        bytes: vec![7; BLOCK_LEN as usize],
    };
    let raw = encode_block(&block);
    assert!(raw.len() <= MAX_BLOCK_BYTES);
    assert_eq!(decode_block(&raw).unwrap(), block);
}

#[test]
fn decoders_reject_trailing_bytes_bad_discriminants_and_unsorted_ids() {
    let manifest = widest_manifest();
    let mut raw = encode_game_manifest(&manifest);
    raw.push(0);
    assert!(
        matches!(
            decode_game_manifest(&raw),
            Err(codec::CodecError::TooLarge { .. })
        ),
        "the widest manifest sits at its bound, so one more byte is TooLarge"
    );
    let mut small = manifest.clone();
    small.slots.truncate(1);
    let mut raw = encode_game_manifest(&small);
    raw.push(0);
    assert!(matches!(
        decode_game_manifest(&raw),
        Err(codec::CodecError::TrailingBytes { .. })
    ));
    let mut raw = encode_game_manifest(&manifest);
    raw[0] = 2;
    assert!(matches!(
        decode_game_manifest(&raw),
        Err(codec::CodecError::UnsupportedVersion { .. })
    ));
    let mut unsorted = manifest.clone();
    unsorted.slots.swap(0, 1);
    assert!(matches!(
        decode_game_manifest(&encode_game_manifest(&unsorted)),
        Err(codec::CodecError::Unsorted { .. })
    ));
    assert_eq!(
        unsorted.validate(),
        Err(vhalla_game_platonik::manifest::ManifestError::Slots)
    );
    let mut event = header(EventBody::BindCommit {
        slot: 1,
        commit: [1; 32],
    });
    event.parents = vec![GameEventDigest([2; 32]), GameEventDigest([1; 32])];
    assert!(matches!(
        decode_game_event(&encode_game_event(&event)),
        Err(codec::CodecError::Unsorted { .. })
    ));
    let seal = header(EventBody::Seal {
        segment: 0,
        through_tick: 1,
        order: vec![GameEventDigest([1; 32]); MAX_SEAL_ORDER + 1],
        checkpoint: CheckpointHash([1; 32]),
    });
    assert!(
        decode_game_event(&encode_game_event(&seal)).is_err(),
        "an over-long order is refused"
    );
    let _ = wire::VERSION;
}
