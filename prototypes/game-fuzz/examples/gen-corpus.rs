//! Writes `corpus/<decoder>/*.hex`, the committed seed corpus every harness
//! in `tests/decoders.rs` starts from.
//!
//! Two sources, both stated in the plan. The first is the frozen v1 vectors
//! under `crates/vhalla-game-platonik/tests/vectors/`: their `game_manifest`,
//! `session_open`, `record[n].record`, and `record[n].checkpoint` hex, plus
//! the event bodies carried inside those records. The second is small
//! hand-built values encoded with the crate's own encoders, so that variants
//! and bounds the vectors never exercise (`Authority::Quorum`, every
//! `ForkReason`, an empty case list, a full block list) are still seeded.
//!
//! Nothing here is on the test path: the corpus is committed and the harness
//! reads files. Run it only to regenerate, and only with a recorded reason:
//! `cargo run --manifest-path prototypes/game-fuzz/Cargo.toml --example gen-corpus`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use vhalla_core::{Epoch, RealmId, RoomId, Sequence};
use vhalla_game_platonik::ids::{
    ArtifactManifestHash, CheckpointHash, GameEventDigest, GameManifestHash, InnerArtifactId,
    InnerKind, RulesetId, SessionKey,
};
use vhalla_game_platonik::manifest::{
    GameManifest, GameSlot, MissingMember, SessionKind, SessionLimits, SlotRole,
    VerificationAllowance,
};
use vhalla_game_platonik::record::{GameRecord, RecordKind};
use vhalla_game_platonik::wire::{
    decode_game_event, encode_artifact_manifest, encode_artifact_request, encode_block,
    encode_checkpoint, encode_game_event, encode_game_manifest, encode_session_open,
    encode_settlement, ArtifactManifest, ArtifactRequest, Authority, Block, CaseCheckpoint,
    Checkpoint, EventBody, FillEvidence, ForkReason, GameEvent, Player, SessionOpen, Settlement,
    WorkSummary,
};
use vhalla_ledger::{Checkpoint as LedgerCheckpoint, EventDigest, StateRoot};
use vhalla_witness::hash::{ManifestHash, ProgramHash, StateHash};
use vhalla_witness::manifest::WorkContract;
use vhalla_witness::model::Program;
use vhalla_witness::platform::{ClaimedReceipt, WorkAllowance};
use vhalla_witness::vectors::{hex, unhex};
use vhalla_witness::vm::RunStatus;
use vhalla_witness::world::EventKind;

/// The vector directory the seeds are lifted from.
fn vectors() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/vhalla-game-platonik/tests/vectors")
}

/// The `key: value` lines of one vector file.
fn parse(path: &Path) -> BTreeMap<String, String> {
    let text = fs::read_to_string(path).expect("a readable vector");
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        if let Some((key, value)) = line.split_once(": ") {
            fields.insert(key.to_string(), value.to_string());
        }
    }
    fields
}

/// Collects `corpus/<decoder>/<name>.hex` entries before they are written.
#[derive(Default)]
struct Corpus(BTreeMap<String, Vec<(String, Vec<u8>)>>);

impl Corpus {
    fn add(&mut self, decoder: &str, name: &str, raw: Vec<u8>) {
        let entries = self.0.entry(decoder.to_string()).or_default();
        if entries.iter().any(|(_, seen)| *seen == raw) {
            return;
        }
        let index = entries.len();
        entries.push((format!("{index:03}-{name}"), raw));
    }
    fn write(self) {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");
        if root.exists() {
            fs::remove_dir_all(&root).expect("a removable corpus");
        }
        for (decoder, entries) in self.0 {
            let dir = root.join(&decoder);
            fs::create_dir_all(&dir).expect("a writable corpus directory");
            for (name, raw) in &entries {
                let path = dir.join(format!("{name}.hex"));
                fs::write(&path, format!("{}\n", hex(raw))).expect("a writable corpus file");
            }
            println!("{decoder}: {} seeds", entries.len());
        }
    }
}

fn fixed_hash(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn limits(kind: SessionKind, missing: MissingMember) -> SessionLimits {
    SessionLimits {
        max_events: 1024,
        max_segments: 8,
        replay: WorkAllowance { max_total: 1 << 20 },
        verification: VerificationAllowance {
            max_replays: 64,
            max_work: 1 << 30,
            max_event_bytes: 1 << 24,
            max_artifact_bytes: 8 * 1024 * 1024,
        },
        missing_member: missing,
        kind,
    }
}

/// The smallest admissible shape: one fixed slot, one case, no artifacts.
fn narrow_manifest() -> GameManifest {
    GameManifest {
        ruleset: RulesetId::V1,
        world: ManifestHash(fixed_hash(0x11)),
        slots: vec![GameSlot {
            cell: 0,
            role: SlotRole::Fixed,
        }],
        contract: WorkContract {
            useful_floor: 0,
            total_ceiling: 0,
            require_passed: false,
        },
        loading_work: vec![7],
        artifacts: Vec::new(),
        limits: limits(SessionKind::Replay, MissingMember::Pause),
        publisher: fixed_hash(0x22),
    }
}

/// Every optional field taken: open slots with and without a fallback, eight
/// cases, four inner artifact ids of four kinds, `Fill`, `Live`.
fn wide_manifest() -> GameManifest {
    GameManifest {
        ruleset: RulesetId {
            codec: 1,
            language: 1,
            protocol: 1,
        },
        world: ManifestHash(fixed_hash(0x33)),
        slots: vec![
            GameSlot {
                cell: 0,
                role: SlotRole::Fixed,
            },
            GameSlot {
                cell: 1,
                role: SlotRole::Open { fallback: None },
            },
            GameSlot {
                cell: 2,
                role: SlotRole::Open {
                    fallback: Some(ProgramHash(fixed_hash(0x44))),
                },
            },
            GameSlot {
                cell: 65_535,
                role: SlotRole::Open {
                    fallback: Some(ProgramHash(fixed_hash(0x55))),
                },
            },
        ],
        contract: WorkContract {
            useful_floor: u64::MAX,
            total_ceiling: u64::MAX,
            require_passed: true,
        },
        loading_work: vec![0, 1, 2, 3, 4, 5, 6, u64::MAX],
        artifacts: vec![
            InnerArtifactId {
                kind: InnerKind::PlatonikExperimentV1,
                sha256: fixed_hash(0x66),
            },
            InnerArtifactId {
                kind: InnerKind::PlatonikResultV1,
                sha256: fixed_hash(0x77),
            },
            InnerArtifactId {
                kind: InnerKind::PlatonikReceiptV1,
                sha256: fixed_hash(0x88),
            },
            InnerArtifactId {
                kind: InnerKind::FrameTraceV1,
                sha256: fixed_hash(0x99),
            },
        ],
        limits: limits(SessionKind::Live, MissingMember::Fill),
        publisher: fixed_hash(0xaa),
    }
}

fn narrow_open() -> SessionOpen {
    SessionOpen {
        realm: RealmId(0),
        room: RoomId(0),
        manifest: GameManifestHash(fixed_hash(0x11)),
        ruleset: RulesetId::V1,
        seed_commitment: [0; 32],
        authority: Authority::Host {
            key: fixed_hash(0x01),
        },
        players: Vec::new(),
        epoch: Epoch(0),
        nonce: [0; 32],
    }
}

/// The reserved quorum discriminant and sorted players with ascending slots.
fn quorum_open() -> SessionOpen {
    SessionOpen {
        realm: RealmId(u128::MAX),
        room: RoomId(1),
        manifest: GameManifestHash(fixed_hash(0x33)),
        ruleset: RulesetId::V1,
        seed_commitment: fixed_hash(0xbb),
        authority: Authority::Quorum {
            scheme: fixed_hash(0xcc),
        },
        players: vec![
            Player {
                key: fixed_hash(0x01),
                slots: vec![1],
            },
            Player {
                key: fixed_hash(0x02),
                slots: vec![2, 3, 65_535],
            },
        ],
        epoch: Epoch(u64::MAX),
        nonce: fixed_hash(0xdd),
    }
}

fn event(body: EventBody) -> GameEvent {
    GameEvent {
        session: SessionKey(fixed_hash(0x10)),
        epoch: Epoch(3),
        author: fixed_hash(0x20),
        sequence: Sequence(1),
        parents: Vec::new(),
        body,
    }
}

fn case(status: RunStatus, total: u64) -> CaseCheckpoint {
    CaseCheckpoint {
        state: StateHash(fixed_hash(0x31)),
        trace: fixed_hash(0x32),
        ledger_total: total,
        status,
    }
}

fn checkpoint(cases: Vec<CaseCheckpoint>) -> Checkpoint {
    Checkpoint {
        session: SessionKey(fixed_hash(0x10)),
        ledger: LedgerCheckpoint {
            realm: RealmId(3),
            epoch: Epoch(0),
            head: EventDigest(fixed_hash(0x41)),
            state_root: StateRoot(fixed_hash(0x42)),
            height: 2,
        },
        parent: [0; 32],
        segment: 0,
        segment_manifest: ManifestHash(fixed_hash(0x43)),
        program: ProgramHash(fixed_hash(0x44)),
        through_tick: 5,
        cases,
        work: WorkSummary {
            useful: 1,
            total: 2,
        },
    }
}

fn artifact_id(kind: InnerKind, byte: u8) -> InnerArtifactId {
    InnerArtifactId {
        kind,
        sha256: fixed_hash(byte),
    }
}

/// Lifts the vector hex and the event bodies inside the vector records.
fn from_vectors(corpus: &mut Corpus) -> (Option<ClaimedReceipt>, Option<Program>) {
    let mut receipt = None;
    let mut program = None;
    for file in ["game-v1-session-replay.txt", "game-v1-session-live.txt"] {
        let fields = parse(&vectors().join(file));
        let tag = file
            .trim_start_matches("game-v1-session-")
            .trim_end_matches(".txt");
        let raw = unhex(&fields["game_manifest"]).expect("vector hex");
        corpus.add("game-manifest", &format!("vector-{tag}"), raw);
        let raw = unhex(&fields["session_open"]).expect("vector hex");
        corpus.add("session-open", &format!("vector-{tag}"), raw);
        if receipt.is_none() {
            let raw = unhex(&fields["receipt"]).expect("vector hex");
            receipt = Some(ClaimedReceipt::decode(&raw).expect("a vector receipt"));
        }
        let count: usize = fields["record_count"].parse().expect("a record count");
        for index in 0..count {
            let raw = unhex(&fields[&format!("record[{index}].record")]).expect("vector hex");
            let record = GameRecord::decode(&raw).expect("a vector record");
            let body = fields[&format!("record[{index}].body")].clone();
            corpus.add("game-record", &format!("vector-{tag}-{body}"), raw);
            let decoded = decode_game_event(&record.body).expect("a vector event");
            if let EventBody::BindReveal { program: p, .. } = &decoded.body {
                program = Some(p.clone());
            }
            corpus.add(
                "game-event",
                &format!("vector-{tag}-{body}"),
                record.body.clone(),
            );
            if let Some(value) = fields.get(&format!("record[{index}].checkpoint")) {
                let raw = unhex(value).expect("vector hex");
                corpus.add("checkpoint", &format!("vector-{tag}-seal{index}"), raw);
            }
        }
    }
    (receipt, program)
}

fn main() {
    let mut corpus = Corpus::default();
    let (receipt, program) = from_vectors(&mut corpus);
    let receipt = receipt.expect("the vectors carry a receipt");
    let program = program.expect("the live vector carries a revealed program");

    corpus.add(
        "game-manifest",
        "built-narrow",
        encode_game_manifest(&narrow_manifest()),
    );
    corpus.add(
        "game-manifest",
        "built-wide",
        encode_game_manifest(&wide_manifest()),
    );

    corpus.add(
        "session-open",
        "built-host-no-players",
        encode_session_open(&narrow_open()),
    );
    corpus.add(
        "session-open",
        "built-quorum-players",
        encode_session_open(&quorum_open()),
    );

    let session = SessionKey(fixed_hash(0x10));
    for (name, body) in [
        (
            "built-bind-commit",
            EventBody::BindCommit {
                slot: 1,
                commit: fixed_hash(0x51),
            },
        ),
        (
            "built-bind-close-empty",
            EventBody::BindClose {
                commits: Vec::new(),
            },
        ),
        (
            "built-bind-close",
            EventBody::BindClose {
                commits: vec![(0, fixed_hash(0x52)), (7, fixed_hash(0x53))],
            },
        ),
        (
            "built-bind-reveal",
            EventBody::BindReveal {
                slot: 2,
                program: program.clone(),
                salt: fixed_hash(0x54),
            },
        ),
        (
            "built-input-link",
            EventBody::Input {
                case: 0,
                tick: 1,
                kind: EventKind::LinkEnabled {
                    id: 3,
                    enabled: true,
                },
            },
        ),
        (
            "built-input-valve",
            EventBody::Input {
                case: 7,
                tick: u32::MAX,
                kind: EventKind::ValveEnabled {
                    id: 0,
                    enabled: false,
                },
            },
        ),
        (
            "built-input-clear",
            EventBody::Input {
                case: 1,
                tick: 2,
                kind: EventKind::ClearMemory { cell: 65_535 },
            },
        ),
        (
            "built-seal-empty",
            EventBody::Seal {
                segment: 0,
                through_tick: 0,
                order: Vec::new(),
                checkpoint: CheckpointHash([0; 32]),
            },
        ),
        (
            "built-seal",
            EventBody::Seal {
                segment: 7,
                through_tick: 64,
                order: vec![
                    GameEventDigest(fixed_hash(0x61)),
                    GameEventDigest(fixed_hash(0x62)),
                    GameEventDigest(fixed_hash(0x63)),
                ],
                checkpoint: CheckpointHash(fixed_hash(0x64)),
            },
        ),
        (
            "built-replace",
            EventBody::Replace {
                slot: 4,
                old: fixed_hash(0x71),
                new: fixed_hash(0x72),
            },
        ),
        (
            "built-fill",
            EventBody::Fill {
                slot: 5,
                program_hash: ProgramHash(fixed_hash(0x73)),
                program: program.clone(),
                evidence: FillEvidence {
                    author: fixed_hash(0x74),
                    sequence: Sequence(9),
                    segment: 2,
                },
            },
        ),
    ] {
        corpus.add("game-event", name, encode_game_event(&event(body)));
    }
    // The header's own optional shape: four sorted parents.
    let mut parented = event(EventBody::BindCommit {
        slot: 0,
        commit: fixed_hash(0x55),
    });
    parented.parents = vec![
        GameEventDigest(fixed_hash(0x01)),
        GameEventDigest(fixed_hash(0x02)),
        GameEventDigest(fixed_hash(0x03)),
        GameEventDigest(fixed_hash(0x04)),
    ];
    parented.sequence = Sequence(u64::MAX);
    parented.epoch = Epoch(u64::MAX);
    corpus.add(
        "game-event",
        "built-four-parents",
        encode_game_event(&parented),
    );

    corpus.add(
        "checkpoint",
        "built-no-cases",
        encode_checkpoint(&checkpoint(Vec::new())),
    );
    corpus.add(
        "checkpoint",
        "built-three-statuses",
        encode_checkpoint(&checkpoint(vec![
            case(RunStatus::Complete, 0),
            case(RunStatus::FuelExhausted, 1),
            case(RunStatus::ActivationLimit, u64::MAX),
        ])),
    );
    let mut eight = checkpoint((0..8).map(|i| case(RunStatus::Complete, i)).collect());
    eight.segment = 7;
    eight.parent = fixed_hash(0x45);
    eight.ledger.epoch = Epoch(1);
    corpus.add("checkpoint", "built-eight-cases", encode_checkpoint(&eight));

    corpus.add(
        "settlement",
        "built-result",
        encode_settlement(&Settlement::Result {
            session,
            epoch: Epoch(0),
            checkpoint: CheckpointHash(fixed_hash(0x81)),
            receipt,
            passed: true,
        }),
    );
    for (index, reason) in [
        ForkReason::CompetingSeals,
        ForkReason::Equivocation,
        ForkReason::RevealMissing,
        ForkReason::MemberMissing,
        ForkReason::BudgetExhausted,
        ForkReason::ReplayMismatch,
        ForkReason::HostSilent,
        ForkReason::Cancelled,
    ]
    .into_iter()
    .enumerate()
    {
        let heads = (0..index.min(4))
            .map(|i| fixed_hash(0x90 + i as u8))
            .collect();
        let evidence = (0..index).map(|i| fixed_hash(0xa0 + i as u8)).collect();
        corpus.add(
            "settlement",
            &format!("built-unresolved-{index}"),
            encode_settlement(&Settlement::Unresolved {
                session,
                epoch: Epoch(index as u64),
                reason,
                heads,
                evidence,
            }),
        );
    }

    for (index, kind) in [
        InnerKind::PlatonikExperimentV1,
        InnerKind::PlatonikResultV1,
        InnerKind::PlatonikReceiptV1,
        InnerKind::PlatonikCheckpointV1,
        InnerKind::FrameTraceV1,
    ]
    .into_iter()
    .enumerate()
    {
        corpus.add(
            "artifact-request",
            &format!("built-kind-{index}"),
            encode_artifact_request(&ArtifactRequest {
                session,
                id: artifact_id(kind, 0xb0 + index as u8),
                max_bytes: 8 * 1024 * 1024,
                nonce: fixed_hash(0xc0 + index as u8),
            }),
        );
    }

    for (name, blocks, total) in [
        ("built-no-blocks", 0_usize, 0_u64),
        ("built-one-block", 1, 1),
        ("built-full", 128, 128 * 65_536),
    ] {
        corpus.add(
            "artifact-manifest",
            name,
            encode_artifact_manifest(&ArtifactManifest {
                id: artifact_id(InnerKind::FrameTraceV1, 0xd0),
                total_len: total,
                block_len: 65_536,
                blocks: (0..blocks).map(|i| fixed_hash(i as u8)).collect(),
                decompressed_len: total,
            }),
        );
    }

    for (name, len, index) in [
        ("built-empty", 0_usize, 0_u8),
        ("built-one", 1, 0),
        ("built-small", 64, 1),
        ("built-kib", 1024, 127),
    ] {
        corpus.add(
            "block",
            name,
            encode_block(&Block {
                manifest: ArtifactManifestHash(fixed_hash(0xe0)),
                index,
                offset: u64::from(index) * 65_536,
                bytes: (0..len).map(|i| (i % 251) as u8).collect(),
            }),
        );
    }

    for (index, kind) in [
        RecordKind::Manifest,
        RecordKind::SessionOpen,
        RecordKind::Event,
        RecordKind::Checkpoint,
        RecordKind::Settlement,
        RecordKind::ArtifactRequest,
        RecordKind::ArtifactManifest,
    ]
    .into_iter()
    .enumerate()
    {
        // The carrier never reads the body, so an unsigned record with an
        // empty body is exactly the shape its decoder has to survive.
        let record = GameRecord {
            kind,
            session,
            signer: fixed_hash(0xf0),
            body: vec![0xab; index],
            signature: [0xcd; 64],
        };
        corpus.add(
            "game-record",
            &format!("built-kind-{index}"),
            record.encode(),
        );
    }

    corpus.write();
}
