//! Spike 2 of the Platonik session adapter plan: measured artifact sizes.
//!
//! Four measurements, each driving the real types rather than an estimate:
//!
//! 1. Every Platonik artifact the six fixtures and the `bridge-v1` suite
//!    produce, sized as the compact `serde_json::to_vec` bytes an
//!    `InnerArtifactId` hashes: the `Experiment`, the `RunResult`, and the
//!    whole `Receipt`.
//! 2. One adapter frame trace, built by appending `codec::encode_state` of
//!    every frame `platform::run_observed` emits for the witness corpus worst
//!    case.
//! 3. The largest of those artifacts driven through `ArtifactAssembly`,
//!    natively and through the browser record mapping, reporting peak
//!    retained bytes against the 1.25 x ceiling.
//! 4. The widest `GameManifest` and `SessionOpen` against
//!    `vhalla_crypto::MAX_SIGNED_BODY_BYTES`.
//!
//! Disposable reference, excluded from the maintained workspace. A measured
//! size is evidence about this corpus at this pin and nothing else.

use vhalla_crypto::MAX_SIGNED_BODY_BYTES;
use vhalla_game_platonik::artifact::{
    block_from_records, split_block, Accepted, ArtifactAssembly, MAX_RECORDS_PER_BLOCK,
    RECORD_BODY_LEN, RECORD_HEADER_LEN,
};
use vhalla_game_platonik::ids::{InnerArtifactId, InnerKind, RulesetId, SessionKey};
use vhalla_game_platonik::manifest::{
    GameManifest, GameSlot, MissingMember, SessionKind, SessionLimits, SlotRole,
    VerificationAllowance, MAX_ARTIFACT_BYTES,
};
use vhalla_game_platonik::wire::{
    encode_game_manifest, encode_session_open, ArtifactManifest, ArtifactRequest, Authority, Block,
    Player, SessionOpen, BLOCK_LEN, MAX_BLOCKS, MAX_PLAYERS,
};
use vhalla_witness::bounds::MAX_CELLS;
use vhalla_witness::codec::{self, MAX_CASES};
use vhalla_witness::hash::{ManifestHash, ProgramHash};
use vhalla_witness::manifest::{ValidManifest, WorkContract};
use vhalla_witness::platform::{self, RunCapability, RunRole, WorkAllowance};
use vhalla_witness::vm::{FrameView, Observer};

use sha2::{Digest, Sha256};
use vhalla_core::{Epoch, RealmId, RoomId};

/// Re-exported so a test names the same bound the crate does.
pub use vhalla_game_platonik::manifest::MAX_ARTIFACT_BYTES as ARTIFACT_CEILING;

/// The margin the plan requires under `MAX_SIGNED_BODY_BYTES`.
pub const REQUIRED_FRAME_MARGIN: usize = 8 * 1024;

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// How many 64 KiB blocks an artifact of `len` bytes needs.
#[must_use]
pub fn blocks_for(len: usize) -> usize {
    len.div_ceil(BLOCK_LEN as usize)
}

// ---------------------------------------------------------------------------
// (a) Platonik artifact sizes
// ---------------------------------------------------------------------------

/// One measured artifact.
#[derive(Clone, Debug)]
pub struct Measured {
    /// Corpus id: `fixture-<name>` or `bridge-v1-<case>`.
    pub id: String,
    /// Which object the bytes are.
    pub kind: InnerKind,
    /// Compact canonical bytes.
    pub len: usize,
}

impl Measured {
    /// Blocks this artifact needs.
    #[must_use]
    pub fn blocks(&self) -> usize {
        blocks_for(self.len)
    }
}

fn measure_experiment(id: &str, experiment: &platonik_core::Experiment) -> Vec<Measured> {
    let result = platonik_core::run(experiment).expect("run");
    let receipt = platonik_core::check::make_receipt(experiment).expect("receipt");
    vec![
        Measured {
            id: id.into(),
            kind: InnerKind::PlatonikExperimentV1,
            len: serde_json::to_vec(experiment)
                .expect("experiment json")
                .len(),
        },
        Measured {
            id: id.into(),
            kind: InnerKind::PlatonikResultV1,
            len: serde_json::to_vec(&result).expect("result json").len(),
        },
        Measured {
            id: id.into(),
            kind: InnerKind::PlatonikReceiptV1,
            len: serde_json::to_vec(&receipt).expect("receipt json").len(),
        },
    ]
}

/// Every Platonik artifact of the six fixtures and the `bridge-v1` suite.
#[must_use]
pub fn platonik_artifacts() -> Vec<Measured> {
    let mut out = Vec::new();
    for name in platonik_core::fixtures::names() {
        let experiment = platonik_core::fixtures::experiment(name).expect("fixture");
        out.extend(measure_experiment(&format!("fixture-{name}"), &experiment));
    }
    let report = platonik_core::suite::run_suite("bridge-v1").expect("suite");
    for case in &report.cases {
        out.extend(measure_experiment(
            &format!("bridge-v1-{}", case.id),
            &case.receipt.experiment,
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// (b) One adapter frame trace
// ---------------------------------------------------------------------------

/// Appends every frame's encoded state, split per case.
///
/// The trace of one `(segment, case)` is what a `FrameTraceV1` artifact
/// carries. Each frame is framed as `tick:u32be | complete:u8 | len:u32be |
/// encode_state`, so the trace is self-delimiting and a reader needs no second
/// index.
#[derive(Default)]
pub struct TraceCollector {
    current: Vec<u8>,
    /// One finished trace per case, in manifest order.
    pub traces: Vec<Vec<u8>>,
    /// Frames appended.
    pub frames: u64,
    /// Encoded state bytes, without the per-frame framing.
    pub state_bytes: u64,
}

impl TraceCollector {
    /// Closes the last case and returns every trace.
    #[must_use]
    pub fn finish(mut self) -> Vec<Vec<u8>> {
        if !self.current.is_empty() {
            self.traces.push(std::mem::take(&mut self.current));
        }
        self.traces
    }
}

impl Observer for TraceCollector {
    fn frame(&mut self, frame: &FrameView<'_>) {
        if frame.tick == 0 && !self.current.is_empty() {
            self.traces.push(std::mem::take(&mut self.current));
        }
        let state = codec::encode_state(frame.state);
        self.current.extend_from_slice(&frame.tick.to_be_bytes());
        self.current.push(u8::from(frame.complete));
        self.current
            .extend_from_slice(&(state.len() as u32).to_be_bytes());
        self.current.extend_from_slice(&state);
        self.frames += 1;
        self.state_bytes += state.len() as u64;
    }
}

/// The committed witness corpus worst case, read from the workspace.
#[must_use]
pub fn worst_case_vector() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/vhalla-witness/tests/vectors/worst-case.txt");
    std::fs::read_to_string(&path).expect("worst-case vector")
}

/// The traces of one segment of the worst-case vector, one per case.
#[must_use]
pub fn worst_case_traces() -> (Vec<Vec<u8>>, u64, u64) {
    let text = worst_case_vector();
    let vector = vhalla_witness::vectors::parse(&text).expect("parse");
    let manifest = codec::decode_manifest(&vector.manifest).expect("manifest");
    let valid = ValidManifest::validate(manifest).expect("validate");
    let candidate = codec::decode_candidate(&vector.assignment).expect("candidate");
    let assignment = valid.assign(candidate).expect("assign");
    let program = ProgramHash::of(&codec::encode_assignment(&assignment));
    let mut observer = TraceCollector::default();
    let run = platform::run_observed(
        &valid,
        &assignment,
        RunCapability::mint(
            valid.hash(),
            program,
            WorkAllowance {
                max_total: valid.fuel_total(),
            },
            RunRole::Replay,
        ),
        &mut observer,
    )
    .expect("run");
    assert_eq!(
        run.output_hash().0,
        vector.output_hash,
        "the observer changed the run"
    );
    let frames = observer.frames;
    let state_bytes = observer.state_bytes;
    (observer.finish(), frames, state_bytes)
}

// ---------------------------------------------------------------------------
// (c) Driving the assembly
// ---------------------------------------------------------------------------

/// What one assembly run retained and cost.
#[derive(Clone, Copy, Debug)]
pub struct Assembled {
    /// Artifact bytes.
    pub len: usize,
    /// Blocks.
    pub blocks: usize,
    /// Peak bytes the assembly held.
    pub peak_retained: u64,
    /// Peak bytes the transport held beside it (one block or one record).
    pub transport_peak: u64,
    /// SHA-256 invocations the assembly charged.
    pub hashes: u64,
}

impl Assembled {
    /// Assembly peak as a multiple of the artifact. This is the figure the
    /// plan caps at 1.25 x: it is what the receiver charges against
    /// `max_artifact_bytes`.
    #[must_use]
    pub fn ratio(&self) -> f64 {
        if self.len == 0 {
            return 0.0;
        }
        self.peak_retained as f64 / self.len as f64
    }

    /// Assembly peak plus the transport's in-flight buffers.
    #[must_use]
    pub const fn combined(&self) -> u64 {
        self.peak_retained + self.transport_peak
    }

    /// The combined peak as a multiple of the artifact. The transport term is
    /// a constant bounded by [`MAX_TRANSPORT_BYTES`], never a ratio, so it
    /// dominates this figure for an artifact of only a block or two and
    /// vanishes at the 8 MiB ceiling.
    #[must_use]
    pub fn combined_ratio(&self) -> f64 {
        if self.len == 0 {
            return 0.0;
        }
        self.combined() as f64 / self.len as f64
    }
}

/// The most the transport may hold beside the assembly: one whole block, its
/// records, and one record being framed.
pub const MAX_TRANSPORT_BYTES: u64 = 2 * BLOCK_LEN as u64
    + (MAX_RECORDS_PER_BLOCK * RECORD_HEADER_LEN) as u64
    + RECORD_BODY_LEN as u64;

fn manifest_of(bytes: &[u8], kind: InnerKind) -> ArtifactManifest {
    ArtifactManifest {
        id: InnerArtifactId {
            kind,
            sha256: sha256(bytes),
        },
        total_len: bytes.len() as u64,
        block_len: BLOCK_LEN,
        blocks: bytes.chunks(BLOCK_LEN as usize).map(sha256).collect(),
        decompressed_len: bytes.len() as u64,
    }
}

fn blocks_of(manifest: &ArtifactManifest, bytes: &[u8]) -> Vec<Block> {
    let hash = manifest.hash();
    bytes
        .chunks(BLOCK_LEN as usize)
        .enumerate()
        .map(|(index, chunk)| Block {
            manifest: hash,
            index: index as u8,
            offset: index as u64 * u64::from(BLOCK_LEN),
            bytes: chunk.to_vec(),
        })
        .collect()
}

/// Assembles `bytes` natively, or through the browser record mapping.
///
/// The transport peak is counted honestly: one whole block on the native
/// path, and one whole block plus its 4 KiB records on the browser path,
/// because a browser receiver holds both while it joins them.
///
/// # Panics
///
/// Panics if the assembly refuses anything, which would be a defect in the
/// crate rather than a measurement.
#[must_use]
pub fn assemble(bytes: &[u8], kind: InnerKind, browser: bool) -> Assembled {
    let manifest = manifest_of(bytes, kind);
    let request = ArtifactRequest {
        session: SessionKey([1; 32]),
        id: manifest.id,
        max_bytes: MAX_ARTIFACT_BYTES,
        nonce: [2; 32],
    };
    let blocks = blocks_of(&manifest, bytes);
    let mut assembly =
        ArtifactAssembly::open(&request, &manifest, 0, blocks.len() as u64 + 1).expect("open");
    let mut transport_peak = 0_u64;
    let mut complete = blocks.is_empty();
    for (step, block) in blocks.iter().enumerate() {
        let delivered = if browser {
            let records = split_block(block).expect("split");
            let record_bytes: usize = records.iter().map(Vec::len).sum();
            transport_peak =
                transport_peak.max((block.bytes.len() + record_bytes + RECORD_BODY_LEN) as u64);
            block_from_records(block.manifest, block.index, block.offset, &records).expect("join")
        } else {
            transport_peak = transport_peak.max(block.bytes.len() as u64);
            block.clone()
        };
        match assembly.accept(&delivered, step as u64).expect("accept") {
            Accepted::Complete => complete = true,
            Accepted::Stored => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    assert!(complete, "the artifact never completed");
    let measured = Assembled {
        len: bytes.len(),
        blocks: assembly.block_count(),
        peak_retained: assembly.peak_retained(),
        transport_peak,
        hashes: assembly.hashes(),
    };
    assert_eq!(assembly.take().expect("take"), bytes, "bytes differ");
    measured
}

// ---------------------------------------------------------------------------
// (d) The widest frame objects
// ---------------------------------------------------------------------------

/// The widest admissible `GameManifest`: every cell open with a fallback,
/// eight cases, four inner artifact ids, and saturated limits.
#[must_use]
pub fn widest_game_manifest() -> GameManifest {
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

/// The widest admissible `SessionOpen`: sixteen players each naming every
/// cell, saturated realm and room.
#[must_use]
pub fn widest_session_open(manifest: &GameManifest) -> SessionOpen {
    SessionOpen {
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
    }
}

/// One object's encoded size and its margin under the signed body bound.
#[derive(Clone, Copy, Debug)]
pub struct FrameFit {
    /// Encoded bytes.
    pub len: usize,
    /// `MAX_SIGNED_BODY_BYTES - len`.
    pub margin: usize,
}

/// The widest manifest and opening against one signed frame.
#[must_use]
pub fn widest_frame_fits() -> (FrameFit, FrameFit) {
    let manifest = widest_game_manifest();
    manifest.validate().expect("the widest manifest is valid");
    let manifest_len = encode_game_manifest(&manifest).len();
    let open_len = encode_session_open(&widest_session_open(&manifest)).len();
    (
        FrameFit {
            len: manifest_len,
            margin: MAX_SIGNED_BODY_BYTES - manifest_len,
        },
        FrameFit {
            len: open_len,
            margin: MAX_SIGNED_BODY_BYTES - open_len,
        },
    )
}

/// The largest artifact the 128-block, 64 KiB grid can carry.
pub const GRID_CEILING: u64 = MAX_BLOCKS as u64 * BLOCK_LEN as u64;
