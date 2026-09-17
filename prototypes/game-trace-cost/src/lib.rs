//! A hashing frame observer over `platform::run_observed`: one `FrameDigest`
//! per frame (`vhalla/game/frame/v1` over tick, complete flag, and the
//! encoded state, never the ledger) chained into a `TraceHead`
//! (`vhalla/game/trace/v1`) seeded with the world digest, the program hash,
//! and the case index. Runs every committed witness vector and reports the
//! trace heads and the work done, so native and wasm32 cost and identity can
//! be compared.

use vhalla_witness::codec;
use vhalla_witness::hash::{digest, ManifestHash, ProgramHash};
use vhalla_witness::manifest::ValidManifest;
use vhalla_witness::platform::{self, RunCapability, RunRole, WorkAllowance};
use vhalla_witness::vectors::{hex, parse};
use vhalla_witness::vm::{FrameView, Observer};

/// Domain of one frame digest.
pub const FRAME_DOMAIN: &[u8] = b"vhalla/game/frame/v1";
/// Domain of the running trace head.
pub const TRACE_DOMAIN: &[u8] = b"vhalla/game/trace/v1";

/// The committed witness vectors, embedded at compile time.
pub const VECTORS: &[(&str, &str)] = &include!(concat!(env!("CARGO_MANIFEST_DIR"), "/vectors.in"));

/// Chains frame digests per case.
pub struct TraceObserver {
    world: ManifestHash,
    program: ProgramHash,
    case: u32,
    head: [u8; 32],
    /// Finished per-case trace heads in manifest order.
    pub heads: Vec<[u8; 32]>,
    /// Frames hashed.
    pub frames: u64,
    /// Bytes of encoded state hashed.
    pub state_bytes: u64,
}

impl TraceObserver {
    /// Seeds for a run over `world` and `program`.
    #[must_use]
    pub fn new(world: ManifestHash, program: ProgramHash) -> Self {
        Self {
            world,
            program,
            case: 0,
            head: [0; 32],
            heads: Vec::new(),
            frames: 0,
            state_bytes: 0,
        }
    }
    fn seed(&self, case: u32) -> [u8; 32] {
        let mut body = Vec::with_capacity(68);
        body.extend_from_slice(&self.world.0);
        body.extend_from_slice(&self.program.0);
        body.extend_from_slice(&case.to_be_bytes());
        digest(TRACE_DOMAIN, &body)
    }
    /// Closes the current case and returns the finished heads.
    pub fn finish(mut self) -> Vec<[u8; 32]> {
        if self.frames > 0 {
            self.heads.push(self.head);
        }
        self.heads
    }
}

impl Observer for TraceObserver {
    fn frame(&mut self, frame: &FrameView<'_>) {
        if frame.tick == 0 {
            if self.frames > 0 {
                self.heads.push(self.head);
                self.case += 1;
            }
            self.head = self.seed(self.case);
        }
        let state = codec::encode_state(frame.state);
        let mut body = Vec::with_capacity(5 + state.len());
        body.extend_from_slice(&frame.tick.to_be_bytes());
        body.push(u8::from(frame.complete));
        body.extend_from_slice(&state);
        let frame_digest = digest(FRAME_DOMAIN, &body);
        let mut link = Vec::with_capacity(64);
        link.extend_from_slice(&self.head);
        link.extend_from_slice(&frame_digest);
        self.head = digest(TRACE_DOMAIN, &link);
        self.frames += 1;
        self.state_bytes += state.len() as u64;
    }
}

/// One vector's trace result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Traced {
    /// Vector id.
    pub id: String,
    /// Per-case trace heads.
    pub heads: Vec<[u8; 32]>,
    /// Frames hashed.
    pub frames: u64,
    /// State bytes hashed.
    pub state_bytes: u64,
    /// Output hash, to prove the observer changed nothing.
    pub output_hash: [u8; 32],
}

/// Traces one vector text.
pub fn trace(text: &str) -> Result<Traced, String> {
    let vector = parse(text).ok_or("parse")?;
    let manifest = codec::decode_manifest(&vector.manifest).map_err(|e| format!("{e:?}"))?;
    let valid = ValidManifest::validate(manifest).map_err(|e| format!("{e:?}"))?;
    let candidate = codec::decode_candidate(&vector.assignment).map_err(|e| format!("{e:?}"))?;
    let assignment = valid.assign(candidate).map_err(|e| format!("{e:?}"))?;
    let program = ProgramHash::of(&codec::encode_assignment(&assignment));
    let mut observer = TraceObserver::new(valid.hash(), program);
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
    .map_err(|e| format!("{e:?}"))?;
    if run.output_hash().0 != vector.output_hash {
        return Err("output hash changed under observation".into());
    }
    let frames = observer.frames;
    let state_bytes = observer.state_bytes;
    Ok(Traced {
        id: vector.id,
        heads: observer.finish(),
        frames,
        state_bytes,
        output_hash: run.output_hash().0,
    })
}

/// Traces every vector and renders one line per vector.
#[must_use]
pub fn run_corpus() -> String {
    let mut out = String::new();
    for (name, text) in VECTORS {
        match trace(text) {
            Ok(traced) => {
                out.push_str(&format!(
                    "{name}: frames {} state_bytes {} heads {} output {}\n",
                    traced.frames,
                    traced.state_bytes,
                    traced
                        .heads
                        .iter()
                        .map(|h| hex(h))
                        .collect::<Vec<_>>()
                        .join(","),
                    hex(&traced.output_hash)
                ));
            }
            Err(error) => out.push_str(&format!("{name}: error {error}\n")),
        }
    }
    out
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use wasm_bindgen::prelude::wasm_bindgen;

    /// The corpus rendering for the Node driver.
    #[wasm_bindgen]
    pub fn run_corpus() -> String {
        super::run_corpus()
    }
}
