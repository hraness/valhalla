//! The one engine seam. `GameEngine` is what a session and a receiver call;
//! `PlatonikV1` in `platonik.rs` is the only implementation. Nothing else in
//! the crate runs a program.

use vhalla_witness::hash::{ManifestHash, ProgramHash};
use vhalla_witness::manifest::{ManifestError, TaskManifest, ValidManifest};
use vhalla_witness::model::Program;
use vhalla_witness::platform::{ReceiptBinding, RunRefused, WitnessReceipt, WorkAllowance};

use crate::ids::RulesetId;
use crate::wire::{CaseCheckpoint, WorkSummary};

/// One admitted world input for one case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmittedInput {
    /// Case index.
    pub case: u8,
    /// Tick.
    pub tick: u32,
    /// The world event.
    pub kind: vhalla_witness::world::EventKind,
}

/// What a segment replay reports; every field is receiver-derived.
#[derive(Debug)]
pub struct SegmentEvidence {
    /// The world digest that seeded every trace head.
    pub world: ManifestHash,
    /// Hash of the segment manifest replayed.
    pub segment_manifest: ManifestHash,
    /// Hash of the assignment replayed.
    pub program: ProgramHash,
    /// Session-wide through tick this evidence was read at.
    pub through_tick: u32,
    /// Per case at that case's checkpoint read tick.
    pub cases: Vec<CaseCheckpoint>,
    /// Work over every case at the read ticks.
    pub work: WorkSummary,
    /// The receipt of the whole run, sealed under the binding.
    pub receipt: WitnessReceipt,
    /// Whether every case passed the contract.
    pub passed: bool,
}

/// Why a replay did not happen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineError {
    /// The segment manifest failed witness validation.
    Manifest(ManifestError),
    /// The candidate was refused.
    Candidate(ManifestError),
    /// The run was refused.
    Run(RunRefused),
}

/// The engine seam.
pub trait GameEngine {
    /// The ruleset this engine plays.
    fn ruleset(&self) -> RulesetId;
    /// The segment manifest: the revealed task with every admitted input
    /// declared in its case, in admission order.
    fn segment_manifest(&self, revealed: &TaskManifest, inputs: &[AdmittedInput]) -> TaskManifest;
    /// Replays every case of `manifest` with `candidate` under `allowance`,
    /// hashing every frame, and reads each case at `min(through_tick,
    /// last_frame_tick)`. `world` seeds the trace heads and is explicit
    /// because a live manifest does not contain the template hash.
    #[allow(clippy::too_many_arguments)]
    fn replay(
        &self,
        world: ManifestHash,
        manifest: &ValidManifest,
        candidate: Vec<(u16, Program)>,
        allowance: WorkAllowance,
        through_tick: u32,
        binding: ReceiptBinding,
    ) -> Result<SegmentEvidence, EngineError>;
}
