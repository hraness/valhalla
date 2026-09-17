//! `PlatonikV1`: the only `GameEngine`. It assigns the candidate, mints the
//! replay capability at this crate's single fenced call site, runs through
//! `platform::run_observed` with a hashing observer, and reads every case at
//! its checkpoint read tick.

use vhalla_witness::codec;
use vhalla_witness::hash::{digest, ManifestHash, ProgramHash, StateHash};
use vhalla_witness::manifest::{TaskManifest, ValidManifest};
use vhalla_witness::model::Program;
use vhalla_witness::platform::{self, ReceiptBinding, RunCapability, RunRole, WorkAllowance};
use vhalla_witness::vm::{ActivationError, FrameView, Observer, RunStatus};
use vhalla_witness::world::Event;

use crate::engine::{AdmittedInput, EngineError, GameEngine, SegmentEvidence};
use crate::ids::{RulesetId, FRAME_DOMAIN, TRACE_DOMAIN};
use crate::wire::{CaseCheckpoint, WorkSummary};

/// The Platonik habitat-v1 engine over `vhalla-witness`.
#[derive(Clone, Copy, Debug, Default)]
pub struct PlatonikV1;

/// Digest of one frame: tick, complete flag, encoded state. The ledger is
/// deliberately excluded so the digest is prefix stable across seals.
#[must_use]
pub fn frame_digest(frame: &FrameView<'_>) -> [u8; 32] {
    let state = codec::encode_state(frame.state);
    let mut body = Vec::with_capacity(5 + state.len());
    body.extend_from_slice(&frame.tick.to_be_bytes());
    body.push(u8::from(frame.complete));
    body.extend_from_slice(&state);
    digest(FRAME_DOMAIN, &body)
}

/// The trace seed for one case: world digest, program hash, case index.
#[must_use]
pub fn trace_seed(world: ManifestHash, program: ProgramHash, case: u32) -> [u8; 32] {
    let mut body = Vec::with_capacity(68);
    body.extend_from_slice(&world.0);
    body.extend_from_slice(&program.0);
    body.extend_from_slice(&case.to_be_bytes());
    digest(TRACE_DOMAIN, &body)
}

/// Chains one frame digest onto a trace head.
#[must_use]
pub fn chain(head: [u8; 32], frame: [u8; 32]) -> [u8; 32] {
    let mut link = Vec::with_capacity(64);
    link.extend_from_slice(&head);
    link.extend_from_slice(&frame);
    digest(TRACE_DOMAIN, &link)
}

/// Per-case values read at the checkpoint read tick.
#[derive(Clone, Copy, Debug)]
struct CaseRead {
    state: Option<StateHash>,
    trace: [u8; 32],
    ledger_total: u64,
    fuel_exhausted: bool,
    activation_limit: bool,
    last_tick: u32,
}

/// The hashing observer: for each case, chains frames through the read tick
/// and derives the status at that tick from the frames it saw.
struct FrameObserver {
    world: ManifestHash,
    program: ProgramHash,
    through_tick: u32,
    cases: Vec<CaseRead>,
}

impl FrameObserver {
    fn new(world: ManifestHash, program: ProgramHash, through_tick: u32) -> Self {
        Self {
            world,
            program,
            through_tick,
            cases: Vec::new(),
        }
    }
}

impl Observer for FrameObserver {
    fn frame(&mut self, frame: &FrameView<'_>) {
        if frame.tick == 0 {
            let case = self.cases.len() as u32;
            self.cases.push(CaseRead {
                state: None,
                trace: trace_seed(self.world, self.program, case),
                ledger_total: 0,
                fuel_exhausted: false,
                activation_limit: false,
                last_tick: 0,
            });
        }
        let Some(read) = self.cases.last_mut() else {
            return;
        };
        if frame.tick > self.through_tick {
            return;
        }
        read.trace = chain(read.trace, frame_digest(frame));
        read.state = Some(StateHash::of(&codec::encode_state(frame.state)));
        read.ledger_total = frame.ledger.total().unwrap_or(u64::MAX);
        read.last_tick = frame.tick;
        if !frame.complete {
            read.fuel_exhausted = true;
        }
        if frame
            .activations
            .iter()
            .any(|activation| activation.error == Some(ActivationError::ActivationLimit))
        {
            read.activation_limit = true;
        }
    }
}

impl GameEngine for PlatonikV1 {
    fn ruleset(&self) -> RulesetId {
        RulesetId::V1
    }
    fn segment_manifest(&self, revealed: &TaskManifest, inputs: &[AdmittedInput]) -> TaskManifest {
        let mut manifest = revealed.clone();
        for input in inputs {
            if let Some(case) = manifest.cases.get_mut(usize::from(input.case)) {
                case.events.push(Event {
                    tick: input.tick,
                    event: input.kind,
                });
            }
        }
        manifest
    }
    fn replay(
        &self,
        world: ManifestHash,
        manifest: &ValidManifest,
        candidate: Vec<(u16, Program)>,
        allowance: WorkAllowance,
        through_tick: u32,
        binding: ReceiptBinding,
    ) -> Result<SegmentEvidence, EngineError> {
        let assignment = manifest.assign(candidate).map_err(EngineError::Candidate)?;
        let program = ProgramHash::of(&codec::encode_assignment(&assignment));
        // The single fenced call site in this crate.
        #[allow(clippy::disallowed_methods)]
        let capability = RunCapability::mint(manifest.hash(), program, allowance, RunRole::Replay);
        let mut observer = FrameObserver::new(world, program, through_tick);
        let run = platform::run_observed(manifest, &assignment, capability, &mut observer)
            .map_err(EngineError::Run)?;
        let mut cases = Vec::with_capacity(run.cases().len());
        let mut useful = 0_u64;
        let mut total = 0_u64;
        for (index, read) in observer.cases.iter().enumerate() {
            let result = &run.cases()[index];
            let status = if read.fuel_exhausted {
                RunStatus::FuelExhausted
            } else if read.activation_limit {
                RunStatus::ActivationLimit
            } else {
                RunStatus::Complete
            };
            cases.push(CaseCheckpoint {
                state: read.state.unwrap_or(result.final_state),
                trace: read.trace,
                ledger_total: read.ledger_total,
                status,
            });
            useful = useful.saturating_add(result.useful);
            total = total.saturating_add(read.ledger_total);
        }
        let passed = run.passed();
        let receipt = run.into_receipt(binding);
        Ok(SegmentEvidence {
            world,
            segment_manifest: manifest.hash(),
            program,
            through_tick,
            cases,
            work: WorkSummary { useful, total },
            receipt,
            passed,
        })
    }
}
