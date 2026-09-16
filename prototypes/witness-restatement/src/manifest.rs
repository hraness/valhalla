//! The verifier-authored task: a world, which cells the candidate programs
//! fill, the cases to replay, and the work contract.
//!
//! A `TaskManifest` is data. `ValidManifest::validate` builds the `World` and
//! every `Case`, computes the `ManifestHash`, and is the only way to bind
//! candidate programs into an `Assignment` that `platform::run` accepts.

use alloc::vec::Vec;

use crate::bounds::{MAX_CELLS, MAX_INITIAL_SPARKS};
use crate::codec::{self, MAX_CASES, MAX_MANIFEST_BYTES};
use crate::hash::ManifestHash;
use crate::model::Program;
use crate::world::{Assignment, Case, CaseSpec, World, WorldError, WorldSpec};

/// One cell of the world: either the manifest fixes its program or the
/// candidate must supply one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramSlot {
    /// The world cell.
    pub cell: u16,
    /// A fixed program, or `None` for an open slot.
    pub fixed: Option<Program>,
}

/// The games plan threshold: pass all cases with at least `useful_floor`
/// delivered sparks and at most `total_ceiling` total work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkContract {
    /// Minimum `Σ beacons.delivered` across every case.
    pub useful_floor: u64,
    /// Maximum `Σ ledger.total()` across every case.
    pub total_ceiling: u64,
    /// Whether every case outcome must pass.
    pub require_passed: bool,
}

/// The session input a verifier authors and hashes into a challenge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskManifest {
    /// The world minus programs and budgets.
    pub world: WorldSpec,
    /// One slot per world cell, strictly ascending by cell id.
    pub slots: Vec<ProgramSlot>,
    /// One to eight replays; each declares its own budgets and loading work,
    /// at least the manifest's canonical length.
    pub cases: Vec<CaseSpec>,
    /// The floor and ceiling.
    pub contract: WorkContract,
}

/// Why a manifest or a candidate is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManifestError {
    /// The world, a case, or the merged assignment failed validation.
    World(WorldError),
    /// Slots are unsorted, duplicated, or do not name exactly the world cells.
    Slots,
    /// There are no cases or more than [`MAX_CASES`].
    Cases,
    /// The ceiling exceeds the fuel that can be charged, or the floor exceeds
    /// the sparks that can be delivered.
    Contract,
    /// The canonical encoding exceeds [`MAX_MANIFEST_BYTES`].
    TooLarge,
    /// A case declares less loading work than the manifest's canonical length,
    /// so parsing would be under-charged.
    LoadingWork,
    /// The candidate does not supply exactly the open slots in ascending order.
    Candidate,
}

impl From<WorldError> for ManifestError {
    fn from(error: WorldError) -> Self {
        Self::World(error)
    }
}

/// A manifest whose world and cases are validated and whose hash is fixed.
#[derive(Debug)]
pub struct ValidManifest {
    manifest: TaskManifest,
    world: World,
    cases: Vec<Case>,
    hash: ManifestHash,
    encoded_len: usize,
}

impl ValidManifest {
    /// Validates the world, every case, the slots, and the contract.
    pub fn validate(manifest: TaskManifest) -> Result<Self, ManifestError> {
        let world = World::new(manifest.world.clone())?;
        if manifest.cases.is_empty() || manifest.cases.len() > MAX_CASES {
            return Err(ManifestError::Cases);
        }
        let mut cases = Vec::with_capacity(manifest.cases.len());
        for spec in &manifest.cases {
            cases.push(Case::new(&world, spec.clone())?);
        }
        let mut expected: Vec<u16> = world.cells().iter().map(|cell| cell.id).collect();
        expected.sort_unstable();
        let named: Vec<u16> = manifest.slots.iter().map(|slot| slot.cell).collect();
        if named != expected || named.len() > MAX_CELLS {
            return Err(ManifestError::Slots);
        }
        let mut fuel = 0_u64;
        for case in &cases {
            fuel = fuel
                .checked_add(case.fuel())
                .ok_or(ManifestError::Contract)?;
        }
        let max_useful = (MAX_INITIAL_SPARKS * MAX_CASES) as u64;
        if manifest.contract.total_ceiling > fuel || manifest.contract.useful_floor > max_useful {
            return Err(ManifestError::Contract);
        }
        let encoded = codec::encode_manifest(&manifest);
        if encoded.len() > MAX_MANIFEST_BYTES {
            return Err(ManifestError::TooLarge);
        }
        let floor = encoded.len() as u64;
        if cases.iter().any(|case| case.loading_work() < floor) {
            return Err(ManifestError::LoadingWork);
        }
        Ok(Self {
            hash: ManifestHash::of(&encoded),
            encoded_len: encoded.len(),
            manifest,
            world,
            cases,
        })
    }
    /// The manifest as authored.
    #[must_use]
    pub const fn manifest(&self) -> &TaskManifest {
        &self.manifest
    }
    /// The validated world.
    #[must_use]
    pub const fn world(&self) -> &World {
        &self.world
    }
    /// The validated cases in manifest order.
    #[must_use]
    pub fn cases(&self) -> &[Case] {
        &self.cases
    }
    /// The digest a challenge carries as `task_manifest_hash`.
    #[must_use]
    pub const fn hash(&self) -> ManifestHash {
        self.hash
    }
    /// Canonical encoded length in bytes.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        self.encoded_len
    }
    /// The cells a candidate must supply, ascending.
    pub fn open_slots(&self) -> impl Iterator<Item = u16> + '_ {
        self.manifest
            .slots
            .iter()
            .filter(|slot| slot.fixed.is_none())
            .map(|slot| slot.cell)
    }
    /// The contract.
    #[must_use]
    pub const fn contract(&self) -> WorkContract {
        self.manifest.contract
    }
    /// Sum of every case's fuel: the most work a replay can charge.
    #[must_use]
    pub fn fuel_total(&self) -> u64 {
        self.cases.iter().map(Case::fuel).sum()
    }
    /// Binds candidate programs for exactly the open slots, in ascending cell
    /// order, together with the fixed programs, into the only assignment type
    /// `platform::run` accepts.
    pub fn assign(&self, candidate: Vec<(u16, Program)>) -> Result<Assignment, ManifestError> {
        let open: Vec<u16> = self.open_slots().collect();
        let supplied: Vec<u16> = candidate.iter().map(|(cell, _)| *cell).collect();
        if supplied != open {
            return Err(ManifestError::Candidate);
        }
        let mut candidate = candidate.into_iter();
        let mut merged = Vec::with_capacity(self.manifest.slots.len());
        for slot in &self.manifest.slots {
            let program = match &slot.fixed {
                Some(program) => program.clone(),
                None => candidate.next().ok_or(ManifestError::Candidate)?.1,
            };
            merged.push((slot.cell, program));
        }
        Ok(Assignment::validate(&self.world, merged)?)
    }
}
