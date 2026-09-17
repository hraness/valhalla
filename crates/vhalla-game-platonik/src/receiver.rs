//! The receiver: admits records into a session, replays every sealed segment
//! through the engine under pre-charged budgets, checks the sealed prefix
//! against the previous checkpoint, and commits. Its outputs have private
//! fields, no `Clone`, no decoder, and no `From` into any authority type.

use std::collections::BTreeMap;

use vhalla_witness::hash::{ManifestHash, ProgramHash};
use vhalla_witness::manifest::ValidManifest;
use vhalla_witness::platform::{ReceiptBinding, WorkAllowance};
use vhalla_witness::vm::RunStatus;

use crate::engine::{EngineError, GameEngine, SegmentEvidence};
use crate::ids::{CheckpointHash, SessionKey};
use crate::manifest::VerificationAllowance;
use crate::record::GameRecord;
use crate::session::{Admitted, Rejection, SealPlan, Session, State};
use crate::wire::{CaseCheckpoint, Checkpoint, ForkReason, WorkSummary};

/// Receiver-wide policy; the minimum of policy and session limits applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiverPolicy {
    /// Most replays per session.
    pub max_replays: u32,
    /// Most replay work per session.
    pub max_work: u64,
    /// Most steps a session may consume.
    pub max_steps: u64,
}

/// Why the receiver refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum ReceiverError {
    Session(Rejection),
    BudgetExhausted,
    Engine(EngineError),
    Manifest,
    StepNotMonotone,
    ReplayMismatch,
    PrefixMismatch(u8),
    StatusRegressed(u8),
    LedgerOffset(u8),
    Settle(crate::settlement::SettleError),
}

impl From<Rejection> for ReceiverError {
    fn from(error: Rejection) -> Self {
        Self::Session(error)
    }
}

/// Evidence that the receiver reproduced a sealed checkpoint itself.
///
/// ```compile_fail
/// use vhalla_game_platonik::receiver::VerifiedCheckpoint;
/// fn dup(v: &VerifiedCheckpoint) -> VerifiedCheckpoint { v.clone() }
/// ```
#[derive(Debug)]
pub struct VerifiedCheckpoint {
    session: SessionKey,
    segment: u8,
    hash: CheckpointHash,
    through_tick: u32,
    work: WorkSummary,
    passed: bool,
    is_final: bool,
}

impl VerifiedCheckpoint {
    /// Session.
    #[must_use]
    pub const fn session(&self) -> SessionKey {
        self.session
    }
    /// Segment.
    #[must_use]
    pub const fn segment(&self) -> u8 {
        self.segment
    }
    /// The reproduced checkpoint hash.
    #[must_use]
    pub const fn hash(&self) -> CheckpointHash {
        self.hash
    }
    /// Through tick.
    #[must_use]
    pub const fn through_tick(&self) -> u32 {
        self.through_tick
    }
    /// Work summary at the read ticks.
    #[must_use]
    pub const fn work(&self) -> WorkSummary {
        self.work
    }
    /// Whether the whole-run contract passed as of this replay.
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.passed
    }
    /// Whether this was the final seal.
    #[must_use]
    pub const fn is_final(&self) -> bool {
        self.is_final
    }
}

/// One session's verification budget, charged before work.
#[derive(Clone, Copy, Debug)]
struct Budget {
    replays_left: u32,
    work_left: u64,
}

/// A receiver over one engine.
pub struct Receiver<E: GameEngine> {
    engine: E,
    policy: ReceiverPolicy,
    step: u64,
    budgets: BTreeMap<SessionKey, Budget>,
    memo: BTreeMap<(ManifestHash, ManifestHash, ProgramHash, u32), Vec<CaseCheckpoint>>,
}

impl<E: GameEngine> Receiver<E> {
    /// A receiver.
    pub fn new(engine: E, policy: ReceiverPolicy) -> Self {
        Self {
            engine,
            policy,
            step: 0,
            budgets: BTreeMap::new(),
            memo: BTreeMap::new(),
        }
    }
    /// Advances the monotone step from another module.
    pub(crate) fn advance_step(&mut self, step: u64) -> Result<(), ReceiverError> {
        self.advance(step)
    }
    /// Charges one replay of `work` against the session's budget.
    pub(crate) fn charge_replay(
        &mut self,
        session: &Session,
        work: u64,
    ) -> Result<(), ReceiverError> {
        self.charge(session, work)
    }
    /// The engine.
    pub(crate) const fn engine(&self) -> &E {
        &self.engine
    }
    fn advance(&mut self, step: u64) -> Result<(), ReceiverError> {
        if step < self.step {
            return Err(ReceiverError::StepNotMonotone);
        }
        self.step = step;
        Ok(())
    }
    fn budget(&mut self, session: &Session) -> Budget {
        let limits: VerificationAllowance = session.manifest().limits.verification;
        *self.budgets.entry(session.key()).or_insert(Budget {
            replays_left: limits.max_replays.min(self.policy.max_replays),
            work_left: limits.max_work.min(self.policy.max_work),
        })
    }
    fn charge(&mut self, session: &Session, work: u64) -> Result<(), ReceiverError> {
        let mut budget = self.budget(session);
        if budget.replays_left == 0 || budget.work_left < work {
            return Err(ReceiverError::BudgetExhausted);
        }
        budget.replays_left -= 1;
        budget.work_left -= work;
        self.budgets.insert(session.key(), budget);
        Ok(())
    }
    /// Admits one event record; a seal is replayed and committed here.
    pub fn admit(
        &mut self,
        session: &mut Session,
        record: &GameRecord,
        step: u64,
    ) -> Result<Option<VerifiedCheckpoint>, ReceiverError> {
        self.advance(step)?;
        match session.admit(record)? {
            Admitted::Pending(_) => Ok(None),
            Admitted::Seal(plan) => self.verify_seal(session, &plan).map(Some),
        }
    }
    fn replay(
        &mut self,
        session: &Session,
        plan: &SealPlan,
        manifest: &ValidManifest,
        through_tick: u32,
    ) -> Result<SegmentEvidence, ReceiverError> {
        let allowance = WorkAllowance {
            max_total: manifest
                .fuel_total()
                .min(session.manifest().limits.replay.max_total),
        };
        if manifest.fuel_total() > allowance.max_total {
            return Err(ReceiverError::BudgetExhausted);
        }
        self.charge(session, manifest.fuel_total())?;
        let binding = ReceiptBinding {
            challenge_id: session.key().0,
            subject_key: session.host(),
        };
        let evidence = self
            .engine
            .replay(
                session.world(),
                manifest,
                plan.candidate.clone(),
                allowance,
                through_tick,
                binding,
            )
            .map_err(ReceiverError::Engine)?;
        self.memo.insert(
            (
                session.world(),
                manifest.hash(),
                evidence.program,
                through_tick,
            ),
            evidence.cases.clone(),
        );
        Ok(evidence)
    }
    /// Derives the checkpoint a planned seal produces, charging this
    /// receiver's budget for the replay but committing nothing. An honest host
    /// runs this to learn the hash it must sign.
    pub fn derive(
        &mut self,
        session: &Session,
        plan: &SealPlan,
    ) -> Result<Checkpoint, ReceiverError> {
        let manifest =
            ValidManifest::validate(plan.manifest.clone()).map_err(|_| ReceiverError::Manifest)?;
        let evidence = self.replay(session, plan, &manifest, plan.through_tick)?;
        let ledger_checkpoint = session
            .ledger()
            .preview_seal(&plan.order)
            .map_err(|e| ReceiverError::Session(Rejection::SealApply(e)))?;
        Ok(Checkpoint {
            session: session.key(),
            ledger: ledger_checkpoint,
            parent: session.parent_checkpoint(),
            segment: plan.segment,
            segment_manifest: manifest.hash(),
            program: evidence.program,
            through_tick: plan.through_tick,
            cases: evidence.cases,
            work: evidence.work,
        })
    }
    /// The per-case values at `through_tick`, from the memo when the same
    /// world, segment manifest, program, and tick were replayed before.
    fn prefix_cases(
        &mut self,
        session: &Session,
        plan: &SealPlan,
        manifest: &ValidManifest,
        through_tick: u32,
    ) -> Result<Vec<CaseCheckpoint>, ReceiverError> {
        let assignment = manifest
            .assign(plan.candidate.clone())
            .map_err(|_| ReceiverError::Manifest)?;
        let program = ProgramHash::of(&vhalla_witness::codec::encode_assignment(&assignment));
        let key = (session.world(), manifest.hash(), program, through_tick);
        if let Some(cases) = self.memo.get(&key) {
            return Ok(cases.clone());
        }
        Ok(self.replay(session, plan, manifest, through_tick)?.cases)
    }
    fn verify_seal(
        &mut self,
        session: &mut Session,
        plan: &SealPlan,
    ) -> Result<VerifiedCheckpoint, ReceiverError> {
        let manifest =
            ValidManifest::validate(plan.manifest.clone()).map_err(|_| ReceiverError::Manifest)?;
        // Prefix check against the previous checkpoint at its read ticks; a
        // memoized replay of the same manifest, program, and tick costs nothing.
        if let Some(&(_, previous_tick, _)) = session.segments().last() {
            let prefix_cases = self.prefix_cases(session, plan, &manifest, previous_tick)?;
            for (index, case) in prefix_cases.iter().enumerate() {
                let Some(previous) = session.last_case(index) else {
                    continue;
                };
                let n = u64::from(plan.inputs_since_last[index]);
                let terminal = previous.status == RunStatus::FuelExhausted
                    || previous_tick >= plan.manifest.cases[index].ticks;
                if terminal && n != 0 {
                    return Err(ReceiverError::PrefixMismatch(index as u8));
                }
                if case.state != previous.state
                    || case.trace != previous.trace
                    || case.status != previous.status
                {
                    session.unresolve(ForkReason::ReplayMismatch, &[plan.seal.0]);
                    return Err(ReceiverError::PrefixMismatch(index as u8));
                }
                if case.ledger_total != previous.ledger_total + n {
                    session.unresolve(ForkReason::ReplayMismatch, &[plan.seal.0]);
                    return Err(ReceiverError::LedgerOffset(index as u8));
                }
            }
        }
        let evidence = self.replay(session, plan, &manifest, plan.through_tick)?;
        // Status advances only along Complete -> ActivationLimit -> FuelExhausted.
        for (index, case) in evidence.cases.iter().enumerate() {
            if let Some(previous) = session.last_case(index) {
                let rank = |s: RunStatus| match s {
                    RunStatus::Complete => 0,
                    RunStatus::ActivationLimit => 1,
                    RunStatus::FuelExhausted => 2,
                };
                if rank(case.status) < rank(previous.status) {
                    return Err(ReceiverError::StatusRegressed(index as u8));
                }
            }
        }
        // Derive the ledger checkpoint the seal will produce without mutating
        // the session's ledger: apply to a copy.
        let ledger_checkpoint = session
            .ledger()
            .preview_seal(&plan.order)
            .map_err(|e| ReceiverError::Session(Rejection::SealApply(e)))?;
        let checkpoint = Checkpoint {
            session: session.key(),
            ledger: ledger_checkpoint,
            parent: session.parent_checkpoint(),
            segment: plan.segment,
            segment_manifest: manifest.hash(),
            program: evidence.program,
            through_tick: plan.through_tick,
            cases: evidence.cases.clone(),
            work: evidence.work,
        };
        let hash = session.commit_seal(plan, &checkpoint)?;
        Ok(VerifiedCheckpoint {
            session: session.key(),
            segment: plan.segment,
            hash,
            through_tick: plan.through_tick,
            work: evidence.work,
            passed: evidence.passed,
            is_final: plan.is_final,
        })
    }
    /// Current step.
    #[must_use]
    pub const fn step(&self) -> u64 {
        self.step
    }
    /// Replays left for a session, if known.
    #[must_use]
    pub fn replays_left(&self, session: SessionKey) -> Option<u32> {
        self.budgets.get(&session).map(|b| b.replays_left)
    }
    /// Whether the session ended in a state the receiver reproduced.
    #[must_use]
    pub fn finished(session: &Session) -> bool {
        session.state() == State::Finished
    }
}
