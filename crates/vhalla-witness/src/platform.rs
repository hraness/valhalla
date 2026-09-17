//! The platform side of the split: the move-only run capability, the run
//! that executes every case of a validated manifest, and the receipt.
//!
//! The application supplies only an `Assignment`. It can name only conditions,
//! actions, memory slots, and ports; the platform owns the world, the tick
//! loop, the ledger, and the allowance, and it hands back plain data.

use alloc::vec::Vec;

use crate::codec::{self, LANGUAGE_FINITE_RULE_V1, VERSION};
use crate::hash::{ManifestHash, OutputHash, ProgramHash, ReceiptHash, StateHash};
use crate::ledger::{Arithmetic, Ledger};
use crate::manifest::ValidManifest;
use crate::vm::{self, Outcome, RunError, RunStatus};
use crate::world::Assignment;

/// The most total work a capability lets one run charge across its cases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkAllowance {
    /// Upper bound on `Σ case.fuel`.
    pub max_total: u64,
}

/// Who is running: the prover producing a receipt or a verifier replaying one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunRole {
    /// The candidate producing a witness.
    Prove,
    /// A verifier reproducing a claimed witness.
    Replay,
}

/// Permission for exactly one run of one assignment against one manifest.
///
/// Minted locally from data the caller already holds, so it proves no remote
/// fact; its value is that `run` consumes it, so one allowance cannot be spent
/// twice, and that it binds the manifest and program the run is for.
///
/// ```compile_fail
/// use vhalla_witness::platform::RunCapability;
/// fn dup(cap: &RunCapability) -> RunCapability { cap.clone() }
/// ```
///
/// ```compile_fail
/// use vhalla_witness::platform::{RunCapability, RunRole, WorkAllowance};
/// use vhalla_witness::hash::{ManifestHash, ProgramHash};
/// fn forge() -> RunCapability {
///     RunCapability { manifest: ManifestHash([0; 32]), program: ProgramHash([0; 32]),
///                     allowance: WorkAllowance { max_total: 0 }, role: RunRole::Prove }
/// }
/// ```
#[derive(Debug)]
pub struct RunCapability {
    manifest: ManifestHash,
    program: ProgramHash,
    allowance: WorkAllowance,
    role: RunRole,
}

impl RunCapability {
    /// Mints a capability for one run.
    #[must_use]
    pub const fn mint(
        manifest: ManifestHash,
        program: ProgramHash,
        allowance: WorkAllowance,
        role: RunRole,
    ) -> Self {
        Self {
            manifest,
            program,
            allowance,
            role,
        }
    }
    /// The manifest this run is for.
    #[must_use]
    pub const fn manifest(&self) -> ManifestHash {
        self.manifest
    }
    /// The assignment this run is for.
    #[must_use]
    pub const fn program(&self) -> ProgramHash {
        self.program
    }
    /// The allowance.
    #[must_use]
    pub const fn allowance(&self) -> WorkAllowance {
        self.allowance
    }
    /// The role.
    #[must_use]
    pub const fn role(&self) -> RunRole {
        self.role
    }
}

/// Why `run` refused before executing anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunRefused {
    /// The capability names a different manifest.
    Manifest,
    /// The capability names a different assignment.
    Program,
    /// `Σ case.fuel` exceeds the allowance.
    Allowance,
    /// The engine failed an internal invariant.
    Engine(RunError),
}

impl From<RunError> for RunRefused {
    fn from(error: RunError) -> Self {
        Self::Engine(error)
    }
}

impl From<Arithmetic> for RunRefused {
    fn from(_: Arithmetic) -> Self {
        Self::Engine(RunError::Arithmetic)
    }
}

/// One case's replayable result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaseResult {
    /// How the run ended.
    pub status: RunStatus,
    /// Completed ticks.
    pub ticks_completed: u32,
    /// Mission outcome.
    pub outcome: Outcome,
    /// Digest of the final state.
    pub final_state: StateHash,
    /// Every counter.
    pub ledger: Ledger,
    /// `Σ beacons.delivered`, read from the final state.
    pub useful: u64,
}

/// Every case result of one run, sealed by the manifest and program hashes.
#[derive(Debug)]
pub struct WitnessRun {
    manifest: ManifestHash,
    program: ProgramHash,
    role: RunRole,
    cases: Vec<CaseResult>,
    useful: u64,
    total: u64,
}

impl WitnessRun {
    /// The manifest.
    #[must_use]
    pub const fn manifest(&self) -> ManifestHash {
        self.manifest
    }
    /// The assignment.
    #[must_use]
    pub const fn program(&self) -> ProgramHash {
        self.program
    }
    /// The role the run was made under.
    #[must_use]
    pub const fn role(&self) -> RunRole {
        self.role
    }
    /// Case results in manifest order.
    #[must_use]
    pub fn cases(&self) -> &[CaseResult] {
        &self.cases
    }
    /// The floor quantity: delivered sparks summed over every case.
    #[must_use]
    pub const fn useful(&self) -> u64 {
        self.useful
    }
    /// The ceiling quantity: total work summed over every case.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.total
    }
    /// Whether every case outcome passed.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.cases.iter().all(|case| case.outcome.passed)
    }
    /// The canonical output bytes.
    #[must_use]
    pub fn output(&self) -> Vec<u8> {
        codec::encode_output(&self.cases)
    }
    /// Digest of the output bytes.
    #[must_use]
    pub fn output_hash(&self) -> OutputHash {
        OutputHash::of(&self.output())
    }
    /// Seals the run under a challenge binding.
    #[must_use]
    pub fn into_receipt(self, binding: ReceiptBinding) -> WitnessReceipt {
        WitnessReceipt {
            challenge_id: binding.challenge_id,
            subject_key: binding.subject_key,
            manifest: self.manifest,
            program: self.program,
            output: self.output_hash(),
            useful: self.useful,
            total: self.total,
            passed: self.passed(),
            case_count: self.cases.len() as u8,
        }
    }
}

/// Executes every case of the manifest under one consumed capability.
pub fn run(
    manifest: &ValidManifest,
    assignment: &Assignment,
    capability: RunCapability,
) -> Result<WitnessRun, RunRefused> {
    run_observed(manifest, assignment, capability, &mut ())
}

/// [`run`] with an observer that sees every frame of every case in manifest
/// order, including each case's tick-0 loading frame, so a caller can chain
/// per-frame digests without a second run. The observer changes nothing:
/// results, hashes, and ledgers are identical to [`run`].
pub fn run_observed<O: vm::Observer>(
    manifest: &ValidManifest,
    assignment: &Assignment,
    capability: RunCapability,
    observer: &mut O,
) -> Result<WitnessRun, RunRefused> {
    if capability.manifest != manifest.hash() {
        return Err(RunRefused::Manifest);
    }
    let program = ProgramHash::of(&codec::encode_assignment(assignment));
    if capability.program != program {
        return Err(RunRefused::Program);
    }
    if manifest.fuel_total() > capability.allowance.max_total {
        return Err(RunRefused::Allowance);
    }
    let mut cases = Vec::with_capacity(manifest.cases().len());
    let mut useful = 0_u64;
    let mut total = 0_u64;
    for case in manifest.cases() {
        let result = vm::run(manifest.world(), assignment, case, observer)?;
        let mut delivered = 0_u64;
        for beacon in &result.final_state.beacons {
            delivered = delivered
                .checked_add(u64::from(beacon.delivered))
                .ok_or(Arithmetic)?;
        }
        useful = useful.checked_add(delivered).ok_or(Arithmetic)?;
        total = total
            .checked_add(result.ledger.total()?)
            .ok_or(Arithmetic)?;
        cases.push(CaseResult {
            status: result.status,
            ticks_completed: result.ticks_completed,
            outcome: result.outcome,
            final_state: StateHash::of(&codec::encode_state(&result.final_state)),
            ledger: result.ledger,
            useful: delivered,
        });
    }
    Ok(WitnessRun {
        manifest: capability.manifest,
        program,
        role: capability.role,
        cases,
        useful,
        total,
    })
}

/// The challenge fields a receipt is sealed under: plain bytes, no key type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiptBinding {
    /// The challenge's 32 random bytes.
    pub challenge_id: [u8; 32],
    /// The subject's full verifying key.
    pub subject_key: [u8; 32],
}

/// Fixed encoded width of a receipt.
pub const RECEIPT_BYTES: usize = 2 + 32 + 32 + 32 + 32 + 32 + 8 + 8 + 1 + 1;

/// A sealed run: private fields, no decoder. The wire form is
/// [`ClaimedReceipt`]; a verifier replays and compares `encode()` bit for bit.
///
/// ```compile_fail
/// use vhalla_witness::platform::WitnessReceipt;
/// fn forge(raw: &[u8]) -> WitnessReceipt { WitnessReceipt::decode(raw).unwrap() }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WitnessReceipt {
    challenge_id: [u8; 32],
    subject_key: [u8; 32],
    manifest: ManifestHash,
    program: ProgramHash,
    output: OutputHash,
    useful: u64,
    total: u64,
    passed: bool,
    case_count: u8,
}

impl WitnessReceipt {
    /// Canonical bytes: version, language, binding, hashes, quantities.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = codec::Writer::with_capacity(RECEIPT_BYTES);
        writer.u8(VERSION);
        writer.u8(LANGUAGE_FINITE_RULE_V1);
        writer.bytes(&self.challenge_id);
        writer.bytes(&self.subject_key);
        writer.bytes(&self.manifest.0);
        writer.bytes(&self.program.0);
        writer.bytes(&self.output.0);
        writer.u64(self.useful);
        writer.u64(self.total);
        writer.bool(self.passed);
        writer.u8(self.case_count);
        writer.finish()
    }
    /// Digest of the canonical bytes.
    #[must_use]
    pub fn hash(&self) -> ReceiptHash {
        ReceiptHash::of(&self.encode())
    }
    /// The binding.
    #[must_use]
    pub const fn binding(&self) -> ReceiptBinding {
        ReceiptBinding {
            challenge_id: self.challenge_id,
            subject_key: self.subject_key,
        }
    }
    /// The manifest.
    #[must_use]
    pub const fn manifest(&self) -> ManifestHash {
        self.manifest
    }
    /// The assignment.
    #[must_use]
    pub const fn program(&self) -> ProgramHash {
        self.program
    }
    /// The output.
    #[must_use]
    pub const fn output(&self) -> OutputHash {
        self.output
    }
    /// Delivered sparks over every case.
    #[must_use]
    pub const fn useful(&self) -> u64 {
        self.useful
    }
    /// Total work over every case.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.total
    }
    /// Whether every case passed.
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.passed
    }
    /// Number of cases.
    #[must_use]
    pub const fn case_count(&self) -> u8 {
        self.case_count
    }
}

/// What a prover sends: public fields, decodable, tamperable in tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClaimedReceipt {
    /// Claimed challenge id.
    pub challenge_id: [u8; 32],
    /// Claimed subject key.
    pub subject_key: [u8; 32],
    /// Claimed manifest.
    pub manifest: ManifestHash,
    /// Claimed assignment.
    pub program: ProgramHash,
    /// Claimed output.
    pub output: OutputHash,
    /// Claimed delivered sparks.
    pub useful: u64,
    /// Claimed total work.
    pub total: u64,
    /// Claimed pass flag.
    pub passed: bool,
    /// Claimed case count.
    pub case_count: u8,
}

impl ClaimedReceipt {
    /// The same bytes a `WitnessReceipt` with these fields would encode to.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        WitnessReceipt {
            challenge_id: self.challenge_id,
            subject_key: self.subject_key,
            manifest: self.manifest,
            program: self.program,
            output: self.output,
            useful: self.useful,
            total: self.total,
            passed: self.passed,
            case_count: self.case_count,
        }
        .encode()
    }
    /// Decodes exactly [`RECEIPT_BYTES`].
    pub fn decode(raw: &[u8]) -> Result<Self, codec::CodecError> {
        use codec::{CodecError, Field, Reader};
        let mut reader = Reader::bounded(raw, RECEIPT_BYTES)?;
        let found = reader.u8(Field::Version)?;
        if found != VERSION {
            return Err(CodecError::UnsupportedVersion { found });
        }
        let found = reader.u8(Field::Language)?;
        if found != LANGUAGE_FINITE_RULE_V1 {
            return Err(CodecError::UnsupportedLanguage { found });
        }
        let claimed = Self {
            challenge_id: reader.hash()?,
            subject_key: reader.hash()?,
            manifest: ManifestHash(reader.hash()?),
            program: ProgramHash(reader.hash()?),
            output: OutputHash(reader.hash()?),
            useful: reader.u64(Field::Ledger)?,
            total: reader.u64(Field::Ledger)?,
            passed: reader.bool(Field::Bool)?,
            case_count: reader.u8(Field::Count)?,
        };
        reader.finish()?;
        Ok(claimed)
    }
    /// A `WitnessReceipt` with these exact fields, for the verifier's bit-exact
    /// comparison after its own replay.
    #[must_use]
    pub fn matches(&self, receipt: &WitnessReceipt) -> bool {
        self.encode() == receipt.encode()
    }
}
