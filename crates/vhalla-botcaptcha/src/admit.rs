//! The verifier: every step from bytes to a `VerifiedWitness`, with the
//! one-use consumption last.

use alloc::vec::Vec;

use ed25519_dalek::{Signature, VerifyingKey};
use vhalla_witness::codec;
use vhalla_witness::hash::{digest, ProgramHash, ReceiptHash};
use vhalla_witness::manifest::ValidManifest;
use vhalla_witness::platform::{self, RunRole, WitnessReceipt, WorkAllowance};

use crate::challenge::{Challenge, ChallengeContext, Purpose, VerifiedChallenge, WitnessError};
use crate::response::{claim, Response};
use crate::window::{OneUseWindow, WindowError};
use crate::REWARD_DOMAIN;

/// Evidence that one response satisfied one challenge and was consumed once.
///
/// Private fields, no `Clone`, no `From`, no decoder. It is not a
/// `VerifiedEnvelope` and cannot enter `RemoteRequest::from_verified`.
///
/// ```compile_fail
/// use vhalla_botcaptcha::admit::VerifiedWitness;
/// fn dup(witness: &VerifiedWitness) -> VerifiedWitness { witness.clone() }
/// ```
///
/// ```compile_fail
/// use vhalla_botcaptcha::admit::VerifiedWitness;
/// fn forge() -> VerifiedWitness { VerifiedWitness { scope_key: [0; 32], response_hash: [0; 32], reward: [0; 32], receipt: todo!(), purpose: todo!(), expires_at: 0 } }
/// ```
#[derive(Debug)]
pub struct VerifiedWitness {
    scope_key: [u8; 32],
    response_hash: [u8; 32],
    reward: [u8; 32],
    receipt: WitnessReceipt,
    purpose: Purpose,
    expires_at: u64,
}

impl VerifiedWitness {
    /// The dedup scope that was consumed.
    #[must_use]
    pub const fn scope_key(&self) -> [u8; 32] {
        self.scope_key
    }
    /// The response that was admitted.
    #[must_use]
    pub const fn response_hash(&self) -> [u8; 32] {
        self.response_hash
    }
    /// The reward digest over `scope_key || response_hash`: policy grants at
    /// most one badge per scope by this digest.
    #[must_use]
    pub const fn reward(&self) -> [u8; 32] {
        self.reward
    }
    /// The replayed receipt.
    #[must_use]
    pub const fn receipt(&self) -> &WitnessReceipt {
        &self.receipt
    }
    /// The challenge purpose.
    #[must_use]
    pub const fn purpose(&self) -> Purpose {
        self.purpose
    }
    /// The challenge expiry.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

/// Owns the injected start time, the allowance, and the one-use window.
#[derive(Debug)]
pub struct WitnessVerifier {
    started_at: u64,
    allowance: WorkAllowance,
    window: OneUseWindow,
}

impl WitnessVerifier {
    /// A verifier that refuses challenges issued before `started_at`.
    #[must_use]
    pub const fn new(started_at: u64, allowance: WorkAllowance, window: OneUseWindow) -> Self {
        Self {
            started_at,
            allowance,
            window,
        }
    }
    /// The one-use window.
    #[must_use]
    pub const fn window(&self) -> &OneUseWindow {
        &self.window
    }
    /// Drops expired entries.
    pub fn prune(&mut self, now: u64) {
        self.window.prune(now);
    }
    /// Verifies encoded bytes.
    pub fn verify_bytes(
        &mut self,
        challenge: &[u8],
        manifest: &ValidManifest,
        response: &[u8],
        expected: ChallengeContext,
        now: u64,
    ) -> Result<VerifiedWitness, WitnessError> {
        let challenge = Challenge::decode(challenge)?;
        let response = Response::decode(response)?;
        self.verify_response(challenge, manifest, &response, expected, now)
    }
    /// Every verifier step in order; the window is consumed last.
    pub fn verify_response(
        &mut self,
        challenge: Challenge,
        manifest: &ValidManifest,
        response: &Response,
        expected: ChallengeContext,
        now: u64,
    ) -> Result<VerifiedWitness, WitnessError> {
        let verified = VerifiedChallenge::verify(challenge, expected, self.started_at, now)?;
        let challenge = verified.challenge();
        if manifest.hash() != challenge.task_manifest_hash {
            return Err(WitnessError::Manifest);
        }
        let subject = VerifyingKey::from_bytes(&challenge.subject_key)
            .map_err(|_| WitnessError::SubjectSignature)?;
        if subject.is_weak() {
            return Err(WitnessError::WeakSubjectKey);
        }
        subject
            .verify_strict(
                &response.transcript(),
                &Signature::from_bytes(&response.signature),
            )
            .map_err(|_| WitnessError::SubjectSignature)?;
        let claimed = response.claimed;
        if response.challenge_id != challenge.challenge_id
            || response.subject_key != challenge.subject_key
            || response.task_manifest_hash != challenge.task_manifest_hash
            || claimed.challenge_id != challenge.challenge_id
            || claimed.subject_key != challenge.subject_key
            || claimed.manifest != challenge.task_manifest_hash
        {
            return Err(WitnessError::Binding);
        }
        if response.program_hash != claimed.program
            || response.output_hash != claimed.output
            || response.measured_work.useful != claimed.useful
            || response.measured_work.total != claimed.total
            || response.receipt_hash != ReceiptHash::of(&claimed.encode())
        {
            return Err(WitnessError::Claim);
        }
        let candidate = codec::decode_candidate(&response.candidate)?;
        let assignment = manifest
            .assign(candidate)
            .map_err(|_| WitnessError::Candidate)?;
        let program = ProgramHash::of(&codec::encode_assignment(&assignment));
        if program != claimed.program {
            return Err(WitnessError::Program);
        }
        if manifest.fuel_total() > self.allowance.max_total {
            return Err(WitnessError::Allowance);
        }
        let capability = verified.run_capability(program, self.allowance, RunRole::Replay);
        let run =
            platform::run(manifest, &assignment, capability).map_err(|_| WitnessError::Run)?;
        let receipt = run.into_receipt(verified.receipt_binding());
        if !claimed.matches(&receipt) || claim(&receipt) != claimed {
            return Err(WitnessError::Receipt);
        }
        let contract = challenge.contract;
        if receipt.useful() < contract.useful_floor {
            return Err(WitnessError::Floor);
        }
        if receipt.total() > contract.total_ceiling {
            return Err(WitnessError::Ceiling);
        }
        if contract.require_passed && !receipt.passed() {
            return Err(WitnessError::NotPassed);
        }
        let scope_key = verified.scope_key();
        let response_hash = response.hash();
        let expires_at = challenge.expires_at;
        let purpose = challenge.purpose;
        self.window
            .consume(scope_key, response_hash, expires_at)
            .map_err(|error| match error {
                WindowError::Replay => WitnessError::Replay,
                WindowError::Equivocation => WitnessError::Equivocation,
                WindowError::Capacity => WitnessError::Capacity,
            })?;
        let mut body = Vec::with_capacity(64);
        body.extend_from_slice(&scope_key);
        body.extend_from_slice(&response_hash);
        Ok(VerifiedWitness {
            scope_key,
            response_hash,
            reward: digest(REWARD_DOMAIN, &body),
            receipt,
            purpose,
            expires_at,
        })
    }
}
