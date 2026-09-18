//! The signed response and the prover that produces one.

use alloc::vec::Vec;

use ed25519_dalek::{Signer, SigningKey};
use vhalla_witness::codec::{self, CodecError, Field, Reader, Writer, MAX_ASSIGNMENT_BYTES};
use vhalla_witness::hash::{digest, ManifestHash, OutputHash, ProgramHash, ReceiptHash};
use vhalla_witness::manifest::{ManifestError, ValidManifest};
use vhalla_witness::model::Program;
use vhalla_witness::platform::{
    self, ClaimedReceipt, RunRefused, RunRole, WitnessReceipt, WorkAllowance, RECEIPT_BYTES,
};

use crate::challenge::{Algorithm, VerifiedChallenge};
use crate::{transcript, RESPONSE_DOMAIN, VERSION};

/// Closed proof profile set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ProofProfile {
    /// The receipt itself; the verifier replays.
    TransparentReceipt = 1,
}

/// `measured_work`: the two contract quantities the subject claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MeasuredWork {
    /// Delivered sparks over every case.
    pub useful: u64,
    /// Total work over every case.
    pub total: u64,
}

/// Fixed part of a response before the candidate bytes and the receipt.
const RESPONSE_FIXED_BYTES: usize = 1 + 1 + 32 * 7 + 8 + 8 + 9 + 2;
/// Largest response: fixed part, candidate, receipt, signature.
pub const MAX_RESPONSE_BYTES: usize =
    RESPONSE_FIXED_BYTES + MAX_ASSIGNMENT_BYTES + RECEIPT_BYTES + 64;

/// A signed response as produced and as carried on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// Encoding version.
    pub version: u8,
    /// Proof profile.
    pub proof_profile: ProofProfile,
    /// The challenge answered.
    pub challenge_id: [u8; 32],
    /// `Challenge::hash()` of the exact challenge answered.
    pub challenge_hash: [u8; 32],
    /// The subject's full key.
    pub subject_key: [u8; 32],
    /// The manifest run.
    pub task_manifest_hash: ManifestHash,
    /// The assignment run.
    pub program_hash: ProgramHash,
    /// The output produced.
    pub output_hash: OutputHash,
    /// Digest of the receipt below.
    pub receipt_hash: ReceiptHash,
    /// The claimed quantities.
    pub measured_work: MeasuredWork,
    /// Reserved for Hashcash mode.
    pub hashcash_nonce: Option<u64>,
    /// Canonical candidate program bytes for the manifest's open slots.
    pub candidate: Vec<u8>,
    /// The receipt, decodable and tamperable.
    pub claimed: ClaimedReceipt,
    /// Subject signature over the transcript.
    pub signature: [u8; 64],
}

fn put_body(writer: &mut Writer, response: &Response) {
    writer.u8(response.version);
    writer.u8(response.proof_profile as u8);
    writer.bytes(&response.challenge_id);
    writer.bytes(&response.challenge_hash);
    writer.bytes(&response.subject_key);
    writer.bytes(&response.task_manifest_hash.0);
    writer.bytes(&response.program_hash.0);
    writer.bytes(&response.output_hash.0);
    writer.bytes(&response.receipt_hash.0);
    writer.u64(response.measured_work.useful);
    writer.u64(response.measured_work.total);
    match response.hashcash_nonce {
        None => writer.u8(0),
        Some(nonce) => {
            writer.u8(1);
            writer.u64(nonce);
        }
    }
    writer.u16(response.candidate.len() as u16);
    writer.bytes(&response.candidate);
    writer.bytes(&response.claimed.encode());
}

impl Response {
    /// The signed bytes: every field except the signature.
    #[must_use]
    pub fn body(&self) -> Vec<u8> {
        let mut writer = Writer::with_capacity(MAX_RESPONSE_BYTES);
        put_body(&mut writer, self);
        writer.finish()
    }
    /// The message the subject signs.
    #[must_use]
    pub fn transcript(&self) -> Vec<u8> {
        transcript(RESPONSE_DOMAIN, &self.body())
    }
    /// The digest that identifies this response in the one-use window and the
    /// reward: over the transcript, so two responses differ if any signed
    /// field differs.
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        digest(RESPONSE_DOMAIN, &self.body())
    }
    /// Canonical bytes: body then signature.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::with_capacity(MAX_RESPONSE_BYTES);
        put_body(&mut writer, self);
        writer.bytes(&self.signature);
        writer.finish()
    }
    /// Decodes at most [`MAX_RESPONSE_BYTES`].
    pub fn decode(raw: &[u8]) -> Result<Self, CodecError> {
        let mut reader = Reader::bounded(raw, MAX_RESPONSE_BYTES)?;
        let version = reader.u8(Field::Version)?;
        if version != VERSION {
            return Err(CodecError::UnsupportedVersion { found: version });
        }
        let proof_profile = match reader.u8(Field::Language)? {
            1 => ProofProfile::TransparentReceipt,
            found => {
                return Err(CodecError::Discriminant {
                    field: Field::Language,
                    found,
                })
            }
        };
        let challenge_id = reader.hash()?;
        let challenge_hash = reader.hash()?;
        let subject_key = reader.hash()?;
        let task_manifest_hash = ManifestHash(reader.hash()?);
        let program_hash = ProgramHash(reader.hash()?);
        let output_hash = OutputHash(reader.hash()?);
        let receipt_hash = ReceiptHash(reader.hash()?);
        let measured_work = MeasuredWork {
            useful: reader.u64(Field::Ledger)?,
            total: reader.u64(Field::Ledger)?,
        };
        let hashcash_nonce = match reader.u8(Field::Remember)? {
            0 => None,
            1 => Some(reader.u64(Field::Value)?),
            found => {
                return Err(CodecError::Discriminant {
                    field: Field::Remember,
                    found,
                })
            }
        };
        let candidate_len = usize::from(reader.u16(Field::Count)?);
        if candidate_len > MAX_ASSIGNMENT_BYTES {
            return Err(CodecError::Bound {
                field: Field::Count,
            });
        }
        let mut candidate = Vec::with_capacity(candidate_len);
        for _ in 0..candidate_len {
            candidate.push(reader.u8(Field::Cell)?);
        }
        let mut receipt = [0_u8; RECEIPT_BYTES];
        for byte in &mut receipt {
            *byte = reader.u8(Field::Hash)?;
        }
        let claimed = ClaimedReceipt::decode(&receipt)?;
        let mut signature = [0_u8; 64];
        signature[..32].copy_from_slice(&reader.hash()?);
        signature[32..].copy_from_slice(&reader.hash()?);
        reader.finish()?;
        Ok(Self {
            version,
            proof_profile,
            challenge_id,
            challenge_hash,
            subject_key,
            task_manifest_hash,
            program_hash,
            output_hash,
            receipt_hash,
            measured_work,
            hashcash_nonce,
            candidate,
            claimed,
            signature,
        })
    }
}

/// Why the prover could not respond.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProveError {
    /// The signing key is not the challenge's subject.
    Subject,
    /// The challenge is not a witness-mode challenge.
    Algorithm,
    /// The manifest is not the challenge's manifest.
    Manifest,
    /// The candidate was refused.
    Candidate(ManifestError),
    /// The run was refused.
    Run(RunRefused),
}

/// The receipt in its wire form.
#[must_use]
pub fn claim(receipt: &WitnessReceipt) -> ClaimedReceipt {
    let binding = receipt.binding();
    ClaimedReceipt {
        challenge_id: binding.challenge_id,
        subject_key: binding.subject_key,
        manifest: receipt.manifest(),
        program: receipt.program(),
        output: receipt.output(),
        useful: receipt.useful(),
        total: receipt.total(),
        passed: receipt.passed(),
        case_count: receipt.case_count(),
    }
}

/// Runs the candidate under the challenge and signs the response.
pub fn respond(
    challenge: &VerifiedChallenge,
    manifest: &ValidManifest,
    candidate: Vec<(u16, Program)>,
    allowance: WorkAllowance,
    key: &SigningKey,
) -> Result<Response, ProveError> {
    let subject_key = key.verifying_key().to_bytes();
    if subject_key != challenge.challenge().subject_key {
        return Err(ProveError::Subject);
    }
    if challenge.challenge().algorithm != Algorithm::Witness {
        return Err(ProveError::Algorithm);
    }
    if manifest.hash() != challenge.challenge().task_manifest_hash {
        return Err(ProveError::Manifest);
    }
    let candidate_bytes = codec::encode_candidate(&candidate);
    let assignment = manifest.assign(candidate).map_err(ProveError::Candidate)?;
    let program = ProgramHash::of(&codec::encode_assignment(&assignment));
    let capability = challenge.run_capability(program, allowance, RunRole::Prove);
    let run = platform::run(manifest, &assignment, capability).map_err(ProveError::Run)?;
    let receipt = run.into_receipt(challenge.receipt_binding());
    let claimed = claim(&receipt);
    let mut response = Response {
        version: VERSION,
        proof_profile: ProofProfile::TransparentReceipt,
        challenge_id: challenge.challenge().challenge_id,
        challenge_hash: challenge.challenge().hash(),
        subject_key,
        task_manifest_hash: receipt.manifest(),
        program_hash: receipt.program(),
        output_hash: receipt.output(),
        receipt_hash: receipt.hash(),
        measured_work: MeasuredWork {
            useful: receipt.useful(),
            total: receipt.total(),
        },
        hashcash_nonce: None,
        candidate: candidate_bytes,
        claimed,
        signature: [0; 64],
    };
    response.signature = key.sign(&response.transcript()).to_bytes();
    Ok(response)
}
