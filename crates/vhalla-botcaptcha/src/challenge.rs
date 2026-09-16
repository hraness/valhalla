//! The signed challenge, its issuer, and the verified challenge that is this
//! crate's only source of run capabilities and receipt bindings.

use alloc::vec::Vec;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use vhalla_core::{RealmId, RoomId};
use vhalla_witness::codec::{CodecError, Field, Reader, Writer};
use vhalla_witness::hash::{digest, ManifestHash, ProgramHash};
use vhalla_witness::manifest::WorkContract;
use vhalla_witness::platform::{ReceiptBinding, RunCapability, RunRole, WorkAllowance};

use crate::{transcript, CHALLENGE_DOMAIN, DEDUP_DOMAIN, MAX_CHALLENGE_LIFETIME, VERSION};

/// Closed algorithm set. Hashcash is reserved; this crate accepts witness mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Algorithm {
    /// Hash-preimage anti-spam mode, reserved.
    Hashcash = 1,
    /// Program witness mode.
    Witness = 2,
}

/// Closed purpose set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Purpose {
    /// A passing witness relieves a rate limit.
    RateLimitRelief = 1,
    /// A passing witness qualifies an event for a game session.
    GameQualification = 2,
}

/// The fields a verifier expects a challenge to carry; compared as a whole.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChallengeContext {
    /// Full issuer verifying key.
    pub issuer_key: [u8; 32],
    /// Full subject verifying key.
    pub subject_key: [u8; 32],
    /// Realm.
    pub realm: RealmId,
    /// Room.
    pub room: RoomId,
    /// Purpose.
    pub purpose: Purpose,
}

/// Fixed encoded width of a challenge.
pub const CHALLENGE_BYTES: usize = 1 + 1 + 32 + 32 + 32 + 16 + 16 + 1 + 32 + 8 + 8 + 8 + 8 + 1 + 64;

/// A signed challenge as issued and as carried on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    /// Encoding version.
    pub version: u8,
    /// Algorithm.
    pub algorithm: Algorithm,
    /// 32 injected random bytes.
    pub challenge_id: [u8; 32],
    /// Full issuer key.
    pub issuer_key: [u8; 32],
    /// Full subject key.
    pub subject_key: [u8; 32],
    /// Realm.
    pub realm: RealmId,
    /// Room.
    pub room: RoomId,
    /// Purpose.
    pub purpose: Purpose,
    /// Hash of the task manifest the subject must run.
    pub task_manifest_hash: ManifestHash,
    /// Issue time, seconds.
    pub issued_at: u64,
    /// Expiry, seconds, inclusive.
    pub expires_at: u64,
    /// `target_or_work_floor` in witness mode: the work contract.
    pub contract: WorkContract,
    /// Issuer signature over the transcript.
    pub signature: [u8; 64],
}

fn put_body(writer: &mut Writer, challenge: &Challenge) {
    writer.u8(challenge.version);
    writer.u8(challenge.algorithm as u8);
    writer.bytes(&challenge.challenge_id);
    writer.bytes(&challenge.issuer_key);
    writer.bytes(&challenge.subject_key);
    writer.bytes(&challenge.realm.0.to_be_bytes());
    writer.bytes(&challenge.room.0.to_be_bytes());
    writer.u8(challenge.purpose as u8);
    writer.bytes(&challenge.task_manifest_hash.0);
    writer.u64(challenge.issued_at);
    writer.u64(challenge.expires_at);
    writer.u64(challenge.contract.useful_floor);
    writer.u64(challenge.contract.total_ceiling);
    writer.bool(challenge.contract.require_passed);
}

fn read_u128(reader: &mut Reader<'_>) -> Result<u128, CodecError> {
    let hi = reader.u64(Field::Contract)?;
    let lo = reader.u64(Field::Contract)?;
    Ok((u128::from(hi) << 64) | u128::from(lo))
}

impl Challenge {
    /// The signed bytes: every field except the signature.
    #[must_use]
    pub fn body(&self) -> Vec<u8> {
        let mut writer = Writer::with_capacity(CHALLENGE_BYTES - 64);
        put_body(&mut writer, self);
        writer.finish()
    }
    /// The message the issuer signs.
    #[must_use]
    pub fn transcript(&self) -> Vec<u8> {
        transcript(CHALLENGE_DOMAIN, &self.body())
    }
    /// Canonical bytes: body then signature.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::with_capacity(CHALLENGE_BYTES);
        put_body(&mut writer, self);
        writer.bytes(&self.signature);
        writer.finish()
    }
    /// Decodes exactly [`CHALLENGE_BYTES`]; closed enums are enforced here.
    pub fn decode(raw: &[u8]) -> Result<Self, CodecError> {
        let mut reader = Reader::bounded(raw, CHALLENGE_BYTES)?;
        let version = reader.u8(Field::Version)?;
        if version != VERSION {
            return Err(CodecError::UnsupportedVersion { found: version });
        }
        let algorithm = match reader.u8(Field::Language)? {
            1 => Algorithm::Hashcash,
            2 => Algorithm::Witness,
            found => {
                return Err(CodecError::Discriminant {
                    field: Field::Language,
                    found,
                })
            }
        };
        let challenge_id = reader.hash()?;
        let issuer_key = reader.hash()?;
        let subject_key = reader.hash()?;
        let realm = RealmId(read_u128(&mut reader)?);
        let room = RoomId(read_u128(&mut reader)?);
        let purpose = match reader.u8(Field::Contract)? {
            1 => Purpose::RateLimitRelief,
            2 => Purpose::GameQualification,
            found => {
                return Err(CodecError::Discriminant {
                    field: Field::Contract,
                    found,
                })
            }
        };
        let task_manifest_hash = ManifestHash(reader.hash()?);
        let issued_at = reader.u64(Field::Contract)?;
        let expires_at = reader.u64(Field::Contract)?;
        let contract = WorkContract {
            useful_floor: reader.u64(Field::Contract)?,
            total_ceiling: reader.u64(Field::Contract)?,
            require_passed: reader.bool(Field::Contract)?,
        };
        let mut signature = [0_u8; 64];
        signature[..32].copy_from_slice(&reader.hash()?);
        signature[32..].copy_from_slice(&reader.hash()?);
        reader.finish()?;
        Ok(Self {
            version,
            algorithm,
            challenge_id,
            issuer_key,
            subject_key,
            realm,
            room,
            purpose,
            task_manifest_hash,
            issued_at,
            expires_at,
            contract,
            signature,
        })
    }
    /// The context this challenge was issued under.
    #[must_use]
    pub const fn context(&self) -> ChallengeContext {
        ChallengeContext {
            issuer_key: self.issuer_key,
            subject_key: self.subject_key,
            realm: self.realm,
            room: self.room,
            purpose: self.purpose,
        }
    }
    /// The dedup scope digest over `issuer_key || challenge_id || subject_key`.
    #[must_use]
    pub fn scope_key(&self) -> [u8; 32] {
        let mut body = Vec::with_capacity(96);
        body.extend_from_slice(&self.issuer_key);
        body.extend_from_slice(&self.challenge_id);
        body.extend_from_slice(&self.subject_key);
        digest(DEDUP_DOMAIN, &body)
    }
}

/// Why a challenge could not be issued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IssueError {
    /// Lifetime is zero or above [`MAX_CHALLENGE_LIFETIME`].
    Lifetime,
    /// `issued_at + lifetime` overflows.
    Clock,
}

/// Holds the issuer signing key; entropy and the clock are passed in.
#[derive(Debug)]
pub struct ChallengeIssuer {
    key: SigningKey,
}

impl ChallengeIssuer {
    /// From a 32-byte seed.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(&seed),
        }
    }
    /// The full issuer key.
    #[must_use]
    pub fn verifying_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
    /// Issues a witness-mode challenge with `entropy` as its id.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        &self,
        entropy: [u8; 32],
        now: u64,
        lifetime: u64,
        subject_key: [u8; 32],
        realm: RealmId,
        room: RoomId,
        purpose: Purpose,
        task_manifest_hash: ManifestHash,
        contract: WorkContract,
    ) -> Result<Challenge, IssueError> {
        if lifetime == 0 || lifetime > MAX_CHALLENGE_LIFETIME {
            return Err(IssueError::Lifetime);
        }
        let expires_at = now.checked_add(lifetime).ok_or(IssueError::Clock)?;
        let mut challenge = Challenge {
            version: VERSION,
            algorithm: Algorithm::Witness,
            challenge_id: entropy,
            issuer_key: self.verifying_key(),
            subject_key,
            realm,
            room,
            purpose,
            task_manifest_hash,
            issued_at: now,
            expires_at,
            contract,
            signature: [0; 64],
        };
        challenge.signature = self.key.sign(&challenge.transcript()).to_bytes();
        Ok(challenge)
    }
}

/// Why a challenge or response is refused; one variant per verifier step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitnessError {
    /// Bytes did not decode within their bounds.
    Codec(CodecError),
    /// The algorithm is not witness mode.
    Algorithm,
    /// The issuer key is a known weak Ed25519 point.
    WeakIssuerKey,
    /// The issuer signature does not verify.
    IssuerSignature,
    /// Issuer, subject, realm, room, or purpose differ from what was expected.
    Context,
    /// `now` is before `issued_at`.
    NotYetValid,
    /// `now` is after `expires_at`.
    Expired,
    /// The challenge was issued before this verifier instance started.
    BeforeVerifierStart,
    /// The lifetime is zero, negative, or above the maximum.
    Lifetime,
    /// The challenge names a different manifest than the one supplied.
    Manifest,
    /// The subject key is a known weak Ed25519 point.
    WeakSubjectKey,
    /// The subject signature does not verify.
    SubjectSignature,
    /// Response fields or the receipt do not name this challenge.
    Binding,
    /// The response's top-level hashes or work differ from its receipt.
    Claim,
    /// The candidate programs were refused by the manifest.
    Candidate,
    /// The claimed program hash is not the hash of the assignment.
    Program,
    /// The manifest's fuel exceeds the verifier's allowance.
    Allowance,
    /// The engine refused or failed the replay.
    Run,
    /// The replayed receipt is not bit for bit the claimed receipt.
    Receipt,
    /// Delivered sparks are below the floor.
    Floor,
    /// Total work is above the ceiling.
    Ceiling,
    /// The contract requires every case to pass and one did not.
    NotPassed,
    /// The same response was already consumed.
    Replay,
    /// A different response for the same challenge was already consumed.
    Equivocation,
    /// The one-use window is full.
    Capacity,
}

impl From<CodecError> for WitnessError {
    fn from(error: CodecError) -> Self {
        Self::Codec(error)
    }
}

/// A challenge whose issuer signature, context, and time window are checked.
///
/// Private fields, no `Clone`, no decoder; produced only by [`VerifiedChallenge::verify`].
///
/// ```compile_fail
/// use vhalla_botcaptcha::challenge::{Challenge, VerifiedChallenge};
/// fn forge(challenge: Challenge) -> VerifiedChallenge {
///     VerifiedChallenge { challenge, scope_key: [0; 32] }
/// }
/// ```
///
/// ```compile_fail
/// use vhalla_botcaptcha::challenge::VerifiedChallenge;
/// fn dup(verified: &VerifiedChallenge) -> VerifiedChallenge { verified.clone() }
/// ```
#[derive(Debug)]
pub struct VerifiedChallenge {
    challenge: Challenge,
    scope_key: [u8; 32],
}

impl VerifiedChallenge {
    /// Steps one to five of the verifier: algorithm, issuer key and signature,
    /// context equality, and the time window relative to `now` and the
    /// verifier's `started_at`.
    pub fn verify(
        challenge: Challenge,
        expected: ChallengeContext,
        started_at: u64,
        now: u64,
    ) -> Result<Self, WitnessError> {
        if challenge.algorithm != Algorithm::Witness {
            return Err(WitnessError::Algorithm);
        }
        let issuer = VerifyingKey::from_bytes(&challenge.issuer_key)
            .map_err(|_| WitnessError::IssuerSignature)?;
        if issuer.is_weak() {
            return Err(WitnessError::WeakIssuerKey);
        }
        issuer
            .verify_strict(
                &challenge.transcript(),
                &Signature::from_bytes(&challenge.signature),
            )
            .map_err(|_| WitnessError::IssuerSignature)?;
        if challenge.context() != expected {
            return Err(WitnessError::Context);
        }
        let lifetime = challenge
            .expires_at
            .checked_sub(challenge.issued_at)
            .ok_or(WitnessError::Lifetime)?;
        if lifetime == 0 || lifetime > MAX_CHALLENGE_LIFETIME {
            return Err(WitnessError::Lifetime);
        }
        if now < challenge.issued_at {
            return Err(WitnessError::NotYetValid);
        }
        if now > challenge.expires_at {
            return Err(WitnessError::Expired);
        }
        if challenge.issued_at < started_at {
            return Err(WitnessError::BeforeVerifierStart);
        }
        let scope_key = challenge.scope_key();
        Ok(Self {
            challenge,
            scope_key,
        })
    }
    /// The verified challenge.
    #[must_use]
    pub const fn challenge(&self) -> &Challenge {
        &self.challenge
    }
    /// The dedup scope.
    #[must_use]
    pub const fn scope_key(&self) -> [u8; 32] {
        self.scope_key
    }
    /// The only call site of `RunCapability::mint` in this crate.
    #[allow(clippy::disallowed_methods)]
    #[must_use]
    pub fn run_capability(
        &self,
        program: ProgramHash,
        allowance: WorkAllowance,
        role: RunRole,
    ) -> RunCapability {
        RunCapability::mint(self.challenge.task_manifest_hash, program, allowance, role)
    }
    /// The binding a receipt for this challenge is sealed under.
    #[must_use]
    pub const fn receipt_binding(&self) -> ReceiptBinding {
        ReceiptBinding {
            challenge_id: self.challenge.challenge_id,
            subject_key: self.challenge.subject_key,
        }
    }
}
