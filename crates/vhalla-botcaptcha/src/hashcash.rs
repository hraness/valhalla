//! Hashcash mode: the work digest, a bounded solver, and the signed response.

use alloc::vec::Vec;

use ed25519_dalek::{Signer, SigningKey};
use vhalla_witness::codec::{CodecError, Field, Reader, Writer};
use vhalla_witness::hash::digest;

use crate::challenge::{Algorithm, VerifiedChallenge};
use crate::{transcript, HASHCASH_RESPONSE_DOMAIN, VERSION, WORK_DOMAIN};

/// `SHA-256(WORK_DOMAIN || len || challenge_hash || subject_key || nonce)`.
#[must_use]
pub fn work_digest(challenge_hash: [u8; 32], subject_key: [u8; 32], nonce: u64) -> [u8; 32] {
    let mut body = Vec::with_capacity(72);
    body.extend_from_slice(&challenge_hash);
    body.extend_from_slice(&subject_key);
    body.extend_from_slice(&nonce.to_be_bytes());
    digest(WORK_DOMAIN, &body)
}

/// Leading zero bits of a digest.
#[must_use]
pub fn leading_zero_bits(bytes: &[u8; 32]) -> u32 {
    let mut count = 0;
    for byte in bytes {
        if *byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

/// Why no nonce was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolveError {
    /// The challenge is not a Hashcash challenge.
    Algorithm,
    /// No nonce below `max_attempts` met the target.
    Exhausted,
}

/// Searches nonces `0..max_attempts` for one that meets the challenge target.
/// Bounded so a caller never spins without a declared budget.
pub fn solve(challenge: &VerifiedChallenge, max_attempts: u64) -> Result<u64, SolveError> {
    let challenge = challenge.challenge();
    let difficulty = challenge.difficulty().ok_or(SolveError::Algorithm)?;
    let hash = challenge.hash();
    let target = u32::from(difficulty.bits());
    (0..max_attempts)
        .find(|nonce| {
            leading_zero_bits(&work_digest(hash, challenge.subject_key, *nonce)) >= target
        })
        .ok_or(SolveError::Exhausted)
}

/// Fixed encoded width of a Hashcash response.
pub const HASHCASH_RESPONSE_BYTES: usize = 1 + 32 + 32 + 32 + 8 + 64;

/// A signed Hashcash response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HashcashResponse {
    /// Encoding version.
    pub version: u8,
    /// The challenge answered.
    pub challenge_id: [u8; 32],
    /// `Challenge::hash()` of the exact challenge answered.
    pub challenge_hash: [u8; 32],
    /// The subject's full key.
    pub subject_key: [u8; 32],
    /// The nonce that met the target.
    pub nonce: u64,
    /// Subject signature over the transcript.
    pub signature: [u8; 64],
}

fn put_body(writer: &mut Writer, response: &HashcashResponse) {
    writer.u8(response.version);
    writer.bytes(&response.challenge_id);
    writer.bytes(&response.challenge_hash);
    writer.bytes(&response.subject_key);
    writer.u64(response.nonce);
}

impl HashcashResponse {
    /// The signed bytes: every field except the signature.
    #[must_use]
    pub fn body(&self) -> Vec<u8> {
        let mut writer = Writer::with_capacity(HASHCASH_RESPONSE_BYTES - 64);
        put_body(&mut writer, self);
        writer.finish()
    }
    /// The message the subject signs.
    #[must_use]
    pub fn transcript(&self) -> Vec<u8> {
        transcript(HASHCASH_RESPONSE_DOMAIN, &self.body())
    }
    /// The digest that identifies this response in the one-use window.
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        digest(HASHCASH_RESPONSE_DOMAIN, &self.body())
    }
    /// Canonical bytes: body then signature.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::with_capacity(HASHCASH_RESPONSE_BYTES);
        put_body(&mut writer, self);
        writer.bytes(&self.signature);
        writer.finish()
    }
    /// Decodes exactly [`HASHCASH_RESPONSE_BYTES`].
    pub fn decode(raw: &[u8]) -> Result<Self, CodecError> {
        let mut reader = Reader::bounded(raw, HASHCASH_RESPONSE_BYTES)?;
        let version = reader.u8(Field::Version)?;
        if version != VERSION {
            return Err(CodecError::UnsupportedVersion { found: version });
        }
        let challenge_id = reader.hash()?;
        let challenge_hash = reader.hash()?;
        let subject_key = reader.hash()?;
        let nonce = reader.u64(Field::Value)?;
        let mut signature = [0_u8; 64];
        signature[..32].copy_from_slice(&reader.hash()?);
        signature[32..].copy_from_slice(&reader.hash()?);
        reader.finish()?;
        Ok(Self {
            version,
            challenge_id,
            challenge_hash,
            subject_key,
            nonce,
            signature,
        })
    }
}

/// Why the subject could not respond.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RespondError {
    /// The signing key is not the challenge's subject.
    Subject,
    /// The challenge is not a Hashcash challenge.
    Algorithm,
}

/// Signs a response for a nonce the caller found with [`solve`].
pub fn respond_hashcash(
    challenge: &VerifiedChallenge,
    nonce: u64,
    key: &SigningKey,
) -> Result<HashcashResponse, RespondError> {
    let subject_key = key.verifying_key().to_bytes();
    let inner = challenge.challenge();
    if subject_key != inner.subject_key {
        return Err(RespondError::Subject);
    }
    if inner.algorithm != Algorithm::Hashcash {
        return Err(RespondError::Algorithm);
    }
    let mut response = HashcashResponse {
        version: VERSION,
        challenge_id: inner.challenge_id,
        challenge_hash: inner.hash(),
        subject_key,
        nonce,
        signature: [0; 64],
    };
    response.signature = key.sign(&response.transcript()).to_bytes();
    Ok(response)
}
