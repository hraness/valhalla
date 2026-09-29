//! Disposable Botcaptcha reference protocol.
//!
//! This proves possession of a key and expenditure of bounded hash work for a
//! fresh, scoped challenge. It does **not** prove that the signer is an AI
//! agent, a human, or a trusted execution environment. Passing a challenge is
//! an admission/rate-limit signal only; it must never mint host capabilities.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

const CHALLENGE_DOMAIN: &[u8] = b"vhalla/valhalla/botcaptcha/challenge/v1\0";
const WORK_DOMAIN: &[u8] = b"vhalla/valhalla/botcaptcha/pow/v1\0";

/// Maximum accepted challenge lifetime, in seconds.
pub const MAX_LIFETIME: u64 = 15 * 60;

/// A verifier-selected scope. Work is bound to this exact context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Scope {
    /// Realm namespace.
    pub realm: u128,
    /// Room namespace.
    pub room: u128,
    /// Local purpose code (for example, admission or posting).
    pub purpose: u8,
}

/// A signed, fresh challenge issued to one public key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Challenge {
    /// Cryptographically random one-use challenge identifier.
    pub id: [u8; 32],
    /// Issuer public key bytes.
    pub issuer: [u8; 32],
    /// Subject public key bytes; the proof is not transferable to another key.
    pub subject: [u8; 32],
    /// Realm/room/purpose binding.
    pub scope: Scope,
    /// Issuance time in verifier clock seconds.
    pub issued_at: u64,
    /// Expiry time in verifier clock seconds.
    pub expires_at: u64,
    /// Required leading zero bits in the work digest.
    pub difficulty: u8,
    /// Issuer signature over every field above except this signature.
    pub signature: [u8; 64],
}

/// A proof of work for one challenge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkProof {
    /// Challenge identifier being answered.
    pub challenge_id: [u8; 32],
    /// Subject key that performed the work.
    pub subject: [u8; 32],
    /// Search nonce.
    pub nonce: u64,
}

/// Why challenge verification failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifyError {
    /// Ed25519 issuer signature did not verify.
    InvalidIssuerSignature,
    /// Issuer public key bytes are not a valid Ed25519 key.
    InvalidIssuerKey,
    /// The challenge is malformed or exceeds the protocol lifetime.
    InvalidLifetime,
    /// The verifier clock is before issuance.
    NotYetValid,
    /// The challenge has expired.
    Expired,
    /// The proof is for another public key.
    WrongSubject,
    /// The challenge is outside the expected realm/room/purpose.
    WrongScope,
    /// The proof references another challenge.
    WrongChallenge,
    /// The digest does not meet the declared target.
    InsufficientWork,
    /// This challenge was already consumed.
    Replay,
}

/// Errors encountered while searching for a nonce.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SolveError {
    /// The requested challenge cannot be valid.
    InvalidChallenge,
    /// The bounded search exhausted its nonce space.
    Exhausted,
}

impl Challenge {
    /// Create and sign a challenge. The caller must supply a fresh random ID.
    pub fn sign(
        id: [u8; 32],
        subject: [u8; 32],
        scope: Scope,
        issued_at: u64,
        expires_at: u64,
        difficulty: u8,
        issuer: &SigningKey,
    ) -> Result<Self, VerifyError> {
        if expires_at < issued_at || expires_at - issued_at > MAX_LIFETIME {
            return Err(VerifyError::InvalidLifetime);
        }
        let issuer_bytes = issuer.verifying_key().to_bytes();
        let unsigned = unsigned_challenge(
            id,
            issuer_bytes,
            subject,
            scope,
            issued_at,
            expires_at,
            difficulty,
        );
        let signature = issuer.sign(&unsigned).to_bytes();
        Ok(Self {
            id,
            issuer: issuer_bytes,
            subject,
            scope,
            issued_at,
            expires_at,
            difficulty,
            signature,
        })
    }

    /// Verify issuer signature and freshness/context, without consuming it.
    pub fn verify(
        &self,
        now: u64,
        expected_subject: [u8; 32],
        expected_scope: Scope,
    ) -> Result<(), VerifyError> {
        if self.expires_at < self.issued_at || self.expires_at - self.issued_at > MAX_LIFETIME {
            return Err(VerifyError::InvalidLifetime);
        }
        if now < self.issued_at {
            return Err(VerifyError::NotYetValid);
        }
        if now > self.expires_at {
            return Err(VerifyError::Expired);
        }
        if self.subject != expected_subject {
            return Err(VerifyError::WrongSubject);
        }
        if self.scope != expected_scope {
            return Err(VerifyError::WrongScope);
        }
        let key =
            VerifyingKey::from_bytes(&self.issuer).map_err(|_| VerifyError::InvalidIssuerKey)?;
        let unsigned = unsigned_challenge(
            self.id,
            self.issuer,
            self.subject,
            self.scope,
            self.issued_at,
            self.expires_at,
            self.difficulty,
        );
        key.verify(&unsigned, &Signature::from_bytes(&self.signature))
            .map_err(|_| VerifyError::InvalidIssuerSignature)
    }

    /// Verify a proof's challenge binding and hash target.
    pub fn verify_work(&self, proof: WorkProof) -> Result<[u8; 32], VerifyError> {
        if proof.challenge_id != self.id {
            return Err(VerifyError::WrongChallenge);
        }
        if proof.subject != self.subject {
            return Err(VerifyError::WrongSubject);
        }
        let digest = work_digest(self, proof.nonce);
        if !has_leading_zero_bits(&digest, self.difficulty) {
            return Err(VerifyError::InsufficientWork);
        }
        Ok(digest)
    }

    /// Search nonces from zero, bounded by `max_attempts` for a deterministic demo.
    pub fn solve(&self, max_attempts: u64) -> Result<WorkProof, SolveError> {
        if self.expires_at < self.issued_at {
            return Err(SolveError::InvalidChallenge);
        }
        for nonce in 0..max_attempts {
            let proof = WorkProof {
                challenge_id: self.id,
                subject: self.subject,
                nonce,
            };
            if self.verify_work(proof).is_ok() {
                return Ok(proof);
            }
        }
        Err(SolveError::Exhausted)
    }
}

/// One-use challenge ledger. It is deliberately verifier-local state.
#[derive(Default, Debug)]
pub struct ReplayGuard {
    consumed: HashSet<[u8; 32]>,
}

impl ReplayGuard {
    /// Verify and consume one challenge exactly once.
    pub fn accept(
        &mut self,
        challenge: &Challenge,
        proof: WorkProof,
        now: u64,
        expected_subject: [u8; 32],
        expected_scope: Scope,
    ) -> Result<[u8; 32], VerifyError> {
        challenge.verify(now, expected_subject, expected_scope)?;
        if self.consumed.contains(&challenge.id) {
            return Err(VerifyError::Replay);
        }
        let digest = challenge.verify_work(proof)?;
        self.consumed.insert(challenge.id);
        Ok(digest)
    }
}

fn unsigned_challenge(
    id: [u8; 32],
    issuer: [u8; 32],
    subject: [u8; 32],
    scope: Scope,
    issued_at: u64,
    expires_at: u64,
    difficulty: u8,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 32 + 32 + 16 + 16 + 8 + 8 + 1);
    out.extend_from_slice(CHALLENGE_DOMAIN);
    out.extend_from_slice(&id);
    out.extend_from_slice(&issuer);
    out.extend_from_slice(&subject);
    out.extend_from_slice(&scope.realm.to_be_bytes());
    out.extend_from_slice(&scope.room.to_be_bytes());
    out.push(scope.purpose);
    out.extend_from_slice(&issued_at.to_be_bytes());
    out.extend_from_slice(&expires_at.to_be_bytes());
    out.push(difficulty);
    out
}

fn work_digest(challenge: &Challenge, nonce: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(WORK_DOMAIN);
    hasher.update(challenge.id);
    hasher.update(challenge.issuer);
    hasher.update(challenge.subject);
    hasher.update(challenge.scope.realm.to_be_bytes());
    hasher.update(challenge.scope.room.to_be_bytes());
    hasher.update([challenge.scope.purpose]);
    hasher.update(challenge.issued_at.to_be_bytes());
    hasher.update(challenge.expires_at.to_be_bytes());
    hasher.update([challenge.difficulty]);
    hasher.update(nonce.to_be_bytes());
    hasher.finalize().into()
}

fn has_leading_zero_bits(digest: &[u8; 32], bits: u8) -> bool {
    let whole = usize::from(bits / 8);
    let remainder = bits % 8;
    if digest[..whole].iter().any(|byte| *byte != 0) {
        return false;
    }
    remainder == 0 || digest[whole] >> (8 - remainder) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn keys() -> (SigningKey, SigningKey) {
        (
            SigningKey::from_bytes(&[7; 32]),
            SigningKey::from_bytes(&[9; 32]),
        )
    }

    fn challenge(difficulty: u8) -> (Challenge, [u8; 32], Scope) {
        let (issuer, subject) = keys();
        let subject_bytes = subject.verifying_key().to_bytes();
        let scope = Scope {
            realm: 1,
            room: 2,
            purpose: 3,
        };
        (
            Challenge::sign([4; 32], subject_bytes, scope, 100, 200, difficulty, &issuer).unwrap(),
            subject_bytes,
            scope,
        )
    }

    #[test]
    fn signed_challenge_solves_and_is_one_use() {
        let (challenge, subject, scope) = challenge(8);
        let proof = challenge.solve(2_000).unwrap();
        let mut guard = ReplayGuard::default();
        assert!(guard.accept(&challenge, proof, 150, subject, scope).is_ok());
        assert_eq!(
            guard.accept(&challenge, proof, 150, subject, scope),
            Err(VerifyError::Replay)
        );
    }

    #[test]
    fn context_expiry_and_tamper_are_rejected() {
        let (mut challenge, subject, scope) = challenge(4);
        assert_eq!(
            challenge.verify(99, subject, scope),
            Err(VerifyError::NotYetValid)
        );
        assert_eq!(
            challenge.verify(201, subject, scope),
            Err(VerifyError::Expired)
        );
        assert_eq!(
            challenge.verify(150, subject, Scope { room: 9, ..scope }),
            Err(VerifyError::WrongScope)
        );
        challenge.signature[0] ^= 1;
        assert_eq!(
            challenge.verify(150, subject, scope),
            Err(VerifyError::InvalidIssuerSignature)
        );
    }

    #[test]
    fn proof_cannot_transfer_between_keys_or_challenges() {
        let (challenge, subject, _) = challenge(1);
        let proof = challenge.solve(100).unwrap();
        let mut wrong = proof;
        wrong.subject = [0; 32];
        assert_eq!(challenge.verify_work(wrong), Err(VerifyError::WrongSubject));
        wrong = proof;
        wrong.challenge_id = [0; 32];
        assert_eq!(
            challenge.verify_work(wrong),
            Err(VerifyError::WrongChallenge)
        );
        assert_eq!(subject, challenge.subject);
    }

    proptest! {
        #[test]
        fn signature_binds_every_challenge_id(id in any::<[u8; 32]>()) {
            let (issuer, subject) = keys();
            let scope = Scope { realm: 8, room: 9, purpose: 1 };
            let challenge = Challenge::sign(id, subject.verifying_key().to_bytes(), scope, 1, 2, 0, &issuer).unwrap();
            prop_assert!(challenge.verify(1, subject.verifying_key().to_bytes(), scope).is_ok());
            let mut changed = challenge.clone();
            changed.id[0] ^= 1;
            prop_assert_eq!(changed.verify(1, subject.verifying_key().to_bytes(), scope), Err(VerifyError::InvalidIssuerSignature));
        }
    }
}
