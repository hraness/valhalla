//! Dependency-free envelope and policy model for zero-knowledge profiles.
//!
//! The prototype intentionally does not verify cryptography. It checks the
//! shape, binding, and lifetime of evidence, then requires a separate
//! authority decision before granting a capability.

/// A 32-byte content digest or public-key identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Digest(pub [u8; 32]);

/// Candidate proving systems. These are labels, not implementations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofSystem {
    /// Transparent proof (for example, a STARK-style system).
    Transparent,
    /// Succinct proof with a setup/prover ecosystem (for example, a SNARK).
    Snark,
    /// Incrementally verifiable computation / recursive proof family.
    Nova,
}

/// Public statement supplied to a verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Statement {
    /// Schema identifier and version.
    pub schema: String,
    /// Subject to which the claim applies.
    pub subject: Digest,
    /// Public claim inputs; private witness material must not appear here.
    pub public_inputs: Vec<u8>,
}

/// Opaque proof envelope. The cryptographic verifier is intentionally injected
/// by a later implementation so this crate has no crypto dependencies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofEnvelope {
    /// Proof-system family.
    pub system: ProofSystem,
    /// Digest of the canonical statement.
    pub statement: Digest,
    /// Issuer or proving service identifier.
    pub issuer: Digest,
    /// Proof bytes, uninterpreted here.
    pub proof: Vec<u8>,
    /// Expiration in caller-defined time units.
    pub expires_at: u64,
}

/// Authority is deliberately separate from proof evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityDecision {
    /// Subject for which the authority layer made this decision.
    pub subject: Digest,
    /// Whether an external policy/trust layer authorized this subject.
    pub authorized: bool,
    /// Channel or realm for which authorization applies.
    pub scope: Digest,
    /// Expiration of the authority grant.
    pub expires_at: u64,
}

/// Result of structural evidence checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Evidence {
    /// Envelope is structurally bound but cryptography has not been checked.
    WellFormed,
    /// Proof is bound to a different statement.
    WrongStatement,
    /// Proof has expired.
    Expired,
    /// Empty or oversized proof bytes were rejected.
    InvalidShape,
}

/// Final policy outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    /// Evidence may be shown or queued, but grants no authority.
    EvidenceOnly,
    /// A separate authority layer granted the requested scope.
    Authorized,
}

/// Check envelope binding and lifetime without pretending to verify a proof.
#[must_use]
pub fn inspect(
    statement: &Statement,
    statement_digest: Digest,
    proof: &ProofEnvelope,
    now: u64,
) -> Evidence {
    if proof.proof.is_empty() || proof.proof.len() > 1 << 20 {
        return Evidence::InvalidShape;
    }
    if proof.statement != statement_digest {
        return Evidence::WrongStatement;
    }
    if now > proof.expires_at {
        return Evidence::Expired;
    }
    let _ = statement;
    Evidence::WellFormed
}

/// Apply policy after evidence inspection and an independent authority result.
#[must_use]
pub fn decide(
    evidence: Evidence,
    subject: Digest,
    scope: Digest,
    now: u64,
    authority: AuthorityDecision,
) -> Decision {
    if evidence != Evidence::WellFormed
        || !authority.authorized
        || authority.subject != subject
        || authority.scope != scope
        || authority.expires_at < now
    {
        return Decision::EvidenceOnly;
    }
    Decision::Authorized
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(n: u8) -> Digest {
        Digest([n; 32])
    }

    fn statement() -> Statement {
        Statement {
            schema: "agent-irc/profile/v1".into(),
            subject: digest(1),
            public_inputs: b"capability:read".to_vec(),
        }
    }

    #[test]
    fn proof_is_evidence_until_authority_grants_scope() {
        let statement = statement();
        let proof = ProofEnvelope {
            system: ProofSystem::Transparent,
            statement: digest(9),
            issuer: digest(2),
            proof: vec![1, 2, 3],
            expires_at: 10,
        };
        assert_eq!(
            inspect(&statement, digest(9), &proof, 5),
            Evidence::WellFormed
        );
        let no_authority = AuthorityDecision {
            subject: statement.subject,
            authorized: false,
            scope: digest(7),
            expires_at: 10,
        };
        assert_eq!(
            decide(
                Evidence::WellFormed,
                statement.subject,
                digest(7),
                5,
                no_authority
            ),
            Decision::EvidenceOnly
        );
        let authority = AuthorityDecision {
            subject: statement.subject,
            authorized: true,
            scope: digest(7),
            expires_at: 10,
        };
        assert_eq!(
            decide(
                Evidence::WellFormed,
                statement.subject,
                digest(7),
                5,
                authority
            ),
            Decision::Authorized
        );
    }

    #[test]
    fn expired_or_wrongly_bound_proofs_cannot_authorize() {
        let statement = statement();
        let proof = ProofEnvelope {
            system: ProofSystem::Snark,
            statement: digest(3),
            issuer: digest(2),
            proof: vec![1],
            expires_at: 4,
        };
        assert_eq!(
            inspect(&statement, digest(9), &proof, 5),
            Evidence::WrongStatement
        );
        let authority = AuthorityDecision {
            subject: statement.subject,
            authorized: true,
            scope: digest(7),
            expires_at: 4,
        };
        assert_eq!(
            decide(
                Evidence::Expired,
                statement.subject,
                digest(7),
                5,
                authority
            ),
            Decision::EvidenceOnly
        );
    }
}
