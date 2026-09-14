//! Certificate verification for `RoomContext`: the consumer-side checks a
//! node runs before a `Decided`/`Finalized` certificate may enter the
//! durable commit boundary.
//!
//! Mirrors the `room-cert-ack` evidence: non-Nil round, bounded signature
//! count, unique known signers, each commit signature verified over the
//! canonical precommit preimage (`RV1`), and strictly-greater-than
//! two-thirds distinct voting power. The certificate is canonicalized to
//! bounded bytes for the durable bundle.

use std::collections::BTreeSet;

use arc_malachitebft_core_types::{
    CommitCertificate, NilOrVal, Round, ValidatorSet as _, VoteType,
};

use crate::{vote_sign_bytes, RoomContext, RoomValidatorSet, RoomValueId, RoomVote};

/// Bounded certificate size: at most this many commit signatures are
/// considered.
pub const MAX_CERT_SIGNATURES: usize = 64;

/// Errors the certificate consumer reports before any commit is attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertError {
    /// The certificate decided a Nil round.
    NilRound,
    /// More signatures than the bound.
    TooManySignatures,
    /// The same validator signed twice.
    DuplicateSigner,
    /// A signature does not resolve to a validator in the trusted set.
    UnknownSigner,
    /// A signature does not verify over the precommit sign bytes.
    BadSignature,
    /// Distinct voting power did not reach strictly more than 2/3.
    BelowQuorum,
}

/// A verified engine certificate: canonical bytes plus the extracted
/// fields the durable boundary commits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedCertificate {
    /// Canonical certificate bytes, stored verbatim in the bundle.
    pub bytes: Vec<u8>,
    /// Consensus height.
    pub height: u64,
    /// The decided application value commitment — the real 32-byte id.
    pub value_id: RoomValueId,
}

/// Canonicalize a certificate into bounded bytes:
/// `VC2 || height || round || value_id(32) || count || (address ||
/// signature)*`. `VC2` because the value id is now a full 32-byte
/// commitment, not a `u64`.
pub fn canonical_bytes(certificate: &CommitCertificate<RoomContext>) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 8 + 4 + 32 + 2 + certificate.commit_signatures.len() * 84);
    out.extend_from_slice(b"VC2");
    out.extend_from_slice(&certificate.height.as_u64().to_be_bytes());
    out.extend_from_slice(&certificate.round.as_u32().unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(&certificate.value_id.0);
    out.extend_from_slice(&(certificate.commit_signatures.len() as u16).to_be_bytes());
    for sig in &certificate.commit_signatures {
        out.extend_from_slice(&sig.address.into_inner());
        use arc_malachitebft_core_types::SigningScheme;
        out.extend_from_slice(&crate::Ed25519::encode_signature(&sig.signature));
    }
    out
}

/// Verifies a real engine `CommitCertificate` against the trusted
/// validator set.
pub fn verify_commit_certificate(
    certificate: &CommitCertificate<RoomContext>,
    validators: &RoomValidatorSet,
) -> Result<AcceptedCertificate, CertError> {
    if certificate.round == Round::Nil {
        return Err(CertError::NilRound);
    }
    if certificate.commit_signatures.is_empty()
        || certificate.commit_signatures.len() > MAX_CERT_SIGNATURES
    {
        return Err(CertError::TooManySignatures);
    }
    let mut seen = BTreeSet::new();
    let mut signed_power = 0u64;
    for sig in &certificate.commit_signatures {
        let Some(validator) = validators.get_by_address(&sig.address) else {
            return Err(CertError::UnknownSigner);
        };
        if !seen.insert(sig.address) {
            return Err(CertError::DuplicateSigner);
        }
        // Rebuild the exact signed precommit and verify over its own sign
        // bytes — the certificate's signature binds height/round/value/signer.
        let vote = RoomVote::new(
            VoteType::Precommit,
            certificate.height,
            certificate.round,
            NilOrVal::Val(certificate.value_id),
            sig.address,
        );
        if validator
            .public_key
            .verify(&vote_sign_bytes(&vote), &sig.signature)
            .is_err()
        {
            return Err(CertError::BadSignature);
        }
        signed_power += validator.power;
    }
    let total = validators.total_voting_power();
    if signed_power * 3 <= total * 2 {
        return Err(CertError::BelowQuorum);
    }
    Ok(AcceptedCertificate {
        bytes: canonical_bytes(certificate),
        height: certificate.height.as_u64(),
        value_id: certificate.value_id,
    })
}
