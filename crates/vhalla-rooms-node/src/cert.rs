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
    CommitCertificate, ExtendedCommitCertificate, ExtendedCommitSignature, NilOrVal, Round,
    SigningScheme as _, ValidatorSet as _, VoteType,
};

use crate::{
    vote_sign_bytes, Address, Ed25519, Height, RoomContext, RoomValidatorSet, RoomValueId, RoomVote,
};

/// Bounded certificate size: at most this many commit signatures are
/// considered.
pub const MAX_CERT_SIGNATURES: usize = 64;

/// Errors the certificate consumer reports before any commit is attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertError {
    /// The trusted validator set has invalid identities, powers or bounds.
    InvalidValidatorSet,
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
    validators
        .validate()
        .map_err(|_| CertError::InvalidValidatorSet)?;
    if certificate.round == Round::Nil {
        return Err(CertError::NilRound);
    }
    if certificate.commit_signatures.is_empty()
        || certificate.commit_signatures.len() > MAX_CERT_SIGNATURES
    {
        return Err(CertError::TooManySignatures);
    }
    let mut seen = BTreeSet::new();
    let mut signed_power = 0u128;
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
        signed_power += u128::from(validator.power);
    }
    let total = u128::from(validators.total_voting_power());
    if signed_power * 3 <= total * 2 {
        return Err(CertError::BelowQuorum);
    }
    Ok(AcceptedCertificate {
        bytes: canonical_bytes(certificate),
        height: certificate.height.as_u64(),
        value_id: certificate.value_id,
    })
}

/// Verifies a canonical `VC2` certificate — the bounded bytes a journal
/// bundle carries — against the trusted validator set for `height`.
/// Decodes strictly (exact length, no trailing data), binds the embedded
/// height and value id to the expected ones, verifies every signature
/// over the rebuilt precommit preimage, and requires strictly more than
/// two-thirds distinct voting power. This is the replica data-plane
/// check: a consumer that never saw the engine run can still hold the
/// committed bundle to the same standard a voter did.
pub fn verify_canonical_certificate(
    raw: &[u8],
    height: u64,
    value_id: &RoomValueId,
    validators: &RoomValidatorSet,
) -> bool {
    if validators.validate().is_err() {
        return false;
    }
    let Some((count, mut rest)) = decode_head(raw, height, value_id) else {
        return false;
    };
    if count == 0 || count > MAX_CERT_SIGNATURES || rest.len() != count * 84 {
        return false;
    }
    let mut seen = BTreeSet::new();
    let mut signed_power = 0u128;
    for _ in 0..count {
        let address = Address::new(rest[..20].try_into().unwrap());
        let Ok(signature) = Ed25519::decode_signature(&rest[20..84]) else {
            return false;
        };
        rest = &rest[84..];
        let Some(validator) = validators.get_by_address(&address) else {
            return false;
        };
        if !seen.insert(address) {
            return false;
        }
        let vote = RoomVote::new(
            VoteType::Precommit,
            Height::new(height),
            round_of(raw),
            NilOrVal::Val(*value_id),
            address,
        );
        if validator
            .public_key
            .verify(&vote_sign_bytes(&vote), &signature)
            .is_err()
        {
            return false;
        }
        signed_power += u128::from(validator.power);
    }
    signed_power * 3 > u128::from(validators.total_voting_power()) * 2
}

/// Decodes the fixed `VC2` head: magic, height, round, value id, count —
/// checking height and value id against the expected commitment. Returns
/// the signature count and the remaining `(address || signature)` span.
fn decode_head<'a>(
    raw: &'a [u8],
    height: u64,
    value_id: &RoomValueId,
) -> Option<(usize, &'a [u8])> {
    if raw.len() < 49 || raw.get(..3) != Some(b"VC2") {
        return None;
    }
    if u64::from_be_bytes(raw[3..11].try_into().unwrap()) != height {
        return None;
    }
    if raw[11..15] == u32::MAX.to_be_bytes() {
        return None; // Nil round is never a commit certificate.
    }
    if raw[15..47] != value_id.0 {
        return None;
    }
    let count = u16::from_be_bytes(raw[47..49].try_into().unwrap()) as usize;
    Some((count, &raw[49..]))
}

/// The round field inside a `VC2` head, already known to be non-Nil.
fn round_of(raw: &[u8]) -> Round {
    Round::Some(u32::from_be_bytes(raw[11..15].try_into().unwrap()))
}

/// Rebuilds an `ExtendedCommitCertificate` from the canonical `VC2` bytes
/// a journal bundle stores — the shape `GetDecidedValues` answers carry.
/// The canonical form records no vote extensions, so every signature's
/// `extension` is `None`. Strict length checks only; signature VALIDITY
/// is the bundle's already-established property, not re-verified here.
pub fn ext_certificate_from_canonical(
    raw: &[u8],
) -> Option<ExtendedCommitCertificate<RoomContext>> {
    if raw.len() < 49 || raw.get(..3) != Some(b"VC2") {
        return None;
    }
    let height = u64::from_be_bytes(raw[3..11].try_into().unwrap());
    let round = u32::from_be_bytes(raw[11..15].try_into().unwrap());
    if round == u32::MAX {
        return None; // Nil round is never a commit certificate.
    }
    let value_id = RoomValueId(raw[15..47].try_into().unwrap());
    let count = u16::from_be_bytes(raw[47..49].try_into().unwrap()) as usize;
    let sigs = &raw[49..];
    if count == 0 || count > MAX_CERT_SIGNATURES || sigs.len() != count * 84 {
        return None;
    }
    let mut commit_signatures = Vec::with_capacity(count);
    for chunk in sigs.as_chunks::<84>().0 {
        let address = Address::new(chunk[..20].try_into().unwrap());
        let signature = Ed25519::decode_signature(&chunk[20..84]).ok()?;
        commit_signatures.push(ExtendedCommitSignature::new(address, signature, None));
    }
    Some(ExtendedCommitCertificate {
        height: Height::new(height),
        round: Round::Some(round),
        value_id,
        commit_signatures,
    })
}
