//! Quorum attestation of a verified settlement: a rooms-consensus commit
//! certificate, checked through the same verify hook `Adapter::absorb` takes,
//! whose decided batch carries the settlement hash. The certificate never
//! replaces reproduction: the settlement is verified first, by replay, and the
//! certificate only says a quorum decided a batch that names that hash.
//!
//! The certificate decides a `Batch::value_id`, so the binding to the game is
//! transitive: the caller says where inside the decided batch the settlement
//! hash lives. Rooms and social records have no game commitment kind yet, so
//! the locator is the caller's, not this crate's, and a quorum-ordered session
//! (`Authority::Quorum` at open) stays reserved until that record kind exists.

use vhalla_rooms_consensus::{Batch, CommitCertificate};

use crate::ids::SessionKey;
use crate::settlement::VerifiedSettlement;

/// Why a certificate does not attest a settlement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum QuorumError {
    /// The batch bytes do not decode.
    Batch,
    /// The certificate decides a different value than the batch.
    ValueMismatch,
    /// The verify hook refused the certificate.
    Certificate,
    /// The decided batch carries no settlement hash.
    Unbound,
    /// The batch names a different settlement.
    Mismatch,
}

/// Evidence that a quorum decided a batch naming a settlement this receiver
/// reproduced.
///
/// ```compile_fail
/// use vhalla_game_platonik::quorum::QuorumSettlement;
/// fn dup(q: &QuorumSettlement) -> QuorumSettlement { q.clone() }
/// ```
#[derive(Debug)]
pub struct QuorumSettlement {
    session: SessionKey,
    epoch: u64,
    hash: [u8; 32],
    height: u64,
    value: [u8; 32],
}

impl QuorumSettlement {
    /// Session.
    #[must_use]
    pub const fn session(&self) -> SessionKey {
        self.session
    }
    /// Session epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
    /// The settlement hash.
    #[must_use]
    pub const fn hash(&self) -> [u8; 32] {
        self.hash
    }
    /// The consensus height of the decision. It is the batch's height, not
    /// the session's checkpoint height.
    #[must_use]
    pub const fn height(&self) -> u64 {
        self.height
    }
    /// The decided value id.
    #[must_use]
    pub const fn value(&self) -> [u8; 32] {
        self.value
    }
}

/// Attests `settlement` under `certificate` deciding the batch `batch_bytes`
/// (journal bundle field 3).
///
/// `verify` is the certificate check, with the `Adapter::absorb` signature:
/// `(certificate bytes, height, value commitment) -> accepted`. `locate` reads
/// the settlement hash the decided batch carries, or `None`.
///
/// Order: decode the batch, require the certificate to decide its value id,
/// verify the certificate, locate the hash, and require it to equal the
/// reproduced settlement's hash.
pub fn attest<V, L>(
    settlement: &VerifiedSettlement,
    certificate: &CommitCertificate,
    batch_bytes: &[u8],
    verify: V,
    locate: L,
) -> Result<QuorumSettlement, QuorumError>
where
    V: FnOnce(&[u8], u64, &[u8; 32]) -> bool,
    L: FnOnce(&Batch) -> Option<[u8; 32]>,
{
    let batch = Batch::decode(batch_bytes).map_err(|_| QuorumError::Batch)?;
    if batch.value_id() != certificate.value_commitment {
        return Err(QuorumError::ValueMismatch);
    }
    if !verify(
        &certificate.bytes,
        certificate.height,
        &certificate.value_commitment,
    ) {
        return Err(QuorumError::Certificate);
    }
    let named = locate(&batch).ok_or(QuorumError::Unbound)?;
    if named != settlement.hash() {
        return Err(QuorumError::Mismatch);
    }
    Ok(QuorumSettlement {
        session: settlement.session(),
        epoch: settlement.epoch(),
        hash: settlement.hash(),
        height: certificate.height,
        value: certificate.value_commitment,
    })
}

/// A locator for a batch whose `records` carry the bare 32-byte settlement
/// hash as one entry: the stand-in binding until a rooms record kind exists.
/// Exactly one such entry must be present.
#[must_use]
pub fn bare_hash_record(batch: &Batch) -> Option<[u8; 32]> {
    let mut found: Vec<[u8; 32]> = batch
        .records
        .iter()
        .filter_map(|record| <[u8; 32]>::try_from(record.as_slice()).ok())
        .collect();
    match (found.len(), found.pop()) {
        (1, Some(hash)) => Some(hash),
        _ => None,
    }
}
