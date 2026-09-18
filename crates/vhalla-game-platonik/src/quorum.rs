//! Quorum attestation of a verified settlement: a rooms-consensus commit
//! certificate, checked through the same verify hook `Adapter::absorb` takes,
//! whose decided batch carries a typed settlement commitment. The certificate
//! never replaces reproduction: the settlement is verified first by replay.

use vhalla_rooms_consensus::{Batch, CommitCertificate, GameCommitment, GameCommitmentKind};

use crate::ids::SessionKey;
use crate::record::{GameRecord, RecordKind};
use crate::session::Session;
use crate::settlement::VerifiedSettlement;
use crate::wire::{decode_checkpoint, decode_game_event, decode_session_open, decode_settlement};

/// Why a game record cannot become a rooms-consensus commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitmentError {
    /// The record signature is invalid.
    Record,
    /// This game record kind is not ordered through the commitment lane.
    Kind,
    /// The record's embedded scope differs from the session.
    Scope,
    /// The record body does not decode as its declared kind.
    Codec,
}

/// Converts a signed game record into the fixed rooms-consensus commitment for
/// `session`, deriving scope and epoch from the decoded record rather than from
/// caller-supplied fields.
pub fn commitment(
    session: &Session,
    record: &GameRecord,
) -> Result<GameCommitment, CommitmentError> {
    record.verify().map_err(|_| CommitmentError::Record)?;
    if record.session != session.key() {
        return Err(CommitmentError::Scope);
    }
    let (epoch, kind) = match record.kind {
        RecordKind::SessionOpen => {
            let open = decode_session_open(&record.body).map_err(|_| CommitmentError::Codec)?;
            if open.key() != session.key()
                || open.realm != session.realm()
                || open.room != session.room()
                || open.epoch != session.epoch()
            {
                return Err(CommitmentError::Scope);
            }
            (open.epoch.0, GameCommitmentKind::SessionOpen)
        }
        RecordKind::Event => {
            let event = decode_game_event(&record.body).map_err(|_| CommitmentError::Codec)?;
            if event.session != session.key() || event.epoch != session.epoch() {
                return Err(CommitmentError::Scope);
            }
            (event.epoch.0, GameCommitmentKind::Event)
        }
        RecordKind::Checkpoint => {
            let checkpoint = decode_checkpoint(&record.body).map_err(|_| CommitmentError::Codec)?;
            if checkpoint.session != session.key()
                || checkpoint.ledger.realm != session.realm()
                || checkpoint.ledger.epoch != session.epoch()
            {
                return Err(CommitmentError::Scope);
            }
            (checkpoint.ledger.epoch.0, GameCommitmentKind::Checkpoint)
        }
        RecordKind::Settlement => {
            let settlement = decode_settlement(&record.body).map_err(|_| CommitmentError::Codec)?;
            let (named, epoch) = match settlement {
                crate::wire::Settlement::Result { session, epoch, .. }
                | crate::wire::Settlement::Unresolved { session, epoch, .. } => (session, epoch),
            };
            if named != session.key() || epoch != session.epoch() {
                return Err(CommitmentError::Scope);
            }
            (epoch.0, GameCommitmentKind::Settlement)
        }
        RecordKind::Manifest | RecordKind::ArtifactRequest | RecordKind::ArtifactManifest => {
            return Err(CommitmentError::Kind)
        }
    };
    Ok(GameCommitment {
        realm: session.realm(),
        room: session.room(),
        session: session.key().0,
        epoch,
        kind,
        object: record.object_digest(),
    })
}

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
/// `(certificate bytes, height, value commitment) -> accepted`.
///
/// Order: decode the batch, require the certificate to decide its value id,
/// verify the certificate, locate exactly one settlement commitment under the
/// reproduced settlement's full realm/room/session/epoch scope, and require
/// its object digest to equal the reproduced settlement hash.
pub fn attest<V>(
    settlement: &VerifiedSettlement,
    certificate: &CommitCertificate,
    batch_bytes: &[u8],
    verify: V,
) -> Result<QuorumSettlement, QuorumError>
where
    V: FnOnce(&[u8], u64, &[u8; 32]) -> bool,
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
    let mut matching = batch.games.iter().filter(|commitment| {
        commitment.realm == settlement.realm()
            && commitment.room == settlement.room()
            && commitment.session == settlement.session().0
            && commitment.epoch == settlement.epoch()
            && commitment.kind == GameCommitmentKind::Settlement
    });
    let named = matching.next().ok_or(QuorumError::Unbound)?.object;
    if matching.next().is_some() {
        return Err(QuorumError::Unbound);
    }
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
