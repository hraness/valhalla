//! Quorum attestation of a verified settlement: a rooms-consensus commit
//! certificate, checked through the same verify hook `Adapter::absorb` takes,
//! whose decided batch carries a typed settlement commitment. The certificate
//! never replaces reproduction: the settlement is verified first by replay.

use vhalla_core::RealmId;
use vhalla_rooms_consensus::{Batch, CommitCertificate, GameCommitment, GameCommitmentKind};

use crate::engine::GameEngine;
use crate::ids::SessionKey;
use crate::manifest::GameManifest;
use crate::receiver::{Receiver, ReceiverError, VerifiedCheckpoint};
use crate::record::{GameRecord, RecordKind};
use crate::session::{quorum_actor, OpenError, ProvenCommitment, Session};
use crate::settlement::VerifiedSettlement;
use crate::wire::{
    decode_checkpoint, decode_game_event, decode_session_open, decode_settlement, Authority,
    SessionOpen,
};

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
/// caller-supplied fields. Under `Authority::Quorum` a record authored by the
/// quorum actor carries the zero signature and no verification is attempted —
/// the decided commitment is its authority.
pub fn commitment(
    session: &Session,
    record: &GameRecord,
) -> Result<GameCommitment, CommitmentError> {
    let actor_authored = matches!(session.opening().authority, Authority::Quorum { .. })
        && record.signer == session.host();
    if actor_authored {
        if record.signature != [0; 64] {
            return Err(CommitmentError::Record);
        }
    } else {
        record.verify().map_err(|_| CommitmentError::Record)?;
    }
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

/// Why a quorum-decided opening could not start a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuorumOpenError {
    /// The certificate proof did not hold.
    Proof(QuorumError),
    /// The opening or manifest was refused.
    Open(OpenError),
}

impl From<OpenError> for QuorumOpenError {
    fn from(error: OpenError) -> Self {
        Self::Open(error)
    }
}

/// The commitment a `SessionOpen` must carry inside a decided batch.
#[must_use]
pub fn open_commitment(open: &SessionOpen) -> GameCommitment {
    GameCommitment {
        realm: open.realm,
        room: open.room,
        session: open.key().0,
        epoch: 0,
        kind: GameCommitmentKind::SessionOpen,
        object: open.key().0,
    }
}

fn check<V>(certificate: &CommitCertificate, batch: &Batch, verify: V) -> Result<(), QuorumError>
where
    V: FnOnce(&[u8], u64, &[u8; 32]) -> bool,
{
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
    Ok(())
}

/// Opens a session whose authority is a consensus quorum: the opening itself
/// must be decided, proven by a certificate over a batch carrying the exact
/// `SessionOpen` commitment at `position` in its game lane. The session's
/// authority actor is the unforgeable `quorum_actor(scheme)`; every later
/// admission consumes `prove` output instead of a host signature.
pub fn open<V>(
    manifest: GameManifest,
    open: SessionOpen,
    realm: RealmId,
    certificate: &CommitCertificate,
    batch: &Batch,
    position: usize,
    verify: V,
) -> Result<Session, QuorumOpenError>
where
    V: FnOnce(&[u8], u64, &[u8; 32]) -> bool,
{
    let Authority::Quorum { scheme } = open.authority else {
        return Err(QuorumOpenError::Open(OpenError::Authority));
    };
    check(certificate, batch, verify).map_err(QuorumOpenError::Proof)?;
    let expected = open_commitment(&open);
    match batch.games.get(position) {
        Some(found) if *found == expected => {}
        _ => return Err(QuorumOpenError::Proof(QuorumError::Unbound)),
    }
    Session::open_with_actor(manifest, open, realm, quorum_actor(&scheme))
        .map_err(QuorumOpenError::Open)
}

/// Proves that a quorum decided this record's commitment at `position` in the
/// batch the certificate decides. The certificate check is the caller's hook,
/// the same signature `Adapter::absorb` takes. On success the consumed
/// `ProvenCommitment` admits the record exactly once through `admit_proven`
/// or `settle_proven`.
pub fn prove<V>(
    session: &Session,
    record: &GameRecord,
    certificate: &CommitCertificate,
    batch: &Batch,
    position: usize,
    verify: V,
) -> Result<ProvenCommitment, QuorumError>
where
    V: FnOnce(&[u8], u64, &[u8; 32]) -> bool,
{
    check(certificate, batch, verify)?;
    let expected = commitment(session, record).map_err(|_| QuorumError::Unbound)?;
    match batch.games.get(position) {
        Some(found) if *found == expected => {}
        _ => return Err(QuorumError::Unbound),
    }
    Ok(ProvenCommitment::new(
        session.key(),
        expected.epoch,
        record.kind,
        expected.object,
        certificate.height,
        position,
    ))
}

/// Why a quorum-ordered admission was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmitError {
    /// The certificate proof did not hold.
    Proof(QuorumError),
    /// The session or receiver refused the record.
    Receiver(ReceiverError),
}

impl<E: GameEngine> Receiver<E> {
    /// Admits one event record under `Authority::Quorum`: proves the decided
    /// commitment at `position`, then admits and — for a seal — replays and
    /// commits the checkpoint. The proof orders; reproduction still verifies.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_quorum<V>(
        &mut self,
        session: &mut Session,
        record: &GameRecord,
        certificate: &CommitCertificate,
        batch: &Batch,
        position: usize,
        step: u64,
        verify: V,
    ) -> Result<Option<VerifiedCheckpoint>, AdmitError>
    where
        V: FnOnce(&[u8], u64, &[u8; 32]) -> bool,
    {
        let proven = prove(session, record, certificate, batch, position, verify)
            .map_err(AdmitError::Proof)?;
        self.admit_proven(session, record, proven, step)
            .map_err(AdmitError::Receiver)
    }
    /// Admits a settlement record under `Authority::Quorum`: proves the
    /// decided commitment at `position`, then reproduces the settlement.
    /// `attest` remains available for observers that never admitted.
    #[allow(clippy::too_many_arguments)]
    pub fn settle_quorum<V>(
        &mut self,
        session: &mut Session,
        record: &GameRecord,
        certificate: &CommitCertificate,
        batch: &Batch,
        position: usize,
        step: u64,
        verify: V,
    ) -> Result<VerifiedSettlement, AdmitError>
    where
        V: FnOnce(&[u8], u64, &[u8; 32]) -> bool,
    {
        let proven = prove(session, record, certificate, batch, position, verify)
            .map_err(AdmitError::Proof)?;
        self.settle_proven(session, record, proven, step)
            .map_err(AdmitError::Receiver)
    }
}
