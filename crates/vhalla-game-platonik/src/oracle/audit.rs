//! Publisher-side and test-side audit of the bytes an [`InnerArtifactId`]
//! names.
//!
//! An `InnerArtifactId` is the plain SHA-256 of the compact canonical JSON of
//! the object its [`InnerKind`] names. The `platonik` CLI writes receipts
//! pretty printed with a trailing newline and habitat exports append a
//! newline, so a publisher re-serializes compactly before computing an id or
//! shipping bytes. This module is where a publisher does that and where the
//! tests check it. It is never on a receiver's path.
//!
//! The default receiver path is the one in
//! [`crate::wire`] and the artifact assembly beside it: it compares the plain
//! SHA-256 of the assembled bytes to the id of that artifact's own kind and
//! never parses JSON, never reaches `platonik-core`, and never re-derives a
//! Platonik hash. Everything here is behind the `oracle` feature for exactly
//! that reason.
//!
//! Comparing a receipt's bytes to the `result_hash` the receipt itself carries
//! is a known non-check: the receipt's own fields are hashes of the
//! `Experiment` and the `RunResult` inside it, and the whole receipt is a
//! third value, [`InnerKind::PlatonikReceiptV1`], that Platonik computes as
//! `check::artifact_hash(&receipt)`.

use platonik_core::check::{self, Receipt, VerificationReport};
use platonik_core::model::{Experiment, RunResult};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::ids::{InnerArtifactId, InnerKind};

/// Why an audit refused the bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditError {
    /// The kind names no JSON object this auditor parses: the habitat
    /// checkpoint and the adapter frame trace are audited elsewhere.
    UnsupportedKind(InnerKind),
    /// The bytes are not the object the kind names.
    Parse(String),
    /// The object does not re-serialize.
    Serialize(String),
    /// The bytes parse but are not that object's compact canonical form.
    /// Pretty printing and a trailing newline both land here: they are a
    /// publisher error, refused rather than normalized.
    NotCompact,
    /// Platonik's own `artifact_hash` disagrees with the plain SHA-256 of the
    /// compact bytes. Unreachable while both hash the same serializer output;
    /// it is checked rather than assumed.
    HashDisagrees {
        /// What `artifact_hash` rendered.
        platonik: String,
        /// What the plain SHA-256 renders.
        plain: String,
    },
    /// A receipt whose `verify_receipt` refused, carrying Platonik's reason.
    ReceiptRejected(String),
}

/// What an audit established about one artifact's bytes.
#[derive(Clone, Debug)]
pub struct Audit {
    /// The id those bytes hash to, tagged by the audited kind.
    pub id: InnerArtifactId,
    /// Platonik's own verdict, present only for
    /// [`InnerKind::PlatonikReceiptV1`], where the audit runs
    /// `check::verify_receipt` over the parsed receipt.
    pub report: Option<VerificationReport>,
}

/// The compact canonical bytes of an object: `serde_json::to_vec`, no pretty
/// printing, no trailing newline.
pub fn canonical_bytes<T: Serialize>(object: &T) -> Result<Vec<u8>, AuditError> {
    serde_json::to_vec(object).map_err(|error| AuditError::Serialize(error.to_string()))
}

/// The plain SHA-256 of the bytes: no domain, no length prefix. This is the
/// hash an `InnerArtifactId` carries, and it is deliberately not
/// `vhalla_witness::hash::digest`.
#[must_use]
pub fn plain_sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// The id a publisher declares for an object of the given kind: the plain
/// SHA-256 of that object's compact canonical bytes.
pub fn id_of<T: Serialize>(kind: InnerKind, object: &T) -> Result<InnerArtifactId, AuditError> {
    let bytes = canonical_bytes(object)?;
    Ok(InnerArtifactId {
        kind,
        sha256: plain_sha256(&bytes),
    })
}

/// The [`InnerKind::PlatonikExperimentV1`] id of an experiment, equal to the
/// `experiment_hash` a receipt over it carries.
pub fn experiment_id(experiment: &Experiment) -> Result<InnerArtifactId, AuditError> {
    id_of(InnerKind::PlatonikExperimentV1, experiment)
}

/// The [`InnerKind::PlatonikResultV1`] id of a run result, equal to the
/// `result_hash` a receipt over it carries.
pub fn result_id(result: &RunResult) -> Result<InnerArtifactId, AuditError> {
    id_of(InnerKind::PlatonikResultV1, result)
}

/// The [`InnerKind::PlatonikReceiptV1`] id of a whole receipt, equal to
/// Platonik's `check::artifact_hash(&receipt)` and distinct from both hashes
/// the receipt carries in its own fields.
pub fn receipt_id(receipt: &Receipt) -> Result<InnerArtifactId, AuditError> {
    id_of(InnerKind::PlatonikReceiptV1, receipt)
}

/// Parses `bytes` as the object `kind` names, requires them to be that
/// object's compact canonical form, and returns the id they hash to.
///
/// The kind is the only thing that decides how the bytes are parsed, so no
/// cross-kind comparison is ever attempted: an experiment's bytes audited as a
/// result fail to parse rather than being hashed and compared to some other
/// kind's id.
pub fn audit_bytes(kind: InnerKind, bytes: &[u8]) -> Result<InnerArtifactId, AuditError> {
    audit(kind, bytes).map(|audit| audit.id)
}

/// [`audit_bytes`] plus Platonik's verdict on a receipt.
pub fn audit(kind: InnerKind, bytes: &[u8]) -> Result<Audit, AuditError> {
    match kind {
        InnerKind::PlatonikExperimentV1 => {
            let experiment: Experiment = parse(bytes)?;
            let id = compact_id(kind, bytes, &experiment)?;
            agrees(&id, check::artifact_hash(&experiment))?;
            Ok(Audit { id, report: None })
        }
        InnerKind::PlatonikResultV1 => {
            let result: RunResult = parse(bytes)?;
            let id = compact_id(kind, bytes, &result)?;
            Ok(Audit { id, report: None })
        }
        InnerKind::PlatonikReceiptV1 => {
            let receipt: Receipt = parse(bytes)?;
            let id = compact_id(kind, bytes, &receipt)?;
            let report = check::verify_receipt(&receipt).map_err(AuditError::ReceiptRejected)?;
            Ok(Audit {
                id,
                report: Some(report),
            })
        }
        InnerKind::PlatonikCheckpointV1 | InnerKind::FrameTraceV1 => {
            Err(AuditError::UnsupportedKind(kind))
        }
    }
}

fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, AuditError> {
    serde_json::from_slice(bytes).map_err(|error| AuditError::Parse(error.to_string()))
}

/// Re-serializes the parsed object compactly, requires the supplied bytes to
/// be exactly that, and hashes them.
fn compact_id<T: Serialize>(
    kind: InnerKind,
    bytes: &[u8],
    object: &T,
) -> Result<InnerArtifactId, AuditError> {
    let compact = canonical_bytes(object)?;
    if compact != bytes {
        return Err(AuditError::NotCompact);
    }
    Ok(InnerArtifactId {
        kind,
        sha256: plain_sha256(&compact),
    })
}

/// Checks Platonik's own `sha256:` rendering against the id.
fn agrees(id: &InnerArtifactId, platonik: Result<String, String>) -> Result<(), AuditError> {
    let platonik = platonik.map_err(AuditError::Serialize)?;
    let plain = id.render();
    if platonik == plain {
        Ok(())
    } else {
        Err(AuditError::HashDisagrees { platonik, plain })
    }
}
