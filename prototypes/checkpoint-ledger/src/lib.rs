//! Disposable composition of certificate verification and derived ledger roots.
//!
//! Recovery requires a separately retained anchor and restores exactly that
//! certified frontier. The anchor is an in-memory model, not durable storage or
//! proof that it is the newest checkpoint in the network. No type grants host
//! authority, establishes event authorship, or provides consensus.
#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

use alloc::{format, string::String, vec::Vec};
use valhalla_checkpoint_proof_prototype::{
    CheckpointStatement, Digest32, Reject, TrustConfig, VerifiedProof,
};
use vhalla_core::{Epoch, RealmId};
use vhalla_ledger::{Checkpoint, Event, EventDigest, Ledger, StateRoot};

/// Exact, versioned mapping of all 128 realm bits into the certificate namespace.
///
/// The suffix is always 32 lowercase hexadecimal digits, including leading
/// zeroes. Aliases, display names, Unicode normalization, and truncated hashes
/// are not accepted by the adapter.
#[must_use]
pub fn certificate_realm(realm: RealmId) -> String {
    format!("vhalla/realm/u128/v1/{:032x}", realm.0)
}

/// A claim whose certificate and complete retained history were both checked.
/// This evidence remains valid for its checkpoint even if newer events arrive.
///
/// ```compile_fail
/// use valhalla_checkpoint_ledger_prototype::CheckedCheckpoint;
/// fn change_height(checked: &mut CheckedCheckpoint) {
///     checked.checkpoint.height = 0;
/// }
/// ```
///
/// A signature alone cannot construct history-checked evidence.
///
/// ```compile_fail
/// use valhalla_checkpoint_ledger_prototype::CheckedCheckpoint;
/// use valhalla_checkpoint_proof_prototype::VerifiedProof;
/// fn skip_history(proof: VerifiedProof) -> CheckedCheckpoint {
///     proof.into()
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckedCheckpoint {
    checkpoint: Checkpoint,
    proof: VerifiedProof,
}

impl CheckedCheckpoint {
    /// A copy of the derived checkpoint. Mutating the copy changes no evidence.
    #[must_use]
    pub fn checkpoint(&self) -> Checkpoint {
        self.checkpoint
    }

    /// Immutable signature evidence that approved this exact checkpoint.
    #[must_use]
    pub fn proof(&self) -> &VerifiedProof {
        &self.proof
    }

    /// Model the frontier the owner must retain separately for recovery.
    ///
    /// The caller must select the latest locally accepted anchor. This function
    /// neither persists it nor prevents the caller from retaining an older one.
    #[must_use]
    pub fn recovery_anchor(&self) -> RecoveryAnchor {
        RecoveryAnchor {
            checkpoint: self.checkpoint,
            trust_digest: self.proof.statement().trust_digest,
        }
    }
}

/// Independently retained local recovery expectation, never read from a snapshot.
///
/// Its private constructor makes the model start from checked history. Real
/// recovery needs an authenticated, rollback-resistant storage boundary for this
/// value; there is intentionally no serialization or raw-data constructor yet.
///
/// ```compile_fail
/// use valhalla_checkpoint_ledger_prototype::RecoveryAnchor;
/// use vhalla_ledger::Checkpoint;
/// fn trust_snapshot(checkpoint: Checkpoint) -> RecoveryAnchor {
///     RecoveryAnchor { checkpoint, trust_digest: [0; 32] }
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryAnchor {
    checkpoint: Checkpoint,
    trust_digest: Digest32,
}

impl RecoveryAnchor {
    /// The exact certified frontier required during recovery.
    #[must_use]
    pub fn checkpoint(&self) -> Checkpoint {
        self.checkpoint
    }

    /// The complete trust-policy digest bound to the frontier.
    #[must_use]
    pub fn trust_digest(&self) -> Digest32 {
        self.trust_digest
    }
}

/// Bounded linear history with one immutable certificate policy.
///
/// The ledger and accepted evidence have no mutable projections. Appends still
/// carry untrusted data; only `admit` creates history-checked evidence. This model
/// retains one latest checked checkpoint, not certificate bytes or a durable
/// conflict archive. Callers retain certificate bytes separately for recovery.
pub struct CertifiedLedger {
    realm: RealmId,
    epoch: Epoch,
    trust: TrustConfig,
    ledger: Ledger,
    accepted: Option<CheckedCheckpoint>,
}

impl CertifiedLedger {
    /// Create an empty model after checking the explicit realm/epoch mapping.
    pub fn new(
        realm: RealmId,
        epoch: Epoch,
        trust: TrustConfig,
        max_events: usize,
    ) -> Result<Self, Error> {
        // The trust API's claim constructor exposes its immutable context. This
        // zero-valued claim is never signed, admitted, or treated as evidence.
        let context = trust.statement([0; 32], [0; 32], 0);
        if context.realm != certificate_realm(realm) || context.epoch != epoch.0 {
            return Err(Error::TrustContextMismatch);
        }
        Ok(Self {
            realm,
            epoch,
            trust,
            ledger: Ledger::new(realm, epoch, max_events),
            accepted: None,
        })
    }

    /// Append a content-addressed event under the underlying history bounds.
    /// Actor identifiers are claims; this does not verify event authorship.
    pub fn append(&mut self, event: Event) -> Result<(), Error> {
        self.ledger.append(event).map_err(Error::Ledger)
    }

    /// Derive a signing proposal from the current tip; it is still unapproved.
    pub fn propose_tip(&self) -> Result<CheckpointStatement, Error> {
        let head = self.ledger.head().ok_or(Error::EmptyHistory)?;
        let root = self.ledger.state_root(head).map_err(Error::Ledger)?;
        Ok(self
            .trust
            .statement(head.0, root.0, (self.ledger.event_count() - 1) as u64))
    }

    /// Bound and authenticate bytes, then independently validate the local tip.
    ///
    /// Any rejection preserves history and the previously accepted certificate.
    /// A valid signature over a false root or height never creates checked
    /// evidence. A new admission must name the current tip, including on retry.
    pub fn admit(&mut self, certificate: &[u8]) -> Result<&CheckedCheckpoint, Error> {
        let proof = self.trust.verify_bytes(certificate).map_err(Error::Proof)?;
        let checkpoint = mapped_checkpoint(self.realm, self.epoch, &proof);
        self.ledger
            .accept_checkpoint(checkpoint)
            .map_err(Error::Ledger)?;
        self.accepted = Some(CheckedCheckpoint { checkpoint, proof });
        Ok(self.accepted.as_ref().expect("just admitted"))
    }

    /// Recover exactly a separately pinned certified frontier, under the same
    /// trust policy. The supplied certificate is reverified on every recovery.
    ///
    /// Older snapshots, divergent history, changed policies, and uncertified
    /// suffixes fail closed. A snapshot's embedded checkpoint cannot nominate
    /// its own recovery anchor. Previously retained local checkpoint metadata
    /// may trail the anchor; successful recovery replaces it with the anchor.
    ///
    /// This checks consistency against the supplied anchor, not anchor freshness
    /// or storage durability. It neither rolls forward nor truncates a suffix.
    pub fn recover(
        snapshot: &[u8],
        certificate: &[u8],
        anchor: &RecoveryAnchor,
        trust: TrustConfig,
        max_events: usize,
    ) -> Result<Self, Error> {
        if trust.digest() != anchor.trust_digest {
            return Err(Error::TrustChanged);
        }
        let mut model = Self::new(
            anchor.checkpoint.realm,
            anchor.checkpoint.epoch,
            trust,
            max_events,
        )?;
        let proof = model
            .trust
            .verify_bytes(certificate)
            .map_err(Error::Proof)?;
        let checkpoint = mapped_checkpoint(model.realm, model.epoch, &proof);
        if checkpoint != anchor.checkpoint {
            return Err(Error::AnchorMismatch);
        }
        let mut ledger = Ledger::restore(snapshot, max_events).map_err(Error::Ledger)?;
        // This one operation checks context, current tip, derived root, height,
        // and monotonic checkpoint admission against replayed bounded history.
        ledger
            .accept_checkpoint(checkpoint)
            .map_err(Error::Ledger)?;
        model.ledger = ledger;
        model.accepted = Some(CheckedCheckpoint { checkpoint, proof });
        Ok(model)
    }

    /// Current tip, possibly ahead of the last certified checkpoint.
    #[must_use]
    pub fn head(&self) -> Option<EventDigest> {
        self.ledger.head()
    }

    /// Number of retained events, including any uncertified suffix.
    #[must_use]
    pub fn event_count(&self) -> usize {
        self.ledger.event_count()
    }

    /// Latest checked certificate, which may trail newly appended events.
    #[must_use]
    pub fn accepted(&self) -> Option<&CheckedCheckpoint> {
        self.accepted.as_ref()
    }

    /// Serialize local history; this does not authenticate snapshot metadata.
    /// A snapshot ahead of the recovery anchor will be rejected by `recover`.
    #[must_use]
    pub fn snapshot(&self) -> Vec<u8> {
        self.ledger.snapshot()
    }
}

// Only call after verification under the immutable, constructor-checked policy.
fn mapped_checkpoint(realm: RealmId, epoch: Epoch, proof: &VerifiedProof) -> Checkpoint {
    let statement = proof.statement();
    Checkpoint {
        realm,
        epoch,
        head: EventDigest(statement.head),
        state_root: StateRoot(statement.state_root),
        height: statement.height,
    }
}

/// Rejections preserve existing live state; recovery returns no partial model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The trust policy uses another realm spelling or epoch.
    TrustContextMismatch,
    /// The recovery policy differs from the separately retained anchor.
    TrustChanged,
    /// An authentic certificate names a frontier other than the pinned anchor.
    AnchorMismatch,
    /// No event exists from which to derive a checkpoint proposal.
    EmptyHistory,
    /// Certificate decoding or authentication failed.
    Proof(Reject),
    /// History, snapshot, context, root, height, or bound validation failed.
    Ledger(vhalla_ledger::Error),
}
