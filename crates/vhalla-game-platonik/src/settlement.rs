//! Settlement: post-ledger evidence about the final checkpoint, admitted by
//! reproducing the receipt rather than by finding it inside a root. Resolution
//! between competing settlements ranks by self-verifiability, never by
//! arrival order.

use vhalla_core::{Epoch, PeerId, RealmId, RoomId, Sequence};
use vhalla_crypto::{sign_claim, Claim, ClaimDomain, SignedClaim, SubjectDigest};
use vhalla_witness::hash::ReceiptHash;
use vhalla_witness::manifest::ValidManifest;
use vhalla_witness::platform::{ReceiptBinding, WorkAllowance};

use crate::engine::GameEngine;
use crate::ids::SessionKey;
use crate::receiver::{Receiver, ReceiverError};
use crate::record::{GameRecord, RecordKind};
use crate::session::{Session, State, Verdict};
use crate::wire::{decode_settlement, ForkReason, Settlement};

/// Why a settlement is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum SettleError {
    NotASettlement,
    Signature,
    NotHost,
    WrongSession,
    WrongEpoch,
    NoFinalCheckpoint,
    WrongCheckpoint,
    PendingNotEmpty,
    Height,
    ReceiptMismatch,
    PassedMismatch,
    CancelAfterFinal,
    Outranked,
    Contradiction,
    Terminal,
}

/// Evidence that this receiver settled a session.
///
/// ```compile_fail
/// use vhalla_game_platonik::settlement::VerifiedSettlement;
/// fn dup(v: &VerifiedSettlement) -> VerifiedSettlement { v.clone() }
/// ```
#[derive(Debug)]
pub struct VerifiedSettlement {
    realm: RealmId,
    room: RoomId,
    session: SessionKey,
    epoch: u64,
    verdict: Verdict,
    hash: [u8; 32],
}

impl VerifiedSettlement {
    /// Realm scope.
    #[must_use]
    pub const fn realm(&self) -> RealmId {
        self.realm
    }
    /// Room scope.
    #[must_use]
    pub const fn room(&self) -> RoomId {
        self.room
    }
    /// Session.
    #[must_use]
    pub const fn session(&self) -> SessionKey {
        self.session
    }
    /// Epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
    /// The verdict.
    #[must_use]
    pub const fn verdict(&self) -> &Verdict {
        &self.verdict
    }
    /// Whether the verdict is a reproduced passing result.
    #[must_use]
    pub fn passed(&self) -> bool {
        matches!(self.verdict, Verdict::Result { passed: true, .. })
    }
    /// The settlement hash.
    #[must_use]
    pub const fn hash(&self) -> [u8; 32] {
        self.hash
    }
    /// Exports this verdict as a `SignedClaim` in `ClaimDomain::Receipt` with
    /// the settlement hash as its subject, signed by the verifier's own seed,
    /// so a per-realm receipt DAG can record it. The claim is the verifier's
    /// statement about its own reproduction, never the host's.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn export_claim(
        &self,
        realm: RealmId,
        claim_session: vhalla_crypto::SessionId,
        audience: PeerId,
        epoch: Epoch,
        sequence: Sequence,
        issued_at: u64,
        expires_at: u64,
        seed: [u8; 32],
    ) -> SignedClaim {
        sign_claim(
            Claim {
                domain: ClaimDomain::Receipt,
                realm,
                session: claim_session,
                subject: SubjectDigest::from_digest(self.hash),
                sequence,
                epoch,
                issued_at,
                expires_at,
                audience,
            },
            seed,
        )
    }
}

impl<E: GameEngine> Receiver<E> {
    /// Admits a host-signed settlement record by reproducing what it claims.
    pub fn settle(
        &mut self,
        session: &mut Session,
        record: &GameRecord,
        step: u64,
    ) -> Result<VerifiedSettlement, ReceiverError> {
        self.advance_step(step)?;
        if record.kind != RecordKind::Settlement {
            return Err(ReceiverError::Settle(SettleError::NotASettlement));
        }
        record
            .verify()
            .map_err(|_| ReceiverError::Settle(SettleError::Signature))?;
        if record.signer != session.host() {
            return Err(ReceiverError::Settle(SettleError::NotHost));
        }
        if record.session != session.key() {
            return Err(ReceiverError::Settle(SettleError::WrongSession));
        }
        let settlement = decode_settlement(&record.body)
            .map_err(|_| ReceiverError::Settle(SettleError::NotASettlement))?;
        let hash = record.object_digest();
        match settlement {
            Settlement::Result {
                session: named,
                epoch,
                checkpoint,
                receipt,
                passed,
            } => {
                if named != session.key() {
                    return Err(ReceiverError::Settle(SettleError::WrongSession));
                }
                if epoch != session.epoch() {
                    return Err(ReceiverError::Settle(SettleError::WrongEpoch));
                }
                if session.state() != State::Finished {
                    return Err(ReceiverError::Settle(SettleError::NoFinalCheckpoint));
                }
                let Some(&(_, _, final_hash)) = session.segments().last() else {
                    return Err(ReceiverError::Settle(SettleError::NoFinalCheckpoint));
                };
                if checkpoint != final_hash {
                    return Err(ReceiverError::Settle(SettleError::WrongCheckpoint));
                }
                if session.pending() != 0 {
                    return Err(ReceiverError::Settle(SettleError::PendingNotEmpty));
                }
                let expected_height =
                    session.epoch_orders() + u64::from(session.ledger().seals_appended());
                if session.ledger().height() != expected_height {
                    return Err(ReceiverError::Settle(SettleError::Height));
                }
                let Some((manifest, candidate, through_tick)) = session.final_plan().cloned()
                else {
                    return Err(ReceiverError::Settle(SettleError::NoFinalCheckpoint));
                };
                let valid =
                    ValidManifest::validate(manifest).map_err(|_| ReceiverError::Manifest)?;
                let allowance = WorkAllowance {
                    max_total: valid
                        .fuel_total()
                        .min(session.manifest().limits.replay.max_total),
                };
                self.charge_replay(session, valid.fuel_total())?;
                let evidence = self
                    .engine()
                    .replay(
                        session.world(),
                        &valid,
                        candidate,
                        allowance,
                        through_tick,
                        ReceiptBinding {
                            challenge_id: session.key().0,
                            subject_key: session.host(),
                        },
                    )
                    .map_err(ReceiverError::Engine)?;
                if !receipt.matches(&evidence.receipt) {
                    return Err(ReceiverError::Settle(SettleError::ReceiptMismatch));
                }
                if passed != evidence.passed {
                    return Err(ReceiverError::Settle(SettleError::PassedMismatch));
                }
                let verdict = Verdict::Result {
                    checkpoint,
                    passed,
                    receipt: ReceiptHash::of(&receipt.encode()).0,
                };
                match session.settled() {
                    Some(existing) if *existing == verdict => {}
                    Some(Verdict::Result { .. }) => {
                        session.unresolve(ForkReason::Equivocation, &[hash]);
                        return Err(ReceiverError::Settle(SettleError::Contradiction));
                    }
                    Some(Verdict::Unresolved { .. }) | None => {
                        session.record_verdict(verdict.clone())
                    }
                }
                Ok(VerifiedSettlement {
                    realm: session.realm(),
                    room: session.room(),
                    session: session.key(),
                    epoch: epoch.0,
                    verdict,
                    hash,
                })
            }
            Settlement::Unresolved {
                session: named,
                epoch,
                reason,
                heads,
                evidence,
            } => {
                if named != session.key() {
                    return Err(ReceiverError::Settle(SettleError::WrongSession));
                }
                if epoch != session.epoch() {
                    return Err(ReceiverError::Settle(SettleError::WrongEpoch));
                }
                if reason == ForkReason::Cancelled && session.state() == State::Finished {
                    return Err(ReceiverError::Settle(SettleError::CancelAfterFinal));
                }
                if let Some(Verdict::Result { .. }) = session.settled() {
                    return Err(ReceiverError::Settle(SettleError::Outranked));
                }
                if let State::Unresolved(ForkReason::Cancelled) = session.state() {
                    return Err(ReceiverError::Settle(SettleError::Terminal));
                }
                let verdict = Verdict::Unresolved {
                    reason,
                    heads: heads.clone(),
                    evidence: evidence.clone(),
                };
                match session.settled() {
                    Some(existing) if *existing == verdict => {}
                    Some(Verdict::Unresolved { .. }) => {
                        session.unresolve(ForkReason::Equivocation, &[hash]);
                        return Err(ReceiverError::Settle(SettleError::Contradiction));
                    }
                    _ => session.record_verdict(verdict.clone()),
                }
                Ok(VerifiedSettlement {
                    realm: session.realm(),
                    room: session.room(),
                    session: session.key(),
                    epoch: epoch.0,
                    verdict,
                    hash,
                })
            }
        }
    }
}
