//! Account-authorized owner-device handoff.
//!
//! The grant is signed by the owner account, not a device, and authorizes
//! nothing alone: only the exact predecessor-signed control at the grant's
//! pinned sequence carries it, only while the embedded successor enrollment is
//! already an accepted roster member. The predecessor is demoted to ordinary
//! membership; it is never implicitly removed, and its historical controls stay
//! attributed to its own generation.

use openmls::prelude::*;

use super::membership::{advance, check_control, control};
use super::messages::{process, wire};
use super::renewal::check_stage;
use super::*;
use crate::{
    model::{app_aad, check_credential, MAX_SUCCESSIONS},
    packets::{self, ControlPacket},
    protocol::*,
    Error,
};

impl<S: Store> Kernel<S> {
    /// Prepare the exact account-signing request authorizing a handoff to the
    /// already-enrolled `successor` device at the current control floor. The
    /// prepared sequence is the next control only; if the floor advances before
    /// commit, the signed grant is refused rather than rebound. This performs
    /// no storage write or MLS change by itself.
    pub async fn succession_request(
        &mut self,
        successor: Key,
        validity: Validity,
    ) -> Result<UnsignedOwnerSuccession> {
        if self.needs_reopen {
            return Err(Error::NeedsReopen);
        }
        if self.status.quarantined {
            return Err(Error::Quarantined);
        }
        if !matches!(
            self.status.phase,
            Phase::OwnerGenesis | Phase::OwnerJoined | Phase::OwnerAfterRemoval
        ) {
            return Err(Error::Policy);
        }
        let work = self.begin().await?;
        let enrollment = work
            .state
            .roster
            .iter()
            .find(|e| e.claims().device == successor)
            .ok_or(Error::Policy)?;
        if work.state.successions.len() >= MAX_SUCCESSIONS {
            return Err(Error::Bounds);
        }
        let request = UnsignedOwnerSuccession::new(OwnerSuccessionClaims {
            scope: self.context.scope,
            account: self.context.account,
            predecessor: work.state.owner.claims().device,
            successor: enrollment.signed().clone(),
            sequence: work.state.floor.next_sequence()?,
            validity,
        })?;
        self.needs_reopen = false;
        Ok(request)
    }

    /// Commit the account-signed handoff as the next predecessor-signed control.
    /// The MLS commit re-keys only the predecessor leaf; no membership proposal,
    /// PSK or extension rides along. MLS state, the retained grant chain, owner
    /// state, floor and output commit atomically, and exact retries return the
    /// retained ciphertext instead of minting a second handoff.
    pub async fn succeed(
        &mut self,
        operation: OperationId,
        grant: SignedOwnerSuccession,
        now: u64,
    ) -> Result<CommittedOutbox> {
        let grant = grant.verify()?;
        let request = packets::request(
            self.context,
            OutboxKind::Succession,
            &[&grant.signed().encode()],
        )?;
        let mut work = self.begin_live().await?;
        if let Some(retained) = self
            .retained(
                operation,
                request,
                OutboxKind::Succession,
                work.state.outbox,
            )
            .await?
        {
            self.needs_reopen = false;
            return Ok(retained);
        }
        if !work.state.owner_role() {
            return Err(Error::Policy);
        }
        check_grant(&work.state, &grant, work.state.floor.next_sequence()?, now)?;
        let mut group = work.group()?;
        if group.pending_proposals().next().is_some() || group.pending_commit().is_some() {
            return Err(Error::Policy);
        }
        group.set_aad(app_aad(self.context));
        let bundle = group
            .self_update(
                &work.provider,
                &work.signer()?,
                LeafNodeParameters::default(),
            )
            .map_err(|_| Error::Mls)?;
        if bundle.welcome().is_some() {
            return Err(Error::Policy);
        }
        // The predecessor keeps its own credential; only the leaf secret moves.
        check_stage(
            group.pending_commit().ok_or(Error::Mls)?,
            &work,
            &work.state.owner.clone(),
        )?;
        let commit = wire(bundle.commit())?;
        let owner_control = control(
            &work,
            &commit,
            ControlChange::Succession {
                grant: Box::new(grant.signed().clone()),
            },
        )?;
        let packet = ControlPacket {
            control: owner_control.clone(),
            commit,
            invitation: None,
            enrollment: None,
        };
        let output = transport::seal(&work, &group, &packet)?;
        group
            .merge_pending_commit(&work.provider)
            .map_err(|_| Error::Mls)?;
        promote(&mut work.state, &owner_control)?;
        advance(&mut work, &owner_control, now)?;
        work.state.set_membership_phase();
        self.publish_sent_control(
            work,
            operation,
            request,
            OutboxKind::Succession,
            output.clone(),
            Some((&packet, &output)),
        )
        .await
    }

    /// Apply a strict succession envelope: authenticate the predecessor-signed
    /// carrying control and the account-signed grant against retained state,
    /// merge only after every check, then promote the successor and demote the
    /// predecessor to ordinary membership in the same transaction.
    pub(super) async fn apply_succession(
        &mut self,
        mut work: Working,
        packet: ControlPacket,
        envelope: &[u8],
        now: u64,
    ) -> Result<Status> {
        let ControlChange::Succession { grant } = &packet.control.claims().change else {
            return Err(Error::Policy);
        };
        let grant = grant.verify()?;
        check_control(&work, &packet.control, &packet.commit)?;
        check_grant(
            &work.state,
            &grant,
            packet.control.claims().sequence()?,
            now,
        )?;
        // The applying member's own credential must still be current. The
        // predecessor's expiry does not block an account-authorized handoff;
        // signature authentication comes from process_message and the exact
        // previous-owner leaf/credential match below.
        work.state.local.claims().validity.check_at(now)?;
        let mut group = work.group()?;
        let processed = process(&work, &mut group, &packet.commit)?;
        let sender = processed.sender().clone();
        let credential = processed.credential().clone();
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err(Error::Policy);
        };
        let Sender::Member(index) = sender else {
            return Err(Error::Policy);
        };
        let member = group
            .members()
            .find(|m| m.index == index)
            .ok_or(Error::Policy)?;
        check_credential(&member.credential, &member.signature_key, &work.state.owner)?;
        check_credential(&credential, &member.signature_key, &work.state.owner)?;
        check_stage(&staged, &work, &work.state.owner.clone())?;
        group
            .merge_staged_commit(&work.provider, *staged)
            .map_err(|_| Error::Mls)?;
        promote(&mut work.state, &packet.control)?;
        advance(&mut work, &packet.control, now)?;
        work.state.set_membership_phase();
        let record = self.encrypt_record(
            RecordKey::Control(packet.floor()?.sequence()),
            &transport::RetainedControl::new(packet.control.clone(), Some(envelope.to_vec()))?
                .encode()?,
        )?;
        self.publish(work, vec![record]).await?;
        self.needs_reopen = false;
        Ok(self.status)
    }
}

/// Stateful pins the verified grant still needs: retained scope/anchor account,
/// current-generation predecessor, exact carrying sequence, a live grant window,
/// a live identical roster enrollment for the successor and headroom in the
/// bounded chain. This never upgrades the anchor or rewrites prior controls.
fn check_grant(
    state: &State,
    grant: &VerifiedOwnerSuccession,
    sequence: u64,
    now: u64,
) -> Result<()> {
    let claims = grant.claims();
    if now < state.clock {
        return Err(Error::Time);
    }
    if claims.scope != state.context().scope
        || claims.account != state.anchor.claims().owner_account
        || claims.account != state.owner.claims().account
        || claims.predecessor != state.owner.claims().device
        || claims.sequence != sequence
    {
        return Err(Error::Scope);
    }
    claims.validity.check_at(now)?;
    claims.successor.claims().validity.check_at(now)?;
    if state.successions.len() >= MAX_SUCCESSIONS {
        return Err(Error::Bounds);
    }
    // The exact signed enrollment must already be rostered; a renewed or
    // reissued successor enrollment is a different grant, not a late bind.
    if !state.roster.iter().any(|e| *e.signed() == claims.successor) {
        return Err(Error::Policy);
    }
    Ok(())
}

/// Record the grant, promote the rostered successor and retire any outstanding
/// owner-scoped contact basis in one state transition.
fn promote(state: &mut State, control: &VerifiedOwnerControl) -> Result<()> {
    let grant = OwnerSuccessionProof::from_control(control.signed().clone())?;
    let successor = state
        .roster
        .iter()
        .find(|e| *e.signed() == grant.claims().successor)
        .ok_or(Error::Policy)?
        .clone();
    if state.successions.len() >= MAX_SUCCESSIONS {
        return Err(Error::Bounds);
    }
    state.successions.push(grant);
    state.owner = successor;
    // A former account-signed owner basis cannot authorize a pending contact.
    state.offers.clear();
    Ok(())
}
