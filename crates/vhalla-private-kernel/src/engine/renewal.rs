use super::membership::{advance, check_control, control};
use super::messages::{process, wire};
use super::*;
use crate::{
    model::{app_aad, check_credential, State},
    packets::{self, ControlPacket},
    protocol::*,
    Error,
};
use openmls::prelude::*;

impl<S: Store> Kernel<S> {
    /// Prepare an exact public account-signing request for this same owner device.
    /// The later renewal transaction checks the retained prior interval and time.
    /// This never changes the anchor, owner key, room, or MLS state by itself.
    pub fn owner_renewal_request(&self, validity: Validity) -> Result<UnsignedDeviceEnrollment> {
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
        Ok(UnsignedDeviceEnrollment::new(DeviceEnrollmentClaims {
            account: self.context.account,
            device: self.context.device,
            validity,
        })?)
    }

    /// Renew only the exact anchored owner device under a current account-signed
    /// enrollment. The prior enrollment may have expired on this narrow path;
    /// ordinary operations retain their existing expiry checks. Exact retries
    /// return retained ciphertext and never perform a second credential update.
    pub async fn renew_owner(
        &mut self,
        operation: OperationId,
        enrollment: SignedDeviceEnrollment,
        now: u64,
    ) -> Result<CommittedOutbox> {
        let replacement = enrollment.verify()?;
        let request = packets::request(
            self.context,
            OutboxKind::OwnerUpdate,
            &[&enrollment.encode()],
        )?;
        let mut work = self.begin_live().await?;
        if let Some(retained) = self
            .retained(
                operation,
                request,
                OutboxKind::OwnerUpdate,
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
        check_replacement(&work.state, &replacement, now)?;
        let mut group = work.group()?;
        // The convenience self_update consumes every pending proposal. Requiring
        // an empty queue and then checking the complete stage excludes hidden
        // membership/PSK/extension operations from this credential-only grant.
        if group.pending_proposals().next().is_some() || group.pending_commit().is_some() {
            return Err(Error::Policy);
        }
        let parameters = LeafNodeParameters::builder()
            .with_credential_with_key(CredentialWithKey {
                credential: BasicCredential::new(replacement.signed().encode()).into(),
                signature_key: work.state.owner.claims().device.as_bytes().to_vec().into(),
            })
            .build();
        group.set_aad(app_aad(self.context));
        let bundle = group
            .self_update(&work.provider, &work.signer()?, parameters)
            .map_err(|_| Error::Mls)?;
        if bundle.welcome().is_some() {
            return Err(Error::Policy);
        }
        check_stage(
            group.pending_commit().ok_or(Error::Mls)?,
            &work,
            &replacement,
        )?;
        let commit = wire(bundle.commit())?;
        let owner_control = control(&work, &commit, ControlChange::OwnerUpdate)?;
        let packet = ControlPacket {
            control: owner_control.clone(),
            commit,
            invitation: None,
            enrollment: Some(replacement.clone()),
        };
        let output = transport::seal(&work, &group, &packet)?;
        group
            .merge_pending_commit(&work.provider)
            .map_err(|_| Error::Mls)?;
        replace_owner(&mut work.state, replacement)?;
        advance(&mut work, &owner_control, now)?;
        work.state.set_membership_phase();
        self.publish_sent_control(
            work,
            operation,
            request,
            OutboxKind::OwnerUpdate,
            output.clone(),
            Some((&packet, &output)),
        )
        .await
    }

    pub(super) async fn apply_owner_renewal(
        &mut self,
        mut work: Working,
        packet: ControlPacket,
        envelope: &[u8],
        now: u64,
    ) -> Result<Status> {
        if packet.control.claims().change != ControlChange::OwnerUpdate {
            return Err(Error::Policy);
        }
        check_control(&work, &packet.control, &packet.commit)?;
        let replacement = packet.enrollment.as_ref().ok_or(Error::Policy)?;
        check_replacement(&work.state, replacement, now)?;
        // A member's own credential must still be current. Only the old owner's
        // expiry is bypassed after authenticating its replacement account grant.
        work.state.local.claims().validity.check_at(now)?;
        let mut group = work.group()?;
        let processed = process(&work, &mut group, &packet.commit)?;
        let sender = processed.sender().clone();
        let credential = processed.credential().clone();
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err(Error::Policy);
        };
        // This intentionally does not call the general sender helper's old-owner
        // expiry check. Signature authentication is provided by process_message,
        // then the exact previous owner leaf/credential is matched here.
        let Sender::Member(index) = sender else {
            return Err(Error::Policy);
        };
        let member = group
            .members()
            .find(|m| m.index == index)
            .ok_or(Error::Policy)?;
        check_credential(&member.credential, &member.signature_key, &work.state.owner)?;
        check_credential(&credential, &member.signature_key, &work.state.owner)?;
        check_stage(&staged, &work, replacement)?;
        group
            .merge_staged_commit(&work.provider, *staged)
            .map_err(|_| Error::Mls)?;
        replace_owner(&mut work.state, replacement.clone())?;
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

fn check_replacement(
    state: &State,
    replacement: &VerifiedDeviceEnrollment,
    now: u64,
) -> Result<()> {
    let old = state.owner.claims();
    let next = replacement.claims();
    if now < state.clock {
        return Err(Error::Time);
    }
    // The account pin stays anchored; the device pin is generational so a
    // succeeded owner can still renew its own credential later.
    if next.account != old.account
        || next.device != old.device
        || next.account != state.anchor.claims().owner_account
    {
        return Err(Error::Scope);
    }
    next.validity.check_at(now)?;
    if next.validity.not_before() < old.validity.not_before()
        || next.validity.expires_at() <= old.validity.expires_at()
    {
        return Err(Error::Time);
    }
    Ok(())
}
pub(super) fn check_stage(
    staged: &StagedCommit,
    work: &Working,
    replacement: &VerifiedDeviceEnrollment,
) -> Result<()> {
    if staged.epoch().as_u64() != work.state.epoch.checked_add(1).ok_or(Error::Bounds)?
        || staged.self_removed()
        || staged.queued_proposals().next().is_some()
    {
        return Err(Error::Policy);
    }
    let leaf = staged.update_path_leaf_node().ok_or(Error::Policy)?;
    check_credential(
        leaf.credential(),
        leaf.signature_key().as_slice(),
        replacement,
    )
}
fn replace_owner(state: &mut State, replacement: VerifiedDeviceEnrollment) -> Result<()> {
    let index = state
        .roster
        .iter()
        .position(|e| e.claims().device == state.owner.claims().device)
        .ok_or(Error::Policy)?;
    if state.owner_role() {
        state.local = replacement.clone();
    }
    state.roster[index] = replacement.clone();
    state.owner = replacement;
    // A former account-signed owner basis cannot authorize a pending contact.
    state.offers.clear();
    Ok(())
}
