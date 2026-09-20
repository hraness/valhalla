use openmls::prelude::*;
use openmls_traits::{signatures::Signer, OpenMlsProvider};
use tls_codec::Deserialize as _;

use super::messages::{member_sender, process, wire};
use super::*;
use crate::Error;
use crate::{
    checkpoint::{CheckpointClaims, UnsignedCheckpoint},
    model::{app_aad, check_credential, check_members, SUITE},
    packets::{self, ControlPacket, InvitePacket, JoinRequest},
    protocol::*,
};

impl<S: Store> Kernel<S> {
    /// Publish exactly one fresh-device KeyPackage. A different operation cannot
    /// mint a replacement package for the same pending device. Exact retries
    /// return the committed package even after it was consumed by joining.
    pub async fn key_package(
        &mut self,
        operation: OperationId,
        now: u64,
    ) -> Result<CommittedOutbox> {
        let request = packets::request(self.context, OutboxKind::KeyPackage, &[])?;
        let mut work = self.begin_live().await?;
        if let Some(retained) = self
            .retained(
                operation,
                request,
                OutboxKind::KeyPackage,
                work.state.outbox,
            )
            .await?
        {
            self.needs_reopen = false;
            return Ok(retained);
        }
        if work.state.phase != Phase::AwaitingWelcome || work.state.key_package.is_some() {
            return Err(Error::Policy);
        }
        work.state.check_time(now)?;
        let validity = work.state.local.claims().validity;
        let lifetime = Lifetime::init(validity.not_before(), validity.expires_at());
        if !lifetime.has_acceptable_range() {
            return Err(Error::Time);
        }
        let package = KeyPackage::builder()
            .key_package_lifetime(lifetime)
            .build(SUITE, &work.provider, &work.signer()?, work.credential())
            .map_err(|_| Error::Mls)?;
        let package = wire(package.key_package())?;
        work.state.key_package = Some(KeyPackageDigest::of_bytes(&package)?);
        let output = JoinRequest {
            scope: self.context.scope,
            enrollment: work.state.local.clone(),
            package,
        }
        .encode()?;
        work.state.clock = now;
        self.publish_sent(work, operation, request, OutboxKind::KeyPackage, output)
            .await
    }

    /// Add one explicitly enrolled fresh device while capacity remains. The
    /// exact control, Commit, recipient Welcome and signed joining checkpoint
    /// commit with the changed MLS state before any artifact is released.
    pub async fn invite(
        &mut self,
        operation: OperationId,
        raw_request: &[u8],
        validity: Validity,
        now: u64,
    ) -> Result<CommittedOutbox> {
        let join = JoinRequest::decode(raw_request)?;
        let request = packets::request(
            self.context,
            OutboxKind::Invitation,
            &[
                raw_request,
                &validity.not_before().to_be_bytes(),
                &validity.expires_at().to_be_bytes(),
            ],
        )?;
        let mut work = self.begin_live().await?;
        if let Some(retained) = self
            .retained(
                operation,
                request,
                OutboxKind::Invitation,
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
        if work.state.roster.len() >= MAX_MEMBERS {
            return Err(Error::Bounds);
        }
        work.state.check_time(now)?;
        validity.check_at(now)?;
        join.enrollment.claims().validity.check_at(now)?;
        if join.scope != self.context.scope
            || work
                .state
                .roster
                .iter()
                .any(|e| e.claims().device == join.enrollment.claims().device)
        {
            return Err(Error::Scope);
        }
        let package = KeyPackageIn::tls_deserialize_exact(&join.package)
            .map_err(|_| Error::Encoding)?
            .validate(work.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|_| Error::Mls)?;
        if package.ciphersuite() != SUITE {
            return Err(Error::Policy);
        }
        let leaf = package.leaf_node();
        check_credential(
            leaf.credential(),
            leaf.signature_key().as_slice(),
            &join.enrollment,
        )?;
        // Upstream validation also checks its own wall clock. Explicitly enforce
        // the controller's retained clock; do not mislabel upstream time custody.
        let time = web_time::UNIX_EPOCH
            .checked_add(web_time::Duration::from_secs(now))
            .ok_or(Error::Time)?;
        package
            .life_time()
            .validate_with_time(time)
            .map_err(|_| Error::Time)?;
        if !package.life_time().has_acceptable_range() {
            return Err(Error::Time);
        }
        let key_package = KeyPackageDigest::of_bytes(&join.package)?;
        let unsigned = UnsignedInvitation::new(InvitationClaims {
            scope: self.context.scope,
            owner_device: self.context.device,
            recipient_account: join.enrollment.claims().account,
            recipient_device: join.enrollment.claims().device,
            key_package,
            nonce: Nonce::from_bytes(codec::random()?)?,
            validity,
            floor: work.state.floor,
        })?;
        let invitation = unsigned
            .attach(signature(&work, &unsigned.signing_bytes())?)?
            .verify()?;
        let mut group = work.group()?;
        group.set_aad(app_aad(self.context));
        let (commit, welcome, _) = group
            .add_members(&work.provider, &work.signer()?, &[package])
            .map_err(|_| Error::Mls)?;
        check_add(
            group.pending_commit().ok_or(Error::Mls)?,
            &work,
            &join.enrollment,
            key_package,
        )?;
        let group_context =
            group_context_hash(group.pending_commit().ok_or(Error::Mls)?.group_context())?;
        let commit = wire(&commit)?;
        let welcome = wire(&welcome)?;
        let addition = Addition {
            invitation: invitation.id(),
            account: join.enrollment.claims().account,
            device: join.enrollment.claims().device,
            key_package,
            welcome: WelcomeDigest::of_bytes(&welcome)?,
        };
        let control = control(
            &work,
            &commit,
            ControlChange::Membership {
                additions: vec![addition],
                removals: Vec::new(),
            },
        )?;
        let mut roster = work.state.roster.clone();
        roster.push(join.enrollment.clone());
        roster.sort_by_key(|e| e.claims().device);
        let checkpoint = UnsignedCheckpoint::new(CheckpointClaims {
            scope: self.context.scope,
            owner: self.context.device,
            invitation: invitation.id(),
            parent: work.state.floor,
            accepted: ControlFloor::new(control.claims().sequence()?, Some(control.id()))?,
            epoch: control.claims().next_epoch,
            commit: control.claims().commit,
            welcome: WelcomeDigest::of_bytes(&welcome)?,
            group_context,
            roster: roster.clone(),
        })?;
        let checkpoint = checkpoint.attach(signature(&work, &checkpoint.signing_bytes()?)?)?;
        let control_packet = ControlPacket {
            control: control.clone(),
            commit: commit.clone(),
            invitation: Some(invitation.clone()),
            enrollment: Some(join.enrollment.clone()),
        };
        let envelope = transport::seal(&work, &group, &control_packet)?;
        group
            .merge_pending_commit(&work.provider)
            .map_err(|_| Error::Mls)?;
        let output = InvitePacket {
            invitation,
            control: control.clone(),
            owner: work.state.owner.clone(),
            member: join.enrollment,
            commit,
            welcome,
            checkpoint,
        }
        .encode()?;
        work.state.roster = roster;
        advance(&mut work, &control, now)?;
        work.state.set_membership_phase();
        self.publish_sent_control(
            work,
            operation,
            request,
            OutboxKind::Invitation,
            output,
            Some((&control_packet, &envelope)),
        )
        .await
    }

    /// Consume an exact owner invitation and its one-time Welcome. The retained
    /// anchor and owner enrollment must already be independently selected.
    /// Repeating the identical committed join is harmless; later/replacement
    /// Welcomes cannot reset this device or its consumed KeyPackage.
    pub async fn join(&mut self, raw: &[u8], now: u64) -> Result<Status> {
        let packet = InvitePacket::decode(raw)?;
        let id = codec::hash(b"vhalla/private-kernel/join-packet/v1\0", raw);
        let mut work = self.begin_live().await?;
        if work.state.phase == Phase::MemberJoined && work.state.joined == Some(id) {
            self.needs_reopen = false;
            return Ok(self.status);
        }
        if work.state.phase != Phase::AwaitingWelcome {
            return Err(Error::Policy);
        }
        work.state.check_time(now)?;
        if packet.owner.signed() != work.state.owner.signed()
            || packet.member.signed() != work.state.local.signed()
        {
            return Err(Error::Scope);
        }
        let invite = packet.invitation.claims();
        let transition = packet.control.claims();
        invite.validity.check_at(now)?;
        if invite.scope != self.context.scope
            || invite.owner_device != work.state.owner.claims().device
            || invite.recipient_account != self.context.account
            || invite.recipient_device != self.context.device
            || Some(invite.key_package) != work.state.key_package
        {
            return Err(Error::Policy);
        }
        // This check does not claim that the fresh joiner decrypts the old epoch.
        check_control_header(self.context.scope, &packet.control, &packet.commit)?;
        let control_packet = ControlPacket {
            control: packet.control.clone(),
            commit: packet.commit.clone(),
            invitation: Some(packet.invitation.clone()),
            enrollment: Some(packet.member.clone()),
        };
        control_packet.validate()?;
        let checkpoint = packet.checkpoint.claims();
        if transition.owner_device != work.state.owner.claims().device
            || transition.parent != invite.floor
            || checkpoint.scope != self.context.scope
            || checkpoint.owner != work.state.owner.claims().device
            || checkpoint.invitation != packet.invitation.id()
            || checkpoint.parent != invite.floor
            || checkpoint.accepted != control_packet.floor()?
            || checkpoint.epoch != transition.next_epoch
            || checkpoint.commit != transition.commit
            || checkpoint.welcome != WelcomeDigest::of_bytes(&packet.welcome)?
            || !checkpoint
                .roster
                .iter()
                .any(|e| e.signed() == work.state.owner.signed())
            || !checkpoint
                .roster
                .iter()
                .any(|e| e.signed() == work.state.local.signed())
        {
            return Err(Error::Policy);
        }
        let expected = Addition {
            invitation: packet.invitation.id(),
            account: self.context.account,
            device: self.context.device,
            key_package: invite.key_package,
            welcome: checkpoint.welcome,
        };
        if transition.change
            != (ControlChange::Membership {
                additions: vec![expected],
                removals: Vec::new(),
            })
        {
            return Err(Error::Policy);
        }
        let MlsMessageBodyIn::Welcome(welcome) =
            MlsMessageIn::tls_deserialize_exact(&packet.welcome)
                .map_err(|_| Error::Encoding)?
                .extract()
        else {
            return Err(Error::Encoding);
        };
        let config = MlsGroupJoinConfig::builder()
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(4, 32))
            .build();
        // OpenMLS consumes KeyPackage material here, exclusively in the isolated
        // candidate. A failed storage commit must preserve the original provider.
        let staged = StagedWelcome::new_from_welcome(&work.provider, &config, welcome, None)
            .map_err(|_| Error::Mls)?;
        let context = staged.group_context();
        if context.group_id().as_slice() != self.context.scope.room.as_bytes()
            || context.ciphersuite() != SUITE
            || context.epoch().as_u64() != transition.next_epoch
            || group_context_hash(context)? != checkpoint.group_context
        {
            return Err(Error::Scope);
        }
        let owner = staged.welcome_sender().map_err(|_| Error::Mls)?;
        check_credential(
            owner.credential(),
            owner.signature_key().as_slice(),
            &work.state.owner,
        )?;
        let local = staged.own_leaf_node().ok_or(Error::Policy)?;
        check_credential(
            local.credential(),
            local.signature_key().as_slice(),
            &work.state.local,
        )?;
        check_members(
            staged.members(),
            &checkpoint.roster.iter().collect::<Vec<_>>(),
        )?;
        staged.into_group(&work.provider).map_err(|_| Error::Mls)?;
        work.state.roster = checkpoint.roster.clone();
        work.state.base = checkpoint.parent;
        work.state.checkpoint = Some(packet.checkpoint.clone());
        work.state.phase = Phase::MemberJoined;
        work.state.joined = Some(id);
        advance(&mut work, &packet.control, now)?;
        let record = self.encrypt_record(
            RecordKey::Control(control_packet.floor()?.sequence()),
            &transport::RetainedControl::new(control_packet.control.clone(), None)?.encode()?,
        )?;
        self.publish(work, vec![record]).await?;
        self.needs_reopen = false;
        Ok(self.status)
    }

    /// Remove one exact current non-owner device. Same-account devices are not
    /// implicitly removed. The exact control and ciphertext commit together.
    pub async fn remove(
        &mut self,
        operation: OperationId,
        target: Key,
        now: u64,
    ) -> Result<CommittedOutbox> {
        let request = packets::request(self.context, OutboxKind::Removal, &[target.as_bytes()])?;
        let mut work = self.begin_live().await?;
        if let Some(retained) = self
            .retained(operation, request, OutboxKind::Removal, work.state.outbox)
            .await?
        {
            self.needs_reopen = false;
            return Ok(retained);
        }
        if !work.state.owner_role()
            || target == self.context.device
            || !work
                .state
                .roster
                .iter()
                .any(|e| e.claims().device == target)
        {
            return Err(Error::Policy);
        }
        work.state.check_time(now)?;
        let mut group = work.group()?;
        let index = group
            .members()
            .find(|m| m.signature_key.as_slice() == target.as_bytes())
            .ok_or(Error::Policy)?
            .index;
        group.set_aad(app_aad(self.context));
        let (commit, _, _) = group
            .remove_members(&work.provider, &work.signer()?, &[index])
            .map_err(|_| Error::Mls)?;
        check_remove(
            group.pending_commit().ok_or(Error::Mls)?,
            &work,
            &group,
            target,
        )?;
        let commit = wire(&commit)?;
        let control = control(
            &work,
            &commit,
            ControlChange::Membership {
                additions: Vec::new(),
                removals: vec![target],
            },
        )?;
        let packet = ControlPacket {
            control: control.clone(),
            commit,
            invitation: None,
            enrollment: None,
        };
        let output = transport::seal(&work, &group, &packet)?;
        group
            .merge_pending_commit(&work.provider)
            .map_err(|_| Error::Mls)?;
        work.state.roster.retain(|e| e.claims().device != target);
        advance(&mut work, &control, now)?;
        work.state.set_membership_phase();
        self.publish_sent_control(
            work,
            operation,
            request,
            OutboxKind::Removal,
            output.clone(),
            Some((&packet, &output)),
        )
        .await
    }

    /// Apply a strict confidential envelope for exactly the next owner control.
    /// Plaintext proof packets are never accepted by this input. Old ciphertext
    /// retries require exact retained bytes; a changed old envelope is not proof
    /// of an owner fork. Use observe_owner_control for signed fork evidence.
    pub async fn apply_control(&mut self, raw: &[u8], now: u64) -> Result<Status> {
        self.apply_envelope(raw, now, false).await
    }

    async fn apply_envelope(&mut self, raw: &[u8], now: u64, removal_only: bool) -> Result<Status> {
        let envelope = transport::Envelope::decode(raw)?;
        if removal_only && envelope.kind != 2 {
            return Err(Error::Policy);
        }
        let work = self.begin_live().await?;
        if now < work.state.clock {
            return Err(Error::Time);
        }
        if envelope.sequence <= work.state.floor.sequence() {
            if envelope.sequence <= encrypted_base(&work).sequence() {
                return Err(Error::Missing);
            }
            let retained = self.control_at(envelope.sequence).await?;
            if retained.envelope.as_deref() != Some(raw) {
                return Err(Error::Conflict);
            }
            self.needs_reopen = false;
            return Ok(self.status);
        }
        if work.state.phase != Phase::MemberJoined {
            return Err(Error::Policy);
        }
        let packet = transport::open(&work, &envelope)?;
        self.apply_control_packet(work, packet, raw, now).await
    }

    async fn apply_control_packet(
        &mut self,
        mut work: Working,
        packet: ControlPacket,
        envelope: &[u8],
        now: u64,
    ) -> Result<Status> {
        if work.state.phase != Phase::MemberJoined {
            return Err(Error::Policy);
        }
        if packet.control.claims().change == ControlChange::OwnerUpdate {
            return self.apply_owner_renewal(work, packet, envelope, now).await;
        }
        work.state.check_time(now)?;
        check_control(&work, &packet.control, &packet.commit)?;
        let mut group = work.group()?;
        let processed = process(&work, &mut group, &packet.commit)?;
        let sender = processed.sender().clone();
        let credential = processed.credential().clone();
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err(Error::Policy);
        };
        if member_sender(&work, &group, &sender, &credential, now)?
            != work.state.owner.claims().device
        {
            return Err(Error::Policy);
        }
        let mut roster = work.state.roster.clone();
        let removed = match &packet.control.claims().change {
            ControlChange::Membership {
                additions,
                removals,
            } if additions.len() == 1 && removals.is_empty() => {
                if roster.len() >= MAX_MEMBERS {
                    return Err(Error::Bounds);
                }
                let member = packet.enrollment.as_ref().ok_or(Error::Policy)?;
                if roster
                    .iter()
                    .any(|e| e.claims().device == member.claims().device)
                {
                    return Err(Error::Policy);
                }
                member.claims().validity.check_at(now)?;
                check_add(&staged, &work, member, additions[0].key_package)?;
                roster.push(member.clone());
                roster.sort_by_key(|e| e.claims().device);
                false
            }
            ControlChange::Membership {
                additions,
                removals,
            } if additions.is_empty() && removals.len() == 1 => {
                let target = removals[0];
                if target == work.state.owner.claims().device {
                    return Err(Error::Policy);
                }
                check_remove(&staged, &work, &group, target)?;
                let before = roster.len();
                roster.retain(|e| e.claims().device != target);
                if roster.len() + 1 != before {
                    return Err(Error::Policy);
                }
                target == self.context.device
            }
            _ => return Err(Error::Unsupported),
        };
        if staged.self_removed() != removed {
            return Err(Error::Policy);
        }
        group
            .merge_staged_commit(&work.provider, *staged)
            .map_err(|_| Error::Mls)?;
        work.state.roster = roster;
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

    /// Accept only a strict removal envelope; no plaintext or invitation fallback.
    pub async fn apply_removal(&mut self, raw: &[u8], now: u64) -> Result<Status> {
        self.apply_envelope(raw, now, true).await
    }
}

fn signature(work: &Working, bytes: &[u8]) -> Result<[u8; 64]> {
    work.signer()?
        .sign(bytes)
        .map_err(|_| Error::Mls)?
        .try_into()
        .map_err(|_| Error::Mls)
}
pub(super) fn control(
    work: &Working,
    commit: &[u8],
    change: ControlChange,
) -> Result<VerifiedOwnerControl> {
    let unsigned = UnsignedOwnerControl::new(OwnerControlClaims {
        scope: work.state.context().scope,
        owner_device: work.state.owner.claims().device,
        parent: work.state.floor,
        prior_epoch: work.state.epoch,
        next_epoch: work.state.epoch.checked_add(1).ok_or(Error::Bounds)?,
        commit: CommitDigest::of_bytes(commit)?,
        change,
    })?;
    Ok(unsigned
        .attach(signature(work, &unsigned.signing_bytes())?)?
        .verify()?)
}
pub(super) fn check_control(
    work: &Working,
    control: &VerifiedOwnerControl,
    commit: &[u8],
) -> Result<()> {
    let claims = control.claims();
    if claims.scope != work.state.context().scope
        || claims.owner_device != work.state.owner.claims().device
        || claims.parent != work.state.floor
        || claims.prior_epoch != work.state.epoch
        || claims.next_epoch != work.state.epoch.checked_add(1).ok_or(Error::Bounds)?
        || claims.commit != CommitDigest::of_bytes(commit)?
    {
        return Err(Error::Policy);
    }
    check_control_header(work.state.context().scope, control, commit)
}
fn check_control_header(
    scope: PrivateRoomScope,
    control: &VerifiedOwnerControl,
    commit: &[u8],
) -> Result<()> {
    let claims = control.claims();
    if claims.scope != scope || claims.commit != CommitDigest::of_bytes(commit)? {
        return Err(Error::Scope);
    }
    let frame = MlsMessageIn::tls_deserialize_exact(commit)
        .map_err(|_| Error::Encoding)?
        .try_into_protocol_message()
        .map_err(|_| Error::Encoding)?;
    if frame.wire_format() != WireFormat::PrivateMessage
        || frame.content_type() != ContentType::Commit
        || frame.group_id().as_slice() != scope.room.as_bytes()
        || frame.epoch().as_u64() != claims.prior_epoch
    {
        return Err(Error::Scope);
    }
    Ok(())
}
fn group_context_hash(context: &GroupContext) -> Result<[u8; 32]> {
    Ok(codec::hash(
        b"vhalla/private-kernel/group-context/v1\0",
        &wire(context)?,
    ))
}
pub(super) fn advance(work: &mut Working, control: &VerifiedOwnerControl, now: u64) -> Result<()> {
    work.state.floor = ControlFloor::new(control.claims().sequence()?, Some(control.id()))?;
    work.state.epoch = control.claims().next_epoch;
    work.state.clock = now;
    Ok(())
}
fn owner_path(staged: &StagedCommit, work: &Working) -> Result<()> {
    if staged.epoch().as_u64() != work.state.epoch.checked_add(1).ok_or(Error::Bounds)? {
        return Err(Error::Policy);
    }
    if let Some(leaf) = staged.update_path_leaf_node() {
        check_credential(
            leaf.credential(),
            leaf.signature_key().as_slice(),
            &work.state.owner,
        )?;
    }
    Ok(())
}
fn check_add(
    staged: &StagedCommit,
    work: &Working,
    member: &VerifiedDeviceEnrollment,
    key_package: KeyPackageDigest,
) -> Result<()> {
    owner_path(staged, work)?;
    let mut count = 0usize;
    for queued in staged.queued_proposals() {
        let Proposal::Add(add) = queued.proposal() else {
            return Err(Error::Policy);
        };
        if KeyPackageDigest::of_bytes(&wire(add.key_package())?)? != key_package {
            return Err(Error::Policy);
        }
        let leaf = add.key_package().leaf_node();
        check_credential(leaf.credential(), leaf.signature_key().as_slice(), member)?;
        count += 1;
    }
    if count != 1 {
        return Err(Error::Policy);
    }
    Ok(())
}
fn check_remove(
    staged: &StagedCommit,
    work: &Working,
    group: &MlsGroup,
    target: Key,
) -> Result<()> {
    owner_path(staged, work)?;
    let mut count = 0usize;
    for queued in staged.queued_proposals() {
        let Proposal::Remove(remove) = queued.proposal() else {
            return Err(Error::Policy);
        };
        let member = group
            .members()
            .find(|member| member.index == remove.removed())
            .ok_or(Error::Policy)?;
        if member.signature_key.as_slice() != target.as_bytes() {
            return Err(Error::Policy);
        }
        count += 1;
    }
    if count != 1 {
        return Err(Error::Policy);
    }
    Ok(())
}
