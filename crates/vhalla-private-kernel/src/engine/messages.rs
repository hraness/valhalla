use openmls::framing::errors::{MessageDecryptionError, SecretTreeError};
use openmls::prelude::*;
use openmls_memory_storage::MemoryStorageError;
use tls_codec::Deserialize as _;

use super::*;
use crate::Error;
use crate::{
    model::{app_aad, check_credential},
    packets,
};

impl<S: Store> Kernel<S> {
    /// Bind an explicit message release to the currently observed private room,
    /// author, epoch and complete roster. The send transaction rechecks every
    /// binding against retained state before encrypting. This method performs no
    /// storage/network write and does not automatically renew stale consent.
    pub fn prepare_message(&self, body: &[u8]) -> Result<MessageDraft> {
        if self.needs_reopen {
            return Err(Error::NeedsReopen);
        }
        if self.status.quarantined {
            return Err(Error::Quarantined);
        }
        if matches!(self.status.phase, Phase::AwaitingWelcome | Phase::Removed) {
            return Err(Error::Policy);
        }
        if body.is_empty() || body.len() > MAX_BODY_BYTES {
            return Err(Error::Bounds);
        }
        Ok(MessageDraft {
            context: self.context,
            epoch: self.status.epoch,
            roster: self.status.roster,
            body: Zeroizing::new(body.to_vec()),
        })
    }
    /// Encrypt an application message and publish its exact retryable ciphertext
    /// with the advanced sender ratchet before returning it. This is local durable
    /// outbox publication, not transport delivery or remote receipt.
    pub async fn send(
        &mut self,
        operation: OperationId,
        draft: &MessageDraft,
        now: u64,
    ) -> Result<CommittedOutbox> {
        if draft.context != self.context {
            return Err(Error::Scope);
        }
        let request = packets::request(
            self.context,
            OutboxKind::Application,
            &[&draft.epoch.to_be_bytes(), &draft.roster, &draft.body],
        )?;
        let mut work = self.begin_live().await?;
        if let Some(retained) = self
            .retained(
                operation,
                request,
                OutboxKind::Application,
                work.state.outbox,
            )
            .await?
        {
            return Ok(retained);
        }
        if matches!(work.state.phase, Phase::AwaitingWelcome | Phase::Removed) {
            return Err(Error::Policy);
        }
        if draft.epoch != work.state.epoch || draft.roster != work.state.roster_digest() {
            return Err(Error::Conflict);
        }
        work.state.check_time(now)?;
        let mut group = work.group()?;
        group.set_aad(app_aad(self.context));
        let message = group
            .create_message(&work.provider, &work.signer()?, &draft.body)
            .map_err(|_| Error::Mls)?;
        let bytes = wire(&message)?;
        work.state.clock = now;
        self.publish_sent(work, operation, request, OutboxKind::Application, bytes)
            .await
    }

    /// Decrypt only current-epoch authenticated member application content.
    /// Plaintext remains quarantined until its encrypted inbox record and changed
    /// receiver ratchet commit together. Exact retained retries read history only.
    pub async fn receive(&mut self, raw: &[u8], now: u64) -> Result<ReceivedMessage> {
        bounded_wire(raw)?;
        let mut work = self.begin_live().await?;
        if let Some(retained) = self.received(raw, work.state.inbox).await? {
            return Ok(retained);
        }
        if !matches!(work.state.phase, Phase::OwnerJoined | Phase::MemberJoined) {
            return Err(Error::Policy);
        }
        work.state.check_time(now)?;
        let mut group = work.group()?;
        let processed = process(&work, &mut group, raw)?;
        let sender = processed.sender().clone();
        let credential = processed.credential().clone();
        // OwnPrivateMessage carries an unauthenticated sender claim. No sender
        // authorization or plaintext release may occur for any other variant.
        let ProcessedMessageContent::ApplicationMessage(message) = processed.into_content() else {
            return Err(Error::Policy);
        };
        let sender = member_sender(&work, &group, &sender, &credential, now)?;
        if sender == self.context.device {
            return Err(Error::Policy);
        }
        let body = message.into_bytes();
        if body.is_empty() || body.len() > MAX_BODY_BYTES {
            return Err(Error::Bounds);
        }
        work.state.clock = now;
        self.publish_received(work, raw, sender, body).await
    }
}

pub(super) fn bounded_wire(raw: &[u8]) -> Result<()> {
    if raw.is_empty() || raw.len() > MAX_WIRE_BYTES {
        return Err(Error::Bounds);
    }
    Ok(())
}
pub(super) fn wire(value: &impl tls_codec::Serialize) -> Result<Vec<u8>> {
    // MLS structures are already bounded by our input/group limits, but do not
    // clone or publish a frame whose exact serialized length exceeds the cap.
    if value.tls_serialized_len() > MAX_WIRE_BYTES {
        return Err(Error::Bounds);
    }
    let bytes = value
        .tls_serialize_detached()
        .map_err(|_| Error::Encoding)?;
    bounded_wire(&bytes)?;
    Ok(bytes)
}
pub(super) fn process(
    work: &Working,
    group: &mut MlsGroup,
    raw: &[u8],
) -> Result<ProcessedMessage> {
    bounded_wire(raw)?;
    let message = MlsMessageIn::tls_deserialize_exact(raw)
        .map_err(|_| Error::Encoding)?
        .try_into_protocol_message()
        .map_err(|_| Error::Encoding)?;
    if message.group_id().as_slice() != work.state.context().scope.room.as_bytes() {
        return Err(Error::Scope);
    }
    // Epoch mismatches are typed for drivers: an older epoch is permanently
    // undecryptable here, a newer one needs the pending control applied first.
    // Neither is a foreign-room or tampering signal.
    match message.epoch().as_u64().cmp(&work.state.epoch) {
        core::cmp::Ordering::Less => return Err(Error::StaleEpoch),
        core::cmp::Ordering::Greater => return Err(Error::FutureEpoch),
        core::cmp::Ordering::Equal => {}
    }
    let processed = group
        .process_message(&work.provider, message)
        .map_err(process_error)?;
    if processed.group_id().as_slice() != work.state.context().scope.room.as_bytes()
        || processed.epoch().as_u64() != work.state.epoch
        || processed.aad() != app_aad(work.state.context())
    {
        return Err(Error::Scope);
    }
    Ok(processed)
}
/// Map only typed delivery-gap conditions out of the MLS error surface.
/// Everything else stays a generic refusal: drivers may skip the exact item,
/// but no ratchet/epoch interpretation is claimed for untyped failures.
fn process_error(error: ProcessMessageError<MemoryStorageError>) -> Error {
    match error {
        ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
            MessageDecryptionError::SecretTreeError(SecretTreeError::TooDistantInThePast),
        ))
        | ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
            MessageDecryptionError::SecretTreeError(SecretTreeError::SecretReuseError),
        ))
        | ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
            MessageDecryptionError::GenerationOutOfBound,
        )) => Error::RatchetGap { past: true },
        ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
            MessageDecryptionError::SecretTreeError(SecretTreeError::TooDistantInTheFuture),
        )) => Error::RatchetGap { past: false },
        _ => Error::Mls,
    }
}
pub(super) fn member_sender(
    work: &Working,
    group: &MlsGroup,
    sender: &Sender,
    credential: &Credential,
    now: u64,
) -> Result<protocol::Key> {
    let Sender::Member(index) = sender else {
        return Err(Error::Policy);
    };
    let member = group
        .members()
        .find(|member| member.index == *index)
        .ok_or(Error::Policy)?;
    let expected = work.expected_members()?;
    let enrollment = expected
        .into_iter()
        .find(|record| record.claims().device.as_bytes() == member.signature_key.as_slice())
        .ok_or(Error::Policy)?;
    check_credential(&member.credential, &member.signature_key, enrollment)?;
    check_credential(credential, &member.signature_key, enrollment)?;
    enrollment.claims().validity.check_at(now)?;
    Ok(enrollment.claims().device)
}
