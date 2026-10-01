//! Two authority owners sharing the same delivery algorithm.
//!
//! The legacy host retains its one-use launch checks and metadata view. The
//! daemon host borrows room custody under a separately retained admin profile;
//! it neither creates an agent grant nor replaces the durable queue/kernel.

#[cfg(any(test, feature = "headless"))]
use super::KernelError;
use super::{ClientError, REFUSED};
use std::{future::Future, time::Instant};
#[cfg(any(test, feature = "headless"))]
use vhalla_private_kernel::OutboxEntry;
use vhalla_private_kernel::{
    CommittedOutbox, Context, EncryptedControlPage, MemberAcceptance, OperationId, OutboxPage,
    ReceivedMessage, Status,
};
use vhalla_private_native::{
    client::agent_rpc::RpcSession,
    relay::{delivery::JobStatus, RelayNamespace},
};
#[cfg(any(test, feature = "headless"))]
use vhalla_private_native::{
    client::RoomSession,
    relay::{delivery::JobState, RelayItem},
};

type Result<T> = std::result::Result<T, ClientError>;
pub(super) trait Host {
    fn begin(&mut self, context: Context) -> std::result::Result<Option<Instant>, String>;
    /// Validate native custody before recording completed local work. This
    /// does not authorize agent output or another operation under a closed grant.
    fn check_marker(&mut self) -> std::result::Result<(), String>;
    fn check_release(&mut self) -> std::result::Result<(), String>;
    fn status(&mut self) -> Result<Status>;
    fn outbox(&mut self, after: u64, limit: usize) -> impl Future<Output = Result<OutboxPage>>;
    fn encrypted_controls(
        &mut self,
        after: Option<u64>,
        limit: usize,
    ) -> impl Future<Output = Result<EncryptedControlPage>>;
    fn receive(&mut self, raw: &[u8]) -> impl Future<Output = Result<ReceivedMessage>>;
    fn apply_control(&mut self, raw: &[u8]) -> impl Future<Output = Result<Status>>;
    fn issue_acceptance(
        &mut self,
        operation: OperationId,
        raw: &[u8],
    ) -> impl Future<Output = Result<CommittedOutbox>>;
    fn retained_received(
        &mut self,
        raw: &[u8],
    ) -> impl Future<Output = Result<Option<ReceivedMessage>>>;
    fn retained_control(&mut self, raw: &[u8]) -> impl Future<Output = Result<bool>>;
    fn original(
        &mut self,
        hash: &[u8; 32],
    ) -> impl Future<Output = Result<Option<CommittedOutbox>>>;
    fn update_delivery(
        &mut self,
        namespace: RelayNamespace,
        status: &JobStatus,
    ) -> impl Future<Output = std::result::Result<(), String>>;
    fn record_member_acceptance(
        &mut self,
        sequence: u64,
        proof: MemberAcceptance,
    ) -> impl Future<Output = std::result::Result<(), String>>;
}

pub(super) struct RpcHost<'a>(&'a mut RpcSession);
impl<'a> RpcHost<'a> {
    pub(super) fn new(rpc: &'a mut RpcSession) -> Self {
        Self(rpc)
    }
}
impl Host for RpcHost<'_> {
    fn begin(&mut self, context: Context) -> std::result::Result<Option<Instant>, String> {
        self.0.ensure_claimed().map_err(|_| REFUSED)?;
        self.0.check_release().map_err(|_| REFUSED)?;
        if self.status().map_err(|_| REFUSED)?.context != context {
            return Err(REFUSED.into());
        }
        Ok(Some(self.0.deadline()))
    }
    fn check_marker(&mut self) -> std::result::Result<(), String> {
        // An accepted control may revoke the agent grant while leaving the
        // native commit healthy. Record that commit before check_release ends
        // the launch; locked or uncertain custody still cannot publish a marker.
        let agent = self.0.host().agent();
        if agent.is_locked() || agent.latched() {
            return Err(REFUSED.into());
        }
        Ok(())
    }
    fn check_release(&mut self) -> std::result::Result<(), String> {
        self.0.check_release().map_err(|_| REFUSED.into())
    }
    fn status(&mut self) -> Result<Status> {
        Ok(self.0.host().agent().status()?.accepted)
    }
    async fn outbox(&mut self, after: u64, limit: usize) -> Result<OutboxPage> {
        self.0.host().outbox(after, limit).await
    }
    async fn encrypted_controls(
        &mut self,
        after: Option<u64>,
        limit: usize,
    ) -> Result<EncryptedControlPage> {
        self.0.host().encrypted_controls(after, limit).await
    }
    async fn receive(&mut self, raw: &[u8]) -> Result<ReceivedMessage> {
        self.0.host().receive(raw).await
    }
    async fn apply_control(&mut self, raw: &[u8]) -> Result<Status> {
        self.0.host().apply_control(raw).await
    }
    async fn issue_acceptance(
        &mut self,
        operation: OperationId,
        raw: &[u8],
    ) -> Result<CommittedOutbox> {
        self.0.host().issue_acceptance(operation, raw).await
    }
    async fn retained_received(&mut self, raw: &[u8]) -> Result<Option<ReceivedMessage>> {
        self.0.host().retained_received(raw).await
    }
    async fn retained_control(&mut self, raw: &[u8]) -> Result<bool> {
        self.0.host().retained_control(raw).await
    }
    async fn original(&mut self, hash: &[u8; 32]) -> Result<Option<CommittedOutbox>> {
        self.0.host().original(hash).await
    }
    async fn update_delivery(
        &mut self,
        namespace: RelayNamespace,
        status: &JobStatus,
    ) -> std::result::Result<(), String> {
        self.0
            .update_delivery(namespace, status)
            .await
            .map_err(|_| REFUSED.into())
    }
    async fn record_member_acceptance(
        &mut self,
        sequence: u64,
        proof: MemberAcceptance,
    ) -> std::result::Result<(), String> {
        self.0
            .record_member_acceptance(sequence, proof)
            .await
            .map_err(|_| REFUSED.into())
    }
}

#[cfg(any(test, feature = "headless"))]
pub(super) struct RoomHost<'a> {
    room: &'a mut RoomSession,
    context: Option<Context>,
    // A retained read can fail authentication without setting the kernel's
    // publication latch. Preserve that origin before the shared driver reduces
    // errors to strings or classifies malformed peer input as skippable.
    native_unavailable: bool,
}
#[cfg(any(test, feature = "headless"))]
impl<'a> RoomHost<'a> {
    pub(super) fn new(room: &'a mut RoomSession) -> Self {
        Self {
            room,
            context: None,
            native_unavailable: false,
        }
    }

    pub(super) fn native_unavailable(&self) -> bool {
        self.native_unavailable
    }

    fn native_status(&mut self) -> Result<Status> {
        let result = self.room.status();
        self.native_unavailable |= result.is_err();
        result
    }

    fn checked(&mut self) -> Result<Status> {
        if self.native_unavailable {
            return Err(KernelError::NeedsReopen.into());
        }
        let status = self.native_status()?;
        if self.context != Some(status.context) {
            return Err(KernelError::Scope.into());
        }
        Ok(status)
    }

    fn native_result<T>(&mut self, result: Result<T>) -> Result<T> {
        if result.is_err() {
            self.native_unavailable = true;
        } else {
            self.checked()?;
        }
        result
    }

    fn peer_result<T>(&mut self, result: Result<T>) -> Result<T> {
        if matches!(
            &result,
            Err(ClientError::Locked)
                | Err(ClientError::Storage(
                    vhalla_private_kernel::storage::StoreError::Uncertain
                        | vhalla_private_kernel::storage::StoreError::Corrupt
                ))
                | Err(ClientError::Kernel(KernelError::NeedsReopen))
        ) {
            self.native_unavailable = true;
        }
        // A failed publication can return its original error while the kernel
        // independently requires reopen. Inspect that latch after every result.
        let status = self.native_status();
        result.and_then(|value| status.map(|_| value))
    }

    async fn authenticated_status(&mut self) -> Result<Status> {
        let result = self.room.membership().await;
        self.native_result(result).map(|snapshot| snapshot.status())
    }

    async fn artifact(&mut self, sequence: u64) -> std::result::Result<CommittedOutbox, String> {
        self.checked().map_err(|_| REFUSED)?;
        let after = sequence.checked_sub(1).ok_or(REFUSED)?;
        let page = self.outbox(after, 1).await.map_err(|_| REFUSED)?;
        match page.records.into_iter().next() {
            Some(OutboxEntry::Artifact(original)) if original.sequence() == sequence => {
                Ok(original)
            }
            _ => Err(REFUSED.into()),
        }
    }
}
#[cfg(any(test, feature = "headless"))]
impl Host for RoomHost<'_> {
    fn begin(&mut self, context: Context) -> std::result::Result<Option<Instant>, String> {
        if self.native_unavailable
            || self.native_status().map_err(|_| REFUSED)?.context != context
            || self.context.is_some_and(|prior| prior != context)
        {
            return Err(REFUSED.into());
        }
        self.context = Some(context);
        Ok(None)
    }
    fn check_marker(&mut self) -> std::result::Result<(), String> {
        self.checked().map(|_| ()).map_err(|_| REFUSED.into())
    }
    fn check_release(&mut self) -> std::result::Result<(), String> {
        self.checked().map(|_| ()).map_err(|_| REFUSED.into())
    }
    fn status(&mut self) -> Result<Status> {
        self.checked()
    }
    async fn outbox(&mut self, after: u64, limit: usize) -> Result<OutboxPage> {
        self.checked()?;
        // Queue cursors are separate selected-source state. Authenticate the
        // exact native image first, then distinguish an invalid cursor from a
        // failed retained read. Live native rollback still latches the kernel.
        let status = self.authenticated_status().await?;
        if after > status.outbox_head
            || limit == 0
            || limit > vhalla_private_kernel::MAX_PAGE_RECORDS
        {
            return Err(KernelError::Bounds.into());
        }
        let result = self.room.outbox(after, limit).await;
        self.native_result(result)
    }
    async fn encrypted_controls(
        &mut self,
        after: Option<u64>,
        limit: usize,
    ) -> Result<EncryptedControlPage> {
        self.checked()?;
        // The encrypted history base may be later than Status::history_base.
        // Read it from native custody rather than trusting a queue watermark.
        let result = self.room.encrypted_controls_from(None, 1).await;
        let first = self.native_result(result)?;
        if limit == 0
            || limit > vhalla_private_kernel::MAX_PAGE_RECORDS
            || after.is_some_and(|cursor| cursor > first.head.sequence())
        {
            return Err(KernelError::Bounds.into());
        }
        if after.is_some_and(|cursor| cursor < first.base.sequence()) {
            return Err(KernelError::Missing.into());
        }
        if after.is_none() && limit == 1 {
            return Ok(first);
        }
        let result = self.room.encrypted_controls_from(after, limit).await;
        self.native_result(result)
    }
    async fn receive(&mut self, raw: &[u8]) -> Result<ReceivedMessage> {
        self.checked()?;
        let result = self.room.receive(raw).await;
        let result = self.peer_result(result);
        if result.is_err()
            && !self.native_unavailable
            && !raw.is_empty()
            && raw.len() <= vhalla_private_kernel::MAX_WIRE_BYTES
        {
            // The same Authentication/Encoding error can come from the peer
            // frame or its retained receive index. Reauthenticate only that
            // local evidence before the driver may classify the frame.
            let _ = self.retained_received(raw).await;
        }
        result
    }
    async fn apply_control(&mut self, raw: &[u8]) -> Result<Status> {
        self.checked()?;
        vhalla_private_kernel::control_sequence_hint(raw)?;
        let result = self.room.apply_control(raw).await;
        let result = self.peer_result(result);
        if result.is_err() && !self.native_unavailable {
            let _ = self.retained_control(raw).await;
        }
        result
    }
    async fn issue_acceptance(
        &mut self,
        operation: OperationId,
        raw: &[u8],
    ) -> Result<CommittedOutbox> {
        self.checked()?;
        // Receipt issuance is internal, but the raw argument is still only a
        // lookup until its existing native receive has been authenticated.
        let received = self
            .retained_received(raw)
            .await?
            .ok_or(KernelError::Missing)?;
        if MemberAcceptance::is_receipt(received.body()) {
            return Err(KernelError::Policy.into());
        }
        let result = self.room.issue_acceptance(operation, raw).await;
        if matches!(
            &result,
            Err(ClientError::Kernel(
                KernelError::Authentication | KernelError::Encoding | KernelError::Scope
            ))
        ) {
            self.native_unavailable = true;
        }
        self.peer_result(result)
    }
    async fn retained_received(&mut self, raw: &[u8]) -> Result<Option<ReceivedMessage>> {
        self.checked()?;
        if raw.is_empty() || raw.len() > vhalla_private_kernel::MAX_WIRE_BYTES {
            return Err(KernelError::Bounds.into());
        }
        let result = self.room.retained_received(raw).await;
        self.native_result(result)
    }
    async fn retained_control(&mut self, raw: &[u8]) -> Result<bool> {
        self.checked()?;
        // Framing is untrusted input. Once it parses, this method only reads
        // native history; a nonmatching valid envelope returns false, not error.
        vhalla_private_kernel::control_sequence_hint(raw)?;
        let result = self.room.retained_control(raw).await;
        self.native_result(result)
    }
    async fn original(&mut self, hash: &[u8; 32]) -> Result<Option<CommittedOutbox>> {
        self.checked()?;
        if *hash == [0; 32] {
            return Err(KernelError::Encoding.into());
        }
        let result = self.room.original(hash).await;
        self.native_result(result)
    }
    async fn update_delivery(
        &mut self,
        namespace: RelayNamespace,
        status: &JobStatus,
    ) -> std::result::Result<(), String> {
        if status.sequence == 0
            || status.attempts > 100
            || (status.state == JobState::Retained) != status.position.is_some()
            || status.position == Some(0)
            || (status.state == JobState::Retained && status.uncertain)
            || (status.state == JobState::Uncertain && !status.uncertain)
        {
            return Err(REFUSED.into());
        }
        let original = self.artifact(status.sequence).await?;
        let item = RelayItem::from_artifact(namespace, &original).map_err(|_| REFUSED)?;
        if original.operation() != status.operation || item.digest() != status.id {
            return Err(REFUSED.into());
        }
        // No second metadata cache: the queue is the daemon's durable relay
        // evidence, and the kernel holds independently verified receptions.
        Ok(())
    }
    async fn record_member_acceptance(
        &mut self,
        sequence: u64,
        proof: MemberAcceptance,
    ) -> std::result::Result<(), String> {
        let original = self.artifact(sequence).await?;
        let context = self.checked().map_err(|_| REFUSED)?.context;
        if !proof.matches_original(context, &original) {
            return Err(REFUSED.into());
        }
        // The driver has received and verified this claim in kernel custody.
        // Reports read the kernel's durable index instead of adding a new log.
        Ok(())
    }
}
