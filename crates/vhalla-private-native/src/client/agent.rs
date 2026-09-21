//! Preserve account custody when narrowing a trusted client to agent methods.
//!
//! This is a capability adapter, not an OS sandbox. A process with independent
//! filesystem, process, key or network access can bypass it. The host must keep
//! provider disclosure and execution policy outside this type.

use super::{Error, Result, RoomSession};
use crate::{
    agent::{AgentRoomSession, AgentStatus, DraftRef, LocalGrant, OutboxStatusPage, QueuedStatus},
    bridge::KernelStore,
};
use vhalla_identity::Identity;
use vhalla_private_kernel::{InboxPage, OperationId};

struct AgentCustody {
    // Room state and keys are dropped before account custody is released.
    session: AgentRoomSession<KernelStore>,
    _identity: Identity,
}

/// One account-owned fixed-room agent session.
///
/// Only the trusted host constructs this value by consuming a [`RoomSession`]
/// under a [`LocalGrant`]. It exposes bounded status, inbox, preparation, queue
/// and outbox metadata. It has no signer, kernel, store, ciphertext export,
/// membership mutation, relay or conversion back to a trusted client.
pub struct OwnedAgentRoomSession {
    custody: Option<AgentCustody>,
}

impl RoomSession {
    /// Consume this exact client and its account custody under an explicit grant.
    ///
    /// Locked, uncertain, expired, revoked or mismatched custody is refused.
    /// A failed conversion consumes the client and releases both handles; the
    /// host must explicitly reopen the retained identity and room state.
    pub fn into_agent(mut self, grant: LocalGrant) -> Result<OwnedAgentRoomSession> {
        self.status()?;
        let custody = self.custody.take().ok_or(Error::Locked)?;
        let session = AgentRoomSession::new(custody.kernel, grant).map_err(Error::Agent)?;
        Ok(OwnedAgentRoomSession {
            custody: Some(AgentCustody {
                session,
                _identity: custody.identity,
            }),
        })
    }
}

impl OwnedAgentRoomSession {
    fn live(&mut self) -> Result<&mut AgentRoomSession<KernelStore>> {
        Ok(&mut self.custody.as_mut().ok_or(Error::Locked)?.session)
    }

    /// Destroy room and account custody together. Previously returned plaintext
    /// cannot be retracted; the host must clear its own agent views as well.
    pub fn lock(&mut self) {
        drop(self.custody.take());
    }

    /// Whether this wrapper's complete custody lifetime has been destroyed.
    pub fn is_locked(&self) -> bool {
        self.custody.is_none()
    }

    /// Read bounded locally authenticated status.
    pub fn status(&mut self) -> Result<AgentStatus> {
        self.live()?.status().map_err(Error::Agent)
    }

    /// Read bounded inert plaintext only under the standing fixed-room grant.
    pub async fn inbox(&mut self, after: u64, limit: usize) -> Result<InboxPage> {
        self.live()?.inbox(after, limit).await.map_err(Error::Agent)
    }

    /// Prepare exact inert bytes for the grant's room, epoch and roster.
    pub fn prepare(&mut self, body: &[u8]) -> Result<DraftRef> {
        self.live()?.prepare(body).map_err(Error::Agent)
    }

    /// Queue a retained local draft and return metadata only.
    pub async fn queue(&mut self, operation: OperationId, draft: DraftRef) -> Result<QueuedStatus> {
        self.live()?
            .queue(operation, draft)
            .await
            .map_err(Error::Agent)
    }

    /// Read bounded local outbox metadata, never ciphertext or delivery status.
    pub async fn outbox_status(&mut self, after: u64, limit: usize) -> Result<OutboxStatusPage> {
        self.live()?
            .outbox_status(after, limit)
            .await
            .map_err(Error::Agent)
    }
}
