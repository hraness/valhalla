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
use vhalla_private_kernel::{
    CommittedOutbox, InboxPage, OperationId, OutboxPage, ReceivedMessage, Status,
};

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
    /// Construct the trusted host's delivery facet before narrowing agent access.
    /// This is not an agent tool constructor and grants no network destination.
    pub fn into_agent_host(self, grant: LocalGrant) -> Result<AgentHostSession> {
        Ok(AgentHostSession {
            agent: self.into_agent(grant)?,
        })
    }
    /// Consume this exact client and its account custody under an explicit grant.
    ///
    /// Locked, uncertain, expired, revoked or mismatched custody is refused.
    /// A failed conversion consumes the client and releases both handles; the
    /// host must explicitly reopen the retained identity and room state.
    pub fn into_agent(mut self, grant: LocalGrant) -> Result<OwnedAgentRoomSession> {
        self.status()?;
        if self.live()?.delivery_paused {
            return Err(vhalla_private_kernel::storage::StoreError::Refused.into());
        }
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

/// Trusted controller for delivery under the same exclusive account/room owner.
///
/// Register only [`Self::agent`]'s five methods with the agent. The separate host
/// methods accept authenticated encrypted inputs and page retained artifacts for
/// an independently authorized relay. They expose no key, signer or arbitrary
/// membership mutation. A control changing epoch/roster revokes the agent grant;
/// the host may still reconcile already committed delivery before dropping it.
pub struct AgentHostSession {
    agent: OwnedAgentRoomSession,
}
impl AgentHostSession {
    /// Read-only exact reception evidence for durable driver-marker recovery.
    pub async fn retained_received(&mut self, raw: &[u8]) -> Result<Option<ReceivedMessage>> {
        self.agent
            .live()?
            .host_retained_received(raw)
            .await
            .map_err(Error::Agent)
    }
    /// Read-only exact control evidence; never applies a new owner transition.
    pub async fn retained_control(&mut self, raw: &[u8]) -> Result<bool> {
        self.agent
            .live()?
            .host_retained_control(raw)
            .await
            .map_err(Error::Agent)
    }
    /// Host-only exact encrypted control suffix, including admission controls.
    /// `None` selects authenticated retained history, never a remote checkpoint.
    /// This grants no membership mutation and is never registered as an MCP tool.
    pub async fn encrypted_controls(
        &mut self,
        after: Option<u64>,
        limit: usize,
    ) -> Result<vhalla_private_kernel::EncryptedControlPage> {
        self.agent
            .live()?
            .host_encrypted_controls(after, limit)
            .await
            .map_err(Error::Agent)
    }

    /// Borrow only the fixed-room agent surface.
    pub fn agent(&mut self) -> &mut OwnedAgentRoomSession {
        &mut self.agent
    }
    /// Host-only retained output; eligibility/destination must be checked by the
    /// separately authorized relay controller. Never expose this as an RPC tool.
    pub async fn outbox(&mut self, after: u64, limit: usize) -> Result<OutboxPage> {
        self.agent
            .live()?
            .host_outbox(after, limit)
            .await
            .map_err(Error::Agent)
    }
    /// Host-only encrypted application delivery. Content remains inert.
    pub async fn receive(&mut self, raw: &[u8]) -> Result<ReceivedMessage> {
        self.agent
            .live()?
            .host_receive(raw)
            .await
            .map_err(Error::Agent)
    }
    /// Host-only device-signed durable reception claim for one exact retained
    /// application ciphertext. Never signs caller-selected plaintext or another
    /// receipt. Retain the operation ID for exact reconciliation after uncertainty.
    /// This does not assert physical disk honesty, human reading or delivery.
    pub async fn issue_acceptance(
        &mut self,
        operation: OperationId,
        original_ciphertext: &[u8],
    ) -> Result<CommittedOutbox> {
        self.agent
            .live()?
            .host_issue_acceptance(operation, original_ciphertext)
            .await
            .map_err(Error::Agent)
    }
    /// Host-only strict authenticated encrypted control delivery. An authority
    /// change revokes the agent before any subsequent output is released.
    pub async fn apply_control(&mut self, raw: &[u8]) -> Result<Status> {
        self.agent
            .live()?
            .host_apply_control(raw)
            .await
            .map_err(Error::Agent)
    }
    /// Host-only durable lookup of one committed send by exact ciphertext
    /// commitment. The kernel sent index answers without replaying the outbox.
    pub async fn original(
        &mut self,
        ciphertext_hash: &[u8; 32],
    ) -> Result<Option<CommittedOutbox>> {
        self.agent
            .live()?
            .host_original(ciphertext_hash)
            .await
            .map_err(Error::Agent)
    }
    /// Host-only durable verified member acceptances for one committed outbox
    /// position, restored from the kernel's receipt index after any restart.
    pub async fn acceptances(
        &mut self,
        outbox_sequence: u64,
    ) -> Result<Vec<vhalla_private_kernel::MemberAcceptance>> {
        self.agent
            .live()?
            .host_acceptances(outbox_sequence)
            .await
            .map_err(Error::Agent)
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

    /// Whether live custody is latched by an uncertain operation. A latched
    /// session refuses data operations but still answers, so a transport can
    /// deliver the refusal instead of closing without a reply.
    pub fn latched(&self) -> bool {
        self.custody
            .as_ref()
            .is_some_and(|custody| custody.session.latched())
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
