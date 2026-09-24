//! Trusted native private-room controller with one explicit custody lifetime.
//!
//! This API is for a local client, not an agent tool surface. It can return room
//! metadata, plaintext inbox messages and retained encrypted artifacts. Agents
//! must use the narrower fixed-room grant API. No operation here opens a network
//! connection or interprets room content as executable instructions.

use crate::{bridge::KernelStore, private_rooms::Limits};
use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use vhalla_identity::Identity;
use vhalla_private_kernel::{
    protocol::{
        Key, OwnerSuccessionProof, PrivateRoomScope, SignedDeviceEnrollment, SignedRoomAnchor,
        Validity,
    },
    storage::StoreError,
    CommittedOutbox, ConfidentialContactOffer, ContactBootstrap, Context, ControlPage,
    EncryptedControlPage, ForkEvidence, InboxPage, Kernel, MemberDraft, MembershipSnapshot,
    MessageDraft, OperationId, OutboxPage, OwnerDraft, ReceivedMessage, Status,
};

#[cfg(feature = "client")]
pub mod agent;

/// Private drained mailbox-generation evidence and controller maintenance.
pub mod generation;

/// Bounded, fixed-grant MCP adapter for cooperating native agent hosts.
#[cfg(feature = "agent-rpc")]
pub mod agent_rpc;

/// Closed local failures; errors contain no key, password, message or path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Lock destroyed both account and room custody. Open explicitly to continue.
    Locked,
    /// No valid system clock. Never substitute a caller or peer supplied clock.
    Clock,
    /// Typed account/device claim validation failed before publication.
    Protocol(vhalla_private_kernel::protocol::Error),
    /// Exact native namespace creation or recovery failed; preserve the store.
    Storage(StoreError),
    /// Room verification or publication refused; uncertainty requires reopen.
    Kernel(vhalla_private_kernel::Error),
    /// The fixed-room agent boundary refused the exact grant or operation.
    Agent(crate::agent::Error),
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
impl From<vhalla_private_kernel::Error> for Error {
    fn from(value: vhalla_private_kernel::Error) -> Self {
        Self::Kernel(value)
    }
}
impl From<vhalla_private_kernel::protocol::Error> for Error {
    fn from(value: vhalla_private_kernel::protocol::Error) -> Self {
        Self::Protocol(value)
    }
}
impl From<StoreError> for Error {
    fn from(value: StoreError) -> Self {
        Self::Storage(value)
    }
}
impl From<crate::agent::Error> for Error {
    fn from(value: crate::agent::Error) -> Self {
        Self::Agent(value)
    }
}
type Result<T> = std::result::Result<T, Error>;
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| Error::Clock)
}

enum Draft {
    Owner(Box<OwnerDraft>),
    Member(Box<MemberDraft>),
}

/// Unpublished, move-only creation. Inspect and retain its exact context before
/// commit. Consuming it never means recovery of a previous device or ratchet.
/// Dropping it destroys unpublished device and account custody.
pub struct RoomCreation {
    identity: Identity,
    draft: Draft,
    context: Context,
    enrollment: SignedDeviceEnrollment,
    anchor: SignedRoomAnchor,
}
impl RoomCreation {
    /// Prepare a fresh random owner device and room under this exact account.
    /// The caller authorizes creation and selects the half-open validity interval.
    pub fn owner(identity: Identity, validity: Validity) -> Result<Self> {
        validity.check_at(now()?)?;
        let draft = OwnerDraft::new(Key::from_bytes(identity.public_key())?, validity)?;
        let enrollment = identity.sign_private_enrollment(draft.enrollment_request())?;
        let anchor = identity.sign_private_anchor(draft.anchor_request())?;
        let context = draft.context(&anchor)?;
        Ok(Self {
            identity,
            draft: Draft::Owner(Box::new(draft)),
            context,
            enrollment,
            anchor,
        })
    }

    /// Prepare an explicitly invited fresh member under an independently selected
    /// full room anchor. Restoring an account never recreates an old device.
    pub fn member(
        identity: Identity,
        scope: PrivateRoomScope,
        anchor: SignedRoomAnchor,
        owner: SignedDeviceEnrollment,
        validity: Validity,
    ) -> Result<Self> {
        let draft = MemberDraft::new(
            scope,
            anchor.clone(),
            owner,
            Key::from_bytes(identity.public_key())?,
            validity,
            now()?,
        )?;
        Self::member_checked(identity, anchor, draft)
    }

    /// Prepare an explicitly invited fresh member after owner handoffs: the
    /// exact predecessor-authorized control chain must prove `owner` against `anchor`. An empty
    /// or stale chain is refused; it never downgrades to the anchor device.
    pub fn member_succeeded(
        identity: Identity,
        scope: PrivateRoomScope,
        anchor: SignedRoomAnchor,
        owner: SignedDeviceEnrollment,
        successions: Vec<OwnerSuccessionProof>,
        validity: Validity,
    ) -> Result<Self> {
        let draft = MemberDraft::new_succeeded(
            scope,
            anchor.clone(),
            owner,
            successions,
            Key::from_bytes(identity.public_key())?,
            validity,
            now()?,
        )?;
        Self::member_checked(identity, anchor, draft)
    }

    fn member_checked(
        identity: Identity,
        anchor: SignedRoomAnchor,
        draft: MemberDraft,
    ) -> Result<Self> {
        let enrollment = identity.sign_private_enrollment(draft.enrollment_request())?;
        let context = draft.context();
        Ok(Self {
            identity,
            draft: Draft::Member(Box::new(draft)),
            context,
            enrollment,
            anchor,
        })
    }

    /// Prepare a fresh member from one complete confidential owner-signed offer.
    /// The caller independently selects the owner account and reviews the signed
    /// room before committing. This does not contact a relay or join the room.
    pub fn from_contact(
        identity: Identity,
        offer: &[u8],
        expected_owner: Key,
        validity: Validity,
    ) -> Result<Self> {
        let bootstrap = ContactBootstrap::inspect(
            offer,
            expected_owner,
            Key::from_bytes(identity.public_key())?,
            now()?,
        )?;
        let successions = bootstrap.successions();
        if successions.is_empty() {
            Self::member(
                identity,
                bootstrap.scope(),
                bootstrap.anchor().clone(),
                bootstrap.owner().clone(),
                validity,
            )
        } else {
            Self::member_succeeded(
                identity,
                bootstrap.scope(),
                bootstrap.anchor().clone(),
                bootstrap.owner().clone(),
                successions,
                validity,
            )
        }
    }

    /// Retain this exact nonsecret locator before consuming commit. It does not
    /// authorize state recreation after a failed or canceled initialization.
    pub const fn context(&self) -> Context {
        self.context
    }

    /// Exact newly signed anchor; private metadata, never public discovery data.
    pub fn anchor(&self) -> &SignedRoomAnchor {
        &self.anchor
    }

    /// Exact fresh local enrollment, not proof that a member was admitted.
    pub fn enrollment(&self) -> &SignedDeviceEnrollment {
        &self.enrollment
    }

    /// Persist a never-used private namespace and device before returning a live
    /// session. FORMAT retains the full context before device publication. Partial
    /// initialization stays preserved; never retry by deleting or resetting it.
    /// Run on a native worker: SQLite/filesystem barriers block within one poll.
    pub async fn commit(self, path: impl AsRef<Path>, limits: Limits) -> Result<RoomSession> {
        let key = self.identity.private_storage_key(self.context)?;
        let time = now()?;
        self.enrollment.claims().validity.check_at(time)?;
        let store = KernelStore::create_new(path, self.context, limits)?;
        let kernel = match self.draft {
            Draft::Owner(draft) => {
                draft
                    .create(store, &key, self.enrollment, self.anchor, time)
                    .await?
            }
            Draft::Member(draft) => draft.initialize(store, &key, self.enrollment, time).await?,
        };
        Ok(RoomSession {
            custody: Some(Custody {
                kernel,
                identity: self.identity,
                delivery_paused: false,
            }),
        })
    }
}

struct Custody {
    // Drop the room key/state/store before releasing the account custody lock.
    kernel: Kernel<KernelStore>,
    identity: Identity,
    delivery_paused: bool,
}

/// One exact room/device with account and kernel custody owned together.
/// There is no raw key, generic signer, kernel accessor, clone or state-import API.
/// Lock/drop destroys both handles; account-only lock cannot leave this kernel live.
pub struct RoomSession {
    custody: Option<Custody>,
}
impl RoomSession {
    /// Explicitly recover the exact existing context. Wrong account is refused
    /// before opening the backend. Missing state never falls back to creation.
    pub async fn open(
        identity: Identity,
        path: impl AsRef<Path>,
        context: Context,
    ) -> Result<Self> {
        let key = identity.private_storage_key(context)?;
        let store = KernelStore::open(path, context)?;
        let delivery_paused = store.delivery_is_paused()?;
        let kernel = Kernel::open(store, &key, context).await?;
        Ok(Self {
            custody: Some(Custody {
                kernel,
                identity,
                delivery_paused,
            }),
        })
    }

    /// Destroy account and room custody together. Previously returned plaintext
    /// cannot be retracted; the client must clear its own views and draft buffers.
    /// Cancel/drop an outstanding borrowed operation before calling lock.
    pub fn lock(&mut self) {
        drop(self.custody.take());
    }

    /// Whether this controller has destroyed its entire custody lifetime.
    pub fn is_locked(&self) -> bool {
        self.custody.is_none()
    }

    fn live(&self) -> Result<&Custody> {
        self.custody.as_ref().ok_or(Error::Locked)
    }
    fn live_mut(&mut self) -> Result<&mut Custody> {
        self.custody.as_mut().ok_or(Error::Locked)
    }

    /// Last authenticated local status; refuse an interrupted/stale kernel.
    pub fn status(&self) -> Result<Status> {
        let kernel = &self.live()?.kernel;
        if kernel.needs_reopen() {
            return Err(vhalla_private_kernel::Error::NeedsReopen.into());
        }
        Ok(kernel.status())
    }

    /// Reauthenticate complete recipient/account/device metadata before display.
    pub async fn membership(&mut self) -> Result<MembershipSnapshot> {
        Ok(self.live_mut()?.kernel.membership().await?)
    }

    /// Prepare the exact user-selected content for the current room and roster.
    /// No membership change may silently renew this disclosure decision.
    pub fn prepare_message(&self, body: &[u8]) -> Result<MessageDraft> {
        if self.live()?.delivery_paused {
            return Err(StoreError::Refused.into());
        }
        Ok(self.live()?.kernel.prepare_message(body)?)
    }

    /// Commit exact prepared content; returning ciphertext is not network delivery.
    pub async fn send(
        &mut self,
        operation: OperationId,
        draft: &MessageDraft,
    ) -> Result<CommittedOutbox> {
        let time = now()?;
        Ok(self.live_mut()?.kernel.send(operation, draft, time).await?)
    }

    /// Admit one encrypted application frame; plaintext is returned only after
    /// durable publication. Message content remains inert and untrusted.
    pub async fn receive(&mut self, raw: &[u8]) -> Result<ReceivedMessage> {
        let time = now()?;
        Ok(self.live_mut()?.kernel.receive(raw, time).await?)
    }

    /// Trusted host-only signed reception claim for an already committed inbox
    /// ciphertext. Exact retries return the retained receipt under the same
    /// operation; another receipt can never be acknowledged. This is a device
    /// claim, not proof of disk honesty, human reading or network delivery.
    pub async fn issue_acceptance(
        &mut self,
        operation: OperationId,
        original_ciphertext: &[u8],
    ) -> Result<CommittedOutbox> {
        let time = now()?;
        Ok(self
            .live_mut()?
            .kernel
            .issue_acceptance(operation, original_ciphertext, time)
            .await?)
    }

    /// Bounded retained plaintext history for the trusted client's selected room.
    pub async fn inbox(&mut self, after: u64, limit: usize) -> Result<InboxPage> {
        Ok(self.live_mut()?.kernel.inbox(after, limit).await?)
    }

    /// Bounded exact local artifacts, not permission to publish them. Bootstrap
    /// kinds may contain private metadata and require confidential transfer.
    /// Secret contact offers appear only as metadata, without their key bytes.
    pub async fn outbox(&mut self, after: u64, limit: usize) -> Result<OutboxPage> {
        Ok(self.live_mut()?.kernel.outbox(after, limit).await?)
    }

    /// Issue one recipient-account-bound secret after committing it locally.
    /// It contains one-use keys: transfer it confidentially, never to a relay.
    /// Recovering the original issuance does not reactivate a consumed offer.
    pub async fn create_contact_offer(
        &mut self,
        operation: OperationId,
        recipient: Key,
        validity: Validity,
    ) -> Result<ConfidentialContactOffer> {
        let time = now()?;
        Ok(self
            .live_mut()?
            .kernel
            .create_contact_offer(operation, recipient, validity, time)
            .await?)
    }

    /// Commit one complete encrypted KeyPackage request from an inspected offer.
    /// Durable output is not network delivery or an automatic export grant.
    pub async fn contact_request(
        &mut self,
        operation: OperationId,
        offer: &[u8],
    ) -> Result<CommittedOutbox> {
        let time = now()?;
        Ok(self
            .live_mut()?
            .kernel
            .contact_request(operation, offer, time)
            .await?)
    }

    /// Authorize the exact recipient request and consume its outstanding offer
    /// atomically with admission, encrypted response and existing-member control.
    pub async fn accept_contact(
        &mut self,
        operation: OperationId,
        encrypted_request: &[u8],
        validity: Validity,
    ) -> Result<CommittedOutbox> {
        let time = now()?;
        Ok(self
            .live_mut()?
            .kernel
            .accept_contact(operation, encrypted_request, validity, time)
            .await?)
    }

    /// Admit only the owner response bound to this exact retained request.
    pub async fn join_contact(&mut self, encrypted_response: &[u8]) -> Result<Status> {
        let time = now()?;
        Ok(self
            .live_mut()?
            .kernel
            .join_contact(encrypted_response, time)
            .await?)
    }

    /// Produce a one-use join request only after the fresh device is durable.
    /// This artifact exposes enrollment metadata: transfer it confidentially.
    pub async fn key_package(&mut self, operation: OperationId) -> Result<CommittedOutbox> {
        let time = now()?;
        Ok(self.live_mut()?.kernel.key_package(operation, time).await?)
    }

    /// Explicitly authorize one exact enrolled device. The full response remains
    /// a confidential bootstrap artifact; it is not a public relay envelope.
    pub async fn invite(
        &mut self,
        operation: OperationId,
        request: &[u8],
        validity: Validity,
    ) -> Result<CommittedOutbox> {
        let time = now()?;
        Ok(self
            .live_mut()?
            .kernel
            .invite(operation, request, validity, time)
            .await?)
    }

    /// Accept the confidential invitation only for this retained pending device.
    pub async fn join(&mut self, invitation: &[u8]) -> Result<Status> {
        let time = now()?;
        Ok(self.live_mut()?.kernel.join(invitation, time).await?)
    }

    /// Explicitly remove one complete device key; other devices of its account
    /// are not implicitly removed and already received plaintext is not erased.
    pub async fn remove(&mut self, operation: OperationId, device: Key) -> Result<CommittedOutbox> {
        let time = now()?;
        Ok(self
            .live_mut()?
            .kernel
            .remove(operation, device, time)
            .await?)
    }

    /// Accept only a strict encrypted next control or an exact retained retry.
    pub async fn apply_control(&mut self, encrypted: &[u8]) -> Result<Status> {
        let time = now()?;
        Ok(self
            .live_mut()?
            .kernel
            .apply_control(encrypted, time)
            .await?)
    }

    /// Compare one signed owner control with retained history only. A
    /// conflicting valid claim at a known floor writes durable quarantine
    /// before reporting; persistence failure never fabricates acceptance.
    pub async fn observe_owner_control(&mut self, signed: &[u8]) -> Result<Status> {
        let time = now()?;
        Ok(self
            .live_mut()?
            .kernel
            .observe_owner_control(signed, time)
            .await?)
    }

    /// Read the first locally proven owner-signed fork, if one was retained.
    pub async fn fork_evidence(&mut self) -> Result<Option<ForkEvidence>> {
        Ok(self.live_mut()?.kernel.fork_evidence().await?)
    }

    /// Read committed encrypted controls, with the explicit late-join boundary.
    pub async fn encrypted_controls(
        &mut self,
        after: vhalla_private_kernel::protocol::ControlFloor,
        limit: usize,
    ) -> Result<EncryptedControlPage> {
        Ok(self
            .live_mut()?
            .kernel
            .encrypted_controls(after, limit)
            .await?)
    }

    /// Read committed encrypted controls from a durable sequence watermark.
    /// `None` selects this device's retained wire-history base, which for a
    /// checkpoint member sits above `Status::history_base`; it never selects a
    /// relay-supplied checkpoint or grants access before the joining floor.
    pub async fn encrypted_controls_from(
        &mut self,
        after: Option<u64>,
        limit: usize,
    ) -> Result<EncryptedControlPage> {
        Ok(self
            .live_mut()?
            .kernel
            .encrypted_controls_from(after, limit)
            .await?)
    }

    /// Export the plaintext signed-proof control suffix, never relay wire.
    /// The exact floor cursor prevents an accidental gap or cross-fork cursor.
    pub async fn controls(
        &mut self,
        after: vhalla_private_kernel::protocol::ControlFloor,
        limit: usize,
    ) -> Result<ControlPage> {
        Ok(self.live_mut()?.kernel.controls(after, limit).await?)
    }

    /// Explicitly sign and commit renewal for the same anchored owner device.
    /// Retain operation and exact validity for retries; no automatic renewal.
    pub async fn renew_owner(
        &mut self,
        operation: OperationId,
        validity: Validity,
    ) -> Result<CommittedOutbox> {
        let time = now()?;
        let custody = self.live_mut()?;
        let request = custody.kernel.owner_renewal_request(validity)?;
        let signed = custody.identity.sign_private_enrollment(&request)?;
        Ok(custody.kernel.renew_owner(operation, signed, time).await?)
    }

    /// Explicitly sign and commit an owner handoff to an already-enrolled
    /// successor device of the same account. The predecessor keeps ordinary
    /// membership; the exact retained envelope is the only transferable proof.
    /// Retain operation, successor key and validity for retry after uncertain
    /// completion. A committed handoff refuses re-issue — the grant pinned the
    /// pre-handoff floor — so recover the committed envelope through the
    /// retained control export instead of repeating this call.
    pub async fn succeed(
        &mut self,
        operation: OperationId,
        successor: Key,
        validity: Validity,
    ) -> Result<CommittedOutbox> {
        let time = now()?;
        let custody = self.live_mut()?;
        let request = custody
            .kernel
            .succession_request(successor, validity)
            .await?;
        let signed = custody.identity.sign_private_succession(&request)?;
        Ok(custody.kernel.succeed(operation, signed, time).await?)
    }
}
