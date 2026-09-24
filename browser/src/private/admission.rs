//! Explicit owner review of retained encrypted requests. No transport or new authority.
use crate::private_wire::{AdmissionConsent, Bytes, JoinConsent, Membership, Request};
use vhalla_private_kernel::{
    protocol::{Key, Validity},
    storage::Store,
    CommittedOutbox, ContactBootstrap, Error, Kernel, OperationId, OutboxKind,
};
use vhalla_private_relay::{RelayItem, RelayKind};
use zeroize::Zeroizing;

struct Pending {
    consent: AdmissionConsent,
    bytes: Bytes,
}
struct PendingJoin {
    consent: JoinConsent,
    bytes: Bytes,
}

/// One review per worker session. Only an unchanged confirmation may consume it.
pub struct Admission {
    session: [u8; 16],
    counter: u64,
    pending: Option<Pending>,
    join_pending: Option<PendingJoin>,
}
impl Admission {
    /// File fallback must not bypass an existing connection's reviewed join
    /// transaction. The caller reads this same-context image durably for every
    /// attempt, including after reload; unknown or legacy bytes also refuse.
    pub async fn join_file<S: Store>(
        kernel: &mut Kernel<S>,
        delivery_image: Option<&[u8]>,
        response: &[u8],
        now: u64,
    ) -> Result<(), Error> {
        if kernel.status().phase == vhalla_private_kernel::Phase::AwaitingWelcome
            && delivery_image.is_some()
        {
            return Err(Error::Policy);
        }
        kernel.join_contact(response, now).await?;
        Ok(())
    }

    /// Start a fresh worker-local review lifetime with independently generated entropy.
    pub fn new(session: [u8; 16]) -> Result<Self, Error> {
        if session == [0; 16] {
            return Err(Error::Entropy);
        }
        Ok(Self {
            session,
            counter: 0,
            pending: None,
            join_pending: None,
        })
    }

    /// Even same-roster sync or a read request ends the prior review. Rendering
    /// already-returned metadata does not dispatch a worker operation.
    pub fn before(&mut self, request: &Request) {
        if !matches!(request, Request::ConfirmAdmission { .. }) {
            self.pending = None;
        }
        if !matches!(request, Request::ConfirmJoinResponse { .. }) {
            self.join_pending = None;
        }
    }

    /// Check the complete proposed membership without publishing it. The
    /// response and connection selection remain fixed for this worker lifetime.
    pub async fn review_join<S: Store>(
        &mut self,
        kernel: &mut Kernel<S>,
        connection: [u8; 32],
        position: u64,
        item: &RelayItem,
        now: u64,
    ) -> Result<JoinConsent, Error> {
        self.join_pending = None;
        if connection == [0; 32]
            || position == 0
            || position > vhalla_private_relay::MAX_RELAY_ITEMS as u64
            || item.kind() != RelayKind::Outbox(OutboxKind::ContactInvitation)
        {
            return Err(Error::Policy);
        }
        let review = kernel.inspect_contact_response(item.payload(), now).await?;
        self.counter = self.counter.checked_add(1).ok_or(Error::Bounds)?;
        let validity = Validity::new(
            now,
            review
                .validity()
                .expires_at()
                .min(now.checked_add(300).ok_or(Error::Time)?),
        )?;
        let consent = JoinConsent {
            session: self.session,
            id: self.counter,
            pending: review.pending(),
            connection,
            position,
            digest: item.digest(),
            request: review.request(),
            response: review.response(),
            validity,
            proposed: proposed(&review),
        };
        self.join_pending = Some(PendingJoin {
            consent: consent.clone(),
            bytes: Zeroizing::new(item.payload().to_vec()),
        });
        Ok(consent)
    }

    /// Consume volatile consent and recheck its exact current pending state.
    /// The caller then persists transition intent and invokes the existing join
    /// inside the same exclusive worker operation. No membership is written here.
    pub async fn authorize_join<S: Store>(
        &mut self,
        kernel: &mut Kernel<S>,
        connection: [u8; 32],
        consent: &JoinConsent,
        item: &RelayItem,
        now: u64,
    ) -> Result<(), Error> {
        let pending = self.join_pending.take().ok_or(Error::Policy)?;
        if pending.consent != *consent
            || consent.connection != connection
            || item.kind() != RelayKind::Outbox(OutboxKind::ContactInvitation)
            || item.digest() != consent.digest
            || item.payload() != pending.bytes.as_slice()
        {
            return Err(Error::Scope);
        }
        consent.validity.check_at(now)?;
        let review = kernel.inspect_contact_response(item.payload(), now).await?;
        let mut current = proposed(&review);
        // Candidate publication advances the clock when confirmed. Its new
        // time is not a roster or destination change; all signed metadata and
        // the unchanged actual pending clock still compare exactly.
        current.status.clock = consent.proposed.status.clock;
        if review.pending() != consent.pending
            || review.request() != consent.request
            || review.response() != consent.response
            || current != consent.proposed
            || consent.validity.not_before() < review.validity().not_before()
            || consent.validity.expires_at() > review.validity().expires_at()
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }

    /// Authenticate selected request metadata without consuming the retained offer.
    pub async fn review<S: Store>(
        &mut self,
        kernel: &mut Kernel<S>,
        position: u64,
        item: &RelayItem,
        offer: &[u8],
        recipient: Key,
        now: u64,
    ) -> Result<AdmissionConsent, Error> {
        self.pending = None;
        if position == 0
            || position > vhalla_private_relay::MAX_RELAY_ITEMS as u64
            || item.kind() != RelayKind::Outbox(OutboxKind::ContactRequest)
        {
            return Err(Error::Policy);
        }
        let membership = kernel.membership().await?;
        let status = membership.status();
        if status.quarantined
            || status.context.account != membership.owner().claims().account
            || status.context.device != membership.owner().claims().device
        {
            return Err(Error::Policy);
        }
        let (info, enrollment) = ContactBootstrap::inspect_request(
            offer,
            item.payload(),
            status.context.account,
            recipient,
            now,
        )?;
        if info.scope() != status.context.scope || info.owner() != membership.owner() {
            return Err(Error::Scope);
        }
        let expires = info
            .validity()
            .expires_at()
            .min(enrollment.claims().validity.expires_at())
            .min(now.checked_add(3600).ok_or(Error::Time)?);
        let validity = Validity::new(now, expires)?;
        validity.check_at(now)?;
        self.counter = self.counter.checked_add(1).ok_or(Error::Bounds)?;
        let consent = AdmissionConsent {
            session: self.session,
            id: self.counter,
            context: status.context,
            epoch: status.epoch,
            roster: status.roster,
            control_floor: status.control_floor,
            position,
            digest: item.digest(),
            recipient,
            device: enrollment.claims().device,
            validity,
        };
        self.pending = Some(Pending {
            consent: consent.clone(),
            bytes: Zeroizing::new(item.payload().to_vec()),
        });
        Ok(consent)
    }

    /// Recheck the exact review and current custody before the existing kernel operation.
    pub async fn confirm<S: Store>(
        &mut self,
        kernel: &mut Kernel<S>,
        operation: OperationId,
        consent: &AdmissionConsent,
        item: &RelayItem,
        now: u64,
    ) -> Result<CommittedOutbox, Error> {
        // Take before every check/await: refusal or interruption never leaves a
        // reusable local permission. Uncertain kernel writes require reopen.
        let pending = self.pending.take().ok_or(Error::Policy)?;
        if pending.consent != *consent
            || item.digest() != consent.digest
            || item.kind() != RelayKind::Outbox(OutboxKind::ContactRequest)
            || item.payload() != pending.bytes.as_slice()
        {
            return Err(Error::Scope);
        }
        let membership = kernel.membership().await?;
        let status = membership.status();
        if status.quarantined
            || status.context != consent.context
            || status.epoch != consent.epoch
            || status.roster != consent.roster
            || status.control_floor != consent.control_floor
            || membership.owner().claims().account != consent.context.account
            || membership.owner().claims().device != consent.context.device
        {
            return Err(Error::Conflict);
        }
        consent.validity.check_at(now)?;
        kernel
            .accept_contact(operation, &pending.bytes, consent.validity, now)
            .await
    }
}

fn proposed(review: &vhalla_private_kernel::ContactResponseReview) -> Membership {
    let m = review.proposed();
    Membership {
        status: m.status(),
        anchor: m.anchor().clone(),
        owner: m.owner().clone(),
        local: m.local().clone(),
        members: m.members().to_vec(),
        successions: m.successions().to_vec(),
    }
}
