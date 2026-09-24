//! Explicit owner review of retained encrypted requests. No transport or new authority.
use crate::private_wire::{AdmissionConsent, Bytes, Request};
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

/// One review per worker session. Only an unchanged confirmation may consume it.
pub struct Admission {
    session: [u8; 16],
    counter: u64,
    pending: Option<Pending>,
}
impl Admission {
    /// Start a fresh worker-local review lifetime with independently generated entropy.
    pub fn new(session: [u8; 16]) -> Result<Self, Error> {
        if session == [0; 16] {
            return Err(Error::Entropy);
        }
        Ok(Self {
            session,
            counter: 0,
            pending: None,
        })
    }

    /// Even same-roster sync or a read request ends the prior review. Rendering
    /// already-returned metadata does not dispatch a worker operation.
    pub fn before(&mut self, request: &Request) {
        if !matches!(request, Request::ConfirmAdmission { .. }) {
            self.pending = None;
        }
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
