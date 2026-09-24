use super::membership::{make_key_package, InvitePreparation};
use super::*;
use crate::{
    contact::{self, Frame, Offer, PendingContact},
    packets::{InvitePacket, JoinRequest},
    protocol::{Key, Validity},
};
use zeroize::Zeroize;

/// Fully authenticated proposed membership from one encrypted response. This
/// inspection is private metadata, not committed membership, permission to send,
/// a relay checkpoint, or evidence of the owner's latest global state.
pub struct ContactResponseReview {
    pending: Status,
    request: [u8; 32],
    response: [u8; 32],
    validity: Validity,
    proposed: MembershipSnapshot,
}
impl ContactResponseReview {
    /// Authenticated local pending state against which this response was checked.
    pub fn pending(&self) -> Status {
        self.pending
    }
    /// Commitment to the exact encrypted request retained by this device.
    pub fn request(&self) -> [u8; 32] {
        self.request
    }
    /// Commitment to the complete encrypted response inspected here.
    pub fn response(&self) -> [u8; 32] {
        self.response
    }
    /// Common validity of offer, invitation, owner and local enrollment.
    pub fn validity(&self) -> Validity {
        self.validity
    }
    /// The proposed resulting roster and bindings, never an accepted snapshot.
    pub fn proposed(&self) -> &MembershipSnapshot {
        &self.proposed
    }
}

fn open_response(work: &Working, raw: &[u8], now: u64) -> Result<(InvitePacket, Validity)> {
    let frame = Frame::decode(raw)?;
    if frame.direction != 2 {
        return Err(Error::Encoding);
    }
    if work.state.phase != Phase::AwaitingWelcome {
        return Err(Error::Policy);
    }
    work.state.check_time(now)?;
    let pending = work.state.contact.as_ref().ok_or(Error::Missing)?;
    pending.offer.check_owner(&work.state)?;
    pending.offer.check_time(now)?;
    let clear = Zeroizing::new(pending.offer.open(&frame, Some(pending.request))?);
    let packet = InvitePacket::decode(&clear)?;
    let intervals = [
        pending.offer.validity,
        packet.invitation.claims().validity,
        work.state.owner.claims().validity,
        work.state.local.claims().validity,
    ];
    let validity = Validity::new(
        intervals
            .iter()
            .map(|v| v.not_before())
            .max()
            .ok_or(Error::Time)?,
        intervals
            .iter()
            .map(|v| v.expires_at())
            .min()
            .ok_or(Error::Time)?,
    )?;
    validity.check_at(now)?;
    Ok((packet, validity))
}

impl<S: Store> Kernel<S> {
    /// Inspect an exact encrypted response without publishing a state image or
    /// record. The same complete Welcome, credential and checkpoint validation
    /// constructs the isolated candidate used by `join_contact`. A successful or
    /// rejected inspection leaves the durable pending request and KeyPackage
    /// unchanged. Storage-read uncertainty still requires exact-store reopen.
    pub async fn inspect_contact_response(
        &mut self,
        raw: &[u8],
        now: u64,
    ) -> Result<ContactResponseReview> {
        let work = self.begin_live().await?;
        let pending = work.state.status();
        let request = work.state.contact.as_ref().ok_or(Error::Missing)?.request;
        let (packet, validity) = open_response(&work, raw, now)?;
        let response = contact::response_hash(raw);
        let (candidate, _) = self.prepare_join(work, packet, response, now)?;
        Ok(ContactResponseReview {
            pending,
            request,
            response,
            validity,
            proposed: MembershipSnapshot::from_state(&candidate.state),
        })
    }

    /// Reconcile only an already committed exact contact join. This read never
    /// accepts a Welcome or consumes membership. The answer remains available
    /// after later controls or removal, so a connection can finish an interrupted
    /// local transition without reviving the device.
    pub async fn contact_response_committed(&mut self, raw: &[u8]) -> Result<bool> {
        if Frame::decode(raw)?.direction != 2 {
            return Err(Error::Encoding);
        }
        let state = self.begin_state().await?;
        Ok(state.joined == Some(contact::response_hash(raw)))
    }

    async fn retained_offer(
        &mut self,
        operation: OperationId,
        request: [u8; 32],
        head: u64,
    ) -> Result<Option<ConfidentialContactOffer>> {
        let Some(lookup) = self.read_clear(RecordKey::Operation(operation)).await? else {
            return Ok(None);
        };
        let mut sent = self.sent_at(decode_index(&lookup)?, head).await?;
        let bytes = Zeroizing::new(std::mem::take(&mut sent.bytes));
        if sent.operation != operation
            || sent.request != request
            || sent.kind != OutboxKind::ContactOffer
        {
            return Err(Error::Conflict);
        }
        let parsed = Offer::decode(&bytes)?;
        if parsed.scope != self.context.scope {
            return Err(Error::Scope);
        }
        Ok(Some(ConfidentialContactOffer { operation, bytes }))
    }

    /// Create one recipient-bound secret offer, only after durable publication.
    /// Transfer it through an independently confidential authenticated channel.
    /// Exact creation retry recovers the old artifact, NEVER reactivates it.
    pub async fn create_contact_offer(
        &mut self,
        operation: OperationId,
        recipient: Key,
        validity: Validity,
        now: u64,
    ) -> Result<ConfidentialContactOffer> {
        let request = packets::request(
            self.context,
            OutboxKind::ContactOffer,
            &[
                recipient.as_bytes(),
                &validity.not_before().to_be_bytes(),
                &validity.expires_at().to_be_bytes(),
            ],
        )?;
        let mut work = self.begin_live().await?;
        if let Some(retained) = self
            .retained_offer(operation, request, work.state.outbox)
            .await?
        {
            return Ok(retained);
        }
        if !work.state.owner_role() {
            return Err(Error::Policy);
        }
        work.state.check_time(now)?;
        // Reclamation removes only unused authority from the current image. Its
        // immutable issuance evidence stays indexed, so old creation cannot reset.
        work.state
            .offers
            .retain(|offer| now < offer.validity.expires_at());
        if work.state.offers.len() >= MAX_CONTACT_OFFERS {
            return Err(Error::Bounds);
        }
        let offer = Offer::new(&work, recipient, validity, now)?;
        let raw = offer.encode()?;
        work.state.offers.push(offer);
        work.state.offers.sort_by_key(|offer| offer.id);
        work.state.clock = now;
        let index = work.state.outbox.checked_add(1).ok_or(Error::Bounds)?;
        let mut sent = Sent {
            sequence: index,
            operation,
            request,
            kind: OutboxKind::ContactOffer,
            bytes: raw.to_vec(),
        };
        let clear = Zeroizing::new(sent.encode()?);
        sent.bytes.zeroize();
        let records = vec![
            self.encrypt_record(RecordKey::Outbox(index), &clear)?,
            self.encrypt_record(RecordKey::Operation(operation), &index.to_be_bytes())?,
        ];
        work.state.outbox = index;
        self.publish(work, records).await?;
        let retained = self
            .retained_offer(operation, request, index)
            .await?
            .ok_or(Error::Missing)?;
        self.needs_reopen = false;
        Ok(retained)
    }

    /// Publish one exact encrypted KeyPackage request for this fresh device.
    /// The imported secret is checked against independently pinned scope/owner
    /// and this account. It grants neither admission nor permission to publish.
    pub async fn contact_request(
        &mut self,
        operation: OperationId,
        raw_offer: &[u8],
        now: u64,
    ) -> Result<CommittedOutbox> {
        let offer = Offer::decode(raw_offer)?;
        let request = packets::request(self.context, OutboxKind::ContactRequest, &[raw_offer])?;
        let mut work = self.begin_live().await?;
        if let Some(retained) = self
            .retained(
                operation,
                request,
                OutboxKind::ContactRequest,
                work.state.outbox,
            )
            .await?
        {
            return Ok(retained);
        }
        work.state.check_time(now)?;
        offer.check_owner(&work.state)?;
        offer.check_time(now)?;
        if offer.recipient != self.context.account || work.state.contact.is_some() {
            return Err(Error::Scope);
        }
        let clear = Zeroizing::new(make_key_package(&mut work, now)?);
        let output = offer.seal(None, &clear)?;
        work.state.contact = Some(PendingContact {
            offer,
            request: contact::request_hash(&output),
        });
        work.state.clock = now;
        self.publish_sent(work, operation, request, OutboxKind::ContactRequest, output)
            .await
    }

    /// Explicit owner admission of one exact request. Consumption, MLS change,
    /// confidential response and encrypted control publish in the same max3
    /// transaction. Unknown/consumed offers never authorize a new operation.
    pub async fn accept_contact(
        &mut self,
        operation: OperationId,
        raw: &[u8],
        validity: Validity,
        now: u64,
    ) -> Result<CommittedOutbox> {
        let frame = Frame::decode(raw)?;
        if frame.direction != 1 {
            return Err(Error::Encoding);
        }
        let request = packets::request(
            self.context,
            OutboxKind::ContactInvitation,
            &[
                raw,
                &validity.not_before().to_be_bytes(),
                &validity.expires_at().to_be_bytes(),
            ],
        )?;
        let mut work = self.begin_live().await?;
        if let Some(retained) = self
            .retained(
                operation,
                request,
                OutboxKind::ContactInvitation,
                work.state.outbox,
            )
            .await?
        {
            return Ok(retained);
        }
        if !work.state.owner_role() {
            return Err(Error::Policy);
        }
        work.state.check_time(now)?;
        let index = work
            .state
            .offers
            .iter()
            .position(|offer| offer.id == frame.id)
            .ok_or(Error::Missing)?;
        let offer = work.state.offers.remove(index);
        offer.check_owner(&work.state)?;
        offer.check_time(now)?;
        if validity.expires_at() > offer.validity.expires_at() {
            return Err(Error::Time);
        }
        let clear = offer.open(&frame, None)?;
        let join = JoinRequest::decode(&clear)?;
        if join.enrollment.claims().account != offer.recipient {
            return Err(Error::Scope);
        }
        self.invite_prepared(
            work,
            InvitePreparation {
                operation,
                request,
                join,
                validity,
                now,
                response: Some((offer, contact::request_hash(raw))),
            },
        )
        .await
    }

    /// Consume only a response bound to this exact retained encrypted request.
    /// Inner pinned-owner, recipient, MLS Welcome and checkpoint checks remain
    /// mandatory. Secret request state is removed only by the committed join.
    pub async fn join_contact(&mut self, raw: &[u8], now: u64) -> Result<Status> {
        let frame = Frame::decode(raw)?;
        if frame.direction != 2 {
            return Err(Error::Encoding);
        }
        let id = contact::response_hash(raw);
        let work = self.begin_live().await?;
        if work.state.phase == Phase::MemberJoined && work.state.joined == Some(id) {
            return Ok(self.status);
        }
        let (packet, _) = open_response(&work, raw, now)?;
        self.join_prepared(work, packet, id, now).await
    }
}
