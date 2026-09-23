use super::membership::{make_key_package, InvitePreparation};
use super::*;
use crate::{
    contact::{self, Frame, Offer, PendingContact},
    packets::{InvitePacket, JoinRequest},
    protocol::{Key, Validity},
};
use zeroize::Zeroize;

impl<S: Store> Kernel<S> {
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
        if work.state.phase != Phase::AwaitingWelcome {
            return Err(Error::Policy);
        }
        work.state.check_time(now)?;
        let pending = work.state.contact.as_ref().ok_or(Error::Missing)?;
        pending.offer.check_owner(&work.state)?;
        pending.offer.check_time(now)?;
        let clear = pending.offer.open(&frame, Some(pending.request))?;
        let packet = InvitePacket::decode(&clear)?;
        self.join_prepared(work, packet, id, now).await
    }
}
