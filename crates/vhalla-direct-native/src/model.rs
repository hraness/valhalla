use crate::{codec::*, *};
use vhalla_direct_room::{
    EventId, PolicyId, SignedEvent, SignedPolicy, UnsignedEvent, UnsignedPolicy, VerifiedPolicy,
};
use vhalla_direct_store::{Entry, Record};

impl RoomSession {
    pub(crate) fn reservation(&mut self, op: [u8; 16]) -> Result<Option<Reservation>> {
        let Some(raw) = self.store.read(operation_key(RESERVATION, op))? else {
            return Ok(None);
        };
        let reservation = Reservation::decode(&raw)?;
        if reservation.operation != op {
            return Err(Error::Corrupt);
        }
        self.check_reservation(&reservation)?;
        Ok(Some(reservation))
    }
    fn check_reservation(&self, reservation: &Reservation) -> Result<()> {
        match reservation.kind {
            EVENT => {
                let unsigned = UnsignedEvent::decode(&reservation.unsigned)?;
                if unsigned.claims().room != self.room_id()
                    || unsigned.claims().author != self.author_key()
                {
                    return Err(Error::Corrupt);
                }
            }
            POLICY => {
                let unsigned = UnsignedPolicy::decode(&reservation.unsigned)?;
                if !self.created_here
                    || unsigned.claims().room != self.room_id()
                    || unsigned.claims().owner != self.account.public_key()
                {
                    return Err(Error::Corrupt);
                }
            }
            _ => return Err(Error::Corrupt),
        }
        Ok(())
    }
    pub(crate) fn completed_bytes(&mut self, reserved: &Reservation) -> Result<Option<Vec<u8>>> {
        let Some(raw) = self
            .store
            .read(operation_key(COMPLETION, reserved.operation))?
        else {
            return Ok(None);
        };
        if raw.len() != 49 || raw[0] != reserved.kind || raw[1..17] != reserved.operation {
            return Err(Error::Corrupt);
        }
        let id = array(&raw[17..])?;
        let bytes = self
            .store
            .read(raw_key(reserved.kind, id))?
            .ok_or(Error::Corrupt)?;
        if bytes.len() < 64 || bytes[..bytes.len() - 64] != reserved.unsigned {
            return Err(Error::Corrupt);
        }
        let local_tag = if reserved.kind == EVENT {
            LOCAL_EVENT
        } else {
            LOCAL_POLICY
        };
        if self.store.read(raw_key(local_tag, id))?.as_deref()
            != Some(reserved.operation.as_slice())
        {
            return Err(Error::Corrupt);
        }
        match reserved.kind {
            EVENT if *self.event_raw(&bytes)?.id().as_bytes() == id => {}
            POLICY if *self.policy_raw(&bytes)?.id().as_bytes() == id => {}
            _ => return Err(Error::Corrupt),
        }
        Ok(Some(bytes))
    }
    pub(crate) fn finish_operation(
        &mut self,
        reserved: Reservation,
        retry: bool,
    ) -> Result<OperationOutcome> {
        self.finish_reserved(reserved, retry, true)
    }
    fn finish_reserved(
        &mut self,
        reserved: Reservation,
        retry: bool,
        advance: bool,
    ) -> Result<OperationOutcome> {
        if let Some(bytes) = self.completed_bytes(&reserved)? {
            return self.operation_outcome(reserved.operation, reserved.kind, bytes, retry);
        }
        self.writable(reserved.kind == POLICY)?;
        let pending = if reserved.kind == EVENT {
            self.image.pending_event
        } else {
            self.image.pending_policy
        };
        if pending != Some(reserved.operation) {
            return Err(Error::Corrupt);
        }
        let (bytes, id, index) = if reserved.kind == EVENT {
            let signed = self
                .author
                .sign_direct_event(UnsignedEvent::decode(&reserved.unsigned)?)?;
            let verified = signed.clone().verify()?;
            (
                signed.encode(),
                *signed.id().as_bytes(),
                self.event_index_record(&verified)?,
            )
        } else {
            if !self.created_here {
                return Err(Error::NotOwner);
            }
            let unsigned = UnsignedPolicy::decode(&reserved.unsigned)?;
            // An intervening owner signature cannot authorize rebasing this operation.
            let signed = if let Some(raw) = self
                .store
                .read(raw_key(POLICY, *unsigned.id().as_bytes()))?
            {
                let signed = SignedPolicy::decode(&raw)?;
                if raw[..raw.len() - 64] != reserved.unsigned {
                    return Err(Error::Corrupt);
                }
                signed.clone().verify()?;
                signed
            } else {
                if Some(unsigned.claims().revision) != self.policy.head().revision.checked_add(1)
                    || unsigned.claims().previous != self.policy.head().id
                {
                    return Err(Error::ReadOnly);
                }
                self.account.sign_direct_policy(unsigned)?
            };
            let verified = signed.clone().verify()?;
            (
                signed.encode(),
                *signed.id().as_bytes(),
                self.observed_index_record(&verified)?,
            )
        };
        let mut completion = vec![reserved.kind];
        completion.extend_from_slice(&reserved.operation);
        completion.extend_from_slice(&id);
        let local_tag = if reserved.kind == EVENT {
            LOCAL_EVENT
        } else {
            LOCAL_POLICY
        };
        let mut records = vec![
            record(raw_key(reserved.kind, id), &bytes)?,
            record(operation_key(COMPLETION, reserved.operation), &completion)?,
            record(raw_key(local_tag, id), &reserved.operation)?,
        ];
        if let Some(index) = index {
            records.push(index);
        }
        let mut image = self.image.clone();
        if reserved.kind == EVENT {
            image.pending_event = None;
        } else {
            image.pending_policy = None;
        }
        self.publish(image, &records, true)?;
        if reserved.kind == EVENT {
            self.event_persisted(&self.event_raw(&bytes)?)?;
        } else {
            self.observe_cached(self.policy_raw(&bytes)?)?;
        }
        if advance {
            self.apply_policies()?;
        }
        self.operation_outcome(reserved.operation, reserved.kind, bytes, retry)
    }
    fn operation_outcome(
        &mut self,
        operation: [u8; 16],
        kind: u8,
        bytes: Vec<u8>,
        exact_retry: bool,
    ) -> Result<OperationOutcome> {
        let state = if kind == EVENT {
            match self.visibility(self.event_raw(&bytes)?)? {
                Visibility::Provisional => OperationState::Provisional,
                Visibility::OwnerSealed => OperationState::OwnerSealed,
                Visibility::ContinuityOnly => OperationState::NeedsRepost,
                Visibility::Incomplete => OperationState::PendingHistory,
            }
        } else {
            let policy = self.policy_raw(&bytes)?;
            if self
                .committed(policy.claims().revision)?
                .is_some_and(|old| old.id() == policy.id())
            {
                OperationState::PolicyApplied
            } else {
                OperationState::PendingHistory
            }
        };
        Ok(OperationOutcome {
            operation,
            bytes,
            state,
            exact_retry,
        })
    }
    pub(crate) fn event_raw(&self, raw: &[u8]) -> Result<VerifiedEvent> {
        let event = SignedEvent::decode(raw)?.verify()?;
        if event.claims().room != self.room_id() {
            return Err(vhalla_direct_room::Error::Scope.into());
        }
        Ok(event)
    }
    pub(crate) fn policy_raw(&self, raw: &[u8]) -> Result<VerifiedPolicy> {
        let policy = SignedPolicy::decode(raw)?.verify()?;
        if policy.claims().room != self.room_id() {
            return Err(vhalla_direct_room::Error::Scope.into());
        }
        if policy.claims().owner != self.genesis.claims().owner {
            return Err(vhalla_direct_room::Error::Owner.into());
        }
        Ok(policy)
    }
    fn event_by_id(&mut self, id: EventId) -> Result<VerifiedEvent> {
        let bytes = self
            .store
            .read(raw_key(EVENT, *id.as_bytes()))?
            .ok_or(Error::Corrupt)?;
        let event = self.event_raw(&bytes)?;
        if event.id() != id {
            return Err(Error::Corrupt);
        }
        Ok(event)
    }
    fn policy_by_id(&mut self, id: PolicyId) -> Result<VerifiedPolicy> {
        let bytes = self
            .store
            .read(raw_key(POLICY, *id.as_bytes()))?
            .ok_or(Error::Corrupt)?;
        let policy = self.policy_raw(&bytes)?;
        if policy.id() != id {
            return Err(Error::Corrupt);
        }
        Ok(policy)
    }
    pub(crate) fn indexed_event(
        &mut self,
        author: [u8; 32],
        sequence: u64,
    ) -> Result<Option<VerifiedEvent>> {
        #[cfg(test)]
        {
            self.frame_reads += 1;
        }
        let Some(raw) = self.store.read(author_key(author, sequence))? else {
            return Ok(None);
        };
        if raw.len() != 72 || raw[..32] != author || raw[32..40] != sequence.to_be_bytes() {
            return Err(Error::Corrupt);
        }
        let event = self.event_by_id(EventId::from_bytes(array(&raw[40..])?))?;
        if event.claims().author != author || event.claims().sequence != sequence {
            return Err(Error::Corrupt);
        }
        Ok(Some(event))
    }
    pub(crate) fn indexed_policy(
        &mut self,
        tag: u8,
        revision: u64,
    ) -> Result<Option<VerifiedPolicy>> {
        let Some(raw) = self.store.read(revision_key(tag, revision))? else {
            return Ok(None);
        };
        if raw.len() != 40 || raw[..8] != revision.to_be_bytes() {
            return Err(Error::Corrupt);
        }
        let policy = self.policy_by_id(PolicyId::from_bytes(array(&raw[8..])?))?;
        if policy.claims().revision != revision {
            return Err(Error::Corrupt);
        }
        Ok(Some(policy))
    }
    fn committed(&mut self, revision: u64) -> Result<Option<VerifiedPolicy>> {
        self.indexed_policy(COMMITTED, revision)
    }
    pub(crate) fn event_index_record(&mut self, event: &VerifiedEvent) -> Result<Option<Record>> {
        let claims = event.claims();
        if let Some(old) = self.indexed_event(claims.author, claims.sequence)? {
            if old.id() != event.id() {
                return Err(vhalla_direct_room::Error::Fork.into());
            }
            return Ok(None);
        }
        let mut prefix = claims.author.to_vec();
        prefix.extend_from_slice(&claims.sequence.to_be_bytes());
        Ok(Some(record(
            author_key(claims.author, claims.sequence),
            &index_bytes(&prefix, *event.id().as_bytes()),
        )?))
    }
    pub(crate) fn observed_index_record(
        &mut self,
        policy: &VerifiedPolicy,
    ) -> Result<Option<Record>> {
        let revision = policy.claims().revision;
        if let Some(old) = self.indexed_policy(OBSERVED, revision)? {
            if old.id() != policy.id() {
                return Err(vhalla_direct_room::Error::Fork.into());
            }
            return Ok(None);
        }
        Ok(Some(record(
            revision_key(OBSERVED, revision),
            &index_bytes(&revision.to_be_bytes(), *policy.id().as_bytes()),
        )?))
    }

    /// Retain authenticated public event bytes. Receipt means local storage only.
    pub fn receive_event(&mut self, raw: &[u8]) -> Result<ReceiveOutcome> {
        self.ready()?;
        // Do not authenticate and then forget another observation while the
        // bounded emergency slot is occupied. Trusted local reads remain usable.
        if self.image.blocked.is_some() {
            return Err(Error::Capacity);
        }
        let event = self.event_raw(raw)?;
        let raw_record = record(raw_key(EVENT, *event.id().as_bytes()), raw)?;
        if let Some(old) = self.store.read(raw_record.key())? {
            if old != raw {
                return Err(Error::Corrupt);
            }
            return Ok(ReceiveOutcome {
                duplicate: true,
                visibility: self.visibility(event)?,
            });
        }
        let mut image = self.image.clone();
        let mut records = vec![raw_record.clone()];
        let mut critical = false;
        if let Some(old) = self.indexed_event(event.claims().author, event.claims().sequence)? {
            if old.id() != event.id() {
                critical = true;
                let fork_key = key(AUTHOR_FORK, &event.claims().author);
                if self.store.read(fork_key)?.is_none() {
                    let mut proof = event.claims().author.to_vec();
                    proof.extend_from_slice(&event.claims().sequence.to_be_bytes());
                    proof.extend_from_slice(old.id().as_bytes());
                    proof.extend_from_slice(event.id().as_bytes());
                    records.push(record(fork_key, &proof)?);
                }
            }
        } else if let Some(index) = self.event_index_record(&event)? {
            records.push(index);
        }
        if event.claims().author == self.author_key()
            && !self.pending_matches(EVENT, *event.id().as_bytes())?
        {
            image.author_lost = true;
            critical = true;
            records.push(record(
                raw_key(LOST_AUTHOR, *event.id().as_bytes()),
                event.id().as_bytes(),
            )?);
        }
        match self.publish(image, &records, critical) {
            Err(Error::Capacity) if critical => return self.capacity_fence(raw_record),
            result => result?,
        }
        self.event_persisted(&event)?;
        self.apply_policies()?;
        Ok(ReceiveOutcome {
            duplicate: false,
            visibility: self.visibility(event)?,
        })
    }

    /// Retain an owner-authenticated observation before any further fresh send.
    /// Historical and future revisions both participate in fork comparison.
    pub fn observe_policy(&mut self, raw: &[u8]) -> Result<PolicyOutcome> {
        self.ready()?;
        if self.image.blocked.is_some() {
            return Err(Error::Capacity);
        }
        let policy = self.policy_raw(raw)?;
        let raw_record = record(raw_key(POLICY, *policy.id().as_bytes()), raw)?;
        if let Some(old) = self.store.read(raw_record.key())? {
            if old != raw {
                return Err(Error::Corrupt);
            }
            return Ok(self.policy_outcome(true));
        }
        let mut image = self.image.clone();
        let mut records = vec![raw_record.clone()];
        if let Some(old) = self.indexed_policy(OBSERVED, policy.claims().revision)? {
            if old.id() != policy.id() {
                let mut proof = old.id().as_bytes().to_vec();
                proof.extend_from_slice(policy.id().as_bytes());
                records.push(record(key(OWNER_FORK, &proof), &proof)?);
            }
        } else if let Some(index) = self.observed_index_record(&policy)? {
            records.push(index);
        }
        if self.created_here && !self.pending_matches(POLICY, *policy.id().as_bytes())? {
            image.owner_lost = true;
            records.push(record(
                raw_key(LOST_OWNER, *policy.id().as_bytes()),
                policy.id().as_bytes(),
            )?);
        }
        match self.publish(image, &records, true) {
            Err(Error::Capacity) => return self.capacity_fence(raw_record),
            result => result?,
        }
        self.observe_cached(policy)?;
        self.apply_policies()?;
        Ok(self.policy_outcome(false))
    }
    fn policy_outcome(&self, duplicate: bool) -> PolicyOutcome {
        PolicyOutcome {
            duplicate,
            current: self.policy.head(),
            pending: self.policy.pending(),
            forked: self.policy.is_forked(),
        }
    }
    pub(crate) fn pending_matches(&mut self, kind: u8, id: [u8; 32]) -> Result<bool> {
        let pending = if kind == EVENT {
            self.image.pending_event
        } else {
            self.image.pending_policy
        };
        let Some(op) = pending else {
            return Ok(false);
        };
        let reserved = self.reservation(op)?.ok_or(Error::Corrupt)?;
        Ok(reserved.kind == kind
            && if kind == EVENT {
                *UnsignedEvent::decode(&reserved.unsigned)?.id().as_bytes() == id
            } else {
                *UnsignedPolicy::decode(&reserved.unsigned)?.id().as_bytes() == id
            })
    }

    fn prepare_policy(
        &mut self,
        state: &PolicyState,
        policy: &VerifiedPolicy,
    ) -> Result<vhalla_direct_room::PreparedPolicy> {
        let mut prepared = state.prepare_update(SignedPolicy::decode(&policy.encode())?)?;
        for seal in &policy.claims().sealed_heads {
            let mut sequence = state
                .sealed_head(&seal.author)
                .map_or(0, |head| head.sequence);
            while sequence < seal.sequence {
                let mut page = Vec::new();
                for _ in 0..vhalla_direct_room::MAX_CHAIN_PAGE {
                    if sequence == seal.sequence {
                        break;
                    }
                    sequence = sequence.checked_add(1).ok_or(Error::Bounds)?;
                    page.push(
                        self.indexed_event(seal.author, sequence)?
                            .ok_or(vhalla_direct_room::Error::Gap)?,
                    );
                }
                prepared.push_seal(&seal.author, &page)?;
            }
        }
        Ok(prepared)
    }
    /// Complete retained exact reservations and reconcile available policy history.
    /// This never invents missing author state or rebases a reservation.
    pub fn reconcile(&mut self) -> Result<Status> {
        self.ready()?;
        for op in [self.image.pending_event, self.image.pending_policy]
            .into_iter()
            .flatten()
        {
            let reservation = self.reservation(op)?.ok_or(Error::Corrupt)?;
            self.finish_reserved(reservation, true, false)?;
        }
        self.apply_policies()?;
        self.status()
    }
    /// Inspect local custody, pending history and storage use.
    pub fn status(&mut self) -> Result<Status> {
        self.ready()?;
        let policy = self.policy.clone();
        let minimum_unsigned =
            vhalla_direct_room::MAX_EVENT_BYTES - vhalla_direct_room::MAX_TEXT_BYTES - 64 + 1;
        let has_capacity = self.has_capacity(5, 2 * minimum_unsigned as u64 + 218, false)?;
        let can_send = self.writable(false).is_ok()
            && self.image.pending_event.is_none()
            && has_capacity
            && self
                .author_chain(self.author_key(), &policy)
                .and_then(|chain| chain.authoring_head(&policy).map_err(Error::from))
                .is_ok();
        Ok(Status {
            room: self.room_id(),
            author: self.author_key(),
            created_here: self.created_here,
            policy: self.policy.head(),
            pending_policy: self.policy.pending(),
            owner_forked: self.policy.is_forked(),
            capacity_fenced: self.image.blocked.is_some() || self.policy.observation_overflow(),
            author_custody_lost: self.image.author_lost,
            owner_custody_lost: self.image.owner_lost,
            pending_event_operation: self.image.pending_event,
            pending_policy_operation: self.image.pending_policy,
            reconciliation_pending: self.reconciliation_pending(),
            can_send,
            storage: self.store.accounting()?,
        })
    }

    /// Trusted local inspection. Contains unsent reservations and operation
    /// metadata; never expose this page verbatim through a network transport.
    pub fn records(&mut self, after: u64, limit: usize) -> Result<vhalla_direct_store::Page> {
        self.ready()?;
        Ok(self.store.page(after, limit)?)
    }
    /// Filter only authenticated public wire records from a bounded local scan.
    /// No keys, configuration, reservation text or completion metadata is returned.
    pub fn replicated_records(&mut self, after: u64, limit: usize) -> Result<PublicPage> {
        let (tip, entries, next) =
            self.filtered_entries(after, limit, |tag| matches!(tag, GENESIS | EVENT | POLICY))?;
        let mut records = Vec::new();
        for entry in entries {
            let kind = match entry.key[0] {
                GENESIS => {
                    if entry.data != self.genesis.encode() {
                        return Err(Error::Corrupt);
                    }
                    PublicRecordKind::Genesis
                }
                EVENT => {
                    self.event_raw(&entry.data)?;
                    PublicRecordKind::Event
                }
                POLICY => {
                    self.policy_raw(&entry.data)?;
                    PublicRecordKind::Policy
                }
                _ => continue,
            };
            records.push(PublicRecord {
                cursor: entry.cursor,
                kind,
                bytes: entry.data,
            });
        }
        Ok(PublicPage { tip, records, next })
    }
    /// Classify messages found in a bounded local journal scan. Empty filtered
    /// pages can still have a continuation cursor.
    pub fn messages(&mut self, after: u64, limit: usize) -> Result<MessagePage> {
        let (tip, entries, next) = self.filtered_entries(after, limit, |tag| tag == EVENT)?;
        let mut messages = Vec::new();
        for entry in entries {
            if entry.key[0] == EVENT {
                let event = self.event_raw(&entry.data)?;
                let visibility = self.visibility(event.clone())?;
                messages.push(Message {
                    cursor: entry.cursor,
                    event,
                    visibility,
                });
            }
        }
        Ok(MessagePage {
            tip,
            messages,
            next,
        })
    }
    fn filtered_entries(
        &mut self,
        after: u64,
        limit: usize,
        keep: fn(u8) -> bool,
    ) -> Result<(u64, Vec<Entry>, Option<u64>)> {
        self.ready()?;
        if limit == 0 || limit > vhalla_direct_store::MAX_PAGE_RECORDS {
            return Err(Error::Bounds);
        }
        let mut cursor = after;
        let mut scanned = 0;
        let mut entries = Vec::new();
        loop {
            let page = self.store.page(
                cursor,
                (MAX_FILTER_SCAN - scanned).min(vhalla_direct_store::MAX_PAGE_RECORDS),
            )?;
            for entry in page.records {
                cursor = entry.cursor;
                scanned += 1;
                if keep(entry.key[0]) {
                    entries.push(entry);
                }
                if entries.len() == limit || scanned == MAX_FILTER_SCAN {
                    return Ok((page.tip, entries, (cursor < page.tip).then_some(cursor)));
                }
            }
            if page.next.is_none() {
                return Ok((page.tip, entries, None));
            }
        }
    }
    fn visibility(&mut self, event: VerifiedEvent) -> Result<Visibility> {
        let claims = event.claims();
        if !self
            .indexed_event(claims.author, claims.sequence)?
            .is_some_and(|retained| retained.id() == event.id())
        {
            return Ok(Visibility::ContinuityOnly);
        }
        if claims.policy == self.policy.head().id {
            if !self.policy.allows(&claims.author) {
                return Ok(Visibility::ContinuityOnly);
            }
            if self.policy.pending().is_some()
                || self.policy.is_forked()
                || self.policy.observation_overflow()
                || self.image.blocked.is_some()
            {
                return Ok(Visibility::Incomplete);
            }
            let policy = self.policy.clone();
            return Ok(match self.author_chain(claims.author, &policy) {
                Ok(chain)
                    if chain.head().sequence >= claims.sequence
                        && chain.authoring_head(&policy).is_ok() =>
                {
                    Visibility::Provisional
                }
                Ok(_) | Err(Error::Protocol(_)) => Visibility::Incomplete,
                Err(error) => return Err(error),
            });
        }
        let Some(raw) = self
            .store
            .read(raw_key(POLICY_INDEX, *claims.policy.as_bytes()))?
        else {
            return Ok(Visibility::Incomplete);
        };
        let revision = u64::from_be_bytes(array(&raw)?);
        let closing_revision = revision.checked_add(1).ok_or(Error::Bounds)?;
        if closing_revision > self.policy.head().revision {
            return Ok(Visibility::Incomplete);
        }
        let allowed = if revision == 0 {
            if claims.policy != self.room_id().initial_policy() {
                return Err(Error::Corrupt);
            }
            self.genesis
                .claims()
                .writers
                .binary_search(&claims.author)
                .is_ok()
        } else {
            let original = self.committed(revision)?.ok_or(Error::Corrupt)?;
            if original.id() != claims.policy {
                return Err(Error::Corrupt);
            }
            original
                .claims()
                .writers
                .binary_search(&claims.author)
                .is_ok()
        };
        if !allowed {
            return Ok(Visibility::ContinuityOnly);
        }
        let closing = self.committed(closing_revision)?.ok_or(Error::Corrupt)?;
        if closing.claims().previous != claims.policy {
            return Err(Error::Corrupt);
        }
        let Some(seal) = closing
            .claims()
            .sealed_heads
            .iter()
            .find(|seal| seal.author == claims.author)
        else {
            return Ok(Visibility::ContinuityOnly);
        };
        if claims.sequence > seal.sequence {
            return Ok(Visibility::ContinuityOnly);
        }
        let terminal = self
            .indexed_event(seal.author, seal.sequence)?
            .ok_or(Error::Corrupt)?;
        if terminal.id() != seal.event || terminal.claims().policy != claims.policy {
            return Err(Error::Corrupt);
        }
        // Every COMMITTED revision through the live head has already passed the
        // core's full previous-seal ancestry proof against these exact immutable
        // indices. Open reconstructs this invariant; live commits establish it
        // after publication. The candidate and terminal above name that same
        // canonical chain, not merely a numeric sequence cutoff. No unchecked
        // core VerifiedHistoricalEvent is constructed here.
        Ok(Visibility::OwnerSealed)
    }

    pub(crate) fn reload_model(&mut self) -> Result<()> {
        match self.replay_model() {
            Ok(policy) => {
                self.policy = policy;
                if let Err(error) = self.rebuild_author_cache() {
                    self.poisoned = true;
                    return Err(error);
                }
                Ok(())
            }
            Err(error) => {
                self.poisoned = true;
                Err(error)
            }
        }
    }
    fn replay_model(&mut self) -> Result<PolicyState> {
        #[cfg(test)]
        {
            self.full_replays += 1;
        }
        let mut after = 0;
        let mut committed_count = 0u64;
        let mut committed_max = 0u64;
        loop {
            let page = self
                .store
                .page(after, vhalla_direct_store::MAX_PAGE_RECORDS)?;
            for entry in &page.records {
                self.validate_entry(entry)?;
                if entry.key[0] == COMMITTED {
                    committed_count = committed_count.checked_add(1).ok_or(Error::Corrupt)?;
                    committed_max = committed_max.max(u64::from_be_bytes(array(&entry.data[..8])?));
                }
            }
            let Some(next) = page.next else {
                break;
            };
            after = next;
        }
        if committed_count != committed_max {
            return Err(Error::Corrupt);
        }
        for (op, kind) in [
            (self.image.pending_event, EVENT),
            (self.image.pending_policy, POLICY),
        ] {
            if let Some(op) = op {
                let reservation = self.reservation(op)?.ok_or(Error::Corrupt)?;
                if reservation.kind != kind || self.completed_bytes(&reservation)?.is_some() {
                    return Err(Error::Corrupt);
                }
            }
        }
        let mut state = PolicyState::new(self.genesis.clone());
        for revision in 1..=committed_max {
            let update = self.committed(revision)?.ok_or(Error::Corrupt)?;
            let prepared = self.prepare_policy(&state, &update)?;
            state.commit_after_persist(prepared)?;
        }
        // Reconcile every retained observation, not only the latest revision or
        // the first-observation index. Old and superseded forks remain effective.
        after = 0;
        loop {
            let page = self
                .store
                .page(after, vhalla_direct_store::MAX_PAGE_RECORDS)?;
            for entry in &page.records {
                if entry.key[0] == POLICY {
                    let update = self.policy_raw(&entry.data)?;
                    self.replay_observation(&mut state, update)?;
                }
            }
            let Some(next) = page.next else {
                break;
            };
            after = next;
        }
        if let Some(blocked) = self.image.blocked.clone() {
            match blocked.key()[0] {
                POLICY => {
                    let update = self.policy_raw(blocked.as_bytes())?;
                    if blocked.key() != raw_key(POLICY, *update.id().as_bytes()) {
                        return Err(Error::Corrupt);
                    }
                    self.replay_observation(&mut state, update)?;
                }
                EVENT => {
                    let event = self.event_raw(blocked.as_bytes())?;
                    if blocked.key() != raw_key(EVENT, *event.id().as_bytes()) {
                        return Err(Error::Corrupt);
                    }
                }
                _ => return Err(Error::Corrupt),
            }
        }
        Ok(state)
    }
    pub(crate) fn replay_observation(
        &mut self,
        state: &mut PolicyState,
        update: VerifiedPolicy,
    ) -> Result<()> {
        // This comparison does not depend on the bounded in-memory observation
        // map. A conflict beyond that map's capacity must still quarantine the
        // room before any policy branch can be committed.
        if let Some(first) = self.indexed_policy(OBSERVED, update.claims().revision)? {
            if first.id() != update.id() {
                let comparison = state.observe_retained_after_persist(
                    &first,
                    SignedPolicy::decode(&update.encode())?,
                );
                if comparison != Err(vhalla_direct_room::Error::Fork) || !state.is_forked() {
                    return Err(Error::Corrupt);
                }
                return Ok(());
            }
        }
        let result = if update.claims().revision <= state.head().revision {
            let retained = self
                .committed(update.claims().revision)?
                .ok_or(Error::Corrupt)?;
            state.observe_retained_after_persist(&retained, SignedPolicy::decode(&update.encode())?)
        } else {
            state.observe_after_persist(&update)
        };
        match result {
            Ok(())
            | Err(
                vhalla_direct_room::Error::Duplicate
                | vhalla_direct_room::Error::Fork
                | vhalla_direct_room::Error::Capacity,
            ) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
    fn validate_entry(&mut self, entry: &Entry) -> Result<()> {
        match entry.key[0] {
            CONFIG => {
                let config = Config::decode(&entry.data)?;
                if entry.key != config_key()
                    || config.account != self.account.public_key()
                    || config.author != self.author_key()
                    || config.created != self.created_here
                    || config.creation_nonce != self.creation_nonce
                {
                    return Err(Error::Corrupt);
                }
            }
            GENESIS => {
                if entry.key != raw_key(GENESIS, *self.room_id().as_bytes())
                    || entry.data != self.genesis.encode()
                {
                    return Err(Error::Corrupt);
                }
            }
            RESERVATION => {
                let reservation = Reservation::decode(&entry.data)?;
                self.check_reservation(&reservation)?;
                if entry.key != operation_key(RESERVATION, reservation.operation) {
                    return Err(Error::Corrupt);
                }
                if self.completed_bytes(&reservation)?.is_none() {
                    let pending = if reservation.kind == EVENT {
                        self.image.pending_event
                    } else {
                        self.image.pending_policy
                    };
                    if pending != Some(reservation.operation) {
                        return Err(Error::Corrupt);
                    }
                }
            }
            COMPLETION => {
                if entry.data.len() != 49 {
                    return Err(Error::Corrupt);
                }
                let op = array(&entry.data[1..17])?;
                let reserved = self.reservation(op)?.ok_or(Error::Corrupt)?;
                if entry.key != operation_key(COMPLETION, op)
                    || self.completed_bytes(&reserved)?.is_none()
                {
                    return Err(Error::Corrupt);
                }
            }
            EVENT => {
                let event = self.event_raw(&entry.data)?;
                if entry.key != raw_key(EVENT, *event.id().as_bytes())
                    || self
                        .indexed_event(event.claims().author, event.claims().sequence)?
                        .is_none()
                {
                    return Err(Error::Corrupt);
                }
                if event.claims().author == self.author_key()
                    && self
                        .store
                        .read(raw_key(LOCAL_EVENT, *event.id().as_bytes()))?
                        .is_none()
                    && !self.pending_matches(EVENT, *event.id().as_bytes())?
                    && !self.image.author_lost
                {
                    return Err(Error::Corrupt);
                }
            }
            POLICY => {
                let update = self.policy_raw(&entry.data)?;
                if entry.key != raw_key(POLICY, *update.id().as_bytes())
                    || self
                        .indexed_policy(OBSERVED, update.claims().revision)?
                        .is_none()
                {
                    return Err(Error::Corrupt);
                }
                if self.created_here
                    && self
                        .store
                        .read(raw_key(LOCAL_POLICY, *update.id().as_bytes()))?
                        .is_none()
                    && !self.pending_matches(POLICY, *update.id().as_bytes())?
                    && !self.image.owner_lost
                {
                    return Err(Error::Corrupt);
                }
            }
            AUTHOR_INDEX => {
                if entry.data.len() != 72 {
                    return Err(Error::Corrupt);
                }
                let author = array(&entry.data[..32])?;
                let sequence = u64::from_be_bytes(array(&entry.data[32..40])?);
                if entry.key != author_key(author, sequence)
                    || self.indexed_event(author, sequence)?.is_none()
                {
                    return Err(Error::Corrupt);
                }
            }
            COMMITTED | OBSERVED => {
                if entry.data.len() != 40 {
                    return Err(Error::Corrupt);
                }
                let revision = u64::from_be_bytes(array(&entry.data[..8])?);
                if revision == 0
                    || entry.key != revision_key(entry.key[0], revision)
                    || self.indexed_policy(entry.key[0], revision)?.is_none()
                {
                    return Err(Error::Corrupt);
                }
            }
            POLICY_INDEX => {
                let revision = u64::from_be_bytes(array(&entry.data)?);
                let id = if revision == 0 {
                    self.room_id().initial_policy()
                } else {
                    self.committed(revision)?.ok_or(Error::Corrupt)?.id()
                };
                if entry.key != raw_key(POLICY_INDEX, *id.as_bytes()) {
                    return Err(Error::Corrupt);
                }
            }
            LOCAL_EVENT | LOCAL_POLICY => {
                let op = array(&entry.data)?;
                let reserved = self.reservation(op)?.ok_or(Error::Corrupt)?;
                let kind = if entry.key[0] == LOCAL_EVENT {
                    EVENT
                } else {
                    POLICY
                };
                if reserved.kind != kind {
                    return Err(Error::Corrupt);
                }
                let raw = self.completed_bytes(&reserved)?.ok_or(Error::Corrupt)?;
                let id = if kind == EVENT {
                    *self.event_raw(&raw)?.id().as_bytes()
                } else {
                    *self.policy_raw(&raw)?.id().as_bytes()
                };
                if entry.key != raw_key(entry.key[0], id) {
                    return Err(Error::Corrupt);
                }
            }
            AUTHOR_FORK => {
                if entry.data.len() != 104 {
                    return Err(Error::Corrupt);
                }
                let author = array(&entry.data[..32])?;
                let sequence = u64::from_be_bytes(array(&entry.data[32..40])?);
                let a = self.event_by_id(EventId::from_bytes(array(&entry.data[40..72])?))?;
                let b = self.event_by_id(EventId::from_bytes(array(&entry.data[72..])?))?;
                if entry.key != key(AUTHOR_FORK, &author)
                    || a.id() == b.id()
                    || a.claims().author != author
                    || b.claims().author != author
                    || a.claims().sequence != sequence
                    || b.claims().sequence != sequence
                {
                    return Err(Error::Corrupt);
                }
            }
            OWNER_FORK => {
                if entry.data.len() != 64 {
                    return Err(Error::Corrupt);
                }
                let a = self.policy_by_id(PolicyId::from_bytes(array(&entry.data[..32])?))?;
                let b = self.policy_by_id(PolicyId::from_bytes(array(&entry.data[32..])?))?;
                if entry.key != key(OWNER_FORK, &entry.data)
                    || a.id() == b.id()
                    || a.claims().revision != b.claims().revision
                {
                    return Err(Error::Corrupt);
                }
            }
            LOST_AUTHOR => {
                let id = EventId::from_bytes(array(&entry.data)?);
                let event = self.event_by_id(id)?;
                if entry.key != raw_key(LOST_AUTHOR, *id.as_bytes())
                    || event.claims().author != self.author_key()
                    || !self.image.author_lost
                {
                    return Err(Error::Corrupt);
                }
            }
            LOST_OWNER => {
                let id = PolicyId::from_bytes(array(&entry.data)?);
                self.policy_by_id(id)?;
                if !self.created_here
                    || entry.key != raw_key(LOST_OWNER, *id.as_bytes())
                    || !self.image.owner_lost
                {
                    return Err(Error::Corrupt);
                }
            }
            _ => return Err(Error::Corrupt),
        }
        Ok(())
    }
}
