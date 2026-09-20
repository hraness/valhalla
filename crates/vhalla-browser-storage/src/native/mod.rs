//! Native single-author outbox with explicit creation, exact recovery and no pruning.
//!
//! The controller must establish fresh-scope provenance and verify certified
//! policy before supplying metadata. This store never certifies room admission,
//! resets a lost author floor, imports a key, or claims remote/global delivery.
//! One directory and exclusive writer bind one full author and bootstrap scope.
//! Retained bytes are budgeted; bounded control/intent/temp overhead is additional
//! (under 64 KiB). Capacity refusal never deletes evidence. Disk rollback and a
//! hostile writer with the same OS identity are outside the custody contract.

mod codec;
mod disk;
pub mod peers;
#[cfg(test)]
mod tests;

use crate::{
    history::{HistoryHead, HistoryScope},
    outbox::{
        check_finalize, check_rebase, check_reservation,
        delivery::{advance, DeliveryHead, DeliveryRecord, MAX_DELIVERY_RECORD_BYTES},
        AuthorHead, AuthorScope, OutboxPage, ReservedDraft, MAX_OUTBOX_PAGE_BYTES,
        MAX_OUTBOX_PAGE_RECORDS,
    },
    Error, PublishError,
};
use codec::{Change, Intent, State, MAX_INTENT, MAX_STATE};
use disk::Disk;
#[cfg(test)]
use disk::Point;
use std::{fs::File, path::Path};
use vhalla_public_protocol::activity::{ActivityRequest, ActivityResponseProof};
use vhalla_room_activity::{EventId, SignedEvent, VerifiedEvent, MAX_EVENT_BYTES};

/// Persisted retention ceilings. No operation prunes to make room.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Lifetime retained signed events, at most 1,000,000.
    pub max_events: u64,
    /// Retained event and receipt bytes, at most 8 GiB; excludes bounded metadata.
    pub max_bytes: u64,
    /// Retained full peer delivery chains, at most 16.
    pub max_peers: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_events: 65_536,
            max_bytes: 256 * 1024 * 1024,
            max_peers: 8,
        }
    }
}
impl Limits {
    fn check(self) -> Result<(), Error> {
        if self.max_events == 0
            || self.max_events > 1_000_000
            || self.max_bytes < MAX_EVENT_BYTES as u64
            || self.max_bytes > 8 * 1024 * 1024 * 1024
            || self.max_peers == 0
            || self.max_peers > 16
        {
            return Err(Error::Bounds);
        }
        Ok(())
    }
}

/// One exclusively owned native author outbox. Contains no private key material.
pub struct NativeOutbox {
    disk: Disk,
    _lock: File,
    state: State,
    poisoned: bool,
}
impl NativeOutbox {
    /// Create a never-existing directory for a controller-authorized fresh scope.
    /// Only sequence zero is accepted. An absent store or restored key is NOT
    /// evidence of freshness; the controller must establish that independently.
    /// Failed creation leaves partial state and never authorizes signing.
    pub fn create_new(
        path: impl AsRef<Path>,
        authorized_fresh: AuthorHead,
        policy: HistoryHead,
        limits: Limits,
    ) -> Result<Self, Error> {
        limits.check()?;
        if authorized_fresh.sequence() != 0 || authorized_fresh.event_id() != EventId::ZERO {
            return Err(Error::RecoveryRequired);
        }
        let state = State {
            generation: 0,
            head: authorized_fresh,
            policy,
            limits,
            retained_bytes: 0,
            pending: None,
            deliveries: Vec::new(),
        };
        state.check()?;
        let (mut disk, lock) = Disk::create(path.as_ref())?;
        disk.create_file("FORMAT", b"VHNAO001")?;
        disk.create_file("STATE", &state.encode())?;
        disk.sync()?;
        disk.sync_parent()?;
        Ok(Self {
            disk,
            _lock: lock,
            state,
            poisoned: false,
        })
    }

    /// Open existing state, check exact caller scope/pin BEFORE recovery writes,
    /// and finish only the retained exact intent. Never create, reset, or import.
    /// Reopening rechecks tips; older indexed evidence is checked when read.
    pub fn open(
        path: impl AsRef<Path>,
        expected_author: AuthorScope,
        expected_history: HistoryScope,
    ) -> Result<Self, Error> {
        let (disk, lock) = Disk::open(path.as_ref())?;
        if disk.read("FORMAT", 8)? != b"VHNAO001" {
            return Err(Error::Corrupt);
        }
        let state = State::decode(&disk.read("STATE", MAX_STATE)?)?;
        scope(&state, expected_author, expected_history)?;
        let mut out = Self {
            disk,
            _lock: lock,
            state,
            poisoned: true,
        };
        let mut final_intent = out.disk.optional("INTENT", MAX_INTENT)?;
        let staged = out.disk.optional("INTENT.tmp", MAX_INTENT)?;
        if final_intent.is_some() && staged.is_some() {
            return Err(Error::Corrupt);
        }
        if final_intent.is_none() {
            if let Some(raw) = staged {
                if out.disk.present("STATE.tmp", MAX_STATE)?
                    || out
                        .disk
                        .present("RECORD.tmp", MAX_EVENT_BYTES.max(MAX_DELIVERY_RECORD_BYTES))?
                {
                    return Err(Error::RecoveryRequired);
                }
                out.check_tips()?;
                if incomplete_outbox_stage(&raw, &out.state.encode())? {
                    if let Some(sequence) = out.state.head.sequence().checked_add(1) {
                        if out.disk.present(&event_name(sequence), MAX_EVENT_BYTES)? {
                            return Err(Error::RecoveryRequired);
                        }
                    }
                    for head in &out.state.deliveries {
                        if let Some(sequence) = head.sequence().checked_add(1) {
                            if out.disk.present(
                                &receipt_name(head.peer(), sequence),
                                MAX_DELIVERY_RECORD_BYTES,
                            )? {
                                return Err(Error::RecoveryRequired);
                            }
                        }
                    }
                    out.disk.discard_staged_intent()?;
                } else {
                    let intent = Intent::decode(&raw)?;
                    scope(&intent.before, expected_author, expected_history)?;
                    if out.state != intent.before {
                        return Err(Error::Corrupt);
                    }
                    out.calculate(&intent.before, &intent.change)?;
                    out.disk.promote_staged_intent(&raw)?;
                    final_intent = Some(raw);
                }
            }
        }
        if let Some(raw) = final_intent {
            let intent = Intent::decode(&raw)?;
            scope(&intent.before, expected_author, expected_history)?;
            let next = out.calculate(&intent.before, &intent.change)?;
            if out.state != intent.before && out.state != next {
                return Err(Error::Corrupt);
            }
            // A retained rename is not proof that its directory entry was synced.
            out.disk.resync("INTENT", MAX_INTENT)?;
            out.apply(&intent, &next)?;
            out.state = next;
        } else if out.disk.present("STATE.tmp", MAX_STATE)?
            || out
                .disk
                .present("RECORD.tmp", MAX_EVENT_BYTES.max(MAX_DELIVERY_RECORD_BYTES))?
        {
            return Err(Error::RecoveryRequired);
        }
        out.check_tips()?;
        // Absence after an interrupted INTENT unlink still needs directory sync.
        out.disk.resync("STATE", MAX_STATE)?;
        out.disk.sync_parent()?;
        out.poisoned = false;
        Ok(out)
    }

    /// Whether this handle must be dropped and reopened before any further use.
    #[must_use]
    pub const fn needs_reopen(&self) -> bool {
        self.poisoned
    }
    fn ready(&self) -> Result<(), Error> {
        if self.poisoned {
            Err(Error::NeedsReopen)
        } else {
            Ok(())
        }
    }
    /// Exact locally finalized floor, not a peer acknowledgment.
    pub fn head(&self) -> Result<AuthorHead, Error> {
        self.ready()?;
        Ok(self.state.head)
    }
    /// Controller-supplied certified-history metadata, not certification evidence.
    pub fn history_head(&self) -> Result<HistoryHead, Error> {
        self.ready()?;
        Ok(self.state.policy)
    }
    /// Persisted retention limits; changing them requires a separate reviewed tool.
    pub fn limits(&self) -> Result<Limits, Error> {
        self.ready()?;
        Ok(self.state.limits)
    }
    /// Return the exact possibly-already-signed pending intent. Never discard it.
    pub fn load_pending(&self) -> Result<Option<ReservedDraft>, Error> {
        self.ready()?;
        Ok(self.state.pending.clone())
    }
    /// Advance controller-verified same-bootstrap history by exact CAS. Skipping
    /// heights requires the controller to replay them first. No regressions or
    /// same-height replacements; pending unsigned bytes remain untouched.
    pub fn advance_history(
        &mut self,
        expected: HistoryHead,
        next: HistoryHead,
    ) -> Result<(), PublishError> {
        self.reject_ready()?;
        if self.state.policy != expected {
            return Err(PublishError::Rejected(Error::Stale));
        }
        if next == expected {
            return Ok(());
        }
        self.publish(Change::History(next))
    }
    /// Persist exact unsigned bytes before invoking any signer. Repeating an
    /// identical retained reservation is idempotent and does not consume capacity.
    pub fn reserve(&mut self, draft: &ReservedDraft) -> Result<(), PublishError> {
        self.publish(Change::Reserve(draft.clone()))
    }
    /// Rebase policy metadata only, under the portable exact-content checks.
    pub fn rebase_reservation(
        &mut self,
        old: &ReservedDraft,
        new: &ReservedDraft,
    ) -> Result<(), PublishError> {
        self.publish(Change::Rebase(old.clone(), Box::new(new.clone())))
    }
    /// Publish only the exact reserved signature. Retain immutable bytes before
    /// the author head advances. An exact latest finalized retry is idempotent.
    pub fn finalize(
        &mut self,
        draft: &ReservedDraft,
        event: &VerifiedEvent,
    ) -> Result<(), PublishError> {
        self.reject_ready()?;
        let next = draft.signed_head(event).map_err(PublishError::Rejected)?;
        if self.state.head == next {
            let retained = self
                .event(next.sequence())
                .map_err(PublishError::Rejected)?;
            if retained.encode() == event.encode() {
                return Ok(());
            }
            return Err(PublishError::Rejected(Error::Stale));
        }
        self.publish(Change::Finalize(draft.clone(), event.encode()))
    }
    /// Read an exclusive-after contiguous page (1..=16 records, <=128 KiB),
    /// retaining all history and checking the preceding link and observed tip.
    pub fn read_page(&self, after: u64, limit: usize) -> Result<OutboxPage, Error> {
        self.ready()?;
        if limit == 0 || limit > MAX_OUTBOX_PAGE_RECORDS {
            return Err(Error::Bounds);
        }
        if after > self.state.head.sequence() {
            return Err(Error::Stale);
        }
        let mut previous = if after == 0 {
            EventId::ZERO
        } else {
            self.event(after)?.id()
        };
        let end = after
            .saturating_add(limit as u64)
            .min(self.state.head.sequence());
        let mut events = Vec::new();
        let mut bytes = 0;
        for sequence in after..end {
            let event = self.event(sequence + 1)?;
            bytes += event.encode().len();
            if bytes > MAX_OUTBOX_PAGE_BYTES || event.claims().previous != previous {
                return Err(Error::Corrupt);
            }
            previous = event.id();
            events.push(event);
        }
        if end == self.state.head.sequence() && previous != self.state.head.event_id() {
            return Err(Error::Corrupt);
        }
        Ok(OutboxPage {
            head: self.state.head,
            events,
        })
    }
    /// Authenticate the latest retained acknowledgment of one full peer key.
    pub fn load_delivery(&self, peer: [u8; 32]) -> Result<Option<DeliveryHead>, Error> {
        self.ready()?;
        self.delivery(&self.state, peer)
            .map(|r| r.map(|r| r.head()))
    }
    /// Read original immutable acknowledgment evidence at one peer/author sequence.
    pub fn load_delivery_receipt(
        &self,
        peer: [u8; 32],
        sequence: u64,
    ) -> Result<Option<DeliveryRecord>, Error> {
        self.ready()?;
        let Some(head) = self.state.delivery(peer) else {
            return Ok(None);
        };
        if sequence == 0 || sequence > head.sequence() {
            return Ok(None);
        }
        self.receipt(peer, sequence).map(Some)
    }
    /// Retain a strictly verified exact peer acknowledgment and advance by CAS.
    /// Fresh nonce generation is the transport caller's responsibility. Original
    /// latest-event evidence survives retries; no signed event/outbox is deleted.
    pub fn record_delivery(
        &mut self,
        peer: [u8; 32],
        expected: Option<&DeliveryHead>,
        request: &ActivityRequest,
        proof: &ActivityResponseProof,
        receipt: &[u8],
    ) -> Result<DeliveryHead, PublishError> {
        self.reject_ready()?;
        let record = DeliveryRecord::new(self.state.head.scope(), peer, request, proof, receipt)
            .map_err(PublishError::Rejected)?;
        let observed = self
            .delivery(&self.state, peer)
            .map_err(PublishError::Rejected)?;
        let event = self
            .event(record.head().sequence())
            .map_err(PublishError::Rejected)?;
        record
            .check_event(&event.encode())
            .map_err(PublishError::Rejected)?;
        if !advance(
            expected,
            observed.as_ref().map(|r| r.head()).as_ref(),
            &record,
            &event,
        )
        .map_err(PublishError::Rejected)?
        {
            return observed
                .map(|r| r.head())
                .ok_or(PublishError::Rejected(Error::Corrupt));
        }
        let head = record.head();
        self.publish(Change::Delivery(record))?;
        Ok(head)
    }
    fn reject_ready(&self) -> Result<(), PublishError> {
        self.ready().map_err(PublishError::Rejected)
    }
    fn event(&self, sequence: u64) -> Result<VerifiedEvent, Error> {
        if sequence == 0 || sequence > self.state.head.sequence() {
            return Err(Error::Stale);
        }
        self.event_at(sequence, self.state.head.scope())
    }
    fn event_at(&self, sequence: u64, author: AuthorScope) -> Result<VerifiedEvent, Error> {
        let raw = self.disk.read(&event_name(sequence), MAX_EVENT_BYTES)?;
        let event = SignedEvent::decode(&raw)
            .and_then(|e| e.verify())
            .map_err(|_| Error::Corrupt)?;
        if event.encode() != raw
            || event.claims().sequence != sequence
            || AuthorScope::new(event.claims().scope, event.claims().author) != author
        {
            return Err(Error::Corrupt);
        }
        Ok(event)
    }
    fn receipt(&self, peer: [u8; 32], sequence: u64) -> Result<DeliveryRecord, Error> {
        let raw = self
            .disk
            .read(&receipt_name(peer, sequence), MAX_DELIVERY_RECORD_BYTES)?;
        let record = DeliveryRecord::decode(&raw)?;
        if record.head().scope() != self.state.head.scope()
            || record.head().peer() != peer
            || record.head().sequence() != sequence
        {
            return Err(Error::Corrupt);
        }
        record.check_event(&self.event_at(sequence, self.state.head.scope())?.encode())?;
        Ok(record)
    }
    fn delivery(&self, state: &State, peer: [u8; 32]) -> Result<Option<DeliveryRecord>, Error> {
        match state.delivery(peer) {
            None => Ok(None),
            Some(head) => {
                let record = self.receipt(peer, head.sequence())?;
                if record.head() != head {
                    return Err(Error::Corrupt);
                }
                Ok(Some(record))
            }
        }
    }
    fn check_tips(&self) -> Result<(), Error> {
        if self.state.head.sequence() > 0 {
            let event = self.event(self.state.head.sequence())?;
            if event.id() != self.state.head.event_id() {
                return Err(Error::Corrupt);
            }
        }
        for head in &self.state.deliveries {
            self.delivery(&self.state, head.peer())?;
        }
        Ok(())
    }
    fn calculate(&self, before: &State, change: &Change) -> Result<State, Error> {
        before.check()?;
        let mut next = before.clone();
        let h = before.head.encode();
        let p = before.policy.encode();
        let pending = before.pending.as_ref().map(ReservedDraft::as_bytes);
        match change {
            Change::History(policy) => {
                if policy.scope() != before.policy.scope() {
                    return Err(Error::WrongScope);
                }
                if policy.frontier().height <= before.policy.frontier().height
                    || policy.frontier().time < before.policy.frontier().time
                {
                    return Err(Error::Stale);
                }
                next.policy = *policy;
            }
            Change::Reserve(draft) => {
                check_reservation(draft, Some(&h), pending, Some(&p))?;
                next.pending = Some(draft.clone());
            }
            Change::Rebase(old, new) => {
                check_rebase(old, new, Some(&h), pending, Some(&p))?;
                next.pending = Some(new.as_ref().clone());
            }
            Change::Finalize(draft, raw) => {
                check_finalize(draft, Some(&h), pending, Some(&p))?;
                let event = SignedEvent::decode(raw)
                    .and_then(|e| e.verify())
                    .map_err(|_| Error::Corrupt)?;
                if event.encode() != *raw {
                    return Err(Error::Corrupt);
                }
                next.head = draft.signed_head(&event)?;
                next.pending = None;
                next.retained_bytes = next
                    .retained_bytes
                    .checked_add(raw.len() as u64)
                    .ok_or(Error::Bounds)?;
            }
            Change::Delivery(record) => {
                let head = record.head();
                if head.scope() != before.head.scope() || head.sequence() > before.head.sequence() {
                    return Err(Error::WrongScope);
                }
                let event = self.event_at(head.sequence(), before.head.scope())?;
                record.check_event(&event.encode())?;
                let observed = self.delivery(before, head.peer())?.map(|r| r.head());
                if !advance(observed.as_ref(), observed.as_ref(), record, &event)? {
                    return Err(Error::Stale);
                }
                match next
                    .deliveries
                    .binary_search_by_key(&head.peer(), |h| h.peer())
                {
                    Ok(i) => next.deliveries[i] = head,
                    Err(i) => next.deliveries.insert(i, head),
                }
                next.retained_bytes = next
                    .retained_bytes
                    .checked_add(record.as_bytes().len() as u64)
                    .ok_or(Error::Bounds)?;
            }
        }
        if next == *before {
            return Ok(next);
        }
        next.generation = next.generation.checked_add(1).ok_or(Error::Bounds)?;
        next.check()?;
        Ok(next)
    }
    fn publish(&mut self, change: Change) -> Result<(), PublishError> {
        self.reject_ready()?;
        let next = self
            .calculate(&self.state, &change)
            .map_err(PublishError::Rejected)?;
        if next == self.state {
            return Ok(());
        }
        let intent = Intent {
            before: self.state.clone(),
            change,
        };
        let raw = intent.encode();
        self.poisoned = true;
        let result = (|| {
            self.disk.stage_intent(&raw)?;
            self.apply(&intent, &next)
        })();
        result.map_err(PublishError::ReopenRequired)?;
        self.state = next;
        self.poisoned = false;
        Ok(())
    }
    fn apply(&mut self, intent: &Intent, next: &State) -> Result<(), Error> {
        match &intent.change {
            Change::Finalize(_, raw) => self
                .disk
                .immutable(&event_name(next.head.sequence()), raw)?,
            Change::Delivery(record) => self.disk.immutable(
                &receipt_name(record.head().peer(), record.head().sequence()),
                record.as_bytes(),
            )?,
            _ => {}
        }
        self.disk
            .replace_state(&intent.before.encode(), &next.encode())?;
        self.disk.remove_intent()?;
        Ok(())
    }
}
fn scope(state: &State, author: AuthorScope, history: HistoryScope) -> Result<(), Error> {
    if state.head.scope() != author || state.policy.scope() != history {
        return Err(Error::WrongScope);
    }
    Ok(())
}
fn event_name(sequence: u64) -> String {
    format!("event-{sequence:016x}")
}
fn receipt_name(peer: [u8; 32], sequence: u64) -> String {
    let key: String = peer.iter().map(|b| format!("{b:02x}")).collect();
    format!("receipt-{key}-{sequence:016x}")
}

// Recognize only an exact-current-state prefix of an unpublished v1 intent.
// Complete malformed/checksum-invalid frames and stale/foreign prefixes stay.
fn incomplete_outbox_stage(raw: &[u8], expected: &[u8]) -> Result<bool, Error> {
    use crate::outbox::MAX_RESERVATION_BYTES;
    if raw.len() > MAX_INTENT || expected.len() > MAX_STATE {
        return Err(Error::Bounds);
    }
    let magic = b"VHNAIN01";
    let prefix = raw.len().min(magic.len());
    if raw[..prefix] != magic[..prefix] {
        return Err(Error::Corrupt);
    }
    if raw.len() < 8 {
        return Ok(true);
    }
    let length = (expected.len() as u32).to_be_bytes();
    let length_prefix = (raw.len() - 8).min(4);
    if raw[8..8 + length_prefix] != length[..length_prefix] {
        return Err(Error::Stale);
    }
    if raw.len() < 12 {
        return Ok(true);
    }
    let available = (raw.len() - 12).min(expected.len());
    if raw[12..12 + available] != expected[..available] {
        return Err(Error::Stale);
    }
    let mut at = 12 + expected.len();
    if raw.len() <= at {
        return Ok(true);
    }
    fn part(raw: &[u8], at: &mut usize, max: usize) -> Result<bool, Error> {
        let length_end = at.checked_add(4).ok_or(Error::Bounds)?;
        if raw.len() < length_end {
            return Ok(true);
        }
        let size = u32::from_be_bytes(
            raw[*at..length_end]
                .try_into()
                .map_err(|_| Error::Corrupt)?,
        ) as usize;
        if size == 0 || size > max {
            return Err(Error::Bounds);
        }
        *at = length_end.checked_add(size).ok_or(Error::Bounds)?;
        Ok(raw.len() < *at)
    }
    let tag = raw[at];
    at += 1;
    let maxima: &[usize] = match tag {
        0 => &[248],
        1 => &[MAX_RESERVATION_BYTES],
        2 => &[MAX_RESERVATION_BYTES, MAX_RESERVATION_BYTES],
        3 => &[MAX_RESERVATION_BYTES, MAX_EVENT_BYTES],
        4 => &[MAX_DELIVERY_RECORD_BYTES],
        _ => return Err(Error::Corrupt),
    };
    for max in maxima {
        if part(raw, &mut at, *max)? {
            return Ok(true);
        }
    }
    Ok(raw.len() < at.checked_add(32).ok_or(Error::Bounds)?)
}
