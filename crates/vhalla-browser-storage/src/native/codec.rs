use super::*;
use crate::outbox::delivery::DELIVERY_HEAD_BYTES;
use crate::outbox::{AUTHOR_HEAD_BYTES, MAX_RESERVATION_BYTES};
use sha2::{Digest, Sha256};

pub(super) const MAX_STATE: usize = 16 * 1024;
pub(super) const MAX_INTENT: usize = 32 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct State {
    pub generation: u64,
    pub head: AuthorHead,
    pub policy: HistoryHead,
    pub limits: Limits,
    pub retained_bytes: u64,
    pub pending: Option<ReservedDraft>,
    pub deliveries: Vec<DeliveryHead>,
}
impl State {
    pub fn delivery(&self, peer: [u8; 32]) -> Option<DeliveryHead> {
        self.deliveries
            .binary_search_by_key(&peer, |h| h.peer())
            .ok()
            .map(|i| self.deliveries[i])
    }
    pub fn check(&self) -> Result<(), Error> {
        self.limits.check()?;
        if self.head.scope().network() != self.policy.scope().network() {
            return Err(Error::WrongScope);
        }
        if self.head.sequence() > self.limits.max_events
            || self.deliveries.len() > self.limits.max_peers
        {
            return Err(Error::Bounds);
        }
        if let Some(draft) = &self.pending {
            if draft.base() != self.head
                || draft.policy_head().scope() != self.policy.scope()
                || draft.policy_head().frontier().height > self.policy.frontier().height
            {
                return Err(Error::Corrupt);
            }
            if self.head.sequence() >= self.limits.max_events {
                return Err(Error::Bounds);
            }
        }
        let held = if self.pending.is_some() {
            MAX_EVENT_BYTES as u64
        } else {
            0
        };
        if self.retained_bytes.checked_add(held).ok_or(Error::Bounds)? > self.limits.max_bytes {
            return Err(Error::Bounds);
        }
        let mut receipts = 0u64;
        let mut previous = None;
        for head in &self.deliveries {
            if head.scope() != self.head.scope()
                || head.sequence() == 0
                || head.sequence() > self.head.sequence()
                || previous.is_some_and(|p| p >= head.peer())
            {
                return Err(Error::Corrupt);
            }
            previous = Some(head.peer());
            receipts = receipts.checked_add(head.sequence()).ok_or(Error::Bounds)?;
        }
        // Framing-accounting plausibility; exact changes are recomputed from intents.
        let count = self
            .head
            .sequence()
            .checked_add(receipts)
            .ok_or(Error::Bounds)?;
        let ceiling = self
            .head
            .sequence()
            .checked_mul(MAX_EVENT_BYTES as u64)
            .and_then(|n| {
                receipts
                    .checked_mul(MAX_DELIVERY_RECORD_BYTES as u64)
                    .and_then(|r| n.checked_add(r))
            })
            .ok_or(Error::Bounds)?;
        if self.retained_bytes < count || self.retained_bytes > ceiling {
            return Err(Error::Corrupt);
        }
        Ok(())
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = b"VHNAST01".to_vec();
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&self.head.encode());
        out.extend_from_slice(&self.policy.encode());
        for n in [
            self.limits.max_events,
            self.limits.max_bytes,
            self.retained_bytes,
        ] {
            out.extend_from_slice(&n.to_be_bytes());
        }
        out.push(self.limits.max_peers as u8);
        part(
            &mut out,
            self.pending.as_ref().map_or(&[], ReservedDraft::as_bytes),
        );
        out.push(self.deliveries.len() as u8);
        for head in &self.deliveries {
            out.extend_from_slice(&head.encode());
        }
        seal(out)
    }
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        let mut r = checked(raw, MAX_STATE)?;
        if r.take(8)? != b"VHNAST01" {
            return Err(Error::Corrupt);
        }
        let generation = r.u64()?;
        let head = AuthorHead::decode(r.take(AUTHOR_HEAD_BYTES)?)?;
        let policy = HistoryHead::decode(r.take(248)?)?;
        let max_events = r.u64()?;
        let max_bytes = r.u64()?;
        let retained_bytes = r.u64()?;
        let max_peers = usize::from(r.byte()?);
        let raw_pending = r.part(MAX_RESERVATION_BYTES)?;
        let pending = if raw_pending.is_empty() {
            None
        } else {
            Some(ReservedDraft::decode(raw_pending)?)
        };
        let count = usize::from(r.byte()?);
        if count > 16 {
            return Err(Error::Bounds);
        }
        let mut deliveries = Vec::with_capacity(count);
        for _ in 0..count {
            deliveries.push(DeliveryHead::decode(r.take(DELIVERY_HEAD_BYTES)?)?);
        }
        r.end()?;
        let out = Self {
            generation,
            head,
            policy,
            limits: Limits {
                max_events,
                max_bytes,
                max_peers,
            },
            retained_bytes,
            pending,
            deliveries,
        };
        out.check()?;
        if out.encode() != raw {
            return Err(Error::Corrupt);
        }
        Ok(out)
    }
}
pub(super) enum Change {
    History(HistoryHead),
    Reserve(ReservedDraft),
    Rebase(ReservedDraft, Box<ReservedDraft>),
    Finalize(ReservedDraft, Vec<u8>),
    Delivery(DeliveryRecord),
}
pub(super) struct Intent {
    pub before: State,
    pub change: Change,
}
impl Intent {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = b"VHNAIN01".to_vec();
        part(&mut out, &self.before.encode());
        match &self.change {
            Change::History(head) => {
                out.push(0);
                part(&mut out, &head.encode());
            }
            Change::Reserve(draft) => {
                out.push(1);
                part(&mut out, draft.as_bytes());
            }
            Change::Rebase(old, new) => {
                out.push(2);
                part(&mut out, old.as_bytes());
                part(&mut out, new.as_bytes());
            }
            Change::Finalize(draft, raw) => {
                out.push(3);
                part(&mut out, draft.as_bytes());
                part(&mut out, raw);
            }
            Change::Delivery(record) => {
                out.push(4);
                part(&mut out, record.as_bytes());
            }
        }
        seal(out)
    }
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        let mut r = checked(raw, MAX_INTENT)?;
        if r.take(8)? != b"VHNAIN01" {
            return Err(Error::Corrupt);
        }
        let before = State::decode(r.part(MAX_STATE)?)?;
        let change = match r.byte()? {
            0 => Change::History(HistoryHead::decode(r.part(248)?)?),
            1 => Change::Reserve(ReservedDraft::decode(r.part(MAX_RESERVATION_BYTES)?)?),
            2 => Change::Rebase(
                ReservedDraft::decode(r.part(MAX_RESERVATION_BYTES)?)?,
                Box::new(ReservedDraft::decode(r.part(MAX_RESERVATION_BYTES)?)?),
            ),
            3 => Change::Finalize(
                ReservedDraft::decode(r.part(MAX_RESERVATION_BYTES)?)?,
                r.part(MAX_EVENT_BYTES)?.to_vec(),
            ),
            4 => Change::Delivery(DeliveryRecord::decode(r.part(MAX_DELIVERY_RECORD_BYTES)?)?),
            _ => return Err(Error::Corrupt),
        };
        r.end()?;
        let out = Self { before, change };
        if out.encode() != raw {
            return Err(Error::Corrupt);
        }
        Ok(out)
    }
}
fn part(out: &mut Vec<u8>, raw: &[u8]) {
    out.extend_from_slice(&(raw.len() as u32).to_be_bytes());
    out.extend_from_slice(raw);
}
fn seal(mut out: Vec<u8>) -> Vec<u8> {
    let hash = Sha256::digest(&out);
    out.extend_from_slice(&hash);
    out
}
fn checked(raw: &[u8], max: usize) -> Result<Reader<'_>, Error> {
    if raw.len() > max {
        return Err(Error::Bounds);
    }
    let split = raw.len().checked_sub(32).ok_or(Error::Corrupt)?;
    let (body, sum) = raw.split_at(split);
    if Sha256::digest(body).as_slice() != sum {
        return Err(Error::Corrupt);
    }
    Ok(Reader(body))
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if n > self.0.len() {
            return Err(Error::Corrupt);
        }
        let (out, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(out)
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| Error::Corrupt)?,
        ))
    }
    fn part(&mut self, max: usize) -> Result<&'a [u8], Error> {
        let n = u32::from_be_bytes(self.take(4)?.try_into().map_err(|_| Error::Corrupt)?) as usize;
        if n > max {
            return Err(Error::Bounds);
        }
        self.take(n)
    }
    fn end(&self) -> Result<(), Error> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Corrupt)
        }
    }
}
