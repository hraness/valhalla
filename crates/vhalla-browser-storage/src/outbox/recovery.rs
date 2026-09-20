//! Complete, bounded author-state streams. A key backup alone is insufficient.
//!
//! Recovery only activates an entirely absent author namespace. Pages may stage
//! without publishing its head; partial imports must never authorize fresh scope
//! initialization. Authentication cannot establish global freshness, prevent
//! coherent rollback or reconcile two devices that signed conflicting events.
#![cfg_attr(not(any(test, target_arch = "wasm32")), allow(dead_code))]
use super::delivery::{DeliveryHead, DeliveryRecord, MAX_DELIVERY_RECORD_BYTES};
use super::{AuthorHead, AuthorScope, Reader, ReservedDraft, MAX_RESERVATION_BYTES};
use crate::{history::HistoryScope, Error};
#[cfg(any(test, target_arch = "wasm32"))]
use sha2::{Digest, Sha256};
use vhalla_browser_vault::backup::AuthorBackupPage;
use vhalla_room_activity::{EventId, SignedEvent, MAX_EVENT_BYTES};

/// Maximum entries in one transaction/page; total stream length is unrestricted.
pub const PAGE_ENTRIES: usize = 16;
/// Longest recognized relative author key.
pub const MAX_ENTRY_KEY: usize = 98;
/// Maximum one source value, checked before copying from JavaScript.
pub const MAX_ENTRY_BYTES: usize = MAX_RESERVATION_BYTES;
pub(crate) const MAX_SNAPSHOT_BYTES: usize = 8 + 192 + 32 + 9 + 4 + MAX_RESERVATION_BYTES;
pub(crate) const MAX_IMPORT_BYTES: usize = MAX_SNAPSHOT_BYTES + 2048;

/// Exact source author floor, pending intent, and delivery mutation revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    head: AuthorHead,
    pin: [u8; 32],
    pending: Option<ReservedDraft>,
    revision: Option<u64>,
}
impl Snapshot {
    pub(crate) fn new(
        head: AuthorHead,
        history: HistoryScope,
        pending: Option<ReservedDraft>,
        revision: Option<u64>,
    ) -> Result<Self, Error> {
        if head.scope().network() != history.network()
            || pending
                .as_ref()
                .is_some_and(|p| p.base() != head || p.policy_head().scope() != history)
        {
            return Err(Error::WrongScope);
        }
        Ok(Self {
            head,
            pin: history.bootstrap_pin(),
            pending,
            revision,
        })
    }
    /// Complete locally finalized author floor, including explicit sequence zero.
    pub const fn head(&self) -> AuthorHead {
        self.head
    }
    /// Exact possibly-signed next intent; never discard this during recovery.
    pub fn pending(&self) -> Option<&ReservedDraft> {
        self.pending.as_ref()
    }
    /// Independently selected immutable bootstrap context.
    pub fn history_scope(&self) -> HistoryScope {
        HistoryScope::new(self.head.scope().network(), self.pin)
    }
    pub(crate) fn compare(&self, observed: &Self) -> Result<(), Error> {
        if self == observed {
            Ok(())
        } else {
            Err(Error::Stale)
        }
    }
    pub(crate) fn context(&self) -> [u8; 176] {
        let mut raw = Vec::with_capacity(176);
        self.head.scope().encode(&mut raw);
        raw.extend_from_slice(&self.pin);
        raw.try_into().expect("fixed scope size")
    }
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut raw = Vec::new();
        raw.extend_from_slice(b"VHBASN01");
        raw.extend_from_slice(&self.head.encode());
        raw.extend_from_slice(&self.pin);
        raw.push(u8::from(self.revision.is_some()));
        raw.extend_from_slice(&self.revision.unwrap_or(0).to_be_bytes());
        let pending = self
            .pending
            .as_ref()
            .map_or(&[][..], ReservedDraft::as_bytes);
        raw.extend_from_slice(&(pending.len() as u32).to_be_bytes());
        raw.extend_from_slice(pending);
        raw
    }
    pub(crate) fn decode(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() > MAX_SNAPSHOT_BYTES {
            return Err(Error::Bounds);
        }
        let mut r = Reader(raw);
        if &r.array::<8>()? != b"VHBASN01" {
            return Err(Error::Corrupt);
        }
        let head = AuthorHead::decode(r.take(192)?)?;
        let pin = r.array()?;
        let flag = r.array::<1>()?[0];
        let rev = u64::from_be_bytes(r.array()?);
        if flag > 1 || (flag == 0 && rev != 0) {
            return Err(Error::Corrupt);
        }
        let length = u32::from_be_bytes(r.array()?) as usize;
        let pending = if length == 0 {
            None
        } else {
            Some(ReservedDraft::decode(r.take(length)?)?)
        };
        if !r.0.is_empty() {
            return Err(Error::Corrupt);
        }
        Self::new(
            head,
            HistoryScope::new(head.scope().network(), pin),
            pending,
            (flag == 1).then_some(rev),
        )
    }
}

/// One immutable canonical relative-key/value pair; no arbitrary database keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry {
    key: String,
    value: Vec<u8>,
}
impl Entry {
    pub(crate) fn new(key: String, value: Vec<u8>, snapshot: &Snapshot) -> Result<Self, Error> {
        if key.len() > MAX_ENTRY_KEY || value.len() > MAX_ENTRY_BYTES {
            return Err(Error::Bounds);
        }
        let entry = Self { key, value };
        entry.kind(snapshot)?;
        Ok(entry)
    }
    /// Canonical recognized relative key, without profile or author prefix.
    pub fn key(&self) -> &str {
        &self.key
    }
    /// Exact original signed bytes or canonical metadata.
    pub fn value(&self) -> &[u8] {
        &self.value
    }
    pub(crate) fn kind(&self, snapshot: &Snapshot) -> Result<Kind, Error> {
        let scope = snapshot.head.scope();
        match self.key.as_str() {
            "head" => {
                if self.value != snapshot.head.encode() {
                    return Err(Error::Corrupt);
                }
                Ok(Kind::Head)
            }
            "pending" => {
                if snapshot
                    .pending
                    .as_ref()
                    .is_none_or(|p| p.as_bytes() != self.value)
                {
                    return Err(Error::Corrupt);
                }
                Ok(Kind::Pending)
            }
            "receipt-revision" => {
                if self.value.as_slice() != snapshot.revision.ok_or(Error::Corrupt)?.to_be_bytes() {
                    return Err(Error::Corrupt);
                }
                Ok(Kind::Revision)
            }
            key if key.starts_with("event/") || key.starts_with("outbox/") => {
                let (name, number) = key.split_once('/').ok_or(Error::Corrupt)?;
                let sequence = parse_sequence(number)?;
                if self.value.len() > MAX_EVENT_BYTES {
                    return Err(Error::Bounds);
                }
                let event = SignedEvent::decode(&self.value)
                    .and_then(SignedEvent::verify)
                    .map_err(|_| Error::Corrupt)?;
                if AuthorScope::new(event.claims().scope, event.claims().author) != scope
                    || event.claims().sequence != sequence
                    || sequence > snapshot.head.sequence()
                {
                    return Err(Error::WrongScope);
                }
                Ok(Kind::Event {
                    outbox: name == "outbox",
                    sequence,
                    id: event.id(),
                    previous: event.claims().previous,
                })
            }
            key if key.starts_with("delivery/") => {
                let suffix = key.strip_prefix("delivery/").ok_or(Error::Corrupt)?;
                let (peer, tail) = suffix.split_once('/').ok_or(Error::Corrupt)?;
                let peer = parse_peer(peer)?;
                if tail == "head" {
                    let head = DeliveryHead::decode(&self.value)?;
                    if head.peer() != peer
                        || head.scope() != scope
                        || head.sequence() > snapshot.head.sequence()
                    {
                        return Err(Error::WrongScope);
                    }
                    Ok(Kind::Peer(head))
                } else {
                    let sequence =
                        parse_sequence(tail.strip_prefix("receipt/").ok_or(Error::Corrupt)?)?;
                    if self.value.len() > MAX_DELIVERY_RECORD_BYTES {
                        return Err(Error::Bounds);
                    }
                    let receipt = DeliveryRecord::decode(&self.value)?;
                    let head = receipt.head();
                    if head.peer() != peer || head.scope() != scope || head.sequence() != sequence {
                        return Err(Error::WrongScope);
                    }
                    Ok(Kind::Receipt(head))
                }
            }
            _ => Err(Error::Corrupt),
        }
    }
}
pub(crate) enum Kind {
    Head,
    Pending,
    Revision,
    Event {
        outbox: bool,
        sequence: u64,
        id: EventId,
        previous: EventId,
    },
    Peer(DeliveryHead),
    Receipt(DeliveryHead),
}
fn parse_sequence(raw: &str) -> Result<u64, Error> {
    if raw.len() != 16
        || !raw
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Corrupt);
    }
    let value = u64::from_str_radix(raw, 16).map_err(|_| Error::Corrupt)?;
    if value == 0 {
        return Err(Error::Corrupt);
    }
    Ok(value)
}
fn parse_peer(raw: &str) -> Result<[u8; 32], Error> {
    if raw.len() != 64
        || !raw
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Corrupt);
    }
    let mut peer = [0; 32];
    for (i, b) in peer.iter_mut().enumerate() {
        *b = u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16).map_err(|_| Error::Corrupt)?;
    }
    Ok(peer)
}

/// A portable incremental completeness validator with constant retained memory.
/// Receipt-to-event byte joins are checked by the storage adapter separately.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Validator {
    last: String,
    event_sequence: u64,
    event_id: [u8; 32],
    outbox_sequence: u64,
    outbox_id: [u8; 32],
    peer: Option<DeliveryHead>,
    receipt: Option<DeliveryHead>,
    seen: u8,
}
impl Validator {
    pub(crate) fn push(&mut self, snapshot: &Snapshot, entry: &Entry) -> Result<(), Error> {
        if entry.key <= self.last {
            return Err(Error::Corrupt);
        }
        match entry.kind(snapshot)? {
            Kind::Peer(head) => {
                self.peer_complete()?;
                self.peer = Some(head);
                self.receipt = None;
            }
            Kind::Receipt(head) => {
                let expected = self.peer.ok_or(Error::Corrupt)?;
                if expected.peer() != head.peer()
                    || head.sequence()
                        != self
                            .receipt
                            .map_or(Some(1), |r| r.sequence().checked_add(1))
                            .ok_or(Error::Bounds)?
                    || head.sequence() > expected.sequence()
                    || self
                        .receipt
                        .is_some_and(|r| head.local_cursor() <= r.local_cursor())
                {
                    return Err(Error::Corrupt);
                }
                self.receipt = Some(head);
            }
            Kind::Event {
                outbox,
                sequence,
                id,
                previous,
            } => {
                self.peer_complete()?;
                let (prior, prior_id) = if outbox {
                    (&mut self.outbox_sequence, &mut self.outbox_id)
                } else {
                    (&mut self.event_sequence, &mut self.event_id)
                };
                if prior.checked_add(1) != Some(sequence) || previous.as_bytes() != prior_id {
                    return Err(Error::Corrupt);
                }
                *prior = sequence;
                *prior_id = *id.as_bytes();
            }
            Kind::Head => {
                self.peer_complete()?;
                self.seen |= 1;
            }
            Kind::Pending => {
                self.seen |= 2;
            }
            Kind::Revision => {
                self.seen |= 4;
            }
        }
        self.last = entry.key.clone();
        Ok(())
    }
    fn peer_complete(&self) -> Result<(), Error> {
        if self.peer != self.receipt {
            return Err(Error::Corrupt);
        }
        Ok(())
    }
    pub(crate) fn finish(&self, snapshot: &Snapshot) -> Result<(), Error> {
        self.peer_complete()?;
        if self.event_sequence != snapshot.head.sequence()
            || self.outbox_sequence != snapshot.head.sequence()
            || self.event_id != *snapshot.head.event_id().as_bytes()
            || self.outbox_id != self.event_id
            || self.seen
                != 1 | (u8::from(snapshot.pending.is_some()) << 1)
                    | (u8::from(snapshot.revision.is_some()) << 2)
        {
            return Err(Error::Corrupt);
        }
        Ok(())
    }
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut raw = Vec::new();
        raw.push(self.last.len() as u8);
        raw.extend_from_slice(self.last.as_bytes());
        for (seq, id) in [
            (self.event_sequence, self.event_id),
            (self.outbox_sequence, self.outbox_id),
        ] {
            raw.extend_from_slice(&seq.to_be_bytes());
            raw.extend_from_slice(&id);
        }
        raw.push(self.seen);
        for head in [self.peer, self.receipt] {
            raw.push(u8::from(head.is_some()));
            if let Some(head) = head {
                raw.extend_from_slice(&head.encode());
            }
        }
        raw
    }
    pub(crate) fn decode(raw: &[u8]) -> Result<Self, Error> {
        let mut r = Reader(raw);
        let len = r.array::<1>()?[0] as usize;
        if len > MAX_ENTRY_KEY {
            return Err(Error::Bounds);
        }
        let last = std::str::from_utf8(r.take(len)?)
            .map_err(|_| Error::Corrupt)?
            .to_owned();
        let event_sequence = u64::from_be_bytes(r.array()?);
        let event_id = r.array()?;
        let outbox_sequence = u64::from_be_bytes(r.array()?);
        let outbox_id = r.array()?;
        let seen = r.array::<1>()?[0];
        let mut heads = [None, None];
        for head in &mut heads {
            *head = match r.array::<1>()?[0] {
                0 => None,
                1 => Some(DeliveryHead::decode(r.take(264)?)?),
                _ => return Err(Error::Corrupt),
            };
        }
        if !r.0.is_empty() || seen > 7 {
            return Err(Error::Corrupt);
        }
        Ok(Self {
            last,
            event_sequence,
            event_id,
            outbox_sequence,
            outbox_id,
            seen,
            peer: heads[0],
            receipt: heads[1],
        })
    }
}

/// Streaming export continuation; a page or final marker alone is not a backup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Export {
    pub(crate) snapshot: Snapshot,
    pub(crate) backup: [u8; 32],
    pub(crate) index: u64,
    pub(crate) previous: [u8; 32],
    pub(crate) validator: Validator,
    pub(crate) ended: bool,
}
impl Export {
    pub(crate) fn new(snapshot: Snapshot, backup: [u8; 32]) -> Self {
        Self {
            snapshot,
            backup,
            index: 0,
            previous: [0; 32],
            validator: Validator::default(),
            ended: false,
        }
    }
    /// Exact captured source floor and pending intent.
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }
    /// All source keys have been read; finish still rechecks source state.
    pub const fn ended(&self) -> bool {
        self.ended
    }
    #[cfg(target_arch = "wasm32")]
    pub(crate) fn last(&self) -> &str {
        &self.validator.last
    }
    pub(crate) fn page(
        &self,
        entries: &[Entry],
        final_page: bool,
    ) -> Result<AuthorBackupPage, Error> {
        if entries.len() > PAGE_ENTRIES || (final_page && !entries.is_empty()) {
            return Err(Error::Bounds);
        }
        let snapshot = self.snapshot.encode();
        let mut payload = Vec::new();
        payload.extend_from_slice(&(snapshot.len() as u16).to_be_bytes());
        payload.extend_from_slice(&snapshot);
        payload.extend_from_slice(&(entries.len() as u16).to_be_bytes());
        for entry in entries {
            payload.push(entry.key.len() as u8);
            payload.extend_from_slice(entry.key.as_bytes());
            payload.extend_from_slice(&(entry.value.len() as u32).to_be_bytes());
            payload.extend_from_slice(&entry.value);
        }
        AuthorBackupPage::new(
            self.snapshot.context(),
            self.backup,
            self.index,
            self.previous,
            final_page,
            &payload,
        )
        .map_err(|_| Error::Bounds)
    }
    pub(crate) fn advance(&self, page: &AuthorBackupPage) -> Result<Self, Error> {
        let (snapshot, entries) = decode_page(page)?;
        if snapshot != self.snapshot
            || page.backup_id() != self.backup
            || page.index() != self.index
            || page.previous() != self.previous
            || self.ended
        {
            return Err(Error::Stale);
        }
        let mut next = self.clone();
        for entry in entries {
            next.validator.push(&snapshot, &entry)?;
        }
        if page.is_final() {
            next.validator.finish(&snapshot)?;
            next.ended = true;
        }
        next.index = next.index.checked_add(1).ok_or(Error::Bounds)?;
        next.previous = page.digest();
        Ok(next)
    }
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut raw = Vec::new();
        raw.extend_from_slice(b"VHBEXP01");
        let snap = self.snapshot.encode();
        raw.extend_from_slice(&(snap.len() as u16).to_be_bytes());
        raw.extend_from_slice(&snap);
        raw.extend_from_slice(&self.backup);
        raw.extend_from_slice(&self.index.to_be_bytes());
        raw.extend_from_slice(&self.previous);
        raw.push(u8::from(self.ended));
        raw.extend_from_slice(&self.validator.encode());
        raw
    }
    pub(crate) fn decode(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() > MAX_SNAPSHOT_BYTES + 1024 {
            return Err(Error::Bounds);
        }
        let mut r = Reader(raw);
        if &r.array::<8>()? != b"VHBEXP01" {
            return Err(Error::Corrupt);
        }
        let len = u16::from_be_bytes(r.array()?) as usize;
        let snapshot = Snapshot::decode(r.take(len)?)?;
        let backup = r.array()?;
        let index = u64::from_be_bytes(r.array()?);
        let previous = r.array()?;
        let ended = match r.array::<1>()?[0] {
            0 => false,
            1 => true,
            _ => return Err(Error::Corrupt),
        };
        let validator = Validator::decode(r.0)?;
        Ok(Self {
            snapshot,
            backup,
            index,
            previous,
            ended,
            validator,
        })
    }
}
pub(crate) fn decode_page(page: &AuthorBackupPage) -> Result<(Snapshot, Vec<Entry>), Error> {
    let mut r = Reader(page.payload());
    let len = u16::from_be_bytes(r.array()?) as usize;
    let snapshot = Snapshot::decode(r.take(len)?)?;
    if page.scope() != &snapshot.context() {
        return Err(Error::WrongScope);
    }
    let count = u16::from_be_bytes(r.array()?) as usize;
    if count > PAGE_ENTRIES || (page.is_final() && count != 0) || (!page.is_final() && count == 0) {
        return Err(Error::Bounds);
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let len = r.array::<1>()?[0] as usize;
        if len > MAX_ENTRY_KEY {
            return Err(Error::Bounds);
        }
        let key = std::str::from_utf8(r.take(len)?)
            .map_err(|_| Error::Corrupt)?
            .to_owned();
        let len = u32::from_be_bytes(r.array()?) as usize;
        if len > MAX_ENTRY_BYTES {
            return Err(Error::Bounds);
        }
        entries.push(Entry::new(key, r.take(len)?.to_vec(), &snapshot)?);
    }
    if !r.0.is_empty() {
        return Err(Error::Corrupt);
    }
    Ok((snapshot, entries))
}

/// Durable incomplete recovery progress. Possession never authorizes signing.
/// Only successful final activation publishes the retained author head.
#[derive(Clone, Eq, PartialEq)]
pub struct Import {
    pub(crate) stream: Export,
    pub(crate) identity: crate::identity::IdentitySnapshot,
    pub(crate) verified_after: String,
    pub(crate) verified: bool,
}
impl Import {
    #[cfg(any(test, target_arch = "wasm32"))]
    pub(crate) fn guard(
        &self,
        observed: &Self,
        identity: &crate::identity::IdentitySnapshot,
        active_head: bool,
    ) -> Result<(), Error> {
        if active_head
            || identity != &self.identity
            || observed.identity != self.identity
            || observed.snapshot() != self.snapshot()
            || observed.backup_id() != self.backup_id()
        {
            return Err(Error::Stale);
        }
        Ok(())
    }
    pub(crate) fn advance(&self, page: &AuthorBackupPage) -> Result<Self, Error> {
        decode_page(page)?;
        if page.index().checked_add(1) == Some(self.stream.index)
            && page.digest() == self.stream.previous
            && page.backup_id() == self.stream.backup
            && page.scope() == &self.snapshot().context()
        {
            return Ok(self.clone());
        }
        let mut next = self.clone();
        next.stream = self.stream.advance(page)?;
        Ok(next)
    }
    /// Next expected page number; use this after reopening an uncertain write.
    pub fn next_page(&self) -> u64 {
        self.stream.index
    }
    /// Exact backup identifier this partial namespace is reserved for.
    pub fn backup_id(&self) -> [u8; 32] {
        self.stream.backup
    }
    /// The complete intended author floor and pending intent.
    pub fn snapshot(&self) -> &Snapshot {
        &self.stream.snapshot
    }
    /// The authenticated final frame has been retained; joins may remain.
    pub fn received_final(&self) -> bool {
        self.stream.ended
    }
    /// Every retained peer receipt has been joined to its signed local event.
    pub fn ready_to_activate(&self) -> bool {
        self.verified && self.stream.ended
    }
    #[cfg(any(test, target_arch = "wasm32"))]
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut raw = b"VHBIMP01".to_vec();
        let stream = self.stream.encode();
        raw.extend_from_slice(&(stream.len() as u16).to_be_bytes());
        raw.extend_from_slice(&stream);
        let vault = self
            .identity
            .vault()
            .expect("validated imported identity")
            .as_bytes();
        raw.extend_from_slice(&(vault.len() as u16).to_be_bytes());
        raw.extend_from_slice(vault);
        let birth = self.identity.birth_bytes();
        raw.push(u8::from(birth.is_some()));
        if let Some(birth) = birth {
            raw.extend_from_slice(&birth);
        }
        raw.push(self.verified_after.len() as u8);
        raw.extend_from_slice(self.verified_after.as_bytes());
        raw.push(u8::from(self.verified));
        // Detect torn/accidentally altered progress, especially the verified
        // flag. This is not authentication against a hostile origin or rollback.
        let digest = Sha256::digest(&raw);
        raw.extend_from_slice(&digest);
        raw
    }
    #[cfg(any(test, target_arch = "wasm32"))]
    pub(crate) fn decode(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() > MAX_IMPORT_BYTES {
            return Err(Error::Bounds);
        }
        let content_length = raw.len().checked_sub(32).ok_or(Error::Corrupt)?;
        let (content, checksum) = raw.split_at(content_length);
        if &Sha256::digest(content)[..] != checksum {
            return Err(Error::Corrupt);
        }
        let mut r = Reader(content);
        if &r.array::<8>()? != b"VHBIMP01" {
            return Err(Error::Corrupt);
        }
        let len = u16::from_be_bytes(r.array()?) as usize;
        let stream = Export::decode(r.take(len)?)?;
        let len = u16::from_be_bytes(r.array()?) as usize;
        let vault = r.take(len)?;
        let birth = match r.array::<1>()?[0] {
            0 => None,
            1 => Some(r.take(40)?),
            _ => return Err(Error::Corrupt),
        };
        let identity = crate::identity::IdentitySnapshot::decode(Some(vault), birth)?;
        if crate::identity::vault_public(identity.vault().ok_or(Error::Corrupt)?)?
            != stream.snapshot.head.scope().author()
        {
            return Err(Error::WrongScope);
        }
        let len = r.array::<1>()?[0] as usize;
        if len > MAX_ENTRY_KEY {
            return Err(Error::Bounds);
        }
        let verified_after = std::str::from_utf8(r.take(len)?)
            .map_err(|_| Error::Corrupt)?
            .to_owned();
        let verified = match r.array::<1>()?[0] {
            0 => false,
            1 => true,
            _ => return Err(Error::Corrupt),
        };
        if !r.0.is_empty() || (verified && !stream.ended) {
            return Err(Error::Corrupt);
        }
        Ok(Self {
            stream,
            identity,
            verified_after,
            verified,
        })
    }
}

#[cfg(test)]
mod tests;
