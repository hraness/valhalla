//! Durable authoring reservations, distinct from remote activity admission.
//!
//! An exact unsigned event must be reserved before a worker signs it. A pending
//! reservation is never canceled or replaced: a crash may have happened after
//! signature creation. Restored keys need independently recovered author floors;
//! a key backup alone cannot establish that sequence one has never been used.
use crate::{history::HistoryHead, Error};
use vhalla_room_activity::{EventId, RoomScope, UnsignedEvent, VerifiedEvent, MAX_UNSIGNED_BYTES};

pub mod delivery;
pub mod recovery;

const HEAD_MAGIC: &[u8; 8] = b"VHBAHD01";
const DRAFT_MAGIC: &[u8; 8] = b"VHBADR01";
pub(crate) const AUTHOR_HEAD_BYTES: usize = 192;
const DRAFT_HEADER_BYTES: usize = 8 + AUTHOR_HEAD_BYTES + 248 + 4;
/// Maximum exact reservation bytes, checked before allocation.
pub const MAX_RESERVATION_BYTES: usize = DRAFT_HEADER_BYTES + MAX_UNSIGNED_BYTES;
/// Bounded number of signed outbox records per operation.
pub const MAX_OUTBOX_PAGE_RECORDS: usize = 16;
/// Bounded signed bytes per outbox page.
pub const MAX_OUTBOX_PAGE_BYTES: usize = 128 * 1024;

/// Full immutable room and author scope. Configuration rotations do not reset it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorScope {
    network: [u8; 32],
    realm: [u8; 16],
    directory: [u8; 32],
    room: [u8; 32],
    author: [u8; 32],
}
impl AuthorScope {
    /// Derive storage identity from the complete typed room scope and full key.
    #[must_use]
    pub fn new(room: RoomScope, author: [u8; 32]) -> Self {
        Self {
            network: room.network,
            realm: room.realm.0.to_be_bytes(),
            directory: *room.directory.as_bytes(),
            room: *room.room.as_bytes(),
            author,
        }
    }
    /// Full application signing key.
    #[must_use]
    pub const fn author(self) -> [u8; 32] {
        self.author
    }
    /// Immutable public network identifier.
    #[must_use]
    pub const fn network(self) -> [u8; 32] {
        self.network
    }
    fn encode(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.network);
        out.extend_from_slice(&self.realm);
        out.extend_from_slice(&self.directory);
        out.extend_from_slice(&self.room);
        out.extend_from_slice(&self.author);
    }
}

/// Exact retained local authoring floor; not a remote admission receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorHead {
    scope: AuthorScope,
    sequence: u64,
    event: EventId,
}
impl AuthorHead {
    /// Authorize a genuinely never-used room/key scope at sequence zero.
    ///
    /// This is an explicit controller trust decision, not a storage observation.
    /// An absent database, restored key, server head, or lost key history cannot
    /// justify calling this. Recovery/import of previously used scopes is separate.
    #[must_use]
    pub const fn fresh_scope_authorized(scope: AuthorScope) -> Self {
        Self {
            scope,
            sequence: 0,
            event: EventId::ZERO,
        }
    }
    /// Full authoring scope.
    #[must_use]
    pub const fn scope(self) -> AuthorScope {
        self.scope
    }
    /// Highest locally finalized signed sequence, whether delivered or not.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
    /// Exact local event at this floor; zero only at initialized genesis.
    #[must_use]
    pub const fn event_id(self) -> EventId {
        self.event
    }
    /// Canonical exact-CAS bytes.
    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(AUTHOR_HEAD_BYTES);
        out.extend_from_slice(HEAD_MAGIC);
        self.scope.encode(&mut out);
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(self.event.as_bytes());
        out
    }
    /// Parse metadata framing only. Restore only the actual durable local floor.
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() != AUTHOR_HEAD_BYTES {
            return Err(Error::Corrupt);
        }
        let mut input = Reader(raw);
        if &input.array::<8>()? != HEAD_MAGIC {
            return Err(Error::Corrupt);
        }
        let scope = AuthorScope {
            network: input.array()?,
            realm: input.array()?,
            directory: input.array()?,
            room: input.array()?,
            author: input.array()?,
        };
        let sequence = u64::from_be_bytes(input.array()?);
        let event = EventId::from_bytes(input.array()?);
        if (sequence == 0) != (event == EventId::ZERO) {
            return Err(Error::Corrupt);
        }
        Ok(Self {
            scope,
            sequence,
            event,
        })
    }
}

/// Exact unsigned content and policy basis that must survive before signing.
/// Possession is not a persistence receipt: only reserve transaction completion
/// permits dispatch to the worker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservedDraft {
    base: AuthorHead,
    policy: HistoryHead,
    request: UnsignedEvent,
    bytes: Vec<u8>,
}
impl ReservedDraft {
    /// Freeze a next-sequence typed request under a controller-verified policy.
    /// The controller must first check current room admission against its
    /// certified registry; storage only checks exact policy-head continuity.
    pub fn new(
        base: AuthorHead,
        policy: HistoryHead,
        request: UnsignedEvent,
    ) -> Result<Self, Error> {
        let claims = request.claims();
        if AuthorScope::new(claims.scope, claims.author) != base.scope
            || claims.scope.network != policy.scope().network()
        {
            return Err(Error::WrongScope);
        }
        if base.sequence.checked_add(1) != Some(claims.sequence) || claims.previous != base.event {
            return Err(Error::Stale);
        }
        let raw = request.encode();
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(DRAFT_HEADER_BYTES + raw.len())
            .map_err(|_| Error::Bounds)?;
        bytes.extend_from_slice(DRAFT_MAGIC);
        bytes.extend_from_slice(&base.encode());
        bytes.extend_from_slice(&policy.encode());
        bytes.extend_from_slice(&(raw.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&raw);
        Ok(Self {
            base,
            policy,
            request,
            bytes,
        })
    }
    /// Parse exact typed unsigned framing; this is not a completed reservation.
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() > MAX_RESERVATION_BYTES {
            return Err(Error::Bounds);
        }
        let mut input = Reader(raw);
        if &input.array::<8>()? != DRAFT_MAGIC {
            return Err(Error::Corrupt);
        }
        let base = AuthorHead::decode(input.take(AUTHOR_HEAD_BYTES)?)?;
        let policy = HistoryHead::decode(input.take(248)?)?;
        let length = u32::from_be_bytes(input.array()?) as usize;
        let request = UnsignedEvent::decode(input.take(length)?).map_err(|_| Error::Corrupt)?;
        if !input.0.is_empty() {
            return Err(Error::Corrupt);
        }
        Self::new(base, policy, request)
    }
    /// Prior exact author floor.
    #[must_use]
    pub const fn base(&self) -> AuthorHead {
        self.base
    }
    /// Exact certified-history basis selected by the controller.
    #[must_use]
    pub const fn policy_head(&self) -> HistoryHead {
        self.policy
    }
    /// Only these exact typed bytes may be sent to the signing worker.
    #[must_use]
    pub const fn request(&self) -> &UnsignedEvent {
        &self.request
    }
    /// Exact durable reservation framing.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Bind a strictly verified worker response to this exact reservation.
    pub fn signed_head(&self, event: &VerifiedEvent) -> Result<AuthorHead, Error> {
        if event.id() != self.request.id() || event.claims() != self.request.claims() {
            return Err(Error::Stale);
        }
        Ok(AuthorHead {
            scope: self.base.scope,
            sequence: event.claims().sequence,
            event: event.id(),
        })
    }
}

/// Bounded retained signed outbox page; receipt by another peer is not implied.
pub struct OutboxPage {
    /// Locally finalized author floor observed in the same transaction.
    pub head: AuthorHead,
    /// Strictly verified signatures, still requiring room-policy/chain admission.
    pub events: Vec<VerifiedEvent>,
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        if count > self.0.len() {
            return Err(Error::Corrupt);
        }
        let (value, rest) = self.0.split_at(count);
        self.0 = rest;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Corrupt)
    }
}

#[cfg(any(test, unix, target_arch = "wasm32"))]
pub(crate) fn check_reservation(
    draft: &ReservedDraft,
    head: Option<&[u8]>,
    pending: Option<&[u8]>,
    policy: Option<&[u8]>,
) -> Result<(), Error> {
    crate::compare_exact(Some(&draft.base.encode()), head)?;
    crate::compare_exact(Some(&draft.policy.encode()), policy)?;
    if pending.is_some_and(|raw| raw != draft.as_bytes()) {
        return Err(Error::Stale);
    }
    Ok(())
}
#[cfg(any(test, unix, target_arch = "wasm32"))]
pub(crate) fn check_finalize(
    draft: &ReservedDraft,
    head: Option<&[u8]>,
    pending: Option<&[u8]>,
    policy: Option<&[u8]>,
) -> Result<(), Error> {
    check_reservation(draft, head, pending, policy)?;
    crate::compare_exact(Some(draft.as_bytes()), pending)
}

#[cfg(any(test, unix, target_arch = "wasm32"))]
pub(crate) fn rebase_shape(old: &ReservedDraft, new: &ReservedDraft) -> Result<(), Error> {
    if old.base != new.base
        || old.request.id() != new.request.id()
        || old.request.encode() != new.request.encode()
    {
        return Err(Error::Stale);
    }
    if old.policy.scope() != new.policy.scope() {
        return Err(Error::WrongScope);
    }
    if new.policy.frontier().height <= old.policy.frontier().height {
        return Err(Error::Stale);
    }
    Ok(())
}

#[cfg(any(test, unix, target_arch = "wasm32"))]
pub(crate) fn check_rebase(
    old: &ReservedDraft,
    new: &ReservedDraft,
    head: Option<&[u8]>,
    pending: Option<&[u8]>,
    current_policy: Option<&[u8]>,
) -> Result<(), Error> {
    rebase_shape(old, new)?;
    crate::compare_exact(Some(&old.base.encode()), head)?;
    crate::compare_exact(Some(&new.policy.encode()), current_policy)?;
    // Reconcile an uncertain successful write without overwriting any competing
    // intent. Both permitted images contain exactly the same unsigned bytes.
    if pending != Some(old.as_bytes()) && pending != Some(new.as_bytes()) {
        return Err(Error::Stale);
    }
    Ok(())
}
#[cfg(any(test, target_arch = "wasm32"))]
pub(crate) fn prefix(scope: AuthorScope) -> String {
    let mut bytes = Vec::with_capacity(144);
    scope.encode(&mut bytes);
    let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    format!("authoring/v1/{hex}/")
}
#[cfg(test)]
mod tests;
