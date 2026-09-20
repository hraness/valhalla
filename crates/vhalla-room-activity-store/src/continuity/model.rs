//! Public model for the explicit new continuity-capable native store format.
use super::catalogue::{MAX_STAGE_EVENTS, MAX_STAGE_SLOTS, MAX_STAGE_STORAGE_BYTES};
use super::frames::{Evidence, Terminal};
use crate::{Error, Limits};
use vhalla_room_activity::{continuity::EvidenceRole, EventId, VerifiedEvent};

/// Immutable local resource budgets; they grant no network admission entitlement.
/// Temporary stage pages are reclaimable. Published signed evidence is retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContinuityLimits {
    /// Permanent evidence/receipt budgets, separate from temporary stage storage.
    pub history: Limits,
    /// Concurrent temporary author suffixes, between one and 64.
    pub max_stage_slots: u16,
    /// Total unreclaimed staged ancestors, between 32 and 4,096.
    pub max_stage_events: u64,
    /// Maximum unreclaimed exact stage page bytes, at most 32 MiB.
    pub max_stage_bytes: u64,
    /// Fixed staging lease from 60 to 86,400 seconds; retries never extend it.
    pub stage_ttl_seconds: u64,
}
impl ContinuityLimits {
    pub(super) fn check(self) -> Result<(), Error> {
        if self.history.max_events == 0
            || self.history.max_history_bytes == 0
            || self.max_stage_slots == 0
            || usize::from(self.max_stage_slots) > MAX_STAGE_SLOTS
            || !(32..=MAX_STAGE_EVENTS).contains(&self.max_stage_events)
            || self.max_stage_bytes == 0
            || self.max_stage_bytes > MAX_STAGE_STORAGE_BYTES
            || !(60..=86400).contains(&self.stage_ttl_seconds)
        {
            return Err(Error::Capacity);
        }
        Ok(())
    }
}

/// Exact temporary upload position. It does not move an admitted author floor.
/// Retain the original author history locally: the peer may expire these bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StageTicket {
    pub(super) id: [u8; 32],
    pub(super) author: [u8; 32],
    pub(super) base: AuthorPosition,
    pub(super) sequence: u64,
    pub(super) event: EventId,
    pub(super) pages: u32,
    pub(super) expires: u64,
}
impl StageTicket {
    /// Check a request's positional ticket shape and reject the impossible zero
    /// author sentinel. This proves no persistence or full-key validity; checked
    /// operations bind the author to strictly verified events and retained state.
    pub fn new(
        id: [u8; 32],
        author: [u8; 32],
        base: AuthorPosition,
        tail: AuthorPosition,
        pages: u32,
        expires_at: u64,
    ) -> Result<Self, Error> {
        if id == [0; 32]
            || author == [0; 32]
            || pages == 0
            || u64::from(pages) > MAX_STAGE_EVENTS / 32
            || expires_at == 0
            || base.sequence.checked_add(u64::from(pages) * 32) != Some(tail.sequence)
        {
            return Err(Error::Conflict);
        }
        Ok(Self {
            id,
            author,
            base,
            sequence: tail.sequence,
            event: tail.event,
            pages,
            expires: expires_at,
        })
    }
    /// Full local stage identifier, bound to scope, author and published base.
    pub const fn id(&self) -> [u8; 32] {
        self.id
    }
    /// Full author key.
    pub const fn author(&self) -> [u8; 32] {
        self.author
    }
    /// Exact published author base from which this temporary suffix extends.
    pub const fn base(&self) -> AuthorPosition {
        self.base
    }
    /// Exact temporary tail, never an admitted author head.
    pub const fn tail(&self) -> AuthorPosition {
        AuthorPosition {
            sequence: self.sequence,
            event: self.event,
        }
    }
    /// Last checked staged sequence, not an admitted position.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    /// Exact last checked staged event.
    pub const fn event_id(&self) -> EventId {
        self.event
    }
    /// Number of complete fixed-size temporary pages.
    pub const fn pages(&self) -> u32 {
        self.pages
    }
    /// Exclusive expiry; progress and exact retries do not renew it.
    pub const fn expires_at(&self) -> u64 {
        self.expires
    }
}

/// Structurally checked full author position; metadata alone is not evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorPosition {
    pub(super) sequence: u64,
    pub(super) event: EventId,
}
impl AuthorPosition {
    /// No published event; both sentinel fields are zero.
    pub const EMPTY: Self = Self {
        sequence: 0,
        event: EventId::ZERO,
    };
    /// Check the empty/nonempty shape without accepting any history.
    pub fn new(sequence: u64, event: EventId) -> Result<Self, Error> {
        if (sequence == 0) != (event == EventId::ZERO) {
            return Err(Error::Conflict);
        }
        Ok(Self { sequence, event })
    }
    /// Full sequence, zero only for the empty sentinel.
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
    /// Exact event ID, zero only for the empty sentinel.
    pub const fn event_id(self) -> EventId {
        self.event
    }
}

/// Explicit fresh-work precondition supplied by a requester, not authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkExpectation {
    /// Exact published author floor before fresh work.
    pub published: AuthorPosition,
    /// Exact temporary prefix, or none for direct next-event admission.
    pub stage: Option<StageTicket>,
}

/// Checked read-only view at a caller-supplied trusted time. Reading neither
/// advances the retained clock nor expires/deletes files.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorStatus {
    pub(super) published: AuthorPosition,
    pub(super) stage: Option<StageTicket>,
    pub(super) cleanup_pages: u32,
}
impl AuthorStatus {
    /// Exact validated admitted author floor.
    pub const fn published(self) -> AuthorPosition {
        self.published
    }
    /// Live exact prefix only; expired or published cleanup is never live.
    pub const fn stage(self) -> Option<StageTicket> {
        self.stage
    }
    /// This author's expired/published duplicate pages awaiting maintenance.
    pub const fn cleanup_pages(self) -> u32 {
        self.cleanup_pages
    }
}

/// Logical bounded work charged before a checked mutation. This is not a
/// timing/fsync estimate: the current implementation can verify a frame more
/// than once, and finalization traverses the retained prefix several times.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkQuote {
    pub(super) frames: usize,
    pub(super) retained_ancestors: u64,
    pub(super) reconciled: bool,
}
impl WorkQuote {
    /// Submitted signed frames; independently bounded by 33.
    pub const fn frames(self) -> usize {
        self.frames
    }
    /// Retained ancestors participating in a new terminal finalization.
    pub const fn retained_ancestors(self) -> u64 {
        self.retained_ancestors
    }
    /// Exact already-retained page or terminal retry.
    pub const fn reconciled(self) -> bool {
        self.reconciled
    }
    pub(super) fn check(self, allowance: WorkAllowance) -> Result<(), Error> {
        if self.frames > allowance.frames || self.retained_ancestors > allowance.retained_ancestors
        {
            return Err(Error::Capacity);
        }
        Ok(())
    }
}

/// Caller-reserved local work credits. Checked operations recompute the quote
/// and refuse before writes if it exceeds these credits. They do no cleanup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkAllowance {
    /// Maximum charged submitted frames.
    pub frames: usize,
    /// Maximum charged retained ancestors for new finalization.
    pub retained_ancestors: u64,
}

/// Bounded read-only maintenance quote at a trusted time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaintenanceQuote {
    pub(super) pages: u32,
    pub(super) clock_transition: bool,
    pub(super) more: bool,
}
impl MaintenanceQuote {
    /// Maximum pages this bounded maintenance call will remove.
    pub const fn pages(self) -> u32 {
        self.pages
    }
    /// A retained clock/catalogue transition is needed before cleanup.
    pub const fn clock_transition(self) -> bool {
        self.clock_transition
    }
    /// Further bounded calls will be needed to finish current cleanup.
    pub const fn more(self) -> bool {
        self.more
    }
}

/// A terminal durably admitted by this local storage owner under its frozen
/// certified policy view. This is not consensus, current permission or delivery.
#[derive(Clone, Debug)]
pub struct ContinuityReceipt {
    pub(super) terminal: Terminal,
    pub(super) reconciled: bool,
}
impl ContinuityReceipt {
    /// Exact signed terminal bytes, independently authenticated by its author.
    pub fn event(&self) -> &VerifiedEvent {
        &self.terminal.event
    }
    /// Local feed cursor. Historical continuity entries never get feed cursors.
    pub const fn cursor(&self) -> u64 {
        self.terminal.ordinal
    }
    /// Frozen local registry evaluation basis; this digest is not a certificate.
    pub const fn registry_digest(&self) -> &[u8; 32] {
        &self.terminal.registry
    }
    /// Whether this was an exact retry or recovery of a previously frozen decision.
    pub const fn reconciled(&self) -> bool {
        self.reconciled
    }
}

/// Permanent causal evidence carrying an explicit, immutable local role.
#[derive(Clone, Debug)]
pub struct PublishedEvidence {
    pub(super) record: Evidence,
}
impl PublishedEvidence {
    /// Exact signed event; signature alone supplies no current-policy permission.
    pub fn event(&self) -> &VerifiedEvent {
        &self.record.event
    }
    /// Historical ancestors cannot silently be relabelled as local fresh posts.
    pub const fn role(&self) -> EvidenceRole {
        self.record.role
    }
    /// Terminal transaction that retained this event permanently.
    pub const fn committed_by(&self) -> u64 {
        self.record.committed_by
    }
    /// Certified view used for historical checking or terminal admission.
    /// It cannot establish when an ancestor was signed or previously delivered.
    pub const fn registry_digest(&self) -> &[u8; 32] {
        &self.record.registry
    }
}

/// Outcome of one bounded temporary-page reclamation step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Maintenance {
    /// Number of exact catalogue-owned temporary pages removed in this operation.
    pub pages_removed: u32,
    /// Further bounded calls can finish known expired or copied stage cleanup.
    pub more: bool,
}
