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
    pub(super) sequence: u64,
    pub(super) event: EventId,
    pub(super) pages: u32,
    pub(super) expires: u64,
}
impl StageTicket {
    /// Full local stage identifier, bound to scope, author and published base.
    pub const fn id(&self) -> [u8; 32] {
        self.id
    }
    /// Full author key.
    pub const fn author(&self) -> [u8; 32] {
        self.author
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
