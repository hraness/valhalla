//! A fixed-room, process-lifetime capability surface for a cooperating agent host.
//!
//! Only a trusted controller constructs the grant and retains its revocation
//! handle. Register the session's five methods as agent tools, not constructors,
//! kernel methods, or storage access. This is an API boundary, not an OS sandbox:
//! an agent with independent filesystem, process, key or network access can bypass
//! it. Granting inbox access also releases its plaintext to the agent's inference
//! provider. No content classifier promises to detect every secret.
//!
//! A grant never renews, changes rooms, or follows a changed roster. The host must
//! discard the old agent context before separately authorizing a new session.
//! Quotas and expiry are local to this process; a host that constructs another
//! grant can grant more authority. Queueing retains an exact encrypted outbox
//! record, but this interface never exports ciphertext or contacts a relay.

use std::{
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Weak,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use vhalla_private_kernel::{
    storage::Store, CommittedOutbox, Context, InboxPage, Kernel, MessageDraft, OperationId,
    OutboxEntry, OutboxKind, Phase, Status, MAX_BODY_BYTES, MAX_PAGE_BYTES, MAX_PAGE_RECORDS,
};

/// A local refusal; none permits replacing missing or uncertain durable state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The trusted controller revoked or dropped its authority handle.
    Revoked,
    /// The process-monotonic deadline has elapsed.
    Expired,
    /// The exact context, epoch or roster no longer matches the grant.
    AuthorityChanged,
    /// This operation was not granted.
    Denied,
    /// An explicit page, body or duration bound is invalid.
    Bounds,
    /// The finite process budget is exhausted.
    Quota,
    /// The draft reference was replaced or belongs to another session.
    StaleDraft,
    /// A failed/canceled operation requires trusted host reconciliation.
    NeedsReopen,
    /// Trusted wall time is unavailable or a clock moved backwards.
    Clock,
    /// The kernel refused the exact local storage/MLS operation.
    Kernel(vhalla_private_kernel::Error),
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;

/// Operations the trusted controller explicitly makes available in this room.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Permissions {
    /// Read retained authenticated plaintext as inert, untrusted content.
    pub inbox: bool,
    /// Prepare and durably queue application messages for the exact roster.
    pub queue: bool,
    /// Read outbox metadata, never ciphertext or a delivery assertion.
    pub outbox_status: bool,
}

/// Finite process-local allowances. Reads charge the requested maximum before
/// I/O; failed or canceled operations are not refunded. Recreating a grant is a
/// new trusted-host authorization, not durable rate limiting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Budget {
    /// Number of bounded draft preparations allowed.
    pub preparations: u64,
    /// Queue attempts allowed, including exact retries.
    pub messages: u64,
    /// Total bytes of message bodies that may be queued.
    pub body_bytes: u64,
    /// Maximum requested inbox/outbox page slots across this session.
    pub read_records: u64,
    /// Maximum requested plaintext bytes for inbox pages, and bounded internal
    /// artifact bytes for outbox metadata pages.
    pub read_bytes: u64,
}

/// Host-only revocation authority. Dropping this sole handle revokes the grant;
/// there is deliberately no clone, renewal or un-revoke operation.
pub struct RevocationHandle(Arc<AtomicBool>);
impl RevocationHandle {
    /// Revoke monotonically. Pending calls recheck before returning any output.
    pub fn revoke(&self) {
        self.0.store(true, Ordering::Release);
    }
}

/// A host-selected standing grant, bound to one exact local accepted roster.
/// Private fields prevent an agent method from replacing or broadening it.
pub struct LocalGrant {
    context: Context,
    epoch: u64,
    roster: [u8; 32],
    deadline: Instant,
    permissions: Permissions,
    budget: Budget,
    authority: Weak<AtomicBool>,
}
impl LocalGrant {
    /// Trusted-host constructor using a locally authenticated kernel status.
    /// Status is not proof of globally newest membership. Lifetimes are at most
    /// one day; the agent cannot supply or adjust either clock.
    pub fn for_status(
        status: Status,
        lifetime: Duration,
        permissions: Permissions,
        budget: Budget,
    ) -> Result<(Self, RevocationHandle)> {
        if lifetime.is_zero() || lifetime > Duration::from_secs(86_400) {
            return Err(Error::Bounds);
        }
        if status.quarantined || matches!(status.phase, Phase::AwaitingWelcome | Phase::Removed) {
            return Err(Error::AuthorityChanged);
        }
        let authority = Arc::new(AtomicBool::new(false));
        Ok((
            Self {
                context: status.context,
                epoch: status.epoch,
                roster: status.roster,
                deadline: Instant::now().checked_add(lifetime).ok_or(Error::Bounds)?,
                permissions,
                budget,
                authority: Arc::downgrade(&authority),
            },
            RevocationHandle(authority),
        ))
    }
}

/// An opaque reference to the one retained draft. It conveys no authority
/// without the originating live session and its current standing grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DraftRef(u64);

/// Cached authenticated local state and remaining process allowances. A separate
/// writer can make it stale; each subsequent I/O checks the exact durable image.
pub struct AgentStatus {
    /// Last locally authenticated kernel status; no global freshness claim.
    pub accepted: Status,
    /// Remaining finite allowances; no uncertain-operation refunds.
    pub remaining: Budget,
    /// The one currently retained draft, if any.
    pub pending: Option<DraftRef>,
}

/// Locally durable outbox metadata. No bytes, export grant, remote receipt or
/// implication that the original roster is still authorized are included.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueuedStatus {
    /// Exact retained local position.
    pub sequence: u64,
    /// Original local operation ID.
    pub operation: OperationId,
    /// Typed artifact kind.
    pub kind: OutboxKind,
    /// Retained ordinary artifact length; secret issuance metadata has no length.
    pub artifact_bytes: Option<usize>,
}
impl QueuedStatus {
    fn from_entry(entry: &OutboxEntry) -> Self {
        match entry {
            OutboxEntry::Artifact(record) => Self::from_committed(record),
            OutboxEntry::ConfidentialOffer {
                sequence,
                operation,
            } => Self {
                sequence: *sequence,
                operation: *operation,
                kind: OutboxKind::ContactOffer,
                artifact_bytes: None,
            },
        }
    }
    fn from_committed(record: &CommittedOutbox) -> Self {
        Self {
            sequence: record.sequence(),
            operation: record.operation(),
            kind: record.kind(),
            artifact_bytes: Some(record.bytes().len()),
        }
    }
}

/// Bounded retained outbox metadata with snapshot pagination.
pub struct OutboxStatusPage {
    /// Locally observed immutable head.
    pub head: u64,
    /// Next exclusive cursor, if more remains in that snapshot.
    pub next: Option<u64>,
    /// Metadata only; ciphertext is intentionally unavailable.
    pub records: Vec<QueuedStatus>,
}

/// The agent-facing surface. No method imports files, changes grants or members,
/// exports artifacts, executes content, signs arbitrary data, or contacts peers.
pub struct AgentRoomSession<S: Store> {
    kernel: Kernel<S>,
    grant: LocalGrant,
    pending: Option<(DraftRef, MessageDraft)>,
    failed: bool,
    last_tick: Instant,
    last_wall: u64,
    #[cfg(test)]
    test_tick: Option<std::rc::Rc<std::cell::Cell<Instant>>>,
}
impl<S: Store> AgentRoomSession<S> {
    // Trusted host delivery operates the same kernel/custody owner. These are
    // never registered as agent methods and never grant network or export rights.
    #[cfg(feature = "client")]
    pub(crate) async fn host_outbox(
        &mut self,
        after: u64,
        limit: usize,
    ) -> Result<vhalla_private_kernel::OutboxPage> {
        self.host_ready()?;
        self.failed = true;
        let page = self
            .kernel
            .outbox(after, limit)
            .await
            .map_err(Error::Kernel)?;
        self.failed = false;
        Ok(page)
    }

    #[cfg(feature = "client")]
    pub(crate) async fn host_receive(
        &mut self,
        raw: &[u8],
    ) -> Result<vhalla_private_kernel::ReceivedMessage> {
        self.host_ready()?;
        let now = self.host_time()?;
        self.failed = true;
        let received = self.kernel.receive(raw, now).await.map_err(Error::Kernel)?;
        self.failed = false;
        Ok(received)
    }

    #[cfg(feature = "client")]
    pub(crate) async fn host_issue_acceptance(
        &mut self,
        operation: OperationId,
        original_ciphertext: &[u8],
    ) -> Result<CommittedOutbox> {
        self.host_ready()?;
        let now = self.host_time()?;
        self.failed = true;
        let receipt = self
            .kernel
            .issue_acceptance(operation, original_ciphertext, now)
            .await
            .map_err(Error::Kernel)?;
        self.failed = false;
        Ok(receipt)
    }

    #[cfg(feature = "client")]
    pub(crate) async fn host_apply_control(&mut self, raw: &[u8]) -> Result<Status> {
        self.host_ready()?;
        let now = self.host_time()?;
        self.failed = true;
        let status = self
            .kernel
            .apply_control(raw, now)
            .await
            .map_err(Error::Kernel)?;
        if status.context != self.grant.context
            || status.epoch != self.grant.epoch
            || status.roster != self.grant.roster
            || status.quarantined
            || matches!(status.phase, Phase::AwaitingWelcome | Phase::Removed)
        {
            if let Some(authority) = self.grant.authority.upgrade() {
                authority.store(true, Ordering::Release);
            }
            self.pending = None;
        }
        self.failed = false;
        Ok(status)
    }

    #[cfg(feature = "client")]
    fn host_ready(&self) -> Result<()> {
        if self.failed || self.kernel.needs_reopen() {
            return Err(Error::NeedsReopen);
        }
        Ok(())
    }

    #[cfg(feature = "client")]
    fn host_time(&mut self) -> Result<u64> {
        let now = wall_time()?;
        if now < self.last_wall {
            return Err(Error::Clock);
        }
        self.last_wall = now;
        Ok(now)
    }

    /// Host-only installation. The host retains revocation authority separately
    /// and exposes only status/inbox/prepare/queue/outbox_status to its agent.
    pub fn new(kernel: Kernel<S>, grant: LocalGrant) -> Result<Self> {
        let mut session = Self {
            kernel,
            grant,
            pending: None,
            failed: false,
            last_tick: Instant::now(),
            last_wall: wall_time()?,
            #[cfg(test)]
            test_tick: None,
        };
        session.check()?;
        Ok(session)
    }

    /// Return bounded cached local status only while the standing grant is live.
    pub fn status(&mut self) -> Result<AgentStatus> {
        let accepted = self.check()?;
        Ok(AgentStatus {
            accepted,
            remaining: self.grant.budget,
            pending: self.pending.as_ref().map(|(id, _)| *id),
        })
    }

    /// Replace the one draft with these explicit inert bytes, bound by the kernel
    /// to the complete current room/author/epoch/roster. No publication occurs.
    pub fn prepare(&mut self, body: &[u8]) -> Result<DraftRef> {
        self.check()?;
        if !self.grant.permissions.queue {
            return Err(Error::Denied);
        }
        if body.is_empty() || body.len() > MAX_BODY_BYTES {
            return Err(Error::Bounds);
        }
        if self.grant.budget.preparations == 0 {
            return Err(Error::Quota);
        }
        self.grant.budget.preparations -= 1;
        let draft = self.kernel.prepare_message(body).map_err(Error::Kernel)?;
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let id = DraftRef(
            NEXT.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
                .map_err(|_| Error::Bounds)?,
        );
        self.pending = Some((id, draft));
        Ok(id)
    }

    /// Queue only the retained exact draft. Charges precede the first await;
    /// cancellation/uncertainty permanently latches this session. A revoked call
    /// can leave durable bytes for trusted recovery, but cannot return output.
    pub async fn queue(&mut self, operation: OperationId, draft: DraftRef) -> Result<QueuedStatus> {
        self.check()?;
        if !self.grant.permissions.queue {
            return Err(Error::Denied);
        }
        let (id, retained) = self.pending.as_ref().ok_or(Error::StaleDraft)?;
        if *id != draft {
            return Err(Error::StaleDraft);
        }
        let bytes = retained.body().len() as u64;
        if self.grant.budget.messages == 0 || self.grant.budget.body_bytes < bytes {
            return Err(Error::Quota);
        }
        let now = wall_time()?;
        if now < self.last_wall {
            return Err(Error::Clock);
        }
        self.last_wall = now;
        self.grant.budget.messages -= 1;
        self.grant.budget.body_bytes -= bytes;
        self.failed = true;
        let record = self
            .kernel
            .send(operation, retained, now)
            .await
            .map_err(Error::Kernel)?;
        self.authority()?;
        let status = QueuedStatus::from_committed(&record);
        self.pending = None;
        self.failed = false;
        Ok(status)
    }

    /// Read a bounded committed plaintext page as inert content. Expiry or
    /// revocation during the read withholds the entire page. This does not grant
    /// permission to act on instructions contained in any message.
    pub async fn inbox(&mut self, after: u64, limit: usize) -> Result<InboxPage> {
        self.check()?;
        if !self.grant.permissions.inbox {
            return Err(Error::Denied);
        }
        self.charge_page(limit, MAX_BODY_BYTES)?;
        self.failed = true;
        let page = self
            .kernel
            .inbox(after, limit)
            .await
            .map_err(Error::Kernel)?;
        self.authority()?;
        self.failed = false;
        Ok(page)
    }

    /// Read bounded local outbox metadata. Existing ciphertext is read internally
    /// through the kernel's checked page API, then discarded without export.
    pub async fn outbox_status(&mut self, after: u64, limit: usize) -> Result<OutboxStatusPage> {
        self.check()?;
        if !self.grant.permissions.outbox_status {
            return Err(Error::Denied);
        }
        self.charge_page(limit, MAX_PAGE_BYTES)?;
        self.failed = true;
        let page = self
            .kernel
            .outbox(after, limit)
            .await
            .map_err(Error::Kernel)?;
        self.authority()?;
        let result = OutboxStatusPage {
            head: page.head,
            next: page.next,
            records: page.records.iter().map(QueuedStatus::from_entry).collect(),
        };
        self.failed = false;
        Ok(result)
    }

    fn charge_page(&mut self, limit: usize, per_record: usize) -> Result<()> {
        if limit == 0 || limit > MAX_PAGE_RECORDS {
            return Err(Error::Bounds);
        }
        let bytes = limit
            .checked_mul(per_record)
            .ok_or(Error::Bounds)?
            .min(MAX_PAGE_BYTES) as u64;
        if self.grant.budget.read_records < limit as u64 || self.grant.budget.read_bytes < bytes {
            return Err(Error::Quota);
        }
        self.grant.budget.read_records -= limit as u64;
        self.grant.budget.read_bytes -= bytes;
        Ok(())
    }
    fn check(&mut self) -> Result<Status> {
        if self.failed {
            return Err(Error::NeedsReopen);
        }
        self.authority()
    }
    fn authority(&mut self) -> Result<Status> {
        if self.kernel.needs_reopen() {
            return Err(Error::NeedsReopen);
        }
        let authority = self.grant.authority.upgrade().ok_or(Error::Revoked)?;
        if authority.load(Ordering::Acquire) {
            return Err(Error::Revoked);
        }
        let tick = self.tick();
        if tick < self.last_tick {
            return Err(Error::Clock);
        }
        self.last_tick = tick;
        if tick >= self.grant.deadline {
            return Err(Error::Expired);
        }
        let status = self.kernel.status();
        if status.context != self.grant.context
            || status.epoch != self.grant.epoch
            || status.roster != self.grant.roster
            || status.quarantined
            || matches!(status.phase, Phase::AwaitingWelcome | Phase::Removed)
        {
            return Err(Error::AuthorityChanged);
        }
        Ok(status)
    }
    fn tick(&self) -> Instant {
        #[cfg(test)]
        if let Some(tick) = &self.test_tick {
            return tick.get();
        }
        Instant::now()
    }
}
fn wall_time() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Clock)?
        .as_secs())
}

#[cfg(test)]
mod tests;
