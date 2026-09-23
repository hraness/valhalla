//! Portable bounded sync over a host-supplied kernel, image store and
//! transport. Every durability rule lives here; the host only performs I/O.
use super::model::{self, blocked, halt, refusal, State};
use core::future::Future;
use sha2::{Digest, Sha256};
use vhalla_private_kernel::{
    protocol::ControlFloor, storage::Store, Context, Error as KernelError, Kernel,
    MemberAcceptance, OperationId, OutboxKind, Phase,
};
use vhalla_private_relay::{
    codec, kind_byte, PositionedItem, RelayItem, RelayKind, RelayNamespace,
};

#[derive(Clone, Copy, Debug)]
pub enum Failure {
    Invalid,
    IdentityChanged,
    State,
    Storage,
    Kernel,
}
pub type Result<T> = core::result::Result<T, Failure>;
impl From<KernelError> for Failure {
    fn from(_: KernelError) -> Self {
        Self::Kernel
    }
}
impl From<vhalla_private_kernel::protocol::Error> for Failure {
    fn from(_: vhalla_private_kernel::protocol::Error) -> Self {
        Self::Invalid
    }
}
impl From<vhalla_private_kernel::storage::StoreError> for Failure {
    fn from(_: vhalla_private_kernel::storage::StoreError) -> Self {
        Self::Storage
    }
}
/// Closed transport outcomes. None carries ciphertext, tokens or addresses.
#[derive(Clone, Copy, Debug)]
pub enum TransportError {
    /// The gateway or relay was unreachable, slow or deferred the request.
    Retry,
    /// The gateway refused the presented capability.
    Authorization,
    /// A noncanonical or hostile HTTP reply that is never retried.
    Refused,
}

/// Everything the sync algorithm needs from its environment. The host must
/// not reorder, cache or coalesce these calls: each write is one strict
/// durability transaction and each read observes the current committed bytes.
pub trait Host {
    type Store: Store;
    fn now(&self) -> Result<u64>;
    fn canceled(&self) -> bool;
    fn kernel(&mut self) -> Result<&mut Kernel<Self::Store>>;
    /// Reopen the exact same durable custody in place after a verdict-only
    /// kernel refusal that provably committed nothing.
    fn reopen_kernel(&mut self, context: Context) -> impl Future<Output = Result<()>>;
    /// Recheck the account identity around every kernel and network step.
    fn revalidate(&mut self) -> impl Future<Output = Result<()>>;
    /// Read the current delivery image.
    fn load(&mut self) -> impl Future<Output = Result<Option<Vec<u8>>>>;
    /// Publish the next image over the exact expected one, retaining and/or
    /// discarding one bootstrap or deferred ciphertext in the same transaction.
    fn publish(
        &mut self,
        expected: Option<&[u8]>,
        next: &[u8],
        retain: Option<(u64, &[u8])>,
        discard: Option<u64>,
    ) -> impl Future<Output = Result<()>>;
    /// Read one retained bootstrap or deferred item by mailbox position.
    fn load_retained(&mut self, position: u64) -> impl Future<Output = Result<Option<Vec<u8>>>>;
    /// One bounded request/response exchange of an already framed relay op.
    fn exchange(
        &mut self,
        frame: &[u8],
        maximum: usize,
    ) -> impl Future<Output = core::result::Result<Vec<u8>, TransportError>>;
}

/// Bounded progress after one explicit connect or sync.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Summary {
    pub sent: u64,
    pub cursor: u64,
    pub fetched: u64,
    pub deferred: u64,
    pub retained: u64,
    pub received: u64,
    pub attempts: u64,
    pub wire_bytes: u64,
    pub retry_at: u64,
    pub pending: bool,
    pub stop: u8,
    pub detail: u8,
    pub blocked: u8,
    pub refused: u64,
    pub admissions: u64,
    pub review: bool,
}
/// One retained relay-delivered bootstrap item awaiting explicit admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Admission {
    pub position: u64,
    pub kind: OutboxKind,
    pub len: u32,
    pub digest: [u8; 32],
}

enum Verdict {
    /// The record can never apply here; record it durably and move on.
    Skip(u8),
    /// Hold the cursor before this record without ending custody.
    Block(u8),
    /// Preserve exact ciphertext durably and continue fetching prerequisites.
    Defer(u8),
    /// The record is equivocation or authority evidence: stop delivery at a
    /// durable, reported reason rather than trusting this mailbox further.
    Stop(u8),
    /// An indeterminate or in-flight failure ends this worker.
    Fatal,
}
/// Application-record refusals. Every typed verdict-only kernel refusal is
/// mapped; anything else either committed nothing but is not delivery-typed
/// or is an indeterminate in-flight condition, which stays fatal.
fn classify_receive(error: KernelError) -> Verdict {
    match error {
        KernelError::StaleEpoch => Verdict::Skip(refusal::STALE_EPOCH),
        KernelError::FutureEpoch => Verdict::Defer(blocked::FUTURE_EPOCH),
        KernelError::ControlGap => Verdict::Defer(blocked::CONTROL),
        KernelError::RatchetGap { past: false } => Verdict::Defer(blocked::RATCHET),
        KernelError::RatchetGap { past: true } => Verdict::Skip(refusal::RATCHET),
        KernelError::Scope => Verdict::Skip(refusal::SCOPE),
        KernelError::Mls => Verdict::Skip(refusal::RATCHET),
        KernelError::Encoding => Verdict::Skip(refusal::MALFORMED),
        KernelError::Bounds => Verdict::Skip(refusal::BOUNDS),
        // A sender or content this roster cannot authorize can never apply.
        KernelError::Policy => Verdict::Skip(refusal::POLICY),
        KernelError::Time | KernelError::ClockRegressed => Verdict::Block(blocked::TIME),
        _ => Verdict::Fatal,
    }
}
/// Owner-control refusals. Floor gaps retain exact bytes while fetching later
/// prerequisites; a clock condition holds the fetched cursor. An equivocating
/// or unauthorized authority claim stops delivery durably; every other typed
/// verdict is a record that can never apply here and is skipped with evidence.
fn classify_control(error: KernelError) -> Verdict {
    match error {
        KernelError::Missing => Verdict::Skip(refusal::BELOW_BASE),
        KernelError::ControlGap => Verdict::Defer(blocked::CONTROL),
        KernelError::StaleEpoch => Verdict::Skip(refusal::STALE_EPOCH),
        KernelError::FutureEpoch => Verdict::Defer(blocked::FUTURE_EPOCH),
        KernelError::RatchetGap { past: false } => Verdict::Defer(blocked::RATCHET),
        KernelError::RatchetGap { past: true } => Verdict::Skip(refusal::RATCHET),
        KernelError::Scope => Verdict::Skip(refusal::SCOPE),
        KernelError::Encoding => Verdict::Skip(refusal::MALFORMED),
        KernelError::Bounds => Verdict::Skip(refusal::BOUNDS),
        KernelError::Mls => Verdict::Skip(refusal::RATCHET),
        // The envelope header names no room, so a foreign room's control at a
        // coincident floor is indistinguishable from a forged one. Neither
        // authenticates, so neither can change or block local state; both are
        // retained as refusals for inspection.
        KernelError::Authentication => Verdict::Skip(refusal::UNAUTHENTICATED),
        // An owner-sealed control whose claim the roster does not authorize
        // and a different control at an already accepted floor are authority
        // evidence, not junk: the cursor cannot honestly pass them.
        KernelError::Policy => Verdict::Stop(halt::AUTHORITY),
        KernelError::Conflict => Verdict::Stop(halt::CONFLICT),
        KernelError::Time | KernelError::ClockRegressed => Verdict::Block(blocked::TIME),
        _ => Verdict::Fatal,
    }
}
fn acceptance_operation(context: Context, digest: [u8; 32]) -> Result<OperationId> {
    let mut h = Sha256::new();
    h.update(b"vhalla/browser-member-acceptance-operation/v1\0");
    h.update(context.device.as_bytes());
    h.update(digest);
    let digest: [u8; 32] = h.finalize().into();
    OperationId::from_bytes(digest[..16].try_into().map_err(|_| Failure::Invalid)?)
        .map_err(|_| Failure::Invalid)
}

pub struct Engine {
    state: State,
    raw: Vec<u8>,
    namespace: RelayNamespace,
}
impl Engine {
    /// Create over an absent image or reopen the exact retained one. Reopen
    /// re-supplies the capability explicitly, which clears only a transient
    /// backoff pause; spent budgets, refusals and blocks remain.
    pub async fn open<H: Host>(
        host: &mut H,
        namespace: RelayNamespace,
        bound: [u8; 32],
        owner: [u8; 16],
        initial: u64,
        create: bool,
    ) -> Result<Self> {
        let old = host.load().await?;
        let now = host.now()?;
        let mut state = match (create, old.as_ref()) {
            (true, None) => State::new(bound, owner, initial, now),
            (false, Some(raw)) => State::decode(raw).map_err(|_| Failure::Storage)?,
            _ => return Err(Failure::State),
        };
        if state.binding != bound || state.initial != initial {
            return Err(Failure::State);
        }
        // A cursor is permitted to pass deferred bytes only while their exact
        // indexed evidence exists. Missing/corrupt halves refuse reopening.
        for entry in state
            .deferred
            .iter()
            .map(|d| &d.item)
            .chain(&state.admissions)
        {
            Self::read_retained(host, namespace, entry).await?;
        }
        state.observe(now).map_err(|_| Failure::State)?;
        if !create {
            state.resume();
        }
        state.owner = owner;
        let raw = state.encode().map_err(|_| Failure::Storage)?;
        host.publish(old.as_deref(), &raw, None, None).await?;
        Ok(Self {
            state,
            raw,
            namespace,
        })
    }
    pub fn summary(&self, review: bool) -> Summary {
        Summary {
            sent: self.state.sent,
            cursor: self.state.resolved(),
            fetched: self.state.cursor,
            deferred: self.state.deferred.len() as u64,
            retained: self.state.retained,
            received: self.state.received,
            attempts: self.state.attempts,
            wire_bytes: self.state.wire_bytes,
            retry_at: self.state.retry_at,
            pending: !self.state.pending.is_empty()
                || !self.state.pending_control.is_empty()
                || !self.state.staged.is_empty()
                || !self.state.deferred.is_empty(),
            stop: self.state.stop.code(),
            detail: self.state.detail,
            blocked: if self.state.blocked != 0 {
                self.state.blocked
            } else {
                self.state.deferred.first().map_or(0, |d| d.reason)
            },
            refused: self.state.refused_total,
            admissions: self.state.admissions.len() as u64,
            review,
        }
    }
    pub fn admissions(&self) -> Vec<Admission> {
        self.state
            .admissions
            .iter()
            .filter_map(|a| {
                Some(Admission {
                    position: a.position,
                    kind: match vhalla_private_relay::kind_from_byte(a.kind).ok()? {
                        RelayKind::Outbox(kind) => kind,
                        RelayKind::Control => return None,
                    },
                    len: a.len,
                    digest: a.digest,
                })
            })
            .collect()
    }
    /// Read one retained bootstrap item; its bytes must match the index.
    pub async fn retained<H: Host>(&mut self, host: &mut H, position: u64) -> Result<RelayItem> {
        self.fence(host).await?;
        let entry = self
            .state
            .admissions
            .iter()
            .find(|a| a.position == position)
            .cloned()
            .ok_or(Failure::State)?;
        Self::read_retained(host, self.namespace, &entry).await
    }
    async fn read_retained<H: Host>(
        host: &mut H,
        namespace: RelayNamespace,
        entry: &model::Admission,
    ) -> Result<RelayItem> {
        let raw = host
            .load_retained(entry.position)
            .await?
            .ok_or(Failure::Storage)?;
        let item = RelayItem::decode(&raw).map_err(|_| Failure::Storage)?;
        if raw.len() as u32 != entry.len
            || item.digest() != entry.digest
            || kind_byte(item.kind()) != entry.kind
            || item.namespace() != namespace
        {
            return Err(Failure::Storage);
        }
        Ok(item)
    }
    /// Discard one retained bootstrap item explicitly. This is the only way a
    /// retained item leaves the store; nothing is pruned automatically.
    pub async fn discard<H: Host>(&mut self, host: &mut H, position: u64) -> Result<Summary> {
        self.fence(host).await?;
        let at = self
            .state
            .admissions
            .iter()
            .position(|a| a.position == position)
            .ok_or(Failure::State)?;
        self.state.admissions.remove(at);
        if self.state.blocked == blocked::ADMISSIONS_FULL {
            self.state.blocked = 0;
        }
        self.save(host, None, Some(position)).await?;
        Ok(self.summary(false))
    }
    async fn save<H: Host>(
        &mut self,
        host: &mut H,
        retain: Option<(u64, &[u8])>,
        discard: Option<u64>,
    ) -> Result<()> {
        if host.canceled() {
            return Err(Failure::State);
        }
        let raw = self.state.encode().map_err(|_| Failure::State)?;
        host.publish(Some(&self.raw), &raw, retain, discard).await?;
        self.raw = raw;
        Ok(())
    }
    async fn fence<H: Host>(&mut self, host: &mut H) -> Result<()> {
        if host.canceled() {
            return Err(Failure::State);
        }
        if host.load().await?.as_deref() != Some(self.raw.as_slice()) {
            return Err(Failure::State);
        }
        Ok(())
    }
    async fn halt<T, H: Host>(&mut self, host: &mut H, detail: u8) -> Result<T> {
        self.state.halt(detail);
        self.save(host, None, None).await?;
        Err(Failure::Invalid)
    }
    async fn exchange<H: Host>(
        &mut self,
        host: &mut H,
        op: u8,
        body: &[u8],
        maximum: usize,
    ) -> Result<Option<Vec<u8>>> {
        self.fence(host).await?;
        host.revalidate().await?;
        let frame = codec::frame(op, body);
        let reservation = frame.len() + maximum;
        let now = host.now()?;
        let reserved = self
            .state
            .reserve(now, reservation)
            .map_err(|_| Failure::State)?;
        self.save(host, None, None).await?;
        if !reserved {
            return Ok(None);
        }
        let raw = host.exchange(&frame, maximum).await;
        self.fence(host).await?;
        host.revalidate().await?;
        let raw = match raw {
            Ok(raw) => raw,
            Err(TransportError::Retry) => return Ok(None),
            Err(TransportError::Authorization) => return Err(Failure::State),
            Err(TransportError::Refused) => return self.halt(host, halt::FRAME).await,
        };
        let (status, body) = match codec::decode_frame(&raw, maximum.saturating_sub(4)) {
            Ok(frame) => frame,
            Err(_) => return self.halt(host, halt::FRAME).await,
        };
        match codec::decode_status(status, body) {
            Ok(body) => {
                // A canonical reply charges its exact bytes; the caller saves
                // this together with the progress it produces.
                self.state.settle(reservation, frame.len() + raw.len());
                Ok(Some(body))
            }
            Err(codec::NetError::Denied) => Err(Failure::State),
            Err(
                codec::NetError::Capacity
                | codec::NetError::Unavailable
                | codec::NetError::Connect
                | codec::NetError::Timeout,
            ) => Ok(None),
            Err(_) => self.halt(host, halt::FRAME).await,
        }
    }
    async fn own_item<H: Host>(host: &mut H, item: &RelayItem) -> Result<bool> {
        if item.kind() == RelayKind::Control {
            let head = host.kernel()?.status().control_floor;
            if item.sequence() > head.sequence() {
                return Ok(false);
            }
            let base = host.kernel()?.encrypted_controls(head, 1).await?.base;
            if item.sequence() <= base.sequence() {
                return Ok(false);
            }
            let page = host
                .kernel()?
                .encrypted_controls_from(Some(item.sequence() - 1), 1)
                .await?;
            return Ok(page.records.first().is_some_and(|control| {
                RelayItem::from_control(item.namespace(), control).is_ok_and(|own| own == *item)
            }));
        }
        if item.sequence() > host.kernel()?.status().outbox_head {
            return Ok(false);
        }
        let page = host.kernel()?.outbox(item.sequence() - 1, 1).await?;
        Ok(page
            .records
            .first()
            .and_then(|entry| entry.artifact())
            .is_some_and(|v| {
                v.sequence() == item.sequence()
                    && v.operation() == item.operation()
                    && RelayKind::Outbox(v.kind()) == item.kind()
                    && v.bytes() == item.payload()
            }))
    }
    /// Stage the next relay-bound outbox entry as exact pending ciphertext
    /// before any network effect, advancing over a bounded page of non-relay entries.
    /// Secret bootstrap entries advance only this local enumeration; they
    /// never enter network bytes.
    async fn stage_pending<H: Host>(&mut self, host: &mut H) -> Result<bool> {
        if !self.state.pending.is_empty() {
            return Ok(true);
        }
        let page = host.kernel()?.outbox(self.state.sent, model::PAGE).await?;
        if page.records.is_empty() {
            return Ok(false);
        }
        for entry in &page.records {
            if let Some(artifact) = entry.artifact().filter(|a| {
                matches!(
                    a.kind(),
                    OutboxKind::Application
                        | OutboxKind::ContactRequest
                        | OutboxKind::ContactInvitation
                )
            }) {
                self.state.pending = RelayItem::from_artifact(self.namespace, artifact)
                    .and_then(|v| v.encode())
                    .map_err(|_| Failure::Invalid)?;
                break;
            } else {
                self.state.sent = entry.sequence();
            }
        }
        self.save(host, None, None).await?;
        Ok(!self.state.pending.is_empty())
    }
    /// Controls have a separate full-floor watermark: a contact invitation's
    /// member control is not an outbox record. Never replace its exact bytes
    /// with a plaintext proof or manufacture a second membership operation.
    async fn stage_control<H: Host>(&mut self, host: &mut H) -> Result<bool> {
        if !self.state.pending_control.is_empty() {
            return Ok(true);
        }
        let after = match self.state.control_sent {
            Some(after) => after,
            None => {
                let head = host.kernel()?.status().control_floor;
                let base = host.kernel()?.encrypted_controls(head, 1).await?.base;
                self.state.control_sent = Some(base);
                self.save(host, None, None).await?;
                base
            }
        };
        let page = host.kernel()?.encrypted_controls(after, 1).await?;
        let Some(control) = page.records.first() else {
            return Ok(false);
        };
        self.state.pending_control = RelayItem::from_control(self.namespace, control)
            .and_then(|item| item.encode())
            .map_err(|_| Failure::Invalid)?;
        self.save(host, None, None).await?;
        Ok(true)
    }
    /// Merge authenticated local streams by epoch. An older committed message
    /// must reach the relay before the control retiring its epoch, while a
    /// newer message waits for its prerequisite control. This cannot establish
    /// a total order across independently publishing devices.
    async fn pending_control_order<H: Host>(
        &mut self,
        host: &mut H,
        item: &RelayItem,
    ) -> Result<(ControlFloor, bool)> {
        let after = self.state.control_sent.ok_or(Failure::State)?;
        let page = host.kernel()?.encrypted_controls(after, 1).await?;
        let control = page.records.first().ok_or(Failure::State)?;
        let expected =
            RelayItem::from_control(self.namespace, control).map_err(|_| Failure::State)?;
        if expected != *item {
            return Err(Failure::State);
        }
        let floor = control.floor();
        let prior = control.prior_epoch()?;
        if self.state.pending.is_empty() {
            return Ok((floor, true));
        }
        let pending = RelayItem::decode(&self.state.pending).map_err(|_| Failure::Storage)?;
        let page = host.kernel()?.outbox(self.state.sent, 1).await?;
        let artifact = page
            .records
            .first()
            .and_then(|entry| entry.artifact())
            .ok_or(Failure::State)?;
        let expected =
            RelayItem::from_artifact(self.namespace, artifact).map_err(|_| Failure::State)?;
        if expected != pending {
            return Err(Failure::State);
        }
        // Version-2 pending controls may still exist. Drain their independent
        // authenticated history first so an old copy cannot leapfrog a parent.
        let control_first = match artifact.kind() {
            OutboxKind::Removal | OutboxKind::OwnerUpdate | OutboxKind::Succession => true,
            _ => artifact
                .application_epoch()?
                .is_some_and(|epoch| epoch > prior),
        };
        Ok((floor, control_first))
    }
    /// One explicit bounded sync. Inbound controls are fetched and applied
    /// before outbound items are sent, so a control issued elsewhere is seen
    /// before this device publishes into the epoch it changes. Each staged
    /// record commits locally before the cursor passes it.
    pub async fn sync<H: Host>(&mut self, host: &mut H) -> Result<Summary> {
        self.fence(host).await?;
        let initial = host.kernel()?.membership().await?.status();
        if initial.quarantined
            || !matches!(
                initial.phase,
                Phase::OwnerGenesis
                    | Phase::OwnerJoined
                    | Phase::MemberJoined
                    | Phase::OwnerAfterRemoval
            )
        {
            return Err(Failure::State);
        }
        let context = initial.context;
        if self.state.stopped() {
            return Ok(self.summary(false));
        }
        if let Some(summary) = self.retry_deferred(host, context).await? {
            return Ok(summary);
        }
        // Exact pending ciphertext is retained before the first network effect.
        self.stage_pending(host).await?;
        self.stage_control(host).await?;
        if let Some(summary) = self.inbound(host, context).await? {
            return Ok(summary);
        }
        if let Some(summary) = self.retry_deferred(host, context).await? {
            return Ok(summary);
        }
        // At most two outgoing items per user gesture.
        for _ in 0..2 {
            let pending = self.stage_pending(host).await?;
            if !pending && host.kernel()?.status().outbox_head > self.state.sent {
                // A bounded page contained only non-relay entries. Do not
                // advance a control past an application we have not inspected.
                continue;
            }
            if self.stage_control(host).await? {
                let raw = self.state.pending_control.clone();
                let item = RelayItem::decode(&raw).map_err(|_| Failure::Storage)?;
                let (floor, control_first) = self.pending_control_order(host, &item).await?;
                if control_first {
                    let Some(reply) = self.exchange(host, codec::OP_PUT, &raw, 46).await? else {
                        return Ok(self.summary(false));
                    };
                    if codec::decode_receipt(&reply, &item).is_err() {
                        return self.halt(host, halt::RECEIPT).await;
                    }
                    self.state.control_sent = Some(floor);
                    self.state.pending_control.clear();
                    self.state.retained =
                        self.state.retained.checked_add(1).ok_or(Failure::State)?;
                    self.state.success();
                    self.save(host, None, None).await?;
                    continue;
                }
            }
            if !pending {
                break;
            }
            let item = RelayItem::decode(&self.state.pending).map_err(|_| Failure::Storage)?;
            if item.namespace() != self.namespace || !Self::own_item(host, &item).await? {
                return Err(Failure::State);
            }
            let raw = self.state.pending.clone();
            let Some(reply) = self.exchange(host, codec::OP_PUT, &raw, 46).await? else {
                return Ok(self.summary(false));
            };
            if codec::decode_receipt(&reply, &item).is_err() {
                return self.halt(host, halt::RECEIPT).await;
            }
            self.state.sent = item.sequence();
            self.state.retained = self.state.retained.checked_add(1).ok_or(Failure::State)?;
            self.state.pending.clear();
            self.state.success();
            self.save(host, None, None).await?;
        }
        Ok(self.summary(false))
    }
    /// At most one pass over the bounded queue per call. A deferred item may
    /// become applicable after another item in this pass; the next bounded sync
    /// retries it again. Never evict ciphertext to create capacity.
    async fn retry_deferred<H: Host>(
        &mut self,
        host: &mut H,
        context: Context,
    ) -> Result<Option<Summary>> {
        for deferred in self.state.deferred.clone() {
            self.fence(host).await?;
            host.revalidate().await?;
            let item = Self::read_retained(host, self.namespace, &deferred.item).await?;
            let record = PositionedItem {
                position: deferred.item.position,
                item,
            };
            match self.apply(host, context, &record).await? {
                Outcome::Deferred(_) => continue,
                Outcome::Blocked(reason) => {
                    self.state.blocked = reason;
                    self.save(host, None, None).await?;
                    return Ok(Some(self.summary(false)));
                }
                Outcome::Stop(detail) => {
                    self.state.halt(detail);
                    self.save(host, None, None).await?;
                    return Ok(Some(self.summary(false)));
                }
                Outcome::Retain => return Err(Failure::State),
                outcome => {
                    self.state
                        .deferred
                        .retain(|d| d.item.position != record.position);
                    self.state.blocked = 0;
                    self.save(host, None, Some(record.position)).await?;
                    if matches!(outcome, Outcome::Review) {
                        return Ok(Some(self.summary(true)));
                    }
                }
            }
        }
        Ok(None)
    }
    /// Fetch one bounded page when nothing is staged, then apply staged
    /// records in order. Returns a summary when the sync must end early.
    async fn inbound<H: Host>(
        &mut self,
        host: &mut H,
        context: Context,
    ) -> Result<Option<Summary>> {
        if self.state.staged.is_empty() {
            let request = codec::page_request(self.state.cursor, model::PAGE)
                .map_err(|_| Failure::Invalid)?;
            let Some(raw) = self
                .exchange(host, codec::OP_PAGE, &request, codec::MAX_RESPONSE + 4)
                .await?
            else {
                return Ok(Some(self.summary(false)));
            };
            let page = match codec::decode_page(&raw, self.state.cursor, model::PAGE) {
                Ok(page) => page,
                Err(_) => return self.halt(host, halt::PAGE).await,
            };
            if page.head < self.state.cursor
                || page
                    .records
                    .iter()
                    .any(|r| r.item.namespace() != self.namespace)
            {
                return self.halt(host, halt::PAGE).await;
            }
            self.state.success();
            self.state.staged_after = self.state.cursor;
            self.state.applied = 0;
            if !page.records.is_empty() {
                self.state.staged = raw;
            }
            self.save(host, None, None).await?;
        }
        if self.state.staged.is_empty() {
            return Ok(None);
        }
        let page = codec::decode_page(&self.state.staged, self.state.staged_after, model::PAGE)
            .map_err(|_| Failure::Storage)?;
        let mut review = false;
        for record in page.records.iter().skip(self.state.applied as usize) {
            if record.item.namespace() != self.namespace {
                return Err(Failure::State);
            }
            self.fence(host).await?;
            host.revalidate().await?;
            let outcome = if Self::own_item(host, &record.item).await? {
                Outcome::Applied
            } else {
                self.apply(host, context, record).await?
            };
            let mut retain = None;
            match outcome {
                Outcome::Applied => (),
                Outcome::Review => review = true,
                Outcome::Retain => {
                    retain = Some((
                        record.position,
                        record.item.encode().map_err(|_| Failure::Invalid)?,
                    ))
                }
                Outcome::Deferred(reason) => {
                    if self.state.deferred.len() >= model::MAX_DEFERRED {
                        self.state.blocked = blocked::DEFERRED_FULL;
                        self.save(host, None, None).await?;
                        return Ok(Some(self.summary(false)));
                    }
                    let encoded = record.item.encode().map_err(|_| Failure::Invalid)?;
                    self.state
                        .defer(
                            model::Admission {
                                position: record.position,
                                kind: kind_byte(record.item.kind()),
                                len: encoded.len() as u32,
                                digest: record.item.digest(),
                            },
                            reason,
                        )
                        .map_err(|_| Failure::State)?;
                    retain = Some((record.position, encoded));
                }
                Outcome::Blocked(reason) => {
                    if self.state.blocked != reason {
                        self.state.blocked = reason;
                        self.save(host, None, None).await?;
                    }
                    return Ok(Some(self.summary(false)));
                }
                // An equivocating or unauthorized control stops delivery at a
                // durable, reported reason; the cursor never passes it.
                Outcome::Stop(detail) => {
                    self.state.halt(detail);
                    self.save(host, None, None).await?;
                    return Ok(Some(self.summary(false)));
                }
            }
            self.state.blocked = 0;
            self.state.cursor = record.position;
            self.state.applied += 1;
            if self.state.applied as usize == page.records.len() {
                self.state.staged.clear();
                self.state.applied = 0;
                self.state.staged_after = self.state.cursor;
            }
            // Kernel commits are durable per record; the image write that
            // moves the cursor past them is batched. Every intermediate
            // record replays idempotently, so only a retained bootstrap item
            // (which publishes its bytes with the index), a review stop or the
            // page end needs its own strict-durability image write.
            if retain.is_some() || review || self.state.staged.is_empty() {
                self.save(host, retain.as_ref().map(|(p, b)| (*p, b.as_slice())), None)
                    .await?;
            }
            if review {
                return Ok(Some(self.summary(true)));
            }
        }
        Ok(None)
    }
    /// Apply one foreign staged record. Only verdict-only kernel refusals are
    /// classified; any failure after a kernel write remains fatal.
    async fn apply<H: Host>(
        &mut self,
        host: &mut H,
        context: Context,
        record: &PositionedItem,
    ) -> Result<Outcome> {
        let phase = host.kernel()?.status().phase;
        let joined = matches!(phase, Phase::OwnerJoined | Phase::MemberJoined);
        let now = host.now()?;
        // Only a kernel that was actually consulted needs reopening in place.
        let mut touched = false;
        let result = match record.item.kind() {
            RelayKind::Outbox(OutboxKind::Application) => {
                if !joined {
                    Err(Verdict::Skip(refusal::PHASE))
                } else {
                    touched = true;
                    self.receive(host, context, record, now).await
                }
            }
            RelayKind::Control
            | RelayKind::Outbox(
                OutboxKind::Removal | OutboxKind::OwnerUpdate | OutboxKind::Succession,
            ) => {
                if phase != Phase::MemberJoined {
                    // Owner devices author controls; a mailbox control is
                    // never applied to the device that holds owner authority.
                    Err(Verdict::Skip(refusal::PHASE))
                } else {
                    touched = true;
                    let before = host.kernel()?.status().control_floor;
                    match host
                        .kernel()?
                        .apply_control(record.item.payload(), now)
                        .await
                    {
                        Ok(status) => Ok(if status.control_floor != before {
                            Outcome::Review
                        } else {
                            Outcome::Applied
                        }),
                        Err(e) => Err(classify_control(e)),
                    }
                }
            }
            // Canonical encrypted bootstrap artifacts require dedicated,
            // user-selected admission; retain them for that explicit path.
            RelayKind::Outbox(OutboxKind::ContactRequest | OutboxKind::ContactInvitation) => {
                let encoded = record.item.encode().map_err(|_| Failure::Invalid)?;
                let admission = model::Admission {
                    position: record.position,
                    kind: kind_byte(record.item.kind()),
                    len: encoded.len() as u32,
                    digest: record.item.digest(),
                };
                if self.state.admissions.len() >= model::MAX_ADMISSIONS
                    && !self
                        .state
                        .admissions
                        .iter()
                        .any(|a| a.position == record.position)
                {
                    Err(Verdict::Block(blocked::ADMISSIONS_FULL))
                } else {
                    match self.state.admit(admission) {
                        Ok(()) => Ok(Outcome::Retain),
                        Err(()) => Err(Verdict::Fatal),
                    }
                }
            }
            _ => Err(Verdict::Skip(refusal::MALFORMED)),
        };
        match result {
            Ok(outcome) => Ok(outcome),
            Err(Verdict::Skip(reason)) => {
                if touched {
                    host.reopen_kernel(context).await?;
                }
                self.state
                    .refuse(record.position, record.item.digest(), reason)
                    .map_err(|_| Failure::State)?;
                Ok(Outcome::Applied)
            }
            Err(Verdict::Block(reason)) => {
                if touched {
                    host.reopen_kernel(context).await?;
                }
                Ok(Outcome::Blocked(reason))
            }
            Err(Verdict::Defer(reason)) => {
                if touched {
                    host.reopen_kernel(context).await?;
                }
                Ok(Outcome::Deferred(reason))
            }
            Err(Verdict::Stop(detail)) => {
                if touched {
                    host.reopen_kernel(context).await?;
                }
                Ok(Outcome::Stop(detail))
            }
            Err(Verdict::Fatal) => Err(Failure::Kernel),
        }
    }
    async fn receive<H: Host>(
        &mut self,
        host: &mut H,
        context: Context,
        record: &PositionedItem,
        now: u64,
    ) -> core::result::Result<Outcome, Verdict> {
        let kernel = host.kernel().map_err(|_| Verdict::Fatal)?;
        let message = kernel
            .receive(record.item.payload(), now)
            .await
            .map_err(classify_receive)?;
        if !MemberAcceptance::is_receipt(message.body()) {
            let operation =
                acceptance_operation(context, record.item.digest()).map_err(|_| Verdict::Fatal)?;
            let kernel = host.kernel().map_err(|_| Verdict::Fatal)?;
            kernel
                .issue_acceptance(operation, record.item.payload(), now)
                .await
                .map_err(|e| match e {
                    KernelError::Time => Verdict::Block(blocked::TIME),
                    _ => Verdict::Fatal,
                })?;
        }
        self.state.received = self.state.received.checked_add(1).ok_or(Verdict::Fatal)?;
        Ok(Outcome::Applied)
    }
}
enum Outcome {
    Applied,
    Review,
    Retain,
    Blocked(u8),
    Deferred(u8),
    Stop(u8),
}

#[cfg(test)]
mod classification_tests {
    use super::*;

    #[test]
    fn future_epoch_and_ahead_ratchet_are_retryable_but_past_is_terminal() {
        assert!(matches!(
            classify_receive(KernelError::FutureEpoch),
            Verdict::Defer(blocked::FUTURE_EPOCH)
        ));
        assert!(matches!(
            classify_receive(KernelError::RatchetGap { past: false }),
            Verdict::Defer(blocked::RATCHET)
        ));
        assert!(matches!(
            classify_receive(KernelError::RatchetGap { past: true }),
            Verdict::Skip(refusal::RATCHET)
        ));
        assert!(matches!(
            classify_control(KernelError::ControlGap),
            Verdict::Defer(blocked::CONTROL)
        ));
    }
}
