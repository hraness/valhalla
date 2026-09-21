//! Per-selected-peer continuity evidence, separate from authoring and v1 delivery.
//!
//! A terminal proof authenticates one peer's admission statement. Only signed
//! Evidence pages, matched byte-for-byte to the retained local outbox, advance
//! `RetentionHead`. Status and staging are temporary hints. Neither head proves
//! current policy, global completeness, physical remote storage, or availability.
use super::{AuthorHead, AuthorScope};
use crate::{history::HistoryScope, Error};
use sha2::{Digest, Sha256};
use vhalla_public_protocol::{continuity as wire, Endpoint};
use vhalla_room_activity::{EventId, SignedEvent, VerifiedEvent};

pub(crate) mod codec;
#[cfg(test)]
pub(crate) mod tests;

/// Maximum one-session state, including one exact bounded outbound body.
pub const MAX_STATE_BYTES: usize = wire::MAX_BODY_BYTES + 8192;
/// Maximum immutable response record. Original request, proof and body survive.
pub const MAX_RECORD_BYTES: usize = wire::MAX_REPLY_BYTES + 8192;
/// Maximum recovery intent, including its exact prior state and operation.
pub const MAX_INTENT_BYTES: usize = MAX_STATE_BYTES + MAX_RECORD_BYTES + 8192;
/// Maximum source events rechecked by one publication (33 plus fixed job/tips).
pub const MAX_SOURCE_CHECKS: usize = 40;

/// Immutable destination and complete local source identity. No authority claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionScope {
    author: AuthorScope,
    history: HistoryScope,
    peer: [u8; 32],
    endpoint: Endpoint,
}
impl SessionScope {
    /// Select one already known author and exact peer route. This does not create
    /// an author or establish that the peer is currently advertised/suitable.
    pub fn new(
        author: AuthorScope,
        history: HistoryScope,
        peer: [u8; 32],
        endpoint: Endpoint,
    ) -> Result<Self, Error> {
        if author.network != history.network()
            || author.network == [0; 32]
            || history.bootstrap_pin() == [0; 32]
            || peer == [0; 32]
        {
            return Err(Error::WrongScope);
        }
        Ok(Self {
            author,
            history,
            peer,
            endpoint,
        })
    }
    /// Full local author identity.
    pub const fn author(&self) -> AuthorScope {
        self.author
    }
    /// Independently selected bootstrap identity.
    pub const fn history(&self) -> HistoryScope {
        self.history
    }
    /// Exact peer key. Every retained proof verifies this key strictly.
    pub const fn peer(&self) -> [u8; 32] {
        self.peer
    }
    /// Exact route; no redirect, discovered substitution or failover is implied.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
    fn wire_scope(&self) -> wire::Scope {
        wire::Scope {
            network: self.author.network,
            realm: self.author.realm,
            directory: self.author.directory,
            room: self.author.room,
        }
    }
    fn check_event(&self, event: &VerifiedEvent) -> Result<(), Error> {
        if AuthorScope::new(event.claims().scope, event.claims().author) != self.author {
            return Err(Error::WrongScope);
        }
        Ok(())
    }
    fn check_request(&self, request: wire::Request, job: &ContinuityJob) -> Result<(), Error> {
        if request.context().scope != self.wire_scope()
            || request.selection() != wire::Selection::Author(self.author.author)
            || request.context().operation != job.operation
        {
            return Err(Error::WrongScope);
        }
        Ok(())
    }
}
/// Explicit immutable disk quotas. Exhaustion never prunes old evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum immutable signed response count, from one to one million.
    pub max_records: u64,
    /// Maximum retained signed response bytes, at most eight GiB.
    pub max_bytes: u64,
}
impl Limits {
    pub(crate) fn check(self) -> Result<(), Error> {
        if self.max_records == 0
            || self.max_records > 1_000_000
            || self.max_bytes == 0
            || self.max_bytes > 8 * 1024 * 1024 * 1024
        {
            return Err(Error::Bounds);
        }
        Ok(())
    }
}
/// Fixed local terminal selection. Preparing it does not sign or admit anything.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContinuityJob {
    operation: [u8; 16],
    terminal: wire::Position,
    frame: [u8; 32],
}
impl ContinuityJob {
    /// Select exact already-signed bytes; backends still require the actual local
    /// indexed record under existing author custody before publishing the job.
    pub fn new(operation: [u8; 16], terminal: &VerifiedEvent) -> Result<Self, Error> {
        if operation == [0; 16] {
            return Err(Error::Bounds);
        }
        Ok(Self {
            operation,
            terminal: wire::Position::of(terminal),
            frame: hash(&terminal.encode()),
        })
    }
    /// Logical operation identity, unchanged across request nonce retries.
    pub const fn operation(self) -> [u8; 16] {
        self.operation
    }
    /// Exact selected signed terminal position.
    pub const fn terminal(self) -> wire::Position {
        self.terminal
    }
    /// Digest of the complete canonical signed terminal frame.
    pub const fn frame_hash(self) -> [u8; 32] {
        self.frame
    }
}
/// One exact durable attempt. New HTTP attempts require fresh unpredictable
/// nonces; this module rejects immediate reuse but cannot manufacture entropy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContinuityAttempt {
    request: wire::Request,
    body: Vec<u8>,
}
impl ContinuityAttempt {
    /// Canonical request to send only after the reservation transaction completes.
    pub const fn request(&self) -> wire::Request {
        self.request
    }
    /// Exact body; GET requests have no body.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}
/// Immutable local record reference, not a remote retention claim on its own.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordRef {
    index: u64,
    digest: [u8; 32],
}
impl RecordRef {
    /// One-based local evidence ordinal.
    pub const fn index(self) -> u64 {
        self.index
    }
    /// Digest of exact canonical retained proof record.
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }
}
/// Peer-asserted retained prefix, authenticated by locally retained Evidence
/// proofs and byte-matched local signed frames. Not an admission/delivery head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetentionHead {
    position: wire::Position,
    record: Option<RecordRef>,
    role: Option<wire::EvidenceRole>,
    committed_by: u64,
    registry: [u8; 32],
}
impl RetentionHead {
    fn empty() -> Self {
        Self {
            position: wire::Position::EMPTY,
            record: None,
            role: None,
            committed_by: 0,
            registry: [0; 32],
        }
    }
    /// Exact end of the checked contiguous local prefix.
    pub const fn position(self) -> wire::Position {
        self.position
    }
    /// Original immutable Evidence record that last advanced this head.
    pub const fn record(self) -> Option<RecordRef> {
        self.record
    }
}
/// One terminal admission statement; deliberately no prefix-acknowledgment API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalEvidence {
    position: wire::Position,
    cursor: u64,
    registry: [u8; 32],
    record: RecordRef,
}
impl TerminalEvidence {
    /// Exact admitted terminal according to this peer.
    pub const fn position(self) -> wire::Position {
        self.position
    }
    /// Original peer-local admission cursor, not a global ordering.
    pub const fn cursor(self) -> u64 {
        self.cursor
    }
    /// Original local registry basis, not a current certificate.
    pub const fn registry(self) -> [u8; 32] {
        self.registry
    }
    /// Original retained signed terminal proof.
    pub const fn record(self) -> RecordRef {
        self.record
    }
}
/// Bounded session snapshot. Deserialization is metadata parsing; backends must
/// reauthenticate referenced records and exact local source before returning it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    scope: SessionScope,
    limits: Limits,
    generation: u64,
    job: Option<ContinuityJob>,
    attempt: Option<ContinuityAttempt>,
    last_nonce: [u8; 32],
    records: u64,
    bytes: u64,
    latest: Option<RecordRef>,
    retention: RetentionHead,
    terminal: Option<TerminalEvidence>,
}
impl Snapshot {
    pub(crate) fn fresh(scope: SessionScope, limits: Limits) -> Result<Self, Error> {
        limits.check()?;
        Ok(Self {
            scope,
            limits,
            generation: 0,
            job: None,
            attempt: None,
            last_nonce: [0; 32],
            records: 0,
            bytes: 0,
            latest: None,
            retention: RetentionHead::empty(),
            terminal: None,
        })
    }
    /// Immutable destination and local history scope.
    pub fn scope(&self) -> &SessionScope {
        &self.scope
    }
    /// Monotone local exact-CAS revision.
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    /// Fixed current terminal selection, if any.
    pub const fn job(&self) -> Option<ContinuityJob> {
        self.job
    }
    /// Exact retained outbound attempt; its presence is not a network receipt.
    pub fn attempt(&self) -> Option<&ContinuityAttempt> {
        self.attempt.as_ref()
    }
    /// Separately checked peer-asserted retained prefix.
    pub const fn retention(&self) -> RetentionHead {
        self.retention
    }
    /// Separately authenticated terminal admission, never a prefix shortcut.
    pub const fn terminal(&self) -> Option<TerminalEvidence> {
        self.terminal
    }
    /// Last immutable response; may be only a temporary/control hint.
    pub const fn latest(&self) -> Option<RecordRef> {
        self.latest
    }
    /// Permanent selected receipt quotas.
    pub const fn limits(&self) -> Limits {
        self.limits
    }
    /// Number of immutable signed responses, including historical jobs.
    pub const fn record_count(&self) -> u64 {
        self.records
    }
    /// Completion requires BOTH proof types to agree at the selected exact frame.
    pub fn complete(&self) -> bool {
        self.job.is_some_and(|job| {
            self.terminal.is_some_and(|t| {
                t.position == job.terminal
                    && self.retention.position == job.terminal
                    && self.retention.role == Some(wire::EvidenceRole::CurrentAdmission)
                    && self.retention.committed_by == t.cursor
                    && self.retention.registry == t.registry
            })
        })
    }
    /// Explicitly select/replace a job at a strictly later local terminal. A
    /// byte-identical same-job retry is allowed. Retention and all records remain.
    pub fn prepare_job(&self, job: ContinuityJob) -> Result<Publication, Error> {
        prepare(self.clone(), Operation::Job(job))
    }
    /// Reserve exact request bytes before sending. This is not current-policy
    /// approval. Mutation bases must already be verified retention positions.
    pub fn prepare_attempt(
        &self,
        request: wire::Request,
        body: &[u8],
    ) -> Result<Publication, Error> {
        if body.len() > wire::MAX_BODY_BYTES {
            return Err(Error::Bounds);
        }
        prepare(
            self.clone(),
            Operation::Attempt(Box::new(ContinuityAttempt {
                request,
                body: body.to_vec(),
            })),
        )
    }
    /// Authenticate a reply to the exact latest durable attempt. The private
    /// candidate still needs actual local-source checks and durable publication.
    pub fn prepare_response(
        &self,
        proof: &wire::ResponseProof,
        body: &[u8],
    ) -> Result<Publication, Error> {
        let attempt = self.attempt.as_ref().ok_or(Error::Stale)?;
        let record = ContinuityEvidenceRecord::new(
            self.scope.clone(),
            self.job.ok_or(Error::Corrupt)?,
            self.records.checked_add(1).ok_or(Error::Bounds)?,
            self.latest.map_or([0; 32], |r| r.digest),
            attempt.request,
            proof.clone(),
            body,
        )?;
        prepare(self.clone(), Operation::Response(Box::new(record)))
    }
}
/// Original strict peer response with explicit wire roles. This object alone is
/// not a durable receipt; only storage transaction completion confirms retention.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContinuityEvidenceRecord {
    scope: SessionScope,
    job: ContinuityJob,
    index: u64,
    previous: [u8; 32],
    request: wire::Request,
    proof: wire::ResponseProof,
    body: Vec<u8>,
    reply: wire::Reply,
}
impl ContinuityEvidenceRecord {
    fn new(
        scope: SessionScope,
        job: ContinuityJob,
        index: u64,
        previous: [u8; 32],
        request: wire::Request,
        proof: wire::ResponseProof,
        body: &[u8],
    ) -> Result<Self, Error> {
        if index == 0 || body.len() > wire::MAX_REPLY_BYTES || (index == 1) != (previous == [0; 32])
        {
            return Err(Error::Bounds);
        }
        scope.check_request(request, &job)?;
        let reply = proof
            .verify(scope.peer, &request, body)
            .map_err(|_| Error::Corrupt)?
            .reply()
            .clone();
        Ok(Self {
            scope,
            job,
            index,
            previous,
            request,
            proof,
            body: body.to_vec(),
            reply,
        })
    }
    /// Original authenticated, role-separated peer reply.
    pub fn reply(&self) -> &wire::Reply {
        &self.reply
    }
    /// Exact request, including original nonce and independently requested floor.
    pub const fn request(&self) -> wire::Request {
        self.request
    }
    /// Exact retained peer proof.
    pub fn proof(&self) -> &wire::ResponseProof {
        &self.proof
    }
    /// Original canonical response bytes.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    /// Digest and ordinal for immutable local retention.
    pub fn reference(&self) -> RecordRef {
        RecordRef {
            index: self.index,
            digest: hash(&self.encode()),
        }
    }
    /// Exact session scope, not a newly selected endpoint.
    pub fn scope(&self) -> &SessionScope {
        &self.scope
    }
    pub(crate) fn sources(&self) -> Result<Vec<SourceCheck>, Error> {
        let mut out = Vec::new();
        reply_sources(&self.reply, &mut out)?;
        Ok(out)
    }
}
/// Move-only unpublished change. No method sends, signs or mutates an author.
/// Backends consume this only after exact session CAS and local outbox rechecks.
pub struct Publication {
    pub(crate) before: Snapshot,
    pub(crate) after: Snapshot,
    pub(crate) operation: Operation,
    pub(crate) sources: Vec<SourceCheck>,
}
#[derive(Clone)]
pub(crate) enum Operation {
    Job(ContinuityJob),
    Attempt(Box<ContinuityAttempt>),
    Response(Box<ContinuityEvidenceRecord>),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SourceCheck {
    pub position: wire::Position,
    pub frame: Option<[u8; 32]>,
}
impl SourceCheck {
    fn event(event: &VerifiedEvent) -> Self {
        Self {
            position: wire::Position::of(event),
            frame: Some(hash(&event.encode())),
        }
    }
    fn point(position: wire::Position) -> Self {
        Self {
            position,
            frame: None,
        }
    }
    pub(crate) fn check(
        &self,
        scope: &SessionScope,
        head: AuthorHead,
        raw: &[u8],
    ) -> Result<(), Error> {
        let event = SignedEvent::decode(raw)
            .map_err(|_| Error::Corrupt)?
            .verify()
            .map_err(|_| Error::Corrupt)?;
        scope.check_event(&event)?;
        if head.scope() != scope.author
            || self.position.sequence() > head.sequence()
            || wire::Position::of(&event) != self.position
            || self.frame.is_some_and(|h| hash(raw) != h)
            || (self.position.sequence() == head.sequence() && event.id() != head.event_id())
        {
            return Err(Error::Corrupt);
        }
        Ok(())
    }
}
fn hash(raw: &[u8]) -> [u8; 32] {
    Sha256::digest(raw).into()
}
fn point(out: &mut Vec<SourceCheck>, p: wire::Position) {
    if p != wire::Position::EMPTY {
        out.push(SourceCheck::point(p));
    }
}
fn body_sources(attempt: &ContinuityAttempt, out: &mut Vec<SourceCheck>) -> Result<(), Error> {
    match attempt.request.kind() {
        wire::Kind::Stage { base, prior, .. }
        | wire::Kind::Commit {
            base, stage: prior, ..
        } => {
            point(out, base);
            if let Some(s) = prior {
                point(out, s.tail());
            }
            let body = attempt
                .request
                .check_body(&attempt.body)
                .map_err(|_| Error::Corrupt)?;
            out.extend(body.history().iter().map(SourceCheck::event));
            if let Some(e) = body.terminal() {
                out.push(SourceCheck::event(e));
            }
        }
        _ if !attempt.body.is_empty() => return Err(Error::Corrupt),
        _ => {}
    }
    Ok(())
}
fn reply_sources(reply: &wire::Reply, out: &mut Vec<SourceCheck>) -> Result<(), Error> {
    match reply {
        wire::Reply::Staged(a) => {
            point(out, a.base);
            point(out, a.ticket.tail());
        }
        wire::Reply::Committed(t) => out.push(SourceCheck::event(&t.event)),
        wire::Reply::Status(s) => {
            point(out, s.published);
            if let Some(s) = s.stage {
                point(out, s.tail());
            }
        }
        wire::Reply::Evidence(p) => {
            out.extend(p.entries.iter().map(|e| SourceCheck::event(&e.event)))
        }
        wire::Reply::Feed(_) => return Err(Error::WrongScope),
    }
    Ok(())
}
fn request_check(state: &Snapshot, attempt: &ContinuityAttempt) -> Result<(), Error> {
    let job = state.job.ok_or(Error::Stale)?;
    state.scope.check_request(attempt.request, &job)?;
    match attempt.request.kind() {
        wire::Kind::Stage { base, end, .. } => {
            if base != state.retention.position || end.sequence() >= job.terminal.sequence() {
                return Err(Error::Stale);
            }
        }
        wire::Kind::Commit {
            base,
            terminal,
            terminal_frame,
            ..
        } => {
            if base.sequence() > state.retention.position.sequence()
                || (base.sequence() == state.retention.position.sequence()
                    && base != state.retention.position)
                || terminal != job.terminal
                || terminal_frame != job.frame
            {
                return Err(Error::Stale);
            }
        }
        wire::Kind::Status { minimum } => {
            if minimum != state.retention.position {
                return Err(Error::Stale);
            }
        }
        wire::Kind::Evidence { after, count } => {
            if after != state.retention.position
                || after
                    .sequence()
                    .checked_add(u64::from(count))
                    .is_none_or(|n| n > job.terminal.sequence())
            {
                return Err(Error::Stale);
            }
        }
        wire::Kind::Feed { .. } => return Err(Error::WrongScope),
    }
    Ok(())
}
fn prepare(before: Snapshot, operation: Operation) -> Result<Publication, Error> {
    let mut after = before.clone();
    let mut sources = Vec::new();
    match &operation {
        Operation::Job(job) => {
            if job.operation == [0; 16]
                || job.terminal == wire::Position::EMPTY
                || job.frame == [0; 32]
                || job.terminal.sequence() < before.retention.position.sequence()
            {
                return Err(Error::Bounds);
            }
            if let Some(old) = before.job {
                if old != *job
                    && (job.terminal.sequence() <= old.terminal.sequence()
                        || job.operation == old.operation)
                {
                    return Err(Error::Stale);
                }
            }
            if after.job != Some(*job) {
                after.attempt = None;
                after.terminal = None;
                after.job = Some(*job);
            }
        }
        Operation::Attempt(attempt) => {
            request_check(&before, attempt)?;
            if attempt.request.context().nonce == before.last_nonce {
                return Err(Error::Stale);
            }
            body_sources(attempt, &mut sources)?;
            after.last_nonce = attempt.request.context().nonce;
            after.attempt = Some((**attempt).clone());
        }
        Operation::Response(record) => {
            let attempt = before.attempt.as_ref().ok_or(Error::Stale)?;
            if record.scope != before.scope
                || Some(record.job) != before.job
                || record.request != attempt.request
                || record.index != before.records.checked_add(1).ok_or(Error::Bounds)?
                || record.previous != before.latest.map_or([0; 32], |r| r.digest)
            {
                return Err(Error::Stale);
            }
            request_check(&before, attempt)?;
            body_sources(attempt, &mut sources)?;
            reply_sources(&record.reply, &mut sources)?;
            let reference = record.reference();
            after.records = record.index;
            after.bytes = before
                .bytes
                .checked_add(record.encode().len() as u64)
                .ok_or(Error::Bounds)?;
            if after.records > before.limits.max_records || after.bytes > before.limits.max_bytes {
                return Err(Error::Bounds);
            }
            after.latest = Some(reference);
            match &record.reply {
                wire::Reply::Committed(t) => {
                    let value = TerminalEvidence {
                        position: wire::Position::of(&t.event),
                        cursor: t.cursor,
                        registry: t.registry,
                        record: reference,
                    };
                    if before.terminal.is_some_and(|prior| {
                        prior.position != value.position
                            || prior.cursor != value.cursor
                            || prior.registry != value.registry
                    }) {
                        return Err(Error::Corrupt);
                    }
                    if after.retention.position == value.position
                        && (after.retention.role != Some(wire::EvidenceRole::CurrentAdmission)
                            || after.retention.committed_by != value.cursor
                            || after.retention.registry != value.registry)
                    {
                        return Err(Error::Corrupt);
                    }
                    if after.terminal.is_none() {
                        after.terminal = Some(value);
                    }
                }
                wire::Reply::Evidence(page) => {
                    if let Some(first) = page.entries.first() {
                        match before.retention.role {
                            Some(wire::EvidenceRole::HistoricalContinuity)
                                if first.committed_by != before.retention.committed_by =>
                            {
                                return Err(Error::Corrupt)
                            }
                            Some(wire::EvidenceRole::CurrentAdmission)
                                if first.committed_by <= before.retention.committed_by =>
                            {
                                return Err(Error::Corrupt)
                            }
                            _ => {}
                        }
                    }
                    if let Some(last) = page.entries.last() {
                        after.retention = RetentionHead {
                            position: wire::Position::of(&last.event),
                            record: Some(reference),
                            role: Some(last.role),
                            committed_by: last.committed_by,
                            registry: last.registry,
                        };
                        if let Some(t) = after.terminal {
                            if after.retention.position == t.position
                                && (last.role != wire::EvidenceRole::CurrentAdmission
                                    || last.committed_by != t.cursor
                                    || last.registry != t.registry)
                            {
                                return Err(Error::Corrupt);
                            }
                        }
                    }
                }
                _ => {}
            }
            after.attempt = None;
        }
    }
    if let Some(job) = after.job {
        sources.push(SourceCheck {
            position: job.terminal,
            frame: Some(job.frame),
        });
    }
    sources.sort_by_key(|v| v.position.sequence());
    sources.dedup();
    if sources.len() > MAX_SOURCE_CHECKS {
        return Err(Error::Bounds);
    }
    after.generation = before.generation.checked_add(1).ok_or(Error::Bounds)?;
    Ok(Publication {
        before,
        after,
        operation,
        sources,
    })
}
impl Publication {
    /// Projected metadata only, never a transaction-completion receipt.
    pub fn projected(&self) -> &Snapshot {
        &self.after
    }
    pub(crate) fn record(&self) -> Option<&ContinuityEvidenceRecord> {
        match &self.operation {
            Operation::Response(r) => Some(r),
            _ => None,
        }
    }
    #[cfg(any(unix, test))]
    pub(crate) fn check_sources(
        &self,
        head: AuthorHead,
        mut read: impl FnMut(u64) -> Result<Vec<u8>, Error>,
    ) -> Result<(), Error> {
        if head.scope() != self.before.scope.author {
            return Err(Error::WrongScope);
        }
        for source in &self.sources {
            source.check(&self.before.scope, head, &read(source.position.sequence())?)?;
        }
        Ok(())
    }
}
