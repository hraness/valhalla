//! Historical causal evidence is separate from fresh activity admission.
//!
//! A certified registry can prove that an enabled policy revision existed. It
//! cannot prove when an activity signature was made. Ancestors checked here
//! therefore never become fresh posts or past-admission receipts. Only an exact
//! terminal event passing the current policy can advance an admitted chain.
use super::*;
use vhalla_rooms::{Body, RoomUpdate, UpdateAction};

/// Maximum signed ancestors prepared in one independently bounded operation.
pub const MAX_HISTORY_SEGMENT: usize = 32;

/// Immutable evidence meaning, not a claim about global delivery or signing time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceRole {
    /// Causal predecessor under an admitted enabled historical policy revision.
    /// This never grants current publication permission or past-admission proof.
    HistoricalContinuity,
    /// Terminal event checked against this storage owner's current policy view.
    CurrentAdmission,
}

/// Exact unsigned historical-policy check, never a posting or signing grant.
///
/// The caller must independently establish the AdmissionContext's certified
/// provenance and the exact existing durable reservation before using a signer.
/// This non-serialized result proves neither persistence, signature time nor
/// past admission, and cannot advance an admitted AuthorChain.
#[derive(Debug)]
pub struct HistoricalUnsigned {
    request: UnsignedEvent,
    registry: [u8; 32],
}
impl HistoricalUnsigned {
    /// The exact canonical request checked before any signature was produced.
    pub const fn request(&self) -> &UnsignedEvent {
        &self.request
    }
    /// Immutable evaluation basis; not a certificate or current-policy grant.
    pub const fn registry_digest(&self) -> &[u8; 32] {
        &self.registry
    }
}
impl AdmissionContext<'_> {
    /// Check one typed unsigned request against its exact admitted enabled
    /// historical revision, using the same rules as signed continuity evidence.
    ///
    /// At most one room's bounded retained revisions are searched. Revocation
    /// or archival does not erase that history, but this result never authorizes
    /// fresh publication. It does not prove that the request was reserved or
    /// signed when the named policy was current. A custody controller must bind
    /// it to the actual unchanged pending request and author base before signing.
    pub fn check_historical_unsigned(
        &self,
        request: UnsignedEvent,
    ) -> Result<HistoricalUnsigned, Error> {
        check_historical(self, request.claims())?;
        Ok(HistoricalUnsigned {
            request,
            registry: self.digest,
        })
    }
}

/// A hidden staging position. Advancing it never changes a published AuthorChain.
/// A storage owner must bind it to its own exact durable staging catalogue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContinuityPosition {
    scope: RoomScope,
    author: [u8; 32],
    base: Option<ChainPosition>,
    tail: Option<ChainPosition>,
}
impl ContinuityPosition {
    /// Begin an empty hidden suffix at the owner's actual published author floor.
    pub const fn begin(chain: &AuthorChain) -> Self {
        Self {
            scope: chain.scope,
            author: chain.author,
            base: chain.head,
            tail: chain.head,
        }
    }
    /// Restore this owner's previously checked, still-unpublished staging tail.
    ///
    /// This is a TRUSTED LOCAL STORAGE boundary. The caller must establish the
    /// complete contiguous staged prefix and its exact published base from its
    /// own retained catalogue/pages. A remote signed event alone is insufficient.
    /// This creates no admission receipt and does not move the published floor.
    pub fn restore_local_staging(chain: &AuthorChain, tail: &VerifiedEvent) -> Result<Self, Error> {
        let claims = tail.claims();
        if claims.scope != chain.scope {
            return Err(Error::Scope);
        }
        if claims.author != chain.author {
            return Err(Error::Author);
        }
        if chain
            .head
            .is_some_and(|base| claims.sequence <= base.sequence)
        {
            return Err(Error::StaleBase);
        }
        Ok(Self {
            scope: chain.scope,
            author: chain.author,
            base: chain.head,
            tail: Some(position(tail)),
        })
    }
    /// Complete pinned room scope.
    pub const fn scope(&self) -> RoomScope {
        self.scope
    }
    /// Complete author key.
    pub const fn author(&self) -> [u8; 32] {
        self.author
    }
    /// Published floor against which the entire hidden suffix was prepared.
    pub const fn published_base(&self) -> Option<ChainPosition> {
        self.base
    }
    /// Current staged tail, equal to published_base before the first segment.
    pub const fn staged_tail(&self) -> Option<ChainPosition> {
        self.tail
    }
    /// Validate a bounded contiguous historical suffix without changing state.
    /// The context must come from the caller's independently certified registry.
    pub fn prepare_segment(
        &self,
        events: Vec<VerifiedEvent>,
        context: &AdmissionContext<'_>,
    ) -> Result<PendingHistorySegment, Error> {
        if events.is_empty() || events.len() > MAX_HISTORY_SEGMENT {
            return Err(Error::Bounds);
        }
        let mut next = self.tail;
        for event in &events {
            self.check_identity(event)?;
            check_historical(context, event.claims())?;
            check_extension(next, event)?;
            next = Some(position(event));
        }
        Ok(PendingHistorySegment {
            before: *self,
            next: next.expect("nonempty checked segment"),
            events,
            registry: context.digest,
        })
    }
    /// Install only after the exact stage transaction is durable. Temporary
    /// staging may expire under its owner's documented policy; this is never an
    /// activity acceptance receipt or a promise of indefinite storage.
    pub fn commit_segment_after_persist(
        &mut self,
        candidate: PendingHistorySegment,
        context: &AdmissionContext<'_>,
    ) -> Result<HistoricalSegment, Error> {
        if *self != candidate.before {
            return Err(Error::StaleBase);
        }
        if context.digest != candidate.registry || context.network != self.scope.network {
            return Err(Error::StalePolicy);
        }
        self.tail = Some(candidate.next);
        Ok(HistoricalSegment {
            events: candidate.events,
            registry: candidate.registry,
        })
    }
    fn check_identity(&self, event: &VerifiedEvent) -> Result<(), Error> {
        if event.claims().scope != self.scope {
            return Err(Error::Scope);
        }
        if event.claims().author != self.author {
            return Err(Error::Author);
        }
        Ok(())
    }
}

/// Move-only candidate for temporary hidden staging, never fresh publication.
#[derive(Debug)]
pub struct PendingHistorySegment {
    before: ContinuityPosition,
    next: ChainPosition,
    events: Vec<VerifiedEvent>,
    registry: [u8; 32],
}
impl PendingHistorySegment {
    /// Exact catalogue position to compare-and-set with the page publication.
    pub const fn before(&self) -> ContinuityPosition {
        self.before
    }
    /// Exact tail after durable page publication.
    pub const fn next(&self) -> ChainPosition {
        self.next
    }
    /// Project the checked hidden position without I/O or state mutation.
    ///
    /// This is NONDURABLE. It permits preparing an inline terminal before one
    /// atomic storage transaction publishes both suffix and terminal. The owner
    /// must compare-and-set `before()`, retain every event and the terminal,
    /// then use the actually persisted projected tail for the terminal commit.
    pub const fn next_position(&self) -> ContinuityPosition {
        ContinuityPosition {
            tail: Some(self.next),
            ..self.before
        }
    }
    /// Canonical signed frames to retain in the bounded stage page.
    pub fn events(&self) -> &[VerifiedEvent] {
        &self.events
    }
    /// Independently certified evaluation basis, not a certificate by itself.
    pub const fn registry_digest(&self) -> &[u8; 32] {
        &self.registry
    }
}

/// Locally retained temporary historical evidence. No AdmittedEvent is exposed.
#[derive(Debug)]
pub struct HistoricalSegment {
    events: Vec<VerifiedEvent>,
    registry: [u8; 32],
}
impl HistoricalSegment {
    /// Exact frames in this segment's immutable historical evidence role.
    /// The same signed bytes may independently qualify for current admission
    /// elsewhere; this segment never attests that such admission occurred.
    pub fn events(&self) -> &[VerifiedEvent] {
        &self.events
    }
    /// Immutable meaning of every entry.
    pub const fn role(&self) -> EvidenceRole {
        EvidenceRole::HistoricalContinuity
    }
    /// Evaluation basis at local staging, not signing-time evidence.
    pub const fn registry_digest(&self) -> &[u8; 32] {
        &self.registry
    }
}

/// Move-only current-policy terminal candidate, bound to both author positions.
#[derive(Debug)]
pub struct PendingContinuityAdmission {
    before: ContinuityPosition,
    event: VerifiedEvent,
    registry: [u8; 32],
}
impl PendingContinuityAdmission {
    /// Exact published floor and staged tail for the durable compare-and-set.
    pub const fn before(&self) -> ContinuityPosition {
        self.before
    }
    /// Terminal frame to expose only after the entire transaction is durable.
    pub const fn event(&self) -> &VerifiedEvent {
        &self.event
    }
    /// Current certified evaluation basis required by the final transaction.
    pub const fn registry_digest(&self) -> &[u8; 32] {
        &self.registry
    }
}
impl AuthorChain {
    /// Prepare a terminal event under CURRENT policy after an exact hidden
    /// contiguous prefix. Ancestors never inherit the terminal's authorization.
    pub fn prepare_continuity_terminal(
        &self,
        staged: ContinuityPosition,
        event: VerifiedEvent,
        context: &AdmissionContext<'_>,
    ) -> Result<PendingContinuityAdmission, Error> {
        if self.scope != staged.scope || self.author != staged.author || self.head != staged.base {
            return Err(Error::StaleBase);
        }
        staged.check_identity(&event)?;
        context.check(event.claims())?;
        check_extension(staged.tail, &event)?;
        Ok(PendingContinuityAdmission {
            before: staged,
            event,
            registry: context.digest,
        })
    }
    /// Advance ONLY after durable terminal publication protected every ancestor
    /// and atomically compared the published base, staged tail and registry.
    /// The portable method cannot perform or attest to filesystem/IndexedDB I/O.
    pub fn commit_continuity_terminal_after_persist(
        &mut self,
        candidate: PendingContinuityAdmission,
        staged: ContinuityPosition,
        context: &AdmissionContext<'_>,
    ) -> Result<AdmittedEvent, Error> {
        if staged != candidate.before
            || self.scope != candidate.before.scope
            || self.author != candidate.before.author
            || self.head != candidate.before.base
        {
            return Err(Error::StaleBase);
        }
        if context.digest != candidate.registry || context.network != self.scope.network {
            return Err(Error::StalePolicy);
        }
        context.check(candidate.event.claims())?;
        self.head = Some(position(&candidate.event));
        Ok(AdmittedEvent {
            event: candidate.event,
            registry_digest: candidate.registry,
        })
    }
}

fn position(event: &VerifiedEvent) -> ChainPosition {
    ChainPosition {
        sequence: event.claims().sequence,
        id: event.id(),
    }
}
fn check_extension(tail: Option<ChainPosition>, event: &VerifiedEvent) -> Result<(), Error> {
    let claims = event.claims();
    if let Some(tail) = tail {
        if claims.sequence == tail.sequence {
            return Err(if event.id() == tail.id {
                Error::Duplicate
            } else {
                Error::Fork
            });
        }
        if claims.sequence < tail.sequence {
            return Err(Error::Replay);
        }
        let next = tail
            .sequence
            .checked_add(1)
            .ok_or(Error::SequenceExhausted)?;
        if claims.sequence != next {
            return Err(Error::Gap);
        }
        if claims.previous != tail.id {
            return Err(Error::Fork);
        }
    } else if claims.sequence != 1 || claims.previous != EventId::ZERO {
        return Err(Error::Gap);
    }
    Ok(())
}
fn check_historical(context: &AdmissionContext<'_>, claims: &EventClaims) -> Result<(), Error> {
    if claims.scope.network != context.network
        || claims.scope.realm != context.registry.realm()
        || claims.scope.directory != context.registry.directory()
    {
        return Err(Error::Scope);
    }
    let room = context
        .registry
        .room_by_genesis(claims.scope.room)
        .ok_or(Error::UnknownRoom)?;
    let valid = room.revisions().iter().any(|record| {
        record.id() == claims.policy
            && matches!(record.body(),
            Body::Update(RoomUpdate {
                action: UpdateAction::SetPublicActivityPolicy { network, enabled: true }, ..
            }) if *network == context.network)
    });
    if !valid {
        return Err(Error::Policy);
    }
    Ok(())
}
