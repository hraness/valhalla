use crate::{
    codec::checked_key, Error, EventId, PinnedGenesis, PolicyId, RoomId, SealHead, SignedPolicy,
    VerifiedEvent, VerifiedPolicy,
};
use alloc::{collections::BTreeMap, vec::Vec};

/// Maximum distinct authors with retained seals in one in-memory policy replica.
/// Refusal preserves all existing history; no entry is evicted to admit a key.
pub const MAX_SEALED_AUTHORS: usize = 4096;

/// Maximum unresolved owner revisions tracked before storage must rebuild from
/// its complete retained policy evidence. Overflow fences fresh admission.
pub const MAX_OBSERVED_POLICIES: usize = 256;

/// Exact observed owner-policy position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyPosition {
    /// Zero for genesis, then monotonically increasing owner updates.
    pub revision: u64,
    /// Full policy commitment at this revision.
    pub id: PolicyId,
}

/// Bounded current owner authority reconstructed from signed policy replay.
///
/// The storage owner retains prior signed policies and compares old revisions
/// with those records to distinguish exact retries from authenticated forks.
/// This state never keeps a lifetime vector of policy history in memory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyState {
    genesis: PinnedGenesis,
    current: Option<VerifiedPolicy>,
    sealed: BTreeMap<[u8; 32], AuthorHead>,
    observed: BTreeMap<u64, PolicyId>,
    observation_overflow: bool,
    forked: bool,
}
impl PolicyState {
    /// Start at an independently pinned genesis. Joining grants no writer rights.
    pub fn new(genesis: PinnedGenesis) -> Self {
        Self {
            genesis,
            current: None,
            sealed: BTreeMap::new(),
            observed: BTreeMap::new(),
            observation_overflow: false,
            forked: false,
        }
    }
    /// Full pinned room commitment.
    pub fn room(&self) -> RoomId {
        self.genesis.id()
    }
    /// Immutable room owner.
    pub fn owner(&self) -> [u8; 32] {
        self.genesis.claims().owner
    }
    /// Exact current policy basis.
    pub fn head(&self) -> PolicyPosition {
        match &self.current {
            Some(current) => PolicyPosition {
                revision: current.claims().revision,
                id: current.id(),
            },
            None => PolicyPosition {
                revision: 0,
                id: self.room().initial_policy(),
            },
        }
    }
    /// Current complete writer list in canonical key order.
    pub fn writers(&self) -> &[[u8; 32]] {
        match &self.current {
            Some(current) => &current.claims().writers,
            None => &self.genesis.claims().writers,
        }
    }
    /// Whether this key is listed by the verified policy. Pending updates and
    /// forks additionally fence fresh admission in AuthorChain.
    pub fn allows(&self, author: &[u8; 32]) -> bool {
        self.writers().binary_search(author).is_ok()
    }
    /// Last fully verified owner-sealed terminal for an author, including removed
    /// authors. Policy changes never erase the continuity needed on rejoining.
    pub fn sealed_head(&self, author: &[u8; 32]) -> Option<AuthorHead> {
        self.sealed.get(author).copied()
    }
    /// Highest authenticated owner update awaiting policy/history replay.
    pub fn pending(&self) -> Option<PolicyPosition> {
        self.observed
            .last_key_value()
            .map(|(&revision, &id)| PolicyPosition { revision, id })
    }
    /// A retained observation exceeded the unresolved-revision budget. This
    /// latch never clears by catching up only the in-memory observations; storage
    /// must reconstruct against every retained observation, including overflow.
    pub const fn observation_overflow(&self) -> bool {
        self.observation_overflow
    }
    /// Authenticated owner equivocation has fenced all fresh room writes.
    pub const fn is_forked(&self) -> bool {
        self.forked
    }
    /// Fence new messages after retaining an authenticated owner update. Even a
    /// gap in its ancestry blocks stale authority. Storage must persist this
    /// observation before further sends and replay it on open. No timeout may
    /// remove this fence. Foreign signers cannot create it.
    pub fn observe_after_persist(&mut self, update: &VerifiedPolicy) -> Result<(), Error> {
        self.check_owner(update)?;
        let offered = PolicyPosition {
            revision: update.claims().revision,
            id: update.id(),
        };
        let head = self.head();
        if offered.revision < head.revision {
            return Err(Error::Replay);
        }
        if offered.revision == head.revision {
            if offered.id == head.id {
                return Err(Error::Duplicate);
            }
            self.forked = true;
            return Err(Error::Fork);
        }
        if let Some(observed) = self.observed.get(&offered.revision) {
            if offered.id != *observed {
                self.forked = true;
                return Err(Error::Fork);
            }
            return Ok(());
        }
        if self.observed.len() == MAX_OBSERVED_POLICIES {
            self.observation_overflow = true;
            return Err(Error::Capacity);
        }
        self.observed.insert(offered.revision, offered.id);
        Ok(())
    }
    fn fresh_admission(&self) -> Result<(), Error> {
        if self.forked {
            return Err(Error::Fork);
        }
        if self.observation_overflow {
            return Err(Error::Capacity);
        }
        if !self.observed.is_empty() {
            return Err(Error::PolicyPending);
        }
        Ok(())
    }
    /// Validate an update without changing state. The caller persists both
    /// conflicting signed records and stops writes on an authenticated fork.
    pub fn prepare_update(&self, signed: SignedPolicy) -> Result<PreparedPolicy, Error> {
        if self.forked {
            return Err(Error::Fork);
        }
        let update = signed.verify()?;
        self.check_owner(&update)?;
        if self
            .observed
            .get(&update.claims().revision)
            .is_some_and(|id| *id != update.id())
        {
            return Err(Error::Fork);
        }
        let head = self.head();
        let claims = update.claims();
        if claims.revision < head.revision {
            return Err(Error::Replay);
        }
        if claims.revision == head.revision {
            return Err(if update.id() == head.id {
                Error::Duplicate
            } else {
                Error::Fork
            });
        }
        let next = head.revision.checked_add(1).ok_or(Error::Exhausted)?;
        if claims.revision != next {
            return Err(Error::Gap);
        }
        if claims.previous != head.id {
            return Err(Error::Fork);
        }
        if claims
            .sealed_heads
            .iter()
            .any(|seal| !self.allows(&seal.author))
        {
            return Err(Error::Author);
        }
        let added = claims
            .sealed_heads
            .iter()
            .filter(|seal| !self.sealed.contains_key(&seal.author))
            .count();
        if self
            .sealed
            .len()
            .checked_add(added)
            .ok_or(Error::Capacity)?
            > MAX_SEALED_AUTHORS
        {
            return Err(Error::Capacity);
        }
        let mut proofs = Vec::with_capacity(claims.sealed_heads.len());
        for seal in &claims.sealed_heads {
            let prior = self.sealed_head(&seal.author).unwrap_or(AuthorHead::EMPTY);
            if seal.sequence < prior.sequence
                || (seal.sequence == prior.sequence && seal.event != prior.event)
            {
                return Err(Error::Fork);
            }
            // A new seal's terminal must name the policy now closing. Reusing
            // an old terminal would falsely endorse its bytes under a new policy.
            if seal.sequence == prior.sequence {
                return Err(Error::Policy);
            }
            proofs.push(SealProof {
                chain: AuthorChain {
                    room: self.room(),
                    author: seal.author,
                    head: prior,
                    checked_seal: None,
                },
                target: *seal,
                policy: head.id,
            });
        }
        let closed = ClosedPolicy {
            room: self.room(),
            policy: head.id,
            closing_policy: update.id(),
            writers: self.writers().to_vec(),
            seals: claims.sealed_heads.clone(),
        };
        Ok(PreparedPolicy {
            room: self.room(),
            base: head,
            update,
            closed,
            proofs,
        })
    }
    /// Advance only after durable publication under the same controller lock.
    /// Returns the immutable historical boundary for the preceding policy.
    /// This method cannot itself attest that the caller performed filesystem I/O.
    pub fn commit_after_persist(
        &mut self,
        prepared: PreparedPolicy,
    ) -> Result<ClosedPolicy, Error> {
        if self.forked {
            return Err(Error::Fork);
        }
        if prepared.room != self.room() || prepared.base != self.head() {
            return Err(Error::StaleBase);
        }
        if !prepared.is_ready() {
            return Err(Error::Gap);
        }
        if self
            .observed
            .get(&prepared.update.claims().revision)
            .is_some_and(|id| *id != prepared.update.id())
        {
            return Err(Error::Fork);
        }
        for proof in &prepared.proofs {
            self.sealed.insert(proof.target.author, proof.chain.head());
        }
        self.current = Some(prepared.update);
        self.observed.remove(&self.head().revision);
        Ok(prepared.closed)
    }
    /// Reconcile an old revision against its retained authenticated record.
    /// Neither argument is selected by an untrusted remote "latest" assertion.
    pub fn compare_retained(
        &self,
        retained: &VerifiedPolicy,
        offered: SignedPolicy,
    ) -> Result<(), Error> {
        let offered = offered.verify()?;
        self.check_owner(retained)?;
        self.check_owner(&offered)?;
        if retained.claims().revision != offered.claims().revision {
            return Err(Error::Sequence);
        }
        Err(if retained.id() == offered.id() {
            Error::Duplicate
        } else {
            Error::Fork
        })
    }
    /// Persist and then fence an authenticated conflict at a retained revision.
    /// Exact retries remain harmless; the caller keeps both signed records.
    pub fn observe_retained_after_persist(
        &mut self,
        retained: &VerifiedPolicy,
        offered: SignedPolicy,
    ) -> Result<(), Error> {
        let result = self.compare_retained(retained, offered);
        if result == Err(Error::Fork) {
            self.forked = true;
        }
        result
    }
    fn check_owner(&self, update: &VerifiedPolicy) -> Result<(), Error> {
        if update.claims().room != self.room() {
            return Err(Error::Scope);
        }
        if update.claims().owner != self.owner() {
            return Err(Error::Owner);
        }
        Ok(())
    }
}

/// A checked policy replacement bound to its exact preparation base.
#[derive(Debug)]
pub struct PreparedPolicy {
    room: RoomId,
    base: PolicyPosition,
    update: VerifiedPolicy,
    closed: ClosedPolicy,
    proofs: Vec<SealProof>,
}
impl PreparedPolicy {
    /// Exact authenticated update to publish durably before committing.
    pub fn update(&self) -> &VerifiedPolicy {
        &self.update
    }
    /// Verify a page extending this author's prior owner-sealed terminal to the
    /// proposed new seal. No proof progress survives a malformed page.
    pub fn push_seal(&mut self, author: &[u8; 32], page: &[VerifiedEvent]) -> Result<(), Error> {
        let proof = self
            .proofs
            .iter_mut()
            .find(|proof| &proof.target.author == author)
            .ok_or(Error::Author)?;
        proof.push(page)
    }
    /// All declared seals have complete signed ancestry extending earlier seals.
    pub fn is_ready(&self) -> bool {
        self.proofs.iter().all(SealProof::complete)
    }
}

#[derive(Debug)]
struct SealProof {
    chain: AuthorChain,
    target: SealHead,
    policy: PolicyId,
}
impl SealProof {
    fn push(&mut self, page: &[VerifiedEvent]) -> Result<(), Error> {
        if page.is_empty() || page.len() > crate::MAX_CHAIN_PAGE {
            return Err(Error::Bounds);
        }
        let mut next = self.chain.clone();
        for event in page {
            if event.claims().sequence > self.target.sequence {
                return Err(Error::Bounds);
            }
            next.check_next(event)?;
            if event.claims().sequence == self.target.sequence {
                if event.id() != self.target.event {
                    return Err(Error::Fork);
                }
                if event.claims().policy != self.policy {
                    return Err(Error::Policy);
                }
            }
            next.head = AuthorHead {
                sequence: event.claims().sequence,
                event: event.id(),
            };
        }
        self.chain = next;
        Ok(())
    }
    fn complete(&self) -> bool {
        self.chain.head.sequence == self.target.sequence
            && self.chain.head.event == self.target.event
    }
}

/// Immutable policy boundary derived only by replaying an accepted owner update.
/// A later policy cannot replace an earlier boundary or endorse its excluded text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClosedPolicy {
    pub(crate) room: RoomId,
    pub(crate) policy: PolicyId,
    pub(crate) closing_policy: PolicyId,
    pub(crate) writers: Vec<[u8; 32]>,
    pub(crate) seals: Vec<SealHead>,
}
impl ClosedPolicy {
    /// Room whose owner issued the seal.
    pub const fn room(&self) -> RoomId {
        self.room
    }
    /// Exact policy whose historical visibility this boundary governs.
    pub const fn policy(&self) -> PolicyId {
        self.policy
    }
    /// Accepted owner update carrying this boundary.
    pub const fn closing_policy(&self) -> PolicyId {
        self.closing_policy
    }
    /// Canonical complete table of endorsed author terminals.
    pub fn seals(&self) -> &[SealHead] {
        &self.seals
    }
}

/// One verified author-chain position. Empty is sequence zero and the zero ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorHead {
    /// Zero before any event, then one greater for every signed chain step.
    pub sequence: u64,
    /// Exact last content commitment.
    pub event: EventId,
}
impl AuthorHead {
    /// Empty history; never a license to reset an existing recovered author.
    pub const EMPTY: Self = Self {
        sequence: 0,
        event: EventId::ZERO,
    };
}

/// Per-room full-author continuity. Reconstruct from verified retained frames;
/// an advertised remote head or a restored key alone cannot initialize a head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorChain {
    room: RoomId,
    author: [u8; 32],
    head: AuthorHead,
    checked_seal: Option<AuthorHead>,
}
impl AuthorChain {
    /// Start a new chain. Persistent code must separately prove this author has
    /// no prior local state or unresolved reservation before enabling signing.
    pub fn new(room: RoomId, author: [u8; 32]) -> Result<Self, Error> {
        if room == RoomId::ZERO {
            return Err(Error::Scope);
        }
        checked_key(&author)?;
        Ok(Self {
            room,
            author,
            head: AuthorHead::EMPTY,
            checked_seal: None,
        })
    }
    /// Current verified chain position.
    pub const fn head(&self) -> AuthorHead {
        self.head
    }
    /// Begin a bounded-memory proof from the current verified seal to this exact
    /// existing head. This rechecks an anchor learned after these frames were
    /// retained; it neither changes continuity nor grants writing permission.
    pub fn prepare_anchor_reconciliation(
        &self,
        policy: &PolicyState,
    ) -> Result<AnchorReconciliation, Error> {
        if policy.room() != self.room {
            return Err(Error::Scope);
        }
        let seal = policy.sealed_head(&self.author).ok_or(Error::Policy)?;
        if self.head.sequence < seal.sequence {
            return Err(Error::Gap);
        }
        if self.head.sequence == seal.sequence && self.head != seal {
            return Err(Error::Fork);
        }
        Ok(AnchorReconciliation {
            room: self.room,
            author: self.author,
            policy: policy.head(),
            seal,
            target: self.head,
            progress: seal,
        })
    }
    /// Install only checked-anchor metadata after complete signed ancestry
    /// verification. The room, author, policy, seal and existing head must still
    /// match the preparation snapshot. No event or policy head is advanced.
    pub fn reconcile_anchor(
        &mut self,
        proof: AnchorReconciliation,
        policy: &PolicyState,
    ) -> Result<(), Error> {
        if proof.room != self.room || proof.author != self.author || proof.target != self.head {
            return Err(Error::StaleBase);
        }
        if policy.room() != self.room
            || policy.head() != proof.policy
            || policy.sealed_head(&self.author) != Some(proof.seal)
        {
            return Err(Error::StalePolicy);
        }
        if !proof.is_ready() {
            return Err(Error::Gap);
        }
        self.checked_seal = Some(proof.seal);
        Ok(())
    }
    /// Check the basis for reserving unsigned bytes before any signing occurs.
    /// The caller must still persist the exact reservation, sign those bytes,
    /// and prepare/commit the resulting event under the same room writer lock.
    /// This does not prove that a restored key has no missing prior author state.
    pub fn authoring_head(&self, policy: &PolicyState) -> Result<AuthorHead, Error> {
        policy.fresh_admission()?;
        if policy.room() != self.room {
            return Err(Error::Scope);
        }
        if !policy.allows(&self.author) {
            return Err(Error::Author);
        }
        self.check_fresh_anchor(policy)?;
        Ok(self.head)
    }
    /// Validate fresh feed admission without advancing either state.
    pub fn prepare_next(
        &self,
        event: VerifiedEvent,
        policy: &PolicyState,
    ) -> Result<PreparedEvent, Error> {
        policy.fresh_admission()?;
        if policy.room() != self.room {
            return Err(Error::Scope);
        }
        if event.claims().policy != policy.head().id {
            return Err(Error::Policy);
        }
        self.authoring_head(policy)?;
        self.check_next(&event)?;
        Ok(PreparedEvent {
            step: PreparedContinuity {
                room: self.room,
                author: self.author,
                base: self.head,
                event,
            },
            policy: policy.head(),
        })
    }
    /// Advance fresh admission after persisting the exact bytes and outbox.
    pub fn commit_after_persist(
        &mut self,
        prepared: PreparedEvent,
        policy: &PolicyState,
    ) -> Result<(), Error> {
        policy.fresh_admission()?;
        if policy.room() != self.room || prepared.policy != policy.head() {
            return Err(Error::StalePolicy);
        }
        self.check_fresh_anchor(policy)?;
        self.commit_continuity_after_persist(prepared.step, policy)
    }
    /// Check a signed historical predecessor for continuity only. This method
    /// never grants feed visibility or permission to author another event.
    pub fn prepare_continuity(
        &self,
        event: VerifiedEvent,
        policy: &PolicyState,
    ) -> Result<PreparedContinuity, Error> {
        self.check_next(&event)?;
        self.checked_anchor_after(&event, policy)?;
        Ok(PreparedContinuity {
            room: self.room,
            author: self.author,
            base: self.head,
            event,
        })
    }
    /// Retain a checked historical step without treating it as a feed message.
    pub fn commit_continuity_after_persist(
        &mut self,
        prepared: PreparedContinuity,
        policy: &PolicyState,
    ) -> Result<(), Error> {
        if prepared.room != self.room
            || prepared.author != self.author
            || prepared.base != self.head
        {
            return Err(Error::StaleBase);
        }
        let checked_seal = self.checked_anchor_after(&prepared.event, policy)?;
        self.head = AuthorHead {
            sequence: prepared.event.claims().sequence,
            event: prepared.event.id(),
        };
        self.checked_seal = checked_seal;
        Ok(())
    }
    fn check_fresh_anchor(&self, policy: &PolicyState) -> Result<(), Error> {
        if let Some(seal) = policy.sealed_head(&self.author) {
            if self.head.sequence < seal.sequence {
                return Err(Error::Gap);
            }
            if self.head.sequence == seal.sequence {
                if self.head != seal {
                    return Err(Error::Fork);
                }
            } else if self.checked_seal != Some(seal) {
                // The chain predates our observation of this seal. Replay its
                // retained frames against current policy to prove exact ancestry.
                return Err(Error::Gap);
            }
        }
        Ok(())
    }
    fn checked_anchor_after(
        &self,
        event: &VerifiedEvent,
        policy: &PolicyState,
    ) -> Result<Option<AuthorHead>, Error> {
        if policy.room() != self.room {
            return Err(Error::Scope);
        }
        let Some(seal) = policy.sealed_head(&self.author) else {
            return Ok(None);
        };
        if self.head.sequence < seal.sequence {
            if event.claims().sequence == seal.sequence {
                if event.id() != seal.event {
                    return Err(Error::Fork);
                }
                return Ok(Some(seal));
            }
            return Ok(None);
        }
        self.check_fresh_anchor(policy)?;
        Ok(Some(seal))
    }
    fn check_next(&self, event: &VerifiedEvent) -> Result<(), Error> {
        let claims = event.claims();
        if claims.room != self.room {
            return Err(Error::Scope);
        }
        if claims.author != self.author {
            return Err(Error::Author);
        }
        if claims.sequence < self.head.sequence {
            return Err(Error::Replay);
        }
        if claims.sequence == self.head.sequence {
            return Err(if event.id() == self.head.event {
                Error::Duplicate
            } else {
                Error::Fork
            });
        }
        if claims.sequence != self.head.sequence.checked_add(1).ok_or(Error::Exhausted)? {
            return Err(Error::Gap);
        }
        if claims.previous != self.head.event {
            return Err(Error::Fork);
        }
        Ok(())
    }
}

/// Constant-memory proof that an existing exact author head descends from a
/// newly learned, already verified owner seal. Only `AuthorChain` can create or
/// install it; a numeric terminal alone is never sufficient.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorReconciliation {
    room: RoomId,
    author: [u8; 32],
    policy: PolicyPosition,
    seal: AuthorHead,
    target: AuthorHead,
    progress: AuthorHead,
}
impl AnchorReconciliation {
    /// Last checked frame, initially the verified seal.
    pub const fn progress(&self) -> AuthorHead {
        self.progress
    }
    /// Exact frozen author head the proof must reach.
    pub const fn target(&self) -> AuthorHead {
        self.target
    }
    /// Both terminal sequence and commitment match the frozen author head.
    pub fn is_ready(&self) -> bool {
        self.progress == self.target
    }
    /// Verify one bounded, nonempty contiguous page. Invalid input preserves
    /// the previous progress, including a wrong terminal at the right sequence.
    pub fn push(&mut self, page: &[VerifiedEvent]) -> Result<(), Error> {
        if page.is_empty() || page.len() > crate::MAX_CHAIN_PAGE {
            return Err(Error::Bounds);
        }
        let mut chain = AuthorChain {
            room: self.room,
            author: self.author,
            head: self.progress,
            checked_seal: None,
        };
        for event in page {
            if event.claims().sequence > self.target.sequence {
                return Err(Error::Bounds);
            }
            chain.check_next(event)?;
            chain.head = AuthorHead {
                sequence: event.claims().sequence,
                event: event.id(),
            };
            if chain.head.sequence == self.target.sequence && chain.head != self.target {
                return Err(Error::Fork);
            }
        }
        self.progress = chain.head;
        Ok(())
    }
}

/// Fresh event admission prepared against both author and policy heads.
#[derive(Debug)]
pub struct PreparedEvent {
    step: PreparedContinuity,
    policy: PolicyPosition,
}
impl PreparedEvent {
    /// Exact event to persist before committing.
    pub fn event(&self) -> &VerifiedEvent {
        &self.step.event
    }
}

/// Historical chain extension carrying no feed-visibility authority.
#[derive(Debug)]
pub struct PreparedContinuity {
    room: RoomId,
    author: [u8; 32],
    base: AuthorHead,
    event: VerifiedEvent,
}
impl PreparedContinuity {
    /// Exact signed ancestry to retain.
    pub fn event(&self) -> &VerifiedEvent {
        &self.event
    }
}
