//! Borrowed deterministic social projections. All text remains untrusted data.
//! A view has no host authority and cannot establish global network completeness.
use crate::{
    archive::Archive,
    control::{ControlView, SocialStatus},
    model::*,
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use sha2::{Digest, Sha256};

/// Version of the local social projection/eligibility policy.
pub const POLICY_VERSION: u16 = 1;
/// Largest requested biography page.
pub const MAX_PAGE_SIZE: usize = 64;
/// Maximum bounded semantic validation attempts per view; excess stays pending.
pub const MAX_EVALUATION_STEPS: usize = MAX_RECORDS * 64;

/// Explicit local eligibility. Affiliation, following and votes cannot populate it.
#[derive(Clone, Debug, Default)]
pub struct Eligibility {
    owners: Vec<OwnerId>,
}
impl Eligibility {
    /// Admit an explicitly chosen canonical sorted owner set, including empty.
    pub fn new(owners: Vec<OwnerId>) -> Result<Self, Error> {
        if owners.len() > MAX_RECORDS || owners.windows(2).any(|w| w[0] >= w[1]) {
            return Err(Error::Bounds);
        }
        Ok(Self { owners })
    }
    /// Borrow the local policy's exact owner IDs.
    #[must_use]
    pub fn owners(&self) -> &[OwnerId] {
        &self.owners
    }
    fn contains(&self, owner: OwnerId) -> bool {
        self.owners.binary_search(&owner).is_ok()
    }
    fn digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"vhalla/social/eligibility/v1");
        for owner in &self.owners {
            hash.update(owner.as_bytes());
        }
        hash.finalize().into()
    }
}
/// Complete interpretation basis. This is evidence metadata, never a capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvaluationBasis {
    /// Logical root of the retained archive.
    pub archive_root: EvidenceRoot,
    /// Hash of root, realm, policy version, limits, eligible IDs and supplied time.
    pub digest: [u8; 32],
    /// Exact local resource-policy digest; capacity can close current eligibility.
    pub limits_digest: [u8; 32],
    /// Exact eligible-set digest.
    pub eligibility_digest: [u8; 32],
    /// Supplied evaluation clock; not an event-ordering authority.
    pub now: u64,
    /// Projection rules version.
    pub policy_version: u16,
    /// Whether known retained dependencies resolve, not global completeness.
    pub known_history_complete: bool,
}
/// Presentation state of one social record under this exact view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordState {
    /// Semantically valid and in owner-accepted history.
    Committed,
    /// Semantically valid under live authority, not owner-committed.
    Provisional,
    /// A required control or social dependency is absent/unresolved.
    Pending,
    /// Known evidence contradicts this operation's context or authorization.
    Rejected,
    /// Authenticated competing control/writer evidence prevents a choice.
    Conflicted,
}
#[derive(Clone, Copy)]
struct Classification {
    state: RecordState,
    admission_known: bool,
}

/// A causal register retains every maximal ID, even when values are equal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Register<T> {
    /// No admitted update in this evidence subset.
    Empty,
    /// One effective value, possibly represented by several equal-valued heads.
    Resolved {
        /// All maximal evidence IDs.
        heads: Vec<RecordId>,
        /// The effective value after explicit clear/remove semantics.
        value: T,
    },
    /// Concurrent distinct values remain visible; no arbitrary winner.
    Conflict {
        /// All maximal evidence IDs.
        heads: Vec<RecordId>,
        /// Sorted distinct alternatives, not concatenated executable content.
        alternatives: Vec<T>,
    },
    /// Known admitted dependencies are missing or the head budget is exceeded.
    Incomplete,
}
/// Committed owner preferences and the separately labeled observed live view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Preference<T> {
    /// Exact interpretation basis.
    pub basis: EvaluationBasis,
    /// Only owner-accepted history contributes here.
    pub committed: Register<T>,
    /// Includes valid provisional updates; never durable credit by implication.
    pub observed: Register<T>,
}
/// Numeric availability cannot be confused with an actual zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Measured<T> {
    /// Result for the explicitly retained/admitted evidence subset.
    Known(T),
    /// Contributing evidence is unresolved; no fabricated numeric value.
    Incomplete,
}
/// Owner and exact signer attribution, retained through agent retirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Attribution {
    /// Durable admitted owner identity.
    pub owner: OwnerId,
    /// Exact owner/controller or agent/grant author.
    pub actor: Actor,
}
/// One exact revision's borrowed untrusted text.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct RevisionText<'a> {
    /// Creation or revision record that carries this exact text.
    pub revision: RecordId,
    /// Plain text; consumers must escape it for their output medium.
    pub text: &'a str,
}
/// Retraction hides ordinary presentation while the archive retains evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Content<'a> {
    /// Current exact revision alternatives.
    Present(Register<RevisionText<'a>>),
    /// A monotonic withdrawal; no restore operation exists in v1.
    Retracted {
        /// Exact retained withdrawal evidence.
        records: Vec<RecordId>,
    },
    /// Withdrawal/revision dependencies prevent a safe displayed choice.
    Incomplete,
}
/// One validated original post and its separate current revision projections.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostView<'a> {
    /// Exact interpretation basis.
    pub basis: EvaluationBasis,
    /// Stable original creation ID.
    pub id: RecordId,
    /// Immutable original attribution.
    pub attribution: Attribution,
    /// Public profile/channel placement.
    pub placement: Placement,
    /// Profile timeline owner inherited from the root; None for channels.
    pub profile_owner: Option<OwnerId>,
    /// Root post ID, including self for a top-level post.
    pub root: RecordId,
    /// Validated exact immediate-parent reference, when replying.
    pub reply: Option<ReplyRef>,
    /// Validated exact source revision; quotes do not transfer its authorship.
    pub quote: Option<PostRef>,
    /// Original quoted author, kept separate from this post's author.
    pub quote_attribution: Option<Attribution>,
    /// Original creation's commitment status.
    pub state: RecordState,
    /// Owner-accepted current content.
    pub committed: Content<'a>,
    /// Current content including separately identifiable provisional updates.
    pub observed: Content<'a>,
}
/// One owner's repost slot; exact revision IDs never inherit newer source text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepostView {
    /// Owner of the repost relationship, distinct from its source's author.
    pub owner: OwnerId,
    /// Stable original source post ID, including while its bytes are missing.
    pub post: RecordId,
    /// Accepted and observed exact source revisions; None is a cleared repost.
    pub preference: Preference<Option<RecordId>>,
    /// Original author only when the source post's attribution is validated.
    pub attribution: Option<Attribution>,
    /// Source or preference interpretation is missing, disputed or conflicting.
    pub source_incomplete: bool,
    /// The observed source has been withdrawn; exact historical references remain.
    pub source_retracted: bool,
    /// Original source admission, separate from the repost's commitment.
    pub source_state: Option<RecordState>,
}
/// Discoverable owner-profile activity, with original attribution retained.
/// Both finite variants stay inline to avoid an additional allocation per row;
/// the archive bounds the candidate set and each returned page contains at most 64.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum TimelineEntry<'a> {
    /// Owner-authored profile content or a reply attached to this owner's profile.
    Post(PostView<'a>),
    /// One owner-level repost preference, with explicit unavailable source state.
    Repost(RepostView),
}
/// A bounded page over a stable borrowed view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Page<T> {
    /// Exact interpretation basis; use a new cursor when it changes.
    pub basis: EvaluationBasis,
    /// Requested bounded slice.
    pub items: Vec<T>,
    /// Next offset within this exact view, when more items exist.
    pub next_offset: Option<usize>,
    /// Count of known matching records; not a network census.
    pub known_total: usize,
}
/// Biography for one currently authorized, unretired agent in this realm.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentBioView<'a> {
    /// Immutable agent genesis ID.
    pub agent: AgentId,
    /// Admitted owner; no name-based affiliation.
    pub owner: OwnerId,
    /// Full bound application key.
    pub key: [u8; 32],
    /// Committed and observed bio alternatives. Activity is not online presence.
    pub bio: Preference<&'a str>,
}
/// Owner profile plus a first page of its current admitted agent bios.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Profile<'a> {
    /// Exact interpretation basis.
    pub basis: EvaluationBasis,
    /// Durable lookup identity.
    pub owner: OwnerId,
    /// Current controller key if an unambiguous one is known.
    pub controller: Option<[u8; 32]>,
    /// Controller conflict prevents current authority choices.
    pub frozen: bool,
    /// Local capacity pressure closes current eligibility without erasing history.
    pub capacity_blocked: bool,
    /// Known authority or owner-sealed history is incomplete for this account.
    pub incomplete: bool,
    /// Owner-authored profile text, separate from all agent biographies.
    pub profile: Preference<&'a str>,
    /// First bounded roster page; use active_bios for subsequent pages.
    pub active_bios: Page<AgentBioView<'a>>,
}
/// Revision-specific observed reaction counts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Tally {
    /// Distinct owners upvoting this exact revision.
    pub up: u64,
    /// Distinct owners downvoting this exact revision.
    pub down: u64,
}
/// Current revision counts remain distinct from durable owner appreciation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Votes {
    /// Exact interpretation basis.
    pub basis: EvaluationBasis,
    /// Owner-accepted preferences on the exact revision.
    pub committed: Measured<Tally>,
    /// Also includes live provisional preferences.
    pub observed: Measured<Tally>,
}
/// Scope-labeled local social signals; no universal reputation or value balance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Stats {
    /// Exact interpretation basis.
    pub basis: EvaluationBasis,
    /// Distinct committed follower owners, including locally unweighted accounts.
    pub committed_followers: Measured<u64>,
    /// Distinct observed followers, including provisional updates.
    pub observed_followers: Measured<u64>,
    /// Owner-capped historical appreciation from all observed committed voters.
    pub observed_appreciation: Measured<i64>,
    /// Same committed evidence, weighted only by explicit local eligibility.
    pub eligible_appreciation: Measured<i64>,
    /// Known owner-sealed originals, including disputed ones; never a global count.
    pub committed_posts: usize,
    /// Sealed originals whose social dependencies cannot currently be interpreted.
    pub disputed_committed_posts: usize,
    /// This owner's known seal closure and sealed post semantics are available.
    pub committed_history_complete: bool,
    /// Known valid uncommitted original posts, separately labeled.
    pub provisional_posts: usize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum RegisterKey {
    Revision(RecordId),
    Reaction(OwnerId, RecordId),
    Repost(OwnerId, RecordId),
    Follow(OwnerId, OwnerId),
    AgentBio(AgentId),
    OwnerProfile(OwnerId),
}

/// A read-only view borrows its archive and explicit local eligibility policy.
pub struct View<'a> {
    control: ControlView<'a>,
    eligibility: &'a Eligibility,
    basis: EvaluationBasis,
    classification: BTreeMap<RecordId, Classification>,
    registers: BTreeMap<RegisterKey, Vec<RecordId>>,
    withdrawals: BTreeMap<RecordId, Vec<RecordId>>,
    reacting: BTreeMap<RecordId, BTreeSet<OwnerId>>,
    following: BTreeMap<OwnerId, BTreeSet<OwnerId>>,
}
impl<'a> View<'a> {
    /// Derive all classifications before exposing any effective register.
    #[must_use]
    pub fn new(archive: &'a Archive, now: u64, eligibility: &'a Eligibility) -> Self {
        let control = ControlView::new(archive, now);
        let eligibility_digest = eligibility.digest();
        let limits = archive.limits();
        let mut limits_hash = Sha256::new();
        limits_hash.update(b"vhalla/social/limits/v1");
        // Fixed-width encoding is identical on WASM32 and native 64-bit targets.
        // Archive construction has already bounded every field by MAX_RECORDS.
        for value in [
            limits.records,
            limits.control_reserve,
            limits.data_per_owner,
            limits.data_per_writer,
            limits.control_per_owner,
            limits.pending,
            limits.pending_per_signer,
        ] {
            limits_hash.update((value as u64).to_be_bytes());
        }
        let limits_digest: [u8; 32] = limits_hash.finalize().into();
        let mut hash = Sha256::new();
        hash.update(b"vhalla/social/evaluation/v1");
        hash.update(archive.root().as_bytes());
        hash.update(archive.realm().0.to_be_bytes());
        hash.update(POLICY_VERSION.to_be_bytes());
        hash.update(limits_digest);
        hash.update(eligibility_digest);
        hash.update(now.to_be_bytes());
        let basis = EvaluationBasis {
            archive_root: archive.root(),
            digest: hash.finalize().into(),
            limits_digest,
            eligibility_digest,
            now,
            policy_version: POLICY_VERSION,
            known_history_complete: false,
        };
        let mut this = Self {
            control,
            eligibility,
            basis,
            classification: BTreeMap::new(),
            registers: BTreeMap::new(),
            withdrawals: BTreeMap::new(),
            reacting: BTreeMap::new(),
            following: BTreeMap::new(),
        };
        for record in archive.records() {
            if !matches!(record.body(), Body::Social { .. }) {
                continue;
            }
            let (state, admission_known) = match this.control.social_status(record.id()) {
                SocialStatus::Committed | SocialStatus::Provisional => (RecordState::Pending, true),
                SocialStatus::Pending => (RecordState::Pending, false),
                SocialStatus::Rejected => (RecordState::Rejected, false),
                SocialStatus::Conflicted => (RecordState::Conflicted, true),
            };
            this.classification.insert(
                record.id(),
                Classification {
                    state,
                    admission_known,
                },
            );
        }
        // At most one promotion per record. Cycles remain pending, without recursion.
        let mut remaining = MAX_EVALUATION_STEPS;
        for _ in 0..this.classification.len() {
            let mut changed = false;
            let waiting: Vec<_> = this
                .classification
                .iter()
                .filter(|(_, c)| c.admission_known && c.state == RecordState::Pending)
                .map(|(id, _)| *id)
                .collect();
            for id in waiting {
                if remaining == 0 {
                    break;
                }
                remaining -= 1;
                match this.validate(id) {
                    Ok(()) => {
                        let state = if this.control.social_status(id) == SocialStatus::Committed {
                            RecordState::Committed
                        } else {
                            RecordState::Provisional
                        };
                        this.classification
                            .get_mut(&id)
                            .expect("retained classification")
                            .state = state;
                        changed = true;
                    }
                    Err(Error::Missing | Error::Incomplete) => {}
                    Err(Error::Conflict) => {
                        this.classification
                            .get_mut(&id)
                            .expect("retained classification")
                            .state = RecordState::Conflicted;
                        changed = true;
                    }
                    Err(_) => {
                        this.classification
                            .get_mut(&id)
                            .expect("retained classification")
                            .state = RecordState::Rejected;
                        changed = true;
                    }
                }
            }
            if !changed || remaining == 0 {
                break;
            }
        }
        for (&id, c) in &this.classification {
            if let Some(key) = this.key_for(id) {
                this.registers.entry(key).or_default().push(id);
            }
            if let Ok((actor, op)) = this.operation(id) {
                if let Operation::Retract { post } = op {
                    this.withdrawals.entry(*post).or_default().push(id);
                }
                if c.admission_known {
                    match op {
                        Operation::React { post, .. } => {
                            this.reacting
                                .entry(*post)
                                .or_default()
                                .insert(actor.owner());
                        }
                        Operation::Follow { target, .. } => {
                            this.following
                                .entry(*target)
                                .or_default()
                                .insert(actor.owner());
                        }
                        _ => {}
                    }
                }
            }
        }
        this.basis.known_history_complete = this.control.history_complete()
            && !this
                .classification
                .values()
                .any(|c| matches!(c.state, RecordState::Pending | RecordState::Conflicted));
        this
    }
    fn archive(&self) -> &'a Archive {
        self.control.archive()
    }
    /// Exact basis for every result from this borrowed view.
    #[must_use]
    pub const fn basis(&self) -> EvaluationBasis {
        self.basis
    }
    /// Classification of a retained social record, without trusting its display name.
    #[must_use]
    pub fn state(&self, id: RecordId) -> Option<RecordState> {
        self.classification.get(&id).map(|c| c.state)
    }
    fn operation(&self, id: RecordId) -> Result<(Actor, &'a Operation), Error> {
        match self.archive().get(id).ok_or(Error::Missing)?.body() {
            Body::Social {
                actor,
                realm,
                operation,
                ..
            } if *realm == self.archive().realm() => Ok((*actor, operation)),
            _ => Err(Error::Context),
        }
    }
    fn dependency(&self, id: RecordId) -> Result<(), Error> {
        match self.state(id) {
            Some(RecordState::Committed | RecordState::Provisional) => Ok(()),
            Some(RecordState::Rejected) => Err(Error::Context),
            Some(RecordState::Conflicted) => Err(Error::Conflict),
            _ => Err(Error::Missing),
        }
    }
    fn post_operation(&self, id: RecordId) -> Result<(Actor, &'a Operation), Error> {
        let (actor, op) = self.operation(id)?;
        if !matches!(op, Operation::Post { .. }) {
            return Err(Error::Context);
        }
        self.dependency(id)?;
        Ok((actor, op))
    }
    fn exact_revision(&self, reference: PostRef) -> Result<(), Error> {
        self.post_operation(reference.post)?;
        let (_, op) = self.operation(reference.revision)?;
        match op {
            Operation::Post { .. } if reference.revision == reference.post => {}
            Operation::Revise { post, .. } if *post == reference.post => {}
            _ => return Err(Error::Context),
        }
        self.dependency(reference.revision)
    }
    fn key_for(&self, id: RecordId) -> Option<RegisterKey> {
        let (actor, op) = self.operation(id).ok()?;
        match op {
            Operation::Post { .. } => Some(RegisterKey::Revision(id)),
            Operation::Revise { post, .. } if self.can_rewrite(actor, *post).is_ok() => {
                Some(RegisterKey::Revision(*post))
            }
            Operation::Revise { .. } => None,
            Operation::React { post, .. } => Some(RegisterKey::Reaction(actor.owner(), *post)),
            Operation::Repost { post, .. } => Some(RegisterKey::Repost(actor.owner(), *post)),
            Operation::Follow { target, .. } => Some(RegisterKey::Follow(actor.owner(), *target)),
            Operation::AgentBio { .. } => match actor {
                Actor::Agent { agent, .. } => Some(RegisterKey::AgentBio(agent)),
                _ => None,
            },
            Operation::OwnerProfile { .. } if matches!(actor, Actor::Owner { .. }) => {
                Some(RegisterKey::OwnerProfile(actor.owner()))
            }
            Operation::OwnerProfile { .. } => None,
            Operation::Retract { .. } => None,
        }
    }
    fn validate(&self, id: RecordId) -> Result<(), Error> {
        let (actor, op) = self.operation(id)?;
        // Known foreign writers cannot hide failed authorization behind a
        // missing causal predecessor and make another owner's content partial.
        if let Operation::Revise { post, .. } | Operation::Retract { post } = op {
            self.can_rewrite(actor, *post)?;
        }
        for previous in op.supersedes() {
            if *previous == id
                || self
                    .key_for(*previous)
                    .is_some_and(|key| Some(key) != self.key_for(id))
            {
                return Err(Error::Context);
            }
            self.operation(*previous)?;
            if self.key_for(*previous) != self.key_for(id) {
                return Err(Error::Context);
            }
            self.dependency(*previous)?;
        }
        match op {
            Operation::Post {
                placement,
                reply,
                quote,
                ..
            } => {
                if let Some(source) = quote {
                    self.exact_revision(*source)?;
                }
                if let Some(reply) = reply {
                    self.exact_revision(reply.parent)?;
                    let (_, root) = self.post_operation(reply.root)?;
                    let Operation::Post {
                        placement: root_placement,
                        reply: root_reply,
                        ..
                    } = root
                    else {
                        return Err(Error::Context);
                    };
                    if root_reply.is_some() || root_placement != placement {
                        return Err(Error::Context);
                    }
                    let mut parent = reply.parent.post;
                    for depth in 0..MAX_THREAD_DEPTH {
                        let (_, ancestor) = self.post_operation(parent)?;
                        let Operation::Post {
                            placement: ancestor_placement,
                            reply: ancestor_reply,
                            ..
                        } = ancestor
                        else {
                            return Err(Error::Context);
                        };
                        if ancestor_placement != root_placement {
                            return Err(Error::Context);
                        }
                        match ancestor_reply {
                            None => {
                                return if parent == reply.root {
                                    Ok(())
                                } else {
                                    Err(Error::Context)
                                }
                            }
                            Some(previous) => {
                                if previous.root != reply.root {
                                    return Err(Error::Context);
                                }
                                parent = previous.parent.post;
                            }
                        }
                        if depth + 1 == MAX_THREAD_DEPTH {
                            return Err(Error::Bounds);
                        }
                    }
                }
            }
            Operation::Revise { post, .. } | Operation::Retract { post } => {
                self.post_operation(*post)?;
                if matches!(op, Operation::Revise { .. }) && op.supersedes().is_empty() {
                    return Err(Error::Context);
                }
            }
            Operation::React { post, reaction, .. } => {
                self.post_operation(*post)?;
                if let Reaction::Up(revision) | Reaction::Down(revision) = reaction {
                    self.exact_revision(PostRef {
                        post: *post,
                        revision: *revision,
                    })?;
                }
            }
            Operation::Repost { post, revision, .. } => {
                self.post_operation(*post)?;
                if let Some(revision) = revision {
                    self.exact_revision(PostRef {
                        post: *post,
                        revision: *revision,
                    })?;
                }
            }
            Operation::Follow { target, .. } => {
                if self.control.owner(*target).is_none() {
                    return Err(Error::Missing);
                }
            }
            Operation::AgentBio { text, .. } => {
                if !matches!(actor, Actor::Agent { .. }) {
                    return Err(Error::Unauthorized);
                }
                if text.as_str().len() > MAX_BIO_BYTES {
                    return Err(Error::Bounds);
                }
            }
            Operation::OwnerProfile { text, .. } => {
                if !matches!(actor, Actor::Owner { .. }) {
                    return Err(Error::Unauthorized);
                }
                if text.as_str().len() > MAX_BIO_BYTES {
                    return Err(Error::Bounds);
                }
            }
        }
        Ok(())
    }
    fn can_rewrite(&self, actor: Actor, post: RecordId) -> Result<(), Error> {
        let (original, op) = self.operation(post)?;
        if !matches!(op, Operation::Post { .. }) {
            return Err(Error::Context);
        }
        if actor.owner() != original.owner()
            || !match actor {
                Actor::Owner { .. } => true,
                Actor::Agent { agent, .. } => {
                    matches!(original, Actor::Agent { agent: old, .. } if old == agent)
                }
            }
        {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
    fn register<T: Clone + Ord>(
        &self,
        key: RegisterKey,
        committed: bool,
        value: impl Fn(RecordId, &'a Operation) -> T,
        winner: impl Fn(&BTreeSet<T>) -> Option<T>,
    ) -> Register<T> {
        let mut candidates = BTreeMap::new();
        for &id in self.registers.get(&key).map_or(&[][..], Vec::as_slice) {
            let c = &self.classification[&id];
            if c.admission_known
                && matches!(c.state, RecordState::Pending | RecordState::Conflicted)
            {
                return Register::Incomplete;
            }
            if self.control.social_status(id) == SocialStatus::Committed
                && c.state != RecordState::Committed
            {
                // An accepted value losing its external context is disputed
                // evidence, never an implicit clear or removal of its vote.
                return Register::Incomplete;
            }
            if c.state != RecordState::Committed
                && (committed || c.state != RecordState::Provisional)
            {
                continue;
            }
            if let Ok((_, op)) = self.operation(id) {
                candidates.insert(id, (value(id, op), op));
            }
        }
        // Commitment selects values, not a different causal order. A committed
        // C can dominate committed A through provisional same-register B.
        let mut superseded = BTreeSet::new();
        let mut pending = Vec::new();
        for (_, op) in candidates.values() {
            for previous in op.supersedes() {
                if superseded.insert(*previous) {
                    pending.push(*previous);
                }
            }
        }
        while let Some(previous) = pending.pop() {
            if let Ok((_, op)) = self.operation(previous) {
                for ancestor in op.supersedes() {
                    if superseded.insert(*ancestor) {
                        pending.push(*ancestor);
                    }
                }
            }
        }
        let heads: Vec<_> = candidates
            .keys()
            .filter(|id| !superseded.contains(id))
            .copied()
            .collect();
        if heads.len() > MAX_HEADS {
            return Register::Incomplete;
        }
        if heads.is_empty() {
            return Register::Empty;
        }
        let values: BTreeSet<T> = heads.iter().map(|id| candidates[id].0.clone()).collect();
        if let Some(value) = winner(&values).or_else(|| {
            if values.len() == 1 {
                values.first().cloned()
            } else {
                None
            }
        }) {
            Register::Resolved { heads, value }
        } else {
            Register::Conflict {
                heads,
                alternatives: values.into_iter().collect(),
            }
        }
    }
    fn frozen(&self, owner: OwnerId) -> bool {
        self.control
            .owner(owner)
            .is_some_and(|status| status.frozen() || status.incomplete())
    }
    fn pair<T: Clone + Ord>(
        &self,
        owner: OwnerId,
        key: RegisterKey,
        value: impl Fn(RecordId, &'a Operation) -> T,
        winner: impl Fn(&BTreeSet<T>) -> Option<T>,
    ) -> Preference<T> {
        if self.frozen(owner) || !self.control.owner_history_complete(owner) {
            return Preference {
                basis: self.basis,
                committed: Register::Incomplete,
                observed: Register::Incomplete,
            };
        }
        Preference {
            basis: self.basis,
            committed: self.register(key, true, &value, &winner),
            observed: self.register(key, false, value, winner),
        }
    }
    /// Query one owner's exact revision-bound reaction slot.
    pub fn reaction(&self, owner: OwnerId, post: RecordId) -> Result<Preference<Reaction>, Error> {
        self.post_operation(post)?;
        if self.control.owner(owner).is_none() {
            return Err(Error::Missing);
        }
        Ok(self.pair(
            owner,
            RegisterKey::Reaction(owner, post),
            |_, op| match op {
                Operation::React { reaction, .. } => *reaction,
                _ => unreachable!("reaction key"),
            },
            |values| values.contains(&Reaction::Clear).then_some(Reaction::Clear),
        ))
    }
    /// Query one owner-level follow relationship. Unfollow wins concurrency.
    pub fn follow(&self, owner: OwnerId, target: OwnerId) -> Result<Preference<bool>, Error> {
        if self.control.owner(owner).is_none() || self.control.owner(target).is_none() {
            return Err(Error::Missing);
        }
        Ok(self.pair(
            owner,
            RegisterKey::Follow(owner, target),
            |_, op| match op {
                Operation::Follow { following, .. } => *following,
                _ => unreachable!("follow key"),
            },
            |values| values.contains(&false).then_some(false),
        ))
    }
    /// Query a plain repost of the exact original revision, or its explicit clear.
    pub fn repost(
        &self,
        owner: OwnerId,
        post: RecordId,
    ) -> Result<Preference<Option<RecordId>>, Error> {
        self.post_operation(post)?;
        if self.control.owner(owner).is_none() {
            return Err(Error::Missing);
        }
        Ok(self.pair(
            owner,
            RegisterKey::Repost(owner, post),
            |_, op| match op {
                Operation::Repost { revision, .. } => *revision,
                _ => unreachable!("repost key"),
            },
            |values| values.contains(&None).then_some(None),
        ))
    }
    fn text(&self, owner: OwnerId, key: RegisterKey) -> Preference<&'a str> {
        self.pair(
            owner,
            key,
            |_, op| match op {
                Operation::AgentBio { text, .. } | Operation::OwnerProfile { text, .. } => {
                    text.as_str()
                }
                _ => unreachable!("text key"),
            },
            |_| None,
        )
    }
    /// Paginate authorized, unretired agents. Disconnection is not retirement.
    pub fn active_bios(
        &self,
        owner: OwnerId,
        offset: usize,
        limit: usize,
    ) -> Result<Page<AgentBioView<'a>>, Error> {
        if self.control.owner(owner).is_none() {
            return Err(Error::Missing);
        }
        if limit == 0 || limit > MAX_PAGE_SIZE {
            return Err(Error::Bounds);
        }
        let agents: Vec<_> = self
            .control
            .agents()
            .filter(|(_, status)| status.owner() == owner && status.active() && !status.retired())
            .collect();
        if offset > agents.len() {
            return Err(Error::Bounds);
        }
        let end = offset.saturating_add(limit).min(agents.len());
        let items = agents[offset..end]
            .iter()
            .map(|(id, status)| AgentBioView {
                agent: *id,
                owner,
                key: status.key(),
                bio: self.text(owner, RegisterKey::AgentBio(*id)),
            })
            .collect();
        Ok(Page {
            basis: self.basis,
            items,
            next_offset: (end < agents.len()).then_some(end),
            known_total: agents.len(),
        })
    }
    /// Look up an account by durable ID, never by an untrusted name or biography.
    pub fn profile(&self, owner: OwnerId) -> Result<Profile<'a>, Error> {
        let status = self.control.owner(owner).ok_or(Error::Missing)?;
        Ok(Profile {
            basis: self.basis,
            owner,
            controller: status.key(),
            frozen: status.frozen(),
            capacity_blocked: status.capacity_blocked(),
            incomplete: status.incomplete() || !self.control.owner_history_complete(owner),
            profile: self.text(owner, RegisterKey::OwnerProfile(owner)),
            active_bios: self.active_bios(owner, 0, 32)?,
        })
    }
    fn content(&self, post: RecordId, committed: bool) -> Content<'a> {
        let mut retracted = Vec::new();
        for &id in self.withdrawals.get(&post).map_or(&[][..], Vec::as_slice) {
            let c = &self.classification[&id];
            if self
                .operation(id)
                .is_ok_and(|(actor, _)| self.can_rewrite(actor, post).is_err())
            {
                continue;
            }
            if c.admission_known
                && matches!(c.state, RecordState::Pending | RecordState::Conflicted)
            {
                return Content::Incomplete;
            }
            if c.state == RecordState::Committed
                || (!committed && c.state == RecordState::Provisional)
            {
                retracted.push(id);
            }
        }
        if !retracted.is_empty() {
            return Content::Retracted { records: retracted };
        }
        Content::Present(self.register(
            RegisterKey::Revision(post),
            committed,
            |id, op| match op {
                Operation::Post { text, .. } | Operation::Revise { text, .. } => RevisionText {
                    revision: id,
                    text: text.as_str(),
                },
                _ => unreachable!("revision key"),
            },
            |_| None,
        ))
    }
    /// Read one validated original, preserving exact references and authorship.
    pub fn post(&self, id: RecordId) -> Result<PostView<'a>, Error> {
        let (actor, op) = self.post_operation(id)?;
        let Operation::Post {
            placement,
            reply,
            quote,
            ..
        } = op
        else {
            return Err(Error::Context);
        };
        let root = reply.map_or(id, |r| r.root);
        let root_owner = self.operation(root)?.0.owner();
        let quote_attribution = quote
            .map(|q| {
                self.operation(q.post).map(|(author, _)| Attribution {
                    owner: author.owner(),
                    actor: author,
                })
            })
            .transpose()?;
        Ok(PostView {
            basis: self.basis,
            id,
            attribution: Attribution {
                owner: actor.owner(),
                actor,
            },
            placement: *placement,
            profile_owner: (*placement == Placement::Profile).then_some(root_owner),
            root,
            reply: *reply,
            quote: *quote,
            quote_attribution,
            state: self.state(id).ok_or(Error::Missing)?,
            committed: self.content(id, true),
            observed: self.content(id, false),
        })
    }
    /// Known valid originals in stable ID order, optionally filtered by placement.
    #[must_use]
    pub fn posts(&self, placement: Option<Placement>) -> Vec<PostView<'a>> {
        self.classification
            .keys()
            .filter_map(|id| self.post(*id).ok())
            .filter(|post| placement.is_none_or(|p| post.placement == p))
            .collect()
    }
    /// Discover profile posts, replies and reposts in stable original-content-ID
    /// order, with Post before Repost when both refer to the same ID. This is not
    /// chronological or ranked order. Each page belongs to this exact basis.
    ///
    /// Profile posts authored by this owner and replies on this owner's profile
    /// threads are included; unrelated channel content requires an explicit repost.
    /// Repost rows expose exact reviewed revision IDs without newer source text.
    pub fn timeline(
        &self,
        owner: OwnerId,
        offset: usize,
        limit: usize,
    ) -> Result<Page<TimelineEntry<'a>>, Error> {
        if self.control.owner(owner).is_none() {
            return Err(Error::Missing);
        }
        if limit == 0 || limit > MAX_PAGE_SIZE {
            return Err(Error::Bounds);
        }
        let mut rows = Vec::new();
        for post in self.posts(Some(Placement::Profile)) {
            if post.attribution.owner == owner
                || (post.profile_owner == Some(owner) && post.reply.is_some())
            {
                rows.push(((post.id, 0u8), TimelineEntry::Post(post)));
            }
        }
        for (key, records) in &self.registers {
            let RegisterKey::Repost(reposter, post) = key else {
                continue;
            };
            if *reposter != owner
                || !records
                    .iter()
                    .any(|id| self.classification[id].admission_known)
            {
                continue;
            }
            // Unlike the direct source query, discovery must retain an admitted
            // relationship whose exact source has not arrived yet.
            let preference = self.pair(
                owner,
                *key,
                |_, op| match op {
                    Operation::Repost { revision, .. } => *revision,
                    _ => unreachable!("repost register key"),
                },
                |values| values.contains(&None).then_some(None),
            );
            let cleared = |value: &Register<Option<RecordId>>| {
                matches!(
                    value,
                    Register::Empty | Register::Resolved { value: None, .. }
                )
            };
            if cleared(&preference.committed) && cleared(&preference.observed) {
                continue;
            }
            let source = self.post(*post).ok();
            let source_retracted = source
                .as_ref()
                .is_some_and(|value| matches!(value.observed, Content::Retracted { .. }));
            let preference_partial = |value: &Register<Option<RecordId>>| {
                matches!(value, Register::Incomplete | Register::Conflict { .. })
            };
            let source_incomplete = source.as_ref().is_none_or(|value| {
                matches!(
                    value.observed,
                    Content::Incomplete
                        | Content::Present(Register::Incomplete | Register::Conflict { .. })
                )
            }) || preference_partial(&preference.committed)
                || preference_partial(&preference.observed);
            rows.push((
                (*post, 1),
                TimelineEntry::Repost(RepostView {
                    owner,
                    post: *post,
                    preference,
                    attribution: source.map(|value| value.attribution),
                    source_incomplete,
                    source_retracted,
                    source_state: self.state(*post),
                }),
            ));
        }
        rows.sort_by_key(|(key, _)| *key);
        let known_total = rows.len();
        if offset > known_total {
            return Err(Error::Bounds);
        }
        let end = offset.saturating_add(limit).min(known_total);
        Ok(Page {
            basis: self.basis,
            items: rows
                .into_iter()
                .skip(offset)
                .take(limit)
                .map(|(_, row)| row)
                .collect(),
            next_offset: (end < known_total).then_some(end),
            known_total,
        })
    }
    /// Known validated replies for one actual root, sorted by stable content ID.
    pub fn thread(&self, root: RecordId) -> Result<Vec<PostView<'a>>, Error> {
        let original = self.post(root)?;
        if original.reply.is_some() {
            return Err(Error::Context);
        }
        Ok(self
            .posts(None)
            .into_iter()
            .filter(|post| post.root == root)
            .collect())
    }
    fn preference_owners(&self, target: TargetKind) -> BTreeSet<OwnerId> {
        match target {
            TargetKind::React(post) => self.reacting.get(&post).cloned().unwrap_or_default(),
            TargetKind::Follow(owner) => self.following.get(&owner).cloned().unwrap_or_default(),
        }
    }
    fn tally(&self, reference: PostRef, committed: bool) -> Measured<Tally> {
        let mut count = Tally::default();
        for owner in self.preference_owners(TargetKind::React(reference.post)) {
            let Ok(preference) = self.reaction(owner, reference.post) else {
                return Measured::Incomplete;
            };
            match if committed {
                preference.committed
            } else {
                preference.observed
            } {
                Register::Incomplete => return Measured::Incomplete,
                Register::Resolved {
                    value: Reaction::Up(revision),
                    ..
                } if revision == reference.revision => count.up += 1,
                Register::Resolved {
                    value: Reaction::Down(revision),
                    ..
                } if revision == reference.revision => count.down += 1,
                _ => {}
            }
        }
        Measured::Known(count)
    }
    /// Count one slot per owner on the exact revision; edited text inherits none.
    pub fn votes(&self, reference: PostRef) -> Result<Votes, Error> {
        self.exact_revision(reference)?;
        Ok(Votes {
            basis: self.basis,
            committed: self.tally(reference, true),
            observed: self.tally(reference, false),
        })
    }
    fn followers(&self, target: OwnerId, committed: bool) -> Measured<u64> {
        let mut count = 0;
        for owner in self.preference_owners(TargetKind::Follow(target)) {
            if owner == target {
                continue;
            }
            let Ok(preference) = self.follow(owner, target) else {
                return Measured::Incomplete;
            };
            match if committed {
                preference.committed
            } else {
                preference.observed
            } {
                Register::Incomplete => return Measured::Incomplete,
                Register::Resolved { value: true, .. } => count += 1,
                _ => {}
            }
        }
        Measured::Known(count)
    }
    fn appreciation(&self, owner: OwnerId, eligible: bool) -> Measured<i64> {
        if self.frozen(owner) || !self.control.owner_history_complete(owner) {
            return Measured::Incomplete;
        }
        if eligible
            && self
                .eligibility
                .owners()
                .iter()
                .any(|voter| *voter != owner && !self.control.owner_history_complete(*voter))
        {
            return Measured::Incomplete;
        }
        let mut contribution: BTreeMap<OwnerId, i64> = BTreeMap::new();
        for (&post, c) in &self.classification {
            if self.control.social_status(post) != SocialStatus::Committed {
                continue;
            }
            let Ok((author, Operation::Post { .. })) = self.operation(post) else {
                continue;
            };
            if author.owner() != owner {
                continue;
            }
            if c.state != RecordState::Committed {
                return Measured::Incomplete;
            }
            for voter in self.preference_owners(TargetKind::React(post)) {
                if voter == owner || (eligible && !self.eligibility.contains(voter)) {
                    continue;
                }
                let Ok(preference) = self.reaction(voter, post) else {
                    return Measured::Incomplete;
                };
                match preference.committed {
                    Register::Incomplete => return Measured::Incomplete,
                    Register::Resolved {
                        value: Reaction::Up(revision),
                        ..
                    } if self.state(revision) == Some(RecordState::Committed) => {
                        *contribution.entry(voter).or_default() += 1
                    }
                    Register::Resolved {
                        value: Reaction::Down(revision),
                        ..
                    } if self.state(revision) == Some(RecordState::Committed) => {
                        *contribution.entry(voter).or_default() -= 1
                    }
                    _ => {}
                }
            }
        }
        Measured::Known(
            contribution
                .values()
                .map(|value| (*value).clamp(-1, 1))
                .sum(),
        )
    }
    /// Inspect raw observations and explicitly eligible committed appreciation.
    pub fn stats(&self, owner: OwnerId) -> Result<Stats, Error> {
        if self.control.owner(owner).is_none() {
            return Err(Error::Missing);
        }
        let mut committed_posts = 0;
        let mut disputed_committed_posts = 0;
        let mut provisional_posts = 0;
        let accepted: BTreeSet<_> = self.control.accepted_ids().collect();
        for (&id, c) in &self.classification {
            if let Ok((actor, Operation::Post { .. })) = self.operation(id) {
                if actor.owner() == owner {
                    if accepted.contains(&id) {
                        committed_posts += 1;
                        if c.state != RecordState::Committed {
                            disputed_committed_posts += 1;
                        }
                    } else if c.state == RecordState::Provisional {
                        provisional_posts += 1;
                    }
                }
            }
        }
        Ok(Stats {
            basis: self.basis,
            committed_followers: self.followers(owner, true),
            observed_followers: self.followers(owner, false),
            observed_appreciation: self.appreciation(owner, false),
            eligible_appreciation: self.appreciation(owner, true),
            committed_posts,
            disputed_committed_posts,
            committed_history_complete: self.control.owner_history_complete(owner)
                && disputed_committed_posts == 0,
            provisional_posts,
        })
    }
}
#[derive(Clone, Copy)]
enum TargetKind {
    React(RecordId),
    Follow(OwnerId),
}
