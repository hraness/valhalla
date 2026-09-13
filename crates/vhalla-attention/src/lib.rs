#![no_std]
#![forbid(unsafe_code)]
//! Private reader state and source-derived notifications. These types confer no
//! agent execution, network, signing, or filesystem authority.

extern crate alloc;
#[cfg(test)]
extern crate std;

mod codec;
mod derive;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use sha2::{Digest, Sha256};
use vhalla_core::RealmId;
use vhalla_social::{
    archive::Archive,
    control::ControlView,
    view::{Attribution, EvaluationBasis, RecordState},
    AgentId, OwnerId, PostRef, RecordId,
};

/// Maximum single returned inbox page.
pub const MAX_PAGE: usize = 64;
/// Maximum entries retained independently in each lane during derivation.
pub const MAX_CANDIDATES: usize = 256;
/// Per-source-owner candidate bound, preserving space for other populations.
pub const MAX_PER_OWNER: usize = 32;
/// Maximum private group and exact-update marks in each separate lane.
pub const MAX_MARKS: usize = 256;
/// Maximum explicit selection/filter/subscription items per policy set.
pub const MAX_POLICY_ITEMS: usize = 512;
/// Maximum complete canonical private attention encoding.
pub const MAX_STATE_BYTES: usize = 300_000;

/// Stable bounded attention errors; none imply a permission or reset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A local count, byte, page, or generation ceiling was reached.
    Bounds,
    /// Malformed, noncanonical, unsupported, or damaged private bytes.
    Encoding,
    /// The local reader, realm, or historical owner binding differs.
    Context,
    /// Exact source evidence needed by this operation is absent.
    MissingSource,
    /// Social facts cannot currently be interpreted under the requested reader.
    Social(vhalla_social::Error),
}
impl From<vhalla_social::Error> for Error {
    fn from(value: vhalla_social::Error) -> Self {
        Self::Social(value)
    }
}

/// Local namespace admitted against historical owner/agent binding. It is not an
/// authentication credential or secrecy boundary against the same OS account.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReaderScope {
    realm: RealmId,
    owner: OwnerId,
    agent: Option<AgentId>,
    profile: [u8; 32],
    device: [u8; 32],
}
impl ReaderScope {
    /// Explicit local reader selection. Retired agents retain their historical
    /// namespace without receiving current agent execution authority.
    pub fn new(
        archive: &Archive,
        now: u64,
        owner: OwnerId,
        agent: Option<AgentId>,
        profile: [u8; 32],
        device: [u8; 32],
    ) -> Result<Self, Error> {
        let control = ControlView::new(archive, now);
        if control.owner(owner).is_none()
            || agent.is_some_and(|id| control.agent(id).is_none_or(|a| a.owner() != owner))
        {
            return Err(Error::Context);
        }
        Ok(Self {
            realm: archive.realm(),
            owner,
            agent,
            profile,
            device,
        })
    }
    /// Exact public realm.
    #[must_use]
    pub const fn realm(self) -> RealmId {
        self.realm
    }
    /// Durable recipient owner.
    #[must_use]
    pub const fn owner(self) -> OwnerId {
        self.owner
    }
    /// Exact optional reader-agent incarnation.
    #[must_use]
    pub const fn agent(self) -> Option<AgentId> {
        self.agent
    }
    /// Locally selected private interest profile.
    #[must_use]
    pub const fn profile(self) -> [u8; 32] {
        self.profile
    }
    /// Locally selected device namespace.
    #[must_use]
    pub const fn device(self) -> [u8; 32] {
        self.device
    }
    /// Canonical versioned digest shared with the independent discovery codec.
    #[must_use]
    pub fn digest(self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"vhalla/discovery/reader/v1\0");
        hash.update(self.realm.0.to_be_bytes());
        hash.update(self.owner.as_bytes());
        hash.update([u8::from(self.agent.is_some())]);
        if let Some(agent) = self.agent {
            hash.update(agent.as_bytes());
        }
        hash.update(self.profile);
        hash.update(self.device);
        hash.finalize().into()
    }
}

/// Semantic interaction reason, independent of event arrival and local clocks.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u8)]
pub enum Reason {
    /// Signed mention in a currently visible exact revision.
    Mention = 0,
    /// Reply to a post attributed to this owner.
    Reply = 1,
    /// Current follow or unfollow preference targeting this owner.
    Follow = 2,
    /// Current reaction preference on this owner's post.
    Reaction = 3,
    /// Current repost preference on this owner's post.
    Repost = 4,
    /// Current visible post quoting this owner's exact source revision.
    Quote = 5,
    /// Activity in an explicitly watched thread.
    WatchedThread = 6,
}
/// Separate budgets prevent unknown-source requests exhausting selected history.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u8)]
pub enum Lane {
    /// Explicitly selected, followed, or watched sources.
    Selected = 0,
    /// Other admitted sources; no priority notification by default.
    Requests = 1,
}
/// Complete stable owner grouping; an agent fleet cannot mint more owner slots.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Group {
    /// Durable recipient owner.
    pub recipient: OwnerId,
    /// Immutable source owner attribution.
    pub source_owner: OwnerId,
    /// Interaction-specific original post, owner, or preference target.
    pub target: RecordId,
    /// Semantic interaction reason.
    pub reason: Reason,
}
/// One exact revision or effective preference event within a stable group.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Update {
    /// Stable owner interaction group.
    pub group: Group,
    /// Exact source social record, never an arrival ordinal.
    pub event: RecordId,
}
/// Explicit read precision. Unknown is never a lifetime unread zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadState {
    /// No acknowledgement is known and retained history is precise.
    Unread,
    /// This exact update or stable group was acknowledged by this reader.
    Read,
    /// Bounded private retention cannot prove the answer.
    Unknown,
}
/// Derived metadata only. Fetching or displaying it never executes source text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Notification {
    /// Exact source update identity.
    pub update: Update,
    /// Exact authenticated signer attribution.
    pub source: Attribution,
    /// Historical recipient-agent routes; multiple routes retain one owner group.
    pub recipient_agents: Vec<AgentId>,
    /// Original source post, when the interaction has one.
    pub source_post: Option<RecordId>,
    /// Exact reviewed target revision, when applicable.
    pub target: Option<PostRef>,
    /// Validated conversation root, when applicable.
    pub root: Option<RecordId>,
    /// Source commitment under the returned basis.
    pub state: RecordState,
    /// Separate selected/request admission budget.
    pub lane: Lane,
    /// Positive resolved interaction; negative/clear/conflicted activity is false.
    pub positive: bool,
    /// Current preference has incompatible alternatives.
    pub conflict: bool,
    /// Stable priority state; unknown-source and negative activity have none.
    pub priority: Option<ReadState>,
    /// Exact revision acknowledgement, distinct from stable priority.
    pub read: ReadState,
}
impl Notification {
    /// Versioned exact update digest for explicit cross-process local selection.
    /// Group identity excludes revision; this update digest deliberately includes it.
    #[must_use]
    pub fn id(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"vhalla/attention/update/v1\0");
        hash.update(self.update.group.recipient.as_bytes());
        hash.update(self.update.group.source_owner.as_bytes());
        hash.update(self.update.group.target.as_bytes());
        hash.update([self.update.group.reason as u8]);
        hash.update(self.update.event.as_bytes());
        hash.finalize().into()
    }
}
/// Visible limits of this particular local projection.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Coverage {
    /// Known source/control dependencies or bounded semantic evaluation unresolved.
    pub incomplete: bool,
    /// Candidates omitted under the selected-source budget.
    pub selected_limited: bool,
    /// Candidates omitted under the unknown-source request budget.
    pub requests_limited: bool,
    /// At least one source exceeded its independent owner budget.
    pub owner_limited: bool,
    /// Historical recipient-agent binding was unavailable.
    pub unresolved_mentions: usize,
}
/// Counts describe only the returned page, with unknown precision explicit.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Counts {
    /// Exact shown updates currently known unread.
    pub unread_updates: usize,
    /// Exact shown updates whose read state is unknown.
    pub unknown_updates: usize,
    /// Distinct selected positive groups known unread.
    pub unread_groups: usize,
    /// Distinct selected positive groups with unknown priority precision.
    pub unknown_groups: usize,
}
/// Locally issued exact displayed IDs. Construction cannot be supplied by a peer.
#[derive(Clone, Debug)]
pub struct NotificationSnapshot {
    reader: ReaderScope,
    basis: EvaluationBasis,
    entries: Vec<Notification>,
    total: usize,
    coverage: Coverage,
}
impl NotificationSnapshot {
    /// Borrow exact entries acknowledged by this snapshot, not unseen group members.
    #[must_use]
    pub fn entries(&self) -> &[Notification] {
        &self.entries
    }
    /// Count of retained candidates before this bounded page.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.total
    }
    /// Source evaluation metadata; this is not a global completeness proof.
    #[must_use]
    pub const fn basis(&self) -> EvaluationBasis {
        self.basis
    }
    /// Candidate omissions and unresolved dependencies.
    #[must_use]
    pub const fn coverage(&self) -> Coverage {
        self.coverage
    }
    /// Exact local reader scope.
    #[must_use]
    pub const fn reader(&self) -> ReaderScope {
        self.reader
    }
    /// Select only explicit exact IDs from this locally derived snapshot. Unknown
    /// IDs, repeated IDs and oversized selections fail without acknowledging any.
    pub fn select(&self, ids: &[[u8; 32]]) -> Result<Self, Error> {
        if ids.len() > MAX_PAGE {
            return Err(Error::Bounds);
        }
        let requested: BTreeSet<_> = ids.iter().copied().collect();
        if requested.len() != ids.len() {
            return Err(Error::Encoding);
        }
        let entries: Vec<_> = self
            .entries
            .iter()
            .filter(|entry| requested.contains(&entry.id()))
            .cloned()
            .collect();
        if entries.len() != ids.len() {
            return Err(Error::MissingSource);
        }
        Ok(Self {
            reader: self.reader,
            basis: self.basis,
            entries,
            total: self.total,
            coverage: self.coverage,
        })
    }
    /// Count shown unread/unknown updates and deduplicated priority groups.
    #[must_use]
    pub fn counts(&self) -> Counts {
        let mut counts = Counts::default();
        let mut unread = BTreeSet::new();
        let mut unknown = BTreeSet::new();
        for entry in &self.entries {
            match entry.read {
                ReadState::Unread => counts.unread_updates += 1,
                ReadState::Unknown => counts.unknown_updates += 1,
                ReadState::Read => {}
            }
            match entry.priority {
                Some(ReadState::Unread) => {
                    unread.insert(entry.update.group);
                }
                Some(ReadState::Unknown) => {
                    unknown.insert(entry.update.group);
                }
                _ => {}
            }
        }
        counts.unread_groups = unread.len();
        counts.unknown_groups = unknown.len();
        counts
    }
}
/// Ephemeral locally selected filters; persisted preferences belong to discovery.
#[derive(Clone, Debug, Default)]
pub struct AttentionPolicy {
    selected: Vec<OwnerId>,
    muted: Vec<OwnerId>,
    watched: Vec<RecordId>,
    muted_threads: Vec<RecordId>,
    live: bool,
}
impl AttentionPolicy {
    /// Inputs must be sorted, unique and bounded. Following uses committed public
    /// preferences in addition to explicit selection; it never grants authority.
    pub fn new(
        selected: Vec<OwnerId>,
        muted: Vec<OwnerId>,
        watched: Vec<RecordId>,
        live: bool,
    ) -> Result<Self, Error> {
        if !canonical(&selected) || !canonical(&muted) || !canonical(&watched) {
            return Err(Error::Bounds);
        }
        Ok(Self {
            selected,
            muted,
            watched,
            muted_threads: Vec::new(),
            live,
        })
    }
    /// Exclude every interaction rooted in the exact muted threads, including
    /// direct mentions and replies; no silent truncation of persisted filters.
    pub fn with_muted_threads(mut self, roots: Vec<RecordId>) -> Result<Self, Error> {
        if !canonical(&roots) {
            return Err(Error::Bounds);
        };
        self.muted_threads = roots;
        Ok(self)
    }
}
fn canonical<T: Ord>(values: &[T]) -> bool {
    values.len() <= MAX_POLICY_ITEMS && values.windows(2).all(|pair| pair[0] < pair[1])
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Marks {
    // Every stable group retains an exact witness for native durable-source checks.
    groups: BTreeMap<Group, RecordId>,
    updates: BTreeSet<Update>,
    groups_unknown: bool,
    updates_unknown: bool,
    group_unknown_owners: BTreeSet<OwnerId>,
    update_unknown_owners: BTreeSet<OwnerId>,
}
impl Marks {
    fn lose_group(&mut self, owner: OwnerId) {
        lose_precision(
            &mut self.group_unknown_owners,
            &mut self.groups_unknown,
            owner,
        );
    }
    fn lose_update(&mut self, owner: OwnerId) {
        lose_precision(
            &mut self.update_unknown_owners,
            &mut self.updates_unknown,
            owner,
        );
    }
}
fn lose_precision(owners: &mut BTreeSet<OwnerId>, global: &mut bool, owner: OwnerId) {
    if owners.len() < MAX_MARKS || owners.contains(&owner) {
        owners.insert(owner);
    } else {
        *global = true;
    }
}
/// Bounded private acknowledgements; encode only to an explicitly private store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attention {
    reader: ReaderScope,
    generation: u64,
    selected: Marks,
    requests: Marks,
}
impl Attention {
    /// Empty exact private history for an admitted local reader.
    #[must_use]
    pub fn new(reader: ReaderScope) -> Self {
        Self {
            reader,
            generation: 0,
            selected: Marks::default(),
            requests: Marks::default(),
        }
    }
    /// Local namespace; never selected from source text.
    #[must_use]
    pub const fn reader(&self) -> ReaderScope {
        self.reader
    }
    /// Checked local mutation generation, not source event ordering or consensus.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    /// Derive a fresh bounded notification page internally from verified history.
    pub fn notifications(
        &self,
        archive: &Archive,
        now: u64,
        policy: &AttentionPolicy,
        offset: usize,
        limit: usize,
    ) -> Result<NotificationSnapshot, Error> {
        self.notifications_filtered(archive, now, policy, false, offset, limit)
    }
    /// Filter read entries before pagination; Unknown remains visible and labeled.
    pub fn notifications_filtered(
        &self,
        archive: &Archive,
        now: u64,
        policy: &AttentionPolicy,
        unread_only: bool,
        offset: usize,
        limit: usize,
    ) -> Result<NotificationSnapshot, Error> {
        derive::notifications(self, archive, now, policy, unread_only, offset, limit)
    }
    fn marks(&self, lane: Lane) -> &Marks {
        match lane {
            Lane::Selected => &self.selected,
            Lane::Requests => &self.requests,
        }
    }
    fn marks_mut(&mut self, lane: Lane) -> &mut Marks {
        match lane {
            Lane::Selected => &mut self.selected,
            Lane::Requests => &mut self.requests,
        }
    }
    fn read(&self, update: Update, lane: Lane) -> (ReadState, ReadState) {
        let preferred = self.marks(lane);
        let other = self.marks(if lane == Lane::Selected {
            Lane::Requests
        } else {
            Lane::Selected
        });
        // Changing local selection never resurrects already acknowledged content.
        (
            read_state(
                preferred.groups.contains_key(&update.group)
                    || other.groups.contains_key(&update.group),
                preferred.groups_unknown
                    || other.groups_unknown
                    || preferred
                        .group_unknown_owners
                        .contains(&update.group.source_owner)
                    || other
                        .group_unknown_owners
                        .contains(&update.group.source_owner),
            ),
            read_state(
                preferred.updates.contains(&update) || other.updates.contains(&update),
                preferred.updates_unknown
                    || other.updates_unknown
                    || preferred
                        .update_unknown_owners
                        .contains(&update.group.source_owner)
                    || other
                        .update_unknown_owners
                        .contains(&update.group.source_owner),
            ),
        )
    }
    /// Return a candidate private state acknowledging only the issued snapshot.
    /// This checks source presence, not filesystem durability. Native publication
    /// must independently check newly claimed sources in its locked social store.
    pub fn acknowledge(
        &self,
        shown: &NotificationSnapshot,
        archive: &Archive,
    ) -> Result<Self, Error> {
        if shown.reader != self.reader || archive.realm() != self.reader.realm {
            return Err(Error::Context);
        }
        if shown
            .entries
            .iter()
            .any(|entry| archive.get(entry.update.event).is_none())
        {
            return Err(Error::MissingSource);
        }
        let mut next = self.clone();
        for entry in &shown.entries {
            let marks = next.marks_mut(entry.lane);
            if let Some(witness) = marks.groups.get_mut(&entry.update.group) {
                *witness = (*witness).min(entry.update.event);
            } else if marks.groups.len() < MAX_MARKS {
                marks.groups.insert(entry.update.group, entry.update.event);
            } else {
                marks.lose_group(entry.update.group.source_owner);
            }
            if marks.updates.len() < MAX_MARKS || marks.updates.contains(&entry.update) {
                marks.updates.insert(entry.update);
            } else {
                marks.lose_update(entry.update.group.source_owner);
            }
        }
        if next != *self {
            next.generation = self.generation.checked_add(1).ok_or(Error::Bounds)?;
        }
        Ok(next)
    }
    /// Forget bounded exact history conservatively. Stable group acknowledgements
    /// survive; untracked revisions become Unknown, never replayed as Unread.
    pub fn forget_exact_marks(&self) -> Result<Self, Error> {
        let mut next = self.clone();
        for marks in [&mut next.selected, &mut next.requests] {
            let owners: BTreeSet<_> = marks
                .updates
                .iter()
                .map(|update| update.group.source_owner)
                .collect();
            for owner in owners {
                marks.lose_update(owner);
            }
            marks.updates.clear();
        }
        if next != *self {
            next.generation = self.generation.checked_add(1).ok_or(Error::Bounds)?;
        }
        Ok(next)
    }
    /// Sorted exact evidence underlying retained private read claims, including
    /// stable-group witnesses after exact-mark compaction.
    #[must_use]
    pub fn required_sources(&self) -> Vec<RecordId> {
        let mut result = BTreeSet::new();
        for marks in [&self.selected, &self.requests] {
            result.extend(marks.groups.values().copied());
            result.extend(marks.updates.iter().map(|update| update.event));
        }
        result.into_iter().collect()
    }
    /// Exact sources for newly added acknowledgement claims relative to prior
    /// private state. Diff semantic claims, not just the union of referenced IDs:
    /// an older observation or group witness cannot authorize a fresh exact ACK
    /// while that source is absent from the durable canonical store.
    pub fn new_claim_sources(&self, previous: &Self) -> Result<Vec<RecordId>, Error> {
        if self.reader != previous.reader {
            return Err(Error::Context);
        }
        let mut result = BTreeSet::new();
        for lane in [Lane::Selected, Lane::Requests] {
            let old = previous.marks(lane);
            let new = self.marks(lane);
            for (group, witness) in &new.groups {
                if old.groups.get(group) != Some(witness) {
                    result.insert(*witness);
                }
            }
            result.extend(
                new.updates
                    .difference(&old.updates)
                    .map(|update| update.event),
            );
        }
        Ok(result.into_iter().collect())
    }
    /// Exact retained source claims missing after a partial canonical restore.
    pub fn unresolved_sources(&self, archive: &Archive) -> Result<usize, Error> {
        if archive.realm() != self.reader.realm {
            return Err(Error::Context);
        }
        Ok(self
            .required_sources()
            .iter()
            .filter(|id| archive.get(**id).is_none())
            .count())
    }
    /// Bounded canonical private encoding; excluded from every public export API.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        codec::encode(self)
    }
    /// Strict bounded decode with caller-selected expected local reader namespace.
    pub fn decode(bytes: &[u8], expected: ReaderScope) -> Result<Self, Error> {
        codec::decode(bytes, expected)
    }
}
fn read_state(known: bool, unknown: bool) -> ReadState {
    if known {
        ReadState::Read
    } else if unknown {
        ReadState::Unknown
    } else {
        ReadState::Unread
    }
}

#[cfg(test)]
mod tests;
