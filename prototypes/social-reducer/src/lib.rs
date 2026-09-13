#![no_std]
#![forbid(unsafe_code)]
//! Disposable social semantics model. Fixture IDs/bindings are NOT authenticated.
//! This crate exposes no host effects, wire decoder, signature or network API.
extern crate alloc;
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

pub const MAX_OPERATIONS: usize = 1024;
pub const MAX_PARENTS: usize = 4;
pub const MAX_EFFECTIVE_HEADS: usize = 8;
pub const MAX_BINDINGS: usize = 2048;

macro_rules! id { ($($name:ident),+) => { $(
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct $name(pub u32);
)+ }; }
id!(Owner, Agent, Realm, Post, Revision, Event);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Target {
    Follow(Owner),
    Reaction(Post),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    pub realm: Realm,
    pub owner: Owner,
    pub target: Target,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Vote {
    Up,
    Down,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Reaction {
    Clear,
    On(Revision, Vote),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Body {
    Follow(Owner, bool),
    Reaction(Post, Reaction),
}
impl Body {
    fn target(self) -> Target {
        match self {
            Self::Follow(t, _) => Target::Follow(t),
            Self::Reaction(t, _) => Target::Reaction(t),
        }
    }
}
/// Untrusted fixture data, deliberately not named Verified/Admitted/Authorized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operation {
    pub id: Event,
    pub realm: Realm,
    pub owner: Owner,
    pub agent: Agent,
    pub body: Body,
    pub supersedes: Vec<Event>,
}
impl Operation {
    pub fn key(&self) -> Key {
        Key {
            realm: self.realm,
            owner: self.owner,
            target: self.body.target(),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Capacity,
    Rebinding,
    UnknownBinding,
    ParentLimit,
    DuplicateParent,
    SelfParent,
    IdConflict,
}
#[derive(Clone, Default)]
pub struct FixtureBindings(BTreeMap<Agent, Owner>);
impl FixtureBindings {
    pub fn add(&mut self, agent: Agent, owner: Owner) -> Result<(), Error> {
        match self.0.get(&agent) {
            Some(old) if *old != owner => Err(Error::Rebinding),
            Some(_) => Ok(()),
            None if self.0.len() == MAX_BINDINGS => Err(Error::Capacity),
            None => {
                self.0.insert(agent, owner);
                Ok(())
            }
        }
    }
    fn check(&self, op: &Operation) -> Result<(), Error> {
        if self.0.get(&op.agent) != Some(&op.owner) {
            return Err(Error::UnknownBinding);
        }
        if op.supersedes.len() > MAX_PARENTS {
            return Err(Error::ParentLimit);
        }
        if op.supersedes.contains(&op.id) {
            return Err(Error::SelfParent);
        }
        if op.supersedes.iter().copied().collect::<BTreeSet<_>>().len() != op.supersedes.len() {
            return Err(Error::DuplicateParent);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value {
    Absent,
    Follow(bool),
    Reaction(Reaction),
    ReactionConflict,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum View {
    Complete { heads: Vec<Event>, value: Value },
    Incomplete,
}
/// Reception outcome is separate from the retained local projection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MergeReceipt {
    Applied {
        retained_operations: usize,
    },
    Rejected {
        reason: Error,
        retained_operations: usize,
    },
}
fn resolve<'a>(ops: impl Iterator<Item = &'a Operation>) -> Value {
    let mut seen = false;
    let mut follow = true;
    let mut votes = BTreeSet::new();
    let mut clear = false;
    let mut is_follow = false;
    for op in ops {
        seen = true;
        match op.body {
            Body::Follow(_, v) => {
                is_follow = true;
                follow &= v;
            }
            Body::Reaction(_, Reaction::Clear) => clear = true,
            Body::Reaction(_, r) => {
                votes.insert(r);
            }
        }
    }
    if !seen {
        Value::Absent
    } else if is_follow {
        Value::Follow(follow)
    } else if clear {
        Value::Reaction(Reaction::Clear)
    } else if votes.len() == 1 {
        Value::Reaction(*votes.first().unwrap())
    } else {
        Value::ReactionConflict
    }
}

#[derive(Clone)]
pub struct Store {
    bindings: FixtureBindings,
    operations: BTreeMap<Event, Operation>,
    accepted: BTreeSet<Event>,
    invalid: BTreeSet<Event>,
    pending: BTreeSet<Event>,
    heads: BTreeMap<Key, BTreeSet<Event>>,
    exhausted: bool,
}
impl Store {
    pub fn new(bindings: FixtureBindings) -> Self {
        Self {
            bindings,
            operations: BTreeMap::new(),
            accepted: BTreeSet::new(),
            invalid: BTreeSet::new(),
            pending: BTreeSet::new(),
            heads: BTreeMap::new(),
            exhausted: false,
        }
    }
    pub fn insert(&mut self, op: Operation) -> Result<(), Error> {
        self.bindings.check(&op)?;
        if let Some(old) = self.operations.get(&op.id) {
            if old == &op {
                return Ok(());
            }
            self.exhausted = true;
            return Err(Error::IdConflict);
        }
        if self.operations.len() == MAX_OPERATIONS {
            self.exhausted = true;
            return Err(Error::Capacity);
        }
        self.pending.insert(op.id);
        self.operations.insert(op.id, op);
        self.advance();
        Ok(())
    }
    fn advance(&mut self) {
        loop {
            let mut changed = false;
            for id in self.pending.iter().copied().collect::<Vec<_>>() {
                let op = &self.operations[&id];
                let bad = op.supersedes.iter().any(|p| {
                    self.invalid.contains(p)
                        || self
                            .operations
                            .get(p)
                            .is_some_and(|parent| parent.key() != op.key())
                });
                if bad {
                    self.invalid.insert(id);
                    self.pending.remove(&id);
                    changed = true;
                    continue;
                }
                if op.supersedes.iter().all(|p| self.accepted.contains(p)) {
                    let heads = self.heads.entry(op.key()).or_default();
                    for p in &op.supersedes {
                        heads.remove(p);
                    }
                    heads.insert(id);
                    self.accepted.insert(id);
                    self.pending.remove(&id);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
    }
    pub fn view(&self, key: Key) -> View {
        if self.exhausted
            || self
                .pending
                .iter()
                .any(|id| self.operations[id].key() == key)
        {
            return View::Incomplete;
        }
        let heads = self.heads.get(&key).cloned().unwrap_or_default();
        if heads.len() > MAX_EFFECTIVE_HEADS {
            return View::Incomplete;
        }
        View::Complete {
            value: resolve(heads.iter().map(|id| &self.operations[id])),
            heads: heads.into_iter().collect(),
        }
    }
    /// Union retransmits untrusted operations through the same local fixture checks.
    /// A production merge must additionally bind authenticated context identities.
    pub fn merge(&mut self, other: &Self) -> Result<(), Error> {
        match self.merge_with_receipt(other) {
            MergeReceipt::Applied { .. } => Ok(()),
            MergeReceipt::Rejected { reason, .. } => Err(reason),
        }
    }
    /// A rejected union can leave a complete retained view; it is not union success.
    pub fn merge_with_receipt(&mut self, other: &Self) -> MergeReceipt {
        let mut candidate = self.clone();
        for op in other.operations.values() {
            if let Err(reason) = candidate.insert(op.clone()) {
                return MergeReceipt::Rejected {
                    reason,
                    retained_operations: self.operations.len(),
                };
            }
        }
        candidate.exhausted |= other.exhausted;
        *self = candidate;
        MergeReceipt::Applied {
            retained_operations: self.operations.len(),
        }
    }
    pub fn retained_operations(&self) -> usize {
        self.operations.len()
    }
}

/// Immutable fixture cohort: membership can grow but cannot be erased by content UI.
#[derive(Clone, Default)]
pub struct Cohort(BTreeMap<(Realm, Post), (Owner, BTreeSet<Revision>)>);
impl Cohort {
    pub fn commit(
        &mut self,
        realm: Realm,
        post: Post,
        owner: Owner,
        revision: Revision,
    ) -> Result<(), Error> {
        let exists = self
            .0
            .get(&(realm, post))
            .is_some_and(|(_, rs)| rs.contains(&revision));
        if !exists && self.0.values().map(|(_, rs)| rs.len()).sum::<usize>() == MAX_OPERATIONS {
            return Err(Error::Capacity);
        }
        if let Some((old, revisions)) = self.0.get_mut(&(realm, post)) {
            if *old != owner {
                return Err(Error::Rebinding);
            }
            if revisions.len() == MAX_OPERATIONS && !revisions.contains(&revision) {
                return Err(Error::Capacity);
            }
            revisions.insert(revision);
            return Ok(());
        }
        if self.0.len() == MAX_OPERATIONS {
            return Err(Error::Capacity);
        }
        self.0
            .insert((realm, post), (owner, BTreeSet::from([revision])));
        Ok(())
    }
}
/// Explicit local fixture policy, not inferred from bindings, follows or scores.
#[derive(Clone, Default)]
pub struct EligibleOwners(BTreeSet<Owner>);
impl EligibleOwners {
    pub fn from_local_policy(owners: &[Owner]) -> Result<Self, Error> {
        if owners.len() > MAX_BINDINGS {
            return Err(Error::Capacity);
        }
        Ok(Self(owners.iter().copied().collect()))
    }
}
/// Raw observed owner-capped appreciation, including unknown/Sybil owners.
/// This is deliberately separate from eligible ranking and proves no reputation.
pub fn observed_appreciation(
    store: &Store,
    cohort: &Cohort,
    realm: Realm,
    owner: Owner,
) -> Option<i32> {
    project_appreciation(store, cohort, None, realm, owner)
}
/// No time window, deletion flag or agent-liveness input can alter this projection.
/// None means incomplete evidence; empty eligibility means zero eligible owners.
pub fn eligible_appreciation(
    store: &Store,
    cohort: &Cohort,
    eligible: &EligibleOwners,
    realm: Realm,
    owner: Owner,
) -> Option<i32> {
    project_appreciation(store, cohort, Some(eligible), realm, owner)
}
fn project_appreciation(
    store: &Store,
    cohort: &Cohort,
    eligible: Option<&EligibleOwners>,
    realm: Realm,
    owner: Owner,
) -> Option<i32> {
    if store.exhausted {
        return None;
    }
    let mut by_owner: BTreeMap<Owner, i32> = BTreeMap::new();
    let keys: BTreeSet<_> = store.operations.values().map(Operation::key).collect();
    for key in keys {
        if key.realm != realm || key.owner == owner {
            continue;
        }
        if eligible.is_some_and(|allowed| !allowed.0.contains(&key.owner)) {
            continue;
        }
        let Target::Reaction(post) = key.target else {
            continue;
        };
        let Some((author, revisions)) = cohort.0.get(&(realm, post)) else {
            continue;
        };
        if *author != owner {
            continue;
        }
        match store.view(key) {
            View::Incomplete => return None,
            View::Complete {
                value: Value::Reaction(Reaction::On(revision, vote)),
                ..
            } if revisions.contains(&revision) => {
                *by_owner.entry(key.owner).or_default() += match vote {
                    Vote::Up => 1,
                    Vote::Down => -1,
                };
            }
            _ => {}
        }
    }
    Some(by_owner.values().map(|v| (*v).clamp(-1, 1)).sum())
}
/// A reaction to an old revision does not endorse the replacement text.
pub fn current_revision_vote(view: &View, revision: Revision) -> Option<i8> {
    match view {
        View::Incomplete => None,
        View::Complete {
            value: Value::Reaction(Reaction::On(r, vote)),
            ..
        } if *r == revision => Some(match vote {
            Vote::Up => 1,
            Vote::Down => -1,
        }),
        _ => Some(0),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Visibility {
    Public(Realm),
    Private {
        realm: Realm,
        audience: u32,
        epoch: u32,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placement {
    Profile(Owner),
    Channel(u32),
}
/// Placement has no power to widen visibility. Publication rights remain external.
pub fn repost_scope_allowed(
    source: Visibility,
    destination: Visibility,
    _placement: Placement,
) -> bool {
    source == destination
}

#[cfg(test)]
mod tests;
