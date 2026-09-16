//! Borrowed owner control and historical social admission.
//!
//! Strict signatures are evidence. This layer separately checks exact causal
//! authority, bounded rights and the owner-sealed historical frontier. It cannot
//! mint host capabilities and never selects a winner for controller forks.
use crate::{archive::Archive, model::*, wire::VerifiedRecord};
use alloc::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    vec::Vec,
};

/// Current interpretation of one signed social record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocialStatus {
    /// Exact owner-sealed history, retained across delegate lifecycle changes.
    Committed,
    /// Currently eligible, but not yet included in an owner commitment.
    Provisional,
    /// A required authenticated dependency or bounded evaluation is missing.
    Pending,
    /// Present evidence fails signature-role, scope, rights or lifecycle checks.
    Rejected,
    /// Authenticated control or unsealed writer evidence equivocates.
    Conflicted,
}

/// Derived controller state; the associated archive remains immutably borrowed.
#[derive(Clone, Debug)]
pub struct OwnerStatus {
    head: Option<RecordId>,
    key: Option<[u8; 32]>,
    frozen: bool,
    incomplete: bool,
    capacity_blocked: bool,
}
impl OwnerStatus {
    /// Unique known control head; absent for a controller fork.
    #[must_use]
    pub const fn head(&self) -> Option<RecordId> {
        self.head
    }
    /// Controller at the unique known head; never a fork winner.
    #[must_use]
    pub const fn key(&self) -> Option<[u8; 32]> {
        self.key
    }
    /// Valid controller children conflict. V1 has no automatic recovery.
    #[must_use]
    pub const fn frozen(&self) -> bool {
        self.frozen
    }
    /// An authenticated control action needs a missing authority dependency.
    #[must_use]
    pub const fn incomplete(&self) -> bool {
        self.incomplete
    }
    /// Current writes are closed by set-derived local resource pressure.
    /// This is separate from a cryptographic fork or missing control evidence.
    #[must_use]
    pub const fn capacity_blocked(&self) -> bool {
        self.capacity_blocked
    }
}

/// Immutable affiliation plus a current, clock-scoped agent projection.
#[derive(Clone, Debug)]
pub struct AgentStatus {
    owner: OwnerId,
    key: [u8; 32],
    retired: bool,
    active: bool,
    grant_ids: Vec<RecordId>,
}
impl AgentStatus {
    /// Immutable owner established by jointly signed genesis and control basis.
    #[must_use]
    pub const fn owner(&self) -> OwnerId {
        self.owner
    }
    /// Full application key from the authenticated agent genesis.
    #[must_use]
    pub const fn key(&self) -> [u8; 32] {
        self.key
    }
    /// A semantically admitted owner branch permanently retires this incarnation.
    #[must_use]
    pub const fn retired(&self) -> bool {
        self.retired
    }
    /// At least one current-realm grant is open and unexpired, under clear control.
    #[must_use]
    pub const fn active(&self) -> bool {
        self.active
    }
    /// Historically admitted grant IDs for the archive realm, including closed ones.
    #[must_use]
    pub fn grant_ids(&self) -> &[RecordId] {
        &self.grant_ids
    }
}

#[derive(Clone, Copy)]
struct Node {
    owner: OwnerId,
    previous: Option<RecordId>,
    key: [u8; 32],
}
#[derive(Clone, Copy)]
struct Grant {
    owner: OwnerId,
    agent: AgentId,
    realm: vhalla_core::RealmId,
    rights: Rights,
    expires_at: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Eval {
    Pending,
    Invalid,
}
struct Budget {
    remaining: usize,
    exhausted: bool,
}
impl Budget {
    fn new() -> Self {
        Self::with_limit(MAX_RECORDS * MAX_RECORDS)
    }
    fn with_limit(remaining: usize) -> Self {
        Self {
            remaining,
            exhausted: false,
        }
    }
    fn spend(&mut self) -> Result<(), Eval> {
        if self.remaining == 0 {
            self.exhausted = true;
            return Err(Eval::Pending);
        }
        self.remaining -= 1;
        Ok(())
    }
}
#[derive(Clone, Copy)]
enum HistoryMode {
    Open,
    Ratify,
    Unsealed,
}
#[derive(Clone, Copy)]
enum Filter {
    Owner(OwnerId),
    Agent(OwnerId, AgentId),
    Grant(OwnerId, RecordId),
}
impl Filter {
    fn accepts(self, actor: Actor) -> bool {
        match (self, actor) {
            (Self::Owner(owner), a) => owner == a.owner(),
            (
                Self::Agent(owner, agent),
                Actor::Agent {
                    owner: o, agent: a, ..
                },
            ) => owner == o && agent == a,
            (
                Self::Grant(owner, grant),
                Actor::Agent {
                    owner: o, grant: g, ..
                },
            ) => owner == o && grant == g,
            _ => false,
        }
    }
}
struct Closure {
    ids: BTreeSet<RecordId>,
    incomplete: bool,
}

/// A bounded derived view tied by borrowing to the exact retained archive.
/// Mutation requires dropping this view; no stale admission token can escape.
///
/// ```compile_fail
/// use vhalla_social::{archive::{Archive, Budget}, control::ControlView};
/// fn reuse_after_import(archive: &mut Archive) {
///     let view = ControlView::new(archive, 0);
///     let mut budget = Budget::new(1, 128).unwrap();
///     let _ = archive.ingest(&[], &mut budget);
///     let _ = view.history_complete();
/// }
/// ```
pub struct ControlView<'a> {
    archive: &'a Archive,
    now: u64,
    owners: BTreeMap<OwnerId, OwnerStatus>,
    agents: BTreeMap<AgentId, AgentStatus>,
    nodes: BTreeMap<RecordId, Node>,
    grants: BTreeMap<RecordId, Grant>,
    rejected_controls: BTreeSet<RecordId>,
    accepted: BTreeSet<RecordId>,
    statuses: BTreeMap<RecordId, SocialStatus>,
    history_complete: bool,
    incomplete_history_owners: BTreeSet<OwnerId>,
}

impl<'a> ControlView<'a> {
    /// Derive authority from retained evidence at an explicit evaluation time.
    /// Time changes current grant eligibility, never historical signature time.
    #[must_use]
    pub fn new(archive: &'a Archive, now: u64) -> Self {
        Self::with_history_budget(archive, now, MAX_RECORDS * MAX_RECORDS)
    }
    fn with_history_budget(archive: &'a Archive, now: u64, history_work: usize) -> Self {
        let mut view = Self {
            archive,
            now,
            owners: BTreeMap::new(),
            agents: BTreeMap::new(),
            nodes: BTreeMap::new(),
            grants: BTreeMap::new(),
            rejected_controls: BTreeSet::new(),
            accepted: BTreeSet::new(),
            statuses: BTreeMap::new(),
            history_complete: true,
            incomplete_history_owners: BTreeSet::new(),
        };
        view.derive(history_work);
        view
    }
    /// Borrow the exact immutable archive from which this view was derived.
    #[must_use]
    pub const fn archive(&self) -> &'a Archive {
        self.archive
    }
    /// Authenticated owner state, or None for a mere public-key/ID claim.
    #[must_use]
    pub fn owner(&self, owner: OwnerId) -> Option<&OwnerStatus> {
        self.owners.get(&owner)
    }
    /// Authenticated immutable agent affiliation and current activity.
    #[must_use]
    pub fn agent(&self, agent: AgentId) -> Option<&AgentStatus> {
        self.agents.get(&agent)
    }
    /// All authenticated owner geneses in deterministic identifier order.
    pub fn owners(&self) -> impl Iterator<Item = (OwnerId, &OwnerStatus)> {
        self.owners.iter().map(|(id, s)| (*id, s))
    }
    /// All authenticated agent geneses in deterministic identifier order.
    pub fn agents(&self) -> impl Iterator<Item = (AgentId, &AgentStatus)> {
        self.agents.iter().map(|(id, s)| (*id, s))
    }
    /// Current interpretation of a social record; unknown evidence remains pending.
    #[must_use]
    pub fn social_status(&self, id: RecordId) -> SocialStatus {
        self.statuses
            .get(&id)
            .copied()
            .unwrap_or(SocialStatus::Pending)
    }
    /// Every locally scoped owner-sealed closure is present and evaluation finished.
    /// This is distinct from controller completeness and archive/global completeness.
    #[must_use]
    pub const fn history_complete(&self) -> bool {
        self.history_complete
    }
    /// Whether this owner's locally scoped declared history is fully available.
    /// Unknown owners return false. Other owners' missing seals and foreign-realm
    /// frontiers do not change this value; current authority conflict is separate.
    #[must_use]
    pub fn owner_history_complete(&self, owner: OwnerId) -> bool {
        self.owners.contains_key(&owner) && !self.incomplete_history_owners.contains(&owner)
    }
    /// Exact committed evidence, including disputed branches when control is frozen.
    pub fn accepted_ids(&self) -> impl Iterator<Item = RecordId> + '_ {
        self.accepted.iter().copied()
    }
    /// No implicit account recovery or timestamp/epoch winner exists in v1.
    pub fn activate_recovery(&self) -> Result<(), Error> {
        Err(Error::RecoveryDisabled)
    }

    pub(crate) fn control_admitted(&self, id: RecordId) -> bool {
        self.nodes.contains_key(&id)
            && self
                .archive
                .get(id)
                .is_some_and(|r| matches!(r.body(), Body::Control { .. }))
    }
    /// Stable historical storage affiliation, not social-operation admission.
    /// Closed grants and frozen controllers do not erase authenticated attribution.
    pub(crate) fn storage_owner(&self, record: &VerifiedRecord) -> Option<OwnerId> {
        match record.body() {
            Body::OwnerGenesis { controller, .. } if record.primary_key() == controller => {
                Some(owner_id(record.id()))
            }
            Body::Control { owner, .. } => self
                .owns_historical_key(*owner, record.primary_key())
                .then_some(*owner),
            Body::AgentGenesis { .. } => self.storage_binding(record.id()).map(|(owner, _)| owner),
            Body::Social {
                actor: Actor::Owner { owner, .. },
                realm,
                ..
            } if *realm == self.archive.realm() => self
                .owns_historical_key(*owner, record.primary_key())
                .then_some(*owner),
            Body::Social {
                actor: Actor::Agent { owner, agent, .. },
                realm,
                ..
            } if *realm == self.archive.realm() => self
                .storage_binding(agent_record(*agent))
                .and_then(|(bound_owner, key)| {
                    (bound_owner == *owner && record.primary_key() == &key).then_some(*owner)
                }),
            _ => None,
        }
    }
    fn owns_historical_key(&self, owner: OwnerId, key: &[u8; 32]) -> bool {
        self.nodes
            .values()
            .any(|node| node.owner == owner && &node.key == key)
    }
    fn storage_binding(&self, id: RecordId) -> Option<(OwnerId, [u8; 32])> {
        let record = self.archive.get(id)?;
        let Body::AgentGenesis { owner, key, .. } = record.body() else {
            return None;
        };
        self.owns_historical_key(*owner, record.primary_key())
            .then_some((*owner, *key))
    }

    fn binding(&self, id: RecordId) -> Result<(OwnerId, RecordId, [u8; 32]), Eval> {
        let record = self.archive.get(id).ok_or(Eval::Pending)?;
        let Body::AgentGenesis {
            owner,
            control,
            key,
            ..
        } = record.body()
        else {
            return Err(Eval::Invalid);
        };
        let node = self.node(*control)?;
        if node.owner != *owner || record.primary_key() != &node.key {
            return Err(Eval::Invalid);
        }
        Ok((*owner, *control, *key))
    }
    fn node(&self, id: RecordId) -> Result<&Node, Eval> {
        self.nodes.get(&id).ok_or(
            if self.rejected_controls.contains(&id)
                || self.archive.get(id).is_some_and(|record| {
                    !matches!(
                        record.body(),
                        Body::OwnerGenesis { .. } | Body::Control { .. }
                    )
                })
            {
                Eval::Invalid
            } else {
                Eval::Pending
            },
        )
    }
    fn ancestor(
        &self,
        ancestor: RecordId,
        mut head: RecordId,
        budget: &mut Budget,
    ) -> Result<bool, Eval> {
        loop {
            budget.spend()?;
            if ancestor == head {
                return Ok(true);
            }
            let node = self.node(head)?;
            let Some(previous) = node.previous else {
                return Ok(false);
            };
            head = previous;
        }
    }
    fn branch_flags(
        &self,
        mut head: RecordId,
        agent: AgentId,
        grant: Option<RecordId>,
        budget: &mut Budget,
    ) -> Result<(bool, bool, bool), Eval> {
        let (mut enrolled, mut retired, mut revoked) = (false, false, false);
        loop {
            budget.spend()?;
            if let Some(Body::Control { action, .. }) =
                self.archive.get(head).map(VerifiedRecord::body)
            {
                match action {
                    ControlAction::Grant { agent: a, .. } if *a == agent => enrolled = true,
                    ControlAction::Retire { agent: a, .. } if *a == agent => retired = true,
                    ControlAction::Revoke { grant: g, .. } if Some(*g) == grant => revoked = true,
                    _ => {}
                }
            }
            let Some(previous) = self.node(head)?.previous else {
                return Ok((enrolled, retired, revoked));
            };
            head = previous;
        }
    }
    fn authority(&self, record: &VerifiedRecord, actor: Actor) -> Result<(), Eval> {
        match actor {
            Actor::Owner { owner, control } => {
                let node = self.node(control)?;
                if node.owner == owner && record.primary_key() == &node.key {
                    Ok(())
                } else {
                    Err(Eval::Invalid)
                }
            }
            Actor::Agent {
                owner,
                agent,
                grant,
            } => {
                let (bound_owner, _, key) = self.binding(agent_record(agent))?;
                if bound_owner != owner || record.primary_key() != &key {
                    return Err(Eval::Invalid);
                }
                let g =
                    self.grants
                        .get(&grant)
                        .ok_or(if self.rejected_controls.contains(&grant) {
                            Eval::Invalid
                        } else {
                            Eval::Pending
                        })?;
                if g.owner == owner
                    && g.agent == agent
                    && bound_owner == owner
                    && record.primary_key() == &key
                {
                    Ok(())
                } else {
                    Err(Eval::Invalid)
                }
            }
        }
    }
    fn social_auth(&self, record: &VerifiedRecord) -> Result<Actor, Eval> {
        let Body::Social {
            actor,
            realm,
            operation,
            ..
        } = record.body()
        else {
            return Err(Eval::Invalid);
        };
        if *realm != self.archive.realm() {
            return Err(Eval::Invalid);
        }
        self.authority(record, *actor)?;
        match actor {
            Actor::Owner { .. } if matches!(operation, Operation::AgentBio { .. }) => {
                return Err(Eval::Invalid)
            }
            Actor::Agent { grant, .. } => {
                let g = self.grants.get(grant).ok_or(Eval::Pending)?;
                let right = operation.required_right().ok_or(Eval::Invalid)?;
                if g.realm != *realm || !g.rights.contains(right) {
                    return Err(Eval::Invalid);
                }
            }
            _ => {}
        }
        if let Operation::Revise { post, .. }
        | Operation::ReviseFaceted { post, .. }
        | Operation::Retract { post } = operation
        {
            let original = self.archive.get(*post).ok_or(Eval::Pending)?;
            let Body::Social {
                actor: original_actor,
                realm: original_realm,
                operation: Operation::Post { .. } | Operation::PostFaceted { .. },
                ..
            } = original.body()
            else {
                return Err(Eval::Invalid);
            };
            self.authority(original, *original_actor)?;
            if original_realm != realm || original_actor.owner() != actor.owner() {
                return Err(Eval::Invalid);
            }
            if let Actor::Agent { agent, .. } = actor {
                if !matches!(original_actor, Actor::Agent { agent: a, .. } if a == agent) {
                    return Err(Eval::Invalid);
                }
            }
        }
        Ok(*actor)
    }
    fn historical_open(
        &self,
        actor: Actor,
        basis: RecordId,
        mode: HistoryMode,
        budget: &mut Budget,
    ) -> Result<(), Eval> {
        if matches!(mode, HistoryMode::Unsealed) {
            return Ok(());
        }
        match actor {
            Actor::Owner { control, .. } => {
                if !self.ancestor(control, basis, budget)? {
                    return Err(Eval::Invalid);
                }
                if matches!(mode, HistoryMode::Open)
                    && self.node(control)?.key != self.node(basis)?.key
                {
                    return Err(Eval::Invalid);
                }
            }
            Actor::Agent { agent, grant, .. } => {
                if !self.ancestor(grant, basis, budget)? {
                    return Err(Eval::Invalid);
                }
                if matches!(mode, HistoryMode::Open) {
                    let (_, retired, revoked) =
                        self.branch_flags(basis, agent, Some(grant), budget)?;
                    if retired || revoked {
                        return Err(Eval::Invalid);
                    }
                }
            }
        }
        Ok(())
    }
    fn chain(
        &self,
        head: RecordId,
        filter: Filter,
        basis: RecordId,
        mode: HistoryMode,
        budget: &mut Budget,
    ) -> Result<BTreeSet<RecordId>, Eval> {
        let mut ids = BTreeSet::new();
        let mut cursor = Some(head);
        let mut writer = None;
        let mut expected = None;
        while let Some(id) = cursor {
            budget.spend()?;
            if !ids.insert(id) || ids.len() > MAX_RECORDS {
                return Err(Eval::Invalid);
            }
            let record = self.archive.get(id).ok_or(Eval::Pending)?;
            let actor = self.social_auth(record)?;
            let Body::Social {
                sequence, previous, ..
            } = record.body()
            else {
                return Err(Eval::Invalid);
            };
            if !filter.accepts(actor)
                || writer.is_some_and(|w| w != actor)
                || expected.is_some_and(|s| s != *sequence)
                || (previous.is_none() && *sequence != 0)
            {
                return Err(Eval::Invalid);
            }
            self.historical_open(actor, basis, mode, budget)?;
            writer = Some(actor);
            expected = sequence.checked_sub(1);
            if previous.is_some() && expected.is_none() {
                return Err(Eval::Invalid);
            }
            cursor = *previous;
        }
        Ok(ids)
    }
    fn closure(
        &self,
        heads: &[RecordId],
        filter: Filter,
        basis: RecordId,
        mode: HistoryMode,
        budget: &mut Budget,
    ) -> Result<Closure, Eval> {
        let mut out = Closure {
            ids: BTreeSet::new(),
            incomplete: false,
        };
        for head in heads {
            match self.chain(*head, filter, basis, mode, budget) {
                Ok(ids) => out.ids.extend(ids),
                Err(Eval::Pending) => out.incomplete = true,
                // The controller authenticated its intent to commit these IDs.
                // Discovering an invalid/missing referenced payload cannot undo
                // that control transition or its later revocation/rotation.
                Err(Eval::Invalid) => out.incomplete = true,
            }
        }
        Ok(out)
    }

    fn action(
        &self,
        owner: OwnerId,
        previous: RecordId,
        action: &ControlAction,
        history: bool,
        budget: &mut Budget,
    ) -> Result<Closure, Eval> {
        let empty = || Closure {
            ids: BTreeSet::new(),
            incomplete: false,
        };
        match action {
            ControlAction::Grant { agent, .. } => {
                let (bound_owner, basis, _) = self.binding(agent_record(*agent))?;
                if bound_owner != owner {
                    return Err(Eval::Invalid);
                }
                let (enrolled, retired, _) = self.branch_flags(previous, *agent, None, budget)?;
                if retired || (!enrolled && basis != previous) {
                    return Err(Eval::Invalid);
                }
                Ok(empty())
            }
            ControlAction::Revoke { grant, accepted } => {
                let g = self
                    .grants
                    .get(grant)
                    .ok_or(if self.archive.get(*grant).is_some() {
                        Eval::Invalid
                    } else {
                        Eval::Pending
                    })?;
                if g.owner != owner || !self.ancestor(*grant, previous, budget)? {
                    return Err(Eval::Invalid);
                }
                let (_, retired, revoked) =
                    self.branch_flags(previous, g.agent, Some(*grant), budget)?;
                if retired || revoked {
                    return Err(Eval::Invalid);
                }
                if !history || g.realm != self.archive.realm() {
                    return Ok(empty());
                }
                self.closure(
                    accepted.as_slice(),
                    Filter::Grant(owner, *grant),
                    previous,
                    HistoryMode::Open,
                    budget,
                )
            }
            ControlAction::Retire {
                agent,
                realm,
                accepted,
            } => {
                let (bound_owner, basis, _) = self.binding(agent_record(*agent))?;
                if bound_owner != owner || !self.ancestor(basis, previous, budget)? {
                    return Err(Eval::Invalid);
                }
                let (_, retired, _) = self.branch_flags(previous, *agent, None, budget)?;
                if retired {
                    return Err(Eval::Invalid);
                }
                if !history || *realm != self.archive.realm() {
                    return Ok(empty());
                }
                self.closure(
                    accepted.as_slice(),
                    Filter::Agent(owner, *agent),
                    previous,
                    HistoryMode::Open,
                    budget,
                )
            }
            ControlAction::Seal { realm, heads } | ControlAction::Ratify { realm, heads } => {
                if !history || *realm != self.archive.realm() {
                    return Ok(empty());
                }
                let mode = if matches!(action, ControlAction::Seal { .. }) {
                    HistoryMode::Open
                } else {
                    HistoryMode::Ratify
                };
                self.closure(
                    heads.as_slice(),
                    Filter::Owner(owner),
                    previous,
                    mode,
                    budget,
                )
            }
            ControlAction::Rotate { .. } => Ok(empty()),
        }
    }

    fn derive(&mut self, history_work: usize) {
        // Every structural action visits at most two ancestor paths of at most
        // N admitted nodes plus one child visit. History never spends this budget.
        let mut budget = Budget::with_limit(2 * MAX_RECORDS * MAX_RECORDS + MAX_RECORDS);
        let mut children: BTreeMap<RecordId, Vec<&VerifiedRecord>> = BTreeMap::new();
        let mut queue = VecDeque::new();
        for record in self.archive.records() {
            match record.body() {
                Body::OwnerGenesis { controller, .. } if record.primary_key() == controller => {
                    let owner = owner_id(record.id());
                    self.nodes.insert(
                        record.id(),
                        Node {
                            owner,
                            previous: None,
                            key: *controller,
                        },
                    );
                    self.owners.insert(
                        owner,
                        OwnerStatus {
                            head: Some(record.id()),
                            key: Some(*controller),
                            frozen: false,
                            incomplete: false,
                            capacity_blocked: false,
                        },
                    );
                    queue.push_back(record.id());
                }
                Body::Control { previous, .. } => {
                    children.entry(*previous).or_default().push(record)
                }
                _ => {}
            }
        }
        while let Some(previous) = queue.pop_front() {
            let Some(parent) = self.nodes.get(&previous).copied() else {
                continue;
            };
            let mut admitted_children = 0usize;
            for record in children.get(&previous).into_iter().flatten() {
                if budget.spend().is_err() {
                    break;
                }
                let Body::Control { owner, action, .. } = record.body() else {
                    continue;
                };
                if *owner != parent.owner || record.primary_key() != &parent.key {
                    self.rejected_controls.insert(record.id());
                    continue;
                }
                match self.action(*owner, previous, action, false, &mut budget) {
                    Ok(closure) => {
                        let key = match action {
                            ControlAction::Rotate { new_key } => *new_key,
                            _ => parent.key,
                        };
                        self.nodes.insert(
                            record.id(),
                            Node {
                                owner: *owner,
                                previous: Some(previous),
                                key,
                            },
                        );
                        if let ControlAction::Grant {
                            agent,
                            realm,
                            rights,
                            expires_at,
                            ..
                        } = action
                        {
                            self.grants.insert(
                                record.id(),
                                Grant {
                                    owner: *owner,
                                    agent: *agent,
                                    realm: *realm,
                                    rights: *rights,
                                    expires_at: *expires_at,
                                },
                            );
                        }
                        self.accepted.extend(closure.ids);
                        self.history_complete &= !closure.incomplete;
                        if closure.incomplete {
                            self.incomplete_history_owners.insert(*owner);
                        }
                        admitted_children += 1;
                        queue.push_back(record.id());
                        if let Some(status) = self.owners.get_mut(owner) {
                            status.head = Some(record.id());
                            status.key = Some(key);
                        }
                    }
                    Err(Eval::Pending) => {
                        if let Some(status) = self.owners.get_mut(owner) {
                            status.incomplete = true;
                        }
                    }
                    Err(Eval::Invalid) => {
                        self.rejected_controls.insert(record.id());
                    }
                }
            }
            if admitted_children > 1 {
                if let Some(status) = self.owners.get_mut(&parent.owner) {
                    status.frozen = true;
                }
            }
        }
        for status in self.owners.values_mut() {
            if status.frozen {
                status.head = None;
                status.key = None;
            }
        }
        self.derive_history(history_work);
        let pressure = self.archive.capacity_pressure(self);
        for (owner, status) in &mut self.owners {
            status.capacity_blocked =
                pressure.global_closed || pressure.owners.get(owner).is_some_and(|p| p.closed);
        }
        let mut activity_budget = Budget::with_limit(2 * MAX_RECORDS * MAX_RECORDS);
        self.derive_agents(&mut activity_budget);
        let mut social_budget = Budget::new();
        self.derive_social(&mut social_budget);
        if budget.exhausted || activity_budget.exhausted || social_budget.exhausted {
            self.history_complete = false;
            self.incomplete_history_owners
                .extend(self.owners.keys().copied());
            for owner in self.owners.values_mut() {
                owner.incomplete = true;
            }
            for agent in self.agents.values_mut() {
                agent.active = false;
            }
            for status in self.statuses.values_mut() {
                *status = SocialStatus::Pending;
            }
        }
    }
    fn derive_history(&mut self, remaining: usize) {
        let mut budget = Budget::with_limit(remaining);
        for record in self.archive.records() {
            if !self.nodes.contains_key(&record.id()) {
                continue;
            }
            let Body::Control {
                owner,
                previous,
                action,
            } = record.body()
            else {
                continue;
            };
            if matches!(
                action,
                ControlAction::Grant { .. } | ControlAction::Rotate { .. }
            ) {
                continue;
            }
            match self.action(*owner, *previous, action, true, &mut budget) {
                Ok(closure) => {
                    self.accepted.extend(closure.ids);
                    if closure.incomplete {
                        self.history_complete = false;
                        self.incomplete_history_owners.insert(*owner);
                    }
                }
                Err(_) => {
                    self.history_complete = false;
                    self.incomplete_history_owners.insert(*owner);
                }
            }
        }
    }
    fn derive_agents(&mut self, budget: &mut Budget) {
        for record in self.archive.records() {
            if !matches!(record.body(), Body::AgentGenesis { .. }) {
                continue;
            }
            let Ok((owner, _, key)) = self.binding(record.id()) else {
                continue;
            };
            self.agents.insert(
                agent_id(record.id()),
                AgentStatus {
                    owner,
                    key,
                    retired: false,
                    active: false,
                    grant_ids: Vec::new(),
                },
            );
        }
        for id in self.nodes.keys() {
            if let Some(Body::Control {
                action: ControlAction::Retire { agent, .. },
                ..
            }) = self.archive.get(*id).map(VerifiedRecord::body)
            {
                if let Some(status) = self.agents.get_mut(agent) {
                    status.retired = true;
                }
            }
        }
        for (id, grant) in &self.grants {
            if grant.realm != self.archive.realm() {
                continue;
            }
            let active = self.owners.get(&grant.owner).is_some_and(|o| {
                !o.frozen
                    && !o.incomplete
                    && !o.capacity_blocked
                    && o.head.is_some_and(|head| {
                        self.ancestor(*id, head, budget) == Ok(true)
                            && self
                                .branch_flags(head, grant.agent, Some(*id), budget)
                                .is_ok_and(|(_, retired, revoked)| !retired && !revoked)
                            && self.now < grant.expires_at
                    })
            });
            if let Some(agent) = self.agents.get_mut(&grant.agent) {
                agent.grant_ids.push(*id);
                agent.active |= active;
            }
        }
    }
    fn live(&self, actor: Actor, budget: &mut Budget) -> Result<bool, Eval> {
        let owner = self.owners.get(&actor.owner()).ok_or(Eval::Pending)?;
        if owner.incomplete || owner.capacity_blocked {
            return Err(Eval::Pending);
        }
        let head = owner.head.ok_or(Eval::Invalid)?;
        match actor {
            Actor::Owner { control, .. } => Ok(control == head),
            Actor::Agent { agent, grant, .. } => {
                let g = self.grants.get(&grant).ok_or(Eval::Pending)?;
                let (_, retired, revoked) = self.branch_flags(head, agent, Some(grant), budget)?;
                Ok(self.ancestor(grant, head, budget)?
                    && !retired
                    && !revoked
                    && self.now < g.expires_at)
            }
        }
    }
    fn derive_social(&mut self, budget: &mut Budget) {
        let mut valid = Vec::new();
        let mut sibling_counts: BTreeMap<(Actor, Option<RecordId>), usize> = BTreeMap::new();
        let mut forked = BTreeSet::new();
        for record in self.archive.records() {
            let Body::Social {
                actor, previous, ..
            } = record.body()
            else {
                continue;
            };
            let result = self.chain(
                record.id(),
                Filter::Owner(actor.owner()),
                record.id(),
                HistoryMode::Unsealed,
                budget,
            );
            match result {
                Ok(_) => {
                    let count = sibling_counts.entry((*actor, *previous)).or_default();
                    *count += 1;
                    if *count > 1 {
                        forked.insert(*actor);
                    }
                    valid.push((record.id(), *actor));
                }
                Err(Eval::Pending) => {
                    self.statuses.insert(record.id(), SocialStatus::Pending);
                }
                Err(Eval::Invalid) => {
                    self.statuses.insert(record.id(), SocialStatus::Rejected);
                }
            }
        }
        for (id, actor) in valid {
            let status = if self.owners.get(&actor.owner()).is_some_and(|o| o.frozen) {
                SocialStatus::Conflicted
            } else if self.accepted.contains(&id) {
                SocialStatus::Committed
            } else {
                match self.live(actor, budget) {
                    Ok(false) | Err(Eval::Invalid) => SocialStatus::Rejected,
                    Err(Eval::Pending) => SocialStatus::Pending,
                    Ok(true) if forked.contains(&actor) => SocialStatus::Conflicted,
                    Ok(true) => SocialStatus::Provisional,
                }
            };
            self.statuses.insert(id, status);
        }
    }
}

fn owner_id(id: RecordId) -> OwnerId {
    OwnerId::from_bytes(*id.as_bytes())
}
fn agent_id(id: RecordId) -> AgentId {
    AgentId::from_bytes(*id.as_bytes())
}
fn agent_record(id: AgentId) -> RecordId {
    RecordId::from_bytes(*id.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        archive::{Budget as InputBudget, Limits},
        wire::UnsignedRecord,
    };
    use alloc::{format, string::ToString, vec};
    use ed25519_dalek::SigningKey;
    use hegel::generators as gs;
    use hegel::TestCase;
    use vhalla_core::RealmId;

    const REALM: RealmId = RealmId(77);
    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }
    fn sign(body: Body, key: &SigningKey, second: Option<&SigningKey>) -> VerifiedRecord {
        let primary = UnsignedRecord::new(key.verifying_key().to_bytes(), body)
            .unwrap()
            .sign_with_key(key)
            .unwrap();
        let signed = match second {
            Some(k) => primary.countersign(k).unwrap(),
            None => primary.finish().unwrap(),
        };
        signed.verify().unwrap()
    }
    fn limits() -> Limits {
        Limits {
            records: 256,
            control_reserve: 64,
            data_per_owner: 128,
            data_per_writer: 128,
            control_per_owner: 64,
            pending: 128,
            pending_per_signer: 128,
        }
    }
    fn put(archive: &mut Archive, record: &VerifiedRecord) {
        let bytes = record.encode();
        let mut budget = InputBudget::new(1, bytes.len()).unwrap();
        archive.ingest(&bytes, &mut budget).unwrap();
    }
    fn control(
        owner: OwnerId,
        previous: RecordId,
        action: ControlAction,
        key: &SigningKey,
        ack: Option<&SigningKey>,
    ) -> VerifiedRecord {
        sign(
            Body::Control {
                owner,
                previous,
                action,
            },
            key,
            ack,
        )
    }
    fn social(
        actor: Actor,
        sequence: u64,
        previous: Option<RecordId>,
        operation: Operation,
        key: &SigningKey,
    ) -> VerifiedRecord {
        sign(
            Body::Social {
                actor,
                realm: REALM,
                sequence,
                previous,
                operation,
            },
            key,
            None,
        )
    }
    fn post(text: &str) -> Operation {
        Operation::Post {
            placement: Placement::Profile,
            text: Text::new(text).unwrap(),
            reply: None,
            quote: None,
        }
    }
    fn refs(ids: &[RecordId]) -> References {
        References::sorted(ids.to_vec()).unwrap()
    }
    struct Fixture {
        archive: Archive,
        controller: SigningKey,
        agent_key: SigningKey,
        owner: OwnerId,
        agent: AgentId,
        grant: RecordId,
        records: Vec<VerifiedRecord>,
    }
    impl Fixture {
        fn new(rights: Rights) -> Self {
            let controller = key(1);
            let agent_key = key(2);
            let root = sign(
                Body::OwnerGenesis {
                    controller: controller.verifying_key().to_bytes(),
                    recovery: None,
                    nonce: [1; 32],
                },
                &controller,
                None,
            );
            let owner = owner_id(root.id());
            let genesis = sign(
                Body::AgentGenesis {
                    owner,
                    control: root.id(),
                    key: agent_key.verifying_key().to_bytes(),
                    nonce: [2; 32],
                },
                &controller,
                Some(&agent_key),
            );
            let agent = agent_id(genesis.id());
            let grant = control(
                owner,
                root.id(),
                ControlAction::Grant {
                    agent,
                    realm: REALM,
                    rights,
                    expires_at: 100,
                    nonce: [3; 32],
                },
                &controller,
                None,
            );
            let mut archive = Archive::new(REALM, limits()).unwrap();
            for record in [&root, &genesis, &grant] {
                put(&mut archive, record);
            }
            Self {
                archive,
                controller,
                agent_key,
                owner,
                agent,
                grant: grant.id(),
                records: vec![root, genesis, grant],
            }
        }
        fn actor(&self) -> Actor {
            Actor::Agent {
                owner: self.owner,
                agent: self.agent,
                grant: self.grant,
            }
        }
        fn seal(&self, previous: RecordId, heads: &[RecordId]) -> VerifiedRecord {
            control(
                self.owner,
                previous,
                ControlAction::Seal {
                    realm: REALM,
                    heads: refs(heads),
                },
                &self.controller,
                None,
            )
        }
    }

    #[test]
    fn signatures_do_not_authorize_claimed_owner_agent_or_rights() {
        let mut f = Fixture::new(Rights::POST);
        let arbitrary = social(f.actor(), 0, None, post("wrong key"), &key(9));
        let mismatched = social(
            Actor::Agent {
                owner: OwnerId::from_bytes([8; 32]),
                agent: f.agent,
                grant: RecordId::from_bytes([8; 32]),
            },
            0,
            None,
            post("wrong owner"),
            &f.agent_key,
        );
        let profile = social(
            f.actor(),
            0,
            None,
            Operation::OwnerProfile {
                text: Text::new("claimed profile").unwrap(),
                supersedes: refs(&[]),
            },
            &f.agent_key,
        );
        let follow = social(
            f.actor(),
            0,
            None,
            Operation::Follow {
                target: f.owner,
                following: true,
                supersedes: refs(&[]),
            },
            &f.agent_key,
        );
        let owner_bio = social(
            Actor::Owner {
                owner: f.owner,
                control: f.grant,
            },
            0,
            None,
            Operation::AgentBio {
                text: Text::new("wrong role").unwrap(),
                supersedes: refs(&[]),
            },
            &f.controller,
        );
        for record in [&arbitrary, &mismatched, &profile, &follow, &owner_bio] {
            put(&mut f.archive, record);
        }
        let view = ControlView::new(&f.archive, 1);
        for record in [&arbitrary, &mismatched, &profile, &follow, &owner_bio] {
            assert_eq!(view.social_status(record.id()), SocialStatus::Rejected);
        }
        assert_eq!(view.storage_owner(&arbitrary), None);
        assert_eq!(view.storage_owner(&mismatched), None);
        assert_eq!(view.storage_owner(&follow), Some(f.owner)); // Affiliation is not operation permission.
        assert!(view.agent(f.agent).unwrap().active());
    }

    #[test]
    fn missing_and_invalid_sealed_payloads_do_not_undo_control_progress() {
        let mut f = Fixture::new(Rights::ALL);
        let missing = social(f.actor(), 0, None, post("arrives later"), &f.agent_key);
        let seal = f.seal(f.grant, &[missing.id()]);
        put(&mut f.archive, &seal);
        let next = key(3);
        let rotate = control(
            f.owner,
            seal.id(),
            ControlAction::Rotate {
                new_key: next.verifying_key().to_bytes(),
            },
            &f.controller,
            Some(&next),
        );
        put(&mut f.archive, &rotate);
        let view = ControlView::new(&f.archive, 1);
        assert!(!view.history_complete());
        assert!(!view.owner_history_complete(f.owner));
        assert!(!view.owner(f.owner).unwrap().incomplete());
        assert_eq!(view.owner(f.owner).unwrap().head(), Some(rotate.id()));
        assert!(view.accepted_ids().next().is_none());
        put(&mut f.archive, &missing);
        let view = ControlView::new(&f.archive, 101);
        assert!(view.history_complete());
        assert!(view.owner_history_complete(f.owner));
        assert_eq!(view.social_status(missing.id()), SocialStatus::Committed);
        assert_eq!(
            view.owner(f.owner).unwrap().key(),
            Some(next.verifying_key().to_bytes())
        );

        let invalid = social(
            f.actor(),
            0,
            None,
            post("wrong application signer"),
            &key(8),
        );
        let bad_seal = control(
            f.owner,
            rotate.id(),
            ControlAction::Ratify {
                realm: REALM,
                heads: refs(&[invalid.id()]),
            },
            &next,
            None,
        );
        put(&mut f.archive, &bad_seal);
        let after = control(
            f.owner,
            bad_seal.id(),
            ControlAction::Revoke {
                grant: f.grant,
                accepted: refs(&[]),
            },
            &next,
            None,
        );
        put(&mut f.archive, &after);
        put(&mut f.archive, &invalid);
        let view = ControlView::new(&f.archive, 1);
        assert!(!view.history_complete());
        assert!(view.control_admitted(bad_seal.id()));
        assert!(view.control_admitted(after.id()));
        assert_eq!(view.owner(f.owner).unwrap().head(), Some(after.id()));
        assert_eq!(view.social_status(invalid.id()), SocialStatus::Rejected);
        assert_eq!(view.social_status(missing.id()), SocialStatus::Committed);
        assert!(!view.agent(f.agent).unwrap().active());
    }

    #[test]
    fn committed_owner_preferences_survive_retirement_and_successor_delegation() {
        let mut f = Fixture::new(Rights::ALL);
        let follow = social(
            f.actor(),
            0,
            None,
            Operation::Follow {
                target: OwnerId::from_bytes([9; 32]),
                following: true,
                supersedes: refs(&[]),
            },
            &f.agent_key,
        );
        let react = social(
            f.actor(),
            1,
            Some(follow.id()),
            Operation::React {
                post: RecordId::from_bytes([7; 32]),
                reaction: Reaction::Up(RecordId::from_bytes([7; 32])),
                supersedes: refs(&[]),
            },
            &f.agent_key,
        );
        put(&mut f.archive, &follow);
        put(&mut f.archive, &react);
        let seal = f.seal(f.grant, &[react.id()]);
        put(&mut f.archive, &seal);
        let retire = control(
            f.owner,
            seal.id(),
            ControlAction::Retire {
                agent: f.agent,
                realm: REALM,
                accepted: refs(&[]),
            },
            &f.controller,
            None,
        );
        put(&mut f.archive, &retire);
        let next = key(4);
        let genesis = sign(
            Body::AgentGenesis {
                owner: f.owner,
                control: retire.id(),
                key: next.verifying_key().to_bytes(),
                nonce: [4; 32],
            },
            &f.controller,
            Some(&next),
        );
        put(&mut f.archive, &genesis);
        let next_grant = control(
            f.owner,
            retire.id(),
            ControlAction::Grant {
                agent: agent_id(genesis.id()),
                realm: REALM,
                rights: Rights::ALL,
                expires_at: 300,
                nonce: [5; 32],
            },
            &f.controller,
            None,
        );
        put(&mut f.archive, &next_grant);
        let unfollow = social(
            Actor::Agent {
                owner: f.owner,
                agent: agent_id(genesis.id()),
                grant: next_grant.id(),
            },
            0,
            None,
            Operation::Follow {
                target: OwnerId::from_bytes([9; 32]),
                following: false,
                supersedes: refs(&[follow.id()]),
            },
            &next,
        );
        put(&mut f.archive, &unfollow);
        let next_seal = f.seal(next_grant.id(), &[unfollow.id()]);
        put(&mut f.archive, &next_seal);
        let view = ControlView::new(&f.archive, 200);
        for record in [&follow, &react, &unfollow] {
            assert_eq!(view.social_status(record.id()), SocialStatus::Committed);
        }
        assert!(view.agent(f.agent).unwrap().retired());
        assert!(!view.agent(f.agent).unwrap().active());
        assert!(view.agent(agent_id(genesis.id())).unwrap().active());
        assert_eq!(
            view.accepted_ids().collect::<BTreeSet<_>>(),
            BTreeSet::from([follow.id(), react.id(), unfollow.id()])
        );
        assert_eq!(view.storage_owner(&react), Some(f.owner));
    }

    #[test]
    fn exact_seals_distinguish_equal_sequence_siblings_and_ratification_does_not_reopen_grants() {
        let mut f = Fixture::new(Rights::ALL);
        let first = social(f.actor(), 0, None, post("first branch"), &f.agent_key);
        let sibling = social(
            f.actor(),
            0,
            None,
            post("equal sequence sibling"),
            &f.agent_key,
        );
        put(&mut f.archive, &first);
        put(&mut f.archive, &sibling);
        assert_eq!(
            ControlView::new(&f.archive, 1).social_status(first.id()),
            SocialStatus::Conflicted
        );
        let seal = f.seal(f.grant, &[first.id()]);
        put(&mut f.archive, &seal);
        let view = ControlView::new(&f.archive, 1);
        assert_eq!(view.social_status(first.id()), SocialStatus::Committed);
        assert_eq!(view.social_status(sibling.id()), SocialStatus::Conflicted);
        let revoke = control(
            f.owner,
            seal.id(),
            ControlAction::Revoke {
                grant: f.grant,
                accepted: refs(&[]),
            },
            &f.controller,
            None,
        );
        put(&mut f.archive, &revoke);
        assert_eq!(
            ControlView::new(&f.archive, 1).social_status(sibling.id()),
            SocialStatus::Rejected
        );
        let mut invalid_seal_archive = f.archive.clone();
        let closed_seal = f.seal(revoke.id(), &[sibling.id()]);
        put(&mut invalid_seal_archive, &closed_seal);
        let invalid_view = ControlView::new(&invalid_seal_archive, 1);
        assert!(!invalid_view.history_complete());
        assert_eq!(
            invalid_view.social_status(sibling.id()),
            SocialStatus::Rejected
        );
        let ratify = control(
            f.owner,
            revoke.id(),
            ControlAction::Ratify {
                realm: REALM,
                heads: refs(&[sibling.id()]),
            },
            &f.controller,
            None,
        );
        put(&mut f.archive, &ratify);
        let view = ControlView::new(&f.archive, 1);
        assert!(view.history_complete());
        assert_eq!(view.social_status(sibling.id()), SocialStatus::Committed);
        assert!(!view.agent(f.agent).unwrap().active());
        assert_eq!(view.activate_recovery(), Err(Error::RecoveryDisabled));
    }

    #[test]
    fn planned_rotation_requires_current_basis_and_invalid_children_do_not_freeze() {
        let mut f = Fixture::new(Rights::ALL);
        let new_controller = key(5);
        let new_agent = key(6);
        let rotate = control(
            f.owner,
            f.grant,
            ControlAction::Rotate {
                new_key: new_controller.verifying_key().to_bytes(),
            },
            &f.controller,
            Some(&new_controller),
        );
        put(&mut f.archive, &rotate);
        let stale = sign(
            Body::AgentGenesis {
                owner: f.owner,
                control: f.grant,
                key: new_agent.verifying_key().to_bytes(),
                nonce: [6; 32],
            },
            &f.controller,
            Some(&new_agent),
        );
        put(&mut f.archive, &stale);
        let invalid_grant = control(
            f.owner,
            rotate.id(),
            ControlAction::Grant {
                agent: agent_id(stale.id()),
                realm: REALM,
                rights: Rights::ALL,
                expires_at: 200,
                nonce: [7; 32],
            },
            &new_controller,
            None,
        );
        put(&mut f.archive, &invalid_grant);
        let valid = sign(
            Body::AgentGenesis {
                owner: f.owner,
                control: rotate.id(),
                key: new_agent.verifying_key().to_bytes(),
                nonce: [8; 32],
            },
            &new_controller,
            Some(&new_agent),
        );
        let valid_grant = control(
            f.owner,
            rotate.id(),
            ControlAction::Grant {
                agent: agent_id(valid.id()),
                realm: REALM,
                rights: Rights::ALL,
                expires_at: 200,
                nonce: [9; 32],
            },
            &new_controller,
            None,
        );
        put(&mut f.archive, &valid_grant);
        let view = ControlView::new(&f.archive, 1);
        assert!(view.owner(f.owner).unwrap().incomplete());
        assert!(!view.owner(f.owner).unwrap().frozen());
        put(&mut f.archive, &valid);
        let view = ControlView::new(&f.archive, 1);
        assert!(!view.owner(f.owner).unwrap().incomplete());
        assert!(!view.owner(f.owner).unwrap().frozen());
        assert!(!view.control_admitted(invalid_grant.id()));
        assert!(view.control_admitted(valid_grant.id()));
        assert!(view.agent(agent_id(valid.id())).unwrap().active());
        let old_key_child = control(
            f.owner,
            valid_grant.id(),
            ControlAction::Revoke {
                grant: valid_grant.id(),
                accepted: refs(&[]),
            },
            &f.controller,
            None,
        );
        put(&mut f.archive, &old_key_child);
        let view = ControlView::new(&f.archive, 1);
        assert!(!view.control_admitted(old_key_child.id()));
        assert_eq!(view.owner(f.owner).unwrap().head(), Some(valid_grant.id()));
    }

    #[test]
    fn late_control_forks_preserve_evidence_but_freeze_current_projections() {
        let mut f = Fixture::new(Rights::ALL);
        let post = social(f.actor(), 0, None, post("committed"), &f.agent_key);
        put(&mut f.archive, &post);
        let seal = f.seal(f.grant, &[post.id()]);
        put(&mut f.archive, &seal);
        let retire = control(
            f.owner,
            seal.id(),
            ControlAction::Retire {
                agent: f.agent,
                realm: REALM,
                accepted: refs(&[]),
            },
            &f.controller,
            None,
        );
        put(&mut f.archive, &retire);
        let next = key(7);
        let fork = control(
            f.owner,
            seal.id(),
            ControlAction::Rotate {
                new_key: next.verifying_key().to_bytes(),
            },
            &f.controller,
            Some(&next),
        );
        put(&mut f.archive, &fork);
        let view = ControlView::new(&f.archive, 1);
        assert!(view.owner(f.owner).unwrap().frozen());
        assert_eq!(view.owner(f.owner).unwrap().head(), None);
        assert_eq!(view.social_status(post.id()), SocialStatus::Conflicted);
        assert_eq!(view.accepted_ids().collect::<Vec<_>>(), vec![post.id()]);
        assert!(!view.agent(f.agent).unwrap().active());
        assert_eq!(view.storage_owner(&post), Some(f.owner));
        assert!(view.control_admitted(retire.id()) && view.control_admitted(fork.id()));
    }

    #[test]
    fn foreign_realm_frontiers_do_not_require_hidden_payloads_for_global_control() {
        let mut f = Fixture::new(Rights::ALL);
        let foreign = control(
            f.owner,
            f.grant,
            ControlAction::Seal {
                realm: RealmId(88),
                heads: refs(&[RecordId::from_bytes([8; 32])]),
            },
            &f.controller,
            None,
        );
        put(&mut f.archive, &foreign);
        let retire = control(
            f.owner,
            foreign.id(),
            ControlAction::Retire {
                agent: f.agent,
                realm: RealmId(88),
                accepted: refs(&[RecordId::from_bytes([9; 32])]),
            },
            &f.controller,
            None,
        );
        put(&mut f.archive, &retire);
        let view = ControlView::new(&f.archive, 1);
        assert!(view.history_complete());
        assert_eq!(view.owner(f.owner).unwrap().head(), Some(retire.id()));
        assert!(view.agent(f.agent).unwrap().retired());
        assert!(!view.agent(f.agent).unwrap().active());
    }

    #[test]
    fn unknown_predecessor_claims_cannot_poison_a_victims_control_state() {
        let mut f = Fixture::new(Rights::ALL);
        let claim = control(
            f.owner,
            RecordId::from_bytes([9; 32]),
            ControlAction::Rotate {
                new_key: key(8).verifying_key().to_bytes(),
            },
            &key(9),
            Some(&key(8)),
        );
        put(&mut f.archive, &claim);
        let view = ControlView::new(&f.archive, 1);
        assert!(!view.owner(f.owner).unwrap().incomplete());
        assert!(!view.owner(f.owner).unwrap().frozen());
        assert_eq!(view.storage_owner(&claim), None);
    }

    #[test]
    fn incomplete_seals_are_scoped_to_the_declaring_owner_and_archive_realm() {
        let mut f = Fixture::new(Rights::ALL);
        let other = sign(
            Body::OwnerGenesis {
                controller: key(9).verifying_key().to_bytes(),
                recovery: None,
                nonce: [99; 32],
            },
            &key(9),
            None,
        );
        put(&mut f.archive, &other);
        let other_owner = owner_id(other.id());
        let missing = social(
            f.actor(),
            0,
            None,
            post("known missing commitment"),
            &f.agent_key,
        );
        let seal = f.seal(f.grant, &[missing.id()]);
        put(&mut f.archive, &seal);
        let foreign = control(
            other_owner,
            other.id(),
            ControlAction::Seal {
                realm: RealmId(999),
                heads: refs(&[RecordId::from_bytes([77; 32])]),
            },
            &key(9),
            None,
        );
        put(&mut f.archive, &foreign);
        let view = ControlView::new(&f.archive, 1);
        assert!(!view.history_complete());
        assert!(!view.owner_history_complete(f.owner));
        assert!(view.owner_history_complete(other_owner));
        assert!(!view.owner_history_complete(OwnerId::from_bytes([66; 32])));
        put(&mut f.archive, &missing);
        let view = ControlView::new(&f.archive, 1);
        assert!(view.history_complete());
        assert!(view.owner_history_complete(f.owner));
        assert!(view.owner_history_complete(other_owner));
    }

    #[test]
    fn history_work_exhaustion_cannot_erase_structural_control_or_storage_proof() {
        let mut f = Fixture::new(Rights::ALL);
        let post = social(f.actor(), 0, None, post("bounded history"), &f.agent_key);
        put(&mut f.archive, &post);
        let seal = f.seal(f.grant, &[post.id()]);
        put(&mut f.archive, &seal);
        let revoke = control(
            f.owner,
            seal.id(),
            ControlAction::Revoke {
                grant: f.grant,
                accepted: refs(&[]),
            },
            &f.controller,
            None,
        );
        put(&mut f.archive, &revoke);
        let view = ControlView::with_history_budget(&f.archive, 1, 0);
        assert!(!view.history_complete());
        assert!(!view.owner_history_complete(f.owner));
        assert!(!view.owner(f.owner).unwrap().incomplete());
        assert_eq!(view.owner(f.owner).unwrap().head(), Some(revoke.id()));
        assert!(view.control_admitted(seal.id()) && view.control_admitted(revoke.id()));
        assert_eq!(view.storage_owner(&post), Some(f.owner));
        assert!(!view.agent(f.agent).unwrap().active());
    }

    #[test]
    fn original_author_and_writer_grant_boundaries_survive_same_owner_key_reuse() {
        let mut f = Fixture::new(Rights::ALL);
        let original = social(f.actor(), 0, None, post("original agent"), &f.agent_key);
        put(&mut f.archive, &original);
        // Even reusing the same application key gives a distinct jointly signed
        // incarnation. Possession of that key does not authorize the new actor
        // to revise records attributed to the older incarnation.
        let genesis = sign(
            Body::AgentGenesis {
                owner: f.owner,
                control: f.grant,
                key: f.agent_key.verifying_key().to_bytes(),
                nonce: [44; 32],
            },
            &f.controller,
            Some(&f.agent_key),
        );
        put(&mut f.archive, &genesis);
        let new_agent = agent_id(genesis.id());
        assert_ne!(new_agent, f.agent);
        let grant = control(
            f.owner,
            f.grant,
            ControlAction::Grant {
                agent: new_agent,
                realm: REALM,
                rights: Rights::ALL,
                expires_at: 200,
                nonce: [45; 32],
            },
            &f.controller,
            None,
        );
        put(&mut f.archive, &grant);
        let actor = Actor::Agent {
            owner: f.owner,
            agent: new_agent,
            grant: grant.id(),
        };
        let revise = social(
            actor,
            0,
            None,
            Operation::Revise {
                post: original.id(),
                text: Text::new("stolen authorship").unwrap(),
                supersedes: refs(&[original.id()]),
            },
            &f.agent_key,
        );
        let wrong_chain = social(
            actor,
            1,
            Some(original.id()),
            post("cross-incarnation predecessor"),
            &f.agent_key,
        );
        put(&mut f.archive, &revise);
        put(&mut f.archive, &wrong_chain);
        let owner_actor = Actor::Owner {
            owner: f.owner,
            control: grant.id(),
        };
        let owner_revision = social(
            owner_actor,
            0,
            None,
            Operation::Revise {
                post: original.id(),
                text: Text::new("explicit owner revision").unwrap(),
                supersedes: refs(&[original.id()]),
            },
            &f.controller,
        );
        put(&mut f.archive, &owner_revision);
        let owner_profile = social(
            owner_actor,
            1,
            Some(owner_revision.id()),
            Operation::OwnerProfile {
                text: Text::new("owner profile").unwrap(),
                supersedes: refs(&[]),
            },
            &f.controller,
        );
        put(&mut f.archive, &owner_profile);
        let view = ControlView::new(&f.archive, 1);
        assert_eq!(view.social_status(revise.id()), SocialStatus::Rejected);
        assert_eq!(view.social_status(wrong_chain.id()), SocialStatus::Rejected);
        assert_eq!(
            view.social_status(owner_revision.id()),
            SocialStatus::Provisional
        );
        assert_eq!(
            view.social_status(owner_profile.id()),
            SocialStatus::Provisional
        );
    }

    #[test]
    fn retirement_is_terminal_and_forged_grant_scope_cannot_change_owner_affiliation() {
        let mut f = Fixture::new(Rights::ALL);
        let retire = control(
            f.owner,
            f.grant,
            ControlAction::Retire {
                agent: f.agent,
                realm: REALM,
                accepted: refs(&[]),
            },
            &f.controller,
            None,
        );
        put(&mut f.archive, &retire);
        let invalid = control(
            f.owner,
            retire.id(),
            ControlAction::Grant {
                agent: f.agent,
                realm: REALM,
                rights: Rights::ALL,
                expires_at: u64::MAX,
                nonce: [55; 32],
            },
            &f.controller,
            None,
        );
        put(&mut f.archive, &invalid);
        let next = key(6);
        let rotate = control(
            f.owner,
            retire.id(),
            ControlAction::Rotate {
                new_key: next.verifying_key().to_bytes(),
            },
            &f.controller,
            Some(&next),
        );
        put(&mut f.archive, &rotate);
        let root = sign(
            Body::OwnerGenesis {
                controller: key(7).verifying_key().to_bytes(),
                recovery: None,
                nonce: [7; 32],
            },
            &key(7),
            None,
        );
        put(&mut f.archive, &root);
        let other_owner = owner_id(root.id());
        let bound = sign(
            Body::AgentGenesis {
                owner: other_owner,
                control: root.id(),
                key: f.agent_key.verifying_key().to_bytes(),
                nonce: [2; 32],
            },
            &key(7),
            Some(&f.agent_key),
        );
        put(&mut f.archive, &bound);
        let other_grant = control(
            other_owner,
            root.id(),
            ControlAction::Grant {
                agent: agent_id(bound.id()),
                realm: REALM,
                rights: Rights::ALL,
                expires_at: 200,
                nonce: [3; 32],
            },
            &key(7),
            None,
        );
        put(&mut f.archive, &other_grant);
        let forged = social(
            Actor::Agent {
                owner: f.owner,
                agent: agent_id(bound.id()),
                grant: other_grant.id(),
            },
            0,
            None,
            post("wrong owner"),
            &f.agent_key,
        );
        put(&mut f.archive, &forged);
        let view = ControlView::new(&f.archive, 1);
        assert!(!view.owner(f.owner).unwrap().frozen());
        assert_eq!(view.owner(f.owner).unwrap().head(), Some(rotate.id()));
        assert!(!view.control_admitted(invalid.id()));
        assert!(view.agent(f.agent).unwrap().retired());
        assert!(!view.agent(f.agent).unwrap().active());
        assert_eq!(
            view.agent(agent_id(bound.id())).unwrap().owner(),
            other_owner
        );
        assert_eq!(view.social_status(forged.id()), SocialStatus::Rejected);
        assert_eq!(view.storage_owner(&forged), None);
    }

    /// Delivery order, duplicates and evaluation time are drawn while the
    /// replica archive is replayed, matching the proptest original's
    /// `vec(0usize..6, 0..18)` command sequence in interleaved style.
    #[hegel::test(test_cases = 24)]
    fn signed_delivery_permutations_duplicates_and_expiry_preserve_committed_history(
        tc: TestCase,
    ) {
        let mut f = Fixture::new(Rights::ALL);
        let post = social(f.actor(), 0, None, post("stable exact history"), &f.agent_key);
        let seal = f.seal(f.grant, &[post.id()]);
        let retire = control(f.owner, seal.id(), ControlAction::Retire { agent: f.agent, realm: REALM, accepted: refs(&[]) }, &f.controller, None);
        f.records.extend([post.clone(), seal, retire]);
        let mut replica = Archive::new(REALM, limits()).unwrap();
        let steps = tc.draw(gs::integers::<usize>().max_value(17));
        for _ in 0..steps {
            let index = tc.draw(gs::integers::<usize>().max_value(5));
            put(&mut replica, &f.records[index]);
        }
        for record in &f.records {
            put(&mut replica, record);
        }
        let now = tc.draw(gs::integers::<u64>().max_value(199));
        let view = ControlView::new(&replica, now);
        assert!(view.history_complete());
        assert!(!view.owner(f.owner).unwrap().frozen());
        assert_eq!(view.social_status(post.id()), SocialStatus::Committed);
        assert!(!view.agent(f.agent).unwrap().active());
        assert_eq!(view.accepted_ids().collect::<Vec<_>>(), vec![post.id()]);
    }
}
