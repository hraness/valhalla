//! Sequential room-directory state over verified wire records.
//!
//! `Registry` is the deterministic application state a consensus-ordered
//! history applies: room-control chains and creation authority through
//! [`crate::authority::RoomAuthority`], mature awards through
//! [`crate::awards::assess_support`], and the slug, slot, charge, credit and
//! rate-limit rules of the shared public directory. It owns no journal,
//! consensus engine or transport; callers supply the agreed order, the agreed
//! clock and a borrowed social view, and must durably commit before
//! acknowledging any decision.
use alloc::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    vec::Vec,
};
use sha2::{Digest, Sha256};
use vhalla_core::RealmId;
use vhalla_social::{control::ControlView, OwnerId, RecordId};

use crate::authority::{Denial, RoomAuthority};
use crate::awards::{assess_support, SupportAward};
use crate::model::*;
use crate::wire::VerifiedRecord;

/// Maximum finalized rooms, including archived tombstones.
pub const MAX_ROOMS: usize = 4096;
/// Maximum owners holding accounts.
pub const MAX_OWNERS: usize = 256;
/// Maximum retained support dedup entries.
pub const MAX_SUPPORT: usize = 8192;
/// Largest bounded search page.
pub const MAX_PAGE: usize = 64;
/// Maximum distinct search terms.
pub const MAX_TERMS: usize = 8;
/// Maximum query bytes.
pub const MAX_QUERY: usize = 128;

/// Candidate directory policy. Constants are admitted inputs, not calibrated
/// product economics; the pinned genesis binds the exact commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectoryPolicy {
    /// Marginal price base; slot `n` costs `base_cost * n²`.
    pub base_cost: u64,
    /// Rolling creation window in seconds.
    pub window_seconds: u64,
    /// Maximum creations per owner inside one window.
    pub max_in_window: u16,
    /// Support-award epoch length in seconds.
    pub support_epoch_seconds: u64,
    /// Lifetime finalized slots per owner.
    pub max_lifetime_rooms: u32,
}
impl DirectoryPolicy {
    /// Exact policy commitment that creation intents must name.
    #[must_use]
    pub fn id(&self) -> PolicyId {
        let mut hash = Sha256::new();
        hash.update(b"vhalla/rooms/directory-policy/v1\0");
        hash.update(self.base_cost.to_be_bytes());
        hash.update(self.window_seconds.to_be_bytes());
        hash.update(self.max_in_window.to_be_bytes());
        hash.update(self.support_epoch_seconds.to_be_bytes());
        hash.update(self.max_lifetime_rooms.to_be_bytes());
        PolicyId::from_bytes(hash.finalize().into())
    }
    /// Marginal price of one-based slot `n`; arithmetic overflow denies.
    pub fn cost(&self, slot: u32) -> Result<u64, RegistryError> {
        if slot == 0 || slot > self.max_lifetime_rooms {
            return Err(RegistryError::Slot);
        }
        self.base_cost
            .checked_mul(u64::from(slot))
            .and_then(|v| v.checked_mul(u64::from(slot)))
            .ok_or(RegistryError::Cost)
    }
    fn validate(&self) -> Result<(), RegistryError> {
        if self.base_cost == 0
            || self.window_seconds == 0
            || self.max_in_window == 0
            || usize::from(self.max_in_window) > MAX_ROOMS
            || self.support_epoch_seconds == 0
            || self.max_lifetime_rooms == 0
            || self.max_lifetime_rooms > MAX_ROOMS as u32
        {
            return Err(RegistryError::Bounds);
        }
        self.cost(self.max_lifetime_rooms)?;
        Ok(())
    }
}

/// One owner's allowance ledger and slot usage.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Account {
    /// Credits earned through finalized mature awards.
    pub earned: u64,
    /// Credits spent on finalized rooms, including archived ones.
    pub spent: u64,
    /// Ever-finalized one-based slot count; archiving never resets it.
    pub lifetime_slots: u32,
}

/// A finalized room: retained signed intent plus its current revision state.
#[derive(Clone, Debug)]
pub struct Room {
    genesis: RoomGenesisId,
    intent: CreationIntent,
    description: Description,
    head: RoomRecordId,
    created_at: u64,
    archived: bool,
}
impl Room {
    /// Full immutable genesis commitment, never a routing handle.
    #[must_use]
    pub const fn genesis(&self) -> RoomGenesisId {
        self.genesis
    }
    /// The exact intent that created this room; claims are not re-authenticated.
    #[must_use]
    pub const fn intent(&self) -> &CreationIntent {
        &self.intent
    }
    /// Current description after admitted updates.
    #[must_use]
    pub const fn description(&self) -> &Description {
        &self.description
    }
    /// Latest record in this room's update chain.
    #[must_use]
    pub const fn head(&self) -> RoomRecordId {
        self.head
    }
    /// Directory-agreed creation time.
    #[must_use]
    pub const fn created_at(&self) -> u64 {
        self.created_at
    }
    /// Tombstone: hidden from default discovery but slug and charge retained.
    #[must_use]
    pub const fn archived(&self) -> bool {
        self.archived
    }
    /// The durable owner's immutable identity.
    #[must_use]
    pub fn owner(&self) -> OwnerId {
        self.intent.owner
    }
    /// Canonical slug; archived rooms keep their allocation.
    #[must_use]
    pub fn slug(&self) -> &Slug {
        &self.intent.slug
    }
}

/// What one applied record changed. `Existing`/`DuplicateAward` are exact
/// retry and dedup no-ops, not new effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Applied {
    /// A room-control record extended its owner's agreed chain.
    Control,
    /// A new room was finalized.
    Created(RoomGenesisId),
    /// An exact retry of an already finalized creation.
    Existing(RoomGenesisId),
    /// A room update was applied to its revision chain.
    Updated(RoomRecordId),
    /// A new mature award credited its beneficiary.
    Awarded,
    /// Already-counted evidence or an exhausted dedup slot; no new credit.
    DuplicateAward,
}

/// Closed registry failures. Authority and award denials carry through
/// unmodified; the registry adds only allocation, accounting and revision
/// failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryError {
    /// A bound or capacity ceiling was exceeded.
    Bounds,
    /// Authority assessment denied the record.
    Authority(Denial),
    /// Award assessment denied the evidence.
    Award(crate::awards::AwardDenial),
    /// The intent names a different directory policy.
    WrongPolicy,
    /// The slug is already finalized, including by an archived tombstone.
    Taken,
    /// The claimed slot is not the owner's next ever-finalized slot.
    Slot,
    /// The charge does not equal the policy quote for that slot.
    Cost,
    /// Spent plus charge exceeds the owner's earned allowance.
    InsufficientCredit,
    /// The owner's rolling creation window is full.
    RateLimit,
    /// No room carries the named genesis.
    Missing,
    /// The update's claimed owner does not own the room.
    OwnerMismatch,
    /// The update's predecessor is not the room's current revision.
    StaleRevision,
    /// The room is archived; no further updates are admitted.
    Archived,
    /// A retained bound (`MAX_ROOMS`, `MAX_OWNERS`, `MAX_SUPPORT`) is full.
    Capacity,
    /// The supplied clock moved backwards.
    Clock,
}

/// The deterministic directory state. Applying the same verified records in
/// the same agreed order under the same borrowed view yields the same state.
pub struct Registry {
    directory: DirectoryId,
    realm: RealmId,
    policy: DirectoryPolicy,
    authority: RoomAuthority,
    eligible: BTreeSet<OwnerId>,
    support: BTreeSet<(OwnerId, OwnerId, u64)>,
    evidence: BTreeMap<RecordId, SupportAward>,
    accounts: BTreeMap<OwnerId, Account>,
    windows: BTreeMap<OwnerId, VecDeque<u64>>,
    rooms: BTreeMap<Slug, Room>,
    by_genesis: BTreeMap<RoomGenesisId, Slug>,
    last_time: u64,
    revision: u64,
}

impl Registry {
    /// An empty directory pinned to one identity, realm, policy and eligible
    /// source set. Eligibility is an explicit admitted input, not a claim.
    pub fn new(
        directory: DirectoryId,
        realm: RealmId,
        policy: DirectoryPolicy,
        eligible: &[OwnerId],
    ) -> Result<Self, RegistryError> {
        policy.validate()?;
        if eligible.len() > MAX_OWNERS {
            return Err(RegistryError::Capacity);
        }
        let eligible: BTreeSet<_> = eligible.iter().copied().collect();
        Ok(Self {
            directory,
            realm,
            policy,
            authority: RoomAuthority::new(directory, realm),
            eligible,
            support: BTreeSet::new(),
            evidence: BTreeMap::new(),
            accounts: BTreeMap::new(),
            windows: BTreeMap::new(),
            rooms: BTreeMap::new(),
            by_genesis: BTreeMap::new(),
            last_time: 0,
            revision: 0,
        })
    }
    /// The pinned directory identity.
    #[must_use]
    pub const fn directory(&self) -> DirectoryId {
        self.directory
    }
    /// The pinned realm.
    #[must_use]
    pub const fn realm(&self) -> RealmId {
        self.realm
    }
    /// The admitted policy; `policy.id()` is the commitment intents must name.
    #[must_use]
    pub const fn policy(&self) -> &DirectoryPolicy {
        &self.policy
    }
    /// The agreed room-control ledger.
    #[must_use]
    pub const fn authority(&self) -> &RoomAuthority {
        &self.authority
    }
    /// One owner's allowance ledger; absent owners read as empty.
    #[must_use]
    pub fn account(&self, owner: OwnerId) -> Account {
        self.accounts.get(&owner).copied().unwrap_or_default()
    }
    /// A finalized room by canonical slug, including tombstones.
    #[must_use]
    pub fn room(&self, slug: &Slug) -> Option<&Room> {
        self.rooms.get(slug)
    }
    /// A finalized room by full genesis commitment.
    #[must_use]
    pub fn room_by_genesis(&self, genesis: RoomGenesisId) -> Option<&Room> {
        self.by_genesis
            .get(&genesis)
            .and_then(|slug| self.rooms.get(slug))
    }
    /// Monotonic agreed-clock high-water mark.
    #[must_use]
    pub const fn last_time(&self) -> u64 {
        self.last_time
    }
    /// Total applied state transitions.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// The `(slot, cost)` quote for an owner's next room under this policy.
    pub fn quote(&self, owner: OwnerId) -> Result<(u32, u64), RegistryError> {
        let slot = self
            .account(owner)
            .lifetime_slots
            .checked_add(1)
            .ok_or(RegistryError::Slot)?;
        Ok((slot, self.policy.cost(slot)?))
    }

    /// Apply one verified room record in the agreed order at the agreed clock.
    /// `now` is the directory's consensus time, never a caller's local clock.
    pub fn apply(
        &mut self,
        record: &VerifiedRecord,
        view: &ControlView<'_>,
        now: u64,
    ) -> Result<Applied, RegistryError> {
        if now < self.last_time {
            return Err(RegistryError::Clock);
        }
        let applied = match record.body() {
            Body::Control(_) => {
                self.authority
                    .admit(record, view, now)
                    .map_err(RegistryError::Authority)?;
                Applied::Control
            }
            Body::Create(intent) => self.create(record, intent, view, now)?,
            Body::Update(update) => self.update(record, update, view, now)?,
        };
        self.last_time = now;
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(RegistryError::Capacity)?;
        Ok(applied)
    }

    /// Admit one retained social record as mature-award evidence. `now` is the
    /// directory's agreed clock at this acceptance; the first acceptance pins
    /// the evidence's immutable activity epoch, so later resubmission under a
    /// later epoch cannot earn again.
    pub fn award(
        &mut self,
        record: &vhalla_social::wire::VerifiedRecord,
        view: &ControlView<'_>,
        now: u64,
    ) -> Result<Applied, RegistryError> {
        if now < self.last_time {
            return Err(RegistryError::Clock);
        }
        if let Some(existing) = self.evidence.get(&record.id()) {
            // Evidence identity is immutable; re-deriving under the original
            // acceptance must produce the stored tuple.
            let _ = existing;
            return Ok(Applied::DuplicateAward);
        }
        let award = assess_support(
            record,
            view,
            &self.eligible,
            self.policy.support_epoch_seconds,
            now,
            now,
        )
        .map_err(RegistryError::Award)?;
        let key = (award.beneficiary, award.source_owner, award.activity_epoch);
        if self.support.contains(&key) {
            self.evidence.insert(record.id(), award);
            return Ok(Applied::DuplicateAward);
        }
        if self.support.len() >= MAX_SUPPORT {
            return Err(RegistryError::Capacity);
        }
        if !self.accounts.contains_key(&award.beneficiary) && self.accounts.len() >= MAX_OWNERS {
            return Err(RegistryError::Capacity);
        }
        let mut account = self.account(award.beneficiary);
        account.earned = account.earned.checked_add(1).ok_or(RegistryError::Cost)?;
        self.support.insert(key);
        self.evidence.insert(record.id(), award);
        self.accounts.insert(award.beneficiary, account);
        self.last_time = now;
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(RegistryError::Capacity)?;
        Ok(Applied::Awarded)
    }

    fn create(
        &mut self,
        record: &VerifiedRecord,
        intent: &CreationIntent,
        view: &ControlView<'_>,
        now: u64,
    ) -> Result<Applied, RegistryError> {
        let genesis = record.genesis_id().ok_or(RegistryError::Bounds)?;
        if self.by_genesis.contains_key(&genesis) {
            return Ok(Applied::Existing(genesis));
        }
        if intent.policy != self.policy.id() {
            return Err(RegistryError::WrongPolicy);
        }
        self.authority
            .assess_creation(intent, view, now)
            .map_err(RegistryError::Authority)?;
        if self.rooms.contains_key(&intent.slug) {
            return Err(RegistryError::Taken);
        }
        if self.rooms.len() >= MAX_ROOMS {
            return Err(RegistryError::Capacity);
        }
        let mut account = self.account(intent.owner);
        if !self.accounts.contains_key(&intent.owner) && self.accounts.len() >= MAX_OWNERS {
            return Err(RegistryError::Capacity);
        }
        let slot = account
            .lifetime_slots
            .checked_add(1)
            .ok_or(RegistryError::Slot)?;
        if intent.slot != slot {
            return Err(RegistryError::Slot);
        }
        if intent.charge != self.policy.cost(slot)? {
            return Err(RegistryError::Cost);
        }
        let spent = account
            .spent
            .checked_add(intent.charge)
            .ok_or(RegistryError::Cost)?;
        if spent > account.earned {
            return Err(RegistryError::InsufficientCredit);
        }
        let window = self.windows.entry(intent.owner).or_default();
        while window
            .front()
            .is_some_and(|t| now.saturating_sub(*t) >= self.policy.window_seconds)
        {
            window.pop_front();
        }
        if window.len() >= usize::from(self.policy.max_in_window) {
            return Err(RegistryError::RateLimit);
        }
        account.spent = spent;
        account.lifetime_slots = slot;
        window.push_back(now);
        self.rooms.insert(
            intent.slug.clone(),
            Room {
                genesis,
                intent: intent.clone(),
                description: intent.description.clone(),
                head: record.id(),
                created_at: now,
                archived: false,
            },
        );
        self.by_genesis.insert(genesis, intent.slug.clone());
        self.accounts.insert(intent.owner, account);
        Ok(Applied::Created(genesis))
    }

    fn update(
        &mut self,
        record: &VerifiedRecord,
        update: &RoomUpdate,
        view: &ControlView<'_>,
        now: u64,
    ) -> Result<Applied, RegistryError> {
        self.authority
            .assess_update(update, view, now)
            .map_err(RegistryError::Authority)?;
        let slug = self
            .by_genesis
            .get(&update.genesis)
            .ok_or(RegistryError::Missing)?
            .clone();
        let room = self.rooms.get_mut(&slug).ok_or(RegistryError::Missing)?;
        if room.archived {
            return Err(RegistryError::Archived);
        }
        if room.intent.owner != update.owner {
            return Err(RegistryError::OwnerMismatch);
        }
        if room.head != update.previous {
            return Err(RegistryError::StaleRevision);
        }
        match &update.action {
            UpdateAction::Describe(text) => room.description = text.clone(),
            UpdateAction::Archive => room.archived = true,
        }
        room.head = record.id();
        Ok(Applied::Updated(record.id()))
    }

    /// Bounded literal scan over finalized rooms, never proof a slug is free.
    /// An empty query is the explicit bounded list operation. Terms AND
    /// together with ASCII folding; non-ASCII remains byte-exact. Tombstones
    /// are excluded from results but keep their allocation.
    pub fn search(
        &self,
        query: &str,
        limit: usize,
        budget: usize,
    ) -> Result<Search<'_>, RegistryError> {
        if query.len() > MAX_QUERY || limit == 0 || limit > MAX_PAGE || budget > MAX_ROOMS {
            return Err(RegistryError::Bounds);
        }
        let terms: Vec<_> = query.split_ascii_whitespace().collect();
        if terms.len() > MAX_TERMS || query.chars().any(|c| c.is_control() && c != ' ') {
            return Err(RegistryError::Bounds);
        }
        let mut result = Search {
            rooms: Vec::new(),
            examined: 0,
            retained: self.rooms.len(),
            partial: false,
            revision: self.revision,
        };
        for room in self.rooms.values() {
            if result.examined == budget || result.rooms.len() == limit {
                result.partial = true;
                break;
            }
            result.examined += 1;
            if !room.archived
                && terms.iter().all(|term| {
                    contains(room.slug().as_str(), term)
                        || contains(room.description.as_str(), term)
                })
            {
                result.rooms.push(room);
            }
        }
        Ok(result)
    }
}

/// One bounded search page over the finalized directory.
#[derive(Debug)]
pub struct Search<'a> {
    /// Matching non-archived rooms, up to `limit`.
    pub rooms: Vec<&'a Room>,
    /// Rooms examined before the budget or limit stopped the scan.
    pub examined: usize,
    /// Total finalized rooms including tombstones.
    pub retained: usize,
    /// True when the budget or limit cut the scan short.
    pub partial: bool,
    /// Directory revision at scan time.
    pub revision: u64,
}

fn contains(text: &str, term: &str) -> bool {
    !term.is_empty()
        && text
            .as_bytes()
            .windows(term.len())
            .any(|s| s.eq_ignore_ascii_case(term.as_bytes()))
}
