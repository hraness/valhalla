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

use crate::authority::{Denial, RoomAuthority, MAX_CONTROL_RECORDS};
use crate::awards::{assess_support, SupportAward};
use crate::model::*;
use crate::wire::VerifiedRecord;

/// Maximum finalized rooms, including archived tombstones.
pub const MAX_ROOMS: usize = 4096;
/// Maximum owners holding accounts.
pub const MAX_OWNERS: usize = 256;
/// Maximum retained support dedup entries.
pub const MAX_SUPPORT: usize = 8192;
// Every `evidence` entry derives from a record `assess_support` saw Committed
// in a bounded archive, so live evidence can never exceed the archive's own
// record bound; keep it strictly under the snapshot restore bound.
const _: () = assert!(vhalla_social::MAX_RECORDS <= MAX_SUPPORT);
/// Maximum retained revision records per room.
pub const MAX_REVISIONS: usize = 256;
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
    /// Rejects a policy whose bounds or slot arithmetic cannot hold —
    /// exposed so config scaffolding can refuse an invalid shared file
    /// before it reaches a node.
    pub fn validate(&self) -> Result<(), RegistryError> {
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
/// The verified create and update records are kept in order — they are the
/// room's durable manifest and the source proofs a caller can retrieve.
#[derive(Clone, Debug)]
pub struct Room {
    genesis: RoomGenesisId,
    intent: CreationIntent,
    description: Description,
    head: RoomRecordId,
    created_at: u64,
    archived: bool,
    record: VerifiedRecord,
    revisions: Vec<VerifiedRecord>,
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
    /// The verified creation record; the room's root source proof.
    #[must_use]
    pub const fn record(&self) -> &VerifiedRecord {
        &self.record
    }
    /// The verified revision records in chain order.
    #[must_use]
    pub fn revisions(&self) -> &[VerifiedRecord] {
        &self.revisions
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

/// One mature award plus its retained verified evidence record — the
/// registry's source proof for the credit it wrote.
#[derive(Clone, Debug)]
struct Evidence {
    award: SupportAward,
    record: vhalla_social::wire::VerifiedRecord,
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
    /// A durable snapshot failed integrity, bounds or internal-order checks.
    Corrupt,
}

/// The deterministic directory state. Applying the same verified records in
/// the same agreed order under the same borrowed view yields the same state.
#[derive(Clone)]
pub struct Registry {
    directory: DirectoryId,
    realm: RealmId,
    policy: DirectoryPolicy,
    authority: RoomAuthority,
    eligible: BTreeSet<OwnerId>,
    support: BTreeSet<(OwnerId, OwnerId, u64)>,
    evidence: BTreeMap<RecordId, Evidence>,
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
    /// The admitted eligible award-source set.
    #[must_use]
    pub fn eligible(&self) -> &BTreeSet<OwnerId> {
        &self.eligible
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
        // Retention — not only new dedup triples — must respect the snapshot
        // restore bound: a live state with more evidence than MAX_SUPPORT
        // could never be restored. Unreachable while committed records stay
        // bounded by MAX_RECORDS, but fail closed if that ever changes.
        if self.evidence.len() >= MAX_SUPPORT {
            return Err(RegistryError::Capacity);
        }
        let key = (award.beneficiary, award.source_owner, award.activity_epoch);
        if self.support.contains(&key) {
            self.evidence.insert(
                record.id(),
                Evidence {
                    award,
                    record: record.clone(),
                },
            );
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
        self.evidence.insert(
            record.id(),
            Evidence {
                award,
                record: record.clone(),
            },
        );
        self.accounts.insert(award.beneficiary, account);
        self.last_time = now;
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(RegistryError::Capacity)?;
        Ok(Applied::Awarded)
    }

    /// Replace the eligible award-source set — a committed configuration
    /// transition under the agreed clock, bounded like the genesis set. The
    /// set lives inside `snapshot`/`digest`, so the transition commits and
    /// replays identically on every validator.
    pub fn set_eligible(&mut self, eligible: &[OwnerId], now: u64) -> Result<(), RegistryError> {
        if now < self.last_time {
            return Err(RegistryError::Clock);
        }
        if eligible.len() > MAX_OWNERS {
            return Err(RegistryError::Capacity);
        }
        self.eligible = eligible.iter().copied().collect();
        self.last_time = now;
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(RegistryError::Capacity)?;
        Ok(())
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
                record: record.clone(),
                revisions: Vec::new(),
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
        if room.revisions.len() >= MAX_REVISIONS {
            return Err(RegistryError::Capacity);
        }
        match &update.action {
            UpdateAction::Describe(text) => room.description = text.clone(),
            UpdateAction::Archive => room.archived = true,
        }
        room.head = record.id();
        room.revisions.push(record.clone());
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

    /// Canonical signed bytes backing one applied room record: a control
    /// record, a creation or a revision exactly as admitted. This is the
    /// caller's source proof for a committed state transition.
    #[must_use]
    pub fn source_proof(&self, id: RoomRecordId) -> Option<Vec<u8>> {
        for (_, history) in self.authority.histories() {
            if let Some(record) = history.iter().find(|r| r.id() == id) {
                return Some(record.encode());
            }
        }
        for room in self.rooms.values() {
            if room.record.id() == id {
                return Some(room.record.encode());
            }
            if let Some(record) = room.revisions.iter().find(|r| r.id() == id) {
                return Some(record.encode());
            }
        }
        None
    }

    /// Canonical signed bytes backing one mature-award evidence record.
    #[must_use]
    pub fn evidence_proof(&self, id: RecordId) -> Option<Vec<u8>> {
        self.evidence.get(&id).map(|e| e.record.encode())
    }

    /// Canonical snapshot of the complete registry state: every admitted
    /// record, derived ledger and retained bound. Snapshots are trusted
    /// local state — they carry integrity checks but no live authority
    /// re-assessment, so restore trusts the durable layer's privacy.
    #[must_use]
    pub fn snapshot(&self) -> Vec<u8> {
        let mut out = Out::new();
        out.bytes(self.directory.as_bytes());
        out.bytes(&self.realm.0.to_be_bytes());
        out.u64(self.policy.base_cost);
        out.u64(self.policy.window_seconds);
        out.u16(self.policy.max_in_window);
        out.u64(self.policy.support_epoch_seconds);
        out.u32(self.policy.max_lifetime_rooms);
        out.u64(self.last_time);
        out.u64(self.revision);
        out.u32(self.eligible.len() as u32);
        for owner in &self.eligible {
            out.bytes(owner.as_bytes());
        }
        let chains: Vec<_> = self.authority.histories().collect();
        out.u32(chains.len() as u32);
        for (owner, history) in &chains {
            out.bytes(owner.as_bytes());
            out.u32(history.len() as u32);
            for record in *history {
                out.bytes_len(&record.encode());
            }
        }
        out.u32(self.rooms.len() as u32);
        for room in self.rooms.values() {
            out.bytes_len(&room.record.encode());
            out.u64(room.created_at);
            out.u32(room.revisions.len() as u32);
            for revision in &room.revisions {
                out.bytes_len(&revision.encode());
            }
        }
        out.u32(self.accounts.len() as u32);
        for (owner, account) in &self.accounts {
            out.bytes(owner.as_bytes());
            out.u64(account.earned);
            out.u64(account.spent);
            out.u32(account.lifetime_slots);
        }
        out.u32(self.windows.len() as u32);
        for (owner, window) in &self.windows {
            out.bytes(owner.as_bytes());
            out.u32(window.len() as u32);
            for time in window {
                out.u64(*time);
            }
        }
        out.u32(self.evidence.len() as u32);
        for evidence in self.evidence.values() {
            out.bytes(evidence.award.source_owner.as_bytes());
            out.bytes(evidence.award.beneficiary.as_bytes());
            out.u64(evidence.award.activity_epoch);
            out.bytes_len(&evidence.record.encode());
        }
        let mut framed = Vec::with_capacity(out.0.len() + 40);
        framed.extend_from_slice(SNAPSHOT_MAGIC);
        framed.extend_from_slice(&out.0);
        framed.extend_from_slice(&checksum(&out.0));
        framed
    }

    /// Semantic digest of the complete registry state — the snapshot payload
    /// checksum. A store pin binds this; any state change changes it.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let snapshot = self.snapshot();
        let raw: &[u8] = &snapshot[SNAPSHOT_MAGIC.len()..snapshot.len() - 32];
        checksum(raw)
    }

    /// Restore a registry from `snapshot()` bytes. Signatures are re-verified
    /// and internal order re-checked; live authority assessment is not re-run
    /// — it was evaluated when each record entered the agreed log.
    pub fn restore(raw: &[u8]) -> Result<Self, RegistryError> {
        if raw.len() < SNAPSHOT_MAGIC.len() + 32
            || raw.len() > MAX_SNAPSHOT_BYTES
            || raw.get(..SNAPSHOT_MAGIC.len()) != Some(SNAPSHOT_MAGIC.as_slice())
        {
            return Err(RegistryError::Corrupt);
        }
        let body = &raw[SNAPSHOT_MAGIC.len()..raw.len() - 32];
        if checksum(body) != raw[raw.len() - 32..] {
            return Err(RegistryError::Corrupt);
        }
        let mut in_ = In::new(body);
        let directory = DirectoryId::from_bytes(in_.array()?);
        let realm = RealmId(u128::from_be_bytes(in_.array()?));
        let policy = DirectoryPolicy {
            base_cost: in_.u64()?,
            window_seconds: in_.u64()?,
            max_in_window: in_.u16()?,
            support_epoch_seconds: in_.u64()?,
            max_lifetime_rooms: in_.u32()?,
        };
        let last_time = in_.u64()?;
        let revision = in_.u64()?;
        policy.validate()?;
        let eligible: Vec<OwnerId> = (0..in_.count(MAX_OWNERS)?)
            .map(|_| in_.array().map(OwnerId::from_bytes))
            .collect::<Result<_, _>>()?;
        let mut registry = Self::new(directory, realm, policy, &eligible)?;
        registry.last_time = last_time;
        registry.revision = revision;
        for _ in 0..in_.count(MAX_CONTROL_OWNERS)? {
            let owner = OwnerId::from_bytes(in_.array()?);
            for _ in 0..in_.count(MAX_CONTROL_RECORDS)? {
                let record = in_
                    .record(MAX_RECORD_BYTES)?
                    .verify()
                    .map_err(|_| RegistryError::Corrupt)?;
                match record.body() {
                    Body::Control(control) if control.owner == owner => {}
                    _ => return Err(RegistryError::Corrupt),
                }
                registry
                    .authority
                    .restore_record(&record)
                    .map_err(|_| RegistryError::Corrupt)?;
            }
        }
        for _ in 0..in_.count(MAX_ROOMS)? {
            let record = in_
                .record(MAX_RECORD_BYTES)?
                .verify()
                .map_err(|_| RegistryError::Corrupt)?;
            let genesis = record.genesis_id().ok_or(RegistryError::Corrupt)?;
            let Body::Create(intent) = record.body() else {
                return Err(RegistryError::Corrupt);
            };
            if intent.directory != directory || intent.realm != realm {
                return Err(RegistryError::Corrupt);
            }
            let created_at = in_.u64()?;
            let mut room = Room {
                genesis,
                intent: intent.clone(),
                description: intent.description.clone(),
                head: record.id(),
                created_at,
                archived: false,
                record,
                revisions: Vec::new(),
            };
            let slug = room.intent.slug.clone();
            for _ in 0..in_.count(MAX_REVISIONS)? {
                let revision_record = in_
                    .record(MAX_RECORD_BYTES)?
                    .verify()
                    .map_err(|_| RegistryError::Corrupt)?;
                let Body::Update(update) = revision_record.body() else {
                    return Err(RegistryError::Corrupt);
                };
                if update.genesis != genesis
                    || update.previous != room.head
                    || update.directory != directory
                    || update.realm != realm
                {
                    return Err(RegistryError::Corrupt);
                }
                match &update.action {
                    UpdateAction::Describe(text) => room.description = text.clone(),
                    UpdateAction::Archive => room.archived = true,
                }
                room.head = revision_record.id();
                room.revisions.push(revision_record);
            }
            registry.by_genesis.insert(genesis, slug.clone());
            registry.rooms.insert(slug, room);
        }
        for _ in 0..in_.count(MAX_OWNERS)? {
            let owner = OwnerId::from_bytes(in_.array()?);
            registry.accounts.insert(
                owner,
                Account {
                    earned: in_.u64()?,
                    spent: in_.u64()?,
                    lifetime_slots: in_.u32()?,
                },
            );
        }
        for _ in 0..in_.count(MAX_OWNERS)? {
            let owner = OwnerId::from_bytes(in_.array()?);
            let times = (0..in_.count(usize::from(policy.max_in_window))?)
                .map(|_| in_.u64())
                .collect::<Result<_, _>>()?;
            registry.windows.insert(owner, times);
        }
        for _ in 0..in_.count(MAX_SUPPORT)? {
            let award = SupportAward {
                source_owner: OwnerId::from_bytes(in_.array()?),
                beneficiary: OwnerId::from_bytes(in_.array()?),
                activity_epoch: in_.u64()?,
                evidence_id: RecordId::from_bytes([0; 32]),
            };
            let record = in_
                .social_record()?
                .verify()
                .map_err(|_| RegistryError::Corrupt)?;
            let award = SupportAward {
                evidence_id: record.id(),
                ..award
            };
            registry
                .support
                .insert((award.beneficiary, award.source_owner, award.activity_epoch));
            registry
                .evidence
                .insert(record.id(), Evidence { award, record });
        }
        if !in_.done() {
            return Err(RegistryError::Corrupt);
        }
        Ok(registry)
    }
}

const SNAPSHOT_MAGIC: &[u8; 8] = b"VRSN\0\0\0\x01";
/// Snapshot byte ceiling: the private-store payload bound.
pub const MAX_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
/// Bound on distinct owners holding room-control chains in one snapshot.
const MAX_CONTROL_OWNERS: usize = MAX_OWNERS;

fn checksum(payload: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"vhalla/rooms/registry-snapshot/v1\0");
    hash.update(payload);
    hash.finalize().into()
}

/// Bounded canonical writer.
struct Out(Vec<u8>);
impl Out {
    fn new() -> Self {
        Self(Vec::new())
    }
    fn bytes(&mut self, value: &[u8]) {
        self.0.extend_from_slice(value);
    }
    fn bytes_len(&mut self, value: &[u8]) {
        self.u32(value.len() as u32);
        self.bytes(value);
    }
    fn u16(&mut self, value: u16) {
        self.bytes(&value.to_be_bytes());
    }
    fn u32(&mut self, value: u32) {
        self.bytes(&value.to_be_bytes());
    }
    fn u64(&mut self, value: u64) {
        self.bytes(&value.to_be_bytes());
    }
}

/// Bounded canonical reader; every count is checked against a retained bound.
struct In<'a> {
    raw: &'a [u8],
    at: usize,
}
impl<'a> In<'a> {
    fn new(raw: &'a [u8]) -> Self {
        Self { raw, at: 0 }
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8], RegistryError> {
        let out = self
            .raw
            .get(self.at..self.at.saturating_add(len))
            .ok_or(RegistryError::Corrupt)?;
        self.at += len;
        Ok(out)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], RegistryError> {
        self.take(N)?.try_into().map_err(|_| RegistryError::Corrupt)
    }
    fn u16(&mut self) -> Result<u16, RegistryError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, RegistryError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, RegistryError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    /// A count bounded both by a semantic ceiling and the remaining bytes.
    fn count(&mut self, bound: usize) -> Result<usize, RegistryError> {
        let count = self.u32()? as usize;
        if count > bound {
            return Err(RegistryError::Corrupt);
        }
        Ok(count)
    }
    fn record(&mut self, bound: usize) -> Result<crate::SignedRecord, RegistryError> {
        let len = self.u32()? as usize;
        if len > bound {
            return Err(RegistryError::Corrupt);
        }
        crate::SignedRecord::decode(self.take(len)?).map_err(|_| RegistryError::Corrupt)
    }
    fn social_record(&mut self) -> Result<vhalla_social::SignedRecord, RegistryError> {
        let len = self.u32()? as usize;
        if len > vhalla_social::MAX_RECORD_BYTES {
            return Err(RegistryError::Corrupt);
        }
        vhalla_social::SignedRecord::decode(self.take(len)?).map_err(|_| RegistryError::Corrupt)
    }
    fn done(&self) -> bool {
        self.at == self.raw.len()
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
