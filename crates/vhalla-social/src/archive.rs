//! Bounded signed evidence retention and continuation-based anti-entropy.
//!
//! A retained record is evidence, not current social or host authority. Unknown
//! affiliation consumes a signer-scoped staging quota, never a claimed owner's
//! protected quota. No record is evicted and no tombstone is collected.
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use sha2::{Digest, Sha256};
use vhalla_core::RealmId;

use crate::{
    control::ControlView,
    model::*,
    wire::{SignedRecord, VerifiedRecord},
};

const SNAPSHOT_MAGIC: &[u8; 8] = b"VHSA\0\0\0\x01";
const SNAPSHOT_HEADER: usize = 28;
/// Hard snapshot byte ceiling, checked before any record allocation.
pub const MAX_SNAPSHOT_BYTES: usize = SNAPSHOT_HEADER + MAX_RECORDS * (4 + MAX_RECORD_BYTES);
/// Maximum records in one outgoing synchronization page.
pub const MAX_PAGE_RECORDS: usize = 32;
/// Maximum owner/lane scheduling turns in one page, even when all records are rejected.
pub const MAX_PAGE_TURNS: usize = 256;

/// Local resource policy, supplied by the caller rather than foreign snapshots.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Total retained signed records, at most MAX_RECORDS.
    pub records: usize,
    /// Dedicated admitted-control slots; ordinary data cannot consume these.
    pub control_reserve: usize,
    /// Ordinary data allowance per durable owner, including its identity roots.
    /// Previously staged evidence may use bounded shared overflow after proof arrives.
    pub data_per_owner: usize,
    /// Ordinary data allowance per owner and complete primary signing key.
    pub data_per_writer: usize,
    /// Ordinary control allowance per durable owner; exhaustion closes eligibility.
    pub control_per_owner: usize,
    /// Shared allowance for unaffiliated staging and authenticated overflow evidence.
    pub pending: usize,
    /// Staging slots per complete primary signing key; claimed owners are ignored.
    pub pending_per_signer: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            records: 1024,
            control_reserve: 128,
            data_per_owner: 128,
            data_per_writer: 64,
            control_per_owner: 32,
            pending: 128,
            pending_per_signer: 8,
        }
    }
}
impl Limits {
    fn check(self) -> Result<Self, Error> {
        if self.records == 0
            || self.records > MAX_RECORDS
            || self.control_reserve == 0
            || self.control_reserve >= self.records
            || self.data_per_owner == 0
            || self.data_per_writer == 0
            || self.control_per_owner == 0
            || self.pending == 0
            || self.pending_per_signer == 0
            || self.data_per_owner > self.records
            || self.data_per_writer > self.data_per_owner
            || self.control_per_owner > self.control_reserve
            || self.pending > self.records - self.control_reserve
            || self.pending_per_signer > self.pending
        {
            return Err(Error::Bounds);
        }
        Ok(self)
    }
}

/// Per-call incoming work budget. Each record entails at most two strict signatures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Budget {
    records: usize,
    bytes: usize,
}
impl Budget {
    /// Set bounded verification-attempt and byte allowances.
    pub fn new(records: usize, bytes: usize) -> Result<Self, Error> {
        if records > MAX_RECORDS || bytes > MAX_SNAPSHOT_BYTES {
            return Err(Error::Bounds);
        }
        Ok(Self { records, bytes })
    }
    /// Remaining record-attempt and input-byte allowances.
    #[must_use]
    pub fn remaining(&self) -> (usize, usize) {
        (self.records, self.bytes)
    }
    fn charge(&mut self, bytes: usize) -> Result<(), Error> {
        if self.records == 0 || bytes > self.bytes {
            return Err(Error::Budget);
        }
        self.records -= 1;
        self.bytes -= bytes;
        Ok(())
    }
}

/// Storage accounting only; this is never an operation-admission capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Bucket {
    /// Historically authenticated owner affiliation, without current operation authority.
    Data(OwnerId),
    /// A semantically admitted owner control transition at its exact predecessor.
    Control(OwnerId),
    /// Full historical signer affiliation reserves control storage, not authority.
    ReservedControl(OwnerId),
    /// Unresolved affiliation charged to its actual verified primary key.
    Pending([u8; 32]),
}
/// Deterministic local capacity pressure; it grants no authority.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OwnerPressure {
    /// Affiliated ordinary-data records retained for this owner.
    pub data: usize,
    /// Admitted or source-proved reserved control records for this owner.
    pub controls: usize,
    /// Minimum shared overflow needed for the owner's data and writer allowances.
    pub data_spill: usize,
    /// Shared overflow beyond this owner's ordinary control allowance.
    pub control_spill: usize,
    /// Current eligibility must close under this local bounded policy.
    pub closed: bool,
}
/// Capacity is reconstructed from signed records and supplied limits on every view.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CapacityPressure {
    /// Unaffiliated records charged to their actual primary signer.
    pub pending: usize,
    /// Authenticated data overflow borrowing from the shared staging allowance.
    pub data_spill: usize,
    /// Authenticated control overflow borrowing from the shared staging allowance.
    pub control_spill: usize,
    /// No physical or reserved-control headroom remains for current eligibility.
    pub global_closed: bool,
    /// Only authenticated affiliation can put an owner in this map.
    pub owners: BTreeMap<OwnerId, OwnerPressure>,
}
struct Accounting {
    buckets: BTreeMap<RecordId, Bucket>,
    pressure: CapacityPressure,
    signer_pending: BTreeMap<[u8; 32], usize>,
    data: usize,
}
/// Local ingestion result, deliberately excluded from the logical evidence root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IngestReceipt {
    /// Exact unsigned content identity.
    pub id: RecordId,
    /// False for a valid duplicate, including a different valid proof encoding.
    pub inserted: bool,
    /// Storage accounting class after this successful ingestion.
    pub bucket: Bucket,
    /// Logical root after this operation.
    pub root: EvidenceRoot,
}
/// An archive retains full strict signature evidence within explicit local bounds.
#[derive(Clone, Debug)]
pub struct Archive {
    realm: RealmId,
    limits: Limits,
    records: BTreeMap<RecordId, VerifiedRecord>,
    buckets: BTreeMap<RecordId, Bucket>,
}
impl Archive {
    /// Construct an empty public-realm archive with checked local limits.
    pub fn new(realm: RealmId, limits: Limits) -> Result<Self, Error> {
        Ok(Self {
            realm,
            limits: limits.check()?,
            records: BTreeMap::new(),
            buckets: BTreeMap::new(),
        })
    }
    /// Borrow retained immutable signed facts in canonical ID order.
    pub fn records(&self) -> impl Iterator<Item = &VerifiedRecord> {
        self.records.values()
    }
    /// Borrow one retained signed fact; presence does not imply current eligibility.
    #[must_use]
    pub fn get(&self, id: RecordId) -> Option<&VerifiedRecord> {
        self.records.get(&id)
    }
    /// The public realm for social records. Global control evidence spans realms.
    #[must_use]
    pub fn realm(&self) -> RealmId {
        self.realm
    }
    /// Immutable caller-selected local retention limits.
    #[must_use]
    pub fn limits(&self) -> Limits {
        self.limits
    }
    /// Number of retained records, including staged evidence and controls.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }
    /// Whether this archive retains no signed evidence.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
    /// Current storage class. This is not an authorization or trust decision.
    #[must_use]
    pub fn bucket(&self, id: RecordId) -> Option<Bucket> {
        self.buckets.get(&id).copied()
    }
    /// Logical protocol-version/realm/sorted-ID root, excluding receipt/proof bytes.
    #[must_use]
    pub fn root(&self) -> EvidenceRoot {
        let mut hash = Sha256::new();
        hash.update(b"vhalla/social/archive/evidence/v1\0");
        hash.update(self.realm.0.to_be_bytes());
        hash.update((self.records.len() as u32).to_be_bytes());
        for id in self.records.keys() {
            hash.update(id.as_bytes());
        }
        EvidenceRoot::from_bytes(hash.finalize().into())
    }
    /// Verify bounded foreign bytes before deduplication. Failure leaves evidence unchanged.
    ///
    /// Staging is deliberately finite: callers retry rejected dependencies after
    /// making progress, or report incomplete union/capacity. Fresh keys do not
    /// prove distinct owners and no global Sybil-resistance claim is made.
    pub fn ingest(&mut self, raw: &[u8], budget: &mut Budget) -> Result<IngestReceipt, Error> {
        budget.charge(raw.len())?;
        if raw.len() > MAX_RECORD_BYTES {
            return Err(Error::Bounds);
        }
        let verified = SignedRecord::decode(raw)?.verify()?;
        self.check_realm(&verified)?;
        let id = verified.id();
        if let Some(bucket) = self.bucket(id) {
            return Ok(IngestReceipt {
                id,
                inserted: false,
                bucket,
                root: self.root(),
            });
        }
        if self.len() == self.limits.records {
            return Err(Error::Capacity);
        }
        let mut candidate = self.clone();
        candidate.records.insert(id, verified);
        let pressure = candidate.reclassify()?;
        let bucket = candidate.bucket(id).ok_or(Error::Incomplete)?;
        if let Bucket::Data(owner) = bucket {
            // Overflow preserves evidence when a later control reveals existing
            // staging; it is not an extra per-record publishing allowance.
            if pressure
                .owners
                .get(&owner)
                .is_some_and(|pressure| pressure.data_spill != 0)
            {
                return Err(Error::Capacity);
            }
        }
        let receipt = IngestReceipt {
            id,
            inserted: true,
            bucket,
            root: candidate.root(),
        };
        *self = candidate;
        Ok(receipt)
    }
    fn check_realm(&self, record: &VerifiedRecord) -> Result<(), Error> {
        if matches!(record.body(), Body::Social { realm, .. } if *realm != self.realm) {
            return Err(Error::Context);
        }
        Ok(())
    }
    fn reclassify(&mut self) -> Result<CapacityPressure, Error> {
        if self.len() > self.limits.records {
            return Err(Error::Capacity);
        }
        let controls = ControlView::new(self, 0);
        let accounting = self.accounting(&controls);
        let pressure = &accounting.pressure;
        if accounting.data + pressure.pending + pressure.control_spill
            > self.limits.records - self.limits.control_reserve
            || pressure.pending + pressure.data_spill + pressure.control_spill > self.limits.pending
            || accounting
                .signer_pending
                .values()
                .any(|n| *n > self.limits.pending_per_signer)
        {
            return Err(Error::Capacity);
        }
        self.buckets = accounting.buckets;
        Ok(accounting.pressure)
    }
    /// Inspect bounded local storage pressure. This is not a host capability or
    /// proof of complete network delivery; its limits are local policy.
    #[must_use]
    pub fn capacity(&self) -> CapacityPressure {
        self.capacity_pressure(&ControlView::new(self, 0))
    }
    // The caller is ControlView for this exact borrowed archive. No cached
    // buckets are used while evaluating a newly constructed union candidate.
    pub(crate) fn capacity_pressure(&self, controls: &ControlView<'_>) -> CapacityPressure {
        self.accounting(controls).pressure
    }
    fn accounting(&self, controls: &ControlView<'_>) -> Accounting {
        let mut buckets = BTreeMap::new();
        let mut owner_data = BTreeMap::new();
        let mut writer_data = BTreeMap::new();
        let mut owner_controls = BTreeMap::new();
        let mut signer_pending = BTreeMap::new();
        let (mut data, mut protected, mut pending) = (0usize, 0usize, 0usize);
        for record in self.records() {
            let owner = controls.storage_owner(record);
            let bucket = match (record.body(), owner) {
                (Body::Control { .. }, Some(owner)) => {
                    protected += 1;
                    *owner_controls.entry(owner).or_insert(0usize) += 1;
                    if controls.control_admitted(record.id()) {
                        Bucket::Control(owner)
                    } else {
                        Bucket::ReservedControl(owner)
                    }
                }
                (_, Some(owner)) => {
                    data += 1;
                    *owner_data.entry(owner).or_insert(0usize) += 1;
                    *writer_data
                        .entry((owner, *record.primary_key()))
                        .or_insert(0usize) += 1;
                    Bucket::Data(owner)
                }
                (_, None) => {
                    pending += 1;
                    *signer_pending
                        .entry(*record.primary_key())
                        .or_insert(0usize) += 1;
                    Bucket::Pending(*record.primary_key())
                }
            };
            buckets.insert(record.id(), bucket);
        }
        let mut owners = BTreeMap::<OwnerId, OwnerPressure>::new();
        for (owner, count) in owner_data {
            owners.entry(owner).or_default().data = count;
        }
        for (owner, count) in owner_controls {
            owners.entry(owner).or_default().controls = count;
        }
        for ((owner, _), count) in writer_data {
            owners.entry(owner).or_default().data_spill +=
                count.saturating_sub(self.limits.data_per_writer);
        }
        for pressure in owners.values_mut() {
            pressure.data_spill = pressure
                .data_spill
                .max(pressure.data.saturating_sub(self.limits.data_per_owner));
            pressure.control_spill = pressure
                .controls
                .saturating_sub(self.limits.control_per_owner);
            pressure.closed =
                pressure.controls >= self.limits.control_per_owner || pressure.data_spill != 0;
        }
        let data_spill = owners.values().map(|p| p.data_spill).sum();
        let owner_control_spill: usize = owners.values().map(|p| p.control_spill).sum();
        let control_spill =
            owner_control_spill.max(protected.saturating_sub(self.limits.control_reserve));
        let pressure = CapacityPressure {
            pending,
            data_spill,
            control_spill,
            global_closed: protected >= self.limits.control_reserve
                || self.len() >= self.limits.records,
            owners,
        };
        Accounting {
            buckets,
            pressure,
            signer_pending,
            data,
        }
    }
    /// Encode a canonical full signed archive. No records or local proof bytes are discarded.
    #[must_use]
    pub fn snapshot(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(SNAPSHOT_MAGIC);
        out.extend_from_slice(&self.realm.0.to_be_bytes());
        out.extend_from_slice(&(self.len() as u32).to_be_bytes());
        for record in self.records() {
            let bytes = record.encode();
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(&bytes);
        }
        out
    }
    /// Exact physical snapshot checksum, distinct from the convergent logical root.
    #[must_use]
    pub fn physical_digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"vhalla/social/archive/physical/v1\0");
        hash.update(self.snapshot());
        hash.finalize().into()
    }
    /// Verify a complete bounded canonical snapshot before evaluating dependencies.
    ///
    /// Unlike network ingestion, this does not apply staging quotas to incomplete
    /// prefixes of a complete batch. Final quotas still apply. The caller supplies
    /// realm and limits; snapshot bytes cannot replace them.
    pub fn from_snapshot(realm: RealmId, limits: Limits, raw: &[u8]) -> Result<Self, Error> {
        let mut out = Self::decode_snapshot(realm, limits, raw)?;
        out.reclassify()?;
        Ok(out)
    }
    fn decode_snapshot(realm: RealmId, limits: Limits, raw: &[u8]) -> Result<Self, Error> {
        let mut out = Self::new(realm, limits)?;
        let count = preflight_snapshot(realm, limits, raw)?;
        let mut at = SNAPSHOT_HEADER;
        let mut previous = None;
        for _ in 0..count {
            let length = read_length(raw, &mut at)?;
            let next = at.checked_add(length).ok_or(Error::Bounds)?;
            let record =
                SignedRecord::decode(raw.get(at..next).ok_or(Error::Encoding)?)?.verify()?;
            out.check_realm(&record)?;
            let id = record.id();
            if previous.is_some_and(|old| old >= id) {
                return Err(Error::Encoding);
            }
            previous = Some(id);
            out.records.insert(id, record);
            at = next;
        }
        Ok(out)
    }
    /// Construct an atomic union candidate. Rejection never poisons the retained archive.
    ///
    /// The offered snapshot is independently checked, then all retained IDs are
    /// preserved. A failed union describes that attempt, not a semantic tombstone
    /// or permanent incompleteness of an otherwise complete retained event set.
    pub fn merged_snapshot(&self, raw: &[u8]) -> Result<Self, Error> {
        // Dependencies already retained locally may discharge staging pressure
        // in the offered fragment. Only the complete candidate is classified.
        let incoming = Self::decode_snapshot(self.realm, self.limits, raw)?;
        let mut candidate = self.clone();
        for (id, record) in incoming.records {
            candidate.records.entry(id).or_insert(record);
            if candidate.len() > self.limits.records {
                return Err(Error::Capacity);
            }
        }
        candidate.reclassify()?;
        Ok(candidate)
    }
    /// Check monotonic publication under the same caller-selected local context.
    /// Increasing a disk generation without this subset check can resurrect deletes.
    #[must_use]
    pub fn is_extension_of(&self, previous: &Self) -> bool {
        self.realm == previous.realm
            && self.limits == previous.limits
            && previous
                .records
                .keys()
                .all(|id| self.records.contains_key(id))
    }

    /// Send a bounded page missing from a canonical peer inventory. The rotating
    /// cursor reserves progress for admitted controls and their dependencies even
    /// when a peer repeatedly rejects ordinary data. Static finite inventories
    /// make progress with positive sufficient byte budgets; this is not a proof
    /// of liveness under arbitrary churn, malicious peers, or unavailable storage.
    pub fn next_page(
        &self,
        peer_ids: &[RecordId],
        cursor: &mut SyncCursor,
        max_records: usize,
        max_bytes: usize,
    ) -> Result<SyncPage, Error> {
        if peer_ids.len() > MAX_RECORDS
            || peer_ids.windows(2).any(|w| w[0] >= w[1])
            || max_records == 0
            || max_records > MAX_PAGE_RECORDS
            || max_bytes > MAX_SNAPSHOT_BYTES
        {
            return Err(Error::Bounds);
        }
        let peer: BTreeSet<_> = peer_ids.iter().copied().collect();
        let mut needed = BTreeSet::new();
        for record in self.records() {
            if !peer.contains(&record.id()) {
                needed.extend(
                    dependencies(record.body())
                        .into_iter()
                        .filter(|id| self.records.contains_key(id)),
                );
            }
        }
        let mut groups: BTreeMap<Group, [Vec<RecordId>; 3]> = BTreeMap::new();
        for record in self.records().filter(|r| !peer.contains(&r.id())) {
            let bucket = self.bucket(record.id()).ok_or(Error::Incomplete)?;
            let group = match bucket {
                Bucket::Data(o) | Bucket::Control(o) | Bucket::ReservedControl(o) => {
                    Group::Owner(o)
                }
                Bucket::Pending(key) => Group::Signer(key),
            };
            let lane = if matches!(bucket, Bucket::Control(_) | Bucket::ReservedControl(_)) {
                0
            } else if needed.contains(&record.id()) {
                1
            } else {
                2
            };
            groups.entry(group).or_default()[lane].push(record.id());
        }
        cursor.groups.retain(|key, _| groups.contains_key(key));
        let keys: Vec<_> = groups.keys().copied().collect();
        let mut emitted = BTreeSet::new();
        let mut records = Vec::new();
        let mut bytes = 0;
        // At most every missing record is inspected once in this call. Advances
        // even past an oversize record; that record is still reported as missing.
        let mut visited = BTreeSet::new();
        let mut turns = 0;
        let missing_count: usize = groups
            .values()
            .map(|v| v.iter().map(Vec::len).sum::<usize>())
            .sum();
        while records.len() < max_records && visited.len() < missing_count && turns < MAX_PAGE_TURNS
        {
            turns += 1;
            let Some(group) = next_after(&keys, cursor.last_group) else {
                break;
            };
            cursor.last_group = Some(group);
            let state = cursor.groups.entry(group).or_default();
            let lanes = &groups[&group];
            let mut chosen = None;
            for _ in 0..3 {
                let lane = state.next_lane;
                state.next_lane = (state.next_lane + 1) % 3;
                // O(n) bounded search avoids one blocked lane stopping the others.
                let ids: Vec<_> = lanes[lane]
                    .iter()
                    .copied()
                    .filter(|id| !visited.contains(id))
                    .collect();
                if let Some(id) = next_after(&ids, state.last[lane]) {
                    state.last[lane] = Some(id);
                    chosen = Some(id);
                    break;
                }
            }
            let Some(id) = chosen else {
                // A group exhausted in this page may still have later peers.
                if groups
                    .iter()
                    .all(|(_, lanes)| lanes.iter().flatten().all(|id| visited.contains(id)))
                {
                    break;
                }
                continue;
            };
            visited.insert(id);
            let encoded = self.records[&id].encode();
            if bytes + encoded.len() <= max_bytes {
                bytes += encoded.len();
                records.push(encoded);
                emitted.insert(id);
            }
        }
        Ok(SyncPage {
            root: self.root(),
            records,
            bytes,
            examined: visited.len(),
            remaining: self
                .records
                .keys()
                .filter(|id| !peer.contains(id) && !emitted.contains(id))
                .count(),
        })
    }
}

fn read_length(raw: &[u8], at: &mut usize) -> Result<usize, Error> {
    let end = at.checked_add(4).ok_or(Error::Bounds)?;
    let bytes: [u8; 4] = raw
        .get(*at..end)
        .ok_or(Error::Encoding)?
        .try_into()
        .map_err(|_| Error::Encoding)?;
    *at = end;
    Ok(u32::from_be_bytes(bytes) as usize)
}
fn preflight_snapshot(realm: RealmId, limits: Limits, raw: &[u8]) -> Result<usize, Error> {
    if raw.len() > MAX_SNAPSHOT_BYTES {
        return Err(Error::Bounds);
    }
    if raw.len() < SNAPSHOT_HEADER || raw.get(..8) != Some(SNAPSHOT_MAGIC.as_slice()) {
        return Err(Error::Encoding);
    }
    if raw.get(8..24) != Some(realm.0.to_be_bytes().as_slice()) {
        return Err(Error::Context);
    }
    let mut at = 24;
    let count = read_length(raw, &mut at)?;
    if count > limits.records {
        return Err(Error::Capacity);
    }
    for _ in 0..count {
        let length = read_length(raw, &mut at)?;
        if length > MAX_RECORD_BYTES {
            return Err(Error::Bounds);
        }
        at = at.checked_add(length).ok_or(Error::Bounds)?;
        if at > raw.len() {
            return Err(Error::Encoding);
        }
    }
    if at != raw.len() {
        return Err(Error::Encoding);
    }
    Ok(count)
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Group {
    Owner(OwnerId),
    Signer([u8; 32]),
}
#[derive(Clone, Debug, Default)]
struct GroupCursor {
    next_lane: usize,
    last: [Option<RecordId>; 3],
}
/// A local bounded continuation cursor; it does not confer synchronization trust.
#[derive(Clone, Debug, Default)]
pub struct SyncCursor {
    last_group: Option<Group>,
    groups: BTreeMap<Group, GroupCursor>,
}
/// A bounded outgoing signed-record page and explicit remaining inventory count.
#[derive(Clone, Debug)]
pub struct SyncPage {
    /// Source's logical observed basis; not proof of globally complete coverage.
    pub root: EvidenceRoot,
    /// Complete signed records, checked again by the recipient's ingest boundary.
    pub records: Vec<Vec<u8>>,
    /// Sum of encoded record bytes, excluding transport framing.
    pub bytes: usize,
    /// Records inspected against the byte budget, bounded by MAX_PAGE_TURNS.
    pub examined: usize,
    /// Source records still absent from the supplied peer inventory and this page.
    pub remaining: usize,
}
fn next_after<T: Copy + Ord>(ids: &[T], last: Option<T>) -> Option<T> {
    last.and_then(|last| ids.iter().copied().find(|id| *id > last))
        .or_else(|| ids.first().copied())
}
/// Exact claimed dependencies are hints for bounded delivery, never authentication.
fn dependencies(body: &Body) -> Vec<RecordId> {
    let mut out = Vec::new();
    match body {
        Body::OwnerGenesis { .. } => {}
        Body::AgentGenesis { owner, control, .. } => {
            out.push(RecordId::from_bytes(*owner.as_bytes()));
            out.push(*control);
        }
        Body::Control {
            owner,
            previous,
            action,
        } => {
            out.push(RecordId::from_bytes(*owner.as_bytes()));
            out.push(*previous);
            match action {
                ControlAction::Grant { agent, .. } => {
                    out.push(RecordId::from_bytes(*agent.as_bytes()))
                }
                ControlAction::Revoke { grant, accepted } => {
                    out.push(*grant);
                    out.extend(accepted.as_slice());
                }
                ControlAction::Retire {
                    agent, accepted, ..
                } => {
                    out.push(RecordId::from_bytes(*agent.as_bytes()));
                    out.extend(accepted.as_slice());
                }
                ControlAction::Seal { heads, .. } | ControlAction::Ratify { heads, .. } => {
                    out.extend(heads.as_slice())
                }
                ControlAction::Rotate { .. } => {}
            }
        }
        Body::Social {
            actor,
            previous,
            operation,
            ..
        } => {
            out.push(RecordId::from_bytes(*actor.owner().as_bytes()));
            match actor {
                Actor::Owner { control, .. } => out.push(*control),
                Actor::Agent { agent, grant, .. } => {
                    out.push(RecordId::from_bytes(*agent.as_bytes()));
                    out.push(*grant);
                }
            }
            out.extend(previous);
            out.extend(operation.supersedes());
            match operation {
                Operation::Post { reply, quote, .. } => {
                    if let Some(reply) = reply {
                        out.extend([reply.root, reply.parent.post, reply.parent.revision]);
                    }
                    if let Some(quote) = quote {
                        out.extend([quote.post, quote.revision]);
                    }
                }
                Operation::Revise { post, .. } | Operation::Retract { post } => out.push(*post),
                Operation::Repost { post, revision, .. } => {
                    out.push(*post);
                    out.extend(revision);
                }
                Operation::React { post, reaction, .. } => {
                    out.push(*post);
                    match reaction {
                        Reaction::Clear => {}
                        Reaction::Up(id) | Reaction::Down(id) => out.push(*id),
                    }
                }
                Operation::Follow { target, .. } => {
                    out.push(RecordId::from_bytes(*target.as_bytes()))
                }
                Operation::AgentBio { .. } | Operation::OwnerProfile { .. } => {}
            }
        }
    }
    out
}
