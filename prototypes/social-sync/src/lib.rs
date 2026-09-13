//! Disposable full-archive storage/sync model. No production dependencies,
//! sockets, filesystem, monetary balances or host authority.
#![no_std]
#![forbid(unsafe_code)]
extern crate alloc;
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

pub type Id = [u8; 32];
pub type Key = [u8; 32];
pub const MAX_OWNERS: usize = 4;
pub const MAX_WRITERS: usize = 4;
pub const DATA_PER_OWNER: usize = 8;
pub const DATA_PER_WRITER: usize = 4;
pub const CONTROL_PER_OWNER: usize = 4;
pub const PENDING_PER_WRITER: usize = 2;
pub const MAX_REFS: usize = 8;
pub const MAX_EVENT_BYTES: usize = 512;
pub const MAX_SNAPSHOT_BYTES: usize =
    MAX_OWNERS * (DATA_PER_OWNER + CONTROL_PER_OWNER) * (MAX_EVENT_BYTES + 2) + 5;
const DOMAIN: &[u8] = b"vhalla/social-sync/spike/v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Set { register: u16, value: i8 },
    Retract,
    Revoke { writer: Key },
    Resolve { register: u16, value: i8 },
}
impl Action {
    fn control(&self) -> bool {
        matches!(self, Self::Revoke { .. } | Self::Resolve { .. })
    }
}
/// Plain signing input; constructing it grants no authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    pub scope: u64,
    pub owner: Key,
    pub writer: Key,
    pub seq: u64,
    pub prev: Option<Id>,
    pub action: Action,
    pub refs: Vec<Id>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed {
    claim: Claim,
    signature: [u8; 64],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Bounds,
    Encoding,
    Signature,
    Scope,
    Authority,
    Partial,
    Capacity,
    Budget,
    StalePin,
    Rollback,
    MissingBundle,
    Crash,
}
fn hash(bytes: &[u8]) -> Id {
    Sha256::digest(bytes).into()
}
impl Signed {
    pub fn sign(claim: Claim, key: &SigningKey) -> Result<Self, Error> {
        let bytes = encode_claim(&claim)?;
        Ok(Self {
            claim,
            signature: key.sign(&bytes).to_bytes(),
        })
    }
    pub fn id(&self) -> Id {
        hash(&encode_claim(&self.claim).expect("bounded signed claim"))
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut b = encode_claim(&self.claim).expect("bounded claim");
        b.extend(self.signature);
        b
    }
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() > MAX_EVENT_BYTES {
            return Err(Error::Bounds);
        }
        let mut r = Reader(raw);
        if r.take(DOMAIN.len())? != DOMAIN {
            return Err(Error::Encoding);
        }
        let scope = r.u64()?;
        let owner = r.array()?;
        let writer = r.array()?;
        let seq = r.u64()?;
        let prev = match r.u8()? {
            0 => None,
            1 => Some(r.array()?),
            _ => return Err(Error::Encoding),
        };
        let action = match r.u8()? {
            0 => Action::Set {
                register: r.u16()?,
                value: r.u8()? as i8,
            },
            1 => Action::Retract,
            2 => Action::Revoke { writer: r.array()? },
            3 => Action::Resolve {
                register: r.u16()?,
                value: r.u8()? as i8,
            },
            _ => return Err(Error::Encoding),
        };
        let count = r.u8()? as usize;
        if count > MAX_REFS {
            return Err(Error::Bounds);
        }
        let mut refs = Vec::with_capacity(count);
        for _ in 0..count {
            refs.push(r.array()?);
        }
        let signature = r.array()?;
        if !r.0.is_empty() {
            return Err(Error::Encoding);
        }
        let result = Self {
            claim: Claim {
                scope,
                owner,
                writer,
                seq,
                prev,
                action,
                refs,
            },
            signature,
        };
        let mut canonical = encode_claim(&result.claim)?;
        canonical.extend(result.signature);
        if canonical != raw {
            return Err(Error::Encoding);
        }
        Ok(result)
    }
    fn verify(&self) -> Result<(), Error> {
        let bytes = encode_claim(&self.claim)?;
        VerifyingKey::from_bytes(&self.claim.writer)
            .map_err(|_| Error::Signature)?
            .verify_strict(&bytes, &Signature::from_bytes(&self.signature))
            .map_err(|_| Error::Signature)
    }
}
fn encode_claim(c: &Claim) -> Result<Vec<u8>, Error> {
    if c.seq == 0 || c.refs.len() > MAX_REFS || c.refs.windows(2).any(|v| v[0] >= v[1]) {
        return Err(Error::Bounds);
    }
    if matches!(c.action, Action::Set { value, .. } | Action::Resolve { value, .. } if !(-1..=1).contains(&value))
    {
        return Err(Error::Encoding);
    }
    let mut b = Vec::from(DOMAIN);
    b.extend(c.scope.to_be_bytes());
    b.extend(c.owner);
    b.extend(c.writer);
    b.extend(c.seq.to_be_bytes());
    match c.prev {
        None => b.push(0),
        Some(id) => {
            b.push(1);
            b.extend(id);
        }
    }
    match c.action {
        Action::Set { register, value } => {
            b.push(0);
            b.extend(register.to_be_bytes());
            b.push(value as u8);
        }
        Action::Retract => b.push(1),
        Action::Revoke { writer } => {
            b.push(2);
            b.extend(writer);
        }
        Action::Resolve { register, value } => {
            b.push(3);
            b.extend(register.to_be_bytes());
            b.push(value as u8);
        }
    }
    b.push(c.refs.len() as u8);
    for id in &c.refs {
        b.extend(id);
    }
    if b.len() + 64 > MAX_EVENT_BYTES {
        return Err(Error::Bounds);
    }
    Ok(b)
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let v = self.0.get(..n).ok_or(Error::Encoding)?;
        self.0 = &self.0[n..];
        Ok(v)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Encoding)
    }
    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.array::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.array()?))
    }
}
/// Pinned local fixture policy, NOT a network grant decoder or lifecycle proof.
#[derive(Clone)]
pub struct Policy {
    scope: u64,
    owners: BTreeMap<Key, BTreeSet<Key>>,
}
impl Policy {
    pub fn new(scope: u64, owners: BTreeMap<Key, BTreeSet<Key>>) -> Result<Self, Error> {
        if owners.is_empty()
            || owners.len() > MAX_OWNERS
            || owners
                .iter()
                .any(|(owner, writers)| writers.len() > MAX_WRITERS || !writers.contains(owner))
        {
            return Err(Error::Bounds);
        }
        Ok(Self { scope, owners })
    }
    fn digest(&self) -> Id {
        let mut bytes = Vec::from(b"vhalla/social-sync/policy/v1" as &[u8]);
        bytes.extend(self.scope.to_be_bytes());
        for (owner, writers) in &self.owners {
            bytes.extend(owner);
            bytes.push(writers.len() as u8);
            for writer in writers {
                bytes.extend(writer);
            }
        }
        hash(&bytes)
    }
    fn admit(&self, e: &Signed) -> Result<(), Error> {
        let c = &e.claim;
        if c.scope != self.scope {
            return Err(Error::Scope);
        }
        if !self
            .owners
            .get(&c.owner)
            .is_some_and(|w| w.contains(&c.writer))
            || (c.action.control() && c.writer != c.owner)
        {
            return Err(Error::Authority);
        }
        e.verify()
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Projection {
    pub values: BTreeMap<(Key, u16), i8>,
    pub frozen_owners: BTreeSet<Key>,
    pub conflicted_writers: BTreeSet<(Key, Key)>,
    pub pending: usize,
}
/// Local reception telemetry, deliberately outside the social projection/root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub backpressure_observed: bool,
}
#[derive(Default)]
pub struct SyncCursor {
    owner: usize,
    priority: [usize; MAX_OWNERS],
    regular: [usize; MAX_OWNERS],
}

#[derive(Clone)]
pub struct Archive {
    policy: Policy,
    events: BTreeMap<Id, Signed>,
    partial: bool,
}
impl Archive {
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            events: BTreeMap::new(),
            partial: false,
        }
    }
    pub fn len(&self) -> usize {
        self.events.len()
    }
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
    pub fn ingest(&mut self, raw: &[u8], budget: &mut Budget) -> Result<(), Error> {
        budget.charge(raw.len())?;
        let e = Signed::decode(raw)?;
        self.policy.admit(&e)?;
        if self.events.contains_key(&e.id()) {
            return Ok(());
        }
        let c = &e.claim;
        let owner = self
            .events
            .values()
            .filter(|v| v.claim.owner == c.owner && v.claim.action.control() == c.action.control())
            .count();
        let writer = self
            .events
            .values()
            .filter(|v| {
                v.claim.owner == c.owner && v.claim.writer == c.writer && !v.claim.action.control()
            })
            .count();
        if owner
            >= if c.action.control() {
                CONTROL_PER_OWNER
            } else {
                DATA_PER_OWNER
            }
            || (!c.action.control() && writer >= DATA_PER_WRITER)
        {
            self.partial = true;
            return Err(Error::Capacity);
        }
        let mut proposed = self.events.clone();
        proposed.insert(e.id(), e.clone());
        let (ready, _) = closure(&proposed);
        if !c.action.control()
            && proposed
                .iter()
                .filter(|(id, v)| {
                    v.claim.owner == c.owner && v.claim.writer == c.writer && !ready.contains(*id)
                })
                .count()
                > PENDING_PER_WRITER
        {
            self.partial = true;
            return Err(Error::Partial);
        }
        self.events = proposed;
        Ok(())
    }
    /// Rebuild rather than retaining evidence admitted under obsolete control.
    pub fn projection(&self) -> Projection {
        let (active, _) = closure(&self.events);
        let mut frozen = BTreeSet::new();
        let mut positions = BTreeMap::new();
        for e in self.events.values() {
            let c = &e.claim;
            if c.writer == c.owner {
                if let Some(prior) = positions.insert((c.owner, c.seq), e.id()) {
                    if prior != e.id() {
                        frozen.insert(c.owner);
                    }
                }
            }
        }
        let mut writer_positions = BTreeMap::new();
        let mut writer_forks: BTreeMap<(Key, Key), u64> = BTreeMap::new();
        for e in self.events.values() {
            let c = &e.claim;
            if writer_positions
                .insert((c.owner, c.writer, c.seq), e.id())
                .is_some_and(|previous| previous != e.id())
            {
                writer_forks
                    .entry((c.owner, c.writer))
                    .and_modify(|seq| *seq = (*seq).min(c.seq))
                    .or_insert(c.seq);
            }
        }
        let mut admitted = active.clone();
        admitted.retain(|id| {
            let c = &self.events[id].claim;
            writer_forks
                .get(&(c.owner, c.writer))
                .is_none_or(|fork| c.seq < *fork)
        });
        for id in &active {
            let c = &self.events[id].claim;
            if let Action::Revoke { writer } = c.action {
                for (candidate, e) in &self.events {
                    if e.claim.owner == c.owner
                        && e.claim.writer == writer
                        && !c
                            .refs
                            .iter()
                            .any(|head| prefix(*candidate, *head, &self.events))
                    {
                        admitted.remove(candidate);
                    }
                }
            }
        }
        let mut removed = BTreeSet::new();
        for id in &admitted {
            let c = &self.events[id].claim;
            if matches!(c.action, Action::Retract) {
                for target in &c.refs {
                    if self.events.get(target).is_some_and(|e| {
                        e.claim.owner == c.owner
                            && (e.claim.writer == c.writer || c.writer == c.owner)
                    }) {
                        removed.insert(*target);
                    }
                }
            }
        }
        let mut registers: BTreeMap<(Key, u16), Vec<(Id, i8)>> = BTreeMap::new();
        for id in &admitted {
            let c = &self.events[id].claim;
            if frozen.contains(&c.owner) || removed.contains(id) {
                continue;
            }
            if let Action::Set { register, value } | Action::Resolve { register, value } = c.action
            {
                registers
                    .entry((c.owner, register))
                    .or_default()
                    .push((*id, value));
            }
        }
        let mut values = BTreeMap::new();
        for (key, entries) in registers {
            let superseded: BTreeSet<_> = entries
                .iter()
                .flat_map(|(id, _)| self.events[id].claim.refs.iter().copied())
                .collect();
            let heads: BTreeSet<_> = entries
                .iter()
                .filter(|(id, _)| !superseded.contains(id))
                .map(|(_, v)| *v)
                .collect();
            values.insert(
                key,
                if heads.len() == 1 {
                    *heads.first().unwrap()
                } else {
                    0
                },
            );
        }
        Projection {
            values,
            frozen_owners: frozen,
            conflicted_writers: writer_forks.keys().copied().collect(),
            pending: self.events.len() - active.len(),
        }
    }
    pub fn receipt(&self) -> Receipt {
        Receipt {
            backpressure_observed: self.partial,
        }
    }
    /// Logical inventory identity excludes transport order, local backpressure,
    /// and alternate valid signature bytes for the same canonical event ID.
    pub fn evidence_root(&self) -> Id {
        let mut bytes = Vec::from(b"vhalla/social-sync/evidence/v1" as &[u8]);
        bytes.extend(self.policy.digest());
        for id in self.events.keys() {
            bytes.extend(id);
        }
        hash(&bytes)
    }
    pub fn snapshot(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.push(u8::from(self.partial));
        b.extend((self.events.len() as u32).to_be_bytes());
        for e in self.events.values() {
            let raw = e.encode();
            b.extend((raw.len() as u16).to_be_bytes());
            b.extend(raw)
        }
        b
    }
    /// Restore all signed evidence first: network orphan quotas must not make
    /// canonical snapshot restore depend on digest ordering.
    pub fn restore(policy: Policy, raw: &[u8]) -> Result<Self, Error> {
        if raw.len() > MAX_SNAPSHOT_BYTES {
            return Err(Error::Bounds);
        }
        let mut r = Reader(raw);
        let partial = match r.u8()? {
            0 => false,
            1 => true,
            _ => return Err(Error::Encoding),
        };
        let n = u32::from_be_bytes(r.array()?) as usize;
        if n > MAX_OWNERS * (DATA_PER_OWNER + CONTROL_PER_OWNER) {
            return Err(Error::Bounds);
        }
        let mut out = Self::new(policy);
        out.partial = partial;
        let mut last = None;
        for _ in 0..n {
            let len = r.u16()? as usize;
            let e = Signed::decode(r.take(len)?)?;
            out.policy.admit(&e)?;
            let id = e.id();
            if last.is_some_and(|old| old >= id) {
                return Err(Error::Encoding);
            }
            last = Some(id);
            out.events.insert(id, e);
        }
        if !r.0.is_empty() {
            return Err(Error::Encoding);
        }
        for (owner, writers) in &out.policy.owners {
            let data = out
                .events
                .values()
                .filter(|e| e.claim.owner == *owner && !e.claim.action.control())
                .count();
            let control = out
                .events
                .values()
                .filter(|e| e.claim.owner == *owner && e.claim.action.control())
                .count();
            if data > DATA_PER_OWNER || control > CONTROL_PER_OWNER {
                return Err(Error::Capacity);
            }
            for writer in writers {
                if out
                    .events
                    .values()
                    .filter(|e| {
                        e.claim.owner == *owner
                            && e.claim.writer == *writer
                            && !e.claim.action.control()
                    })
                    .count()
                    > DATA_PER_WRITER
                {
                    return Err(Error::Capacity);
                }
            }
        }
        Ok(out)
    }
    /// One cursor per peer cycles configured owners, never peer-chosen authors.
    pub fn missing_page(&self, other: &Self, cursor: &mut SyncCursor) -> Vec<Vec<u8>> {
        if self.policy.digest() != other.policy.digest() {
            return Vec::new();
        }
        let owners: Vec<_> = self.policy.owners.keys().collect();
        let dependencies: BTreeSet<_> = other
            .events
            .values()
            .flat_map(|e| e.claim.prev.iter().chain(&e.claim.refs))
            .filter(|id| !other.events.contains_key(*id))
            .copied()
            .collect();
        let mut out = Vec::new();
        for _ in 0..owners.len() {
            let index = cursor.owner % owners.len();
            let owner = owners[index];
            cursor.owner = cursor.owner.wrapping_add(1);
            let mut priority = Vec::new();
            let mut regular = Vec::new();
            for (id, e) in self
                .events
                .iter()
                .filter(|(id, e)| e.claim.owner == *owner && !other.events.contains_key(*id))
            {
                if e.claim.action.control() || dependencies.contains(id) {
                    priority.push(e)
                } else {
                    regular.push(e)
                }
            }
            let mut selected = BTreeSet::new();
            for class in [true, false, true, false] {
                if selected.len() == 2 {
                    break;
                }
                let (events, position) = if class {
                    (&priority, &mut cursor.priority[index])
                } else {
                    (&regular, &mut cursor.regular[index])
                };
                if !events.is_empty() {
                    let event = events[*position % events.len()];
                    *position = position.wrapping_add(1);
                    if selected.insert(event.id()) {
                        out.push(event.encode());
                    }
                }
            }
            if out.len() >= 4 {
                break;
            }
        }
        out
    }
}
fn prefix(candidate: Id, mut head: Id, events: &BTreeMap<Id, Signed>) -> bool {
    for _ in 0..MAX_OWNERS * (DATA_PER_OWNER + CONTROL_PER_OWNER) {
        if candidate == head {
            return true;
        }
        match events.get(&head).and_then(|e| e.claim.prev) {
            Some(prev) => head = prev,
            None => return false,
        }
    }
    false
}
// Finite fixed-point evaluation avoids exponentially rewalking shared DAG
// ancestry. At most E passes, each inspecting E records and <= MAX_REFS edges.
fn closure(events: &BTreeMap<Id, Signed>) -> (BTreeSet<Id>, usize) {
    let mut ready = BTreeSet::new();
    let mut work = 0;
    for _ in 0..events.len() {
        let before = ready.len();
        for (id, event) in events {
            work += 1;
            if ready.contains(id) {
                continue;
            }
            let c = &event.claim;
            work += 1 + c.refs.len();
            let previous = match c.prev {
                None => c.seq == 1,
                Some(prev) => {
                    ready.contains(&prev)
                        && events.get(&prev).is_some_and(|p| {
                            p.claim.owner == c.owner
                                && p.claim.writer == c.writer
                                && p.claim.seq.checked_add(1) == Some(c.seq)
                        })
                }
            };
            if previous
                && c.refs.iter().all(|dep| {
                    ready.contains(dep) && events.get(dep).is_some_and(|p| p.claim.owner == c.owner)
                })
            {
                ready.insert(*id);
            }
        }
        if ready.len() == before || ready.len() == events.len() {
            break;
        }
    }
    (ready, work)
}

#[derive(Clone, Debug)]
pub struct Budget {
    pub verifications: usize,
    pub bytes: usize,
}
impl Budget {
    pub fn bounded() -> Self {
        Self {
            verifications: 8,
            bytes: 4096,
        }
    }
    fn charge(&mut self, bytes: usize) -> Result<(), Error> {
        if bytes > MAX_EVENT_BYTES || self.verifications == 0 || bytes > self.bytes {
            return Err(Error::Budget);
        }
        self.verifications -= 1;
        self.bytes -= bytes;
        Ok(())
    }
}

/// Fault-model storage only. A local pin is not an anti-rollback witness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pin {
    pub generation: u64,
    pub root: Id,
}
#[derive(Clone, Default)]
pub struct Disk {
    pub pin: Option<Pin>,
    bundles: BTreeMap<Id, Vec<u8>>,
}
#[derive(Clone)]
pub struct Intent {
    expected: Option<Pin>,
    next: Pin,
    bundle: Vec<u8>,
    policy: Policy,
    ids: BTreeSet<Id>,
}
impl Intent {
    pub fn prepare(a: &Archive, expected: Option<Pin>) -> Result<Self, Error> {
        let mut bundle = Vec::from(a.policy.digest());
        bundle.extend(a.snapshot());
        let next = Pin {
            generation: expected
                .map_or(Some(1), |p| p.generation.checked_add(1))
                .ok_or(Error::Bounds)?,
            root: hash(&bundle),
        };
        Ok(Self {
            expected,
            next,
            bundle,
            policy: a.policy.clone(),
            ids: a.events.keys().copied().collect(),
        })
    }
}
impl Disk {
    /// Bundle durability precedes conditional pin publication. Cut models a crash.
    pub fn commit(&mut self, i: &Intent, cut: u8) -> Result<Pin, Error> {
        if self.pin == Some(i.next) {
            return Ok(i.next);
        }
        if self.pin != i.expected {
            return Err(Error::StalePin);
        }
        if let Some(previous) = i.expected {
            let raw = self
                .bundles
                .get(&previous.root)
                .ok_or(Error::MissingBundle)?;
            if hash(raw) != previous.root || raw.get(..32) != Some(i.policy.digest().as_slice()) {
                return Err(Error::Scope);
            }
            let previous_archive = Archive::restore(i.policy.clone(), &raw[32..])?;
            if previous_archive.events.keys().any(|id| !i.ids.contains(id)) {
                return Err(Error::Rollback);
            }
        }
        if cut == 0 {
            return Err(Error::Crash);
        }
        self.bundles.insert(i.next.root, i.bundle.clone());
        if cut == 1 {
            return Err(Error::Crash);
        }
        self.pin = Some(i.next);
        if cut == 2 {
            return Err(Error::Crash);
        }
        Ok(i.next)
    }
    pub fn load(&self, policy: Policy, external_floor: Option<Pin>) -> Result<Archive, Error> {
        let p = self.pin.ok_or(Error::MissingBundle)?;
        if external_floor.is_some_and(|floor| {
            p.generation < floor.generation
                || (p.generation == floor.generation && p.root != floor.root)
        }) {
            return Err(Error::Rollback);
        }
        let b = self.bundles.get(&p.root).ok_or(Error::MissingBundle)?;
        if hash(b) != p.root {
            return Err(Error::Encoding);
        }
        if b.get(..32) != Some(policy.digest().as_slice()) {
            return Err(Error::Scope);
        }
        Archive::restore(policy, &b[32..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use proptest::prelude::*;
    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }
    fn fixture() -> Policy {
        Policy::new(
            7,
            [
                (
                    key(1).verifying_key().to_bytes(),
                    [1, 2, 3]
                        .map(|i| key(i).verifying_key().to_bytes())
                        .into_iter()
                        .collect(),
                ),
                (
                    key(4).verifying_key().to_bytes(),
                    [4, 5]
                        .map(|i| key(i).verifying_key().to_bytes())
                        .into_iter()
                        .collect(),
                ),
            ]
            .into_iter()
            .collect(),
        )
        .unwrap()
    }
    fn event(
        owner: u8,
        writer: u8,
        seq: u64,
        prev: Option<Id>,
        action: Action,
        mut refs: Vec<Id>,
    ) -> Signed {
        refs.sort();
        Signed::sign(
            Claim {
                scope: 7,
                owner: key(owner).verifying_key().to_bytes(),
                writer: key(writer).verifying_key().to_bytes(),
                seq,
                prev,
                action,
                refs,
            },
            &key(writer),
        )
        .unwrap()
    }
    fn set(writer: u8, seq: u64, prev: Option<Id>, value: i8, refs: Vec<Id>) -> Signed {
        event(
            1,
            writer,
            seq,
            prev,
            Action::Set { register: 1, value },
            refs,
        )
    }
    fn put(a: &mut Archive, e: &Signed) {
        a.ingest(&e.encode(), &mut Budget::bounded()).unwrap()
    }
    #[test]
    fn three_replicas_merge_duplicate_reorder_and_rebuild_after_revocation_or_control_fork() {
        let up = set(2, 1, None, 1, vec![]);
        let down = set(3, 1, None, -1, vec![]);
        let p = fixture();
        let mut a = Archive::new(p.clone());
        let mut b = Archive::new(p.clone());
        let mut c = Archive::new(p.clone());
        for e in [&up, &down, &up] {
            put(&mut a, e)
        }
        for e in [&down, &up] {
            put(&mut b, e)
        }
        for e in [&down, &up] {
            put(&mut c, e)
        }
        assert_eq!(a.projection(), b.projection());
        assert_eq!(b.projection(), c.projection());
        assert_eq!(a.projection().values.values().next(), Some(&0));
        let revoke = event(
            1,
            1,
            1,
            None,
            Action::Revoke {
                writer: key(2).verifying_key().to_bytes(),
            },
            vec![],
        );
        put(&mut a, &revoke);
        assert_ne!(a.projection(), b.projection());
        put(&mut b, &revoke);
        put(&mut c, &revoke);
        assert_eq!(a.projection(), b.projection());
        assert_eq!(b.projection(), c.projection());
        let fork = event(
            1,
            1,
            1,
            None,
            Action::Revoke {
                writer: key(3).verifying_key().to_bytes(),
            },
            vec![],
        );
        put(&mut a, &fork);
        assert!(a
            .projection()
            .frozen_owners
            .contains(&key(1).verifying_key().to_bytes()));
        assert!(a.projection().values.is_empty());
    }
    #[test]
    fn time_gc_resurrects_but_full_archive_and_restart_preserve_retraction() {
        let create = set(2, 1, None, 1, vec![]);
        let retract = event(
            1,
            2,
            2,
            Some(create.id()),
            Action::Retract,
            vec![create.id()],
        );
        let mut safe = Archive::new(fixture());
        put(&mut safe, &retract);
        assert_eq!(safe.projection().pending, 1);
        put(&mut safe, &create);
        assert!(safe.projection().values.is_empty());
        let restored = Archive::restore(fixture(), &safe.snapshot()).unwrap();
        assert_eq!(restored.projection(), safe.projection());
        let mut unsafe_gc = Archive::new(fixture());
        put(&mut unsafe_gc, &create);
        assert!(
            !unsafe_gc.projection().values.is_empty(),
            "forgetting the tombstone permits resurrection from an old peer"
        );
    }
    #[test]
    fn sequence_max_is_not_a_contiguous_frontier() {
        let first = set(2, 1, None, 1, vec![]);
        let third = set(2, 3, Some(first.id()), -1, vec![first.id()]);
        let mut a = Archive::new(fixture());
        put(&mut a, &third);
        put(&mut a, &first);
        assert_eq!(a.projection().pending, 1);
        assert_eq!(a.projection().values.values().next(), Some(&1));
        assert_eq!(a.events.values().map(|e| e.claim.seq).max(), Some(3));
    }
    #[test]
    fn data_pressure_cannot_consume_control_reserve_and_orphans_are_per_writer() {
        let mut a = Archive::new(fixture());
        let mut heads = vec![];
        for writer in [2, 3] {
            let mut prev = None;
            for seq in 1..=4 {
                let e = set(writer, seq, prev, 1, vec![]);
                prev = Some(e.id());
                heads.push(e.id());
                put(&mut a, &e)
            }
        }
        let overflow = set(2, 5, Some(heads[3]), 1, vec![]);
        assert_eq!(
            a.ingest(&overflow.encode(), &mut Budget::bounded()),
            Err(Error::Capacity)
        );
        let resolve = event(
            1,
            1,
            1,
            None,
            Action::Resolve {
                register: 1,
                value: -1,
            },
            heads,
        );
        put(&mut a, &resolve);
        assert_eq!(a.projection().values.values().next(), Some(&-1));
        assert!(a.receipt().backpressure_observed);
        let mut pending = Archive::new(fixture());
        for seq in [2, 3] {
            put(&mut pending, &set(2, seq, Some([seq as u8; 32]), 1, vec![]))
        }
        assert_eq!(
            pending.ingest(
                &set(2, 4, Some([4; 32]), 1, vec![]).encode(),
                &mut Budget::bounded()
            ),
            Err(Error::Partial)
        );
        put(&mut pending, &set(3, 1, None, 1, vec![]));
        assert_eq!(pending.projection().values.values().next(), Some(&1));
    }
    #[test]
    fn commit_crash_retry_cas_and_external_rollback_floor() {
        let mut a = Archive::new(fixture());
        let first = set(2, 1, None, 1, vec![]);
        put(&mut a, &first);
        let i = Intent::prepare(&a, None).unwrap();
        for cut in 0..=2 {
            let mut d = Disk::default();
            assert_eq!(d.commit(&i, cut), Err(Error::Crash));
            assert_eq!(d.commit(&i, 3), Ok(i.next));
            assert_eq!(
                d.load(fixture(), Some(i.next)).unwrap().projection(),
                a.projection()
            )
        }
        let mut d = Disk::default();
        let p1 = d.commit(&i, 3).unwrap();
        let old = d.clone();
        let next = set(2, 2, Some(first.id()), -1, vec![first.id()]);
        put(&mut a, &next);
        let j = Intent::prepare(&a, Some(p1)).unwrap();
        let p2 = d.commit(&j, 3).unwrap();
        assert_eq!(d.commit(&i, 3), Err(Error::StalePin));
        assert!(matches!(
            old.load(fixture(), Some(p2)),
            Err(Error::Rollback)
        ));
        assert!(
            old.load(fixture(), None).is_ok(),
            "same-disk rollback remains undetectable without external freshness"
        );
        let stale_writer_fork = set(2, 1, None, -1, vec![]);
        assert_ne!(
            first.id(),
            stale_writer_fork.id(),
            "restoring a writer counter can equivocate despite possessing the same valid key"
        );
    }
    #[test]
    fn budget_charges_bad_signatures_and_owner_pages_are_fair() {
        let mut a = Archive::new(fixture());
        let good = set(2, 1, None, 1, vec![]);
        let mut invalid = good.encode();
        *invalid.last_mut().unwrap() ^= 1;
        let mut b = Budget {
            verifications: 1,
            bytes: 1024,
        };
        assert_eq!(a.ingest(&invalid, &mut b), Err(Error::Signature));
        assert_eq!(a.ingest(&good.encode(), &mut b), Err(Error::Budget));
        for writer in [2, 3] {
            put(&mut a, &set(writer, 1, None, 1, vec![]))
        }
        let other = event(
            4,
            5,
            1,
            None,
            Action::Set {
                register: 1,
                value: 1,
            },
            vec![],
        );
        put(&mut a, &other);
        let empty = Archive::new(fixture());
        let page = a.missing_page(&empty, &mut SyncCursor::default());
        assert!(page.len() <= 4);
        assert!(page.iter().any(
            |raw| Signed::decode(raw).unwrap().claim.owner == key(4).verifying_key().to_bytes()
        ));
    }
    #[test]
    fn malformed_structured_claim_fails_without_panic_and_writer_fork_quarantines_suffix() {
        let good = set(2, 1, None, 1, vec![]);
        let mut invalid = good.encode();
        invalid[DOMAIN.len() + 8 + 32 + 32..DOMAIN.len() + 8 + 32 + 32 + 8].fill(0);
        assert_eq!(Signed::decode(&invalid), Err(Error::Bounds));
        let fork = set(2, 1, None, -1, vec![]);
        let mut archive = Archive::new(fixture());
        put(&mut archive, &good);
        put(&mut archive, &fork);
        assert!(archive.projection().values.is_empty());
        assert!(archive.projection().conflicted_writers.contains(&(
            key(1).verifying_key().to_bytes(),
            key(2).verifying_key().to_bytes()
        )));
    }
    #[test]
    fn transient_orphan_pressure_does_not_change_complete_projection_or_evidence_root() {
        let e1 = set(2, 1, None, 1, vec![]);
        let e2 = set(2, 2, Some(e1.id()), 1, vec![e1.id()]);
        let e3 = set(2, 3, Some(e2.id()), 1, vec![e2.id()]);
        let e4 = set(2, 4, Some(e3.id()), -1, vec![e3.id()]);
        let mut ordered = Archive::new(fixture());
        for e in [&e1, &e2, &e3, &e4] {
            put(&mut ordered, e)
        }
        let mut shuffled = Archive::new(fixture());
        put(&mut shuffled, &e3);
        put(&mut shuffled, &e4);
        assert_eq!(
            shuffled.ingest(&e2.encode(), &mut Budget::bounded()),
            Err(Error::Partial)
        );
        put(&mut shuffled, &e1);
        put(&mut shuffled, &e2);
        assert_eq!(ordered.projection(), shuffled.projection());
        assert_eq!(ordered.evidence_root(), shuffled.evidence_root());
        assert_ne!(ordered.receipt(), shuffled.receipt());
        assert_eq!(
            Archive::restore(fixture(), &shuffled.snapshot())
                .unwrap()
                .receipt(),
            shuffled.receipt()
        );
    }
    #[test]
    fn control_and_dependency_pages_progress_behind_rejected_data() {
        let revoke = event(
            1,
            1,
            1,
            None,
            Action::Revoke {
                writer: key(2).verifying_key().to_bytes(),
            },
            vec![],
        );
        let mut source = Archive::new(fixture());
        let mut prev = None;
        // Choose a bounded deterministic fixture where the old first-two-ID
        // algorithm provably hides the revocation behind rejected data.
        for register in 1..=64 {
            source = Archive::new(fixture());
            prev = None;
            for seq in 1..=4 {
                let e = event(1, 2, seq, prev, Action::Set { register, value: 1 }, vec![]);
                prev = Some(e.id());
                put(&mut source, &e);
            }
            if source.events.keys().filter(|id| **id < revoke.id()).count() >= 2 {
                break;
            }
        }
        let mut receiver = Archive::new(fixture());
        let mut other_prev = None;
        for seq in 1..=4 {
            let e = set(2, seq, other_prev, -1, vec![]);
            other_prev = Some(e.id());
            put(&mut receiver, &e);
        }
        put(&mut source, &revoke);
        let old_page: Vec<_> = source
            .events
            .keys()
            .filter(|id| !receiver.events.contains_key(*id))
            .take(2)
            .copied()
            .collect();
        assert_eq!(old_page.len(), 2);
        assert!(
            !old_page.contains(&revoke.id()),
            "old selection would starve revocation"
        );
        let page = source.missing_page(&receiver, &mut SyncCursor::default());
        assert!(page
            .iter()
            .any(|raw| Signed::decode(raw).unwrap().id() == revoke.id()));
        for raw in page {
            let _ = receiver.ingest(&raw, &mut Budget::bounded());
        }
        assert!(receiver.events.contains_key(&revoke.id()));
        assert!(receiver.projection().values.is_empty());
        let mut destination = Archive::new(fixture());
        let last = source.events[&prev.unwrap()].clone();
        put(&mut destination, &last);
        let mut cursor = SyncCursor::default();
        let mut pages = source.missing_page(&destination, &mut cursor);
        pages.extend(source.missing_page(&destination, &mut cursor));
        assert!(pages
            .iter()
            .any(|raw| Signed::decode(raw).unwrap().id() == last.claim.prev.unwrap()));
    }
    #[test]
    fn forward_generation_cannot_drop_a_tombstone_or_change_policy() {
        let create = set(2, 1, None, 1, vec![]);
        let retract = event(
            1,
            2,
            2,
            Some(create.id()),
            Action::Retract,
            vec![create.id()],
        );
        let mut history = Archive::new(fixture());
        put(&mut history, &create);
        put(&mut history, &retract);
        let mut disk = Disk::default();
        let old = disk
            .commit(&Intent::prepare(&history, None).unwrap(), 3)
            .unwrap();
        let mut stripped = Archive::new(fixture());
        put(&mut stripped, &create);
        let bad = Intent::prepare(&stripped, Some(old)).unwrap();
        assert_eq!(disk.commit(&bad, 3), Err(Error::Rollback));
        assert_eq!(disk.pin, Some(old));
        assert!(disk
            .load(fixture(), Some(old))
            .unwrap()
            .projection()
            .values
            .is_empty());
        let mut different = fixture();
        different.scope = 8;
        let changed = Archive::new(different);
        assert_eq!(
            disk.commit(&Intent::prepare(&changed, Some(old)).unwrap(), 3),
            Err(Error::Scope)
        );
    }
    #[test]
    fn shared_ancestry_closure_has_explicit_polynomial_work_bound() {
        let mut archive = Archive::new(fixture());
        let mut refs = vec![];
        for writer in [2, 3] {
            let mut prev = None;
            for seq in 1..=4 {
                let e = set(writer, seq, prev, 1, refs.clone());
                prev = Some(e.id());
                refs.push(e.id());
                put(&mut archive, &e);
            }
        }
        let (ready, work) = closure(&archive.events);
        assert_eq!(ready.len(), archive.len());
        assert!(work <= archive.len() * archive.len() * (MAX_REFS + 2));
    }
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]
        #[test]
        fn ordering_and_duplication_of_complete_under_cap_event_set_converge(order in prop::collection::vec(0usize..3,0..18)){
            let x=set(2,1,None,1,vec![]);let y=set(3,1,None,1,vec![]);let z=event(1,1,1,None,Action::Resolve{register:1,value:-1},vec![x.id(),y.id()]);let records=[x,y,z];let mut a=Archive::new(fixture());for index in order{put(&mut a,&records[index])}for e in &records{put(&mut a,e)}let mut b=Archive::new(fixture());for e in records.iter().rev(){put(&mut b,e)}prop_assert_eq!(a.snapshot(),b.snapshot());prop_assert_eq!(a.projection(),b.projection());
        }
        #[test]
        fn arbitrary_bounded_bytes_do_not_mutate_archive(raw in prop::collection::vec(any::<u8>(),0..MAX_EVENT_BYTES+1)){
            let mut a=Archive::new(fixture());let before=a.snapshot();let _=a.ingest(&raw,&mut Budget::bounded());prop_assert_eq!(before,a.snapshot());
        }
    }
}
