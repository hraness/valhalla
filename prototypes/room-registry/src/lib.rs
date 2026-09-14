#![no_std]
#![forbid(unsafe_code)]
//! Sequential reference state machine, NOT a distributed registry or admission API.
//! `Directory` models one agreed directory history. Its clock and support inputs
//! stand in for finalized evidence; this experiment supplies no consensus,
//! social-history verifier, persistence, or live transport.
extern crate alloc;

pub mod transition;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec::Vec,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

pub type Id = [u8; 32];
pub const MAX_ROOMS: usize = 4096;
pub const MAX_OWNERS: usize = 256;
pub const MAX_SUPPORT: usize = 8192;
pub const MAX_SLUG: usize = 48;
pub const MAX_DESCRIPTION: usize = 256;
pub const MAX_PAGE: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Bounds,
    Slug,
    Key,
    Signature,
    WrongDirectory,
    WrongPolicy,
    Expired,
    Slot,
    Cost,
    InsufficientCredit,
    RateLimit,
    Taken,
    Capacity,
    Clock,
    Owner,
    Evidence,
    Missing,
}

/// Testable candidate policy; constants are not calibrated product economics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    pub base_cost: u64,
    pub window_seconds: u64,
    pub max_in_window: u16,
    pub support_epoch_seconds: u64,
    pub max_lifetime_rooms: u32,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            base_cost: 32,
            window_seconds: 86_400,
            max_in_window: 1,
            support_epoch_seconds: 86_400,
            max_lifetime_rooms: 128,
        }
    }
}
impl Policy {
    /// Marginal price of one-based slot n: base*n². Arithmetic overflow denies.
    pub fn cost(self, slot: u32) -> Result<u64, Error> {
        if slot == 0 || slot > self.max_lifetime_rooms {
            return Err(Error::Slot);
        }
        self.base_cost
            .checked_mul(u64::from(slot))
            .and_then(|v| v.checked_mul(u64::from(slot)))
            .ok_or(Error::Cost)
    }
    fn validate(self) -> Result<(), Error> {
        if self.base_cost == 0
            || self.window_seconds == 0
            || self.max_in_window == 0
            || usize::from(self.max_in_window) > MAX_ROOMS
            || self.support_epoch_seconds == 0
            || self.max_lifetime_rooms == 0
            || self.max_lifetime_rooms > MAX_ROOMS as u32
        {
            return Err(Error::Bounds);
        }
        self.cost(self.max_lifetime_rooms)?;
        Ok(())
    }
    fn encode(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.base_cost.to_be_bytes());
        out.extend_from_slice(&self.window_seconds.to_be_bytes());
        out.extend_from_slice(&self.max_in_window.to_be_bytes());
        out.extend_from_slice(&self.support_epoch_seconds.to_be_bytes());
        out.extend_from_slice(&self.max_lifetime_rooms.to_be_bytes());
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Slug(String);
impl Slug {
    /// Wire slugs must already be canonical ASCII; no normalization aliases.
    pub fn new(raw: &str) -> Result<Self, Error> {
        if raw.is_empty()
            || raw.len() > MAX_SLUG
            || raw.starts_with('-')
            || raw.ends_with('-')
            || raw.contains("--")
            || !raw
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(Error::Slug);
        }
        Ok(Self(String::from(raw)))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Inert proposal. An exact owner signature grants only this one actor/draft/slot.
/// Full public keys stand in for social identities in this isolated experiment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Draft {
    pub directory: Id,
    pub policy: Id,
    pub owner: Id,
    pub actor: Id,
    pub slug: Slug,
    pub description: String,
    pub slot: u32,
    pub cost: u64,
    pub expires_at: u64,
    pub nonce: Id,
}
impl Draft {
    fn validate(&self) -> Result<(), Error> {
        checked_key(self.owner)?;
        checked_key(self.actor)?;
        if self.description.is_empty()
            || self.description.len() > MAX_DESCRIPTION
            || self.description.chars().any(|c| c.is_control())
            || self.slot == 0
            || self.cost == 0
            || self.expires_at == 0
            || self.nonce == [0; 32]
        {
            return Err(Error::Bounds);
        }
        Ok(())
    }
    fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);
        for field in [self.directory, self.policy, self.owner, self.actor] {
            out.extend_from_slice(&field);
        }
        out.push(self.slug.0.len() as u8);
        out.extend_from_slice(self.slug.0.as_bytes());
        out.extend_from_slice(&(self.description.len() as u16).to_be_bytes());
        out.extend_from_slice(self.description.as_bytes());
        out.extend_from_slice(&self.slot.to_be_bytes());
        out.extend_from_slice(&self.cost.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out
    }
    /// Canonical draft bytes, as bound into both signatures.
    pub fn encode(&self) -> Vec<u8> {
        self.bytes()
    }
    /// Parses canonical draft bytes and revalidates every bound.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 128 + 1 + 2 + 4 + 8 + 8 + 32 {
            return Err(Error::Bounds);
        }
        let (fixed, rest) = bytes.split_at(128);
        let directory: Id = fixed[..32].try_into().map_err(|_| Error::Bounds)?;
        let policy: Id = fixed[32..64].try_into().map_err(|_| Error::Bounds)?;
        let owner: Id = fixed[64..96].try_into().map_err(|_| Error::Bounds)?;
        let actor: Id = fixed[96..128].try_into().map_err(|_| Error::Bounds)?;
        let (slug_len, rest) = rest.split_first().ok_or(Error::Bounds)?;
        let slug_len = usize::from(*slug_len);
        if rest.len() < slug_len + 2 {
            return Err(Error::Bounds);
        }
        let (slug, rest) = rest.split_at(slug_len);
        let slug = Slug::new(core::str::from_utf8(slug).map_err(|_| Error::Slug)?)?;
        let (desc_len, rest) = rest.split_at(2);
        let desc_len = usize::from(u16::from_be_bytes(
            desc_len.try_into().map_err(|_| Error::Bounds)?,
        ));
        if rest.len() != desc_len + 4 + 8 + 8 + 32 {
            return Err(Error::Bounds);
        }
        let (desc, rest) = rest.split_at(desc_len);
        let description =
            alloc::string::String::from_utf8(desc.to_vec()).map_err(|_| Error::Bounds)?;
        let (slot, rest) = rest.split_at(4);
        let (cost, rest) = rest.split_at(8);
        let (expires_at, nonce) = rest.split_at(8);
        let draft = Draft {
            directory,
            policy,
            owner,
            actor,
            slug,
            description,
            slot: u32::from_be_bytes(slot.try_into().map_err(|_| Error::Bounds)?),
            cost: u64::from_be_bytes(cost.try_into().map_err(|_| Error::Bounds)?),
            expires_at: u64::from_be_bytes(expires_at.try_into().map_err(|_| Error::Bounds)?),
            nonce: nonce.try_into().map_err(|_| Error::Bounds)?,
        };
        draft.validate()?;
        Ok(draft)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proposal {
    draft: Draft,
    owner_signature: [u8; 64],
    actor_signature: [u8; 64],
}
impl Proposal {
    /// Fixture signer, not a custody API. Production agents obtain exact permits
    /// from an owner broker under an explicit revocable room-create grant.
    pub fn sign(draft: Draft, owner: &SigningKey, actor: &SigningKey) -> Result<Self, Error> {
        draft.validate()?;
        if owner.verifying_key().to_bytes() != draft.owner
            || actor.verifying_key().to_bytes() != draft.actor
        {
            return Err(Error::Owner);
        }
        let bytes = draft.bytes();
        let owner_signature = owner
            .sign(&domain(b"vhalla/room-owner-permit/spike-v1", &bytes))
            .to_bytes();
        let actor_signature = actor
            .sign(&domain(b"vhalla/room-create/spike-v1", &bytes))
            .to_bytes();
        Ok(Self {
            draft,
            owner_signature,
            actor_signature,
        })
    }
    pub fn draft(&self) -> &Draft {
        &self.draft
    }
    /// Canonical proposal bytes: the signed draft followed by both exact
    /// signature byte strings.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.draft.bytes();
        out.extend_from_slice(&self.owner_signature);
        out.extend_from_slice(&self.actor_signature);
        out
    }
    /// Parses canonical proposal bytes and re-verifies both signatures, so a
    /// stored or transported proposal cannot bypass verification.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() <= 128 {
            return Err(Error::Bounds);
        }
        let (draft_end, sigs) = (bytes.len() - 128, &bytes[bytes.len() - 128..]);
        let draft = Draft::decode(&bytes[..draft_end])?;
        let proposal = Proposal {
            draft,
            owner_signature: sigs[..64].try_into().map_err(|_| Error::Bounds)?,
            actor_signature: sigs[64..].try_into().map_err(|_| Error::Bounds)?,
        };
        proposal.verify()?;
        Ok(proposal)
    }
    pub fn id(&self) -> Id {
        digest(&domain(
            b"vhalla/room-genesis/spike-v1",
            &self.draft.bytes(),
        ))
    }
    fn verify(&self) -> Result<(), Error> {
        self.draft.validate()?;
        let bytes = self.draft.bytes();
        for (key, tag, signature) in [
            (
                self.draft.owner,
                b"vhalla/room-owner-permit/spike-v1".as_slice(),
                self.owner_signature,
            ),
            (
                self.draft.actor,
                b"vhalla/room-create/spike-v1".as_slice(),
                self.actor_signature,
            ),
        ] {
            checked_key(key)?
                .verify_strict(&domain(tag, &bytes), &Signature::from_bytes(&signature))
                .map_err(|_| Error::Signature)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Room {
    proposal: Proposal,
    pub created_at: u64,
    pub archived: bool,
}
impl Room {
    pub fn id(&self) -> Id {
        self.proposal.id()
    }
    pub fn draft(&self) -> &Draft {
        self.proposal.draft()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Account {
    pub earned: u64,
    pub spent: u64,
    pub lifetime_slots: u32,
}

/// Only the MODEL'S agreed apply order may mutate this state. Copying it and
/// accepting independently on both partitions DOES NOT establish uniqueness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Directory {
    id: Id,
    policy: Policy,
    policy_id: Id,
    eligible: BTreeSet<Id>,
    support: BTreeSet<(Id, Id, u64)>,
    evidence: BTreeMap<Id, (Id, Id, u64)>,
    accounts: BTreeMap<Id, Account>,
    rooms: BTreeMap<Slug, Room>,
    last_time: u64,
    revision: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Created {
    New(Id),
    Existing(Id),
}

impl Directory {
    pub fn new(id: Id, policy: Policy, eligible: &[Id]) -> Result<Self, Error> {
        policy.validate()?;
        if eligible.len() > MAX_OWNERS {
            return Err(Error::Capacity);
        }
        let sources: BTreeSet<_> = eligible.iter().copied().collect();
        if sources.len() != eligible.len() {
            return Err(Error::Bounds);
        }
        for source in &sources {
            checked_key(*source)?;
        }
        let mut raw = Vec::new();
        policy.encode(&mut raw);
        raw.extend_from_slice(&(sources.len() as u16).to_be_bytes());
        for source in &sources {
            raw.extend_from_slice(source);
        }
        Ok(Self {
            id,
            policy,
            policy_id: digest(&domain(b"vhalla/room-policy/spike-v1", &raw)),
            eligible: sources,
            support: BTreeSet::new(),
            evidence: BTreeMap::new(),
            accounts: BTreeMap::new(),
            rooms: BTreeMap::new(),
            last_time: 0,
            revision: 0,
        })
    }
    pub fn id(&self) -> Id {
        self.id
    }
    pub fn policy_id(&self) -> Id {
        self.policy_id
    }
    pub fn account(&self, owner: Id) -> Account {
        self.accounts.get(&owner).copied().unwrap_or_default()
    }
    pub fn room(&self, slug: &Slug) -> Option<&Room> {
        self.rooms.get(slug)
    }
    pub fn quote(&self, owner: Id) -> Result<(u32, u64), Error> {
        let slot = self
            .account(owner)
            .lifetime_slots
            .checked_add(1)
            .ok_or(Error::Slot)?;
        Ok((slot, self.policy.cost(slot)?))
    }
    fn next_revision(&self, now: u64) -> Result<u64, Error> {
        if now < self.last_time {
            return Err(Error::Clock);
        }
        self.revision.checked_add(1).ok_or(Error::Capacity)
    }
    fn capacity_for(&self, owner: Id) -> Result<(), Error> {
        if !self.accounts.contains_key(&owner) && self.accounts.len() >= MAX_OWNERS {
            return Err(Error::Capacity);
        }
        Ok(())
    }
    /// Privileged fixture input standing in for finalized mature social evidence.
    /// NOT a public credit-mint endpoint. A source contributes at most once per
    /// beneficiary/activity epoch, regardless of message or ephemeral agent count.
    /// Evidence identity and activity epoch must come from an authenticated
    /// adapter; this model only enforces deduplication and immutable bindings.
    pub fn apply_finalized_support(
        &mut self,
        source_owner: Id,
        beneficiary: Id,
        activity_epoch: u64,
        evidence_id: Id,
        now: u64,
    ) -> Result<bool, Error> {
        let revision = self.next_revision(now)?;
        checked_key(beneficiary)?;
        if source_owner == beneficiary || !self.eligible.contains(&source_owner) {
            return Err(Error::Owner);
        }
        if evidence_id == [0; 32] || activity_epoch > now / self.policy.support_epoch_seconds {
            return Err(Error::Evidence);
        }
        let key = (beneficiary, source_owner, activity_epoch);
        if let Some(awarded) = self.evidence.get(&evidence_id) {
            return if *awarded == key {
                Ok(false)
            } else {
                Err(Error::Evidence)
            };
        }
        if self.support.contains(&key) {
            return Ok(false);
        }
        if self.support.len() >= MAX_SUPPORT {
            return Err(Error::Capacity);
        }
        self.capacity_for(beneficiary)?;
        let mut account = self.account(beneficiary);
        account.earned = account.earned.checked_add(1).ok_or(Error::Cost)?;
        self.support.insert(key);
        self.evidence.insert(evidence_id, key);
        self.accounts.insert(beneficiary, account);
        self.last_time = now;
        self.revision = revision;
        Ok(true)
    }
    /// Model one final ordered registration. Tentative requests MUST NOT call
    /// this on competing branches and advertise the results as globally final.
    pub fn finalize(&mut self, proposal: &Proposal, now: u64) -> Result<Created, Error> {
        let revision = self.next_revision(now)?;
        proposal.verify()?;
        let d = proposal.draft();
        if d.directory != self.id {
            return Err(Error::WrongDirectory);
        }
        if d.policy != self.policy_id {
            return Err(Error::WrongPolicy);
        }
        if let Some(room) = self.rooms.get(&d.slug) {
            return if room.proposal == *proposal {
                Ok(Created::Existing(room.id()))
            } else {
                Err(Error::Taken)
            };
        }
        if now >= d.expires_at {
            return Err(Error::Expired);
        }
        if self.rooms.len() >= MAX_ROOMS {
            return Err(Error::Capacity);
        }
        self.capacity_for(d.owner)?;
        let mut account = self.account(d.owner);
        let (slot, cost) = self.quote(d.owner)?;
        if d.slot != slot {
            return Err(Error::Slot);
        }
        if d.cost != cost {
            return Err(Error::Cost);
        }
        let spent = account.spent.checked_add(cost).ok_or(Error::Cost)?;
        if spent > account.earned {
            return Err(Error::InsufficientCredit);
        }
        let recent = self
            .rooms
            .values()
            .filter(|room| {
                room.draft().owner == d.owner
                    && now.saturating_sub(room.created_at) < self.policy.window_seconds
            })
            .count();
        if recent >= usize::from(self.policy.max_in_window) {
            return Err(Error::RateLimit);
        }
        // No fallible validation or externally supplied callback follows mutation.
        account.spent = spent;
        account.lifetime_slots = slot;
        let id = proposal.id();
        if self.rooms.values().any(|r| r.id() == id) {
            return Err(Error::Taken);
        }
        self.rooms.insert(
            d.slug.clone(),
            Room {
                proposal: proposal.clone(),
                created_at: now,
                archived: false,
            },
        );
        self.accounts.insert(d.owner, account);
        self.last_time = now;
        self.revision = revision;
        Ok(Created::New(id))
    }
    /// Owner-only fixture closure: preserves slug, original ID and all charges.
    /// Wire signing, delegation and control-chain rotation remain later work.
    pub fn archive_as_owner(
        &mut self,
        owner: &SigningKey,
        slug: &Slug,
        now: u64,
    ) -> Result<(), Error> {
        let revision = self.next_revision(now)?;
        let room = self.rooms.get_mut(slug).ok_or(Error::Missing)?;
        if room.draft().owner != owner.verifying_key().to_bytes() {
            return Err(Error::Owner);
        }
        room.archived = true;
        self.last_time = now;
        self.revision = revision;
        Ok(())
    }
    /// Bounded local scan over finalized manifests, never proof a slug is free.
    /// Empty query is the explicit bounded list operation. AND literal terms,
    /// ASCII folding; non-ASCII UTF-8 remains byte-exact. No regexp or markup.
    pub fn search(&self, query: &str, limit: usize, budget: usize) -> Result<Search<'_>, Error> {
        if query.len() > 128 || limit == 0 || limit > MAX_PAGE || budget > MAX_ROOMS {
            return Err(Error::Bounds);
        }
        let terms: Vec<_> = query.split_ascii_whitespace().collect();
        if terms.len() > 8 || query.chars().any(|c| c.is_control() && c != ' ') {
            return Err(Error::Bounds);
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
                    contains(room.draft().slug.as_str(), term)
                        || contains(&room.draft().description, term)
                })
            {
                result.rooms.push(room);
            }
        }
        Ok(result)
    }
}

#[derive(Debug)]
pub struct Search<'a> {
    pub rooms: Vec<&'a Room>,
    pub examined: usize,
    pub retained: usize,
    pub partial: bool,
    pub revision: u64,
}
fn contains(text: &str, term: &str) -> bool {
    !term.is_empty()
        && text
            .as_bytes()
            .windows(term.len())
            .any(|s| s.eq_ignore_ascii_case(term.as_bytes()))
}
fn checked_key(raw: Id) -> Result<VerifyingKey, Error> {
    let key = VerifyingKey::from_bytes(&raw).map_err(|_| Error::Key)?;
    if key.is_weak() {
        return Err(Error::Key);
    }
    Ok(key)
}
fn domain(tag: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(tag.len() + bytes.len());
    out.extend_from_slice(tag);
    out.extend_from_slice(bytes);
    out
}
fn digest(bytes: &[u8]) -> Id {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests;
