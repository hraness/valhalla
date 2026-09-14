//! Borrowed authority assessment over agreed room-control state.
//!
//! A verified signature is evidence; this layer separately checks that an
//! intent's claimed bases equal the directory's current accepted social and
//! room-control heads, that the owner is not frozen, incomplete or
//! capacity-blocked, that the agent is affiliated and unretired, and that the
//! named grant is open under the accepted chain. Assessment is re-evaluated
//! against live state on every call: no result may be carried across a later
//! state change as a reusable admission token.
//!
//! The committed [`RoomAuthority::snapshot`] digest is the contract a
//! consensus frontier binds as its control commitment. It is a pure function
//! of the borrowed social view and the agreed room-control ledger; feeding
//! identical social evidence to every validator remains a separate
//! data-plane obligation.

use crate::model::*;
use crate::wire::VerifiedRecord;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use sha2::{Digest, Sha256};
use vhalla_core::RealmId;
use vhalla_social::{control::ControlView, AgentId, OwnerId, RecordId};

/// Hard bound on admitted room-control records across all owners.
pub const MAX_CONTROL_RECORDS: usize = 4096;

/// An open `GrantCreate` admitted in one owner's room-control chain.
#[derive(Clone, Copy, Debug)]
struct OpenGrant {
    agent: AgentId,
    agent_key: [u8; 32],
    expires_at: u64,
    maximum_charge: u64,
}

/// One owner's accepted room-control chain and its open grants. The admitted
/// records are retained in order: they are the owner's durable manifest and
/// the source proofs a snapshot restores.
#[derive(Clone, Debug, Default)]
struct OwnerChain {
    head: Option<RoomRecordId>,
    sequence: u64,
    history: Vec<VerifiedRecord>,
    grants: BTreeMap<RoomRecordId, OpenGrant>,
}

/// Closed admission-failure set. A denial is assessment evidence, not a
/// consensus decision and never a routing or finality claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Denial {
    /// The record names a different directory or realm.
    Scope,
    /// The record is not a room-control action.
    Kind,
    /// The owner has no authenticated social genesis.
    UnknownOwner,
    /// The claimed social basis is not the owner's accepted head.
    StaleSocialBasis,
    /// The signer is not the controller at the accepted head.
    ControllerKey,
    /// Conflicting valid control children froze this owner.
    Frozen,
    /// An authenticated dependency needed for authority is missing.
    Incomplete,
    /// Set-derived local resource pressure closed this owner's writes.
    CapacityBlocked,
    /// The owner's locally scoped declared history is not fully present.
    IncompleteHistory,
    /// The claimed room-control basis is not the accepted head.
    StaleRoomBasis,
    /// The claimed predecessor is not the current chain head.
    Previous,
    /// The claimed sequence is not the next chain position.
    Sequence,
    /// The agent is unknown or affiliated with a different owner.
    AgentAffiliation,
    /// The claimed key does not match the authenticated agent genesis key.
    AgentKey,
    /// A semantically admitted owner branch retired this incarnation.
    RetiredAgent,
    /// The named grant is not open in the accepted room-control chain.
    Grant,
    /// The grant names a different agent or incarnation key.
    GrantAgent,
    /// The grant or intent expired at the supplied evaluation clock.
    Expired,
    /// The charge exceeds the grant's authorized maximum.
    Charge,
    /// The bounded ledger is full.
    Capacity,
}

/// Checked admission evidence for one exact intent inside one atomic step.
/// It borrows the assessed authority and cannot outlive it, so a stale
/// assessment cannot be replayed against later state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Admission<'a> {
    intent: &'a CreationIntent,
    grant: &'a RoomRecordId,
}
impl<'a> Admission<'a> {
    /// The intent that passed re-evaluation.
    #[must_use]
    pub const fn intent(&self) -> &'a CreationIntent {
        self.intent
    }
    /// The exact open grant covering this creation.
    #[must_use]
    pub const fn grant(&self) -> &'a RoomRecordId {
        self.grant
    }
    /// The charge the grant authorizes this intent to carry.
    #[must_use]
    pub const fn charge(&self) -> u64 {
        self.intent.charge
    }
}

/// The directory's agreed room-control state: one ordered control chain per
/// owner plus the open grants it retains. Admission re-derives every basis
/// check against the borrowed social view; nothing here grants authority by
/// itself.
#[derive(Clone)]
pub struct RoomAuthority {
    directory: DirectoryId,
    realm: RealmId,
    chains: BTreeMap<OwnerId, OwnerChain>,
    records: usize,
}

impl RoomAuthority {
    /// An empty agreed state pinned to one directory and realm.
    #[must_use]
    pub fn new(directory: DirectoryId, realm: RealmId) -> Self {
        Self {
            directory,
            realm,
            chains: BTreeMap::new(),
            records: 0,
        }
    }
    /// The pinned directory this authority serves.
    #[must_use]
    pub const fn directory(&self) -> DirectoryId {
        self.directory
    }
    /// The pinned realm this authority serves.
    #[must_use]
    pub const fn realm(&self) -> RealmId {
        self.realm
    }
    /// One owner's accepted room-control head, absent before its first record.
    #[must_use]
    pub fn head(&self, owner: OwnerId) -> Option<RoomRecordId> {
        self.chains.get(&owner).and_then(|chain| chain.head)
    }
    /// One owner's next accepted chain sequence — records admitted so far.
    #[must_use]
    pub fn sequence(&self, owner: OwnerId) -> u64 {
        self.chains.get(&owner).map_or(0, |chain| chain.sequence)
    }
    /// Total admitted room-control records, bounded by `MAX_CONTROL_RECORDS`.
    #[must_use]
    pub const fn records(&self) -> usize {
        self.records
    }

    fn owner_status(
        view: &ControlView<'_>,
        owner: OwnerId,
        basis: RecordId,
        key: &[u8; 32],
    ) -> Result<(), Denial> {
        let status = view.owner(owner).ok_or(Denial::UnknownOwner)?;
        if status.frozen() {
            return Err(Denial::Frozen);
        }
        if status.incomplete() {
            return Err(Denial::Incomplete);
        }
        if status.capacity_blocked() {
            return Err(Denial::CapacityBlocked);
        }
        if !view.owner_history_complete(owner) {
            return Err(Denial::IncompleteHistory);
        }
        if status.head() != Some(basis) {
            return Err(Denial::StaleSocialBasis);
        }
        if status.key() != Some(*key) {
            return Err(Denial::ControllerKey);
        }
        Ok(())
    }

    fn agent_status(
        view: &ControlView<'_>,
        owner: OwnerId,
        agent: AgentId,
        key: &[u8; 32],
    ) -> Result<(), Denial> {
        let status = view.agent(agent).ok_or(Denial::AgentAffiliation)?;
        if status.owner() != owner {
            return Err(Denial::AgentAffiliation);
        }
        if status.key() != *key {
            return Err(Denial::AgentKey);
        }
        if status.retired() {
            return Err(Denial::RetiredAgent);
        }
        Ok(())
    }

    /// Admit a verified room-control record into the agreed chain, checking
    /// scope, exact chain order and the claimed social basis against the
    /// borrowed view. The record's signatures were already verified; this
    /// step authenticates its authority claims.
    pub fn admit(
        &mut self,
        record: &VerifiedRecord,
        view: &ControlView<'_>,
        now: u64,
    ) -> Result<(), Denial> {
        let Body::Control(control) = record.body() else {
            return Err(Denial::Kind);
        };
        if control.directory != self.directory || control.realm != self.realm {
            return Err(Denial::Scope);
        }
        Self::owner_status(
            view,
            control.owner,
            control.social_control,
            &control.controller_key,
        )?;
        if let CreateAction::GrantCreate {
            agent,
            agent_key,
            expires_at,
            ..
        } = &control.action
        {
            Self::agent_status(view, control.owner, *agent, agent_key)?;
            if *expires_at <= now {
                return Err(Denial::Expired);
            }
        }
        self.commit_control(record)
    }

    /// Apply one already-verified control record to its owner's chain,
    /// checking only scope and the agreed chain order. Live authority claims
    /// — the social basis, agent status and grant expiry — are the caller's
    /// `admit` obligation; this tail is shared with snapshot restore.
    fn commit_control(&mut self, record: &VerifiedRecord) -> Result<(), Denial> {
        let Body::Control(control) = record.body() else {
            return Err(Denial::Kind);
        };
        if control.directory != self.directory || control.realm != self.realm {
            return Err(Denial::Scope);
        }
        if self.records >= MAX_CONTROL_RECORDS {
            return Err(Denial::Capacity);
        }
        let chain = self.chains.entry(control.owner).or_default();
        if control.previous != chain.head {
            return Err(Denial::Previous);
        }
        if control.sequence != chain.sequence {
            return Err(Denial::Sequence);
        }
        match &control.action {
            CreateAction::GrantCreate {
                agent,
                agent_key,
                expires_at,
                maximum_charge,
                ..
            } => {
                chain.grants.insert(
                    record.id(),
                    OpenGrant {
                        agent: *agent,
                        agent_key: *agent_key,
                        expires_at: *expires_at,
                        maximum_charge: *maximum_charge,
                    },
                );
            }
            CreateAction::RevokeGrant { grant } => {
                if chain.grants.remove(grant).is_none() {
                    return Err(Denial::Grant);
                }
            }
        }
        chain.head = Some(record.id());
        chain.sequence = chain.sequence.checked_add(1).ok_or(Denial::Sequence)?;
        chain.history.push(record.clone());
        self.records += 1;
        Ok(())
    }

    /// Restore one previously admitted control record from a trusted local
    /// snapshot. Order, scope and grant mutations are re-checked; the social
    /// basis and expiry were assessed when the record first entered the
    /// agreed log and are not re-derived from the current view.
    pub(crate) fn restore_record(&mut self, record: &VerifiedRecord) -> Result<(), Denial> {
        self.commit_control(record)
    }

    /// Iterate each owner's retained control records in agreed chain order.
    /// The records are the durable manifest a snapshot persists.
    pub(crate) fn histories(&self) -> impl Iterator<Item = (OwnerId, &[VerifiedRecord])> + '_ {
        self.chains
            .iter()
            .map(|(owner, chain)| (*owner, chain.history.as_slice()))
    }

    /// Re-evaluate a verified creation intent against current state inside
    /// the caller's atomic registration step. The borrowed result cannot
    /// survive a state change as a reusable admission token.
    pub fn assess_creation<'a>(
        &'a self,
        intent: &'a CreationIntent,
        view: &ControlView<'_>,
        now: u64,
    ) -> Result<Admission<'a>, Denial> {
        if intent.directory != self.directory || intent.realm != self.realm {
            return Err(Denial::Scope);
        }
        Self::owner_status(view, intent.owner, intent.social_control, &intent.owner_key)?;
        Self::agent_status(view, intent.owner, intent.agent, &intent.agent_key)?;
        let chain = self
            .chains
            .get(&intent.owner)
            .ok_or(Denial::StaleRoomBasis)?;
        if chain.head != Some(intent.room_control) {
            return Err(Denial::StaleRoomBasis);
        }
        let grant = chain.grants.get(&intent.grant).ok_or(Denial::Grant)?;
        if grant.agent != intent.agent || grant.agent_key != intent.agent_key {
            return Err(Denial::GrantAgent);
        }
        if grant.expires_at <= now || intent.expires_at <= now {
            return Err(Denial::Expired);
        }
        if intent.charge > grant.maximum_charge {
            return Err(Denial::Charge);
        }
        Ok(Admission {
            intent,
            grant: &intent.grant,
        })
    }

    /// Re-evaluate the authority claims of a verified room update. The
    /// room's own revision chain (`update.previous`) is the caller's state;
    /// this checks only scope, social basis, controller key and expiry.
    pub fn assess_update(
        &self,
        update: &RoomUpdate,
        view: &ControlView<'_>,
        now: u64,
    ) -> Result<(), Denial> {
        if update.directory != self.directory || update.realm != self.realm {
            return Err(Denial::Scope);
        }
        Self::owner_status(
            view,
            update.owner,
            update.social_control,
            &update.controller_key,
        )?;
        if update.expires_at <= now {
            return Err(Denial::Expired);
        }
        Ok(())
    }

    /// Canonical committed snapshot of every input an admission decision can
    /// depend on: each authenticated owner's accepted head, controller key and
    /// status flags, each authenticated agent's affiliation, key and lifecycle
    /// flags, and each owner's accepted room-control head with its open grants.
    /// A consensus frontier binds this digest as its control commitment; any
    /// change that could flip an admission changes the digest.
    #[must_use]
    pub fn snapshot(&self, view: &ControlView<'_>) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"vhalla/rooms/control-snapshot/v1\0");
        hash.update(self.directory.as_bytes());
        hash.update(self.realm.0.to_be_bytes());
        let owners: usize = view.owners().count();
        hash.update((owners as u32).to_be_bytes());
        for (owner, status) in view.owners() {
            hash.update(owner.as_bytes());
            hash.update(status.head().map_or([0; 32], |id| *id.as_bytes()));
            hash.update(status.key().unwrap_or([0; 32]));
            hash.update([u8::from(status.frozen())
                | u8::from(status.incomplete()) << 1
                | u8::from(status.capacity_blocked()) << 2
                | u8::from(!view.owner_history_complete(owner)) << 3]);
        }
        let agents: usize = view.agents().count();
        hash.update((agents as u32).to_be_bytes());
        for (agent, status) in view.agents() {
            hash.update(agent.as_bytes());
            hash.update(status.owner().as_bytes());
            hash.update(status.key());
            hash.update([u8::from(status.retired()) | u8::from(status.active()) << 1]);
        }
        hash.update((self.chains.len() as u32).to_be_bytes());
        for (owner, chain) in &self.chains {
            hash.update(owner.as_bytes());
            hash.update(chain.head.map_or([0; 32], |id| *id.as_bytes()));
            hash.update(chain.sequence.to_be_bytes());
            hash.update((chain.grants.len() as u32).to_be_bytes());
            for (grant, open) in &chain.grants {
                hash.update(grant.as_bytes());
                hash.update(open.agent.as_bytes());
                hash.update(open.agent_key);
                hash.update(open.expires_at.to_be_bytes());
                hash.update(open.maximum_charge.to_be_bytes());
            }
        }
        hash.finalize().into()
    }
}
