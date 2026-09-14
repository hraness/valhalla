//! Atomic creation batches for an engine-adapter experiment.
//!
//! These types prove deterministic local replay only. The initial directory and
//! opaque control binding are explicit fixture assumptions. There is no engine,
//! authenticated control snapshot, wire decoder, persistence or finality here.

use super::{Directory, Id, Proposal};
use alloc::vec::Vec;
use sha2::{Digest, Sha256};

/// Maximum creations replayed by a batch, checked before copying its proposals.
pub const MAX_BATCH: usize = 16;

/// A complete captured model frontier. Plain data, never a trust anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frontier {
    pub directory: Id,
    pub policy: Id,
    pub height: u64,
    pub value: Id,
    pub state: Id,
    pub control: Id,
    pub time: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Bounds,
    Parent,
    Control,
    Clock,
    Root,
    Height,
    Operation(super::Error),
}

/// An inert, bounded claimed transition. All supplied hashes remain untrusted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch {
    parent: Frontier,
    time: u64,
    proposals: Vec<Proposal>,
    result: Id,
}
impl Batch {
    pub fn new(
        parent: Frontier,
        time: u64,
        proposals: &[Proposal],
        result: Id,
    ) -> Result<Self, Error> {
        if proposals.is_empty() || proposals.len() > MAX_BATCH {
            return Err(Error::Bounds);
        }
        // Proposal signing already imposes field limits. Recheck before cloning
        // anyway, so a future decoder cannot accidentally bypass this bound.
        for proposal in proposals {
            proposal.draft.validate().map_err(Error::Operation)?;
        }
        Ok(Self {
            parent,
            time,
            proposals: proposals.to_vec(),
            result,
        })
    }
    pub fn parent(&self) -> Frontier {
        self.parent
    }
    pub fn time(&self) -> u64 {
        self.time
    }
    pub fn proposals(&self) -> &[Proposal] {
        &self.proposals
    }
    pub fn result(&self) -> Id {
        self.result
    }
    /// Full application value commitment, including order and exact signatures.
    pub fn value_id(&self) -> Id {
        let mut h = Sha256::new();
        h.update(b"vhalla/room-batch/spike-v1\0");
        hash_frontier(&mut h, self.parent);
        h.update(self.time.to_be_bytes());
        h.update((self.proposals.len() as u16).to_be_bytes());
        for proposal in &self.proposals {
            hash_proposal(&mut h, proposal);
        }
        h.update(self.result);
        h.finalize().into()
    }
}

/// Private immutable replay evidence. Not a consensus decision or host effect.
///
/// ```compile_fail
/// use vhalla_room_registry_spike::transition::{Batch, CheckedBatch};
/// fn bypass_replay(batch: Batch) -> CheckedBatch { batch.into() }
/// ```
///
/// ```compile_fail
/// use vhalla_room_registry_spike::transition::CheckedBatch;
/// fn alter(checked: &mut CheckedBatch) { checked.next.height = 0; }
/// ```
#[derive(Clone, Debug)]
#[must_use]
pub struct CheckedBatch {
    batch: Batch,
    next: Frontier,
    state: Directory,
}
impl CheckedBatch {
    pub fn batch(&self) -> &Batch {
        &self.batch
    }
    pub fn next(&self) -> Frontier {
        self.next
    }
}

/// In-memory adapter reference. Consuming the fixture prevents mutation of the
/// retained directory through a public mutable projection.
pub struct Application {
    state: Directory,
    frontier: Frontier,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Applied {
    New,
    Existing,
}

impl Application {
    /// Pin an explicitly supplied initial state and opaque control commitment.
    /// Its authenticity, maturity, freshness and any earned credit are assumed.
    /// Zero is rejected as a missing binding, not as an authentication check.
    pub fn from_fixture(state: Directory, control: Id) -> Result<Self, Error> {
        if control == [0; 32] {
            return Err(Error::Control);
        }
        let root = state_commitment(&state);
        let mut h = Sha256::new();
        h.update(b"vhalla/room-batch-genesis/spike-v1\0");
        h.update(root);
        h.update(control);
        let frontier = Frontier {
            directory: state.id,
            policy: state.policy_id,
            height: 0,
            value: h.finalize().into(),
            state: root,
            control,
            time: state.last_time,
        };
        Ok(Self { state, frontier })
    }
    pub fn frontier(&self) -> Frontier {
        self.frontier
    }
    pub fn directory(&self) -> &Directory {
        &self.state
    }

    /// Author a candidate by replaying the ordered batch on a bounded copy.
    /// Neither preparation nor checking changes visible local state.
    pub fn prepare(&self, time: u64, proposals: &[Proposal]) -> Result<CheckedBatch, Error> {
        let mut batch = Batch::new(self.frontier, time, proposals, [0; 32])?;
        let state = self.replay(&batch)?;
        batch.result = state_commitment(&state);
        self.checked(batch, state)
    }

    /// Independently replay a claimed root against the complete exact parent.
    /// A signature or majority vote cannot substitute for this application check.
    pub fn validate(&self, batch: &Batch) -> Result<CheckedBatch, Error> {
        let state = self.replay(batch)?;
        if state_commitment(&state) != batch.result {
            return Err(Error::Root);
        }
        self.checked(batch.clone(), state)
    }

    fn replay(&self, batch: &Batch) -> Result<Directory, Error> {
        if batch.parent != self.frontier {
            return Err(Error::Parent);
        }
        if batch.time < self.frontier.time {
            return Err(Error::Clock);
        }
        self.frontier.height.checked_add(1).ok_or(Error::Height)?;
        let mut state = self.state.clone();
        for proposal in &batch.proposals {
            state
                .finalize(proposal, batch.time)
                .map_err(Error::Operation)?;
        }
        Ok(state)
    }

    fn checked(&self, batch: Batch, state: Directory) -> Result<CheckedBatch, Error> {
        let next = Frontier {
            height: self.frontier.height.checked_add(1).ok_or(Error::Height)?,
            value: batch.value_id(),
            state: batch.result,
            time: batch.time,
            ..self.frontier
        };
        Ok(CheckedBatch { batch, next, state })
    }

    /// Simulate applying an externally ordered decision **locally only**.
    ///
    /// No public engine or room service may treat this method as finality. The
    /// future adapter must consume an actual engine decision, reverify its value,
    /// and durably store the application state before acknowledging next height.
    /// Exact uncertain retries are no-ops; different/stale transitions fail.
    pub fn apply_locally(&mut self, checked: CheckedBatch) -> Result<Applied, Error> {
        if checked.next == self.frontier {
            return Ok(Applied::Existing);
        }
        if checked.batch.parent != self.frontier {
            return Err(Error::Parent);
        }
        self.state = checked.state;
        self.frontier = checked.next;
        Ok(Applied::New)
    }
}

/// SHA-256 over every field that affects the model's future acceptance behavior.
/// Includes tombstones and exact signature bytes (retry identity uses them),
/// deduplication/evidence maps, time and revision. No lossy routing ID is used.
pub fn state_commitment(state: &Directory) -> Id {
    let mut h = Sha256::new();
    h.update(b"vhalla/room-state/spike-v1\0");
    h.update(state.id);
    h.update(state.policy_id);
    let mut policy = Vec::new();
    state.policy.encode(&mut policy);
    h.update(policy);
    h.update(state.last_time.to_be_bytes());
    h.update(state.revision.to_be_bytes());
    h.update((state.eligible.len() as u32).to_be_bytes());
    for source in &state.eligible {
        h.update(source);
    }
    h.update((state.support.len() as u32).to_be_bytes());
    for (beneficiary, source, epoch) in &state.support {
        h.update(beneficiary);
        h.update(source);
        h.update(epoch.to_be_bytes());
    }
    h.update((state.evidence.len() as u32).to_be_bytes());
    for (evidence, (beneficiary, source, epoch)) in &state.evidence {
        h.update(evidence);
        h.update(beneficiary);
        h.update(source);
        h.update(epoch.to_be_bytes());
    }
    h.update((state.accounts.len() as u32).to_be_bytes());
    for (owner, account) in &state.accounts {
        h.update(owner);
        h.update(account.earned.to_be_bytes());
        h.update(account.spent.to_be_bytes());
        h.update(account.lifetime_slots.to_be_bytes());
    }
    h.update((state.rooms.len() as u32).to_be_bytes());
    for (slug, room) in &state.rooms {
        h.update((slug.0.len() as u16).to_be_bytes());
        h.update(slug.0.as_bytes());
        hash_proposal(&mut h, &room.proposal);
        h.update(room.created_at.to_be_bytes());
        h.update([u8::from(room.archived)]);
    }
    h.finalize().into()
}

fn hash_proposal(h: &mut Sha256, proposal: &Proposal) {
    let bytes = proposal.draft.bytes();
    h.update((bytes.len() as u32).to_be_bytes());
    h.update(bytes);
    h.update(proposal.owner_signature);
    h.update(proposal.actor_signature);
}

fn hash_frontier(h: &mut Sha256, f: Frontier) {
    h.update(f.directory);
    h.update(f.policy);
    h.update(f.height.to_be_bytes());
    h.update(f.value);
    h.update(f.state);
    h.update(f.control);
    h.update(f.time.to_be_bytes());
}

#[cfg(test)]
mod tests;
