//! Differentiated collective/session reference model.
//!
//! Members retain local budgets and state while a collective records shared
//! checkpoints. A failed member is explicit state, never an implicit authority
//! transfer or deletion of its prior evidence.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

const STATE_ROOT_DOMAIN: &[u8] = b"valhalla/multicell/state-root/v1";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CellId(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Sensor,
    Builder,
    Arbiter,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cell {
    pub id: CellId,
    pub role: Role,
    pub budget: u64,
    pub alive: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Event {
    pub id: u64,
    pub cell: CellId,
    pub parent: Option<u64>,
    pub cost: u64,
    pub action: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Checkpoint {
    pub head: u64,
    pub state_root: StateRoot,
    pub approvals: BTreeSet<CellId>,
    pub unresolved: BTreeSet<CellId>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StateRoot(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    UnknownCell,
    DeadCell,
    DuplicateEvent,
    UnknownParent,
    Budget,
    Unauthorized,
    Conflict,
    InvalidMembership,
    Fork,
    StaleCheckpoint,
    RootMismatch,
    UnknownHead,
}

pub struct Collective {
    threshold: usize,
    cells: BTreeMap<CellId, Cell>,
    events: BTreeMap<u64, Event>,
    checkpoint: Option<Checkpoint>,
    invalid_membership: bool,
    current_head: Option<u64>,
    membership_epoch: u64,
}

impl Collective {
    pub fn new(threshold: usize, cells: impl IntoIterator<Item = Cell>) -> Self {
        let mut map = BTreeMap::new();
        let mut invalid_membership = false;
        for cell in cells {
            if map.insert(cell.id, cell).is_some() {
                invalid_membership = true;
            }
        }
        Self {
            threshold: threshold.max(1),
            cells: map,
            events: BTreeMap::new(),
            checkpoint: None,
            invalid_membership,
            current_head: None,
            membership_epoch: 0,
        }
    }

    pub fn append(&mut self, event: Event) -> Result<(), Error> {
        if self.invalid_membership {
            return Err(Error::InvalidMembership);
        }
        if self.events.contains_key(&event.id) {
            return Err(Error::DuplicateEvent);
        }
        match (self.current_head, event.parent) {
            (None, None) => {}
            (Some(head), Some(parent)) if parent == head => {}
            (None, Some(_)) => return Err(Error::UnknownParent),
            (Some(_), _) => return Err(Error::Fork),
        }
        let cell = self.cells.get_mut(&event.cell).ok_or(Error::UnknownCell)?;
        if !cell.alive {
            return Err(Error::DeadCell);
        }
        if cell.budget < event.cost {
            return Err(Error::Budget);
        }
        cell.budget -= event.cost;
        self.current_head = Some(event.id);
        self.events.insert(event.id, event);
        Ok(())
    }

    pub fn fail(&mut self, cell: CellId) -> Result<(), Error> {
        if self.invalid_membership {
            return Err(Error::InvalidMembership);
        }
        let member = self.cells.get_mut(&cell).ok_or(Error::UnknownCell)?;
        if member.alive {
            member.alive = false;
            self.membership_epoch = self.membership_epoch.saturating_add(1);
        }
        Ok(())
    }

    /// Derive a domain-separated state root from the accepted event chain and
    /// current member state. The caller cannot supply or mutate this digest.
    pub fn state_root(&self, head: u64) -> Result<StateRoot, Error> {
        let mut chain = Vec::new();
        let mut current = Some(head);
        while let Some(id) = current {
            let event = self.events.get(&id).ok_or(Error::UnknownHead)?;
            chain.push(*event);
            current = event.parent;
            if chain.len() > self.events.len() {
                return Err(Error::UnknownHead);
            }
        }
        chain.reverse();

        let mut bytes = Vec::with_capacity(STATE_ROOT_DOMAIN.len() + chain.len() * 48);
        bytes.extend_from_slice(STATE_ROOT_DOMAIN);
        put_u64(&mut bytes, self.threshold as u64);
        put_u64(&mut bytes, self.membership_epoch);
        put_u64(&mut bytes, chain.len() as u64);
        for event in chain {
            put_u64(&mut bytes, event.id);
            match event.parent {
                Some(parent) => {
                    bytes.push(1);
                    put_u64(&mut bytes, parent);
                }
                None => bytes.push(0),
            }
            put_u64(&mut bytes, event.cell.0);
            put_u64(&mut bytes, event.cost);
            bytes.push(event.action);
        }
        put_u64(&mut bytes, self.cells.len() as u64);
        for cell in self.cells.values() {
            put_u64(&mut bytes, cell.id.0);
            bytes.push(match cell.role {
                Role::Sensor => 0,
                Role::Builder => 1,
                Role::Arbiter => 2,
            });
            put_u64(&mut bytes, cell.budget);
            bytes.push(u8::from(cell.alive));
        }
        Ok(StateRoot(Sha256::digest(bytes).into()))
    }

    pub fn accept_checkpoint(&mut self, checkpoint: Checkpoint) -> Result<(), Error> {
        if self.invalid_membership {
            return Err(Error::InvalidMembership);
        }
        if checkpoint
            .unresolved
            .iter()
            .any(|id| !self.cells.contains_key(id))
        {
            return Err(Error::UnknownCell);
        }
        if self.current_head != Some(checkpoint.head) {
            return Err(Error::StaleCheckpoint);
        }
        if self.state_root(checkpoint.head)? != checkpoint.state_root {
            return Err(Error::RootMismatch);
        }
        let live_approvals = checkpoint
            .approvals
            .iter()
            .filter(|id| self.cells.get(id).is_some_and(|cell| cell.alive))
            .count();
        if live_approvals < self.threshold {
            return Err(Error::Unauthorized);
        }
        if self
            .checkpoint
            .as_ref()
            .is_some_and(|old| old != &checkpoint)
        {
            return Err(Error::Conflict);
        }
        self.checkpoint = Some(checkpoint);
        Ok(())
    }

    pub fn cell(&self, id: CellId) -> Option<Cell> {
        self.cells.get(&id).copied()
    }

    pub fn checkpoint(&self) -> Option<&Checkpoint> {
        self.checkpoint.as_ref()
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn cells() -> [Cell; 3] {
        [
            Cell {
                id: CellId(1),
                role: Role::Sensor,
                budget: 5,
                alive: true,
            },
            Cell {
                id: CellId(2),
                role: Role::Builder,
                budget: 5,
                alive: true,
            },
            Cell {
                id: CellId(3),
                role: Role::Arbiter,
                budget: 5,
                alive: true,
            },
        ]
    }

    #[test]
    fn local_failure_preserves_other_cells_and_history() {
        let mut collective = Collective::new(2, cells());
        collective
            .append(Event {
                id: 1,
                cell: CellId(1),
                parent: None,
                cost: 1,
                action: 7,
            })
            .unwrap();
        collective.fail(CellId(1)).unwrap();
        assert_eq!(collective.event_count(), 1);
        assert!(!collective.cell(CellId(1)).unwrap().alive);
        assert!(collective.cell(CellId(2)).unwrap().alive);
        assert!(collective
            .append(Event {
                id: 2,
                cell: CellId(2),
                parent: Some(1),
                cost: 1,
                action: 8
            })
            .is_ok());
    }

    #[test]
    fn checkpoint_quorum_uses_live_members_and_explicit_unresolved_set() {
        let mut collective = Collective::new(2, cells());
        collective
            .append(Event {
                id: 1,
                cell: CellId(1),
                parent: None,
                cost: 1,
                action: 7,
            })
            .unwrap();
        collective.fail(CellId(3)).unwrap();
        let approvals = BTreeSet::from([CellId(1), CellId(2), CellId(3)]);
        let unresolved = BTreeSet::from([CellId(3)]);
        let root = collective.state_root(1).unwrap();
        collective
            .accept_checkpoint(Checkpoint {
                head: 1,
                state_root: root,
                approvals,
                unresolved: unresolved.clone(),
            })
            .unwrap();
        assert_eq!(collective.checkpoint().unwrap().unresolved, unresolved);
        assert_eq!(
            collective.accept_checkpoint(Checkpoint {
                head: 1,
                state_root: root,
                approvals: BTreeSet::from([CellId(1), CellId(2)]),
                unresolved
            }),
            Err(Error::Conflict)
        );
    }

    #[test]
    fn forged_root_and_stale_or_forked_heads_are_rejected() {
        let mut collective = Collective::new(1, cells());
        collective
            .append(Event {
                id: 1,
                cell: CellId(1),
                parent: None,
                cost: 1,
                action: 1,
            })
            .unwrap();
        assert_eq!(
            collective.accept_checkpoint(Checkpoint {
                head: 1,
                state_root: StateRoot([0; 32]),
                approvals: BTreeSet::from([CellId(1)]),
                unresolved: BTreeSet::new(),
            }),
            Err(Error::RootMismatch)
        );
        collective
            .append(Event {
                id: 2,
                cell: CellId(2),
                parent: Some(1),
                cost: 1,
                action: 2,
            })
            .unwrap();
        assert_eq!(
            collective.accept_checkpoint(Checkpoint {
                head: 1,
                state_root: collective.state_root(1).unwrap(),
                approvals: BTreeSet::from([CellId(1)]),
                unresolved: BTreeSet::new(),
            }),
            Err(Error::StaleCheckpoint)
        );
        assert_eq!(
            collective.append(Event {
                id: 3,
                cell: CellId(3),
                parent: Some(1),
                cost: 1,
                action: 3,
            }),
            Err(Error::Fork)
        );
    }

    #[test]
    fn membership_epoch_changes_derived_root() {
        let mut collective = Collective::new(1, cells());
        collective
            .append(Event {
                id: 1,
                cell: CellId(1),
                parent: None,
                cost: 1,
                action: 1,
            })
            .unwrap();
        let before = collective.state_root(1).unwrap();
        collective.fail(CellId(2)).unwrap();
        assert_ne!(before, collective.state_root(1).unwrap());
    }

    #[test]
    fn budgets_and_duplicate_events_fail_closed() {
        let mut collective = Collective::new(1, cells());
        let event = Event {
            id: 1,
            cell: CellId(1),
            parent: None,
            cost: 5,
            action: 1,
        };
        collective.append(event).unwrap();
        assert_eq!(collective.append(event), Err(Error::DuplicateEvent));
        assert_eq!(
            collective.append(Event {
                id: 2,
                cell: CellId(1),
                parent: Some(1),
                cost: 1,
                action: 2
            }),
            Err(Error::Budget)
        );
    }

    proptest! {
        #[test]
        fn arbitrary_event_schedule_preserves_history_and_budget(
            costs in prop::collection::vec(0u8..8, 0..64),
            failures in prop::collection::vec(any::<bool>(), 0..64)
        ) {
            let mut collective = Collective::new(2, cells());
            let mut successful = 0usize;
            for (index, cost) in costs.into_iter().enumerate() {
                if failures.get(index).copied().unwrap_or(false) {
                    let _ = collective.fail(CellId(1));
                }
                let result = collective.append(Event {
                    id: index as u64 + 1,
                    cell: CellId(if index % 2 == 0 { 1 } else { 2 }),
                    parent: (index > 0).then_some(index as u64),
                    cost: u64::from(cost),
                    action: index as u8,
                });
                if result.is_ok() { successful += 1; }
                prop_assert_eq!(collective.event_count(), successful);
                for id in [CellId(1), CellId(2), CellId(3)] {
                    if let Some(cell) = collective.cell(id) {
                        prop_assert!(cell.budget <= 5);
                    }
                }
            }
        }
    }
}
