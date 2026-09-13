//! Differentiated collective/session reference model.
//!
//! Members retain local budgets and state while a collective records shared
//! checkpoints. A failed member is explicit state, never an implicit authority
//! transfer or deletion of its prior evidence.

use std::collections::{BTreeMap, BTreeSet};

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
    pub state_root: u64,
    pub approvals: BTreeSet<CellId>,
    pub unresolved: BTreeSet<CellId>,
}

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
}

pub struct Collective {
    threshold: usize,
    cells: BTreeMap<CellId, Cell>,
    events: BTreeMap<u64, Event>,
    checkpoint: Option<Checkpoint>,
    invalid_membership: bool,
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
        }
    }

    pub fn append(&mut self, event: Event) -> Result<(), Error> {
        if self.invalid_membership {
            return Err(Error::InvalidMembership);
        }
        if self.events.contains_key(&event.id) {
            return Err(Error::DuplicateEvent);
        }
        if event
            .parent
            .is_some_and(|id| !self.events.contains_key(&id))
        {
            return Err(Error::UnknownParent);
        }
        let cell = self.cells.get_mut(&event.cell).ok_or(Error::UnknownCell)?;
        if !cell.alive {
            return Err(Error::DeadCell);
        }
        if cell.budget < event.cost {
            return Err(Error::Budget);
        }
        cell.budget -= event.cost;
        self.events.insert(event.id, event);
        Ok(())
    }

    pub fn fail(&mut self, cell: CellId) -> Result<(), Error> {
        if self.invalid_membership {
            return Err(Error::InvalidMembership);
        }
        self.cells.get_mut(&cell).ok_or(Error::UnknownCell)?.alive = false;
        Ok(())
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
        if !self.events.contains_key(&checkpoint.head) {
            return Err(Error::UnknownParent);
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
            .is_some_and(|old| old.state_root != checkpoint.state_root)
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
        collective
            .accept_checkpoint(Checkpoint {
                head: 1,
                state_root: 99,
                approvals,
                unresolved: unresolved.clone(),
            })
            .unwrap();
        assert_eq!(collective.checkpoint().unwrap().unresolved, unresolved);
        assert_eq!(
            collective.accept_checkpoint(Checkpoint {
                head: 1,
                state_root: 100,
                approvals: BTreeSet::from([CellId(1), CellId(2)]),
                unresolved
            }),
            Err(Error::Conflict)
        );
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
