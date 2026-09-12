//! Reference multiplayer session semantics for Valhalla games.
//!
//! The prototype compares single-host and threshold-checkpoint authority while
//! keeping game inputs signed/content-addressed at the protocol boundary.

use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Peer(pub u64);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EventId(pub u64);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GameEvent {
    pub id: EventId,
    pub author: Peer,
    pub parent: Option<EventId>,
    pub action: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Authority {
    Single(Peer),
    Quorum { threshold: usize },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Checkpoint {
    pub state_hash: u64,
    pub head: EventId,
    pub approvals: BTreeSet<Peer>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionError {
    UnknownParent,
    DuplicateEvent,
    UnauthorizedCheckpoint,
    ConflictingCheckpoint,
}

pub struct Session {
    authority: Authority,
    events: BTreeMap<EventId, GameEvent>,
    checkpoint: Option<Checkpoint>,
}

impl Session {
    pub fn new(authority: Authority) -> Self {
        Self {
            authority,
            events: BTreeMap::new(),
            checkpoint: None,
        }
    }

    pub fn append(&mut self, event: GameEvent) -> Result<(), SessionError> {
        if self.events.contains_key(&event.id) {
            return Err(SessionError::DuplicateEvent);
        }
        if event
            .parent
            .is_some_and(|parent| !self.events.contains_key(&parent))
        {
            return Err(SessionError::UnknownParent);
        }
        self.events.insert(event.id, event);
        Ok(())
    }

    pub fn accept_checkpoint(&mut self, checkpoint: Checkpoint) -> Result<(), SessionError> {
        if !self.events.contains_key(&checkpoint.head) {
            return Err(SessionError::UnknownParent);
        }
        let authorized = match self.authority {
            Authority::Single(owner) => checkpoint.approvals.contains(&owner),
            Authority::Quorum { threshold } => checkpoint.approvals.len() >= threshold,
        };
        if !authorized {
            return Err(SessionError::UnauthorizedCheckpoint);
        }
        if self
            .checkpoint
            .as_ref()
            .is_some_and(|current| current.state_hash != checkpoint.state_hash)
        {
            return Err(SessionError::ConflictingCheckpoint);
        }
        self.checkpoint = Some(checkpoint);
        Ok(())
    }

    pub fn checkpoint(&self) -> Option<&Checkpoint> {
        self.checkpoint.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(id: u64, author: u64, parent: Option<u64>) -> GameEvent {
        GameEvent {
            id: EventId(id),
            author: Peer(author),
            parent: parent.map(EventId),
            action: id as u8,
        }
    }

    #[test]
    fn session_accepts_only_authorized_checkpoints() {
        let mut session = Session::new(Authority::Quorum { threshold: 2 });
        session.append(event(1, 1, None)).unwrap();
        let mut one = BTreeSet::new();
        one.insert(Peer(1));
        assert_eq!(
            session.accept_checkpoint(Checkpoint {
                state_hash: 10,
                head: EventId(1),
                approvals: one,
            }),
            Err(SessionError::UnauthorizedCheckpoint)
        );
        let mut two = BTreeSet::new();
        two.extend([Peer(1), Peer(2)]);
        assert_eq!(
            session.accept_checkpoint(Checkpoint {
                state_hash: 10,
                head: EventId(1),
                approvals: two,
            }),
            Ok(())
        );
    }

    #[test]
    fn conflicting_finalized_state_is_not_silently_replaced() {
        let mut session = Session::new(Authority::Single(Peer(1)));
        session.append(event(1, 1, None)).unwrap();
        let approvals = BTreeSet::from([Peer(1)]);
        session
            .accept_checkpoint(Checkpoint {
                state_hash: 10,
                head: EventId(1),
                approvals: approvals.clone(),
            })
            .unwrap();
        assert_eq!(
            session.accept_checkpoint(Checkpoint {
                state_hash: 11,
                head: EventId(1),
                approvals
            }),
            Err(SessionError::ConflictingCheckpoint)
        );
    }
}
