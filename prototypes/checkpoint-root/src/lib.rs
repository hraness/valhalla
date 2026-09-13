//! Derived checkpoint and state-root reference model.
//!
//! The model makes a checkpoint verifiable from the event history it names:
//! the state root is derived from the canonical ancestor chain, and a new
//! checkpoint must extend the accepted head. This is intentionally a local
//! model; it does not provide consensus, durable storage, or signatures.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

const EVENT_DOMAIN: &[u8] = b"valhalla/checkpoint-root/event/v1";
const STATE_DOMAIN: &[u8] = b"valhalla/checkpoint-root/state/v1";
const MAX_PAYLOAD: usize = 1024;

/// A content address for an event.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EventId(pub [u8; 32]);

/// A derived state root.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StateRoot(pub [u8; 32]);

/// An event in the single-parent history used by this prototype.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Event {
    pub id: EventId,
    pub parent: Option<EventId>,
    pub actor: u64,
    pub sequence: u64,
    pub payload: Vec<u8>,
}

impl Event {
    /// Construct and content-address an event. The parent must be known to a
    /// [`History`] before it can be appended.
    #[must_use]
    pub fn new(parent: Option<EventId>, actor: u64, sequence: u64, payload: Vec<u8>) -> Self {
        let id = EventId(hash_event(parent, actor, sequence, &payload));
        Self {
            id,
            parent,
            actor,
            sequence,
            payload,
        }
    }
}

/// A checkpoint claims that `head` and its derived root are the accepted view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Checkpoint {
    pub head: EventId,
    pub state_root: StateRoot,
    pub height: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reject {
    InvalidPayload,
    InvalidId,
    UnknownParent,
    DuplicateEvent,
    Capacity,
    UnknownHead,
    RootMismatch,
    HeightMismatch,
    NotDescendant,
    ConflictingCheckpoint,
}

/// A bounded event history with a monotonic accepted checkpoint head.
pub struct History {
    max_events: usize,
    events: BTreeMap<EventId, Event>,
    accepted: Option<Checkpoint>,
}

impl History {
    #[must_use]
    pub fn new(max_events: usize) -> Self {
        Self {
            max_events,
            events: BTreeMap::new(),
            accepted: None,
        }
    }

    /// Append an event after verifying its content address and parent.
    pub fn append(&mut self, event: Event) -> Result<(), Reject> {
        if event.payload.len() > MAX_PAYLOAD {
            return Err(Reject::InvalidPayload);
        }
        if event.id
            != EventId(hash_event(
                event.parent,
                event.actor,
                event.sequence,
                &event.payload,
            ))
        {
            return Err(Reject::InvalidId);
        }
        if event
            .parent
            .is_some_and(|parent| !self.events.contains_key(&parent))
        {
            return Err(Reject::UnknownParent);
        }
        if self.events.contains_key(&event.id) {
            return Err(Reject::DuplicateEvent);
        }
        if self.events.len() >= self.max_events {
            return Err(Reject::Capacity);
        }
        self.events.insert(event.id, event);
        Ok(())
    }

    /// Derive the canonical root for an event and its complete ancestor chain.
    pub fn state_root(&self, head: EventId) -> Result<StateRoot, Reject> {
        let chain = self.chain(head)?;
        let mut bytes = Vec::with_capacity(STATE_DOMAIN.len() + chain.len() * 32 + 8);
        bytes.extend_from_slice(STATE_DOMAIN);
        put_u64(&mut bytes, chain.len() as u64);
        for id in chain {
            bytes.extend_from_slice(&id.0);
        }
        Ok(StateRoot(hash(&bytes)))
    }

    /// Accept a checkpoint only when its root is derived and its head extends
    /// the currently accepted head. A same-head identical checkpoint is idempotent.
    pub fn accept_checkpoint(&mut self, checkpoint: Checkpoint) -> Result<(), Reject> {
        let derived = self.state_root(checkpoint.head)?;
        if derived != checkpoint.state_root {
            return Err(Reject::RootMismatch);
        }
        let chain = self.chain(checkpoint.head)?;
        let expected_height = chain.len().saturating_sub(1) as u64;
        if checkpoint.height != expected_height {
            return Err(Reject::HeightMismatch);
        }
        if let Some(old) = self.accepted {
            if old == checkpoint {
                return Ok(());
            }
            if old.state_root == checkpoint.state_root && old.head != checkpoint.head {
                return Err(Reject::ConflictingCheckpoint);
            }
            if !self.is_ancestor(old.head, checkpoint.head)? {
                return Err(Reject::NotDescendant);
            }
            if checkpoint.height <= old.height {
                return Err(Reject::HeightMismatch);
            }
        }
        self.accepted = Some(checkpoint);
        Ok(())
    }

    #[must_use]
    pub fn accepted(&self) -> Option<Checkpoint> {
        self.accepted
    }

    #[must_use]
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    fn chain(&self, head: EventId) -> Result<Vec<EventId>, Reject> {
        let mut reverse = Vec::new();
        let mut current = Some(head);
        while let Some(id) = current {
            let event = self.events.get(&id).ok_or(Reject::UnknownHead)?;
            reverse.push(id);
            current = event.parent;
            if reverse.len() > self.events.len() {
                // Defensive bound for malformed future storage implementations.
                return Err(Reject::UnknownHead);
            }
        }
        reverse.reverse();
        Ok(reverse)
    }

    fn is_ancestor(&self, ancestor: EventId, descendant: EventId) -> Result<bool, Reject> {
        Ok(self.chain(descendant)?.contains(&ancestor))
    }
}

fn hash_event(parent: Option<EventId>, actor: u64, sequence: u64, payload: &[u8]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(EVENT_DOMAIN.len() + 32 + 24 + payload.len());
    bytes.extend_from_slice(EVENT_DOMAIN);
    match parent {
        Some(id) => {
            bytes.push(1);
            bytes.extend_from_slice(&id.0);
        }
        None => bytes.push(0),
    }
    put_u64(&mut bytes, actor);
    put_u64(&mut bytes, sequence);
    put_bytes(&mut bytes, payload);
    hash(&bytes)
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u64(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn history() -> (History, Event, Event) {
        let mut h = History::new(8);
        let root = Event::new(None, 1, 0, b"root".to_vec());
        h.append(root.clone()).unwrap();
        let child = Event::new(Some(root.id), 2, 1, b"child".to_vec());
        h.append(child.clone()).unwrap();
        (h, root, child)
    }

    #[test]
    fn root_is_derived_and_checkpoint_must_extend_current_head() {
        let (mut h, root, child) = history();
        let root_cp = Checkpoint {
            head: root.id,
            state_root: h.state_root(root.id).unwrap(),
            height: 0,
        };
        h.accept_checkpoint(root_cp).unwrap();
        let child_cp = Checkpoint {
            head: child.id,
            state_root: h.state_root(child.id).unwrap(),
            height: 1,
        };
        h.accept_checkpoint(child_cp).unwrap();
        assert_eq!(h.accepted(), Some(child_cp));
    }

    #[test]
    fn forged_root_and_fork_are_rejected() {
        let (mut h, root, child) = history();
        h.accept_checkpoint(Checkpoint {
            head: root.id,
            state_root: StateRoot([7; 32]),
            height: 0,
        })
        .unwrap_err();
        let root_cp = Checkpoint {
            head: root.id,
            state_root: h.state_root(root.id).unwrap(),
            height: 0,
        };
        h.accept_checkpoint(root_cp).unwrap();
        let fork = Event::new(Some(root.id), 3, 1, b"fork".to_vec());
        h.append(fork.clone()).unwrap();
        let child_cp = Checkpoint {
            head: child.id,
            state_root: h.state_root(child.id).unwrap(),
            height: 1,
        };
        h.accept_checkpoint(child_cp).unwrap();
        let fork_cp = Checkpoint {
            head: fork.id,
            state_root: h.state_root(fork.id).unwrap(),
            height: 1,
        };
        assert_eq!(h.accept_checkpoint(fork_cp), Err(Reject::NotDescendant));
        assert_eq!(h.accepted(), Some(child_cp));
        assert!(h.state_root(child.id).is_ok());
    }

    #[test]
    fn canonical_root_is_idempotent_for_same_history() {
        let (h, _, child) = history();
        assert_eq!(h.state_root(child.id), h.state_root(child.id));
    }

    proptest! {
        #[test]
        fn arbitrary_payloads_have_stable_derived_roots(payload in prop::collection::vec(any::<u8>(), 0..MAX_PAYLOAD)) {
            let mut h = History::new(2);
            let root = Event::new(None, 42, 0, payload);
            prop_assert!(h.append(root.clone()).is_ok());
            let first = h.state_root(root.id).unwrap();
            let second = h.state_root(root.id).unwrap();
            prop_assert_eq!(first, second);
            prop_assert_eq!(first.0.len(), 32);
        }
    }
}
