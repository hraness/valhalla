#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Bounded canonical event history and derived checkpoint roots.
//!
//! This crate is intentionally below quorum, persistence, and host authority.
//! It refuses caller-supplied roots unless they are derived from its retained
//! linear history, and it fails closed when the history bound is exhausted.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use sha2::{Digest, Sha256};
use vhalla_core::{Epoch, PeerId, RealmId, Sequence};

const EVENT_DOMAIN: &[u8] = b"vhalla/ledger/event/v1";
const ROOT_DOMAIN: &[u8] = b"vhalla/ledger/root/v1";
/// Maximum event payload accepted by this reference production seam.
pub const MAX_PAYLOAD: usize = 1024;

/// A derived content address for an event.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EventDigest(pub [u8; 32]);

/// A derived state root for a canonical event frontier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StateRoot(pub [u8; 32]);

/// One bounded event in a realm/epoch history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Event {
    /// Content address of the complete event transcript.
    pub id: EventDigest,
    /// The preceding event, or `None` for the first event.
    pub parent: Option<EventDigest>,
    /// Realm namespace.
    pub realm: RealmId,
    /// Membership/policy epoch.
    pub epoch: Epoch,
    /// Event author.
    pub actor: PeerId,
    /// Monotonic actor sequence.
    pub sequence: Sequence,
    /// Opaque bounded event data.
    pub payload: Vec<u8>,
}

impl Event {
    /// Construct and content-address an event.
    #[must_use]
    pub fn new(
        parent: Option<EventDigest>,
        realm: RealmId,
        epoch: Epoch,
        actor: PeerId,
        sequence: Sequence,
        payload: Vec<u8>,
    ) -> Self {
        let id = EventDigest(hash_event(parent, realm, epoch, actor, sequence, &payload));
        Self {
            id,
            parent,
            realm,
            epoch,
            actor,
            sequence,
            payload,
        }
    }
}

/// A checkpoint claim that must be derived from the current ledger state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Checkpoint {
    /// Realm namespace.
    pub realm: RealmId,
    /// Membership/policy epoch.
    pub epoch: Epoch,
    /// Current event frontier.
    pub head: EventDigest,
    /// Derived root of the canonical ancestor chain.
    pub state_root: StateRoot,
    /// Number of parent links from the root event.
    pub height: u64,
}

/// Fail-closed ledger errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The event payload exceeds [`MAX_PAYLOAD`].
    PayloadTooLarge,
    /// The event content address is invalid.
    InvalidEventId,
    /// The event belongs to another realm or epoch.
    WrongContext,
    /// The parent is not the current tip.
    UnknownOrForkedParent,
    /// The event ID already exists.
    DuplicateEvent,
    /// The bounded history cannot retain another event.
    Capacity,
    /// The requested head is not retained.
    UnknownHead,
    /// The supplied root is not derived from retained history.
    RootMismatch,
    /// The supplied height is wrong.
    HeightMismatch,
    /// The checkpoint is older than the current tip.
    StaleCheckpoint,
    /// A different checkpoint was already accepted.
    ConflictingCheckpoint,
}

/// A bounded, single-tip event ledger.
pub struct Ledger {
    realm: RealmId,
    epoch: Epoch,
    max_events: usize,
    events: BTreeMap<EventDigest, Event>,
    head: Option<EventDigest>,
    checkpoint: Option<Checkpoint>,
}

impl Ledger {
    /// Create an empty ledger with an explicit event bound.
    #[must_use]
    pub fn new(realm: RealmId, epoch: Epoch, max_events: usize) -> Self {
        Self {
            realm,
            epoch,
            max_events,
            events: BTreeMap::new(),
            head: None,
            checkpoint: None,
        }
    }

    /// Append an event only when it extends the current tip.
    pub fn append(&mut self, event: Event) -> Result<(), Error> {
        if event.payload.len() > MAX_PAYLOAD {
            return Err(Error::PayloadTooLarge);
        }
        if event.realm != self.realm || event.epoch != self.epoch {
            return Err(Error::WrongContext);
        }
        if event.id
            != EventDigest(hash_event(
                event.parent,
                event.realm,
                event.epoch,
                event.actor,
                event.sequence,
                &event.payload,
            ))
        {
            return Err(Error::InvalidEventId);
        }
        if self.events.contains_key(&event.id) {
            return Err(Error::DuplicateEvent);
        }
        if event.parent != self.head {
            return Err(Error::UnknownOrForkedParent);
        }
        if self.events.len() >= self.max_events {
            return Err(Error::Capacity);
        }
        self.head = Some(event.id);
        self.events.insert(event.id, event);
        Ok(())
    }

    /// Derive a root from the complete retained ancestor chain for `head`.
    pub fn state_root(&self, head: EventDigest) -> Result<StateRoot, Error> {
        let chain = self.chain(head)?;
        let mut bytes = Vec::with_capacity(ROOT_DOMAIN.len() + 32 * chain.len() + 32);
        bytes.extend_from_slice(ROOT_DOMAIN);
        put_u128(&mut bytes, self.realm.0);
        put_u64(&mut bytes, self.epoch.0);
        put_u64(&mut bytes, chain.len() as u64);
        for event in chain {
            bytes.extend_from_slice(&event.id.0);
        }
        Ok(StateRoot(hash(&bytes)))
    }

    /// Accept a checkpoint only when it names the current tip and derived root.
    pub fn accept_checkpoint(&mut self, checkpoint: Checkpoint) -> Result<(), Error> {
        if checkpoint.realm != self.realm || checkpoint.epoch != self.epoch {
            return Err(Error::WrongContext);
        }
        if self.head != Some(checkpoint.head) {
            return Err(Error::StaleCheckpoint);
        }
        if self.state_root(checkpoint.head)? != checkpoint.state_root {
            return Err(Error::RootMismatch);
        }
        let expected_height = self.chain(checkpoint.head)?.len().saturating_sub(1) as u64;
        if checkpoint.height != expected_height {
            return Err(Error::HeightMismatch);
        }
        if let Some(previous) = self.checkpoint {
            if previous == checkpoint {
                return Ok(());
            }
            return Err(Error::ConflictingCheckpoint);
        }
        self.checkpoint = Some(checkpoint);
        Ok(())
    }

    /// Return the current event frontier.
    #[must_use]
    pub fn head(&self) -> Option<EventDigest> {
        self.head
    }

    /// Return the accepted checkpoint, if any.
    #[must_use]
    pub fn checkpoint(&self) -> Option<Checkpoint> {
        self.checkpoint
    }

    /// Return the number of retained events.
    #[must_use]
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    fn chain(&self, head: EventDigest) -> Result<Vec<&Event>, Error> {
        let mut reverse = Vec::new();
        let mut current = Some(head);
        while let Some(id) = current {
            let event = self.events.get(&id).ok_or(Error::UnknownHead)?;
            current = event.parent;
            reverse.push(event);
            if reverse.len() > self.events.len() {
                return Err(Error::UnknownHead);
            }
        }
        reverse.reverse();
        Ok(reverse)
    }
}

fn hash_event(
    parent: Option<EventDigest>,
    realm: RealmId,
    epoch: Epoch,
    actor: PeerId,
    sequence: Sequence,
    payload: &[u8],
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(EVENT_DOMAIN.len() + 96 + payload.len());
    bytes.extend_from_slice(EVENT_DOMAIN);
    match parent {
        Some(parent) => {
            bytes.push(1);
            bytes.extend_from_slice(&parent.0);
        }
        None => bytes.push(0),
    }
    put_u128(&mut bytes, realm.0);
    put_u64(&mut bytes, epoch.0);
    put_u128(&mut bytes, actor.0);
    put_u64(&mut bytes, sequence.0);
    put_u64(&mut bytes, payload.len() as u64);
    bytes.extend_from_slice(payload);
    hash(&bytes)
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u128(out: &mut Vec<u8>, value: u128) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn ledger() -> Ledger {
        Ledger::new(RealmId(1), Epoch(2), 8)
    }

    fn event(parent: Option<EventDigest>, sequence: u64, payload: &[u8]) -> Event {
        Event::new(
            parent,
            RealmId(1),
            Epoch(2),
            PeerId(3),
            Sequence(sequence),
            payload.to_vec(),
        )
    }

    #[test]
    fn root_and_checkpoint_are_derived_from_current_tip() {
        let mut ledger = ledger();
        let first = event(None, 1, b"one");
        ledger.append(first.clone()).unwrap();
        let second = event(Some(first.id), 2, b"two");
        ledger.append(second.clone()).unwrap();
        let checkpoint = Checkpoint {
            realm: RealmId(1),
            epoch: Epoch(2),
            head: second.id,
            state_root: ledger.state_root(second.id).unwrap(),
            height: 1,
        };
        ledger.accept_checkpoint(checkpoint).unwrap();
        assert_eq!(ledger.accept_checkpoint(checkpoint), Ok(()));
    }

    #[test]
    fn forged_roots_forks_stale_heads_and_wrong_context_fail_closed() {
        let mut ledger = ledger();
        let first = event(None, 1, b"one");
        ledger.append(first.clone()).unwrap();
        assert_eq!(
            ledger.accept_checkpoint(Checkpoint {
                realm: RealmId(1),
                epoch: Epoch(2),
                head: first.id,
                state_root: StateRoot([0; 32]),
                height: 0,
            }),
            Err(Error::RootMismatch)
        );
        let second = event(Some(first.id), 2, b"two");
        ledger.append(second.clone()).unwrap();
        assert_eq!(
            ledger.append(event(Some(first.id), 3, b"fork")),
            Err(Error::UnknownOrForkedParent)
        );
        assert_eq!(
            ledger.accept_checkpoint(Checkpoint {
                realm: RealmId(1),
                epoch: Epoch(2),
                head: first.id,
                state_root: ledger.state_root(first.id).unwrap(),
                height: 0,
            }),
            Err(Error::StaleCheckpoint)
        );
        let wrong = Event::new(
            None,
            RealmId(9),
            Epoch(2),
            PeerId(3),
            Sequence(1),
            b"x".to_vec(),
        );
        assert_eq!(ledger.append(wrong), Err(Error::WrongContext));
    }

    #[test]
    fn capacity_and_tampering_do_not_mutate_history() {
        let mut ledger = Ledger::new(RealmId(1), Epoch(2), 1);
        let first = event(None, 1, b"one");
        ledger.append(first.clone()).unwrap();
        let mut forged = first.clone();
        forged.payload = b"tampered".to_vec();
        assert_eq!(ledger.append(forged), Err(Error::InvalidEventId));
        assert_eq!(ledger.event_count(), 1);
        assert_eq!(
            ledger.append(event(Some(first.id), 2, b"two")),
            Err(Error::Capacity)
        );
    }

    proptest! {
        #[test]
        fn bounded_linear_schedules_preserve_deterministic_roots(
            payloads in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..32), 1..8)
        ) {
            let mut left = ledger();
            let mut right = ledger();
            let mut parent = None;
            for (index, payload) in payloads.iter().enumerate() {
                let current = event(parent, index as u64 + 1, payload);
                let duplicate = current.clone();
                prop_assert_eq!(left.append(current.clone()), Ok(()));
                prop_assert_eq!(right.append(duplicate), Ok(()));
                parent = Some(current.id);
            }
            prop_assert_eq!(left.head(), right.head());
            prop_assert_eq!(left.state_root(parent.unwrap()), right.state_root(parent.unwrap()));
        }
    }
}
