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
const SNAPSHOT_DOMAIN: &[u8] = b"vhalla/ledger/snapshot/v1";
const SNAPSHOT_VERSION: u8 = 1;
/// Maximum event payload accepted by this reference production seam.
pub const MAX_PAYLOAD: usize = 1024;
/// Hard ceiling on retained events, even when configuration supplies a larger value.
pub const MAX_EVENTS: usize = 4096;
/// Hard ceiling on an encoded, unauthenticated snapshot.
pub const MAX_SNAPSHOT_BYTES: usize = 16 * 1024 * 1024;

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
    /// The actor sequence is not newer than its last accepted sequence.
    NonMonotonicSequence,
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
    /// The snapshot exceeded [`MAX_SNAPSHOT_BYTES`].
    SnapshotTooLarge,
    /// The snapshot ended before a complete field could be decoded.
    TruncatedSnapshot,
    /// The snapshot has an unsupported version or domain.
    InvalidSnapshotHeader,
    /// The snapshot contains bytes after its canonical payload.
    TrailingSnapshot,
    /// A snapshot field exceeds its protocol bound.
    InvalidSnapshotBounds,
    /// The actor sequence map does not match the decoded event history.
    SnapshotSequenceMismatch,
    /// Snapshot map entries are not in strictly increasing actor order.
    NonCanonicalSnapshot,
}

/// A bounded, single-tip event ledger.
pub struct Ledger {
    realm: RealmId,
    epoch: Epoch,
    max_events: usize,
    events: BTreeMap<EventDigest, Event>,
    head: Option<EventDigest>,
    checkpoint: Option<Checkpoint>,
    last_sequences: BTreeMap<PeerId, Sequence>,
}

impl Ledger {
    /// Create an empty ledger with an explicit event bound.
    #[must_use]
    pub fn new(realm: RealmId, epoch: Epoch, max_events: usize) -> Self {
        Self {
            realm,
            epoch,
            max_events: max_events.min(MAX_EVENTS),
            events: BTreeMap::new(),
            head: None,
            checkpoint: None,
            last_sequences: BTreeMap::new(),
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
        if self
            .last_sequences
            .get(&event.actor)
            .is_some_and(|last| event.sequence.0 <= last.0)
        {
            return Err(Error::NonMonotonicSequence);
        }
        if event.parent != self.head {
            return Err(Error::UnknownOrForkedParent);
        }
        if self.events.len() >= self.max_events {
            return Err(Error::Capacity);
        }
        self.last_sequences.insert(event.actor, event.sequence);
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
        self.validate_retained_checkpoint(checkpoint)?;
        if let Some(previous) = self.checkpoint {
            if previous == checkpoint {
                return Ok(());
            }
            if checkpoint.height <= previous.height {
                return Err(Error::ConflictingCheckpoint);
            }
        }
        self.checkpoint = Some(checkpoint);
        Ok(())
    }

    /// Return the current event frontier.
    #[must_use]
    pub fn head(&self) -> Option<EventDigest> {
        self.head
    }

    /// Return the last locally accepted checkpoint, which may trail the tip.
    #[must_use]
    pub fn checkpoint(&self) -> Option<Checkpoint> {
        self.checkpoint
    }

    /// Return the number of retained events.
    #[must_use]
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Encode the complete retained state as bounded canonical bytes.
    ///
    /// The result is an unauthenticated serialization. Callers that persist or
    /// exchange it must wrap it in an authenticated storage/provenance layer.
    #[must_use]
    pub fn snapshot(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(SNAPSHOT_DOMAIN);
        bytes.push(SNAPSHOT_VERSION);
        put_u128(&mut bytes, self.realm.0);
        put_u64(&mut bytes, self.epoch.0);

        let chain = self
            .head
            .and_then(|head| self.chain(head).ok())
            .unwrap_or_default();
        put_u32(&mut bytes, chain.len() as u32);
        for event in chain {
            bytes.extend_from_slice(&event.id.0);
            match event.parent {
                Some(parent) => {
                    bytes.push(1);
                    bytes.extend_from_slice(&parent.0);
                }
                None => bytes.push(0),
            }
            put_u128(&mut bytes, event.realm.0);
            put_u64(&mut bytes, event.epoch.0);
            put_u128(&mut bytes, event.actor.0);
            put_u64(&mut bytes, event.sequence.0);
            put_u32(&mut bytes, event.payload.len() as u32);
            bytes.extend_from_slice(&event.payload);
        }

        match self.head {
            Some(head) => {
                bytes.push(1);
                bytes.extend_from_slice(&head.0);
            }
            None => bytes.push(0),
        }
        match self.checkpoint {
            Some(checkpoint) => {
                bytes.push(1);
                put_u128(&mut bytes, checkpoint.realm.0);
                put_u64(&mut bytes, checkpoint.epoch.0);
                bytes.extend_from_slice(&checkpoint.head.0);
                bytes.extend_from_slice(&checkpoint.state_root.0);
                put_u64(&mut bytes, checkpoint.height);
            }
            None => bytes.push(0),
        }

        put_u32(&mut bytes, self.last_sequences.len() as u32);
        for (actor, sequence) in &self.last_sequences {
            put_u128(&mut bytes, actor.0);
            put_u64(&mut bytes, sequence.0);
        }
        debug_assert!(bytes.len() <= MAX_SNAPSHOT_BYTES);
        bytes
    }

    /// Restore a ledger from canonical snapshot bytes under an explicit bound.
    ///
    /// Snapshot bytes are not authenticated or durable by this method. The
    /// caller must verify a signature/provenance receipt before treating them
    /// as trusted storage.
    pub fn restore(raw: &[u8], max_events: usize) -> Result<Self, Error> {
        if raw.len() > MAX_SNAPSHOT_BYTES {
            return Err(Error::SnapshotTooLarge);
        }
        let mut reader = SnapshotReader::new(raw);
        if reader.take(SNAPSHOT_DOMAIN.len())? != SNAPSHOT_DOMAIN
            || reader.u8()? != SNAPSHOT_VERSION
        {
            return Err(Error::InvalidSnapshotHeader);
        }
        let realm = RealmId(reader.u128()?);
        let epoch = Epoch(reader.u64()?);
        let effective_max = max_events.min(MAX_EVENTS);
        let event_count = reader.u32()? as usize;
        if event_count > effective_max || event_count > MAX_EVENTS {
            return Err(Error::InvalidSnapshotBounds);
        }
        let mut ledger = Self::new(realm, epoch, effective_max);
        for _ in 0..event_count {
            let id = EventDigest(reader.array32()?);
            let parent = match reader.u8()? {
                0 => None,
                1 => Some(EventDigest(reader.array32()?)),
                _ => return Err(Error::InvalidSnapshotBounds),
            };
            let event_realm = RealmId(reader.u128()?);
            let event_epoch = Epoch(reader.u64()?);
            let actor = PeerId(reader.u128()?);
            let sequence = Sequence(reader.u64()?);
            let payload_len = reader.u32()? as usize;
            if payload_len > MAX_PAYLOAD {
                return Err(Error::InvalidSnapshotBounds);
            }
            let payload = reader.take(payload_len)?.to_vec();
            ledger.append(Event {
                id,
                parent,
                realm: event_realm,
                epoch: event_epoch,
                actor,
                sequence,
                payload,
            })?;
        }

        let encoded_head = match reader.u8()? {
            0 => None,
            1 => Some(EventDigest(reader.array32()?)),
            _ => return Err(Error::InvalidSnapshotBounds),
        };
        if encoded_head != ledger.head {
            return Err(Error::UnknownHead);
        }

        let encoded_checkpoint = match reader.u8()? {
            0 => None,
            1 => Some(Checkpoint {
                realm: RealmId(reader.u128()?),
                epoch: Epoch(reader.u64()?),
                head: EventDigest(reader.array32()?),
                state_root: StateRoot(reader.array32()?),
                height: reader.u64()?,
            }),
            _ => return Err(Error::InvalidSnapshotBounds),
        };
        if let Some(checkpoint) = encoded_checkpoint {
            // A restored anchor may legitimately trail uncheckpointed events.
            // Replay above admits only one linear chain, so a retained head is
            // an ancestor of the current tip. Live admission still requires the tip.
            ledger.validate_retained_checkpoint(checkpoint)?;
            ledger.checkpoint = Some(checkpoint);
        }

        let sequence_count = reader.u32()? as usize;
        if sequence_count > event_count || sequence_count > MAX_EVENTS {
            return Err(Error::InvalidSnapshotBounds);
        }
        let mut encoded_sequences = BTreeMap::new();
        let mut previous_actor = None;
        for _ in 0..sequence_count {
            let actor = PeerId(reader.u128()?);
            let sequence = Sequence(reader.u64()?);
            if previous_actor.is_some_and(|previous| actor <= previous) {
                return Err(Error::NonCanonicalSnapshot);
            }
            previous_actor = Some(actor);
            if encoded_sequences.insert(actor, sequence).is_some() {
                return Err(Error::SnapshotSequenceMismatch);
            }
        }
        if encoded_sequences != ledger.last_sequences {
            return Err(Error::SnapshotSequenceMismatch);
        }
        if !reader.is_empty() {
            return Err(Error::TrailingSnapshot);
        }
        Ok(ledger)
    }

    /// Check context, root, and height against retained history without mutation.
    ///
    /// The checkpoint may trail the tip. Success establishes only consistency
    /// with this local linear history, not signatures, freshness, or authority.
    pub fn validate_retained_checkpoint(&self, checkpoint: Checkpoint) -> Result<(), Error> {
        if checkpoint.realm != self.realm || checkpoint.epoch != self.epoch {
            return Err(Error::WrongContext);
        }
        if self.state_root(checkpoint.head)? != checkpoint.state_root {
            return Err(Error::RootMismatch);
        }
        let height = self.chain(checkpoint.head)?.len().saturating_sub(1) as u64;
        if checkpoint.height != height {
            return Err(Error::HeightMismatch);
        }
        Ok(())
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

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u128(out: &mut Vec<u8>, value: u128) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

struct SnapshotReader<'a> {
    raw: &'a [u8],
    offset: usize,
}

impl<'a> SnapshotReader<'a> {
    fn new(raw: &'a [u8]) -> Self {
        Self { raw, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(Error::TruncatedSnapshot)?;
        if end > self.raw.len() {
            return Err(Error::TruncatedSnapshot);
        }
        let value = &self.raw[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("length checked"),
        ))
    }

    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("length checked"),
        ))
    }

    fn u128(&mut self) -> Result<u128, Error> {
        Ok(u128::from_be_bytes(
            self.take(16)?.try_into().expect("length checked"),
        ))
    }

    fn array32(&mut self) -> Result<[u8; 32], Error> {
        Ok(self.take(32)?.try_into().expect("length checked"))
    }

    fn is_empty(&self) -> bool {
        self.offset == self.raw.len()
    }
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

        let third = event(Some(second.id), 3, b"three");
        ledger.append(third.clone()).unwrap();
        let advanced = Checkpoint {
            realm: RealmId(1),
            epoch: Epoch(2),
            head: third.id,
            state_root: ledger.state_root(third.id).unwrap(),
            height: 2,
        };
        assert_eq!(ledger.accept_checkpoint(advanced), Ok(()));
        assert_eq!(ledger.checkpoint(), Some(advanced));
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

    #[test]
    fn actor_sequences_are_monotonic_and_bound_is_capped() {
        let mut ledger = Ledger::new(RealmId(1), Epoch(2), usize::MAX);
        let first = event(None, 2, b"one");
        ledger.append(first.clone()).unwrap();
        assert_eq!(
            ledger.append(event(Some(first.id), 2, b"repeat")),
            Err(Error::NonMonotonicSequence)
        );
        assert_eq!(
            ledger.append(event(Some(first.id), 1, b"rollback")),
            Err(Error::NonMonotonicSequence)
        );
    }

    #[test]
    fn snapshot_round_trip_preserves_history_and_checkpoint() {
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
        let restored = Ledger::restore(&ledger.snapshot(), 8).unwrap();
        assert_eq!(restored.event_count(), 2);
        assert_eq!(restored.head(), ledger.head());
        assert_eq!(restored.checkpoint(), Some(checkpoint));
        assert_eq!(restored.state_root(second.id), ledger.state_root(second.id));
    }

    #[test]
    fn snapshot_tamper_truncation_and_trailing_bytes_fail_closed() {
        let mut ledger = ledger();
        ledger.append(event(None, 1, b"one")).unwrap();
        let snapshot = ledger.snapshot();
        let mut bad_header = snapshot.clone();
        bad_header[0] ^= 1;
        assert!(matches!(
            Ledger::restore(&bad_header, 8),
            Err(Error::InvalidSnapshotHeader)
        ));
        let mut trailing = snapshot.clone();
        trailing.push(0);
        assert!(matches!(
            Ledger::restore(&trailing, 8),
            Err(Error::TrailingSnapshot)
        ));
        assert!(matches!(
            Ledger::restore(&snapshot[..snapshot.len() - 1], 8),
            Err(Error::TruncatedSnapshot)
        ));
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
