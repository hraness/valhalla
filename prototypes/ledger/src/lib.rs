//! Disposable signed event-DAG prototype.
//!
//! This is deliberately a small model, not a durable database or a consensus
//! protocol. Event IDs and signatures make records self-authenticating; merge
//! is set-union plus deterministic presentation. A policy layer must still
//! decide which authors and channels are trusted.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"valhalla/ledger-prototype/v1";

/// A 32-byte Ed25519 public key.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Author(pub [u8; 32]);

/// A content address for an event body.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EventId(pub [u8; 32]);

/// A signed event body. `sequence` is scoped to `(author, device)` in a
/// production protocol; this prototype uses the public key as that scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventBody {
    /// Logical channel name.
    pub channel: String,
    /// Author's monotonic sequence number.
    pub sequence: u64,
    /// Lamport clock used only for deterministic display order.
    pub lamport: u64,
    /// Parent event IDs known when this event was authored.
    pub parents: Vec<EventId>,
    /// Application payload.
    pub payload: Vec<u8>,
}

/// A content-addressed, signed event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Event {
    /// The author key.
    pub author: Author,
    /// The canonical body.
    pub body: EventBody,
    /// Hash of the domain-separated canonical body and author.
    pub id: EventId,
    /// Ed25519 signature over the same transcript as `id`.
    pub signature: [u8; 64],
}

/// Result of accepting an event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ingested {
    /// Event was newly stored.
    Stored,
    /// This exact content-addressed event was already present.
    Duplicate,
}

/// Why an event was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reject {
    /// Channel or payload violated prototype bounds.
    InvalidBody,
    /// Event ID did not match its canonical body.
    InvalidId,
    /// Signature did not verify for the claimed author.
    InvalidSignature,
    /// A different event used the same author sequence number.
    Equivocation,
    /// The event cannot fit within configured retention limits.
    Capacity,
}

/// A bounded local replica. It does not claim that storage is durable.
pub struct Replica {
    max_events: usize,
    max_bytes: usize,
    max_heads: usize,
    bytes: usize,
    events: BTreeMap<EventId, Event>,
    /// A bounded record of observed author/sequence pairs and their IDs.
    claims: BTreeMap<(Author, u64), EventId>,
    equivocations: BTreeSet<(Author, u64)>,
}

impl EventBody {
    fn encode(&self, out: &mut Vec<u8>) -> bool {
        if self.channel.is_empty() || self.channel.len() > 128 || self.payload.len() > 1 << 20 {
            return false;
        }
        put_bytes(out, self.channel.as_bytes());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.lamport.to_be_bytes());
        if self.parents.len() > 256 {
            return false;
        }
        out.extend_from_slice(&(self.parents.len() as u16).to_be_bytes());
        for parent in &self.parents {
            out.extend_from_slice(&parent.0);
        }
        put_bytes(out, &self.payload);
        true
    }
}

impl Event {
    /// Sign a body and derive its content address.
    #[must_use]
    pub fn sign(key: &SigningKey, body: EventBody) -> Self {
        let author = Author(key.verifying_key().to_bytes());
        let transcript = transcript(author, &body);
        let id = EventId(hash(&transcript));
        let signature = key.sign(&transcript).to_bytes();
        Self {
            author,
            body,
            id,
            signature,
        }
    }

    fn verify(&self) -> Result<(), Reject> {
        let transcript = transcript(self.author, &self.body);
        if EventId(hash(&transcript)) != self.id {
            return Err(Reject::InvalidId);
        }
        let key = VerifyingKey::from_bytes(&self.author.0).map_err(|_| Reject::InvalidSignature)?;
        key.verify(&transcript, &Signature::from_bytes(&self.signature))
            .map_err(|_| Reject::InvalidSignature)
    }
}

impl Replica {
    /// Create a replica with event-count and payload-byte bounds.
    #[must_use]
    pub fn new(max_events: usize, max_bytes: usize) -> Self {
        Self::with_limits(max_events, max_bytes, max_events)
    }

    /// Create a replica with independent retention and head-summary bounds.
    #[must_use]
    pub fn with_limits(max_events: usize, max_bytes: usize, max_heads: usize) -> Self {
        Self {
            max_events,
            max_bytes,
            max_heads,
            bytes: 0,
            events: BTreeMap::new(),
            claims: BTreeMap::new(),
            equivocations: BTreeSet::new(),
        }
    }

    /// Merge one event. Merge is idempotent for an identical event.
    pub fn ingest(&mut self, event: Event) -> Result<Ingested, Reject> {
        if !event.body.encode(&mut Vec::new()) {
            return Err(Reject::InvalidBody);
        }
        event.verify()?;
        if self.events.contains_key(&event.id) {
            return Ok(Ingested::Duplicate);
        }
        let claim = (event.author, event.body.sequence);
        if let Some(existing) = self.claims.get(&claim) {
            if *existing != event.id {
                self.equivocations.insert(claim);
                return Err(Reject::Equivocation);
            }
        }
        let size = event.body.payload.len();
        if size > self.max_bytes {
            return Err(Reject::Capacity);
        }
        while self.events.len() >= self.max_events || self.bytes + size > self.max_bytes {
            let Some(evict) = self.oldest_id() else {
                return Err(Reject::Capacity);
            };
            let old = self.events.remove(&evict).expect("oldest ID came from map");
            self.bytes -= old.body.payload.len();
            self.claims.remove(&(old.author, old.body.sequence));
        }
        self.bytes += size;
        self.claims.insert(claim, event.id);
        self.events.insert(event.id, event);
        Ok(Ingested::Stored)
    }

    /// Merge all events from another replica in a deterministic order.
    pub fn merge(&mut self, other: &Replica) -> Vec<Result<Ingested, Reject>> {
        other
            .ordered()
            .cloned()
            .map(|event| self.ingest(event))
            .collect()
    }

    /// Events ordered by `(lamport, author, event_id)` for stable presentation.
    pub fn ordered(&self) -> impl Iterator<Item = &Event> {
        let mut events: Vec<&Event> = self.events.values().collect();
        events.sort_by_key(|event| (event.body.lamport, event.author, event.id));
        events.into_iter()
    }

    /// Current DAG heads, bounded deterministically by `max_events`.
    #[must_use]
    pub fn heads(&self) -> Vec<EventId> {
        let referenced: BTreeSet<EventId> = self
            .events
            .values()
            .flat_map(|event| event.body.parents.iter().copied())
            .collect();
        let mut heads: Vec<_> = self
            .events
            .keys()
            .copied()
            .filter(|id| !referenced.contains(id))
            .collect();
        heads.sort();
        if heads.len() > self.max_heads {
            heads.drain(..heads.len() - self.max_heads);
        }
        heads
    }

    /// Whether this replica observed author equivocation.
    #[must_use]
    pub fn has_equivocation(&self, author: Author, sequence: u64) -> bool {
        self.equivocations.contains(&(author, sequence))
    }

    fn oldest_id(&self) -> Option<EventId> {
        self.events
            .values()
            .min_by_key(|event| (event.body.lamport, event.author, event.id))
            .map(|event| event.id)
    }
}

fn transcript(author: Author, body: &EventBody) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&author.0);
    assert!(body.encode(&mut bytes));
    bytes
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }

    fn body(sequence: u64, lamport: u64, parents: Vec<EventId>, payload: &[u8]) -> EventBody {
        EventBody {
            channel: "#agents".into(),
            sequence,
            lamport,
            parents,
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn duplicate_is_idempotent_and_order_is_deterministic() {
        let alice = key(1);
        let bob = key(2);
        let a = Event::sign(&alice, body(1, 1, vec![], b"a"));
        let b = Event::sign(&bob, body(1, 1, vec![], b"b"));
        let mut left = Replica::new(8, 100);
        let mut right = Replica::new(8, 100);
        assert_eq!(left.ingest(a.clone()), Ok(Ingested::Stored));
        assert_eq!(left.ingest(b.clone()), Ok(Ingested::Stored));
        assert_eq!(right.ingest(b), Ok(Ingested::Stored));
        assert_eq!(right.ingest(a.clone()), Ok(Ingested::Stored));
        assert_eq!(right.ingest(a), Ok(Ingested::Duplicate));
        let left_ids: Vec<_> = left.ordered().map(|event| event.id).collect();
        let right_ids: Vec<_> = right.ordered().map(|event| event.id).collect();
        assert_eq!(left_ids, right_ids);
    }

    #[test]
    fn conflicting_sequence_is_equivocation() {
        let alice = key(1);
        let first = Event::sign(&alice, body(7, 1, vec![], b"first"));
        let second = Event::sign(&alice, body(7, 2, vec![], b"second"));
        let mut replica = Replica::new(8, 100);
        assert_eq!(replica.ingest(first.clone()), Ok(Ingested::Stored));
        assert_eq!(replica.ingest(second), Err(Reject::Equivocation));
        assert!(replica.has_equivocation(first.author, 7));
    }

    #[test]
    fn retention_and_heads_are_bounded() {
        let alice = key(1);
        let mut replica = Replica::with_limits(2, 5, 1);
        let first = Event::sign(&alice, body(1, 1, vec![], b"12"));
        let second = Event::sign(&alice, body(2, 2, vec![first.id], b"34"));
        let third = Event::sign(&alice, body(3, 3, vec![second.id], b"5"));
        assert_eq!(replica.ingest(first), Ok(Ingested::Stored));
        assert_eq!(replica.ingest(second), Ok(Ingested::Stored));
        assert_eq!(replica.ingest(third), Ok(Ingested::Stored));
        assert!(replica.ordered().count() <= 2);
        assert!(replica.heads().len() <= 2);
    }
}
