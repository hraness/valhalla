//! Reference semantics for optional replicated history.

use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EventId(pub u64);
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Author(pub u64);
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Lamport(pub u64);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Event {
    pub id: EventId,
    pub author: Author,
    pub clock: Lamport,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Receipt {
    pub id: EventId,
    pub stored: bool,
    pub durable: bool,
}

pub struct Replica {
    max_events: usize,
    max_bytes: usize,
    bytes: usize,
    seen: BTreeSet<EventId>,
    events: BTreeMap<(Lamport, Author, EventId), Event>,
}

impl Replica {
    pub fn new(max_events: usize, max_bytes: usize) -> Self {
        Self {
            max_events,
            max_bytes,
            bytes: 0,
            seen: BTreeSet::new(),
            events: BTreeMap::new(),
        }
    }
    pub fn ingest(&mut self, event: Event) -> Receipt {
        if self.seen.contains(&event.id) {
            return Receipt {
                id: event.id,
                stored: false,
                durable: false,
            };
        }
        if event.bytes.len() > self.max_bytes {
            return Receipt {
                id: event.id,
                stored: false,
                durable: false,
            };
        }
        while self.events.len() >= self.max_events
            || self.bytes + event.bytes.len() > self.max_bytes
        {
            let Some(key) = self.events.keys().next().copied() else {
                return Receipt {
                    id: event.id,
                    stored: false,
                    durable: false,
                };
            };
            let old = self.events.remove(&key).expect("key came from map");
            self.bytes -= old.bytes.len();
        }
        self.bytes += event.bytes.len();
        let event_id = event.id;
        self.seen.insert(event_id);
        self.events
            .insert((event.clock, event.author, event_id), event);
        Receipt {
            id: event_id,
            stored: true,
            durable: false,
        }
    }
    pub fn ordered(&self) -> impl Iterator<Item = &Event> {
        self.events.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn event(id: u64, author: u64, clock: u64, bytes: &[u8]) -> Event {
        Event {
            id: EventId(id),
            author: Author(author),
            clock: Lamport(clock),
            bytes: bytes.to_vec(),
        }
    }

    #[test]
    fn merge_is_idempotent_and_order_is_deterministic() {
        let mut left = Replica::new(8, 100);
        let mut right = Replica::new(8, 100);
        let a = event(1, 2, 1, b"a");
        let b = event(2, 1, 1, b"b");
        assert!(left.ingest(a.clone()).stored);
        assert!(left.ingest(b.clone()).stored);
        assert!(right.ingest(b).stored);
        assert!(right.ingest(a.clone()).stored);
        assert!(!right.ingest(a).stored);
        let ids: Vec<_> = left.ordered().map(|e| e.id).collect();
        assert_eq!(ids, vec![EventId(2), EventId(1)]);
    }

    #[test]
    fn receipt_does_not_claim_durability_and_retention_is_bounded() {
        let mut replica = Replica::new(1, 4);
        let receipt = replica.ingest(event(1, 1, 1, b"1234"));
        assert_eq!(
            receipt,
            Receipt {
                id: EventId(1),
                stored: true,
                durable: false
            }
        );
        assert!(replica.ingest(event(2, 1, 2, b"5678")).stored);
        assert_eq!(
            replica.ordered().map(|e| e.id).collect::<Vec<_>>(),
            vec![EventId(2)]
        );
    }
}
