//! Executable projection of verify/ledger.rs against the production map-backed
//! ledger. This is sampled conformance evidence, not an equivalence proof.
//! IDs retain their real digest values here; all offered events are canonically
//! constructed, so hash validation (outside the Verus model) is not abstracted
//! into permission to admit malformed bytes.
use hegel::{generators as gs, TestCase};
use vhalla_core::{Epoch, PeerId, RealmId, Sequence};
use vhalla_ledger::{Error, Event, Ledger, MAX_PAYLOAD};

#[derive(Default)]
struct Reference {
    events: Vec<Event>,
}

impl Reference {
    fn append(&mut self, event: Event, capacity: usize) -> Result<(), Error> {
        // Predicate order and vector lookups correspond to the verified
        // reference model, independently of the production BTreeMap caches.
        let failure = if event.payload.len() > MAX_PAYLOAD {
            Some(Error::PayloadTooLarge)
        } else if event.realm != RealmId(1) || event.epoch != Epoch(2) {
            Some(Error::WrongContext)
        } else if self.events.iter().any(|old| old.id == event.id) {
            Some(Error::DuplicateEvent)
        } else if self
            .events
            .iter()
            .rev()
            .find(|old| old.actor == event.actor)
            .is_some_and(|old| event.sequence <= old.sequence)
        {
            Some(Error::NonMonotonicSequence)
        } else if event.parent != self.events.last().map(|old| old.id) {
            Some(Error::UnknownOrForkedParent)
        } else if self.events.len() >= capacity {
            Some(Error::Capacity)
        } else {
            None
        };
        if let Some(error) = failure {
            Err(error)
        } else {
            self.events.push(event);
            Ok(())
        }
    }
}

#[hegel::test(test_cases = 64)]
fn verified_admission_projection_agrees_with_production_and_reopen(tc: TestCase) {
    let capacity = tc.draw(gs::integers::<usize>().max_value(8));
    let mut real = Ledger::new(RealmId(1), Epoch(2), capacity);
    let mut model = Reference::default();
    let steps = tc.draw(gs::integers::<usize>().min_value(8).max_value(40));
    for step in 0..steps {
        let actor = PeerId(tc.draw(gs::integers::<u128>().max_value(2)));
        let seq = tc.draw(gs::integers::<u64>().max_value(12));
        let command = tc.draw(gs::integers::<u8>().max_value(7));
        let mut event = Event::new(
            if command == 3 { None } else { real.head() },
            RealmId(if command == 4 { 9 } else { 1 }),
            Epoch(if command == 5 { 9 } else { 2 }),
            actor,
            Sequence(seq),
            vec![step as u8; if command == 6 { MAX_PAYLOAD + 1 } else { 3 }],
        );
        if command == 2 && !model.events.is_empty() {
            let index = tc.draw(gs::integers::<usize>().max_value(model.events.len() - 1));
            event = model.events[index].clone();
        }
        let before = real.snapshot();
        let expected = model.append(event.clone(), capacity);
        let observed = real.append(event);
        assert_eq!(observed, expected);
        assert_eq!(real.head(), model.events.last().map(|entry| entry.id));
        assert_eq!(real.event_count(), model.events.len());
        if observed.is_err() {
            assert_eq!(
                real.snapshot(),
                before,
                "rejection changed durable snapshot"
            );
        }
        if command == 7 {
            real = Ledger::restore(&real.snapshot(), capacity).unwrap();
            assert_eq!(real.head(), model.events.last().map(|entry| entry.id));
        }
    }
}

#[test]
fn rejection_precedence_and_capacity_match_reference() {
    let mut real = Ledger::new(RealmId(1), Epoch(2), 1);
    let mut model = Reference::default();
    let first = Event::new(None, RealmId(1), Epoch(2), PeerId(1), Sequence(1), vec![]);
    for event in [
        first.clone(),
        first.clone(),
        Event::new(
            Some(first.id),
            RealmId(1),
            Epoch(2),
            PeerId(1),
            Sequence(1),
            vec![1],
        ),
        Event::new(None, RealmId(1), Epoch(2), PeerId(2), Sequence(1), vec![2]),
        Event::new(
            Some(first.id),
            RealmId(1),
            Epoch(2),
            PeerId(2),
            Sequence(1),
            vec![3],
        ),
        Event::new(
            None,
            RealmId(9),
            Epoch(9),
            PeerId(1),
            Sequence(0),
            vec![4; MAX_PAYLOAD + 1],
        ),
    ] {
        assert_eq!(real.append(event.clone()), model.append(event, 1));
    }
}
