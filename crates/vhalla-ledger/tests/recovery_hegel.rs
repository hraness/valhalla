//! Recovery through the public API under Hegel's interleaved draw model.
//!
//! This is the `restarts_preserve_any_checkpoint_frontier` state machine from
//! `recovery.rs`, ported to Hegel's draw-inside-the-loop style: each command is
//! drawn while the trace executes rather than materialized as a list up front.

use hegel::generators as gs;
use hegel::TestCase;
use vhalla_core::{Epoch, PeerId, RealmId, Sequence};
use vhalla_ledger::{Checkpoint, Event, Ledger};

fn append(ledger: &mut Ledger, actor: u128, sequence: u64, payload: &[u8]) {
    let event = Event::new(
        ledger.head(),
        RealmId(1),
        Epoch(2),
        PeerId(actor),
        Sequence(sequence),
        payload.to_vec(),
    );
    ledger.append(event).unwrap();
}

fn checkpoint(ledger: &mut Ledger) -> Checkpoint {
    let head = ledger.head().unwrap();
    let checkpoint = Checkpoint {
        realm: RealmId(1),
        epoch: Epoch(2),
        head,
        state_root: ledger.state_root(head).unwrap(),
        height: ledger.event_count() as u64 - 1,
    };
    ledger.accept_checkpoint(checkpoint).unwrap();
    checkpoint
}

#[hegel::test(test_cases = 64)]
fn restarts_preserve_any_checkpoint_frontier(tc: TestCase) {
    let mut ledger = Ledger::new(RealmId(1), Epoch(2), 32);
    let mut sequences = [0u64; 4];
    let steps = tc.draw(gs::integers::<usize>().max_value(23));
    for _ in 0..steps {
        let actor = tc.draw(gs::integers::<u8>().max_value(3));
        let take_checkpoint = tc.draw(gs::booleans());
        let payload = tc.draw(gs::vecs(gs::integers::<u8>()).max_size(23));
        sequences[actor as usize] += 1;
        append(
            &mut ledger,
            u128::from(actor),
            sequences[actor as usize],
            &payload,
        );
        if take_checkpoint {
            checkpoint(&mut ledger);
        }
        let snapshot = ledger.snapshot();
        let mut restored = Ledger::restore(&snapshot, 32).unwrap();
        assert_eq!(restored.snapshot(), snapshot);
        assert_eq!(restored.head(), ledger.head());
        assert_eq!(restored.checkpoint(), ledger.checkpoint());
        // Restoring a sequence map must not permit an already used actor sequence.
        let replay = Event::new(
            restored.head(),
            RealmId(1),
            Epoch(2),
            PeerId(u128::from(actor)),
            Sequence(sequences[actor as usize]),
            payload,
        );
        assert!(restored.append(replay).is_err());
        ledger = restored;
    }
}

/// Recorded proptest regression for this property, promoted to an explicit
/// example: the two-command trace `(0, checkpoint, [])`, `(0, no checkpoint,
/// [])` once shrank a real frontier loss.
#[test]
fn recorded_regression_checkpoint_then_append() {
    let mut ledger = Ledger::new(RealmId(1), Epoch(2), 32);
    append(&mut ledger, 0, 1, &[]);
    checkpoint(&mut ledger);
    let snapshot = ledger.snapshot();
    let mut restored = Ledger::restore(&snapshot, 32).unwrap();
    assert_eq!(restored.snapshot(), snapshot);
    assert_eq!(restored.checkpoint(), ledger.checkpoint());
    ledger = restored;
    append(&mut ledger, 0, 2, &[]);
    let snapshot = ledger.snapshot();
    restored = Ledger::restore(&snapshot, 32).unwrap();
    assert_eq!(restored.snapshot(), snapshot);
    assert_eq!(restored.head(), ledger.head());
    assert_eq!(restored.checkpoint(), ledger.checkpoint());
}

/// The same frontier property under a state-dependent command distribution:
/// each step mostly reuses an actor that has already appended, occasionally
/// introducing a fresh one. An up-front `Vec<Command>` cannot express this —
/// the pool depends on the trace so far — without rejection sampling.
#[hegel::test(test_cases = 64)]
fn restarts_preserve_frontier_under_actor_reuse(tc: TestCase) {
    let mut ledger = Ledger::new(RealmId(1), Epoch(2), 32);
    let mut sequences = [0u64; 4];
    let mut active: Vec<u8> = Vec::new();
    let steps = tc.draw(gs::integers::<usize>().max_value(23));
    for _ in 0..steps {
        let actor = if !active.is_empty() && tc.draw(gs::booleans()) {
            let i = tc.draw(gs::integers::<usize>().max_value(active.len() - 1));
            active[i]
        } else {
            let fresh = tc.draw(gs::integers::<u8>().max_value(3));
            active.push(fresh);
            fresh
        };
        let take_checkpoint = tc.draw(gs::booleans());
        let payload = tc.draw(gs::vecs(gs::integers::<u8>()).max_size(23));
        sequences[actor as usize] += 1;
        append(
            &mut ledger,
            u128::from(actor),
            sequences[actor as usize],
            &payload,
        );
        if take_checkpoint {
            checkpoint(&mut ledger);
        }
        let snapshot = ledger.snapshot();
        let restored = Ledger::restore(&snapshot, 32).unwrap();
        assert_eq!(restored.snapshot(), snapshot);
        assert_eq!(restored.checkpoint(), ledger.checkpoint());
        ledger = restored;
    }
}
