//! Recovery through the public API, including checkpoints behind the tip.

use proptest::prelude::*;
use vhalla_core::{Epoch, PeerId, RealmId, Sequence};
use vhalla_ledger::{Checkpoint, Error, Event, Ledger};

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

#[test]
fn retained_checkpoint_validation_is_read_only_and_still_checks_height() {
    let mut ledger = Ledger::new(RealmId(1), Epoch(2), 8);
    append(&mut ledger, 7, 1, b"ancestor");
    let ancestor = checkpoint(&mut ledger);
    append(&mut ledger, 7, 2, b"tip");
    let snapshot = ledger.snapshot();
    assert_eq!(ledger.validate_retained_checkpoint(ancestor), Ok(()));
    let mut incorrect = ancestor;
    incorrect.height = 1;
    assert_eq!(
        ledger.validate_retained_checkpoint(incorrect),
        Err(Error::HeightMismatch)
    );
    assert_eq!(ledger.snapshot(), snapshot);
    assert_eq!(
        ledger.accept_checkpoint(ancestor),
        Err(Error::StaleCheckpoint)
    );
}

#[test]
fn checkpoint_behind_tip_survives_restart_without_becoming_current() {
    let mut ledger = Ledger::new(RealmId(1), Epoch(2), 8);
    append(&mut ledger, 7, 1, b"checkpointed");
    let anchor = checkpoint(&mut ledger);
    append(&mut ledger, 8, 1, b"uncheckpointed");
    let snapshot = ledger.snapshot();
    let mut restored = Ledger::restore(&snapshot, 8).expect("a valid snapshot must restore");
    assert_eq!(restored.snapshot(), snapshot);
    assert_eq!(restored.head(), ledger.head());
    assert_eq!(restored.checkpoint(), Some(anchor));
    assert!(
        restored.accept_checkpoint(anchor).is_err(),
        "restoration must not relax live admission"
    );
    append(&mut restored, 7, 2, b"after restart");
    let advanced = checkpoint(&mut restored);
    assert_eq!(advanced.height, 2);
}

#[test]
fn alternate_sequence_map_order_is_not_canonical() {
    let mut ledger = Ledger::new(RealmId(1), Epoch(2), 8);
    append(&mut ledger, 7, 1, b"first");
    append(&mut ledger, 8, 1, b"second");
    let mut snapshot = ledger.snapshot();
    // Two final fixed-width map records: (actor: u128, sequence: u64).
    let start = snapshot.len() - 48;
    snapshot[start..].rotate_left(24);
    assert!(
        Ledger::restore(&snapshot, 8).is_err(),
        "noncanonical ordering must be rejected"
    );
}

#[test]
fn retained_checkpoint_corruption_is_rejected() {
    let mut ledger = Ledger::new(RealmId(1), Epoch(2), 8);
    append(&mut ledger, 7, 1, b"anchor");
    checkpoint(&mut ledger);
    append(&mut ledger, 8, 1, b"later");
    let snapshot = ledger.snapshot();
    // Checkpoint fields precede the sequence count and two 24-byte records.
    let anchor_start = snapshot.len() - (16 + 8 + 32 + 32 + 8) - (4 + 48);
    for (offset, expected) in [
        (0, Error::WrongContext),
        (16, Error::WrongContext),
        (24, Error::UnknownHead),
        (56, Error::RootMismatch),
        (88, Error::HeightMismatch),
    ] {
        let mut corrupted = snapshot.clone();
        corrupted[anchor_start + offset] ^= 1;
        assert_eq!(Ledger::restore(&corrupted, 8).err(), Some(expected));
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        failure_persistence: Some(Box::new(proptest::test_runner::FileFailurePersistence::WithSource("proptest-regressions"))),
        ..ProptestConfig::default()
    })]
    #[test]
    fn restarts_preserve_any_checkpoint_frontier(
        commands in prop::collection::vec((0u8..4, any::<bool>(), prop::collection::vec(any::<u8>(), 0..24)), 0..24)
    ) {
        let mut ledger = Ledger::new(RealmId(1), Epoch(2), 32);
        let mut sequences = [0u64; 4];
        for (actor, take_checkpoint, payload) in commands {
            sequences[actor as usize] += 1;
            append(&mut ledger, u128::from(actor), sequences[actor as usize], &payload);
            if take_checkpoint { checkpoint(&mut ledger); }
            let snapshot = ledger.snapshot();
            let mut restored = Ledger::restore(&snapshot, 32).unwrap();
            prop_assert_eq!(restored.snapshot(), snapshot);
            prop_assert_eq!(restored.head(), ledger.head());
            prop_assert_eq!(restored.checkpoint(), ledger.checkpoint());
            // Restoring a sequence map must not permit an already used actor sequence.
            let replay = Event::new(restored.head(), RealmId(1), Epoch(2), PeerId(u128::from(actor)),
                Sequence(sequences[actor as usize]), payload);
            prop_assert!(restored.append(replay).is_err());
            ledger = restored;
        }
    }
}
