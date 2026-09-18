//! Ledger binding: all-or-nothing seal application, seal-after-checkpoint,
//! and the two height vectors the plan pins (a two-segment epoch, and a
//! two-segment session with one replace).

use ed25519_dalek::SigningKey;
use vhalla_core::{Epoch, RealmId, Sequence};
use vhalla_game_platonik::checkpoint::{OrderedEvent, SealApplyError, SessionLedger};
use vhalla_game_platonik::ids::{CheckpointHash, GameEventDigest, SessionKey};
use vhalla_ledger::Error as LedgerError;

fn key(seed: u8) -> [u8; 32] {
    SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes()
}

fn event(author: [u8; 32], sequence: u64, tag: u8) -> OrderedEvent {
    OrderedEvent {
        author,
        sequence: Sequence(sequence),
        digest: GameEventDigest([tag; 32]),
    }
}

#[test]
fn a_two_segment_epoch_has_the_pinned_heights() {
    let host = key(1);
    let player = key(2);
    let bound = SessionLedger::bound(64, 8);
    let mut ledger = SessionLedger::open(RealmId(7), SessionKey([9; 32]), host, bound).unwrap();
    assert_eq!(
        ledger.height(),
        0,
        "genesis carries the session key at height 0"
    );
    let order_1 = [event(player, 1, 1), event(host, 1, 2), event(player, 2, 3)];
    let checkpoint_1 = ledger.apply_seal(&order_1).unwrap();
    assert_eq!(checkpoint_1.height, 3, "Checkpoint(1).height == |order_1|");
    assert_eq!(ledger.checkpoint(), Some(checkpoint_1));
    ledger
        .append_seal(Sequence(2), CheckpointHash([1; 32]))
        .unwrap();
    assert_eq!(ledger.seals_appended(), 1);
    let order_2 = [event(player, 3, 4), event(player, 4, 5)];
    let checkpoint_2 = ledger.apply_seal(&order_2).unwrap();
    assert_eq!(
        checkpoint_2.height,
        3 + 1 + 2,
        "Checkpoint(2).height == |order_1| + 1 + |order_2|"
    );
    assert!(checkpoint_2.height > checkpoint_1.height);
    assert_ne!(checkpoint_2.state_root, checkpoint_1.state_root);
}

#[test]
fn a_replace_opens_the_next_epoch_anchored_on_the_checkpoint() {
    let host = key(1);
    let player = key(2);
    let bound = SessionLedger::bound(64, 8);
    let mut epoch_0 = SessionLedger::open(RealmId(7), SessionKey([9; 32]), host, bound).unwrap();
    let checkpoint_1 = epoch_0
        .apply_seal(&[event(player, 1, 1), event(host, 1, 2)])
        .unwrap();
    assert_eq!(checkpoint_1.height, 2);
    // The replace seal appends no Seal event to epoch 0; it becomes the
    // genesis of epoch 1.
    let anchor = CheckpointHash([5; 32]);
    let mut epoch_1 = SessionLedger::open_epoch(RealmId(7), Epoch(1), anchor, host, bound).unwrap();
    assert_eq!(epoch_1.epoch(), Epoch(1));
    assert_eq!(epoch_1.height(), 0);
    let checkpoint_2 = epoch_1
        .apply_seal(&[
            event(player, 1, 7),
            event(player, 2, 8),
            event(player, 3, 9),
        ])
        .unwrap();
    assert_eq!(
        checkpoint_2.height, 3,
        "Checkpoint(2).height == |order_2| in the new epoch"
    );
    assert_eq!(checkpoint_2.epoch, Epoch(1));
}

#[test]
fn a_failing_order_leaves_the_ledger_bit_identical() {
    let host = key(1);
    let player = key(2);
    let bound = SessionLedger::bound(64, 8);
    let mut ledger = SessionLedger::open(RealmId(7), SessionKey([9; 32]), host, bound).unwrap();
    let first = ledger.apply_seal(&[event(player, 1, 1)]).unwrap();
    ledger
        .append_seal(Sequence(1), CheckpointHash([1; 32]))
        .unwrap();
    let head_before = ledger.head();
    let height_before = ledger.height();
    // A non-monotone sequence mid-order fails after one successful append.
    let outcome = ledger.apply_seal(&[event(player, 2, 2), event(player, 2, 3)]);
    assert_eq!(
        outcome.err(),
        Some(SealApplyError::SealApplyFailed(
            LedgerError::NonMonotonicSequence
        ))
    );
    assert_eq!(ledger.head(), head_before, "restored");
    assert_eq!(ledger.height(), height_before);
    assert_eq!(
        ledger.checkpoint(),
        Some(first),
        "the earlier checkpoint stands"
    );
    // The same order with the sequence fixed now applies.
    assert!(ledger
        .apply_seal(&[event(player, 2, 2), event(player, 3, 3)])
        .is_ok());
}

#[test]
fn capacity_is_unreachable_at_the_stated_bound_and_actors_must_be_distinct() {
    let host = key(1);
    let player = key(2);
    let bound = SessionLedger::bound(1024, 8);
    assert_eq!(bound, 1033);
    let mut ledger = SessionLedger::open(RealmId(7), SessionKey([9; 32]), host, bound).unwrap();
    let mut sequence = 0;
    for segment in 0..8 {
        let order: Vec<OrderedEvent> = (0..128)
            .map(|i| {
                sequence += 1;
                event(player, sequence, (segment * 16 + i % 16) as u8)
            })
            .collect();
        ledger.apply_seal(&order).unwrap();
        if segment < 7 {
            ledger
                .append_seal(Sequence(segment + 1), CheckpointHash([segment as u8; 32]))
                .unwrap();
        }
    }
    assert_eq!(
        ledger.height() as usize,
        1024 + 7,
        "every admissible event fits"
    );
    assert!(SessionLedger::actors_distinct(&[host, player]));
    assert!(!SessionLedger::actors_distinct(&[host, host]));
    assert!(
        !SessionLedger::actors_distinct(&[[0; 32]]),
        "an invalid key is never distinct"
    );
}
