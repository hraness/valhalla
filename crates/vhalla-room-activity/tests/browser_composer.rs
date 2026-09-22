//! Native regressions for the browser's actual volatile composer controller.
#[path = "../../../browser/src/composer_model.rs"]
mod model;
use model::{Context, Draft};
use vhalla_core::RealmId;
use vhalla_room_activity::RoomScope;
use vhalla_rooms::{DirectoryId, RoomGenesisId};

fn context() -> Context {
    Context {
        room: RoomScope {
            network: [1; 32],
            realm: RealmId(2),
            directory: DirectoryId::from_bytes([3; 32]),
            room: RoomGenesisId::from_bytes([4; 32]),
        },
        bootstrap_pin: [5; 32],
        author: [6; 32],
    }
}

#[test]
fn every_destination_or_author_change_refuses_until_explicit_move() {
    let a = context();
    let mut alternatives = [a; 6];
    alternatives[0].room.network[0] ^= 1;
    alternatives[1].room.realm = RealmId(3);
    alternatives[2].room.directory = DirectoryId::from_bytes([9; 32]);
    alternatives[3].room.room = RoomGenesisId::from_bytes([9; 32]);
    alternatives[4].bootstrap_pin[0] ^= 1;
    alternatives[5].author[0] ^= 1;
    for b in alternatives {
        let mut draft = Draft::default();
        draft.edit("only for A", Some(a)).unwrap();
        assert!(draft.queue_text("only for A", b).is_err());
        // Editing in the other view does not silently move the original text.
        draft.edit("A with another sentence", Some(b)).unwrap();
        assert!(draft.context() == Some(a));
        assert!(draft.queue_text("A with another sentence", b).is_err());
        assert_eq!(
            draft
                .queue_text("A with another sentence", a)
                .unwrap()
                .as_str(),
            "A with another sentence"
        );
        draft.use_here("A with another sentence", b).unwrap();
        assert!(draft.queue_text("A with another sentence", a).is_err());
        assert_eq!(
            draft
                .queue_text("A with another sentence", b)
                .unwrap()
                .as_str(),
            "A with another sentence"
        );
    }
}

#[test]
fn typing_while_locked_remains_unbound_after_unlock_and_requires_explicit_destination() {
    let a = context();
    let mut draft = Draft::default();
    draft.edit("typed before unlock", None).unwrap();
    assert!(draft.started());
    draft
        .edit("typed before unlock plus edit", Some(a))
        .unwrap();
    assert!(draft.context().is_none());
    assert!(draft
        .queue_text("typed before unlock plus edit", a)
        .is_err());
    draft.use_here("typed before unlock plus edit", a).unwrap();
    assert_eq!(
        draft
            .queue_text("typed before unlock plus edit", a)
            .unwrap()
            .as_str(),
        "typed before unlock plus edit"
    );
    // The identity being locked again cannot rebind this to a later key.
    draft.edit("still A", None).unwrap();
    assert!(draft.context() == Some(a));
    let mut b = a;
    b.author[0] ^= 1;
    assert!(draft.queue_text("still A", b).is_err());
}

#[test]
fn exact_text_and_bounds_fail_closed_without_losing_original_scope() {
    let a = context();
    let mut b = a;
    b.room.room = RoomGenesisId::from_bytes([9; 32]);
    let mut draft = Draft::default();
    let oversized = "é".repeat(2049);
    assert!(draft.edit(&oversized, Some(a)).is_err());
    assert!(draft.context() == Some(a));
    assert!(draft.queue_text(&oversized, a).is_err());
    // Shrinking oversized input in another room must preserve its first scope.
    draft.edit("now bounded", Some(b)).unwrap();
    assert!(draft.queue_text("now bounded", b).is_err());
    assert!(draft.queue_text("programmatically replaced", a).is_err());
    assert!(draft.use_here(&oversized, b).is_err());
    assert!(draft.use_here("\u{0000}", b).is_err());
    assert!(draft.context() == Some(a));
    assert_eq!(
        draft.queue_text("now bounded", a).unwrap().as_str(),
        "now bounded"
    );
    draft.edit(&"é".repeat(2048), Some(b)).unwrap();
    assert_eq!(
        draft
            .queue_text(&"é".repeat(2048), a)
            .unwrap()
            .as_str()
            .len(),
        4096
    );
}

#[test]
fn only_deliberate_clear_or_successful_save_allows_a_new_draft_scope() {
    let a = context();
    let mut b = a;
    b.room.room = RoomGenesisId::from_bytes([9; 32]);
    let mut draft = Draft::default();
    draft.edit("A", Some(a)).unwrap();
    draft.edit("", Some(b)).unwrap();
    assert!(!draft.started());
    draft.edit("B", Some(b)).unwrap();
    assert_eq!(draft.queue_text("B", b).unwrap().as_str(), "B");
    assert!(draft.queue_text("B", a).is_err());
    draft.clear_saved();
    assert!(!draft.started());
    assert!(draft.context().is_none());
    assert!(draft.queue_text("B", b).is_err());
    draft.edit("new A", Some(a)).unwrap();
    assert_eq!(draft.queue_text("new A", a).unwrap().as_str(), "new A");
}
