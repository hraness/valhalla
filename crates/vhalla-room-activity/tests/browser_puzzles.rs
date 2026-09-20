//! Native regressions for the browser's actual derived puzzle controller.
#[path = "../../../browser/src/puzzle_model.rs"]
mod model;
use ed25519_dalek::SigningKey;
use model::{Assembly, Context, Derived, PreparedPart, Selection};
use vhalla_core::RealmId;
use vhalla_room_activity::{
    puzzle_share::{pack, Kind, Part},
    Content, EventClaims, EventId, RoomScope, Text, UnsignedEvent, VerifiedEvent,
};
use vhalla_rooms::{DirectoryId, RoomGenesisId, RoomRecordId};

fn context() -> Context {
    Context {
        room: RoomScope {
            network: [1; 32],
            realm: RealmId(77),
            directory: DirectoryId::from_bytes([2; 32]),
            room: RoomGenesisId::from_bytes([3; 32]),
        },
        bootstrap_pin: [4; 32],
    }
}
fn signed(room: RoomScope, key: &SigningKey, text: Text) -> VerifiedEvent {
    UnsignedEvent::new(EventClaims {
        scope: room,
        policy: RoomRecordId::from_bytes([5; 32]),
        author: key.verifying_key().to_bytes(),
        sequence: 1,
        previous: EventId::ZERO,
        created_at: 100,
        content: Content::Text(text),
    })
    .unwrap()
    .sign_with_key(key)
    .unwrap()
    .verify()
    .unwrap()
}
fn selection(key: &SigningKey, text: &Text) -> Selection {
    let part = Part::decode(text.as_str()).unwrap();
    Selection {
        context: context(),
        author: key.verifying_key().to_bytes(),
        kind: part.kind(),
        digest: *part.digest(),
    }
}

#[test]
fn preview_is_exact_and_never_selects_an_existing_pending_draft() {
    let text = pack(Kind::Responses, br#"{"responses":[]}"#)
        .unwrap()
        .remove(0);
    let pasted = format!("{}\n", text.as_str());
    let preview = PreparedPart::new(&pasted).unwrap();
    assert_eq!(preview.part().encode(), text);
    assert_eq!(preview.queue_text(&pasted, false).unwrap(), text);
    assert!(preview.queue_text(&pasted, true).is_err());
    assert!(preview.queue_text(text.as_str(), false).is_err());
    let other = pack(Kind::Responses, br#"{"responses":[1]}"#)
        .unwrap()
        .remove(0);
    assert!(preview.queue_text(other.as_str(), false).is_err());
    // Refusal has not changed the saved preview into the incoming/new bytes.
    assert_eq!(preview.queue_text(&pasted, false).unwrap(), text);
    for padding in [" ".repeat(4096), "\u{2003}".repeat(1400)] {
        assert!(PreparedPart::new(&format!("{padding}{pasted}")).is_err());
        assert!(PreparedPart::new(&format!("{pasted}{padding}")).is_err());
    }
}

#[test]
fn only_selected_verified_parts_contribute_and_complete_digest_enables_bytes() {
    let key = SigningKey::from_bytes(&[42; 32]);
    let raw = vec![17; 5701];
    let parts = pack(Kind::PublicChallenges, &raw).unwrap();
    let mut assembly = Assembly::new(selection(&key, &parts[0])).unwrap();
    let other_key = SigningKey::from_bytes(&[43; 32]);
    assert!(!assembly
        .observe(&signed(context().room, &other_key, parts[0].clone()))
        .unwrap());
    let mut other_room = context().room;
    other_room.directory = DirectoryId::from_bytes([9; 32]);
    assert!(!assembly
        .observe(&signed(other_room, &key, parts[0].clone()))
        .unwrap());
    assert!(!assembly
        .observe(&signed(
            context().room,
            &key,
            Text::new("ordinary chat").unwrap()
        ))
        .unwrap());
    let other = pack(Kind::Responses, &raw).unwrap();
    assert!(!assembly
        .observe(&signed(context().room, &key, other[0].clone()))
        .unwrap());
    assert_eq!(assembly.received(), 0);
    assert_eq!(assembly.total(), None);
    for index in [2, 2, 0] {
        assert!(assembly
            .observe(&signed(context().room, &key, parts[index].clone()))
            .unwrap());
        assert!(assembly.bytes().is_none());
    }
    assert_eq!(assembly.received(), 2);
    assert_eq!(assembly.total(), Some(3));
    assert!(assembly
        .observe(&signed(context().room, &key, parts[1].clone()))
        .unwrap());
    assert_eq!(assembly.bytes(), Some(raw.as_slice()));
    // Even after completion a conflicting selected signed part disables download.
    let mut altered = parts[0].as_str().as_bytes().to_vec();
    let start = altered.iter().rposition(|b| *b == b'\n').unwrap() + 1;
    altered[start] = if altered[start] == b'A' { b'B' } else { b'A' };
    let altered = Text::new(&String::from_utf8(altered).unwrap()).unwrap();
    assert!(Part::decode(altered.as_str()).is_ok());
    assert!(assembly
        .observe(&signed(context().room, &key, altered))
        .is_err());
    assert!(assembly.bytes().is_none());
    assert!(assembly
        .observe(&signed(context().room, &key, parts[0].clone()))
        .is_err());
}

#[test]
fn context_changes_discard_only_volatile_preview_and_selected_assembly() {
    let key = SigningKey::from_bytes(&[42; 32]);
    let text = pack(Kind::Admission, br#"{"signed":"claim"}"#)
        .unwrap()
        .remove(0);
    let mut derived = Derived::default();
    assert!(derived.set_context(Some(context())));
    derived.preview = Some(PreparedPart::new(text.as_str()).unwrap());
    derived.assembly = Some(Assembly::new(selection(&key, &text)).unwrap());
    derived
        .assembly
        .as_mut()
        .unwrap()
        .observe(&signed(context().room, &key, text.clone()))
        .unwrap();
    assert!(!derived.set_context(Some(context())));
    assert_eq!(derived.assembly.as_ref().unwrap().received(), 1);
    assert!(derived.preview.is_some());
    let mut changed = context();
    changed.bootstrap_pin = [8; 32];
    assert!(derived.set_context(Some(changed)));
    assert!(derived.preview.is_none() && derived.assembly.is_none());
    assert!(derived.set_context(None));
    assert!(derived.context.is_none());
    for invalid in [
        "a".repeat(63),
        "A".repeat(64),
        "é".repeat(32),
        "g".repeat(64),
    ] {
        assert!(model::hex32(&invalid).is_none());
    }
    assert_eq!(model::hex32(&"ab".repeat(32)), Some([0xab; 32]));
}
