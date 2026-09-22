//! Exercise the browser's exact lookup against actual signed registry history.
mod common;
#[path = "../../../browser/src/recovery_room.rs"]
mod recovery_room;

use common::*;
use vhalla_rooms::{registry::Applied, RoomUpdate, UpdateAction};
use vhalla_social::archive::Archive;

#[test]
fn recovery_resolves_archived_and_unlisted_full_ids_without_reopening_posting() {
    let mut archive_limits = limits();
    // This fixture retains 66 owners and their grant/seal controls.
    archive_limits.control_reserve = 192;
    let mut archive = Archive::new(REALM, archive_limits).unwrap();
    let (mut pool, mut registry) = sources(&mut archive, 90, 33);
    let mut last = None;
    for (index, source) in pool.iter_mut().enumerate() {
        let creator = beneficiary(&mut archive, index as u8 + 1);
        let now = 100 + index as u64 * 3;
        let grant = grant_create(&mut registry, &archive, &creator, now);
        award_one(&mut registry, &mut archive, source, &creator, now + 1);
        let create = creation(
            &creator,
            grant,
            grant,
            &format!("room-{index:02}"),
            1,
            1,
            index as u8 + 1,
        );
        let Applied::Created(genesis) = apply(&mut registry, &archive, &create, now + 2).unwrap()
        else {
            panic!("expected room creation");
        };
        last = Some((creator, create.id(), genesis));
    }
    let (creator, create, genesis) = last.unwrap();
    let full: String = genesis
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let page = registry.search("", 32, 4096).unwrap();
    assert_eq!(page.rooms.len(), 32);
    assert!(page.partial);
    assert!(!page.rooms.iter().any(|room| room.genesis() == genesis));
    assert_eq!(recovery_room::lookup(&registry, &full), Ok(genesis));

    let update = |previous, action, nonce| {
        RoomUpdate {
            directory: DIRECTORY,
            realm: REALM,
            genesis,
            previous,
            owner: creator.id,
            social_control: creator.head,
            controller_key: creator.key.verifying_key().to_bytes(),
            expires_at: EXPIRES,
            nonce: [nonce; 32],
            action,
        }
        .sign_with_key(&creator.key)
        .unwrap()
    };
    let open = update(
        create,
        UpdateAction::SetPublicActivityPolicy {
            network: [7; 32],
            enabled: true,
        },
        90,
    );
    apply(&mut registry, &archive, &open, 400).unwrap();
    assert!(registry
        .room_by_genesis(genesis)
        .unwrap()
        .allows_public_activity(&[7; 32], open.id()));
    let archived = update(open.id(), UpdateAction::Archive, 91);
    apply(&mut registry, &archive, &archived, 500).unwrap();
    let room = registry.room_by_genesis(genesis).unwrap();
    assert!(room.archived());
    assert!(!room.allows_public_activity(&[7; 32], open.id()));
    assert!(registry
        .search("room-32", 32, 4096)
        .unwrap()
        .rooms
        .is_empty());
    assert_eq!(recovery_room::lookup(&registry, &full), Ok(genesis));

    for malformed in [
        String::new(),
        full[..63].into(),
        format!("{full}0"),
        full.to_uppercase(),
        "é".repeat(32),
        "g".repeat(64),
    ] {
        assert!(recovery_room::lookup(&registry, &malformed).is_err());
    }
    assert!(recovery_room::lookup(&registry, &"0".repeat(64)).is_err());
    let other = vhalla_rooms::registry::Registry::new(DIRECTORY, REALM, policy(), &[]).unwrap();
    assert!(recovery_room::lookup(&other, &full).is_err());
}
