//! Registry state regressions over real verified wire records.
//!
//! These tests qualify deterministic application of the agreed record order:
//! control admission, award credit, creation accounting, retries, rate limits,
//! revision chains and tombstones. Consensus ordering, durability and live
//! transport remain the engine and store layers' obligations.
mod common;
use common::*;
use vhalla_rooms::{
    registry::{Applied, Registry, RegistryError, MAX_OWNERS},
    Denial, Description, PolicyId, RoomGenesisId, RoomRecordId, RoomUpdate, Slug, UpdateAction,
};
use vhalla_social::{archive::Archive, control::ControlView, Body, Operation};

#[test]
fn grant_award_create_and_search_flow() {
    let mut archive = Archive::new(REALM, limits()).unwrap();
    let creator = beneficiary(&mut archive, 1);
    let (mut pool, mut registry) = sources(&mut archive, 60, 1);
    let head = grant_create(&mut registry, &archive, &creator, 100);
    // No credit yet: authority passes but accounting denies.
    let record = creation(&creator, head, head, "rust-games", 1, 1, 7);
    assert_eq!(
        apply(&mut registry, &archive, &record, 200),
        Err(RegistryError::InsufficientCredit)
    );
    award_one(&mut registry, &mut archive, &mut pool[0], &creator, 200);
    assert_eq!(registry.account(creator.id).earned, 1);
    // The same verified record now registers the room.
    let genesis = match apply(&mut registry, &archive, &record, 300).unwrap() {
        Applied::Created(id) => id,
        other => panic!("expected creation, got {other:?}"),
    };
    // An exact retry returns the same identity without charging again.
    assert_eq!(
        apply(&mut registry, &archive, &record, 300),
        Ok(Applied::Existing(genesis))
    );
    assert_eq!(registry.account(creator.id).spent, 1);
    let room = registry.room(&Slug::new("rust-games").unwrap()).unwrap();
    assert_eq!(room.genesis(), genesis);
    assert!(!room.archived());
    let found = registry.search("rust", 8, 64).unwrap();
    assert_eq!(found.rooms.len(), 1);
    // The next quote is slot two at the quadratic price.
    assert_eq!(registry.quote(creator.id), Ok((2, 4)));
}

#[test]
fn slug_taken_and_wrong_policy_are_denied() {
    let mut archive = Archive::new(REALM, limits()).unwrap();
    let creator = beneficiary(&mut archive, 2);
    let (mut pool, mut registry) = sources(&mut archive, 70, 6);
    let head = grant_create(&mut registry, &archive, &creator, 100);
    for source in &mut pool {
        award_one(&mut registry, &mut archive, source, &creator, 200);
    }
    apply(
        &mut registry,
        &archive,
        &creation(&creator, head, head, "taken-room", 1, 1, 8),
        300,
    )
    .unwrap();
    // A different nonce still collides on the finalized slug.
    let second = creation(&creator, head, head, "taken-room", 2, 4, 9);
    assert_eq!(
        apply(&mut registry, &archive, &second, 400),
        Err(RegistryError::Taken)
    );
    // An intent naming a foreign policy never reaches accounting.
    let foreign = creation_with_policy(
        &creator,
        head,
        head,
        "other-room",
        2,
        4,
        10,
        PolicyId::from_bytes([0; 32]),
    );
    assert_eq!(
        apply(&mut registry, &archive, &foreign, 400),
        Err(RegistryError::WrongPolicy)
    );
}

#[test]
fn rate_limit_and_lifetime_slots_hold_across_creations() {
    let mut archive = Archive::new(REALM, limits()).unwrap();
    let creator = beneficiary(&mut archive, 3);
    let (mut pool, mut registry) = sources(&mut archive, 80, 5);
    let head = grant_create(&mut registry, &archive, &creator, 100);
    for source in &mut pool {
        award_one(&mut registry, &mut archive, source, &creator, 200);
    }
    apply(
        &mut registry,
        &archive,
        &creation(&creator, head, head, "first", 1, 1, 11),
        300,
    )
    .unwrap();
    // The rolling window denies a second creation even with enough credit.
    let second = creation(&creator, head, head, "second", 2, 4, 12);
    assert_eq!(
        apply(&mut registry, &archive, &second, 400),
        Err(RegistryError::RateLimit)
    );
    // Past the window the same owner takes slot two at the higher price.
    assert_eq!(
        apply(&mut registry, &archive, &second, 300 + EPOCH),
        Ok(Applied::Created(
            second.clone().verify().unwrap().genesis_id().unwrap()
        ))
    );
    assert_eq!(registry.account(creator.id).lifetime_slots, 2);
    assert_eq!(registry.account(creator.id).spent, 5);
}

#[test]
fn updates_follow_the_revision_chain_and_archive_tombstones() {
    let mut archive = Archive::new(REALM, limits()).unwrap();
    let creator = beneficiary(&mut archive, 4);
    let (mut pool, mut registry) = sources(&mut archive, 90, 2);
    let head = grant_create(&mut registry, &archive, &creator, 100);
    award_one(&mut registry, &mut archive, &mut pool[0], &creator, 200);
    let create = creation(&creator, head, head, "edited-room", 1, 1, 13);
    let genesis: RoomGenesisId = match apply(&mut registry, &archive, &create, 300).unwrap() {
        Applied::Created(id) => id,
        other => panic!("expected creation, got {other:?}"),
    };
    let create_id = create.id();
    let edit = |previous: RoomRecordId, nonce: u8, action: UpdateAction| {
        RoomUpdate {
            directory: DIRECTORY,
            realm: REALM,
            genesis,
            previous,
            owner: creator.id,
            social_control: creator.head,
            controller_key: creator.key.verifying_key().to_bytes(),
            expires_at: 1_000_000,
            nonce: [nonce; 32],
            action,
        }
        .sign_with_key(&creator.key)
        .unwrap()
        .verify()
        .unwrap()
    };
    let describe = edit(
        create_id,
        15,
        UpdateAction::Describe(Description::new("better room").unwrap()),
    );
    let view = ControlView::new(&archive, 400);
    assert_eq!(
        registry.apply(&describe, &view, 400),
        Ok(Applied::Updated(describe.id()))
    );
    drop(view);
    assert_eq!(
        registry
            .room(&Slug::new("edited-room").unwrap())
            .unwrap()
            .description()
            .as_str(),
        "better room"
    );
    // A stale predecessor never rewrites newer state.
    let stale = edit(create_id, 14, UpdateAction::Archive);
    let view = ControlView::new(&archive, 400);
    assert_eq!(
        registry.apply(&stale, &view, 400),
        Err(RegistryError::StaleRevision)
    );
    drop(view);
    // Archiving keeps the slug and hides the room from search.
    let archive_it = edit(describe.id(), 16, UpdateAction::Archive);
    let view = ControlView::new(&archive, 400);
    assert_eq!(
        registry.apply(&archive_it, &view, 400),
        Ok(Applied::Updated(archive_it.id()))
    );
    drop(view);
    let room = registry.room(&Slug::new("edited-room").unwrap()).unwrap();
    assert!(room.archived());
    assert!(registry.search("edited", 8, 64).unwrap().rooms.is_empty());
    // The tombstone still owns the slug.
    award_one(&mut registry, &mut archive, &mut pool[1], &creator, 500);
    let retry_slug = creation(&creator, head, head, "edited-room", 2, 4, 17);
    assert_eq!(
        apply(&mut registry, &archive, &retry_slug, 500),
        Err(RegistryError::Taken)
    );
    // Updates on an archived room are denied.
    let post_archive = edit(
        archive_it.id(),
        18,
        UpdateAction::Describe(Description::new("revived").unwrap()),
    );
    let view = ControlView::new(&archive, 500);
    assert_eq!(
        registry.apply(&post_archive, &view, 500),
        Err(RegistryError::Archived)
    );
}

#[test]
fn awards_dedup_by_source_beneficiary_and_epoch() {
    let mut archive = Archive::new(REALM, limits()).unwrap();
    let creator = beneficiary(&mut archive, 5);
    let (mut pool, mut registry) = sources(&mut archive, 100, 2);
    award_one(&mut registry, &mut archive, &mut pool[0], &creator, 200);
    // Same evidence again: no second credit.
    let record = archive
        .records()
        .find(|r| {
            matches!(
                r.body(),
                Body::Social {
                    operation: Operation::React { .. },
                    ..
                }
            )
        })
        .unwrap()
        .clone();
    let view = ControlView::new(&archive, 300);
    assert_eq!(
        registry.award(&record, &view, 300),
        Ok(Applied::DuplicateAward)
    );
    drop(view);
    // A different source reacting in the same epoch still credits.
    award_one(&mut registry, &mut archive, &mut pool[1], &creator, 300);
    assert_eq!(registry.account(creator.id).earned, 2);
}

#[test]
fn non_owner_updates_and_stale_grant_authority_are_denied() {
    let mut archive = Archive::new(REALM, limits()).unwrap();
    let creator = beneficiary(&mut archive, 6);
    let other = owner(&mut archive, 120);
    let (mut pool, mut registry) = sources(&mut archive, 130, 1);
    let head = grant_create(&mut registry, &archive, &creator, 100);
    award_one(&mut registry, &mut archive, &mut pool[0], &creator, 200);
    let create = creation(&creator, head, head, "guarded", 1, 1, 20);
    let genesis = match apply(&mut registry, &archive, &create, 300).unwrap() {
        Applied::Created(id) => id,
        other => panic!("expected creation, got {other:?}"),
    };
    // A different owner cannot edit the room even with valid authority.
    let foreign = RoomUpdate {
        directory: DIRECTORY,
        realm: REALM,
        genesis,
        previous: create.id(),
        owner: other.id,
        social_control: other.head,
        controller_key: other.key.verifying_key().to_bytes(),
        expires_at: 1_000_000,
        nonce: [21; 32],
        action: UpdateAction::Archive,
    }
    .sign_with_key(&other.key)
    .unwrap()
    .verify()
    .unwrap();
    let view = ControlView::new(&archive, 400);
    assert_eq!(
        registry.apply(&foreign, &view, 400),
        Err(RegistryError::OwnerMismatch)
    );
    // An intent naming a grant that was never admitted is denied.
    let ghost = creation(
        &creator,
        head,
        RoomRecordId::from_bytes([77; 32]),
        "ghost",
        2,
        4,
        22,
    );
    drop(view);
    assert_eq!(
        apply(&mut registry, &archive, &ghost, 400),
        Err(RegistryError::Authority(Denial::Grant))
    );
    let _ = genesis;
}

#[test]
fn snapshot_round_trip_and_restore_continuity() {
    let mut archive = Archive::new(REALM, limits()).unwrap();
    let creator = beneficiary(&mut archive, 7);
    let (mut pool, mut registry) = sources(&mut archive, 140, 5);
    let head = grant_create(&mut registry, &archive, &creator, 100);
    award_one(&mut registry, &mut archive, &mut pool[0], &creator, 200);
    award_one(&mut registry, &mut archive, &mut pool[1], &creator, 200);
    let create = creation(&creator, head, head, "snap-room", 1, 1, 30);
    let genesis = match apply(&mut registry, &archive, &create, 300).unwrap() {
        Applied::Created(id) => id,
        other => panic!("expected creation, got {other:?}"),
    };
    let edit = RoomUpdate {
        directory: DIRECTORY,
        realm: REALM,
        genesis,
        previous: create.id(),
        owner: creator.id,
        social_control: creator.head,
        controller_key: creator.key.verifying_key().to_bytes(),
        expires_at: 1_000_000,
        nonce: [31; 32],
        action: UpdateAction::Describe(Description::new("snapshot me").unwrap()),
    }
    .sign_with_key(&creator.key)
    .unwrap()
    .verify()
    .unwrap();
    let view = ControlView::new(&archive, 400);
    assert_eq!(
        registry.apply(&edit, &view, 400),
        Ok(Applied::Updated(edit.id()))
    );
    drop(view);
    let digest = registry.digest();
    let snapshot = registry.snapshot();
    // A restored registry is byte-identical and keeps the agreed state.
    let mut restored = Registry::restore(&snapshot).unwrap();
    assert_eq!(restored.digest(), digest);
    assert_eq!(restored.snapshot(), snapshot);
    assert_eq!(restored.revision(), registry.revision());
    assert_eq!(restored.last_time(), registry.last_time());
    assert_eq!(restored.account(creator.id).earned, 2);
    assert_eq!(restored.account(creator.id).lifetime_slots, 1);
    let room = restored.room(&Slug::new("snap-room").unwrap()).unwrap();
    assert_eq!(room.description().as_str(), "snapshot me");
    assert_eq!(room.head(), edit.id());
    // Source proofs survive the round trip byte-for-byte.
    assert_eq!(
        restored.source_proof(edit.id()).unwrap(),
        registry.source_proof(edit.id()).unwrap()
    );
    assert!(restored.source_proof(create.id()).is_some());
    // The restored registry still applies the agreed order at the same clock.
    award_one(&mut restored, &mut archive, &mut pool[2], &creator, 500);
    award_one(&mut restored, &mut archive, &mut pool[3], &creator, 500);
    award_one(&mut restored, &mut archive, &mut pool[4], &creator, 500);
    assert_eq!(restored.account(creator.id).earned, 5);
    let second = creation(&creator, head, head, "snap-two", 2, 4, 32);
    assert!(matches!(
        apply(&mut restored, &archive, &second, 300 + EPOCH),
        Ok(Applied::Created(_))
    ));
    // The original registry is untouched by the restored copy.
    assert_eq!(registry.account(creator.id).earned, 2);
}

#[test]
fn snapshot_integrity_and_bounds_are_checked() {
    let mut archive = Archive::new(REALM, limits()).unwrap();
    let creator = beneficiary(&mut archive, 8);
    let (mut pool, mut registry) = sources(&mut archive, 150, 1);
    let head = grant_create(&mut registry, &archive, &creator, 100);
    award_one(&mut registry, &mut archive, &mut pool[0], &creator, 200);
    apply(
        &mut registry,
        &archive,
        &creation(&creator, head, head, "tampered", 1, 1, 40),
        300,
    )
    .unwrap();
    let snapshot = registry.snapshot();
    // Truncation, bad magic and flipped payload bytes all fail integrity.
    assert!(matches!(
        Registry::restore(&snapshot[..snapshot.len() - 40]),
        Err(RegistryError::Corrupt)
    ));
    let mut bad_magic = snapshot.clone();
    bad_magic[0] ^= 1;
    assert!(matches!(
        Registry::restore(&bad_magic),
        Err(RegistryError::Corrupt)
    ));
    let mut tampered = snapshot.clone();
    let middle = tampered.len() / 2;
    tampered[middle] ^= 1;
    assert!(matches!(
        Registry::restore(&tampered),
        Err(RegistryError::Corrupt)
    ));
    // An empty registry round-trips too.
    let empty = Registry::new(DIRECTORY, REALM, policy(), &[]).unwrap();
    assert_eq!(
        Registry::restore(&empty.snapshot()).unwrap().digest(),
        empty.digest()
    );
}

/// The committed eligible-set transition: replaces under the agreed clock,
/// bounded like genesis, and rejects clock rewind.
#[test]
fn eligible_set_transition_replaces_and_bounds() {
    let mut archive = Archive::new(REALM, limits()).unwrap();
    let (pool, mut registry) = sources(&mut archive, 60, 2);
    let keep = pool[0].id;
    let extra = beneficiary(&mut archive, 7).id;
    registry.set_eligible(&[keep, extra], 5).unwrap();
    assert_eq!(registry.eligible().len(), 2);
    assert!(registry.eligible().contains(&extra));

    // Over the owner bound fails closed; the committed set is untouched.
    let too_many: Vec<vhalla_social::OwnerId> = (0..=MAX_OWNERS)
        .map(|i| vhalla_social::OwnerId::from_bytes([i as u8; 32]))
        .collect();
    assert_eq!(
        registry.set_eligible(&too_many, 6),
        Err(RegistryError::Capacity)
    );
    assert_eq!(registry.eligible().len(), 2);

    // The agreed-clock gate holds.
    assert_eq!(registry.set_eligible(&[keep], 4), Err(RegistryError::Clock));
    assert_eq!(registry.last_time(), 5);
}

#[test]
fn snapshot_restore_accepts_only_canonical_bytes() {
    // Canonical-form invariant: any input `restore` accepts must re-snapshot
    // to the identical bytes. Exhaustively mutating and truncating a valid
    // snapshot therefore covers the noncanonical-input space — a panic or a
    // restore-then-snapshot difference is a codec bug.
    let mut archive = Archive::new(REALM, limits()).unwrap();
    let creator = beneficiary(&mut archive, 8);
    let (mut pool, mut registry) = sources(&mut archive, 40, 3);
    let head = grant_create(&mut registry, &archive, &creator, 100);
    award_one(&mut registry, &mut archive, &mut pool[0], &creator, 200);
    let create = creation(&creator, head, head, "canonical", 1, 1, 5);
    let genesis: RoomGenesisId = match apply(&mut registry, &archive, &create, 300).unwrap() {
        Applied::Created(id) => id,
        other => panic!("expected creation, got {other:?}"),
    };
    let describe = RoomUpdate {
        directory: DIRECTORY,
        realm: REALM,
        genesis,
        previous: create.id(),
        owner: creator.id,
        social_control: creator.head,
        controller_key: creator.key.verifying_key().to_bytes(),
        expires_at: 1_000_000,
        nonce: [9; 32],
        action: UpdateAction::Describe(Description::new("canonical room").unwrap()),
    }
    .sign_with_key(&creator.key)
    .unwrap()
    .verify()
    .unwrap();
    let view = ControlView::new(&archive, 400);
    assert_eq!(
        registry.apply(&describe, &view, 400),
        Ok(Applied::Updated(describe.id()))
    );

    let snapshot = registry.snapshot();
    assert_eq!(Registry::restore(&snapshot).unwrap().snapshot(), snapshot);

    for cut in 0..=snapshot.len() {
        if let Ok(restored) = Registry::restore(&snapshot[..cut]) {
            assert_eq!(
                restored.snapshot(),
                snapshot[..cut],
                "prefix {cut} noncanonical"
            );
        }
    }
    for i in 0..snapshot.len() {
        for delta in [0x01u8, 0x80, 0xFF] {
            let mut mutated = snapshot.clone();
            mutated[i] ^= delta;
            if let Ok(restored) = Registry::restore(&mutated) {
                assert_eq!(restored.snapshot(), mutated, "mutation at {i} noncanonical");
            }
        }
    }
}
