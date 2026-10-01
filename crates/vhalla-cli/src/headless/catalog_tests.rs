//! Catalog crash stages and one-use authorization receipts use real native stores.

use super::*;
use std::path::PathBuf;

#[test]
fn public_creation_mode_survives_binding_completion_and_reopen() {
    let temp = Temp::new();
    let account = Hex([41; 32]);
    let created = Hex([42; 16]);
    let joined = Hex([43; 16]);
    let locator = Locator::Public { pin: Hex([44; 32]) };
    let mut catalog = Catalog::create_new(&temp.path, account).unwrap();
    catalog
        .reserve(created, Kind::Public, commitment(b"created", b""), None)
        .unwrap();
    catalog
        .reserve(
            joined,
            Kind::Public,
            commitment(b"joined", b""),
            Some(locator),
        )
        .unwrap();
    assert_eq!(catalog.public_creation_mode(created), Ok(true));
    assert_eq!(catalog.public_creation_mode(joined), Ok(false));
    catalog.bind(created, locator).unwrap();
    assert_eq!(catalog.public_creation_mode(created), Ok(true));
    catalog.complete(created).unwrap();
    catalog.complete(joined).unwrap();
    drop(catalog);
    let mut catalog = Catalog::open(&temp.path, account).unwrap();
    assert_eq!(catalog.public_creation_mode(created), Ok(true));
    assert_eq!(catalog.public_creation_mode(joined), Ok(false));
    assert_eq!(
        catalog.public_creation_mode(Hex([45; 16])),
        Err(Error::Refused)
    );
    assert!(catalog.check().is_ok());
}

#[test]
fn public_creation_mode_latches_mismatched_immutable_reservation() {
    let temp = Temp::new();
    let account = Hex([46; 32]);
    let id = Hex([47; 16]);
    let mut catalog = Catalog::create_new(&temp.path, account).unwrap();
    catalog
        .reserve(id, Kind::Public, commitment(b"created", b""), None)
        .unwrap();
    let mut altered = catalog.state.clone();
    altered.slots[0].creation_nonce.0[0] ^= 1;
    let image = encode(&altered).unwrap();
    catalog
        .store
        .publish(Some(&catalog.image), &image, &[])
        .unwrap();
    catalog.state = altered;
    catalog.image = image;
    assert_eq!(catalog.public_creation_mode(id), Err(Error::Corrupt));
    assert_eq!(catalog.check(), Err(Error::Uncertain));
}

struct Temp {
    root: tempfile::TempDir,
    path: PathBuf,
}
impl Temp {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("catalog");
        Self { root, path }
    }
}

#[test]
fn creation_stages_reopen_without_reauthorizing_or_changing_the_locator() {
    let temp = Temp::new();
    let account = Hex([1; 32]);
    let id = Hex([2; 16]);
    let intent = commitment(b"create", b"private");
    let mut catalog = Catalog::create_new(&temp.path, account).unwrap();
    assert!(catalog.reserve(id, Kind::Private, intent, None).unwrap());
    let nonce = catalog.slot(id).unwrap().creation_nonce;
    assert_ne!(nonce.0, [0; 32]);
    drop(catalog);
    let mut catalog = Catalog::open(&temp.path, account).unwrap();
    assert!(!catalog.reserve(id, Kind::Private, intent, None).unwrap());
    assert_eq!(catalog.slot(id).unwrap().creation_nonce, nonce);
    assert!(!catalog.slot(id).unwrap().ready);
    assert_eq!(
        catalog.reserve(id, Kind::Public, intent, None),
        Err(Error::Conflict)
    );
    assert_eq!(
        catalog.reserve(id, Kind::Private, commitment(b"other", b""), None),
        Err(Error::Conflict)
    );
    assert_eq!(catalog.complete(id), Err(Error::Refused));
    let locator = Locator::Private {
        room: Hex([3; 32]),
        anchor: Hex([4; 32]),
        account,
        device: Hex([5; 32]),
    };
    catalog.bind(id, locator).unwrap();
    drop(catalog);
    let mut catalog = Catalog::open(&temp.path, account).unwrap();
    assert!(!catalog.reserve(id, Kind::Private, intent, None).unwrap());
    assert_eq!(catalog.slot(id).unwrap().locator, Some(locator));
    assert!(!catalog.slot(id).unwrap().ready);
    assert_eq!(
        catalog.bind(id, Locator::Public { pin: Hex([6; 32]) }),
        Err(Error::Conflict)
    );
    catalog.complete(id).unwrap();
    let before = catalog.accounting().unwrap();
    catalog.complete(id).unwrap();
    catalog.bind(id, locator).unwrap();
    assert!(!catalog.reserve(id, Kind::Private, intent, None).unwrap());
    assert_eq!(catalog.accounting().unwrap(), before);
    drop(catalog);
    let catalog = Catalog::open(&temp.path, account).unwrap();
    assert!(catalog.slot(id).unwrap().ready);
    assert_eq!(catalog.slots().len(), 1);
    assert!(temp.root.path().exists());
}

#[test]
fn grant_claims_survive_restart_and_never_restore_a_budget() {
    let temp = Temp::new();
    let account = Hex([10; 32]);
    let operation = Hex([11; 16]);
    let grant = commitment(b"grant", b"room, methods, expiry and complete allowance");
    let mut catalog = Catalog::create_new(&temp.path, account).unwrap();
    assert!(catalog.claim_grant(operation, grant).unwrap());
    let before = catalog.accounting().unwrap();
    assert!(!catalog.claim_grant(operation, grant).unwrap());
    assert_eq!(catalog.accounting().unwrap(), before);
    assert_eq!(
        catalog.claim_grant(operation, commitment(b"grant", b"other")),
        Err(Error::Conflict)
    );
    drop(catalog);
    let mut catalog = Catalog::open(&temp.path, account).unwrap();
    assert_eq!(catalog.grant_claims(), 1);
    assert!(!catalog.claim_grant(operation, grant).unwrap());
    assert_eq!(
        catalog.claim_grant(Hex([0; 16]), grant),
        Err(Error::Refused)
    );
    assert_eq!(
        catalog.claim_grant(operation, Hex([0; 32])),
        Err(Error::Refused)
    );
    let expanded = Limits {
        max_records: INITIAL_LIMITS.max_records + 1,
        ..INITIAL_LIMITS
    };
    let after = catalog.expand_limits(expanded).unwrap();
    assert_eq!(after.generation, before.generation);
    assert_eq!(after.records, before.records);
    drop(catalog);
    let mut catalog = Catalog::open(&temp.path, account).unwrap();
    assert!(!catalog.claim_grant(operation, grant).unwrap());
    assert_eq!(catalog.accounting().unwrap().limits, expanded);
}

#[test]
fn creation_nonce_is_unique_and_cannot_change_independently_of_immutable_intent() {
    let temp = Temp::new();
    let account = Hex([31; 32]);
    let mut catalog = Catalog::create_new(&temp.path, account).unwrap();
    for number in [32, 33] {
        catalog
            .reserve(
                Hex([number; 16]),
                Kind::Public,
                commitment(b"create", &[number]),
                None,
            )
            .unwrap();
    }
    assert_ne!(
        catalog.slots()[0].creation_nonce,
        catalog.slots()[1].creation_nonce
    );
    let original = catalog.image.clone();
    let mut altered = catalog.state.clone();
    altered.slots[0].creation_nonce.0[0] ^= 1;
    let image = encode(&altered).unwrap();
    drop(catalog);
    let mut store = Store::open(&temp.path, context(account).unwrap()).unwrap();
    store.publish(Some(&original), &image, &[]).unwrap();
    drop(store);
    assert!(matches!(
        Catalog::open(&temp.path, account),
        Err(Error::Corrupt)
    ));
}

#[test]
fn reserved_failed_slots_remain_bounded_and_wrong_account_is_refused() {
    let temp = Temp::new();
    let account = Hex([12; 32]);
    let mut catalog = Catalog::create_new(&temp.path, account).unwrap();
    for number in 1..=MAX_ROOMS {
        assert!(catalog
            .reserve(
                Hex([number as u8; 16]),
                Kind::Public,
                commitment(b"room", &[number as u8]),
                Some(Locator::Public {
                    pin: Hex([number as u8; 32])
                })
            )
            .unwrap());
    }
    let before = catalog.accounting().unwrap();
    assert_eq!(
        catalog.reserve(
            Hex([99; 16]),
            Kind::Public,
            commitment(b"room", b"extra"),
            None
        ),
        Err(Error::Refused)
    );
    assert_eq!(catalog.accounting().unwrap(), before);
    drop(catalog);
    assert!(matches!(
        Catalog::open(&temp.path, Hex([13; 32])),
        Err(Error::Corrupt)
    ));
    let catalog = Catalog::open(&temp.path, account).unwrap();
    assert_eq!(catalog.slots().len(), MAX_ROOMS);
    assert!(catalog.slots().iter().all(|slot| !slot.ready));
}

#[test]
fn a_missing_image_or_inconsistent_reference_is_preserved_and_refused() {
    let temp = Temp::new();
    let account = Hex([14; 32]);
    drop(Store::create_new(&temp.path, context(account).unwrap(), INITIAL_LIMITS).unwrap());
    assert!(matches!(
        Catalog::open(&temp.path, account),
        Err(Error::Corrupt)
    ));
    assert!(temp.path.join("FORMAT").exists());
    let second = temp.root.path().join("inconsistent");
    let mut catalog = Catalog::create_new(&second, account).unwrap();
    let id = Hex([15; 16]);
    catalog
        .reserve(
            id,
            Kind::Public,
            commitment(b"create", b""),
            Some(Locator::Public { pin: Hex([16; 32]) }),
        )
        .unwrap();
    // The storage layer accepts opaque images. The catalog must independently
    // reject a ready bit with no matching immutable completion record.
    let mut altered = catalog.state.clone();
    altered.slots[0].ready = true;
    catalog
        .store
        .publish(Some(&catalog.image), &encode(&altered).unwrap(), &[])
        .unwrap();
    assert_eq!(catalog.check(), Err(Error::Corrupt));
    drop(catalog);
    assert!(matches!(
        Catalog::open(&second, account),
        Err(Error::Corrupt)
    ));
    assert!(second.join("FORMAT").exists());
}

#[test]
fn identifiers_are_full_canonical_nonzero_and_cannot_supply_paths() {
    for invalid in [
        "..",
        "/tmp/state",
        "00",
        &"0".repeat(32),
        &"A".repeat(32),
        &"é".repeat(16),
    ] {
        assert!(Id::parse(invalid).is_err());
    }
    let id = Hex([0x12; 16]);
    assert_eq!(Id::parse(&id.to_string()).unwrap(), id);
    assert_eq!(
        serde_json::from_value::<Id>(serde_json::json!(id)).unwrap(),
        id
    );
    assert_eq!(
        serde_json::from_str::<Id>(&serde_json::to_string(&id).unwrap()).unwrap(),
        id
    );
}

#[test]
fn invalid_locator_fields_refuse_before_publication_and_leave_reopen_intact() {
    let temp = Temp::new();
    let account = Hex([17; 32]);
    let mut catalog = Catalog::create_new(&temp.path, account).unwrap();
    let public = Hex([18; 16]);
    let private = Hex([19; 16]);
    let intent = commitment(b"create", b"bounded");
    catalog.reserve(public, Kind::Public, intent, None).unwrap();
    catalog
        .reserve(private, Kind::Private, intent, None)
        .unwrap();
    let before = catalog.accounting().unwrap();
    let mut invalid = vec![Locator::Public { pin: Hex([0; 32]) }];
    for index in 0..4 {
        let mut fields = [Hex([20; 32]), Hex([21; 32]), account, Hex([22; 32])];
        fields[index] = Hex([0; 32]);
        invalid.push(Locator::Private {
            room: fields[0],
            anchor: fields[1],
            account: fields[2],
            device: fields[3],
        });
    }
    for locator in invalid {
        let existing = if locator.kind() == Kind::Public {
            public
        } else {
            private
        };
        assert_eq!(catalog.bind(existing, locator), Err(Error::Refused));
        assert_eq!(
            catalog.reserve(Hex([23; 16]), locator.kind(), intent, Some(locator)),
            Err(Error::Refused)
        );
        assert_eq!(catalog.accounting().unwrap(), before);
    }
    drop(catalog);
    let catalog = Catalog::open(&temp.path, account).unwrap();
    assert_eq!(catalog.slots().len(), 2);
    assert!(catalog.slots().iter().all(|slot| slot.locator.is_none()));
}
