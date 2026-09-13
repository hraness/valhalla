use super::*;
use ed25519_dalek::SigningKey;
use proptest::prelude::*;
use std::os::unix::fs::{symlink, PermissionsExt};
use vhalla_social::{
    archive::Budget, Actor, Body, Operation, OwnerId, Placement, RecordId, SignedRecord, Text,
    UnsignedRecord, MAX_RECORD_BYTES,
};

const REALM: RealmId = RealmId(71);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).unwrap();
        let name: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let path =
            std::env::temp_dir().join(format!("vhalla-social-store-{}-{name}", std::process::id()));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn store(&self) -> PathBuf {
        self.0.join("store")
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn key() -> SigningKey {
    SigningKey::from_bytes(&[1; 32])
}
fn signed(body: Body) -> SignedRecord {
    UnsignedRecord::new(key().verifying_key().to_bytes(), body)
        .unwrap()
        .sign_with_key(&key())
        .unwrap()
        .finish()
        .unwrap()
}
fn id(record: &SignedRecord) -> RecordId {
    record.clone().verify().unwrap().id()
}
fn add(archive: &mut Archive, record: &SignedRecord) {
    archive
        .ingest(
            &record.encode(),
            &mut Budget::new(1, MAX_RECORD_BYTES).unwrap(),
        )
        .unwrap();
}
fn records() -> Vec<SignedRecord> {
    let root = signed(Body::OwnerGenesis {
        controller: key().verifying_key().to_bytes(),
        recovery: None,
        nonce: [1; 32],
    });
    let actor = Actor::Owner {
        owner: OwnerId::from_bytes(*id(&root).as_bytes()),
        control: id(&root),
    };
    let post = signed(Body::Social {
        actor,
        realm: REALM,
        sequence: 0,
        previous: None,
        operation: Operation::Post {
            placement: Placement::Profile,
            text: Text::new("retained history").unwrap(),
            reply: None,
            quote: None,
        },
    });
    let retract = signed(Body::Social {
        actor,
        realm: REALM,
        sequence: 1,
        previous: Some(id(&post)),
        operation: Operation::Retract { post: id(&post) },
    });
    vec![root, post, retract]
}
fn setup() -> (Temp, Store, Vec<SignedRecord>) {
    let temp = Temp::new();
    let mut store = Store::create(temp.store(), REALM, Limits::default()).unwrap();
    let records = records();
    let mut base = store.archive().clone();
    add(&mut base, &records[0]);
    add(&mut base, &records[1]);
    store.commit(base, store.pin()).unwrap();
    (temp, store, records)
}
fn rewrite(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

#[test]
fn initialize_commit_restart_and_reclaim_only_duplicate_physical_copies() {
    let (temp, mut store, records) = setup();
    assert!(matches!(
        Store::create(temp.store(), REALM, Limits::default()),
        Err(Error::Io(_))
    ));
    assert_eq!(store.pin().generation(), 1);
    let prior = store.pin();
    let mut candidate = store.archive().clone();
    add(&mut candidate, &records[2]);
    let publication = store.commit(candidate.clone(), prior).unwrap();
    assert!(!publication.reconciled());
    assert_eq!(publication.pin().generation(), 2);
    assert_eq!(publication.snapshot(), candidate.snapshot());
    assert_eq!(fs::read_dir(temp.store()).unwrap().count(), 3);
    let current = publication.pin();
    drop(store);
    let mut reopened = Store::open(temp.store(), REALM, Limits::default(), Some(current)).unwrap();
    assert_eq!(reopened.archive().root(), candidate.root());
    assert!(reopened.archive().get(id(&records[2])).is_some());
    let duplicate = reopened.commit(candidate, prior).unwrap();
    assert!(duplicate.reconciled());
    assert_eq!(duplicate.pin(), current);
}

#[test]
fn stale_basis_and_forward_generation_truncation_cannot_publish() {
    let (temp, mut store, records) = setup();
    let old = store.pin();
    let truncated = store.archive().clone();
    let mut complete = truncated.clone();
    add(&mut complete, &records[2]);
    store.commit(complete, old).unwrap();
    let current = store.pin();
    let bytes = store.archive().snapshot();
    assert!(matches!(
        store.commit(truncated, current),
        Err(Error::Conflict)
    ));
    let extra = signed(Body::OwnerGenesis {
        controller: key().verifying_key().to_bytes(),
        recovery: None,
        nonce: [2; 32],
    });
    let mut candidate = store.archive().clone();
    add(&mut candidate, &extra);
    assert!(matches!(store.commit(candidate, old), Err(Error::Conflict)));
    assert_eq!(store.pin(), current);
    assert_eq!(store.archive().snapshot(), bytes);
    assert_eq!(fs::read_dir(temp.store()).unwrap().count(), 3);
}

#[test]
fn each_publication_boundary_recovers_exact_history_or_preserves_torn_intent() {
    let steps = [
        Step::IntentCreated,
        Step::IntentWritten,
        Step::IntentDurable,
        Step::BundleWritten,
        Step::BundleSynced,
        Step::BundleRenamed,
        Step::BundleDurable,
        Step::PinWritten,
        Step::PinSynced,
        Step::PinRenamed,
        Step::PinDurable,
        Step::IntentRemoved,
        Step::CleanupDurable,
    ];
    for step in steps {
        let (temp, mut store, records) = setup();
        let expected = store.pin();
        let prior = store.archive().clone();
        let mut candidate = prior.clone();
        add(&mut candidate, &records[2]);
        store.fault = Some(step);
        assert!(
            matches!(
                store.commit(candidate.clone(), expected),
                Err(Error::Indeterminate(_))
            ),
            "{step:?}"
        );
        drop(store);
        if step == Step::IntentCreated {
            assert!(matches!(
                Store::open(temp.store(), REALM, Limits::default(), None),
                Err(Error::Corrupt)
            ));
            assert_eq!(
                fs::read(temp.store().join(INTENT)).unwrap(),
                Vec::<u8>::new()
            );
            assert_eq!(
                Pin::decode(&fs::read(temp.store().join(PIN)).unwrap()).unwrap(),
                expected
            );
            continue;
        }
        let mut recovered = Store::open(temp.store(), REALM, Limits::default(), None).unwrap();
        let publication = recovered.recover().unwrap();
        assert!(publication.reconciled());
        assert_eq!(
            publication.pin().generation(),
            expected.generation() + 1,
            "{step:?}"
        );
        assert_eq!(recovered.archive().root(), candidate.root(), "{step:?}");
        assert!(recovered.archive().is_extension_of(&prior));
        assert!(recovered.archive().get(id(&records[2])).is_some());
        assert_eq!(fs::read_dir(temp.store()).unwrap().count(), 3, "{step:?}");
        assert_eq!(
            recovered.commit(candidate, expected).unwrap().pin(),
            publication.pin()
        );
    }
}

#[test]
fn pending_exact_intent_rejects_a_different_candidate_and_same_candidate_reconciles() {
    let (temp, mut store, records) = setup();
    let expected = store.pin();
    let mut candidate = store.archive().clone();
    add(&mut candidate, &records[2]);
    store.fault = Some(Step::IntentDurable);
    assert!(store.commit(candidate.clone(), expected).is_err());
    drop(store);
    let mut reopened = Store::open(temp.store(), REALM, Limits::default(), Some(expected)).unwrap();
    assert!(reopened.recovery_required().unwrap());
    let old = reopened.archive().clone();
    assert!(matches!(
        reopened.commit(old, expected),
        Err(Error::RecoveryRequired)
    ));
    assert!(reopened
        .commit(candidate.clone(), expected)
        .unwrap()
        .reconciled());
    assert_eq!(reopened.archive().root(), candidate.root());
}

#[test]
fn exact_intent_can_complete_a_known_partial_temp_but_preserves_different_bytes() {
    for corrupt in [false, true] {
        let (temp, mut store, records) = setup();
        let expected = store.pin();
        let mut candidate = store.archive().clone();
        add(&mut candidate, &records[2]);
        store.fault = Some(Step::IntentDurable);
        assert!(store.commit(candidate.clone(), expected).is_err());
        let bytes = if corrupt {
            vec![255; 17]
        } else {
            candidate.snapshot()[..17].to_vec()
        };
        let mut partial = create_private(&temp.store().join(BUNDLE_TEMP)).unwrap();
        partial.write_all(&bytes).unwrap();
        partial.sync_all().unwrap();
        drop(store);
        let mut reopened = Store::open(temp.store(), REALM, Limits::default(), None).unwrap();
        if corrupt {
            assert!(matches!(reopened.recover(), Err(Error::Corrupt)));
            assert_eq!(fs::read(temp.store().join(BUNDLE_TEMP)).unwrap(), bytes);
            assert_eq!(reopened.pin(), expected);
        } else {
            reopened.recover().unwrap();
            assert_eq!(reopened.archive().root(), candidate.root());
        }
    }
}

#[test]
fn torn_intent_and_corrupt_pin_do_not_become_an_empty_store() {
    let (temp, mut store, records) = setup();
    let expected = store.pin();
    let mut candidate = store.archive().clone();
    add(&mut candidate, &records[2]);
    store.fault = Some(Step::IntentDurable);
    assert!(store.commit(candidate, expected).is_err());
    drop(store);
    let intent = fs::read(temp.store().join(INTENT)).unwrap();
    rewrite(&temp.store().join(INTENT), &intent[..intent.len() / 2]);
    assert!(matches!(
        Store::open(temp.store(), REALM, Limits::default(), None),
        Err(Error::Corrupt)
    ));
    assert_eq!(
        fs::metadata(temp.store().join(INTENT)).unwrap().len(),
        (intent.len() / 2) as u64
    );
    let (other, store, _) = setup();
    drop(store);
    let mut pin = fs::read(other.store().join(PIN)).unwrap();
    pin[16] ^= 1;
    rewrite(&other.store().join(PIN), &pin);
    assert!(matches!(
        Store::open(other.store(), REALM, Limits::default(), None),
        Err(Error::Corrupt)
    ));
    assert_eq!(fs::read(other.store().join(PIN)).unwrap(), pin);
}

#[test]
fn observed_permissions_links_and_unknown_files_fail_closed_without_deletion() {
    for case in 0..5 {
        let (temp, store, _) = setup();
        drop(store);
        match case {
            0 => fs::set_permissions(temp.store(), fs::Permissions::from_mode(0o755)).unwrap(),
            1 => fs::set_permissions(temp.store().join(PIN), fs::Permissions::from_mode(0o644))
                .unwrap(),
            2 => {
                fs::hard_link(temp.store().join(PIN), temp.0.join("linked-pin")).unwrap();
            }
            3 => {
                fs::rename(temp.store().join(PIN), temp.0.join("original-pin")).unwrap();
                symlink(temp.0.join("original-pin"), temp.store().join(PIN)).unwrap();
            }
            4 => {
                create_private(&temp.store().join("user-notes"))
                    .unwrap()
                    .write_all(b"preserve")
                    .unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            matches!(
                Store::open(temp.store(), REALM, Limits::default(), None),
                Err(Error::UnsafePath)
            ),
            "case {case}"
        );
        if case == 4 {
            assert_eq!(
                fs::read(temp.store().join("user-notes")).unwrap(),
                b"preserve"
            );
        }
    }
}

#[test]
fn lock_is_exclusive_across_handles_and_processes() {
    let (temp, store, _) = setup();
    assert!(matches!(
        Store::open(temp.store(), REALM, Limits::default(), None),
        Err(Error::Busy)
    ));
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "unix::tests::child_lock_probe", "--nocapture"])
        .env("VHALLA_SOCIAL_LOCK_PROBE", temp.store())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    drop(store);
    assert!(Store::open(temp.store(), REALM, Limits::default(), None).is_ok());
}

#[test]
fn child_lock_probe() {
    if let Some(path) = std::env::var_os("VHALLA_SOCIAL_LOCK_PROBE") {
        assert!(matches!(
            Store::open(path, REALM, Limits::default(), None),
            Err(Error::Busy)
        ));
    }
}

#[test]
fn external_exact_anchor_rejects_rollback_and_forward_renumbering() {
    let (temp, mut store, records) = setup();
    let old = store.archive().clone();
    let mut current = old.clone();
    add(&mut current, &records[2]);
    store.commit(current, store.pin()).unwrap();
    let anchor = store.pin();
    drop(store);
    // Simulate replacement of the entire disk state with a coherent old signed
    // archive and an attacker-increased, checksummed but unsigned generation.
    fs::remove_file(temp.store().join(bundle_name(anchor.physical()))).unwrap();
    let forged = Pin::for_archive(999, &old);
    create_private(&temp.store().join(bundle_name(forged.physical())))
        .unwrap()
        .write_all(&old.snapshot())
        .unwrap();
    rewrite(&temp.store().join(PIN), &forged.encode());
    assert!(matches!(
        Store::open(temp.store(), REALM, Limits::default(), Some(anchor)),
        Err(Error::Freshness)
    ));
    let without_anchor = Store::open(temp.store(), REALM, Limits::default(), None).unwrap();
    assert!(
        without_anchor.archive().get(id(&records[2])).is_none(),
        "local integrity cannot detect coherent hostile rollback"
    );
}

#[test]
fn unrelated_or_corrupt_bundle_is_preserved_and_never_reclaimed() {
    let (temp, store, _) = setup();
    let mut unrelated = Archive::new(REALM, Limits::default()).unwrap();
    let foreign = signed(Body::OwnerGenesis {
        controller: key().verifying_key().to_bytes(),
        recovery: None,
        nonce: [99; 32],
    });
    add(&mut unrelated, &foreign);
    let name = bundle_name(unrelated.physical_digest());
    create_private(&temp.store().join(&name))
        .unwrap()
        .write_all(&unrelated.snapshot())
        .unwrap();
    drop(store);
    let opened = Store::open(temp.store(), REALM, Limits::default(), None);
    assert!(
        matches!(opened, Err(Error::Conflict)),
        "unrelated bundle must conflict: {:?}",
        opened.err()
    );
    assert_eq!(
        fs::read(temp.store().join(&name)).unwrap(),
        unrelated.snapshot()
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]
    #[test]
    fn pin_roundtrip_and_changed_bits_fail_integrity(generation in any::<u64>(), offset in 0usize..PIN_BYTES, bit in 0u8..8) {
        let archive = Archive::new(REALM, Limits::default()).unwrap();
        let pin = Pin::for_archive(generation, &archive);
        let mut raw = pin.encode();
        prop_assert_eq!(Pin::decode(&raw).unwrap(), pin);
        raw[offset] ^= 1 << bit;
        prop_assert!(Pin::decode(&raw).is_err());
    }
}
