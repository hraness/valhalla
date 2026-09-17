use super::*;
use ed25519_dalek::SigningKey;
use hegel::{generators as gs, HealthCheck, TestCase};
use proptest::prelude::*;
use std::collections::BTreeSet;
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
fn shared_reader_waits_out_a_writers_lock_and_reads_the_fresh_tip() {
    let (temp, mut store, records) = setup();
    let path = temp.store();
    let reader = std::thread::spawn(move || read_archive(path, REALM, Limits::default()));
    // The writer still holds its exclusive lock: publish a new tip while
    // the reader is parked on the shared acquire, then release — the
    // reader must observe the commit, never a torn or stale pair.
    std::thread::sleep(std::time::Duration::from_millis(300));
    let mut candidate = store.archive().clone();
    add(&mut candidate, &records[2]);
    store.commit(candidate.clone(), store.pin()).unwrap();
    drop(store);
    let archive = reader.join().unwrap().unwrap();
    assert_eq!(archive.root(), candidate.root());
    assert!(archive.get(id(&records[2])).is_some());
}

#[test]
fn shared_readers_proceed_concurrently_and_match_the_committed_tip() {
    let (temp, store, _) = setup();
    let tip = store.archive().root();
    drop(store);
    let mut readers = Vec::new();
    for _ in 0..4 {
        let path = temp.store();
        readers.push(std::thread::spawn(move || {
            read_archive(path, REALM, Limits::default())
        }));
    }
    for reader in readers {
        assert_eq!(reader.join().unwrap().unwrap().root(), tip);
    }
}

#[test]
fn shared_reader_on_a_missing_store_fails_closed() {
    let temp = Temp::new();
    assert!(read_archive(temp.store(), REALM, Limits::default()).is_err());
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

// ---------------------------------------------------------------------------
// Generative Hegel properties over the archive lifecycle. Each case draws an
// interleaved command sequence — create owner identities, grow their signed
// post chains in a staging pool, re-ingest retained records, commit a fresh
// generation, restart under drawn anchors, attempt stale/divergent
// publications, interrupt a commit at a drawn boundary step — with generators
// fed from the state accumulated so far (created owners, pool records,
// published pins, committed snapshots). `recovery_hegel.rs` in vhalla-ledger
// is the reference for the draw-inside-the-loop style.
// ---------------------------------------------------------------------------

/// Every publication-boundary step a case can inject, mirroring `Step`.
const STEPS: [Step; 13] = [
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

/// Drawn seeds space distinct owner keys; any byte pattern derives a key.
const MAX_SEED: u8 = 200;

/// An owner identity root and its linear post chain, all under one key.
struct Owner {
    key: SigningKey,
    id: OwnerId,
    root: SignedRecord,
    posts: Vec<SignedRecord>,
}

/// A self-signed owner genesis; its record id is the owner id.
fn owner(seed: u8) -> Owner {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let root = UnsignedRecord::new(
        key.verifying_key().to_bytes(),
        Body::OwnerGenesis {
            controller: key.verifying_key().to_bytes(),
            recovery: None,
            nonce: [seed; 32],
        },
    )
    .unwrap()
    .sign_with_key(&key)
    .unwrap()
    .finish()
    .unwrap();
    Owner {
        key,
        id: OwnerId::from_bytes(*root.id().as_bytes()),
        root,
        posts: Vec::new(),
    }
}

/// The next post in `owner`'s chain; `sequence`/`previous` keep every record
/// distinct, so each is always a fresh insert into any archive lacking it.
fn chain_post(owner: &Owner) -> SignedRecord {
    UnsignedRecord::new(
        owner.key.verifying_key().to_bytes(),
        Body::Social {
            actor: Actor::Owner {
                owner: owner.id,
                control: owner.root.id(),
            },
            realm: REALM,
            sequence: owner.posts.len() as u64,
            previous: owner.posts.last().map(|record| record.id()),
            operation: Operation::Post {
                placement: Placement::Profile,
                text: Text::new(&format!("chain-{}", owner.posts.len())).unwrap(),
                reply: None,
                quote: None,
            },
        },
    )
    .unwrap()
    .sign_with_key(&owner.key)
    .unwrap()
    .finish()
    .unwrap()
}

/// Retain `owner`'s genesis and first `depth` chain posts in `target`; records
/// already retained are exact duplicates and change nothing. Keeping the
/// genesis first also keeps the chain out of the bounded pending bucket.
fn include(target: &mut Archive, owner: &Owner, depth: usize) {
    add(target, &owner.root);
    for record in owner.posts.iter().take(depth) {
        add(target, record);
    }
}

/// State accumulated across one drawn trace; command generators read from it.
struct Trace {
    /// Owners whose identity root was signed and pooled.
    owners: Vec<Owner>,
    /// Seeds already drawn for an owner identity.
    owner_seeds: BTreeSet<u8>,
    /// Every pin ever published, oldest first; `pins.last()` is current.
    pins: Vec<Pin>,
    /// Canonical committed snapshot behind each published pin.
    history: Vec<Vec<u8>>,
}

impl Trace {
    /// Draw the first owner's seed, create the pool and store, and pin the
    /// empty genesis archive at generation zero.
    fn open(tc: &TestCase) -> (Temp, Archive, Store, Self) {
        let temp = Temp::new();
        let mut pool = Archive::new(REALM, Limits::default()).unwrap();
        let seed = tc.draw(gs::integers::<u8>().max_value(MAX_SEED));
        let first = owner(seed);
        pool.ingest(
            &first.root.encode(),
            &mut Budget::new(1, MAX_RECORD_BYTES).unwrap(),
        )
        .unwrap();
        let store = Store::create(temp.store(), REALM, Limits::default()).unwrap();
        let trace = Self {
            owners: vec![first],
            owner_seeds: BTreeSet::from([seed]),
            pins: vec![store.pin()],
            history: vec![store.archive().snapshot()],
        };
        (temp, pool, store, trace)
    }

    /// Draw a seed's owner genesis into the pool: `inserted` iff that exact
    /// signed record is new to the archive. A fresh seed joins the owner set.
    fn create_owner(&mut self, tc: &TestCase, pool: &mut Archive) {
        let seed = tc.draw(gs::integers::<u8>().max_value(MAX_SEED));
        let fresh = self.owner_seeds.insert(seed);
        let drawn = owner(seed);
        let receipt = pool
            .ingest(
                &drawn.root.encode(),
                &mut Budget::new(1, MAX_RECORD_BYTES).unwrap(),
            )
            .unwrap();
        assert_eq!(receipt.inserted, fresh);
        if fresh {
            self.owners.push(drawn);
        }
    }

    /// Sign and pool-retain the next post in owner `i`'s chain.
    fn extend_chain(&mut self, i: usize, pool: &mut Archive) {
        let post = chain_post(&self.owners[i]);
        let receipt = pool
            .ingest(
                &post.encode(),
                &mut Budget::new(1, MAX_RECORD_BYTES).unwrap(),
            )
            .unwrap();
        assert!(receipt.inserted);
        self.owners[i].posts.push(post);
    }

    /// Extend a drawn owner's chain by one fresh pooled post.
    fn post(&mut self, tc: &TestCase, pool: &mut Archive) {
        let i = tc.draw(gs::integers::<usize>().max_value(self.owners.len() - 1));
        self.extend_chain(i, pool);
    }

    /// Re-ingest one retained record drawn by canonical index; always a
    /// duplicate that changes nothing.
    fn reingest(&mut self, tc: &TestCase, pool: &mut Archive) {
        let n = pool.len();
        let raw = pool
            .records()
            .nth(tc.draw(gs::integers::<usize>().max_value(n - 1)))
            .unwrap()
            .encode();
        let receipt = pool
            .ingest(&raw, &mut Budget::new(1, MAX_RECORD_BYTES).unwrap())
            .unwrap();
        assert!(!receipt.inserted);
        assert_eq!(pool.len(), n);
    }

    /// Commit a fresh extension of the committed archive — a drawn owner's
    /// whole chain, lengthened by one new post — under the exact pin. The
    /// only lawful outcome is a non-reconciled publication one generation up.
    fn commit(&mut self, tc: &TestCase, pool: &mut Archive, store: &mut Store) {
        let i = tc.draw(gs::integers::<usize>().max_value(self.owners.len() - 1));
        self.extend_chain(i, pool);
        let mut candidate = store.archive().clone();
        include(&mut candidate, &self.owners[i], usize::MAX);
        let prior = store.pin();
        let publication = store.commit(candidate, prior).unwrap();
        assert!(!publication.reconciled());
        assert_eq!(publication.pin().generation(), prior.generation() + 1);
        assert_eq!(publication.snapshot(), store.archive().snapshot());
        assert_eq!(store.pin(), publication.pin());
        self.pins.push(publication.pin());
        self.history.push(publication.snapshot().to_vec());
    }

    /// Re-commit the exact committed archive: a reconciled readback that
    /// leaves the pin untouched — by design the expected anchor is not
    /// consulted, so a drawn stale pin reconciles the same.
    fn readback(&mut self, tc: &TestCase, store: &mut Store) {
        let prior = store.pin();
        let expected = if self.pins.len() > 1 && tc.draw(gs::booleans()) {
            self.pins[tc.draw(gs::integers::<usize>().max_value(self.pins.len() - 2))]
        } else {
            prior
        };
        let same =
            Archive::from_snapshot(REALM, Limits::default(), &store.archive().snapshot()).unwrap();
        let publication = store.commit(same, expected).unwrap();
        assert!(publication.reconciled());
        assert_eq!(publication.pin(), prior);
        assert_eq!(store.pin(), prior);
    }

    /// Drop and reopen under a drawn anchor — none, the exact pin, or a stale
    /// pin that must fail freshness — then assert complete readback equality.
    /// A live writer refuses a second handle and a shared reader sees exactly
    /// the committed tip.
    fn restart(&mut self, tc: &TestCase, temp: &Temp, store: Store) -> Store {
        let pin = store.pin();
        let snapshot = store.archive().snapshot();
        let root = store.archive().root();
        let len = store.archive().len();
        if tc.draw(gs::booleans()) {
            assert!(matches!(
                Store::open(temp.store(), REALM, Limits::default(), None),
                Err(Error::Busy)
            ));
        }
        drop(store);
        if tc.draw(gs::integers::<u8>().max_value(2)) == 2 && self.pins.len() > 1 {
            let stale = self.pins[tc.draw(gs::integers::<usize>().max_value(self.pins.len() - 2))];
            assert!(matches!(
                Store::open(temp.store(), REALM, Limits::default(), Some(stale)),
                Err(Error::Freshness)
            ));
        }
        if tc.draw(gs::booleans()) {
            let shared = read_archive(temp.store(), REALM, Limits::default()).unwrap();
            assert_eq!(shared.snapshot(), snapshot);
            assert_eq!(shared.root(), root);
        }
        let store = if tc.draw(gs::booleans()) {
            Store::open(temp.store(), REALM, Limits::default(), Some(pin)).unwrap()
        } else {
            Store::open(temp.store(), REALM, Limits::default(), None).unwrap()
        };
        assert_eq!(store.pin(), pin);
        assert!(!store.recovery_required().unwrap());
        assert_eq!(store.archive().snapshot(), snapshot);
        assert_eq!(store.archive().root(), root);
        assert_eq!(store.archive().len(), len);
        // Reconciliation left exactly the lock, pin and current bundle.
        assert_eq!(fs::read_dir(temp.store()).unwrap().count(), 3);
        store
    }

    /// A commit attempt under a drawn basis and expected anchor. The outcome
    /// oracle mirrors `commit_inner`: a candidate that is not an extension of
    /// the committed archive is a conflict, an extension identical to the
    /// committed archive reconciles in place on any anchor, and any other
    /// extension publishes only under the exact current pin.
    fn commit_attempt(&mut self, tc: &TestCase, pool: &mut Archive, store: &mut Store) {
        let i = tc.draw(gs::integers::<usize>().max_value(self.owners.len() - 1));
        // Basis: a foreign realm, the committed records under different local
        // limits, a fresh archive, the live committed state, or a committed
        // snapshot drawn by index — only the live basis can grow into a
        // publishable descendant.
        let mut candidate = match tc.draw(gs::integers::<u8>().max_value(4)) {
            0 => Archive::new(RealmId(97), Limits::default()).unwrap(),
            1 => Archive::from_snapshot(
                REALM,
                Limits {
                    records: 512,
                    ..Limits::default()
                },
                self.history.last().unwrap(),
            )
            .unwrap(),
            2 => Archive::new(REALM, Limits::default()).unwrap(),
            3 => Archive::from_snapshot(REALM, Limits::default(), self.history.last().unwrap())
                .unwrap(),
            _ => Archive::from_snapshot(
                REALM,
                Limits::default(),
                &self.history[tc.draw(gs::integers::<usize>().max_value(self.history.len() - 1))],
            )
            .unwrap(),
        };
        if candidate.realm() == REALM {
            match tc.draw(gs::integers::<u8>().max_value(2)) {
                // The bare basis: identical whenever the basis is current.
                0 => {}
                // A drawn chain prefix — committed prefixes change nothing.
                1 => {
                    let depth =
                        tc.draw(gs::integers::<usize>().max_value(self.owners[i].posts.len()));
                    include(&mut candidate, &self.owners[i], depth);
                }
                // A fresh post plus the whole chain always extends the live
                // archive by a record no committed state ever contained.
                _ => {
                    self.extend_chain(i, pool);
                    include(&mut candidate, &self.owners[i], usize::MAX);
                }
            }
        } else {
            // A foreign realm retains only realm-free identity records and is
            // never an extension of the committed archive.
            add(&mut candidate, &self.owners[i].root);
        }
        // Expected anchor: the current pin, or a drawn stale published pin —
        // stale twice as often so rejection paths exercise often.
        let expected = if self.pins.len() > 1 && tc.draw(gs::integers::<u8>().max_value(2)) != 0 {
            self.pins[tc.draw(gs::integers::<usize>().max_value(self.pins.len() - 2))]
        } else {
            store.pin()
        };
        let prior = store.pin();
        let prior_snapshot = store.archive().snapshot();
        let extension = candidate.is_extension_of(store.archive());
        let identical =
            candidate.physical_digest() == prior.physical() && candidate.root() == prior.logical();
        let candidate_snapshot = candidate.snapshot();
        match store.commit(candidate, expected) {
            Ok(publication) if extension && !identical => {
                assert_eq!(expected, prior, "a fresh extension needs the exact pin");
                assert!(!publication.reconciled());
                assert_eq!(publication.pin().generation(), prior.generation() + 1);
                assert_eq!(publication.snapshot(), candidate_snapshot);
                self.pins.push(publication.pin());
                self.history.push(publication.snapshot().to_vec());
            }
            Ok(publication) => {
                // Only an extension that is the exact committed archive may
                // reconcile in place; anything else reaching here is a bug.
                assert!(extension && identical);
                assert!(publication.reconciled());
                assert_eq!(publication.pin(), prior);
                assert_eq!(store.archive().snapshot(), prior_snapshot);
            }
            Err(Error::Conflict) => {
                // Rejection is lawful only for a non-extension or a fresh
                // extension under a stale anchor — never for a readback or an
                // exact-anchored descendant.
                assert!(
                    !(extension && identical),
                    "the committed archive is a readback"
                );
                assert!(
                    !(extension && !identical && expected == prior),
                    "an exact-anchored extension must publish"
                );
                assert_eq!(store.pin(), prior);
                assert_eq!(store.archive().snapshot(), prior_snapshot);
            }
            Err(other) => panic!("unexpected publication failure: {other:?}"),
        }
    }

    /// Interrupt one fresh-extension commit at a drawn boundary step, then
    /// drive reopen/commit/recover until the exact retained intent lands.
    /// Returns the reopened store, or `None` when the drawn step left a torn
    /// intent that fails closed forever (`Step::IntentCreated`).
    fn faulted_commit(
        &mut self,
        tc: &TestCase,
        pool: &mut Archive,
        temp: &Temp,
        store: Store,
    ) -> Option<Store> {
        let i = tc.draw(gs::integers::<usize>().max_value(self.owners.len() - 1));
        self.extend_chain(i, pool);
        let mut candidate = store.archive().clone();
        include(&mut candidate, &self.owners[i], usize::MAX);
        let prior = store.pin();
        let step = STEPS[tc.draw(gs::integers::<usize>().max_value(STEPS.len() - 1))];
        let mut store = store;
        store.fault = Some(step);
        assert!(matches!(
            store.commit(candidate.clone(), prior),
            Err(Error::Indeterminate(_))
        ));
        store.fault = None;
        drop(store);
        if step == Step::IntentCreated {
            // The torn intent is preserved and fails closed on every reopen.
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
                prior
            );
            // Even a shared reader fails closed on the retained torn intent.
            assert!(matches!(
                read_archive(temp.store(), REALM, Limits::default()),
                Err(Error::RecoveryRequired)
            ));
            return None;
        }
        // A shared reader sees a retained intent as `RecoveryRequired`, never
        // torn bytes; once the pin already advanced it reads the new tip.
        match read_archive(temp.store(), REALM, Limits::default()) {
            Err(Error::RecoveryRequired) => {
                assert!(
                    !matches!(step, Step::IntentRemoved | Step::CleanupDurable),
                    "a resolved intent leaves nothing to recover"
                );
            }
            Ok(archive) => {
                assert!(matches!(step, Step::IntentRemoved | Step::CleanupDurable));
                assert_eq!(archive.snapshot(), candidate.snapshot());
            }
            Err(other) => panic!("unexpected shared-read failure: {other:?}"),
        }
        // Reopen and reconcile: a retained intent may be finished by
        // re-committing the exact candidate, must reject any different one,
        // and tolerates further drawn interruptions during recover.
        let (mut reopened, publication) = 'reconcile: {
            for round in 0..3u8 {
                let mut reopened =
                    Store::open(temp.store(), REALM, Limits::default(), None).unwrap();
                let mut publication = None;
                if reopened.recovery_required().unwrap() {
                    match tc.draw(gs::integers::<u8>().max_value(2)) {
                        0 => {
                            // A different candidate cannot displace the intent.
                            self.extend_chain(i, pool);
                            let mut other = reopened.archive().clone();
                            add(&mut other, self.owners[i].posts.last().unwrap());
                            assert!(matches!(
                                reopened.commit(other, prior),
                                Err(Error::RecoveryRequired)
                            ));
                        }
                        // The intent binds its expected pin: a stale anchor is
                        // refused with the exact candidate too.
                        1 if self.pins.len() > 1 => {
                            let stale = self.pins
                                [tc.draw(gs::integers::<usize>().max_value(self.pins.len() - 2))];
                            assert!(matches!(
                                reopened.commit(candidate.clone(), stale),
                                Err(Error::RecoveryRequired)
                            ));
                        }
                        2 => {
                            // Re-committing the exact intent finishes it.
                            let p = reopened.commit(candidate.clone(), prior).unwrap();
                            assert!(p.reconciled());
                            publication = Some(p);
                        }
                        _ => {}
                    }
                }
                if publication.is_none() {
                    if round < 2 && tc.draw(gs::booleans()) {
                        reopened.fault = Some(
                            STEPS[tc.draw(gs::integers::<usize>().max_value(STEPS.len() - 1))],
                        );
                    }
                    match reopened.recover() {
                        Ok(p) => publication = Some(p),
                        Err(Error::Indeterminate(_)) => {
                            drop(reopened);
                            continue;
                        }
                        Err(other) => {
                            panic!("reconciling the exact intent must not fail: {other:?}")
                        }
                    }
                }
                reopened.fault = None;
                break 'reconcile (reopened, publication.unwrap());
            }
            unreachable!("the final reconciliation round runs clean");
        };
        assert!(publication.reconciled());
        assert_eq!(publication.pin().generation(), prior.generation() + 1);
        assert_eq!(reopened.pin(), publication.pin());
        assert_eq!(reopened.archive().snapshot(), candidate.snapshot());
        assert_eq!(fs::read_dir(temp.store()).unwrap().count(), 3);
        // Re-committing the published intent is a reconciled readback.
        let again = reopened.commit(candidate, prior).unwrap();
        assert!(again.reconciled());
        assert_eq!(again.pin(), publication.pin());
        self.pins.push(reopened.pin());
        self.history.push(reopened.archive().snapshot());
        Some(reopened)
    }
}

/// Property (a): drawn interleavings of ingests, commits and readbacks —
/// every restart preserves exactly the committed archive.
///
/// Each case does real filesystem I/O per command — create, commit, reopen —
/// so only the TooSlow health check is suppressed.
#[hegel::test(test_cases = 64, suppress_health_check = [HealthCheck::TooSlow])]
fn restarts_preserve_exactly_the_committed_archive(tc: TestCase) {
    let (temp, mut pool, mut store, mut trace) = Trace::open(&tc);
    for _ in 0..tc.draw(gs::integers::<usize>().max_value(12)) {
        match tc.draw(gs::integers::<u8>().max_value(9)) {
            0..=2 => trace.commit(&tc, &mut pool, &mut store),
            3 => trace.create_owner(&tc, &mut pool),
            4 => trace.post(&tc, &mut pool),
            5 => trace.reingest(&tc, &mut pool),
            6 => trace.readback(&tc, &mut store),
            _ => store = trace.restart(&tc, &temp, store),
        }
    }
    let _ = temp;
}

/// Property (b): drawn commit attempts on drawn bases and anchors — a stale
/// or divergent candidate never publishes, whatever the interleaving.
#[hegel::test(test_cases = 64, suppress_health_check = [HealthCheck::TooSlow])]
fn stale_or_divergent_candidates_never_publish(tc: TestCase) {
    let (temp, mut pool, mut store, mut trace) = Trace::open(&tc);
    for _ in 0..tc.draw(gs::integers::<usize>().max_value(12)) {
        match tc.draw(gs::integers::<u8>().max_value(9)) {
            0..=1 => trace.commit(&tc, &mut pool, &mut store),
            2 => trace.create_owner(&tc, &mut pool),
            3 => trace.post(&tc, &mut pool),
            4..=7 => trace.commit_attempt(&tc, &mut pool, &mut store),
            _ => store = trace.restart(&tc, &temp, store),
        }
    }
    let _ = temp;
}

/// Property (c): a commit interrupted at any drawn boundary step reconciles
/// the exact retained intent — never a substitute — however often the
/// recovery itself is interrupted again.
#[hegel::test(test_cases = 64, suppress_health_check = [HealthCheck::TooSlow])]
fn every_publication_boundary_recovers_the_exact_intent(tc: TestCase) {
    let (temp, mut pool, mut store, mut trace) = Trace::open(&tc);
    'trace: for _ in 0..tc.draw(gs::integers::<usize>().max_value(16)) {
        match tc.draw(gs::integers::<u8>().max_value(9)) {
            0..=1 => trace.commit(&tc, &mut pool, &mut store),
            2 => trace.create_owner(&tc, &mut pool),
            3 => trace.post(&tc, &mut pool),
            4..=5 => store = trace.restart(&tc, &temp, store),
            _ => match trace.faulted_commit(&tc, &mut pool, &temp, store) {
                Some(reopened) => store = reopened,
                // A torn intent fails closed: the store can never reopen.
                None => break 'trace,
            },
        }
    }
    let _ = temp;
}
