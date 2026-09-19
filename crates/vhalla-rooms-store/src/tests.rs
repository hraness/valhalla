use super::*;
use ed25519_dalek::SigningKey;
use hegel::{generators as gs, TestCase};
use std::fs::DirBuilder;
use std::os::unix::fs::DirBuilderExt;
use std::{
    collections::{BTreeMap, BTreeSet},
    os::unix::fs::PermissionsExt,
};
use vhalla_rooms::{CreateAction, RoomControl, RoomRecordId};
use vhalla_social::{
    archive::{Archive, Budget, Limits},
    control::ControlView,
    AgentId, Body, ControlAction as SocialAction, RecordId, Rights, UnsignedRecord,
    MAX_RECORD_BYTES,
};

const REALM: RealmId = RealmId(73);
const DIRECTORY: DirectoryId = DirectoryId::from_bytes([5; 32]);
const EPOCH: u64 = 86_400;

fn policy() -> DirectoryPolicy {
    DirectoryPolicy {
        base_cost: 1,
        window_seconds: EPOCH,
        max_in_window: 1,
        support_epoch_seconds: EPOCH,
        max_lifetime_rooms: 8,
    }
}

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).unwrap();
        let name: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let path =
            std::env::temp_dir().join(format!("vhalla-rooms-store-{}-{name}", std::process::id()));
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

fn sign(body: Body, key: &SigningKey, ack: Option<&SigningKey>) -> vhalla_social::SignedRecord {
    let primary = UnsignedRecord::new(key.verifying_key().to_bytes(), body)
        .unwrap()
        .sign_with_key(key)
        .unwrap();
    match ack {
        Some(k) => primary.countersign(k).unwrap(),
        None => primary.finish().unwrap(),
    }
}

fn ingest(archive: &mut Archive, record: &vhalla_social::SignedRecord) {
    archive
        .ingest(
            &record.encode(),
            &mut Budget::new(2, MAX_RECORD_BYTES).unwrap(),
        )
        .unwrap();
}

/// An owner, agent and open social grant committed in `archive`.
struct Owner {
    key: SigningKey,
    agent_key: SigningKey,
    id: OwnerId,
    agent: AgentId,
    head: RecordId,
}

fn owner(archive: &mut Archive, seed: u8) -> Owner {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let agent_key = SigningKey::from_bytes(&[seed + 40; 32]);
    let root = sign(
        Body::OwnerGenesis {
            controller: key.verifying_key().to_bytes(),
            recovery: None,
            nonce: [seed; 32],
        },
        &key,
        None,
    );
    let id = OwnerId::from_bytes(*root.id().as_bytes());
    let agent_root = sign(
        Body::AgentGenesis {
            owner: id,
            control: root.id(),
            key: agent_key.verifying_key().to_bytes(),
            nonce: [seed + 41; 32],
        },
        &key,
        Some(&agent_key),
    );
    let grant = sign(
        Body::Control {
            owner: id,
            previous: root.id(),
            action: SocialAction::Grant {
                agent: AgentId::from_bytes(*agent_root.id().as_bytes()),
                realm: REALM,
                rights: Rights::ALL,
                expires_at: 1_000_000,
                nonce: [seed + 42; 32],
            },
        },
        &key,
        None,
    );
    for record in [&root, &agent_root, &grant] {
        ingest(archive, record);
    }
    Owner {
        key,
        agent_key,
        id,
        agent: AgentId::from_bytes(*agent_root.id().as_bytes()),
        head: grant.id(),
    }
}

/// One admitted GrantCreate advances the registry revision by one.
fn advance(
    registry: &Registry,
    archive: &Archive,
    owner: &Owner,
    previous: Option<vhalla_rooms::RoomRecordId>,
    sequence: u64,
    nonce: u8,
    now: u64,
) -> Registry {
    let mut next = Registry::restore(&registry.snapshot()).unwrap();
    let record = RoomControl {
        directory: DIRECTORY,
        realm: REALM,
        owner: owner.id,
        social_control: owner.head,
        controller_key: owner.key.verifying_key().to_bytes(),
        previous,
        sequence,
        action: CreateAction::GrantCreate {
            agent: owner.agent,
            agent_key: owner.agent_key.verifying_key().to_bytes(),
            expires_at: 1_000_000,
            maximum_charge: 1_000,
            nonce: [nonce; 32],
        },
    }
    .sign_with_key(&owner.key)
    .unwrap()
    .verify()
    .unwrap();
    assert!(next
        .apply(&record, &ControlView::new(archive, now), now)
        .is_ok());
    next
}

fn setup() -> (Temp, Store, Archive, Owner) {
    let temp = Temp::new();
    let mut archive = Archive::new(REALM, Limits::default()).unwrap();
    let owner = owner(&mut archive, 1);
    let store = Store::create(temp.store(), DIRECTORY, REALM, policy(), &[owner.id]).unwrap();
    (temp, store, archive, owner)
}

#[test]
fn initialize_commit_restart_and_readback() {
    let (temp, mut store, archive, owner) = setup();
    assert!(matches!(
        Store::create(temp.store(), DIRECTORY, REALM, policy(), &[]),
        Err(Error::Io(_))
    ));
    assert_eq!(store.pin().generation(), 0);
    let prior = store.pin();
    let candidate = advance(store.registry(), &archive, &owner, None, 0, 9, 100);
    let publication = store.commit(candidate, prior).unwrap();
    assert!(!publication.reconciled());
    assert_eq!(publication.pin().generation(), 1);
    let current = publication.pin();
    drop(store);
    let reopened = Store::open(temp.store(), Some(current)).unwrap();
    assert_eq!(reopened.registry().revision(), 1);
    assert_eq!(
        reopened.registry().authority().head(owner.id),
        reopened.registry().authority().head(owner.id)
    );
    // The admitted control record survives as the durable manifest bytes.
    let head = reopened.registry().authority().head(owner.id).unwrap();
    assert!(reopened.registry().source_proof(head).is_some());
    // Re-committing the same published state is a reconciled readback.
    let mut reopened = reopened;
    let same = Registry::restore(publication.snapshot()).unwrap();
    let duplicate = reopened.commit(same, prior).unwrap();
    assert!(duplicate.reconciled());
    assert_eq!(duplicate.pin(), current);
}

#[test]
fn stale_or_divergent_candidates_cannot_publish() {
    let (temp, mut store, archive, owner) = setup();
    let prior = store.pin();
    let candidate = advance(store.registry(), &archive, &owner, None, 0, 9, 100);
    store.commit(candidate, prior).unwrap();
    let current = store.pin();
    // A candidate replaying the same revision with different bytes conflicts.
    let divergent = advance(
        &Registry::new(DIRECTORY, REALM, policy(), &[owner.id]).unwrap(),
        &archive,
        &owner,
        None,
        0,
        10,
        100,
    );
    assert_eq!(divergent.revision(), store.registry().revision());
    assert!(matches!(
        store.commit(divergent, current),
        Err(Error::Conflict)
    ));
    // A stale expected pin is rejected even for a valid descendant.
    let head = store.registry().authority().head(owner.id);
    let next = advance(store.registry(), &archive, &owner, head, 1, 11, 100);
    assert!(matches!(store.commit(next, prior), Err(Error::Conflict)));
    assert_eq!(store.pin(), current);
    let _ = temp;
}

#[test]
fn higher_revision_foreign_context_and_forks_cannot_publish() {
    let (_temp, mut store, archive, owner) = setup();
    let initial = store.registry().clone();
    let first = advance(&initial, &archive, &owner, None, 0, 9, 100);
    store.commit(first, store.pin()).unwrap();
    let pin = store.pin();
    let snapshot = store.registry().snapshot();
    let mut foreign_policy = policy();
    foreign_policy.base_cost += 1;
    let mut candidates = vec![
        Registry::new(DirectoryId::from_bytes([6; 32]), REALM, policy(), &[]).unwrap(),
        Registry::new(DIRECTORY, RealmId(REALM.0 + 1), policy(), &[]).unwrap(),
        Registry::new(DIRECTORY, REALM, foreign_policy, &[]).unwrap(),
        initial.clone(), // Same context, but drops all admitted control proof.
        advance(&initial, &archive, &owner, None, 0, 10, 100), // Replaces it.
    ];
    for candidate in &mut candidates {
        while candidate.revision() <= store.registry().revision() {
            candidate.set_eligible(&[owner.id], 100).unwrap();
        }
        assert!(matches!(
            store.commit(candidate.clone(), pin),
            Err(Error::Conflict)
        ));
        assert_eq!(store.pin(), pin);
        assert_eq!(store.registry().snapshot(), snapshot);
        assert!(!store.recovery_required().unwrap());
    }
    // Eligibility is a permitted configuration transition; retaining the
    // control prefix with a new eligible set must still publish and reopen.
    let mut descendant = store.registry().clone();
    descendant.set_eligible(&[], 101).unwrap();
    store.commit(descendant, pin).unwrap();
    assert!(store.registry().eligible().is_empty());
}

#[test]
fn duplicate_support_proof_can_publish_and_survives_restart() {
    use vhalla_rooms::registry::Applied;
    use vhalla_social::{Actor, Operation, Placement, Reaction, References, Text};
    fn seal(archive: &mut Archive, owner: &mut Owner, head: RecordId) {
        let record = sign(
            Body::Control {
                owner: owner.id,
                previous: owner.head,
                action: SocialAction::Seal {
                    realm: REALM,
                    heads: References::sorted(vec![head]).unwrap(),
                },
            },
            &owner.key,
            None,
        );
        owner.head = record.id();
        ingest(archive, &record);
    }
    let (temp, mut store, mut archive, mut source) = setup();
    let mut beneficiary = owner(&mut archive, 2);
    let post = sign(
        Body::Social {
            actor: Actor::Owner {
                owner: beneficiary.id,
                control: beneficiary.head,
            },
            realm: REALM,
            sequence: 0,
            previous: None,
            operation: Operation::Post {
                placement: Placement::Profile,
                text: Text::new("durable support").unwrap(),
                reply: None,
                quote: None,
            },
        },
        &beneficiary.key,
        None,
    );
    ingest(&mut archive, &post);
    seal(&mut archive, &mut beneficiary, post.id());
    let grant = source.head;
    let mut previous = None;
    let mut proofs = Vec::new();
    for sequence in 0..3 {
        let record = sign(
            Body::Social {
                actor: Actor::Agent {
                    owner: source.id,
                    agent: source.agent,
                    grant,
                },
                realm: REALM,
                sequence,
                previous,
                operation: Operation::React {
                    post: post.id(),
                    reaction: Reaction::Up(post.id()),
                    supersedes: References::default(),
                },
            },
            &source.agent_key,
            None,
        );
        ingest(&mut archive, &record);
        seal(&mut archive, &mut source, record.id());
        previous = Some(record.id());
        let verified = record.clone().verify().unwrap();
        let mut next = store.registry().clone();
        let now = 100 + sequence;
        assert_eq!(
            next.award(&verified, &ControlView::new(&archive, now), now),
            Ok(if sequence == 0 {
                Applied::Awarded
            } else {
                Applied::DuplicateAward
            })
        );
        if sequence == 2 {
            // Recover the same-revision proof extension after its pin rename:
            // the old bundle is still required to validate retained intent.
            store.fault = Some(Step::PinRenamed);
            assert!(matches!(
                store.commit(next, store.pin()),
                Err(Error::Indeterminate(_))
            ));
            drop(store);
            store = Store::open(temp.store(), None).unwrap();
            store.recover().unwrap();
        } else {
            store.commit(next, store.pin()).unwrap();
        }
        assert_eq!(store.registry().revision(), 1);
        assert_eq!(store.registry().last_time(), 100);
        proofs.push((record.id(), record.encode()));
    }
    let pin = store.pin();
    drop(store);
    let reopened = Store::open(temp.store(), Some(pin)).unwrap();
    assert_eq!(reopened.registry().account(beneficiary.id).earned, 1);
    for (id, proof) in proofs {
        assert_eq!(reopened.registry().evidence_proof(id), Some(proof));
    }
}

fn retain_bundle(path: &Path, registry: &Registry) -> PathBuf {
    let raw = registry.snapshot();
    let path = path.join(bundle_name(bundle_digest(&raw)));
    let mut file = create_private(&path).unwrap();
    file.write_all(&raw).unwrap();
    file.sync_all().unwrap();
    path
}

#[test]
fn unrelated_older_bundle_stops_audit_and_preserves_all_retained_evidence() {
    let (temp, mut store, archive, owner) = setup();
    let ancestor = store.registry().clone();
    let next = advance(&ancestor, &archive, &owner, None, 0, 9, 100);
    store.commit(next, store.pin()).unwrap();
    let pin = store.pin();
    let old_path = retain_bundle(&temp.store(), &ancestor);
    let unrelated = Registry::new(DIRECTORY, RealmId(74), policy(), &[]).unwrap();
    let unrelated_path = retain_bundle(&temp.store(), &unrelated);
    assert!(matches!(store.recover(), Err(Error::Conflict)));
    assert_eq!(store.pin(), pin);
    assert!(old_path.exists() && unrelated_path.exists());
    drop(store);
    assert!(matches!(
        Store::open(temp.store(), Some(pin)),
        Err(Error::Conflict)
    ));
    assert!(old_path.exists() && unrelated_path.exists());
}

#[test]
fn divergent_retained_intent_is_rejected_before_and_after_pin_rename() {
    for pin_renamed in [false, true] {
        let (temp, mut store, archive, owner) = setup();
        let initial = store.registry().clone();
        let first = advance(&initial, &archive, &owner, None, 0, 9, 100);
        store.commit(first, store.pin()).unwrap();
        let expected = store.pin();
        let mut fork = advance(&initial, &archive, &owner, None, 0, 10, 100);
        fork.set_eligible(&[], 101).unwrap();
        let intent = Intent {
            expected,
            next: Pin::for_registry(expected.generation + 1, &fork),
            registry: fork,
        };
        let mut file = create_private(&temp.store().join(INTENT)).unwrap();
        file.write_all(&intent.encode()).unwrap();
        file.sync_all().unwrap();
        if pin_renamed {
            retain_bundle(&temp.store(), &intent.registry);
            fs::write(temp.store().join(PIN), intent.next.encode()).unwrap();
        } else {
            assert!(matches!(store.recover(), Err(Error::Conflict)));
        }
        drop(store);
        assert!(matches!(
            Store::open(temp.store(), None),
            Err(Error::Conflict)
        ));
        assert!(temp.store().join(INTENT).exists());
        assert!(temp.store().join(bundle_name(expected.physical)).exists());
    }
}

#[test]
fn each_publication_boundary_recovers_the_exact_intent() {
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
        let (temp, mut store, archive, owner) = setup();
        let expected = store.pin();
        let candidate = advance(store.registry(), &archive, &owner, None, 0, 9, 100);
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
                Store::open(temp.store(), None),
                Err(Error::Corrupt)
            ));
            continue;
        }
        let mut recovered = Store::open(temp.store(), None).unwrap();
        let publication = recovered.recover().unwrap();
        assert!(publication.reconciled());
        assert_eq!(
            publication.pin().generation(),
            expected.generation() + 1,
            "{step:?}"
        );
        assert_eq!(recovered.registry().revision(), 1, "{step:?}");
        assert_eq!(
            recovered.registry().digest(),
            candidate.digest(),
            "{step:?}"
        );
        assert_eq!(
            recovered.commit(candidate, expected).unwrap().pin(),
            publication.pin()
        );
    }
}

#[test]
fn pending_exact_intent_rejects_a_different_candidate() {
    let (temp, mut store, archive, owner) = setup();
    let expected = store.pin();
    let candidate = advance(store.registry(), &archive, &owner, None, 0, 9, 100);
    store.fault = Some(Step::IntentDurable);
    assert!(store.commit(candidate.clone(), expected).is_err());
    drop(store);
    let mut reopened = Store::open(temp.store(), Some(expected)).unwrap();
    assert!(reopened.recovery_required().unwrap());
    let different = advance(reopened.registry(), &archive, &owner, None, 0, 10, 100);
    assert!(matches!(
        reopened.commit(different, expected),
        Err(Error::RecoveryRequired)
    ));
    let reconciled = reopened.commit(candidate, expected).unwrap();
    assert_eq!(reconciled.pin().generation(), 1);
    assert_eq!(reopened.registry().revision(), 1);
}

#[test]
fn corrupt_bundle_and_wrong_anchor_fail_closed() {
    let (temp, mut store, archive, owner) = setup();
    let prior = store.pin();
    let candidate = advance(store.registry(), &archive, &owner, None, 0, 9, 100);
    store.commit(candidate, prior).unwrap();
    let current = store.pin();
    drop(store);
    // A foreign anchor is rejected without touching the durable pin.
    assert!(matches!(
        Store::open(temp.store(), Some(prior)),
        Err(Error::Freshness)
    ));
    // Corrupting the current bundle fails closed, never resets.
    let bundle = temp.store().join(bundle_name(current.physical));
    let mut raw = fs::read(&bundle).unwrap();
    let middle = raw.len() / 2;
    raw[middle] ^= 1;
    fs::write(&bundle, &raw).unwrap();
    assert!(matches!(
        Store::open(temp.store(), None),
        Err(Error::Corrupt)
    ));
    let _ = fs::set_permissions(&bundle, fs::Permissions::from_mode(0o600));
}

#[test]
fn shared_reader_waits_out_a_writers_lock_and_reads_the_fresh_tip() {
    let (temp, mut store, archive, owner) = setup();
    let path = temp.store();
    let reader = std::thread::spawn(move || read_registry(path));
    // The writer still holds its exclusive lock: publish a new tip while
    // the reader is parked on the shared acquire, then release — the
    // reader must observe the commit, never a torn or stale pair.
    std::thread::sleep(std::time::Duration::from_millis(300));
    let candidate = advance(store.registry(), &archive, &owner, None, 0, 9, 100);
    store.commit(candidate, store.pin()).unwrap();
    let tip = store.registry().revision();
    drop(store);
    let registry = reader.join().unwrap().unwrap();
    assert_eq!(registry.revision(), tip);
}

#[test]
fn shared_readers_proceed_concurrently_and_match_the_committed_tip() {
    let (temp, store, ..) = setup();
    let tip = store.registry().revision();
    drop(store);
    let mut readers = Vec::new();
    for _ in 0..4 {
        let path = temp.store();
        readers.push(std::thread::spawn(move || read_registry(path)));
    }
    for reader in readers {
        assert_eq!(reader.join().unwrap().unwrap().revision(), tip);
    }
}

#[test]
fn shared_reader_on_a_missing_store_fails_closed() {
    let temp = Temp::new();
    assert!(read_registry(temp.store()).is_err());
}

// ---------------------------------------------------------------------------
// Generative Hegel properties over the archive lifecycle. Each case draws an
// interleaved command sequence — ingest signed records, advance and commit
// candidates, restart under drawn anchors, attempt stale/divergent
// publications, interrupt a commit at a drawn boundary step — with generators
// fed from the state accumulated so far (created owners, retained records,
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

/// Owner identity seeds are salted `seed + {40, 41, 42}` inside `owner`, so
/// drawn seeds stay below that overflow.
const MAX_SEED: u8 = 200;

/// State accumulated across one drawn trace; command generators read from it.
struct Trace {
    /// Owners whose full identity chain was created in the archive.
    owners: Vec<Owner>,
    /// Seeds already used for a complete owner chain.
    owner_seeds: BTreeSet<u8>,
    /// Seeds whose exact owner-genesis record is already retained.
    genesis_seeds: BTreeSet<u8>,
    /// Every pin ever published, oldest first; `pins.last()` is current.
    pins: Vec<Pin>,
    /// Canonical committed snapshot behind each published pin.
    history: Vec<Vec<u8>>,
    /// Committed room-control head per owner.
    heads: BTreeMap<OwnerId, RoomRecordId>,
    /// Monotone directory clock; every candidate applies at or after it.
    now: u64,
}

impl Trace {
    /// Draw the first owner's seed, create the archive and store, and pin the
    /// genesis snapshot.
    fn open(tc: &TestCase) -> (Temp, Archive, Store, Self) {
        let temp = Temp::new();
        let mut archive = Archive::new(REALM, Limits::default()).unwrap();
        let seed = tc.draw(gs::integers::<u8>().max_value(MAX_SEED));
        let first = owner(&mut archive, seed);
        let store = Store::create(temp.store(), DIRECTORY, REALM, policy(), &[first.id]).unwrap();
        let trace = Self {
            owners: vec![first],
            owner_seeds: BTreeSet::from([seed]),
            genesis_seeds: BTreeSet::from([seed]),
            pins: vec![store.pin()],
            history: vec![store.registry().snapshot()],
            heads: BTreeMap::new(),
            now: 100,
        };
        (temp, archive, store, trace)
    }

    /// Ingest a drawn seed's lone owner genesis: `inserted` iff that exact
    /// signed record is new to the archive.
    fn ingest_stray(&mut self, tc: &TestCase, archive: &mut Archive) {
        let seed = tc.draw(gs::integers::<u8>().max_value(MAX_SEED));
        let key = SigningKey::from_bytes(&[seed; 32]);
        let record = sign(
            Body::OwnerGenesis {
                controller: key.verifying_key().to_bytes(),
                recovery: None,
                nonce: [seed; 32],
            },
            &key,
            None,
        );
        let receipt = archive
            .ingest(
                &record.encode(),
                &mut Budget::new(2, MAX_RECORD_BYTES).unwrap(),
            )
            .unwrap();
        assert_eq!(receipt.inserted, self.genesis_seeds.insert(seed));
    }

    /// Create a fresh owner — three new records — or re-prove a drawn seed's
    /// existing records; ingestion is idempotent on exact duplicates.
    fn create_owner(&mut self, tc: &TestCase, archive: &mut Archive) {
        let seed = tc.draw(gs::integers::<u8>().max_value(MAX_SEED));
        let root_fresh = self.genesis_seeds.insert(seed);
        let owner_fresh = self.owner_seeds.insert(seed);
        let before = archive.len();
        let new_owner = owner(archive, seed);
        // The root is a duplicate whenever the seed was seen as owner or
        // stray; the agent genesis and grant are duplicates only for a seed
        // that already built a complete owner.
        let added = if root_fresh {
            3
        } else if owner_fresh {
            2
        } else {
            0
        };
        assert_eq!(archive.len(), before + added);
        assert!(archive.get(new_owner.head).is_some());
        if owner_fresh {
            self.owners.push(new_owner);
        }
    }

    /// Re-ingest one retained record drawn by canonical index; always a
    /// duplicate that changes nothing.
    fn reingest(&mut self, tc: &TestCase, archive: &mut Archive) {
        let n = archive.len();
        let raw = archive
            .records()
            .nth(tc.draw(gs::integers::<usize>().max_value(n - 1)))
            .unwrap()
            .encode();
        let receipt = archive
            .ingest(&raw, &mut Budget::new(2, MAX_RECORD_BYTES).unwrap())
            .unwrap();
        assert!(!receipt.inserted);
        assert_eq!(archive.len(), n);
    }

    /// Build a signed GrantCreate candidate on `base` for a drawn owner. The
    /// drawn nonce distinguishes its bytes from any sibling built on `base`.
    fn candidate(
        &mut self,
        tc: &TestCase,
        archive: &Archive,
        base: &Registry,
        i: usize,
    ) -> (Registry, u8) {
        let o = &self.owners[i];
        self.now += tc.draw(gs::integers::<u64>().max_value(3));
        // `check_control` requires a nonzero grant salt.
        let nonce = tc.draw(gs::integers::<u8>().min_value(1));
        let candidate = advance(
            base,
            archive,
            o,
            base.authority().head(o.id),
            base.authority().sequence(o.id),
            nonce,
            self.now,
        );
        (candidate, nonce)
    }

    /// Commit a fresh descendant of the committed state; the only lawful
    /// outcome is a non-reconciled publication exactly one generation up.
    fn commit(&mut self, tc: &TestCase, archive: &Archive, store: &mut Store) {
        let i = tc.draw(gs::integers::<usize>().max_value(self.owners.len() - 1));
        let prior = store.pin();
        let (candidate, _) = self.candidate(tc, archive, store.registry(), i);
        let publication = store.commit(candidate, prior).unwrap();
        assert!(!publication.reconciled());
        assert_eq!(publication.pin().generation(), prior.generation() + 1);
        assert_eq!(store.pin(), publication.pin());
        self.pins.push(store.pin());
        self.history.push(store.registry().snapshot());
        let head = store
            .registry()
            .authority()
            .head(self.owners[i].id)
            .unwrap();
        self.heads.insert(self.owners[i].id, head);
    }

    /// Re-commit the exact committed state: a reconciled readback that leaves
    /// the pin untouched — by design the expected anchor is not consulted.
    fn readback(&mut self, tc: &TestCase, store: &mut Store) {
        let prior = store.pin();
        let expected = if self.pins.len() > 1 && tc.draw(gs::booleans()) {
            self.pins[tc.draw(gs::integers::<usize>().max_value(self.pins.len() - 2))]
        } else {
            prior
        };
        let same = Registry::restore(&store.registry().snapshot()).unwrap();
        let publication = store.commit(same, expected).unwrap();
        assert!(publication.reconciled());
        assert_eq!(publication.pin(), prior);
        assert_eq!(store.pin(), prior);
    }

    /// Drop and reopen under a drawn anchor — none, the exact pin, or a stale
    /// pin that must fail freshness — then assert complete readback equality.
    fn restart(&mut self, tc: &TestCase, temp: &Temp, store: Store) -> Store {
        let pin = store.pin();
        let snapshot = store.registry().snapshot();
        let digest = store.registry().digest();
        let revision = store.registry().revision();
        drop(store);
        if tc.draw(gs::integers::<u8>().max_value(2)) == 2 && self.pins.len() > 1 {
            let stale = self.pins[tc.draw(gs::integers::<usize>().max_value(self.pins.len() - 2))];
            assert!(matches!(
                Store::open(temp.store(), Some(stale)),
                Err(Error::Freshness)
            ));
        }
        let store = if tc.draw(gs::booleans()) {
            Store::open(temp.store(), Some(pin)).unwrap()
        } else {
            Store::open(temp.store(), None).unwrap()
        };
        assert_eq!(store.pin(), pin);
        assert!(!store.recovery_required().unwrap());
        assert_eq!(store.registry().snapshot(), snapshot);
        assert_eq!(store.registry().digest(), digest);
        assert_eq!(store.registry().revision(), revision);
        for (id, head) in &self.heads {
            assert_eq!(store.registry().authority().head(*id), Some(*head));
            assert!(store.registry().source_proof(*head).is_some());
        }
        store
    }

    /// A commit attempt under a drawn basis and expected anchor. The outcome
    /// oracle mirrors `commit_inner`: a fresh descendant publishes only under
    /// the exact current pin, the identical committed state reconciles as a
    /// readback on any anchor, and anything else is a conflict that cannot
    /// publish and must leave the store untouched.
    fn commit_attempt(&mut self, tc: &TestCase, archive: &Archive, store: &mut Store) {
        let i = tc.draw(gs::integers::<usize>().max_value(self.owners.len() - 1));
        // Basis: a fresh registry, or a committed snapshot drawn by index
        // (the last entry is the current state — a valid descendant basis).
        let base_choice = tc.draw(gs::integers::<usize>().max_value(self.history.len()));
        let base = if base_choice == 0 {
            Registry::new(DIRECTORY, REALM, policy(), &[self.owners[i].id]).unwrap()
        } else {
            Registry::restore(&self.history[base_choice - 1]).unwrap()
        };
        let (candidate, _) = self.candidate(tc, archive, &base, i);
        // Expected anchor: the current pin or a stale published pin.
        let anchor_choice = tc.draw(gs::integers::<usize>().max_value(self.pins.len()));
        let expected = if anchor_choice == 0 {
            store.pin()
        } else {
            self.pins[anchor_choice - 1]
        };
        let prior = store.pin();
        let prior_digest = store.registry().digest();
        let based_on_current = base.digest() == prior_digest;
        let prior_revision = store.registry().revision();
        let candidate_revision = candidate.revision();
        let candidate_digest = candidate.digest();
        match store.commit(candidate, expected) {
            Ok(publication) if candidate_revision > prior_revision => {
                assert_eq!(expected, prior, "a fresh descendant needs the exact pin");
                assert!(!publication.reconciled());
                assert_eq!(publication.pin().generation(), prior.generation() + 1);
                self.pins.push(publication.pin());
                self.history.push(publication.snapshot().to_vec());
                let head = store
                    .registry()
                    .authority()
                    .head(self.owners[i].id)
                    .unwrap();
                self.heads.insert(self.owners[i].id, head);
            }
            Ok(publication) => {
                assert!(publication.reconciled());
                assert_eq!(candidate_revision, prior_revision);
                assert_eq!(candidate_digest, prior.logical());
                assert_eq!(publication.pin(), prior);
            }
            Err(Error::Conflict) => {
                let lawful =
                    (based_on_current && candidate_revision > prior_revision && expected == prior)
                        || (candidate_revision == prior_revision
                            && candidate_digest == prior.logical());
                assert!(!lawful, "a lawful candidate was rejected");
                assert_eq!(store.pin(), prior);
                assert_eq!(store.registry().digest(), prior_digest);
            }
            Err(other) => panic!("unexpected publication failure: {other:?}"),
        }
    }

    /// Interrupt one fresh-descendant commit at a drawn boundary step, then
    /// drive reopen/commit/recover until the exact retained intent lands.
    /// Returns the reopened store, or `None` when the drawn step left a torn
    /// intent that fails closed forever (`Step::IntentCreated`).
    fn faulted_commit(
        &mut self,
        tc: &TestCase,
        archive: &Archive,
        temp: &Temp,
        store: Store,
    ) -> Option<Store> {
        let i = tc.draw(gs::integers::<usize>().max_value(self.owners.len() - 1));
        let prior = store.pin();
        let prior_revision = store.registry().revision();
        let (candidate, nonce) = self.candidate(tc, archive, store.registry(), i);
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
                Store::open(temp.store(), None),
                Err(Error::Corrupt)
            ));
            return None;
        }
        // Reopen and reconcile: a retained intent may be finished by
        // re-committing the exact candidate, must reject any different one,
        // and tolerates further drawn interruptions during recover.
        let (mut reopened, publication) = 'reconcile: {
            for round in 0..3u8 {
                let mut reopened = Store::open(temp.store(), None).unwrap();
                let mut publication = None;
                if reopened.recovery_required().unwrap() {
                    match tc.draw(gs::integers::<u8>().max_value(2)) {
                        0 => {
                            // A different candidate cannot displace the intent.
                            let o = &self.owners[i];
                            let base = reopened.registry();
                            let other = advance(
                                base,
                                archive,
                                o,
                                base.authority().head(o.id),
                                base.authority().sequence(o.id),
                                // A distinct nonzero salt — different bytes.
                                nonce % 255 + 1,
                                self.now,
                            );
                            assert!(matches!(
                                reopened.commit(other, prior),
                                Err(Error::RecoveryRequired)
                            ));
                        }
                        // The exact candidate under a stale anchor is refused
                        // too: the intent binds its expected pin.
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
        assert_eq!(reopened.registry().digest(), candidate.digest());
        assert_eq!(reopened.registry().revision(), prior_revision + 1);
        // Re-committing the published intent is a reconciled readback.
        let again = reopened.commit(candidate, prior).unwrap();
        assert!(again.reconciled());
        assert_eq!(again.pin(), publication.pin());
        self.pins.push(reopened.pin());
        self.history.push(reopened.registry().snapshot());
        let head = reopened
            .registry()
            .authority()
            .head(self.owners[i].id)
            .unwrap();
        self.heads.insert(self.owners[i].id, head);
        Some(reopened)
    }
}

/// Property (a): drawn interleavings of ingests, commits and readbacks —
/// every restart preserves exactly the committed state.
#[hegel::test(test_cases = 64)]
fn restarts_preserve_exactly_the_committed_state(tc: TestCase) {
    let (temp, mut archive, mut store, mut trace) = Trace::open(&tc);
    for _ in 0..tc.draw(gs::integers::<usize>().max_value(12)) {
        match tc.draw(gs::integers::<u8>().max_value(9)) {
            0..=2 => trace.commit(&tc, &archive, &mut store),
            3 => trace.create_owner(&tc, &mut archive),
            4 => trace.ingest_stray(&tc, &mut archive),
            5 => trace.reingest(&tc, &mut archive),
            6 => trace.readback(&tc, &mut store),
            _ => store = trace.restart(&tc, &temp, store),
        }
    }
    let _ = temp;
}

/// Property (b): drawn commit attempts on drawn bases and anchors — a stale
/// or divergent candidate never publishes, whatever the interleaving.
#[hegel::test(test_cases = 64)]
fn stale_or_divergent_candidates_never_publish(tc: TestCase) {
    let (temp, mut archive, mut store, mut trace) = Trace::open(&tc);
    for _ in 0..tc.draw(gs::integers::<usize>().max_value(12)) {
        match tc.draw(gs::integers::<u8>().max_value(9)) {
            0..=1 => trace.commit(&tc, &archive, &mut store),
            2 => trace.create_owner(&tc, &mut archive),
            3..=6 => trace.commit_attempt(&tc, &archive, &mut store),
            7..=8 => store = trace.restart(&tc, &temp, store),
            _ => trace.ingest_stray(&tc, &mut archive),
        }
    }
    let _ = temp;
}

/// Property (c): a commit interrupted at any drawn boundary step reconciles
/// the exact retained intent — never a substitute — however often the
/// recovery itself is interrupted again.
#[hegel::test(test_cases = 64)]
fn every_publication_boundary_recovers_the_exact_intent(tc: TestCase) {
    let (temp, mut archive, mut store, mut trace) = Trace::open(&tc);
    'trace: for _ in 0..tc.draw(gs::integers::<usize>().max_value(12)) {
        match tc.draw(gs::integers::<u8>().max_value(9)) {
            0..=1 => trace.commit(&tc, &archive, &mut store),
            2 => trace.create_owner(&tc, &mut archive),
            3 => trace.reingest(&tc, &mut archive),
            4..=5 => store = trace.restart(&tc, &temp, store),
            _ => match trace.faulted_commit(&tc, &archive, &temp, store) {
                Some(reopened) => store = reopened,
                // A torn intent fails closed: the store can never reopen.
                None => break 'trace,
            },
        }
    }
    let _ = temp;
}
