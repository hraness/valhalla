use super::*;
use ed25519_dalek::SigningKey;
use std::os::unix::fs::PermissionsExt;
use vhalla_rooms::{CreateAction, RoomControl};
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
