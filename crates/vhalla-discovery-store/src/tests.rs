//! Native private publication and recovery regression fixtures.
use super::*;
use ed25519_dalek::SigningKey;
use std::os::unix::fs::{symlink, PermissionsExt};
use vhalla_core::RealmId;
use vhalla_discovery::Change;
use vhalla_social::{
    archive::{Archive, Budget, Limits},
    view::{Eligibility, View},
    Actor, Body, Operation, OwnerId, Placement, SignedRecord, Text, UnsignedRecord,
    MAX_RECORD_BYTES,
};

const REALM: RealmId = RealmId(29);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).unwrap();
        let suffix: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = std::env::temp_dir().join(format!(
            "vhalla-private-store-{}-{suffix}",
            std::process::id()
        ));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn social(&self) -> PathBuf {
        self.0.join("social")
    }
    fn private(&self) -> PathBuf {
        self.0.join("private")
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn key() -> SigningKey {
    SigningKey::from_bytes(&[31; 32])
}
fn signed(body: Body) -> SignedRecord {
    UnsignedRecord::new(key().verifying_key().to_bytes(), body)
        .unwrap()
        .sign_with_key(&key())
        .unwrap()
        .finish()
        .unwrap()
}
fn add(archive: &mut Archive, record: &SignedRecord) {
    archive
        .ingest(
            &record.encode(),
            &mut Budget::new(1, MAX_RECORD_BYTES).unwrap(),
        )
        .unwrap();
}
fn setup() -> (Temp, SocialStore, ReaderScope, RecordId) {
    let temp = Temp::new();
    let mut sources = SocialStore::create(temp.social(), REALM, Limits::default()).unwrap();
    let genesis = signed(Body::OwnerGenesis {
        controller: key().verifying_key().to_bytes(),
        recovery: None,
        nonce: [31; 32],
    });
    let owner = OwnerId::from_bytes(*genesis.id().as_bytes());
    let mut candidate = sources.archive().clone();
    add(&mut candidate, &genesis);
    sources.commit(candidate, sources.pin()).unwrap();
    let scope = ReaderScope::new(sources.archive(), 10, owner, None, [0; 32], [0; 32]).unwrap();
    (temp, sources, scope, genesis.id())
}
fn changed(state: &PrivateState) -> PrivateState {
    let mut discovery = state.discovery().clone();
    discovery.apply(Change::Wider(true)).unwrap();
    state.with_discovery(discovery).unwrap()
}
fn post(scope: ReaderScope, control: RecordId) -> SignedRecord {
    signed(Body::Social {
        actor: Actor::Owner {
            owner: scope.owner(),
            control,
        },
        realm: REALM,
        sequence: 0,
        previous: None,
        operation: Operation::Post {
            placement: Placement::Profile,
            text: Text::new("private-source-first").unwrap(),
            reply: None,
            quote: None,
        },
    })
}
fn observed(state: &PrivateState, archive: &Archive) -> PrivateState {
    let eligibility = Eligibility::default();
    let view = View::new(archive, 10, &eligibility);
    let mut discovery = state.discovery().clone();
    discovery.observe(&view).unwrap();
    state.with_discovery(discovery).unwrap()
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
fn typed_publication_reopen_exact_cas_and_public_export_exclusion() {
    let (temp, sources, scope, _) = setup();
    let public = sources.archive().snapshot();
    let source_pin = sources.pin();
    let mut store = Store::create(temp.private(), scope, &sources).unwrap();
    let old = store.pin();
    let candidate = changed(store.state());
    let result = store.commit(candidate.clone(), old, &sources).unwrap();
    assert!(!result.reconciled());
    assert_eq!(result.pin().generation(), 1);
    assert_eq!(sources.pin(), source_pin);
    assert_eq!(sources.archive().snapshot(), public);
    assert_eq!(fs::read_dir(temp.social()).unwrap().count(), 3);
    assert_eq!(fs::read_dir(temp.private()).unwrap().count(), 2);
    let current = store.pin();
    drop(store);
    let mut reopened = Store::open(temp.private(), scope, Some(current)).unwrap();
    assert!(reopened.state().discovery().preferences().wider());
    assert!(reopened
        .commit(candidate, old, &sources)
        .unwrap()
        .reconciled());
    let mut backwards = reopened.state().discovery().clone();
    backwards.apply(Change::Wider(false)).unwrap();
    let candidate = reopened.state().with_discovery(backwards).unwrap();
    assert!(matches!(
        reopened.commit(candidate, old, &sources),
        Err(Error::Conflict)
    ));
}

#[test]
fn new_source_claims_require_durable_canonical_commit_before_private_intent() {
    let (temp, mut sources, scope, control) = setup();
    let mut store = Store::create(temp.private(), scope, &sources).unwrap();
    let post = post(scope, control);
    let mut uncommitted = sources.archive().clone();
    add(&mut uncommitted, &post);
    let candidate = observed(store.state(), &uncommitted);
    assert_eq!(candidate.discovery().required_sources(), vec![post.id()]);
    let private_pin = store.pin();
    assert!(matches!(
        store.commit(candidate.clone(), private_pin, &sources),
        Err(Error::MissingSource)
    ));
    assert_eq!(store.pin(), private_pin);
    assert!(!temp.private().join(INTENT).exists());
    sources.commit(uncommitted, sources.pin()).unwrap();
    store.commit(candidate, private_pin, &sources).unwrap();
    assert_eq!(
        store.state().discovery().required_sources(),
        vec![post.id()]
    );
}

#[test]
fn every_private_publication_boundary_recovers_exact_candidate_or_preserves_torn_intent() {
    for step in [
        Step::IntentCreated,
        Step::IntentWritten,
        Step::IntentDurable,
        Step::TempWritten,
        Step::TempDurable,
        Step::StateRenamed,
        Step::StateDurable,
        Step::IntentRemoved,
        Step::CleanupDurable,
    ] {
        let (temp, sources, scope, _) = setup();
        let public = sources.archive().snapshot();
        let mut store = Store::create(temp.private(), scope, &sources).unwrap();
        let candidate = changed(store.state());
        store.fault = Some(step);
        let pin = store.pin();
        assert!(store.commit(candidate.clone(), pin, &sources).is_err());
        drop(store);
        let reopened = Store::open(temp.private(), scope, None);
        if step == Step::IntentCreated {
            assert!(matches!(reopened, Err(Error::Corrupt)));
            assert_eq!(fs::metadata(temp.private().join(INTENT)).unwrap().len(), 0);
        } else {
            let mut reopened = reopened.unwrap();
            reopened.recover(&sources).unwrap();
            assert_eq!(reopened.state().payload(), candidate.payload());
            assert_eq!(reopened.pin().generation(), 1);
            assert_eq!(fs::read_dir(temp.private()).unwrap().count(), 2);
        }
        assert_eq!(sources.archive().snapshot(), public);
    }
}

#[test]
fn pending_intent_refuses_new_candidate_and_missing_source_recovery_until_source_returns() {
    let (temp, mut sources, scope, control) = setup();
    let mut store = Store::create(temp.private(), scope, &sources).unwrap();
    let post = post(scope, control);
    let original = sources.archive().clone();
    let mut full = original.clone();
    add(&mut full, &post);
    sources.commit(full, sources.pin()).unwrap();
    let candidate = observed(store.state(), sources.archive());
    store.fault = Some(Step::IntentDurable);
    let pin = store.pin();
    assert!(store.commit(candidate.clone(), pin, &sources).is_err());
    drop(store);
    let other_path = temp.0.join("restored-social");
    let mut restored = SocialStore::create(other_path, REALM, Limits::default()).unwrap();
    restored.commit(original, restored.pin()).unwrap();
    let mut reopened = Store::open(temp.private(), scope, None).unwrap();
    assert!(reopened.recovery_required().unwrap());
    assert!(matches!(
        reopened.commit(changed(reopened.state()), pin, &restored),
        Err(Error::RecoveryRequired)
    ));
    assert!(matches!(
        reopened.recover(&restored),
        Err(Error::MissingSource)
    ));
    assert!(temp.private().join(INTENT).exists());
    reopened.recover(&sources).unwrap();
    assert_eq!(reopened.state().payload(), candidate.payload());
}

#[test]
fn old_missing_claims_after_partial_source_restore_stay_unresolved_and_do_not_block_preferences() {
    let (temp, mut sources, scope, control) = setup();
    let original = sources.archive().clone();
    let post = post(scope, control);
    let mut full = original.clone();
    add(&mut full, &post);
    sources.commit(full, sources.pin()).unwrap();
    let mut store = Store::create(temp.private(), scope, &sources).unwrap();
    let candidate = observed(store.state(), sources.archive());
    store.commit(candidate, store.pin(), &sources).unwrap();
    let mut restored =
        SocialStore::create(temp.0.join("restored-social"), REALM, Limits::default()).unwrap();
    restored.commit(original, restored.pin()).unwrap();
    let candidate = changed(store.state());
    store.commit(candidate, store.pin(), &restored).unwrap();
    assert_eq!(
        store.state().discovery().required_sources(),
        vec![post.id()]
    );
    assert!(restored.archive().get(post.id()).is_none());
}

#[test]
fn an_old_observation_does_not_justify_new_seen_claim_after_partial_source_restore() {
    let (temp, mut sources, scope, control) = setup();
    let original = sources.archive().clone();
    let post = post(scope, control);
    let mut full = original.clone();
    add(&mut full, &post);
    sources.commit(full.clone(), sources.pin()).unwrap();
    let mut store = Store::create(temp.private(), scope, &sources).unwrap();
    let observed = observed(store.state(), &full);
    store.commit(observed, store.pin(), &sources).unwrap();
    let mut restored =
        SocialStore::create(temp.0.join("restored-social"), REALM, Limits::default()).unwrap();
    restored.commit(original, restored.pin()).unwrap();
    let eligibility = Eligibility::default();
    let view = View::new(&full, 10, &eligibility);
    let mut discovery = store.state().discovery().clone();
    discovery
        .mark_seen(
            &view,
            vhalla_social::PostRef {
                post: post.id(),
                revision: post.id(),
            },
        )
        .unwrap();
    assert_eq!(
        discovery.required_sources(),
        store.state().discovery().required_sources()
    );
    let candidate = store.state().with_discovery(discovery).unwrap();
    let before = store.pin();
    assert!(matches!(
        store.commit(candidate.clone(), before, &restored),
        Err(Error::MissingSource)
    ));
    assert_eq!(store.pin(), before);
    assert!(!store.recovery_required().unwrap());
    store.commit(candidate, before, &sources).unwrap();
}

#[test]
fn same_or_descendant_source_directory_is_rejected_before_any_creation() {
    let (temp, sources, scope, _) = setup();
    let public = sources.archive().snapshot();
    let pin = sources.pin();
    let child = temp.social().join("private");
    assert!(matches!(
        Store::create(&child, scope, &sources),
        Err(Error::UnsafePath)
    ));
    assert!(!child.exists());
    assert!(matches!(
        Store::create(temp.social(), scope, &sources),
        Err(Error::UnsafePath)
    ));
    assert_eq!(sources.pin(), pin);
    assert_eq!(sources.archive().snapshot(), public);
    assert_eq!(fs::read_dir(temp.social()).unwrap().count(), 3);
    let alias = temp.0.join("alias");
    symlink(temp.social(), &alias).unwrap();
    assert!(matches!(
        Store::create(alias.join("private"), scope, &sources),
        Err(Error::UnsafePath)
    ));
    assert!(!child.exists());
}

#[test]
fn path_permissions_links_fifo_and_unknown_files_fail_without_cleanup() {
    for mutation in 0..6 {
        let (temp, sources, scope, _) = setup();
        let store = Store::create(temp.private(), scope, &sources).unwrap();
        drop(store);
        match mutation {
            0 => fs::set_permissions(temp.private(), fs::Permissions::from_mode(0o755)).unwrap(),
            1 => fs::set_permissions(
                temp.private().join(STATE),
                fs::Permissions::from_mode(0o644),
            )
            .unwrap(),
            2 => {
                fs::hard_link(temp.private().join(STATE), temp.0.join("linked")).unwrap();
            }
            3 => {
                fs::rename(temp.private().join(STATE), temp.0.join("moved")).unwrap();
                symlink(temp.0.join("moved"), temp.private().join(STATE)).unwrap();
            }
            4 => {
                let mut file = create_private(&temp.private().join("foreign")).unwrap();
                file.write_all(b"keep this").unwrap();
            }
            _ => {
                fs::remove_file(temp.private().join(STATE)).unwrap();
                assert!(std::process::Command::new("mkfifo")
                    .arg(temp.private().join(STATE))
                    .status()
                    .unwrap()
                    .success());
            }
        }
        assert!(Store::open(temp.private(), scope, None).is_err());
        if mutation == 4 {
            assert_eq!(
                fs::read(temp.private().join("foreign")).unwrap(),
                b"keep this"
            );
        }
    }
}

#[test]
fn lifetime_lock_excludes_other_handles_and_real_processes() {
    let (temp, sources, scope, _) = setup();
    let store = Store::create(temp.private(), scope, &sources).unwrap();
    assert!(matches!(
        Store::open(temp.private(), scope, None),
        Err(Error::Busy)
    ));
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("unix::tests::lock_child")
        .arg("--nocapture")
        .env("VHALLA_PRIVATE_LOCK_TEST", temp.private())
        .status()
        .unwrap();
    assert!(result.success());
    drop(store);
    assert!(Store::open(temp.private(), scope, None).is_ok());
}
#[test]
fn lock_child() {
    let Some(path) = std::env::var_os("VHALLA_PRIVATE_LOCK_TEST") else {
        return;
    };
    let path = PathBuf::from(path);
    let (_, uid) = directory(&path).unwrap();
    let file = open_private(&path.join(LOCK), uid, 0).unwrap();
    assert!(matches!(acquire(&file), Err(Error::Busy)));
}

#[test]
fn coherent_private_rollback_is_detected_only_with_an_independent_exact_pin() {
    let (temp, sources, scope, _) = setup();
    let mut store = Store::create(temp.private(), scope, &sources).unwrap();
    let old = fs::read(temp.private().join(STATE)).unwrap();
    let candidate = changed(store.state());
    store.commit(candidate, store.pin(), &sources).unwrap();
    let pin = store.pin();
    assert_eq!(Pin::decode(&pin.encode()).unwrap(), pin);
    drop(store);
    rewrite(&temp.private().join(STATE), &old);
    assert!(matches!(
        Store::open(temp.private(), scope, Some(pin)),
        Err(Error::Freshness)
    ));
    let reopened = Store::open(temp.private(), scope, None).unwrap();
    assert_eq!(reopened.pin().generation(), 0);
    assert!(!reopened.state().discovery().preferences().wider());
}
