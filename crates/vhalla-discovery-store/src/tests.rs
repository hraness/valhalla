//! Native private publication and recovery regression fixtures.
use super::*;
use ed25519_dalek::SigningKey;
use hegel::{generators as gs, HealthCheck, TestCase};
use std::collections::BTreeSet;
use std::fs::{DirBuilder, OpenOptions};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use vhalla_attention::{AttentionPolicy, MAX_PAGE};
use vhalla_core::RealmId;
use vhalla_discovery::{Change, Subscription};
use vhalla_social::{
    archive::{Archive, Budget, Limits},
    view::{Eligibility, RecordState, View},
    Actor, Body, Operation, OwnerId, Placement, PostRef, SignedRecord, Text, UnsignedRecord,
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
fn every_private_publication_boundary_recovers_or_retries_unpublished_preparation() {
    for step in [
        Step::IntentCreated,
        Step::IntentWritten,
        Step::IntentSynced,
        Step::IntentRenamed,
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
        let mut reopened = Store::open(temp.private(), scope, None).unwrap();
        if step == Step::IntentCreated {
            assert_eq!(
                fs::metadata(temp.private().join(INTENT_TEMP))
                    .unwrap()
                    .len(),
                0
            );
            assert!(!temp.private().join(INTENT).exists());
            assert!(reopened.recovery_required().unwrap());
            assert_eq!(reopened.recover(&sources).unwrap().pin(), pin);
            assert!(!reopened.state().discovery().preferences().wider());
            reopened.commit(candidate.clone(), pin, &sources).unwrap();
        } else {
            reopened.recover(&sources).unwrap();
        }
        assert_eq!(reopened.state().payload(), candidate.payload());
        assert_eq!(reopened.pin().generation(), 1);
        assert_eq!(fs::read_dir(temp.private()).unwrap().count(), 2);
        assert_eq!(sources.archive().snapshot(), public);
    }
}

#[test]
fn incomplete_preparation_reopens_without_writes_and_retries_only_after_source_check() {
    for cut in [0, 1, 8, 80, 100, 108, 120, usize::MAX] {
        let (temp, sources, scope, _) = setup();
        let mut store = Store::create(temp.private(), scope, &sources).unwrap();
        let before = fs::read(temp.private().join(STATE)).unwrap();
        let pin = store.pin();
        let candidate = changed(store.state());
        store.fault = Some(Step::IntentWritten);
        assert!(store.commit(candidate.clone(), pin, &sources).is_err());
        let raw = fs::read(temp.private().join(INTENT_TEMP)).unwrap();
        let raw = &raw[..cut.min(raw.len() - 1)];
        rewrite(&temp.private().join(INTENT_TEMP), raw);
        drop(store);
        let mut reopened = Store::open(temp.private(), scope, Some(pin)).unwrap();
        assert_eq!(fs::read(temp.private().join(INTENT_TEMP)).unwrap(), raw);
        assert_eq!(fs::read(temp.private().join(STATE)).unwrap(), before);
        assert!(!temp.private().join(INTENT).exists());
        let empty_source =
            SocialStore::create(temp.0.join("empty-source"), REALM, Limits::default()).unwrap();
        assert!(matches!(
            reopened.recover(&empty_source),
            Err(Error::MissingSource)
        ));
        assert_eq!(fs::read(temp.private().join(INTENT_TEMP)).unwrap(), raw);
        assert_eq!(reopened.recover(&sources).unwrap().pin(), pin);
        assert!(!reopened.recovery_required().unwrap());
        assert_eq!(fs::read(temp.private().join(STATE)).unwrap(), before);
        reopened.commit(candidate.clone(), pin, &sources).unwrap();
        assert_eq!(reopened.state().payload(), candidate.payload());
    }
}

#[test]
fn malformed_or_ambiguous_preparation_and_legacy_authority_are_preserved() {
    for mutation in 0..10 {
        let (temp, sources, scope, _) = setup();
        let mut store = Store::create(temp.private(), scope, &sources).unwrap();
        let pin = store.pin();
        let candidate = changed(store.state());
        store.fault = Some(Step::IntentWritten);
        assert!(store.commit(candidate, pin, &sources).is_err());
        let stage = temp.private().join(INTENT_TEMP);
        let mut raw = fs::read(&stage).unwrap();
        match mutation {
            0 => *raw.last_mut().unwrap() ^= 1,
            1 => raw.push(0),
            2 => {
                raw[24] ^= 1;
                raw.truncate(40);
            }
            3 => {
                raw[108] ^= 1;
                raw.truncate(120);
            }
            4 => {
                raw[104..108].copy_from_slice(&u32::MAX.to_be_bytes());
                raw.truncate(108);
            }
            5 => {
                drop(create_private(&temp.private().join(TEMP)).unwrap());
            }
            6 => {
                drop(create_private(&temp.private().join(INTENT)).unwrap());
            }
            7 | 8 => {
                fs::rename(&stage, temp.private().join(INTENT)).unwrap();
                raw.truncate(if mutation == 7 { 0 } else { 120 });
            }
            9 => rewrite(
                &temp.private().join(STATE),
                &Image {
                    generation: 1,
                    state: changed(store.state()),
                }
                .encode(),
            ),
            _ => unreachable!(),
        }
        let target = if matches!(mutation, 7 | 8) {
            temp.private().join(INTENT)
        } else {
            stage
        };
        rewrite(&target, &raw);
        let before = fs::read(temp.private().join(STATE)).unwrap();
        drop(store);
        assert!(matches!(
            Store::open(temp.private(), scope, None),
            Err(Error::Corrupt)
        ));
        assert_eq!(fs::read(&target).unwrap(), raw);
        assert_eq!(fs::read(temp.private().join(STATE)).unwrap(), before);
    }
}

#[test]
fn complete_preparation_recovery_rechecks_sources_and_survives_promotion_cuts() {
    for step in [Step::IntentSynced, Step::IntentRenamed, Step::IntentDurable] {
        let (temp, mut sources, scope, control) = setup();
        let original = sources.archive().clone();
        let mut full = original.clone();
        add(&mut full, &post(scope, control));
        sources.commit(full, sources.pin()).unwrap();
        let mut restored =
            SocialStore::create(temp.0.join("restored-source"), REALM, Limits::default()).unwrap();
        restored.commit(original, restored.pin()).unwrap();
        let mut store = Store::create(temp.private(), scope, &sources).unwrap();
        let pin = store.pin();
        let candidate = observed(store.state(), sources.archive());
        store.fault = Some(Step::IntentWritten);
        assert!(store.commit(candidate.clone(), pin, &sources).is_err());
        let raw = fs::read(temp.private().join(INTENT_TEMP)).unwrap();
        drop(store);
        let mut store = Store::open(temp.private(), scope, Some(pin)).unwrap();
        assert!(matches!(
            store.commit(changed(store.state()), pin, &sources),
            Err(Error::RecoveryRequired)
        ));
        assert!(matches!(
            store.recover(&restored),
            Err(Error::MissingSource)
        ));
        assert_eq!(fs::read(temp.private().join(INTENT_TEMP)).unwrap(), raw);
        assert!(!temp.private().join(INTENT).exists());
        store.fault = Some(step);
        assert!(matches!(
            store.recover(&sources),
            Err(Error::Indeterminate(_))
        ));
        assert_eq!(store.pin(), pin);
        assert!(!temp.private().join(TEMP).exists());
        drop(store);
        let mut store = Store::open(temp.private(), scope, Some(pin)).unwrap();
        store.recover(&sources).unwrap();
        assert_eq!(store.state().payload(), candidate.payload());
        assert_eq!(store.pin().generation(), 1);
        assert_eq!(fs::read_dir(temp.private()).unwrap().count(), 2);
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

// ---------------------------------------------------------------------------
// Generative Hegel properties over the private-store lifecycle. Each case draws
// an interleaved command sequence — signed record ingestion, canonical
// publication, private commits on drawn bases and anchors, torn publication
// boundaries at every protocol step, restarts under drawn scopes and freshness
// anchors, pending-intent reconciliation, and partial source restores — while a
// mirror model predicts every outcome. The oracle replays `commit_inner`,
// `open`, `recover` and `finish` in production check order over mirrored disk
// contents, including the residue each injected boundary fault leaves behind;
// pure validation predicates delegate to the same in-module `check_source_ready`
// and `validate_candidate` the store calls. `recovery_hegel.rs` in
// vhalla-ledger is the reference for the draw-inside-the-loop style; the
// journal tests are the reference for the simulate-then-compare oracle.
// ---------------------------------------------------------------------------

/// Fixed derivation time for every `View`, snapshot and scope in the trace.
const NOW: u64 = 10;

/// Every private publication-boundary step a case can inject, mirroring `Step`.
const BOUNDARY: [Step; 11] = [
    Step::IntentCreated,
    Step::IntentWritten,
    Step::IntentSynced,
    Step::IntentRenamed,
    Step::IntentDurable,
    Step::TempWritten,
    Step::TempDurable,
    Step::StateRenamed,
    Step::StateDurable,
    Step::IntentRemoved,
    Step::CleanupDurable,
];

/// Stable discriminants for `Error`, which carries no `PartialEq`; the oracle
/// compares kinds, never embedded payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum K {
    UnsafePath,
    Busy,
    Corrupt,
    Conflict,
    Freshness,
    RecoveryRequired,
    MissingSource,
    Capacity,
    Attention,
    Discovery,
    Social,
    Io,
    Indeterminate,
}
fn kind(error: &Error) -> K {
    match error {
        Error::UnsafePath => K::UnsafePath,
        Error::Busy => K::Busy,
        Error::Corrupt => K::Corrupt,
        Error::Conflict => K::Conflict,
        Error::Freshness => K::Freshness,
        Error::RecoveryRequired => K::RecoveryRequired,
        Error::MissingSource => K::MissingSource,
        Error::Capacity => K::Capacity,
        Error::Attention(_) => K::Attention,
        Error::Discovery(_) => K::Discovery,
        Error::Social(_) => K::Social,
        Error::Io(_) => K::Io,
        Error::Indeterminate(_) => K::Indeterminate,
    }
}
impl K {
    fn name(self) -> &'static str {
        match self {
            K::UnsafePath => "unsafe-path",
            K::Busy => "busy",
            K::Corrupt => "corrupt",
            K::Conflict => "conflict",
            K::Freshness => "freshness",
            K::RecoveryRequired => "recovery-required",
            K::MissingSource => "missing-source",
            K::Capacity => "capacity",
            K::Attention => "attention",
            K::Discovery => "discovery",
            K::Social => "social",
            K::Io => "io",
            K::Indeterminate => "indeterminate",
        }
    }
}

/// A distinct post in the reader owner's signed chain: `sequence` is the chain
/// index and `previous` the preceding post id, so no two posts fork a slot.
fn post_at(
    scope: ReaderScope,
    control: RecordId,
    sequence: u64,
    previous: Option<RecordId>,
) -> SignedRecord {
    signed(Body::Social {
        actor: Actor::Owner {
            owner: scope.owner(),
            control,
        },
        realm: REALM,
        sequence,
        previous,
        operation: Operation::Post {
            placement: Placement::Profile,
            text: Text::new(&format!("private-source-{sequence}")).unwrap(),
            reply: None,
            quote: None,
        },
    })
}

/// Preparation or authoritative intent bytes. Torn unpublished preparation
/// can be discarded only before effects; torn authoritative evidence refuses.
/// Sync state is not modeled: written bytes are always readable back.
enum MIntent {
    Torn,
    Complete {
        expected: Pin,
        generation: u64,
        state: Box<PrivateState>,
    },
}

/// The pin a `(generation, state)` image encodes to — the same digest the
/// store derives for its durable and retained images.
fn image_pin(generation: u64, state: &PrivateState) -> Pin {
    Image {
        generation,
        state: state.clone(),
    }
    .pin()
}

/// One live social-store handle and whether a legacy torn authoritative intent
/// is parked in its directory, as reported by `recovery_required`.
struct Source {
    store: SocialStore,
    torn: bool,
}

/// The mirror model: what the private directory durably holds, what the live
/// handle cached, and which source stores exist. Command generators read this
/// accumulated state; the oracle methods replay the production check order.
struct Trace {
    scope: ReaderScope,
    /// A second admitted scope under the same owner: a different profile
    /// namespace, which `open` must reject while decoding `state`.
    wrong_scope: ReaderScope,
    /// The reader owner's genesis record; its id is `scope.owner()` as a
    /// `RecordId` and the `control` every drawn post cites.
    genesis: SignedRecord,
    /// `(generation, state)` of the durable `state` file.
    disk: (u64, PrivateState),
    /// `(generation, state)` the live handle decoded — stale after a crash
    /// that renamed `state.tmp` before `self.image` was updated.
    handle: (u64, PrivateState),
    /// The `intent` file's decode status, when the file exists.
    intent: Option<MIntent>,
    /// Whether `intent` represents unpublished `intent.tmp` instead.
    staged: bool,
    /// The `state.tmp` bytes when the file exists — always a complete image
    /// under this fault model, since injected step faults fire after write_all.
    temp: Option<Vec<u8>>,
    /// Every `(pin, state)` ever published, oldest first; `.last()` is live.
    history: Vec<(Pin, PrivateState)>,
    /// The reader owner's post chain; `posts[..committed]` is in `sources[0]`.
    posts: Vec<SignedRecord>,
    committed: usize,
    /// Live source stores: index 0 is canonical, the rest are partial restores.
    sources: Vec<Source>,
    active: usize,
}

impl Trace {
    /// Draw the genesis nonce and scope seeds, create the canonical source
    /// store with the owner genesis committed, and create the private store.
    fn open(tc: &TestCase) -> (Temp, Self, Store) {
        let temp = Temp::new();
        let mut canonical = SocialStore::create(temp.social(), REALM, Limits::default()).unwrap();
        let seed = tc.draw(gs::integers::<u8>());
        let genesis = signed(Body::OwnerGenesis {
            controller: key().verifying_key().to_bytes(),
            recovery: None,
            nonce: [seed; 32],
        });
        let mut archive = canonical.archive().clone();
        add(&mut archive, &genesis);
        canonical.commit(archive, canonical.pin()).unwrap();
        let owner = OwnerId::from_bytes(*genesis.id().as_bytes());
        let scope = ReaderScope::new(
            canonical.archive(),
            NOW,
            owner,
            None,
            [seed; 32],
            [seed.wrapping_add(1); 32],
        )
        .unwrap();
        let wrong_scope =
            ReaderScope::new(canonical.archive(), NOW, owner, None, [9; 32], [9; 32]).unwrap();
        let store = Store::create(temp.private(), scope, &canonical).unwrap();
        let image = (0, store.state().clone());
        let trace = Self {
            scope,
            wrong_scope,
            genesis,
            disk: image.clone(),
            handle: image.clone(),
            intent: None,
            staged: false,
            temp: None,
            history: vec![(store.pin(), image.1)],
            posts: Vec::new(),
            committed: 0,
            sources: vec![Source {
                store: canonical,
                torn: false,
            }],
            active: 0,
        };
        (temp, trace, store)
    }

    fn handle_pin(&self) -> Pin {
        image_pin(self.handle.0, &self.handle.1)
    }
    fn disk_pin(&self) -> Pin {
        image_pin(self.disk.0, &self.disk.1)
    }

    /// `check_disk`: the durable `state` image must equal the handle's cache.
    /// After a crash past `StateRenamed` the live handle is stale and every
    /// commit/recover fails Conflict until a reopen re-reads the disk image.
    fn check_disk(&self) -> Result<(), K> {
        if self.disk_pin() == self.handle_pin() {
            Ok(())
        } else {
            Err(K::Conflict)
        }
    }
    /// `check_source_ready` against the active source — the production helper
    /// itself, so realm, social recovery flag, owner and agent checks keep
    /// their exact semantics.
    fn source_ready(&self) -> Result<(), K> {
        check_source_ready(self.handle.1.scope(), &self.sources[self.active].store)
            .map_err(|e| kind(&e))
    }
    /// `validate_candidate` against the live handle image — the production
    /// helper itself: scope equality, source readiness, component generation
    /// monotonicity, then the diffed new-claim source check.
    fn validate(&self, next: &PrivateState) -> Result<(), K> {
        validate_candidate(&self.handle.1, next, &self.sources[self.active].store)
            .map_err(|e| kind(&e))
    }
    /// The retained intent's decoded fields — `None` for the torn empty file,
    /// exactly as `Intent::decode` refuses it.
    fn intent_parts(&self) -> Option<(Pin, u64, PrivateState)> {
        match &self.intent {
            Some(MIntent::Complete {
                expected,
                generation,
                state,
            }) => Some((*expected, *generation, state.as_ref().clone())),
            _ => None,
        }
    }

    fn reconcile_staged_model(&mut self, fault: Option<Step>) -> Result<(), K> {
        if !self.staged {
            return Ok(());
        }
        if self.temp.is_some() {
            return Err(K::Corrupt);
        }
        if let Some((expected, _, state)) = self.intent_parts() {
            if expected != self.handle_pin() {
                return Err(K::Corrupt);
            }
            self.validate(&state)?;
            if fault == Some(Step::IntentSynced) {
                return Err(K::Indeterminate);
            }
            self.staged = false;
            if fault == Some(Step::IntentRenamed) || fault == Some(Step::IntentDurable) {
                return Err(K::Indeterminate);
            }
        } else {
            self.intent = None;
            self.staged = false;
        }
        Ok(())
    }

    /// `Store::finish`: re-check the disk, validate the retained candidate
    /// against the live handle image and current sources, then replay the
    /// write/rename/cleanup sequence, leaving on disk exactly the residue the
    /// drawn fault step permits.
    fn finish_model(
        &mut self,
        expected: Pin,
        generation: u64,
        state: PrivateState,
        fault: Option<Step>,
        reconciled: bool,
    ) -> Result<(Pin, bool), K> {
        self.check_disk()?;
        self.validate(&state)?;
        let next = Image { generation, state };
        let next_bytes = next.encode();
        let next_pin = next.pin();
        if self.handle_pin() == expected {
            if let Some(retained) = &self.temp {
                if !next_bytes.starts_with(retained) {
                    return Err(K::Corrupt);
                }
            }
            self.temp = Some(next_bytes.clone());
            if fault == Some(Step::TempWritten) || fault == Some(Step::TempDurable) {
                return Err(K::Indeterminate);
            }
            self.disk = (next.generation, next.state);
            self.temp = None;
            if fault == Some(Step::StateRenamed) || fault == Some(Step::StateDurable) {
                return Err(K::Indeterminate);
            }
        } else if self.handle_pin() != next_pin {
            return Err(K::Conflict);
        }
        // Durable read-back must be exactly the retained next image.
        if self.disk_pin() != next_pin {
            return Err(K::Conflict);
        }
        self.handle = self.disk.clone();
        if let Some(retained) = self.temp.take() {
            if !next_bytes.starts_with(&retained) {
                self.temp = Some(retained);
                return Err(K::Corrupt);
            }
        }
        // The retained intent always matches — only this model writes intents.
        self.intent = None;
        if fault == Some(Step::IntentRemoved) || fault == Some(Step::CleanupDurable) {
            return Err(K::Indeterminate);
        }
        Ok((self.handle_pin(), reconciled))
    }

    /// `commit_inner`: disk check, source readiness, exact retained-intent
    /// reconciliation, temp-only refusal, identical-payload readback, stale
    /// anchor conflict, candidate validation, then the boundary-step sequence.
    fn commit_model(
        &mut self,
        candidate: &PrivateState,
        expected: Pin,
        fault: Option<Step>,
    ) -> Result<(Pin, bool), K> {
        self.check_disk()?;
        self.source_ready()?;
        if self.staged {
            if let Some((pin, _, state)) = self.intent_parts() {
                if expected != pin || candidate.payload() != state.payload() {
                    return Err(K::RecoveryRequired);
                }
            }
            self.reconcile_staged_model(fault)?;
        }
        if self.intent.is_some() {
            let Some((pin, generation, state)) = self.intent_parts() else {
                return Err(K::Corrupt);
            };
            let handle = self.handle_pin();
            if handle != pin && handle != image_pin(generation, &state) {
                return Err(K::Conflict);
            }
            if expected != pin || candidate.payload() != state.payload() {
                return Err(K::RecoveryRequired);
            }
            return self.finish_model(pin, generation, state, fault, true);
        }
        if self.temp.is_some() {
            return Err(K::RecoveryRequired);
        }
        if candidate.payload() == self.handle.1.payload() {
            return Ok((self.handle_pin(), true));
        }
        if expected != self.handle_pin() {
            return Err(K::Conflict);
        }
        self.validate(candidate)?;
        let generation = self.handle.0.checked_add(1).ok_or(K::Capacity)?;
        // Preparation is not authoritative until its complete synced bytes
        // have been renamed. Neither preparation cut permits successor effects.
        self.staged = true;
        if fault == Some(Step::IntentCreated) {
            self.intent = Some(MIntent::Torn);
            return Err(K::Indeterminate);
        }
        self.intent = Some(MIntent::Complete {
            expected,
            generation,
            state: Box::new(candidate.clone()),
        });
        if fault == Some(Step::IntentWritten) || fault == Some(Step::IntentSynced) {
            return Err(K::Indeterminate);
        }
        self.staged = false;
        if fault == Some(Step::IntentRenamed) || fault == Some(Step::IntentDurable) {
            return Err(K::Indeterminate);
        }
        self.finish_model(expected, generation, candidate.clone(), fault, false)
    }

    /// `recover`: the same disk/source checks, then finish the retained intent
    /// or read back the current pin — never a substitute candidate.
    fn recover_model(&mut self, fault: Option<Step>) -> Result<(Pin, bool), K> {
        self.check_disk()?;
        self.source_ready()?;
        self.reconcile_staged_model(fault)?;
        if self.intent.is_some() {
            let Some((pin, generation, state)) = self.intent_parts() else {
                return Err(K::Corrupt);
            };
            let handle = self.handle_pin();
            if handle != pin && handle != image_pin(generation, &state) {
                return Err(K::Conflict);
            }
            return self.finish_model(pin, generation, state, fault, true);
        }
        if self.temp.is_some() {
            return Err(K::RecoveryRequired);
        }
        Ok((self.handle_pin(), true))
    }

    /// `Store::open`: decode under the caller's scope first, then the optional
    /// exact freshness anchor, then inventory, then the retained-intent check
    /// and finally the temp-only refusal. A successful open re-caches the disk
    /// image; every failure leaves the directory exactly as it was.
    fn open_model(&mut self, scope: ReaderScope, expected: Option<Pin>) -> Result<(), K> {
        if scope != self.scope {
            return Err(K::Corrupt);
        }
        if expected.is_some_and(|pin| pin != self.disk_pin()) {
            return Err(K::Freshness);
        }
        if self.staged {
            if self.temp.is_some()
                || self
                    .intent_parts()
                    .is_some_and(|(pin, _, _)| pin != self.disk_pin())
            {
                return Err(K::Corrupt);
            }
        } else if self.intent.is_some() {
            let Some((pin, generation, state)) = self.intent_parts() else {
                return Err(K::Corrupt);
            };
            let disk = self.disk_pin();
            if disk != pin && disk != image_pin(generation, &state) {
                return Err(K::Conflict);
            }
        } else if self.temp.is_some() {
            return Err(K::RecoveryRequired);
        }
        self.handle = self.disk.clone();
        Ok(())
    }

    // --- state-dependent generators ----------------------------------------

    /// The live state, or — to reach regression and divergence — a committed
    /// snapshot drawn from publication history.
    fn drawn_base(&self, tc: &TestCase) -> PrivateState {
        if self.history.len() > 1 && tc.draw(gs::integers::<u8>().max_value(4)) == 0 {
            self.history[tc.draw(gs::integers::<usize>().max_value(self.history.len() - 2))]
                .1
                .clone()
        } else {
            self.handle.1.clone()
        }
    }
    /// An expected anchor: the live pin, a stale published pin, or a
    /// fabricated one that matches no retained image.
    fn drawn_pin(&self, tc: &TestCase) -> Pin {
        match tc.draw(gs::integers::<u8>().max_value(9)) {
            0..=5 => self.handle_pin(),
            6..=7 if self.history.len() > 1 => {
                self.history[tc.draw(gs::integers::<usize>().max_value(self.history.len() - 2))].0
            }
            _ => Pin {
                generation: tc.draw(gs::integers::<u64>().max_value(3)),
                digest: [tc.draw(gs::integers::<u8>()); 32],
            },
        }
    }
    /// A drawn single-step boundary fault, or `None` for a clean run.
    fn drawn_fault(&self, tc: &TestCase) -> Option<Step> {
        if tc.draw(gs::integers::<u8>().max_value(4)) == 0 {
            Some(BOUNDARY[tc.draw(gs::integers::<usize>().max_value(BOUNDARY.len() - 1))])
        } else {
            None
        }
    }
    /// A real post id or a fabricated `RecordId`, for references that need no
    /// source evidence (bookmarks, thread mutes and subscriptions).
    fn drawn_record(&self, tc: &TestCase) -> RecordId {
        if !self.posts.is_empty() && tc.draw(gs::booleans()) {
            self.posts[tc.draw(gs::integers::<usize>().max_value(self.posts.len() - 1))].id()
        } else {
            RecordId::from_bytes([tc.draw(gs::integers::<u8>()); 32])
        }
    }
    /// The archive a drawn view or acknowledgement runs against: canonical,
    /// canonical plus every signed-but-unpublished post, or a drawn live
    /// source — deliberately richer than the active source, so new claims can
    /// be genuinely missing from it.
    fn basis(&self, tc: &TestCase) -> Archive {
        match tc.draw(gs::integers::<u8>().max_value(9)) {
            0..=3 => self.sources[0].store.archive().clone(),
            4..=6 => {
                let mut staged = self.sources[0].store.archive().clone();
                for post in &self.posts[self.committed..] {
                    add(&mut staged, post);
                }
                staged
            }
            _ => {
                let i = tc.draw(gs::integers::<usize>().max_value(self.sources.len() - 1));
                self.sources[i].store.archive().clone()
            }
        }
    }
    /// Posts whose evidence the drawn basis archive can currently evaluate.
    fn admitted(&self, view: &View<'_>, posts: &[SignedRecord]) -> Vec<RecordId> {
        posts
            .iter()
            .map(SignedRecord::id)
            .filter(|id| {
                matches!(
                    view.state(*id),
                    Some(RecordState::Committed | RecordState::Provisional)
                )
            })
            .collect()
    }

    /// Apply drawn edits to a base state. Preference edits never claim
    /// sources; observe/seen/feedback/acknowledge claim exactly what the drawn
    /// basis archive evidences — which the active source may not retain.
    fn mutate(&self, tc: &TestCase, mut candidate: PrivateState) -> PrivateState {
        for _ in 0..=tc.draw(gs::integers::<usize>().max_value(2)) {
            match tc.draw(gs::integers::<u8>().max_value(11)) {
                0 => {
                    let mut discovery = candidate.discovery().clone();
                    discovery
                        .apply(Change::Wider(tc.draw(gs::booleans())))
                        .unwrap();
                    candidate = candidate.with_discovery(discovery).unwrap();
                }
                1 => {
                    let reference = if !self.posts.is_empty() && tc.draw(gs::booleans()) {
                        let post = &self.posts
                            [tc.draw(gs::integers::<usize>().max_value(self.posts.len() - 1))];
                        PostRef {
                            post: post.id(),
                            revision: post.id(),
                        }
                    } else {
                        PostRef {
                            post: RecordId::from_bytes([tc.draw(gs::integers::<u8>()); 32]),
                            revision: RecordId::from_bytes([tc.draw(gs::integers::<u8>()); 32]),
                        }
                    };
                    let mut discovery = candidate.discovery().clone();
                    discovery
                        .apply(Change::Bookmark(reference, tc.draw(gs::booleans())))
                        .unwrap();
                    candidate = candidate.with_discovery(discovery).unwrap();
                }
                2 => {
                    let id = self.drawn_record(tc);
                    let mut discovery = candidate.discovery().clone();
                    let change = if tc.draw(gs::booleans()) {
                        Change::MuteThread(id, tc.draw(gs::booleans()))
                    } else {
                        Change::Subscribe(Subscription::Thread(id), tc.draw(gs::booleans()))
                    };
                    discovery.apply(change).unwrap();
                    candidate = candidate.with_discovery(discovery).unwrap();
                }
                3 => {
                    let owner = OwnerId::from_bytes([tc.draw(gs::integers::<u8>()); 32]);
                    let mut discovery = candidate.discovery().clone();
                    let change = if tc.draw(gs::booleans()) {
                        Change::MuteOwner(owner, tc.draw(gs::booleans()))
                    } else {
                        Change::BlockOwner(owner, tc.draw(gs::booleans()))
                    };
                    discovery.apply(change).unwrap();
                    candidate = candidate.with_discovery(discovery).unwrap();
                }
                4 => {
                    let mut discovery = candidate.discovery().clone();
                    let change = match tc.draw(gs::integers::<u8>().max_value(3)) {
                        0 => Change::Interest {
                            tag: format!("t{}", tc.draw(gs::integers::<u8>().max_value(3))),
                            delta: tc.draw(gs::integers::<u8>().max_value(8)) as i8 - 4,
                        },
                        1 => Change::SaveSearch {
                            name: format!("q{}", tc.draw(gs::integers::<u8>().max_value(3))),
                            query: String::from("literal"),
                        },
                        2 => Change::RemoveSearch(format!(
                            "q{}",
                            tc.draw(gs::integers::<u8>().max_value(3))
                        )),
                        _ => Change::ClearInterests,
                    };
                    discovery.apply(change).unwrap();
                    candidate = candidate.with_discovery(discovery).unwrap();
                }
                5..=6 => {
                    let basis = self.basis(tc);
                    let eligibility = Eligibility::default();
                    let view = View::new(&basis, NOW, &eligibility);
                    let mut discovery = candidate.discovery().clone();
                    discovery.observe(&view).unwrap();
                    candidate = candidate.with_discovery(discovery).unwrap();
                }
                7..=8 => {
                    let basis = self.basis(tc);
                    let eligibility = Eligibility::default();
                    let view = View::new(&basis, NOW, &eligibility);
                    let admitted = self.admitted(&view, &self.posts);
                    if admitted.is_empty() {
                        continue;
                    }
                    let id =
                        admitted[tc.draw(gs::integers::<usize>().max_value(admitted.len() - 1))];
                    let mut discovery = candidate.discovery().clone();
                    if tc.draw(gs::booleans()) {
                        discovery
                            .mark_seen(
                                &view,
                                PostRef {
                                    post: id,
                                    revision: id,
                                },
                            )
                            .unwrap();
                    } else {
                        discovery
                            .feedback(
                                &view,
                                PostRef {
                                    post: id,
                                    revision: id,
                                },
                                tc.draw(gs::integers::<u8>().max_value(2)) as i8 - 1,
                            )
                            .unwrap();
                    }
                    candidate = candidate.with_discovery(discovery).unwrap();
                }
                _ => {
                    let basis = self.basis(tc);
                    if basis.get(self.genesis.id()).is_none() {
                        // Notifications cannot be derived for an unknown owner.
                        continue;
                    }
                    let eligibility = Eligibility::default();
                    let view = View::new(&basis, NOW, &eligibility);
                    let mut watched = BTreeSet::new();
                    for id in self.admitted(&view, &self.posts) {
                        if tc.draw(gs::booleans()) {
                            watched.insert(id);
                        }
                    }
                    let policy = AttentionPolicy::new(
                        Vec::new(),
                        Vec::new(),
                        watched.into_iter().collect(),
                        true,
                    )
                    .unwrap();
                    let snapshot = candidate
                        .attention()
                        .notifications(&basis, NOW, &policy, 0, MAX_PAGE)
                        .unwrap();
                    let attention = candidate
                        .attention()
                        .acknowledge(&snapshot, &basis)
                        .unwrap();
                    candidate = candidate.with_attention(attention).unwrap();
                }
            }
        }
        candidate
    }

    // --- interleaved commands ------------------------------------------------

    /// Sign a fresh chain post and prove a scratch archive admits it, or
    /// re-ingest a committed record and prove the receipt reports no insertion.
    fn ingest(&mut self, tc: &TestCase) {
        let mut scratch = self.sources[0].store.archive().clone();
        if self.committed > 0 && tc.draw(gs::booleans()) {
            // One retained record, genesis included: an exact duplicate.
            let i = tc.draw(gs::integers::<usize>().max_value(self.committed));
            let record = if i == self.committed {
                &self.genesis
            } else {
                &self.posts[i]
            };
            let receipt = scratch
                .ingest(
                    &record.encode(),
                    &mut Budget::new(1, MAX_RECORD_BYTES).unwrap(),
                )
                .unwrap();
            assert!(!receipt.inserted);
            tc.event("ingest/duplicate");
        } else {
            let sequence = self.posts.len() as u64;
            let post = post_at(
                self.scope,
                self.genesis.id(),
                sequence,
                self.posts.last().map(SignedRecord::id),
            );
            let receipt = scratch
                .ingest(
                    &post.encode(),
                    &mut Budget::new(1, MAX_RECORD_BYTES).unwrap(),
                )
                .unwrap();
            assert!(receipt.inserted);
            self.posts.push(post);
            tc.event("ingest/fresh");
        }
    }

    /// Commit a drawn prefix of the signed-but-unpublished posts into the
    /// canonical source store — or read back the identical archive when
    /// nothing is staged. A torn canonical intent refuses the commit.
    fn publish(&mut self, tc: &TestCase) {
        let staged = self.posts.len() - self.committed;
        let take = tc.draw(gs::integers::<usize>().max_value(staged));
        let mut candidate = self.sources[0].store.archive().clone();
        for post in &self.posts[self.committed..self.committed + take] {
            add(&mut candidate, post);
        }
        let source = &mut self.sources[0];
        if source.torn {
            assert!(source.store.commit(candidate, source.store.pin()).is_err());
            tc.event("social/commit-while-torn");
            return;
        }
        let publication = source.store.commit(candidate, source.store.pin()).unwrap();
        assert_eq!(publication.reconciled(), take == 0);
        self.committed += take;
        tc.event(if take == 0 {
            "social/readback"
        } else {
            "social/published"
        });
    }

    /// Draw a candidate, anchor and boundary fault; predict with the model,
    /// then require the real commit to agree exactly — including whether the
    /// result reconciled a retained intent or published fresh.
    fn commit(&mut self, tc: &TestCase, store: &mut Store) {
        let pending = matches!(self.intent, Some(MIntent::Complete { .. }));
        let pick = tc.draw(gs::integers::<u8>().max_value(9));
        let (candidate, expected) = if pending && pick >= 6 {
            let Some(MIntent::Complete {
                expected: pin,
                state,
                ..
            }) = &self.intent
            else {
                unreachable!()
            };
            tc.event("commit/intent-retried");
            let candidate = if tc.draw(gs::booleans()) {
                state.as_ref().clone()
            } else {
                self.mutate(tc, state.as_ref().clone())
            };
            let expected = if tc.draw(gs::booleans()) {
                *pin
            } else {
                self.drawn_pin(tc)
            };
            (candidate, expected)
        } else {
            let candidate = self.mutate(tc, self.drawn_base(tc));
            (candidate, self.drawn_pin(tc))
        };
        let fault = self.drawn_fault(tc);
        if let Some(step) = fault {
            tc.event(format!("fault/{step:?}"));
        }
        let want = self.commit_model(&candidate, expected, fault);
        store.fault = fault;
        let got = store.commit(candidate, expected, &self.sources[self.active].store);
        // Disarm a fault the drawn path never reached, keeping the model honest.
        store.fault = None;
        compare(tc, "commit", want, got);
    }

    /// Draw a boundary fault and reconcile: whatever intent the crash
    /// retained must finish exactly, or refuse for the modeled reason.
    fn recover(&mut self, tc: &TestCase, store: &mut Store) {
        // A retained intent makes every `finish` boundary reachable, so inject
        // a fault half the time — an intent-write step is never stepped during
        // recovery and must simply stay armed but unfired.
        let fault = if self.intent.is_some() && tc.draw(gs::booleans()) {
            Some(BOUNDARY[tc.draw(gs::integers::<usize>().max_value(BOUNDARY.len() - 1))])
        } else {
            self.drawn_fault(tc)
        };
        if let Some(step) = fault {
            tc.event(format!("fault/{step:?}"));
        }
        let want = self.recover_model(fault);
        store.fault = fault;
        let got = store.recover(&self.sources[self.active].store);
        store.fault = None;
        compare(tc, "recover", want, got);
    }

    /// Drop the handle and reopen under a drawn scope and anchor — none, the
    /// current pin, a stale published pin or a fabricated one — comparing
    /// every refusal with the model. `None` means the drawn residue (a torn
    /// intent) failed closed for good; the trace must stop using the store.
    fn reopen(&mut self, tc: &TestCase, temp: &Temp, store: Store) -> Option<Store> {
        let scope = if tc.draw(gs::integers::<u8>().max_value(7)) == 0 {
            self.wrong_scope
        } else {
            self.scope
        };
        let expected = match tc.draw(gs::integers::<u8>().max_value(9)) {
            0..=4 => None,
            5..=7 => Some(self.disk_pin()),
            8 if self.history.len() > 1 => Some(
                self.history[tc.draw(gs::integers::<usize>().max_value(self.history.len() - 2))].0,
            ),
            _ => Some(Pin {
                generation: tc.draw(gs::integers::<u64>().max_value(3)),
                digest: [tc.draw(gs::integers::<u8>()); 32],
            }),
        };
        drop(store);
        if scope != self.scope {
            // A foreign namespace is refused while decoding `state`, before
            // any anchor or intent check.
            let Err(error) = Store::open(temp.private(), scope, expected) else {
                panic!("a foreign reader scope opened the store")
            };
            assert_eq!(kind(&error), K::Corrupt);
            tc.event("open/foreign-scope");
        }
        let want = self.open_model(self.scope, expected);
        match want {
            Ok(()) => {
                tc.event("open/ok");
                Some(Store::open(temp.private(), self.scope, expected).unwrap())
            }
            Err(K::Freshness) => {
                let Err(error) = Store::open(temp.private(), self.scope, expected) else {
                    panic!("a stale or fabricated pin opened the store")
                };
                assert_eq!(kind(&error), K::Freshness);
                tc.event("open/freshness");
                match self.open_model(self.scope, None) {
                    Ok(()) => Some(Store::open(temp.private(), self.scope, None).unwrap()),
                    Err(k) => {
                        let Err(error) = Store::open(temp.private(), self.scope, None) else {
                            panic!("a modeled refusal opened the store")
                        };
                        assert_eq!(kind(&error), k);
                        tc.event(format!("open/{}", k.name()));
                        None
                    }
                }
            }
            Err(k) => {
                let Err(error) = Store::open(temp.private(), self.scope, expected) else {
                    panic!("a modeled refusal opened the store")
                };
                assert_eq!(kind(&error), k);
                tc.event(format!("open/{}", k.name()));
                None
            }
        }
    }

    /// Either snapshot a drawn prefix of the signed chain — optionally without
    /// the owner genesis — into a fresh restored store and make it active, or
    /// switch the active source among live handles.
    fn source(&mut self, tc: &TestCase, temp: &Temp) {
        if self.sources.len() == 1 || tc.draw(gs::booleans()) {
            let keep = tc.draw(gs::integers::<usize>().max_value(self.posts.len()));
            let with_owner = tc.draw(gs::booleans());
            let mut archive = Archive::new(REALM, Limits::default()).unwrap();
            if with_owner {
                add(&mut archive, &self.genesis);
            }
            for post in &self.posts[..keep] {
                add(&mut archive, post);
            }
            let mut restored = SocialStore::create(
                temp.0.join(format!("restored-{}", self.sources.len())),
                REALM,
                Limits::default(),
            )
            .unwrap();
            restored.commit(archive, restored.pin()).unwrap();
            self.sources.push(Source {
                store: restored,
                torn: false,
            });
            self.active = self.sources.len() - 1;
            tc.event(if with_owner {
                "source/restored"
            } else {
                "source/restored-no-owner"
            });
        } else {
            self.active = tc.draw(gs::integers::<usize>().max_value(self.sources.len() - 1));
            tc.event("source/switch");
        }
    }

    /// Park a legacy torn authoritative intent in the private directory or a drawn source, or
    /// remove a source's, the operator repair the readiness check observes. A
    /// torn private intent fails closed for good: commit, recover and reopen
    /// all see `Corrupt` until the trace stops.
    fn tear_or_repair(&mut self, tc: &TestCase, temp: &Temp) {
        if self.intent.is_none() && tc.draw(gs::integers::<u8>().max_value(4)) == 0 {
            drop(create_private(&temp.private().join(INTENT)).unwrap());
            self.intent = Some(MIntent::Torn);
            tc.event("private/torn-intent");
            return;
        }
        let i = tc.draw(gs::integers::<usize>().max_value(self.sources.len() - 1));
        let source = &mut self.sources[i];
        let path = source.store.directory_path().join(INTENT);
        if source.torn {
            fs::remove_file(path).unwrap();
            source.torn = false;
            tc.event("source/repaired");
        } else {
            drop(create_private(&path).unwrap());
            source.torn = true;
            assert!(source.store.recovery_required().unwrap());
            tc.event("source/torn");
        }
    }

    /// The live handle holds the lifetime lock; a concurrent opener must see
    /// Busy — before any scope, anchor, or intent check runs.
    fn busy(&self, tc: &TestCase, temp: &Temp) {
        let Err(error) = Store::open(temp.private(), self.scope, None) else {
            panic!("a second handle took the lifetime lock")
        };
        assert_eq!(kind(&error), K::Busy);
        tc.event("open/busy");
    }

    // --- per-command invariants ----------------------------------------------

    /// The invariants that must hold after every command: the live handle, the
    /// durable image the model mirrors, and the exact directory file set —
    /// `lock` and `state` plus a retained `intent` or `state.tmp`.
    fn check(&self, store: &Store, temp: &Temp) {
        assert_eq!(store.pin(), self.handle_pin());
        assert_eq!(store.state().payload(), self.handle.1.payload());
        assert_eq!(store.recovery_required().unwrap(), self.intent.is_some());
        assert_eq!(temp.private().join(INTENT_TEMP).exists(), self.staged);
        assert_eq!(
            temp.private().join(INTENT).exists(),
            self.intent.is_some() && !self.staged
        );
        let files = 2 + usize::from(self.intent.is_some()) + usize::from(self.temp.is_some());
        assert_eq!(fs::read_dir(temp.private()).unwrap().count(), files);
    }
    /// Record the live pin+state so later draws can pick stale bases and
    /// anchors; also notes retained claims the active source can no longer
    /// prove — lawful residue of a partial restore that never blocks new edits.
    fn track(&mut self, tc: &TestCase) {
        if self.history.last().map(|(pin, _)| *pin) != Some(self.handle_pin()) {
            self.history
                .push((self.handle_pin(), self.handle.1.clone()));
        }
        let archive = self.sources[self.active].store.archive();
        if self
            .handle
            .1
            .attention()
            .required_sources()
            .iter()
            .chain(self.handle.1.discovery().required_sources().iter())
            .any(|id| archive.get(*id).is_none())
        {
            tc.event("private/unresolved-claims");
        }
    }
}

/// Compare one modeled outcome against the real call, then count it.
fn compare(tc: &TestCase, op: &str, want: Result<(Pin, bool), K>, got: Result<Publication, Error>) {
    match (&want, &got) {
        (Ok((pin, reconciled)), Ok(publication)) => {
            assert_eq!(publication.pin(), *pin, "{op} pin diverged from the model");
            assert_eq!(
                publication.reconciled(),
                *reconciled,
                "{op} reconciliation flag diverged from the model"
            );
        }
        (Err(want), Err(got)) => {
            assert_eq!(kind(got), *want, "{op} error diverged from the model")
        }
        _ => panic!("{op} diverged: model {want:?}, store {got:?}"),
    }
    tc.event(match want {
        Ok((_, true)) => format!("{op}/reconciled"),
        Ok((_, false)) => format!("{op}/published"),
        Err(k) => format!("{op}/{}", k.name()),
    });
}

/// Interleaved ingestion, publication, faults, restarts, reconciliation and
/// partial restores: every outcome the private store reports must equal the
/// model's replay of the production check order. Each drawn command does real
/// filesystem I/O, so only the `TooSlow` health check is suppressed.
#[hegel::test(test_cases = 64, suppress_health_check = [HealthCheck::TooSlow])]
fn interleaved_sources_faults_and_reopens_follow_the_protocol(tc: TestCase) {
    let (temp, mut trace, store) = Trace::open(&tc);
    // `Option` so a torn-intent reopen — which consumes the dead handle — can
    // leave the slot empty for the rest of the trace.
    let mut store = Some(store);
    let steps = tc.draw(gs::integers::<usize>().min_value(1).max_value(16));
    for _ in 0..steps {
        match tc.draw(gs::integers::<u8>().max_value(11)) {
            0 => trace.ingest(&tc),
            1 => trace.publish(&tc),
            2..=4 => trace.commit(&tc, store.as_mut().unwrap()),
            5 => trace.recover(&tc, store.as_mut().unwrap()),
            6 => match trace.reopen(&tc, &temp, store.take().unwrap()) {
                Some(reopened) => store = Some(reopened),
                // A torn intent fails closed on every reopen — nothing in the
                // private store is reachable afterwards.
                None => break,
            },
            7 => trace.source(&tc, &temp),
            8 => trace.tear_or_repair(&tc, &temp),
            9 => trace.busy(&tc, &temp),
            _ => trace.commit(&tc, store.as_mut().unwrap()),
        }
        trace.check(store.as_ref().unwrap(), &temp);
        trace.track(&tc);
    }
    // Whatever residue the trace left: a clean reopen returns exactly the
    // mirrored image, and a torn intent still fails closed identically.
    let want = trace.open_model(trace.scope, None);
    drop(store);
    match want {
        Ok(()) => {
            let reopened = Store::open(temp.private(), trace.scope, None).unwrap();
            assert_eq!(reopened.pin(), trace.handle_pin());
            assert_eq!(reopened.state().payload(), trace.handle.1.payload());
        }
        Err(k) => {
            let Err(error) = Store::open(temp.private(), trace.scope, None) else {
                panic!("a modeled refusal opened the store")
            };
            assert_eq!(kind(&error), k);
        }
    }
}
