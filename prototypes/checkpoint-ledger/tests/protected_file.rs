#![cfg(all(feature = "native-store", unix))]
//! Exact-byte restart exercises for a local file store and an independent,
//! deterministic witness interface. Not a host service or power-loss test.
use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::SigningKey;
use valhalla_checkpoint_ledger_prototype::file_store::FileStore;
use valhalla_checkpoint_ledger_prototype::persistence::{
    bundle_id, commit, load_protected, Pin, PinWitness, PreparedCommit, Storage,
};
use valhalla_checkpoint_ledger_prototype::protected_commit::{
    advance, reconcile, Error, FencedWitness, Intent, IntentStorage, INTENT_BYTES,
};
use valhalla_checkpoint_ledger_prototype::{certificate_realm, CertifiedLedger};
use valhalla_checkpoint_proof_prototype::{wire, Approval, CheckpointProof, TrustConfig};
use vhalla_core::{Epoch, PeerId, RealmId, Sequence};
use vhalla_ledger::Event;

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Sandbox(PathBuf);
impl Sandbox {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "vhalla-protected-file-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn store(&self) -> PathBuf {
        self.0.join("store")
    }
}
impl Drop for Sandbox {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn keys() -> [SigningKey; 2] {
    [1, 2].map(|n| SigningKey::from_bytes(&[n; 32]))
}
fn trust() -> TrustConfig {
    TrustConfig::new(
        certificate_realm(RealmId(1)),
        7,
        keys().iter().map(SigningKey::verifying_key),
        2,
        2,
        4096,
    )
    .unwrap()
}
fn certify(model: &mut CertifiedLedger, content: &[u8]) -> Vec<u8> {
    model
        .append(Event::new(
            model.head(),
            RealmId(1),
            Epoch(7),
            PeerId(2),
            Sequence(model.event_count() as u64 + 1),
            content.to_vec(),
        ))
        .unwrap();
    let statement = model.propose_tip().unwrap();
    let approvals = keys()
        .iter()
        .map(|key| Approval::sign(key, statement.clone()).unwrap())
        .collect();
    let raw = wire::encode(&CheckpointProof {
        statement,
        approvals,
    })
    .unwrap();
    model.admit(&raw).unwrap();
    raw
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum Fault {
    Outage,
    Revoked,
    Conflict,
    LostReply,
}
#[derive(Clone, Copy)]
struct Grant {
    owner: bool,
    fence: u64,
}
fn owner(fence: u64) -> Grant {
    Grant { owner: true, fence }
}

struct Witness {
    durable: Pin,
    visible: Pin,
    fence: u64,
    outage: bool,
    lose_reply: bool,
    calls: usize,
}
impl Witness {
    fn new(base: Pin) -> Self {
        Self {
            visible: base.clone(),
            durable: base,
            fence: 1,
            outage: false,
            lose_reply: false,
            calls: 0,
        }
    }
    fn guard(&self, grant: &Grant) -> Result<(), Fault> {
        if self.outage {
            return Err(Fault::Outage);
        }
        if !grant.owner || grant.fence != self.fence {
            return Err(Fault::Revoked);
        }
        Ok(())
    }
}
impl FencedWitness for Witness {
    type Grant = Grant;
    type Error = Fault;
    fn capture(&mut self, grant: &Grant) -> Result<Option<Pin>, Fault> {
        self.guard(grant)?;
        Ok(Some(self.durable.clone()))
    }
    fn compare_exchange(
        &mut self,
        grant: &Grant,
        expected: &Pin,
        next: &Pin,
    ) -> Result<bool, Fault> {
        self.guard(grant)?;
        self.calls += 1;
        if self.visible != self.durable {
            return Err(Fault::Conflict); // unresolved host CAS serializes retries
        }
        if self.durable != *expected {
            return Ok(false);
        }
        if next.generation() != expected.generation() + 1
            || next.trust_digest() != expected.trust_digest()
            || next.checkpoint().realm != expected.checkpoint().realm
            || next.checkpoint().epoch != expected.checkpoint().epoch
            || next.checkpoint().height <= expected.checkpoint().height
        {
            return Err(Fault::Conflict);
        }
        self.visible = next.clone();
        self.durable = self.visible.clone(); // simulated durable host sync
        if self.lose_reply {
            self.lose_reply = false;
            return Err(Fault::LostReply);
        }
        Ok(true)
    }
}
impl PinWitness for Witness {
    type Error = Fault;
    fn capture_pin(&mut self) -> Result<Option<Pin>, Fault> {
        self.capture(&owner(self.fence))
    }
}

fn provision(store: &mut FileStore) -> (CertifiedLedger, Pin) {
    let mut model = CertifiedLedger::new(RealmId(1), Epoch(7), trust(), 64).unwrap();
    let raw = certify(&mut model, b"base");
    let initial = PreparedCommit::prepare(&model, &raw, None).unwrap();
    // Explicit test provisioning of BOTH stores; never a protected bootstrap.
    commit(store, &initial).unwrap();
    (model, initial.pin().clone())
}
fn next(model: &mut CertifiedLedger, base: &Pin, payload: &[u8]) -> PreparedCommit {
    let raw = certify(model, payload);
    PreparedCommit::prepare(model, &raw, Some(base)).unwrap()
}

#[test]
fn certified_bytes_and_intent_survive_reopen_and_lost_host_ack() {
    let sandbox = Sandbox::new();
    let mut store = FileStore::create_new(sandbox.store(), 3).unwrap();
    let (mut model, base) = provision(&mut store);
    let mut witness = Witness::new(base.clone());
    let prepared = next(&mut model, &base, b"second");
    let snapshot = model.snapshot();
    assert!(matches!(
        advance(
            &mut store,
            &mut witness,
            &Grant {
                owner: false,
                fence: 1
            },
            &prepared,
            trust(),
            64
        ),
        Err(Error::Witness(Fault::Revoked))
    ));
    assert!(store.read_intent().unwrap().is_none());
    witness.lose_reply = true;
    assert!(matches!(
        advance(&mut store, &mut witness, &owner(1), &prepared, trust(), 64),
        Err(Error::Witness(Fault::LostReply))
    ));
    assert_eq!(witness.durable, *prepared.pin());
    let intent_bytes = store.read_intent().unwrap().unwrap();
    assert_eq!(intent_bytes.len(), INTENT_BYTES);
    let intent = Intent::decode(&intent_bytes).unwrap();
    assert_eq!(intent.predecessor(), &base);
    assert_eq!(intent.target(), prepared.pin());
    let bundle_bytes = store.read_bundle(prepared.pin().bundle()).unwrap();
    assert_eq!(bundle_id(&bundle_bytes), prepared.pin().bundle());
    drop(store);
    let mut store = FileStore::open(sandbox.store(), 3).unwrap();
    assert_eq!(store.read_intent().unwrap().unwrap(), intent_bytes);
    assert_eq!(
        store.read_bundle(prepared.pin().bundle()).unwrap(),
        bundle_bytes
    );
    let recovered = reconcile(&mut store, &mut witness, &owner(1), trust(), 64).unwrap();
    assert_eq!(recovered.snapshot(), snapshot);
    assert_eq!(witness.calls, 1); // no second host CAS after lost reply
    let second = advance(&mut store, &mut witness, &owner(1), &prepared, trust(), 64).unwrap();
    assert_eq!(second.snapshot(), snapshot);
    let pinned = load_protected(&mut store, &mut witness, trust(), 64).unwrap();
    assert_eq!(pinned.snapshot(), snapshot);
    assert_eq!(store.read_intent().unwrap().unwrap(), intent_bytes);
}

#[test]
fn pending_witness_and_local_cas_reconcile_only_exact_retained_data() {
    let sandbox = Sandbox::new();
    let mut store = FileStore::create_new(sandbox.store(), 4).unwrap();
    let (mut model, base) = provision(&mut store);
    let mut witness = Witness::new(base.clone());
    let prepared = next(&mut model, &base, b"second");
    // Stage exact candidate data and intent while the witnessed pin is old.
    let mut stage = StagingStore {
        inner: store,
        cut: true,
    };
    assert!(matches!(
        advance(&mut stage, &mut witness, &owner(1), &prepared, trust(), 64),
        Err(Error::Local(_))
    ));
    assert_eq!(witness.calls, 0);
    assert_eq!(stage.read_pin().unwrap(), Some(base.clone()));
    drop(stage);
    let mut store = FileStore::open(sandbox.store(), 4).unwrap();
    assert_eq!(
        reconcile(&mut store, &mut witness, &owner(1), trust(), 64)
            .unwrap()
            .accepted()
            .unwrap()
            .checkpoint(),
        prepared.pin().checkpoint()
    );
    assert_eq!(witness.durable, *prepared.pin());
    let mut fork_model = CertifiedLedger::new(RealmId(1), Epoch(7), trust(), 64).unwrap();
    certify(&mut fork_model, b"base");
    let fork = next(&mut fork_model, &base, b"fork");
    assert!(matches!(
        advance(&mut store, &mut witness, &owner(1), &fork, trust(), 64),
        Err(Error::Conflict)
    ));
}

#[test]
fn pending_host_cas_is_serialized_and_never_acknowledged_while_only_visible() {
    let sandbox = Sandbox::new();
    let mut store = FileStore::create_new(sandbox.store(), 3).unwrap();
    let (mut model, base) = provision(&mut store);
    let prepared = next(&mut model, &base, b"second");
    let mut witness = Witness::new(base.clone());
    // Another host request is visible but not durable: even the exact target
    // may not be acknowledged or replaced by a competing host CAS.
    witness.visible = prepared.pin().clone();
    assert!(matches!(
        advance(&mut store, &mut witness, &owner(1), &prepared, trust(), 64),
        Err(Error::Witness(Fault::Conflict))
    ));
    assert_eq!(witness.durable, base);
    assert_eq!(witness.visible, *prepared.pin());
    drop(store);
    witness.durable = witness.visible.clone(); // host finishes pending sync
    let mut store = FileStore::open(sandbox.store(), 3).unwrap();
    assert_eq!(
        reconcile(&mut store, &mut witness, &owner(1), trust(), 64)
            .unwrap()
            .accepted()
            .unwrap()
            .checkpoint(),
        prepared.pin().checkpoint()
    );
    assert_eq!(witness.calls, 1); // no duplicate CAS after host sync
}

#[test]
fn capacity_wrong_policy_and_missing_witness_refuse_without_a_host_cas() {
    let sandbox = Sandbox::new();
    let mut store = FileStore::create_new(sandbox.store(), 1).unwrap();
    let (mut model, base) = provision(&mut store);
    let prepared = next(&mut model, &base, b"second");
    let mut witness = Witness::new(base.clone());
    let changed_policy = TrustConfig::new(
        certificate_realm(RealmId(1)),
        7,
        keys().iter().map(SigningKey::verifying_key),
        1,
        2,
        4096,
    )
    .unwrap();
    assert!(matches!(
        advance(
            &mut store,
            &mut witness,
            &owner(1),
            &prepared,
            changed_policy,
            64
        ),
        Err(Error::Local(_))
    ));
    assert!(matches!(
        advance(&mut store, &mut witness, &owner(1), &prepared, trust(), 64),
        Err(Error::Local(_)) // capacity is fail-closed, no intent or pin mutation
    ));
    assert_eq!(store.read_pin().unwrap(), Some(base.clone()));
    assert!(store.read_intent().unwrap().is_none());
    assert_eq!(witness.durable, base);
    assert_eq!(witness.calls, 0);
    drop(store);
    let mut store = FileStore::open(sandbox.store(), 1).unwrap();
    assert!(matches!(
        reconcile(&mut store, &mut witness, &owner(1), trust(), 64),
        Err(Error::Missing)
    ));
}

struct StagingStore {
    inner: FileStore,
    cut: bool,
}
impl Storage for StagingStore {
    type Error = valhalla_checkpoint_ledger_prototype::file_store::Error;
    fn read_pin(&mut self) -> Result<Option<Pin>, Self::Error> {
        self.inner.read_pin()
    }
    fn read_bundle(
        &mut self,
        id: valhalla_checkpoint_ledger_prototype::persistence::BundleId,
    ) -> Result<Vec<u8>, Self::Error> {
        self.inner.read_bundle(id)
    }
    fn put_bundle(
        &mut self,
        id: valhalla_checkpoint_ledger_prototype::persistence::BundleId,
        raw: &[u8],
    ) -> Result<(), Self::Error> {
        self.inner.put_bundle(id, raw)
    }
    fn compare_exchange_pin(
        &mut self,
        expected: Option<&Pin>,
        next: &Pin,
    ) -> Result<bool, Self::Error> {
        if self.cut {
            self.cut = false;
            return Err(valhalla_checkpoint_ledger_prototype::file_store::Error::Busy);
        }
        self.inner.compare_exchange_pin(expected, next)
    }
}
impl IntentStorage for StagingStore {
    fn read_intent(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        self.inner.read_intent()
    }
    fn put_intent(&mut self, raw: &[u8]) -> Result<(), Self::Error> {
        self.inner.put_intent(raw)
    }
}

#[test]
fn missing_corrupt_rolled_back_data_outage_and_stale_custody_refuse() {
    let sandbox = Sandbox::new();
    let mut store = FileStore::create_new(sandbox.store(), 3).unwrap();
    let (mut model, base) = provision(&mut store);
    let mut witness = Witness::new(base.clone());
    let prepared = next(&mut model, &base, b"second");
    advance(&mut store, &mut witness, &owner(1), &prepared, trust(), 64).unwrap();
    let path = sandbox.store();
    witness.outage = true;
    assert!(matches!(
        reconcile(&mut store, &mut witness, &owner(1), trust(), 64),
        Err(Error::Witness(Fault::Outage))
    ));
    witness.outage = false;
    witness.fence = 2;
    assert!(matches!(
        reconcile(&mut store, &mut witness, &owner(1), trust(), 64),
        Err(Error::Witness(Fault::Revoked))
    ));
    assert!(reconcile(&mut store, &mut witness, &owner(2), trust(), 64).is_ok());
    drop(store);
    // Coordinated rollback of local pin and bundle does not roll back host.
    fs::write(path.join("pin"), base.encode()).unwrap();
    let mut store = FileStore::open(&path, 3).unwrap();
    assert!(matches!(
        reconcile(&mut store, &mut witness, &owner(2), trust(), 64),
        Err(Error::Conflict)
    ));
    drop(store);
    fs::write(path.join("pin"), prepared.pin().encode()).unwrap();
    let mut store = FileStore::open(&path, 3).unwrap();
    let bundle = store.read_bundle(prepared.pin().bundle()).unwrap();
    let intent = store.read_intent().unwrap().unwrap();
    drop(store);
    fs::remove_file(path.join("intent")).unwrap();
    let mut store = FileStore::open(&path, 3).unwrap();
    assert!(matches!(
        reconcile(&mut store, &mut witness, &owner(2), trust(), 64),
        Err(Error::Missing)
    ));
    drop(store);
    fs::write(path.join("intent"), intent).unwrap();
    fs::set_permissions(path.join("intent"), fs::Permissions::from_mode(0o600)).unwrap();
    let mut store = FileStore::open(&path, 3).unwrap();
    let name = format!("{}.bundle", hex(prepared.pin().bundle().0));
    fs::remove_file(path.join(&name)).unwrap();
    assert!(matches!(
        reconcile(&mut store, &mut witness, &owner(2), trust(), 64),
        Err(Error::Local(_))
    ));
    fs::write(path.join(&name), b"corrupt").unwrap();
    fs::set_permissions(path.join(&name), fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        reconcile(&mut store, &mut witness, &owner(2), trust(), 64),
        Err(Error::Local(_))
    ));
    drop(store);
    fs::write(path.join(name), bundle).unwrap();
    fs::set_permissions(path.join("pin"), fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn witnessed_target_does_not_hide_loss_of_earlier_acknowledged_certificate() {
    let sandbox = Sandbox::new();
    let mut store = FileStore::create_new(sandbox.store(), 3).unwrap();
    let (mut model, base) = provision(&mut store);
    let mut witness = Witness::new(base.clone());
    let prepared = next(&mut model, &base, b"second");
    advance(&mut store, &mut witness, &owner(1), &prepared, trust(), 64).unwrap();
    let base_bytes = store.read_bundle(base.bundle()).unwrap();
    let base_path = sandbox
        .store()
        .join(format!("{}.bundle", hex(base.bundle().0)));
    drop(store);
    fs::remove_file(&base_path).unwrap();
    let mut store = FileStore::open(sandbox.store(), 3).unwrap();
    assert!(matches!(
        reconcile(&mut store, &mut witness, &owner(1), trust(), 64),
        Err(Error::Local(_))
    ));
    assert_eq!(witness.durable, *prepared.pin());
    assert_eq!(witness.calls, 1);
    drop(store);
    fs::write(&base_path, base_bytes).unwrap(); // exact external repair fixture
    fs::set_permissions(&base_path, fs::Permissions::from_mode(0o600)).unwrap();
    let mut store = FileStore::open(sandbox.store(), 3).unwrap();
    assert_eq!(
        reconcile(&mut store, &mut witness, &owner(1), trust(), 64)
            .unwrap()
            .snapshot(),
        model.snapshot()
    );
    assert_eq!(witness.calls, 1);
}

fn hex(bytes: [u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
