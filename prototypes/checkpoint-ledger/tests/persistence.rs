use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use ed25519_dalek::SigningKey;
use proptest::prelude::*;
use valhalla_checkpoint_ledger_prototype::persistence::{
    bundle_id, commit, load, load_protected, BundleId, CommitOutcome, Pin, PinWitness,
    PreparedCommit, ProtectedLoadError, ProtocolError, Storage, StoreError, PIN_BYTES,
};
use valhalla_checkpoint_ledger_prototype::{certificate_realm, CertifiedLedger};
use valhalla_checkpoint_proof_prototype::{wire, Approval, CheckpointProof, TrustConfig};
use vhalla_core::{Epoch, PeerId, RealmId, Sequence};
use vhalla_ledger::{Error as LedgerError, Event};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Cut {
    None,
    BeforeWrite,
    ContentsVisible,
    ContentsSynced,
    NameSynced,
    BeforeCas,
    PinVisible,
    PinSynced,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fault {
    Crash,
    Missing,
    Corrupt,
    Unavailable,
}

// Independent crash oracle: successful sync publishes durable state; a crash
// discards visible-only state. Reads can observe unsynced records before crash.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Disk {
    visible: BTreeMap<BundleId, Vec<u8>>,
    durable: BTreeMap<BundleId, Vec<u8>>,
    pin: Option<Pin>,
    durable_pin: Option<Pin>,
    racing_pin: Option<Pin>,
    cut: Option<Cut>,
    unreadable_pin: bool,
    puts: usize,
    cas: usize,
}
impl Disk {
    fn trip(&mut self, cut: Cut) -> Result<(), Fault> {
        if self.cut == Some(cut) {
            self.cut = None;
            Err(Fault::Crash)
        } else {
            Ok(())
        }
    }
    fn crash(&mut self) {
        self.visible = self.durable.clone();
        self.pin = self.durable_pin.clone();
        self.cut = None;
    }
}
impl Storage for Disk {
    type Error = Fault;
    fn read_pin(&mut self) -> Result<Option<Pin>, Fault> {
        if self.unreadable_pin {
            Err(Fault::Corrupt)
        } else {
            Ok(self.pin.clone())
        }
    }
    fn read_bundle(&mut self, id: BundleId) -> Result<Vec<u8>, Fault> {
        self.visible.get(&id).cloned().ok_or(Fault::Missing)
    }
    fn put_bundle(&mut self, id: BundleId, raw: &[u8]) -> Result<(), Fault> {
        self.puts += 1;
        self.trip(Cut::BeforeWrite)?;
        if bundle_id(raw) != id || self.visible.get(&id).is_some_and(|bytes| bytes != raw) {
            return Err(Fault::Corrupt);
        }
        self.visible.insert(id, raw.to_vec());
        self.trip(Cut::ContentsVisible)?;
        // Data may be synced, but without its durable name recovery cannot use it.
        self.trip(Cut::ContentsSynced)?;
        self.durable.insert(id, raw.to_vec());
        self.trip(Cut::NameSynced)
    }
    fn compare_exchange_pin(&mut self, expected: Option<&Pin>, next: &Pin) -> Result<bool, Fault> {
        self.cas += 1;
        if let Some(winner) = self.racing_pin.take() {
            self.pin = Some(winner.clone());
            self.durable_pin = Some(winner);
        }
        if self.pin.as_ref() != expected {
            return Ok(false);
        }
        self.trip(Cut::BeforeCas)?;
        self.pin = Some(next.clone());
        self.trip(Cut::PinVisible)?;
        self.durable_pin = self.pin.clone();
        self.trip(Cut::PinSynced)?;
        Ok(true)
    }
}

// This test double is separate from Disk: a local pin, even if well formed,
// cannot nominate the witness expectation. It models one snapshot from a
// hypothetical monotonic owner witness, not its durability or write protocol.
#[derive(Default)]
struct IndependentWitness {
    latest: Option<Pin>,
    unavailable: bool,
}
impl PinWitness for IndependentWitness {
    type Error = Fault;
    fn capture_pin(&mut self) -> Result<Option<Pin>, Fault> {
        if self.unavailable {
            Err(Fault::Unavailable)
        } else {
            Ok(self.latest.clone())
        }
    }
}

// The bundle-read hook deterministically moves a separate witness or the local
// pin while the old, valid bundle is being read. No thread timing is involved.
#[derive(Clone)]
struct ReadWitness(Rc<RefCell<ReadWitnessState>>);
struct ReadWitnessState {
    latest: Option<Pin>,
    unavailable: bool,
    reads: usize,
}
impl ReadWitness {
    fn new(pin: Pin) -> Self {
        Self(Rc::new(RefCell::new(ReadWitnessState {
            latest: Some(pin),
            unavailable: false,
            reads: 0,
        })))
    }
}
impl PinWitness for ReadWitness {
    type Error = Fault;
    fn capture_pin(&mut self) -> Result<Option<Pin>, Fault> {
        let mut state = self.0.borrow_mut();
        state.reads += 1;
        if state.unavailable {
            Err(Fault::Unavailable)
        } else {
            Ok(state.latest.clone())
        }
    }
}

enum ReadChange {
    None,
    Witness(Option<Pin>),
    WitnessOutage,
    Local(Option<Pin>),
    LocalOutage,
}
struct ReadRaceDisk {
    disk: Disk,
    witness: ReadWitness,
    change: ReadChange,
    pin_reads: usize,
    bundle_reads: usize,
}
impl Storage for ReadRaceDisk {
    type Error = Fault;
    fn read_pin(&mut self) -> Result<Option<Pin>, Fault> {
        self.pin_reads += 1;
        self.disk.read_pin()
    }
    fn read_bundle(&mut self, id: BundleId) -> Result<Vec<u8>, Fault> {
        self.bundle_reads += 1;
        let raw = self.disk.read_bundle(id)?;
        match std::mem::replace(&mut self.change, ReadChange::None) {
            ReadChange::None => {}
            ReadChange::Witness(pin) => self.witness.0.borrow_mut().latest = pin,
            ReadChange::WitnessOutage => self.witness.0.borrow_mut().unavailable = true,
            ReadChange::Local(pin) => self.disk.pin = pin,
            ReadChange::LocalOutage => self.disk.unreadable_pin = true,
        }
        Ok(raw)
    }
    fn put_bundle(&mut self, _id: BundleId, _raw: &[u8]) -> Result<(), Fault> {
        panic!("protected load must not write a bundle")
    }
    fn compare_exchange_pin(
        &mut self,
        _expected: Option<&Pin>,
        _next: &Pin,
    ) -> Result<bool, Fault> {
        panic!("protected load must not write a pin")
    }
}

fn keys() -> [SigningKey; 2] {
    [1, 2].map(|n| SigningKey::from_bytes(&[n; 32]))
}
fn trust_threshold(threshold: usize) -> TrustConfig {
    TrustConfig::new(
        certificate_realm(RealmId(1)),
        7,
        keys().iter().map(SigningKey::verifying_key),
        threshold,
        2,
        4096,
    )
    .unwrap()
}
fn trust() -> TrustConfig {
    trust_threshold(2)
}
fn new_model() -> CertifiedLedger {
    CertifiedLedger::new(RealmId(1), Epoch(7), trust(), 64).unwrap()
}
fn append(model: &mut CertifiedLedger, payload: &[u8]) {
    model
        .append(Event::new(
            model.head(),
            RealmId(1),
            Epoch(7),
            PeerId(2),
            Sequence(model.event_count() as u64 + 1),
            payload.to_vec(),
        ))
        .unwrap();
}
fn certify(model: &mut CertifiedLedger) -> Vec<u8> {
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
fn base() -> (Disk, CertifiedLedger, Pin) {
    let mut model = new_model();
    append(&mut model, b"first");
    let cert = certify(&mut model);
    let prepared = PreparedCommit::prepare(&model, &cert, None).unwrap();
    let mut disk = Disk::default();
    assert_eq!(commit(&mut disk, &prepared), Ok(CommitOutcome::Committed));
    (disk, model, prepared.pin().clone())
}
fn loaded_count(disk: &mut Disk) -> Option<usize> {
    load(disk, trust(), 64)
        .unwrap()
        .map(|model| model.event_count())
}

#[test]
fn every_crash_boundary_recovers_old_or_new_without_a_partial_frontier() {
    for cut in [
        Cut::BeforeWrite,
        Cut::ContentsVisible,
        Cut::ContentsSynced,
        Cut::NameSynced,
        Cut::BeforeCas,
        Cut::PinVisible,
        Cut::PinSynced,
    ] {
        let (mut disk, mut model, pin) = base();
        append(&mut model, b"second");
        let cert = certify(&mut model);
        let prepared = PreparedCommit::prepare(&model, &cert, Some(&pin)).unwrap();
        disk.cut = Some(cut);
        let result = commit(&mut disk, &prepared);
        assert!(result.is_err());
        if matches!(cut, Cut::BeforeCas | Cut::PinVisible | Cut::PinSynced) {
            assert_eq!(result, Err(StoreError::Indeterminate(Fault::Crash)));
        }
        disk.crash();
        assert_eq!(
            loaded_count(&mut disk),
            Some(if cut == Cut::PinSynced { 2 } else { 1 })
        );
        assert!(commit(&mut disk, &prepared).is_ok());
        disk.crash();
        assert_eq!(loaded_count(&mut disk), Some(2));
    }
}

#[test]
fn bootstrap_crashes_are_absence_until_pin_commit_and_errors_are_not_absence() {
    for cut in [
        Cut::ContentsVisible,
        Cut::ContentsSynced,
        Cut::NameSynced,
        Cut::PinVisible,
        Cut::PinSynced,
    ] {
        let mut disk = Disk::default();
        let mut model = new_model();
        append(&mut model, b"first");
        let cert = certify(&mut model);
        let prepared = PreparedCommit::prepare(&model, &cert, None).unwrap();
        disk.cut = Some(cut);
        assert!(commit(&mut disk, &prepared).is_err());
        disk.crash();
        assert_eq!(
            loaded_count(&mut disk),
            if cut == Cut::PinSynced { Some(1) } else { None }
        );
        disk.unreadable_pin = true;
        assert!(matches!(
            load(&mut disk, trust(), 64),
            Err(StoreError::Backend(Fault::Corrupt))
        ));
        assert_eq!(
            commit(&mut disk, &prepared),
            Err(StoreError::Backend(Fault::Corrupt))
        );
    }
}

#[test]
fn visible_pin_retry_reestablishes_durability_before_acknowledging() {
    let (mut disk, mut model, pin) = base();
    append(&mut model, b"second");
    let cert = certify(&mut model);
    let prepared = PreparedCommit::prepare(&model, &cert, Some(&pin)).unwrap();
    disk.cut = Some(Cut::PinVisible);
    assert_eq!(
        commit(&mut disk, &prepared),
        Err(StoreError::Indeterminate(Fault::Crash))
    );
    assert_eq!(disk.pin.as_ref(), Some(prepared.pin()));
    assert_eq!(disk.durable_pin.as_ref(), Some(&pin));
    let prior_cas = disk.cas;
    let prior_puts = disk.puts;
    assert_eq!(
        commit(&mut disk, &prepared),
        Ok(CommitOutcome::AlreadyCommitted)
    );
    assert_eq!(disk.cas, prior_cas + 1);
    assert_eq!(disk.puts, prior_puts + 1);
    disk.crash();
    assert_eq!(loaded_count(&mut disk), Some(2));
    assert_eq!(
        commit(&mut disk, &prepared),
        Ok(CommitOutcome::AlreadyCommitted)
    );
}

#[test]
fn stale_prepared_writer_requires_reprepare_and_higher_signed_fork_is_rejected() {
    let (mut disk, mut model, old_pin) = base();
    append(&mut model, b"second");
    let second_cert = certify(&mut model);
    let second = PreparedCommit::prepare(&model, &second_cert, Some(&old_pin)).unwrap();
    append(&mut model, b"third");
    let third_cert = certify(&mut model);
    let stale_third = PreparedCommit::prepare(&model, &third_cert, Some(&old_pin)).unwrap();
    assert_eq!(commit(&mut disk, &second), Ok(CommitOutcome::Committed));
    let writes = disk.puts;
    assert_eq!(commit(&mut disk, &stale_third), Err(StoreError::Conflict));
    assert_eq!(disk.puts, writes);
    let third = PreparedCommit::prepare(&model, &third_cert, Some(second.pin())).unwrap();
    assert_eq!(commit(&mut disk, &third), Ok(CommitOutcome::Committed));
    assert_eq!(third.pin().generation(), 3);
    assert_eq!(commit(&mut disk, &second), Err(StoreError::Conflict));

    let mut fork = new_model();
    append(&mut fork, b"different genesis");
    append(&mut fork, b"fork2");
    append(&mut fork, b"fork3");
    let cert = certify(&mut fork);
    assert!(matches!(
        PreparedCommit::prepare(&fork, &cert, Some(&old_pin)),
        Err(ProtocolError::History(
            valhalla_checkpoint_ledger_prototype::Error::Ledger(LedgerError::UnknownHead)
        ))
    ));
}

#[test]
fn a_writer_racing_between_preflight_and_cas_wins_without_partial_admission() {
    let (mut disk, mut model, pin) = base();
    append(&mut model, b"second");
    let cert = certify(&mut model);
    let losing = PreparedCommit::prepare(&model, &cert, Some(&pin)).unwrap();
    append(&mut model, b"third");
    let cert = certify(&mut model);
    let winning = PreparedCommit::prepare(&model, &cert, Some(&pin)).unwrap();
    let mut other_writer = disk.clone();
    commit(&mut other_writer, &winning).unwrap();
    // The other writer's immutable bytes are durable, but its pin update becomes
    // visible to this writer only after preflight and put, inside the actual CAS.
    disk.visible = other_writer.visible;
    disk.durable = other_writer.durable;
    disk.racing_pin = Some(winning.pin().clone());
    let writes = disk.puts;
    assert_eq!(commit(&mut disk, &losing), Err(StoreError::Conflict));
    assert_eq!(disk.puts, writes + 1);
    assert!(disk.durable.contains_key(&losing.pin().bundle()));
    assert_eq!(disk.pin.as_ref(), Some(winning.pin()));
    disk.crash();
    assert_eq!(loaded_count(&mut disk), Some(3));
}

#[test]
fn missing_or_corrupt_current_bundle_never_falls_back_and_pin_rollback_is_outside_model() {
    let (mut disk, mut model, old_pin) = base();
    let old_disk = disk.clone();
    append(&mut model, b"second");
    let cert = certify(&mut model);
    let prepared = PreparedCommit::prepare(&model, &cert, Some(&old_pin)).unwrap();
    commit(&mut disk, &prepared).unwrap();
    let good = disk.clone();
    disk.visible.remove(&prepared.pin().bundle());
    assert!(matches!(
        load(&mut disk, trust(), 64),
        Err(StoreError::Backend(Fault::Missing))
    ));
    disk = good;
    disk.visible.get_mut(&prepared.pin().bundle()).unwrap()[0] ^= 1;
    assert!(matches!(
        load(&mut disk, trust(), 64),
        Err(StoreError::Invalid(ProtocolError::BundleMismatch))
    ));
    let mut rolled_back = old_disk;
    assert_eq!(loaded_count(&mut rolled_back), Some(1));
}

#[test]
fn protected_pin_refuses_stale_missing_and_coordinated_store_rollback() {
    fn refuses(
        disk: &mut Disk,
        witness: &mut IndependentWitness,
        policy: TrustConfig,
        reason: ProtectedLoadError<Fault, Fault>,
    ) {
        let before = disk.clone();
        assert_eq!(
            load_protected(disk, witness, policy, 64).err(),
            Some(reason)
        );
        // Refusal never repairs, re-pins, publishes an orphan, or changes the
        // certified in-memory model: no model exists on this error path.
        assert_eq!(*disk, before);
    }

    let (mut disk, mut model, old_pin) = base();
    let old_disk = disk.clone();
    append(&mut model, b"second");
    let cert = certify(&mut model);
    let prepared = PreparedCommit::prepare(&model, &cert, Some(&old_pin)).unwrap();
    commit(&mut disk, &prepared).unwrap();
    let good = disk.clone();
    let new_pin = prepared.pin().clone();
    let mut witness = IndependentWitness {
        latest: Some(new_pin.clone()),
        ..Default::default()
    };
    let original_snapshot = model.snapshot();
    let recovered = load_protected(&mut disk, &mut witness, trust(), 64).unwrap();
    assert_eq!(recovered.snapshot(), original_snapshot);
    assert_eq!(
        recovered.accepted().unwrap().checkpoint(),
        new_pin.checkpoint()
    );
    assert_eq!(disk, good);

    // A valid, current local pin is not a fallback when the witness disappears.
    witness.unavailable = true;
    refuses(
        &mut disk,
        &mut witness,
        trust(),
        ProtectedLoadError::Witness(Fault::Unavailable),
    );
    witness.unavailable = false;
    witness.latest = None;
    refuses(
        &mut disk,
        &mut witness,
        trust(),
        ProtectedLoadError::MissingWitness,
    );
    witness.latest = Some(new_pin.clone());

    // The old local pin is still valid plain data, but no longer the witness's
    // full pin, even if its old bundle still exists.
    disk.pin = Some(old_pin.clone());
    disk.durable_pin = Some(old_pin);
    refuses(
        &mut disk,
        &mut witness,
        trust(),
        ProtectedLoadError::PinMismatch,
    );
    disk = good.clone();
    disk.pin = None;
    disk.durable_pin = None;
    refuses(
        &mut disk,
        &mut witness,
        trust(),
        ProtectedLoadError::MissingLocalPin,
    );
    // Replacing the *entire* local store with a previously valid old store
    // still cannot roll back the independent expectation.
    disk = old_disk;
    assert_eq!(
        load(&mut disk, trust(), 64).unwrap().unwrap().event_count(),
        1
    );
    refuses(
        &mut disk,
        &mut witness,
        trust(),
        ProtectedLoadError::PinMismatch,
    );

    // Every field of the canonical full pin must match, not just its height or
    // bundle address. Decode is structural and does not authenticate a forgery.
    let generation = b"vhalla/checkpoint-store/pin/v1".len() + 2;
    for offset in [
        generation,
        generation + 8,
        generation + 40,
        generation + 56,
        generation + 64,
        generation + 96,
        generation + 128,
        generation + 160,
    ] {
        disk = good.clone();
        let mut bytes = new_pin.encode();
        bytes[offset] ^= 1;
        let forged = Pin::decode(&bytes).unwrap();
        assert_ne!(forged, new_pin);
        disk.pin = Some(forged.clone());
        disk.durable_pin = Some(forged);
        refuses(
            &mut disk,
            &mut witness,
            trust(),
            ProtectedLoadError::PinMismatch,
        );
    }

    disk = good.clone();
    disk.visible.get_mut(&new_pin.bundle()).unwrap()[0] ^= 1;
    refuses(
        &mut disk,
        &mut witness,
        trust(),
        ProtectedLoadError::Local(StoreError::Invalid(ProtocolError::BundleMismatch)),
    );
    disk = good.clone();
    disk.visible.remove(&new_pin.bundle());
    refuses(
        &mut disk,
        &mut witness,
        trust(),
        ProtectedLoadError::Local(StoreError::Backend(Fault::Missing)),
    );
    disk = good.clone();
    refuses(
        &mut disk,
        &mut witness,
        trust_threshold(1),
        ProtectedLoadError::Local(StoreError::Invalid(ProtocolError::WrongPredecessor)),
    );

    disk.unreadable_pin = true;
    refuses(
        &mut disk,
        &mut witness,
        trust(),
        ProtectedLoadError::Local(StoreError::Backend(Fault::Corrupt)),
    );
    // Even when local bytes are unreadable, the witness failure takes priority.
    witness.unavailable = true;
    refuses(
        &mut disk,
        &mut witness,
        trust(),
        ProtectedLoadError::Witness(Fault::Unavailable),
    );
    witness.unavailable = false;
    witness.latest = None;
    refuses(
        &mut disk,
        &mut witness,
        trust(),
        ProtectedLoadError::MissingWitness,
    );
    assert_eq!(model.snapshot(), original_snapshot);
}

#[test]
fn protected_load_refuses_mid_read_advance() {
    let (good, mut model, pin) = base();
    let old_snapshot = model.snapshot();
    append(&mut model, b"second");
    let cert = certify(&mut model);
    let next = PreparedCommit::prepare(&model, &cert, Some(&pin))
        .unwrap()
        .pin()
        .clone();
    let advanced_snapshot = model.snapshot();

    for (change, reason, local_reads) in [
        (
            ReadChange::Witness(Some(next.clone())),
            ProtectedLoadError::PinChanged,
            1,
        ),
        (
            ReadChange::Local(Some(next.clone())),
            ProtectedLoadError::PinChanged,
            2,
        ),
        (
            ReadChange::Witness(None),
            ProtectedLoadError::MissingWitness,
            1,
        ),
        (
            ReadChange::WitnessOutage,
            ProtectedLoadError::Witness(Fault::Unavailable),
            1,
        ),
        (
            ReadChange::Local(None),
            ProtectedLoadError::MissingLocalPin,
            2,
        ),
        (
            ReadChange::LocalOutage,
            ProtectedLoadError::Local(StoreError::Backend(Fault::Corrupt)),
            2,
        ),
    ] {
        let mut witness = ReadWitness::new(pin.clone());
        let mut raced = ReadRaceDisk {
            disk: good.clone(),
            witness: witness.clone(),
            change,
            pin_reads: 0,
            bundle_reads: 0,
        };
        assert_eq!(
            load_protected(&mut raced, &mut witness, trust(), 64).err(),
            Some(reason)
        );
        assert_eq!(witness.0.borrow().reads, 2);
        assert_eq!(raced.pin_reads, local_reads);
        assert_eq!(raced.bundle_reads, 1);
        // Only the injected read-side change occurs; neither recovery nor
        // refusal writes, repairs or scans for an older certified bundle.
        assert_eq!(raced.disk.visible, good.visible);
        assert_eq!(raced.disk.durable, good.durable);
        assert_eq!(raced.disk.durable_pin, good.durable_pin);
        assert_eq!((raced.disk.puts, raced.disk.cas), (good.puts, good.cas));
        assert_eq!(model.snapshot(), advanced_snapshot);
    }

    let mut witness = ReadWitness::new(pin.clone());
    let mut stable = ReadRaceDisk {
        disk: good.clone(),
        witness: witness.clone(),
        change: ReadChange::None,
        pin_reads: 0,
        bundle_reads: 0,
    };
    let recovered = load_protected(&mut stable, &mut witness, trust(), 64).unwrap();
    assert_eq!(recovered.snapshot(), old_snapshot);
    assert_eq!(recovered.accepted().unwrap().checkpoint(), pin.checkpoint());
    assert_eq!(
        (
            witness.0.borrow().reads,
            stable.pin_reads,
            stable.bundle_reads
        ),
        (2, 2, 1)
    );
    assert_eq!(stable.disk, good);

    let mut corrupt = good.clone();
    corrupt.visible.get_mut(&pin.bundle()).unwrap()[0] ^= 1;
    let before = corrupt.clone();
    let mut witness = ReadWitness::new(pin);
    let mut invalid = ReadRaceDisk {
        disk: corrupt,
        witness: witness.clone(),
        change: ReadChange::None,
        pin_reads: 0,
        bundle_reads: 0,
    };
    assert_eq!(
        load_protected(&mut invalid, &mut witness, trust(), 64).err(),
        Some(ProtectedLoadError::Local(StoreError::Invalid(
            ProtocolError::BundleMismatch
        )))
    );
    assert_eq!(
        (
            witness.0.borrow().reads,
            invalid.pin_reads,
            invalid.bundle_reads
        ),
        (1, 1, 1)
    );
    assert_eq!(invalid.disk, before);
}

#[test]
fn preparation_rejects_bad_history_uncheckpointed_suffix_rotation_and_overflow() {
    let (_, mut model, pin) = base();
    let cert = certify(&mut model);
    assert!(matches!(
        PreparedCommit::prepare(&model, &cert, Some(&pin)),
        Err(ProtocolError::NonAdvancing)
    ));
    append(&mut model, b"uncertified");
    assert!(matches!(
        PreparedCommit::prepare(&model, &cert, Some(&pin)),
        Err(ProtocolError::History(_))
    ));
    let cert = certify(&mut model);
    let mut raw = pin.encode();
    let generation = b"vhalla/checkpoint-store/pin/v1".len() + 2;
    raw[generation..generation + 8].copy_from_slice(&u64::MAX.to_be_bytes());
    let exhausted = Pin::decode(&raw).unwrap();
    assert!(matches!(
        PreparedCommit::prepare(&model, &cert, Some(&exhausted)),
        Err(ProtocolError::GenerationOverflow)
    ));

    let mut rotated = CertifiedLedger::new(RealmId(1), Epoch(7), trust_threshold(1), 64).unwrap();
    append(&mut rotated, b"first");
    append(&mut rotated, b"second");
    let rotated_cert = certify(&mut rotated);
    assert!(matches!(
        PreparedCommit::prepare(&rotated, &rotated_cert, Some(&pin)),
        Err(ProtocolError::WrongPredecessor)
    ));
}

#[test]
fn pin_structure_is_exact_but_decode_is_not_authentication() {
    let (_, _, pin) = base();
    let raw = pin.encode();
    assert_eq!(raw.len(), PIN_BYTES);
    assert_eq!(Pin::decode(&raw), Ok(pin));
    for end in 0..raw.len() {
        assert!(Pin::decode(&raw[..end]).is_err());
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(Pin::decode(&trailing).is_err());
    let mut forged = raw;
    // Ordinary data fields remain parseable when changed: only checked recovery
    // against an owner-selected local store gives this record meaning.
    *forged.last_mut().unwrap() ^= 1;
    assert!(Pin::decode(&forged).is_ok());
}

#[cfg(all(feature = "native-store", unix))]
#[test]
fn certified_history_survives_native_store_close_reopen_and_advancement() {
    use valhalla_checkpoint_ledger_prototype::file_store::FileStore;
    let path = std::env::temp_dir().join(format!("vhalla-certified-reopen-{}", std::process::id()));
    // create_new refuses reuse; this test removes only its newly created store.
    let mut store = FileStore::create_new(&path, 3).unwrap();
    let mut model = new_model();
    append(&mut model, b"first");
    let cert = certify(&mut model);
    let first = PreparedCommit::prepare(&model, &cert, None).unwrap();
    commit(&mut store, &first).unwrap();
    drop(store);
    drop(model);

    let mut store = FileStore::open(&path, 3).unwrap();
    let mut recovered = load(&mut store, trust(), 64).unwrap().unwrap();
    assert_eq!(recovered.event_count(), 1);
    let previous = store.read_pin().unwrap().unwrap();
    append(&mut recovered, b"second");
    let cert = certify(&mut recovered);
    let second = PreparedCommit::prepare(&recovered, &cert, Some(&previous)).unwrap();
    commit(&mut store, &second).unwrap();
    drop(store);
    drop(recovered);

    let mut store = FileStore::open(&path, 3).unwrap();
    let recovered = load(&mut store, trust(), 64).unwrap().unwrap();
    assert_eq!(recovered.event_count(), 2);
    assert_eq!(
        recovered.accepted().unwrap().checkpoint(),
        second.pin().checkpoint()
    );
    assert_eq!(
        commit(&mut store, &second).unwrap(),
        CommitOutcome::AlreadyCommitted
    );
    drop(store);
    std::fs::remove_dir_all(path).unwrap();
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn generated_crash_retry_schedules_preserve_acknowledged_frontiers(
        actions in prop::collection::vec((0usize..8, any::<bool>(), any::<u16>()), 1..12)
    ) {
        let mut disk = Disk::default(); let mut model = new_model();
        let mut predecessor = None;
        let cuts = [Cut::None, Cut::BeforeWrite, Cut::ContentsVisible, Cut::ContentsSynced,
            Cut::NameSynced, Cut::BeforeCas, Cut::PinVisible, Cut::PinSynced];
        for (index, (cut_index, retry_before_crash, payload)) in actions.iter().enumerate() {
            append(&mut model, &payload.to_be_bytes()); let cert = certify(&mut model);
            let prepared = PreparedCommit::prepare(&model, &cert, predecessor.as_ref()).unwrap();
            disk.cut = Some(cuts[*cut_index]);
            let first = commit(&mut disk, &prepared);
            if *retry_before_crash { prop_assert!(commit(&mut disk, &prepared).is_ok()); }
            disk.crash();
            let expected_new = first.is_ok() || *retry_before_crash || cuts[*cut_index] == Cut::PinSynced;
            let expected = if expected_new { Some(index+1) } else if index == 0 { None } else { Some(index) };
            prop_assert_eq!(loaded_count(&mut disk), expected);
            prop_assert!(commit(&mut disk, &prepared).is_ok()); disk.crash();
            prop_assert_eq!(loaded_count(&mut disk), Some(index+1));
            predecessor = Some(prepared.pin().clone());
        }
    }
    #[test]
    fn bounded_arbitrary_pin_input_never_panics_or_normalizes(raw in prop::collection::vec(any::<u8>(), 0..512)) {
        if let Ok(pin) = Pin::decode(&raw) { prop_assert_eq!(pin.encode(), raw); }
    }
}
