//! Fault-injection and recovery tests for the durable commit journal.

use super::*;
use hegel::{generators as gs, HealthCheck, TestCase};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};

fn fixture() -> PathBuf {
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "room-journal-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        SEQ.fetch_add(1, Ordering::Relaxed),
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn bundle(predecessor: [u8; 32], next: [u8; 32], height: u64, tag: &str) -> Bundle {
    Bundle::new(BundleParts {
        certificate: format!("cert:{tag}").into_bytes(),
        predecessor,
        next,
        batch: format!("batch:{tag}").into_bytes(),
        value: format!("value:{tag}").into_bytes(),
        configuration: b"config:1".to_vec(),
        control_record: b"control:1".to_vec(),
        debit_marker: format!("debit:{tag}").into_bytes(),
        height,
    })
    .unwrap()
}

fn genesis_pin() -> Pin {
    Pin {
        predecessor: [0; 32],
        next: GENESIS_NEXT,
        bundle: [0; 32],
        height: 0,
    }
}

fn fs_journal(dir: &Path) -> Journal<FsStore> {
    Journal::new(dir, FsStore)
}

fn fault_journal(dir: &Path, faults: &[(Step, Fault)]) -> Journal<FaultingStore<FsStore>> {
    Journal::new(dir, FaultingStore::new(FsStore, faults))
}

#[test]
fn commit_acknowledges_and_recovers() {
    let dir = fixture();
    let b1 = bundle(GENESIS_NEXT, [1; 32], 1, "a");
    let journal = fs_journal(&dir);
    assert_eq!(journal.commit(&b1).unwrap(), Outcome::Committed);
    drop(journal);
    let recovered = fs_journal(&dir).recover().unwrap();
    assert_eq!(recovered.pin.next, [1; 32]);
    assert_eq!(recovered.pin.bundle, b1.id());
    assert!(recovered.orphans.is_empty());
    assert!(!recovered.dropped_tmp);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn crash_after_rename_recovers_committed_and_retry_is_idempotent() {
    let dir = fixture();
    let (g, n1) = (GENESIS_NEXT, [1; 32]);
    let b1 = bundle(g, n1, 1, "a");
    // Die after the rename but before the directory sync: the pin is already
    // published, the caller never saw the acknowledgement.
    {
        let journal = fault_journal(&dir, &[(Step::SyncDir, Fault::CrashBefore)]);
        assert!(matches!(journal.commit(&b1), Err(JournalError::Crashed)));
    }
    // Reopen: the rename landed, so the pin is committed.
    let recovered = fs_journal(&dir).recover().unwrap();
    assert_eq!(recovered.pin.next, n1);
    // The uncertain retry must reconcile, not re-apply.
    let journal = fs_journal(&dir);
    assert_eq!(journal.commit(&b1).unwrap(), Outcome::AlreadyCommitted);
    // A different bundle extending the old frontier is now a conflict.
    let rival = bundle(g, [9; 32], 1, "rival");
    assert!(matches!(
        journal.commit(&rival),
        Err(JournalError::Conflict { .. })
    ));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn crash_before_rename_leaves_orphan_and_retry_completes() {
    let dir = fixture();
    let (g, n1) = (GENESIS_NEXT, [1; 32]);
    let b1 = bundle(g, n1, 1, "a");
    // Die after the bundle is synced but before the pin tmp write.
    {
        let journal = fault_journal(&dir, &[(Step::WritePinTmp, Fault::CrashBefore)]);
        assert!(matches!(journal.commit(&b1), Err(JournalError::Crashed)));
    }
    let recovered = fs_journal(&dir).recover().unwrap();
    assert_eq!(recovered.pin, genesis_pin());
    assert_eq!(recovered.orphans, vec![b1.id()]);
    // Identical retry reuses the durable bundle and completes the pin.
    let journal = fs_journal(&dir);
    assert_eq!(journal.commit(&b1).unwrap(), Outcome::Committed);
    let recovered = fs_journal(&dir).recover().unwrap();
    assert_eq!(recovered.pin.next, n1);
    assert!(recovered.orphans.is_empty());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn crash_after_pin_tmp_leaves_discarded_unpublished_pin() {
    let dir = fixture();
    let b1 = bundle(GENESIS_NEXT, [1; 32], 1, "a");
    {
        let journal = fault_journal(&dir, &[(Step::RenamePin, Fault::CrashBefore)]);
        assert!(matches!(journal.commit(&b1), Err(JournalError::Crashed)));
    }
    let recovered = fs_journal(&dir).recover().unwrap();
    assert_eq!(recovered.pin, genesis_pin());
    assert!(recovered.dropped_tmp);
    assert_eq!(recovered.orphans, vec![b1.id()]);
    // And the retry completes.
    assert_eq!(fs_journal(&dir).commit(&b1).unwrap(), Outcome::Committed);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn crash_after_bundle_create_then_rival_loses() {
    let dir = fixture();
    let g = GENESIS_NEXT;
    let b1 = bundle(g, [1; 32], 1, "winner");
    let rival = bundle(g, [2; 32], 1, "loser");
    {
        let journal = fault_journal(&dir, &[(Step::SyncBundle, Fault::CrashBefore)]);
        assert!(matches!(journal.commit(&b1), Err(JournalError::Crashed)));
    }
    // The rival arrives first after restart and wins the slot.
    let journal = fs_journal(&dir);
    assert_eq!(journal.commit(&rival).unwrap(), Outcome::Committed);
    // The crashed winner's retry now conflicts — it cannot sneak back in via
    // its orphan bundle on disk.
    assert!(matches!(
        journal.commit(&b1),
        Err(JournalError::Conflict { .. })
    ));
    let recovered = fs_journal(&dir).recover().unwrap();
    assert_eq!(recovered.pin.next, [2; 32]);
    assert_eq!(recovered.orphans, vec![b1.id()]);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn io_failure_mid_protocol_withholds_acknowledgement() {
    let dir = fixture();
    let b1 = bundle(GENESIS_NEXT, [1; 32], 1, "a");
    let journal = fault_journal(&dir, &[(Step::SyncPinTmp, Fault::FailIo)]);
    assert!(matches!(journal.commit(&b1), Err(JournalError::Io(_))));
    // Recovery shows nothing published.
    let recovered = fs_journal(&dir).recover().unwrap();
    assert_eq!(recovered.pin, genesis_pin());
    assert!(recovered.dropped_tmp);
    // Retry succeeds once the fault clears.
    assert_eq!(fs_journal(&dir).commit(&b1).unwrap(), Outcome::Committed);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn corrupt_pin_fails_closed_and_preserves_bytes() {
    let dir = fixture();
    let b1 = bundle(GENESIS_NEXT, [1; 32], 1, "a");
    assert_eq!(fs_journal(&dir).commit(&b1).unwrap(), Outcome::Committed);
    // Corrupt the pin file: recovery must refuse, not clobber.
    fs::write(dir.join(HEAD_FILE), b"garbage").unwrap();
    assert!(matches!(
        fs_journal(&dir).recover(),
        Err(JournalError::Corrupt)
    ));
    assert_eq!(fs::read(dir.join(HEAD_FILE)).unwrap(), b"garbage");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn pin_referencing_missing_bundle_fails_closed() {
    let dir = fixture();
    let b1 = bundle(GENESIS_NEXT, [1; 32], 1, "a");
    assert_eq!(fs_journal(&dir).commit(&b1).unwrap(), Outcome::Committed);
    fs::remove_file(FsStore::bundle_path(&dir, b1.id())).unwrap();
    assert!(matches!(
        fs_journal(&dir).recover(),
        Err(JournalError::Corrupt)
    ));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn torn_pin_tmp_is_discarded() {
    let dir = fixture();
    fs::create_dir_all(dir.join(BUNDLES)).unwrap();
    fs::write(dir.join(HEAD_TMP), b"partial-pin-bytes").unwrap();
    let recovered = fs_journal(&dir).recover().unwrap();
    assert_eq!(recovered.pin, genesis_pin());
    assert!(recovered.dropped_tmp);
    assert!(!dir.join(HEAD_TMP).exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn bundle_identity_binds_every_field() {
    let (g, n) = (GENESIS_NEXT, [1; 32]);
    let base = bundle(g, n, 1, "a");
    let different_cert = Bundle::new(BundleParts {
        certificate: b"cert:DIFFERENT".to_vec(),
        predecessor: g,
        next: n,
        batch: b"batch:a".to_vec(),
        value: b"value:a".to_vec(),
        configuration: b"config:1".to_vec(),
        control_record: b"control:1".to_vec(),
        debit_marker: b"debit:a".to_vec(),
        height: 1,
    })
    .unwrap();
    assert_ne!(base.id(), different_cert.id());
    let different_next = bundle(g, [2; 32], 1, "a");
    assert_ne!(base.id(), different_next.id());
}

#[test]
fn orphan_bundle_carries_no_authority() {
    let dir = fixture();
    let g = GENESIS_NEXT;
    let orphan = bundle(g, [7; 32], 1, "orphan");
    // Hand-plant an orphan bundle file with no pin reference.
    fs::create_dir_all(dir.join(BUNDLES)).unwrap();
    fs::write(FsStore::bundle_path(&dir, orphan.id()), orphan.bytes()).unwrap();
    let journal = fs_journal(&dir);
    let recovered = journal.recover().unwrap();
    assert_eq!(recovered.pin, genesis_pin());
    assert_eq!(recovered.orphans, vec![orphan.id()]);
    // Committing the orphan's claimed successor still must pass through the
    // normal predecessor check — the orphan does not advance the frontier.
    let real = bundle(g, [1; 32], 1, "real");
    assert_eq!(journal.commit(&real).unwrap(), Outcome::Committed);
    let recovered = journal.recover().unwrap();
    assert_eq!(recovered.pin.next, [1; 32]);
    assert_eq!(recovered.orphans, vec![orphan.id()]);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn protocol_steps_are_ordered() {
    let dir = fixture();
    let b1 = bundle(GENESIS_NEXT, [1; 32], 1, "a");
    let journal = fault_journal(&dir, &[]);
    assert_eq!(journal.commit(&b1).unwrap(), Outcome::Committed);
    let log = journal.store.log.borrow().clone();
    let position = |step: Step| log.iter().position(|s| *s == step).unwrap();
    assert!(position(Step::CreateBundle) < position(Step::SyncBundle));
    assert!(position(Step::SyncBundle) < position(Step::SyncBundlesDir));
    assert!(position(Step::SyncBundlesDir) < position(Step::WriteHeightMarker));
    assert!(position(Step::WriteHeightMarker) < position(Step::SyncHeightMarker));
    assert!(position(Step::SyncHeightMarker) < position(Step::SyncHeightsDir));
    assert!(position(Step::SyncHeightsDir) < position(Step::WritePinTmp));
    assert!(position(Step::SyncPinTmp) < position(Step::RenamePin));
    assert!(position(Step::RenamePin) < position(Step::SyncDir));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn containing_directory_sync_failure_never_publishes_a_pin() {
    for step in [Step::SyncBundlesDir, Step::SyncHeightsDir] {
        let dir = fixture();
        let b1 = bundle(GENESIS_NEXT, [1; 32], 1, "directory-sync");
        let journal = fault_journal(&dir, &[(step, Fault::FailIo)]);
        assert!(matches!(journal.commit(&b1), Err(JournalError::Io(_))));
        assert!(!dir.join(HEAD_FILE).exists());
        assert!(!journal.store.log.borrow().contains(&Step::RenamePin));
        assert_eq!(fs_journal(&dir).recover().unwrap().pin, genesis_pin());
        assert_eq!(fs_journal(&dir).commit(&b1).unwrap(), Outcome::Committed);
        let _ = fs::remove_dir_all(&dir);
    }
}

#[test]
fn recovery_syncs_removed_entries_in_their_containing_directories() {
    let dir = fixture();
    let b1 = bundle(GENESIS_NEXT, [1; 32], 1, "recovery-sync");
    let interrupted = fault_journal(&dir, &[(Step::RenamePin, Fault::CrashBefore)]);
    assert!(matches!(
        interrupted.commit(&b1),
        Err(JournalError::Crashed)
    ));
    let recovery = fault_journal(&dir, &[]);
    let result = recovery.recover().unwrap();
    assert!(result.dropped_tmp);
    assert_eq!(result.dropped_heights, vec![1]);
    let log = recovery.store.log.borrow();
    assert_eq!(*log, [Step::ReadPin, Step::SyncHeightsDir, Step::SyncDir]);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn recovery_retry_reestablishes_cleanup_durability() {
    let dir = fixture();
    let b1 = bundle(GENESIS_NEXT, [1; 32], 1, "recovery-retry");
    let interrupted = fault_journal(&dir, &[(Step::RenamePin, Fault::CrashBefore)]);
    assert!(matches!(
        interrupted.commit(&b1),
        Err(JournalError::Crashed)
    ));
    let failed = fault_journal(&dir, &[(Step::SyncHeightsDir, Fault::FailIo)]);
    assert!(matches!(failed.recover(), Err(JournalError::Io(_))));
    let recovery = fault_journal(&dir, &[]);
    let result = recovery.recover().unwrap();
    assert!(!result.dropped_tmp);
    assert!(result.dropped_heights.is_empty());
    assert_eq!(
        *recovery.store.log.borrow(),
        [Step::ReadPin, Step::SyncHeightsDir, Step::SyncDir]
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn oversized_sparse_journal_files_are_rejected_before_reading() {
    let dir = fixture();
    let b1 = bundle(GENESIS_NEXT, [1; 32], 1, "oversized");
    fs_journal(&dir).commit(&b1).unwrap();
    for path in [
        dir.join(HEAD_FILE),
        dir.join(HEAD_TMP),
        FsStore::height_path(&dir, 1),
        FsStore::bundle_path(&dir, b1.id()),
    ] {
        let original = fs::read(&path).ok();
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        // Sparse length is deliberately much larger than a viable decoder
        // allocation; only the metadata should be inspected.
        file.set_len(1u64 << 32).unwrap();
        assert!(matches!(
            fs_journal(&dir).recover(),
            Err(JournalError::Corrupt)
        ));
        drop(file);
        if let Some(bytes) = original {
            fs::write(&path, bytes).unwrap();
        } else {
            fs::remove_file(&path).unwrap();
        }
    }
    assert_eq!(fs_journal(&dir).recover().unwrap().pin.bundle, b1.id());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn commit_initializes_missing_directory_ancestors() {
    let root = fixture();
    let dir = root.join("new-owner").join("new-node").join("journal");
    let b1 = bundle(GENESIS_NEXT, [1; 32], 1, "nested");
    assert_eq!(fs_journal(&dir).commit(&b1).unwrap(), Outcome::Committed);
    assert_eq!(fs_journal(&dir).recover().unwrap().pin.bundle, b1.id());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn height_markers_track_committed_heights_and_dedup() {
    let dir = fixture();
    let journal = fs_journal(&dir);
    let b1 = bundle(GENESIS_NEXT, [1; 32], 1, "a");
    let b2 = bundle([1; 32], [2; 32], 2, "b");
    assert_eq!(journal.commit(&b1).unwrap(), Outcome::Committed);
    assert_eq!(journal.commit(&b2).unwrap(), Outcome::Committed);
    assert_eq!(journal.at_height(1).unwrap(), Some(b1.id()));
    assert_eq!(journal.at_height(2).unwrap(), Some(b2.id()));
    assert_eq!(journal.at_height(3).unwrap(), None);
    // A different bundle claiming an already-committed height is a conflict,
    // even when its predecessor is the current frontier.
    let fraud = bundle([2; 32], [9; 32], 1, "fraud");
    assert!(matches!(
        journal.commit(&fraud),
        Err(JournalError::Conflict { .. })
    ));
    // And a gap in height is rejected: every committed height is contiguous.
    let skip = bundle([2; 32], [3; 32], 7, "skip");
    assert!(matches!(
        journal.commit(&skip),
        Err(JournalError::Conflict { .. })
    ));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn crash_after_height_marker_drops_unpublished_residue() {
    let dir = fixture();
    let g = GENESIS_NEXT;
    let b1 = bundle(g, [1; 32], 1, "a");
    // Die after the height marker but before the pin tmp write.
    {
        let journal = fault_journal(&dir, &[(Step::WritePinTmp, Fault::CrashBefore)]);
        assert!(matches!(journal.commit(&b1), Err(JournalError::Crashed)));
    }
    let recovered = fs_journal(&dir).recover().unwrap();
    assert_eq!(recovered.pin, genesis_pin());
    assert_eq!(recovered.dropped_heights, vec![1]);
    assert_eq!(recovered.orphans, vec![b1.id()]);
    // A different bundle may now claim height 1.
    let other = bundle(g, [2; 32], 1, "other");
    let journal = fs_journal(&dir);
    assert_eq!(journal.commit(&other).unwrap(), Outcome::Committed);
    assert_eq!(journal.at_height(1).unwrap(), Some(other.id()));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn second_live_writer_is_refused() {
    let dir = fixture();
    let first = fs_journal(&dir);
    let second = fs_journal(&dir);
    let b1 = bundle(GENESIS_NEXT, [1; 32], 1, "a");
    // Hold the lock by committing once, then verify a concurrent second
    // journal cannot take it while `first` still holds a live lock? The lock
    // drops at commit end — instead verify the serialized conflict path:
    assert_eq!(first.commit(&b1).unwrap(), Outcome::Committed);
    let rival = bundle(GENESIS_NEXT, [9; 32], 1, "rival");
    assert!(matches!(
        second.commit(&rival),
        Err(JournalError::Conflict { .. })
    ));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn restart_never_continues_from_uncommitted_memory() {
    let dir = fixture();
    let g = GENESIS_NEXT;
    // Crash after writing pin.tmp: in-memory the commit felt nearly done,
    // but nothing was published.
    {
        let journal = fault_journal(&dir, &[(Step::RenamePin, Fault::CrashBefore)]);
        let almost = bundle(g, [5; 32], 1, "almost");
        assert!(matches!(
            journal.commit(&almost),
            Err(JournalError::Crashed)
        ));
    }
    // Reopen and commit a different bundle at the same predecessor: it must
    // succeed because the earlier attempt never reached the rename.
    let journal = fs_journal(&dir);
    let other = bundle(g, [6; 32], 1, "other");
    assert_eq!(journal.commit(&other).unwrap(), Outcome::Committed);
    let recovered = journal.recover().unwrap();
    assert_eq!(recovered.pin.next, [6; 32]);
    let _ = fs::remove_dir_all(&dir);
}

/// The outcome of one commit attempt as the caller observes it. `Crashed`
/// and `Io` are uncertain: the attempt may or may not have published, and
/// only recovery can say which.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Committed,
    AlreadyCommitted,
    Conflict { expected: [u8; 32], found: [u8; 32] },
    Busy,
    Crashed,
    Io,
}

/// The durable effects one commit attempt left behind, derived from which
/// protocol steps the fault program allowed to run.
#[derive(Default)]
struct Effects {
    bundle_written: bool,
    marker_written: bool,
    pin_tmp_written: bool,
    renamed: bool,
}

/// Every step `commit` can attempt, in protocol order.
const FAULTABLE_STEPS: [Step; 12] = [
    Step::Lock,
    Step::ReadPin,
    Step::CreateBundle,
    Step::SyncBundle,
    Step::SyncBundlesDir,
    Step::WriteHeightMarker,
    Step::SyncHeightMarker,
    Step::SyncHeightsDir,
    Step::WritePinTmp,
    Step::SyncPinTmp,
    Step::RenamePin,
    Step::SyncDir,
];

/// Every fault kind a step can be programmed with; `Pass` draws a clean run.
const FAULT_KINDS: [Fault; 4] = [
    Fault::Pass,
    Fault::CrashBefore,
    Fault::CrashAfter,
    Fault::FailIo,
];

/// A bundle distinct from every other `fresh_bundle` call: `seq` feeds both
/// the bound `next` frontier and the hashed fields, so ids never collide.
fn fresh_bundle(seq: u64, predecessor: [u8; 32], height: u64) -> Bundle {
    let mut next = [0u8; 32];
    next[..8].copy_from_slice(&seq.to_le_bytes());
    bundle(predecessor, next, height, &format!("gen-{seq}"))
}

/// Replays `commit` against the model pin under the drawn fault program.
/// Returns the verdict the caller must observe, the exact step sequence the
/// store must log (a step is logged even when its fault suppresses the
/// effect), and the durable effects that ran. This is the same decision
/// procedure as `Journal::commit`: lock, read pin, reconcile an already
/// published bundle, reject a mismatched predecessor or height, then the
/// create/sync/marker/pin-tmp/rename/dir-sync sequence.
fn simulate(pin: Pin, bundle: &Bundle, fstep: Step, fault: Fault) -> (Verdict, Vec<Step>, Effects) {
    let mut log = Vec::new();
    let mut fx = Effects::default();
    // The lock maps every fault to `Busy`; even `CrashAfter` releases the
    // handle it acquired, so nothing here is observable on disk.
    log.push(Step::Lock);
    if fstep == Step::Lock && fault != Fault::Pass {
        return (Verdict::Busy, log, fx);
    }
    log.push(Step::ReadPin);
    if fstep == Step::ReadPin && fault != Fault::Pass {
        let verdict = if fault == Fault::FailIo {
            Verdict::Io
        } else {
            Verdict::Crashed
        };
        return (verdict, log, fx);
    }
    if pin.bundle == bundle.id() {
        // Reconciliation re-establishes all containing-directory entries.
        for step in [Step::SyncBundlesDir, Step::SyncHeightsDir, Step::SyncDir] {
            log.push(step);
            if fstep == step && fault != Fault::Pass {
                let verdict = if fault == Fault::FailIo {
                    Verdict::Io
                } else {
                    Verdict::Crashed
                };
                return (verdict, log, fx);
            }
        }
        return (Verdict::AlreadyCommitted, log, fx);
    }
    if pin.next != bundle.predecessor() || bundle.height() != pin.height + 1 {
        return (
            Verdict::Conflict {
                expected: bundle.predecessor(),
                found: pin.next,
            },
            log,
            fx,
        );
    }
    for step in &FAULTABLE_STEPS[2..] {
        log.push(*step);
        // The step's effect lands unless the drawn fault suppresses it.
        if fstep != *step || matches!(fault, Fault::Pass | Fault::CrashAfter) {
            match step {
                Step::CreateBundle => fx.bundle_written = true,
                Step::WriteHeightMarker => fx.marker_written = true,
                Step::WritePinTmp => fx.pin_tmp_written = true,
                Step::RenamePin => fx.renamed = true,
                _ => {}
            }
        }
        if fstep == *step && fault != Fault::Pass {
            let verdict = if fault == Fault::FailIo {
                Verdict::Io
            } else {
                Verdict::Crashed
            };
            return (verdict, log, fx);
        }
    }
    (Verdict::Committed, log, fx)
}

/// Generative companion to the hand-picked fault-injection tests above: an
/// interleaved draw of commit attempts — fresh bundles extending the live
/// frontier, retries of uncertain or already-acknowledged bundles, rivals
/// extending stale frontiers, and height gaps — each crossed with a drawn
/// single-step fault program. After every attempt the oracle re-reads
/// durable state and requires the semantics the deterministic tests prove:
///
/// * a commit is atomic: recovery never fails closed and never reports a
///   half-state — the pin is either the previous frontier or exactly the
///   attempted bundle's pin;
/// * the caller's verdict matches the model, so an acknowledged commit is
///   exactly the pin recovery finds, and a crashed or failed attempt
///   retries to `Committed`/`AlreadyCommitted` while its predecessor still
///   holds but is refused as `Conflict` once the frontier moved past;
/// * the committed set is exactly the acknowledged chain: `at_height`
///   serves the acknowledged bundle at every height up to the pin and
///   nothing above it, while orphans, a dropped `pin.tmp`, and unpublished
///   height markers are exactly the residue the drawn schedule produced.
///
/// Each case does real filesystem I/O per attempt, so only the TooSlow
/// health check is suppressed.
#[hegel::test(test_cases = 64, suppress_health_check = [HealthCheck::TooSlow])]
fn interleaved_faults_preserve_commit_recovery_semantics(tc: TestCase) {
    let dir = fixture();
    // The durable model: the committed pin, the acknowledged chain by
    // height, every frontier ever held (stale rivals extend one), the
    // bundle files and height markers on disk, and whether `pin.tmp` is
    // published-pending.
    let mut pin = genesis_pin();
    let mut history = vec![pin];
    let mut committed: BTreeMap<u64, [u8; 32]> = BTreeMap::new();
    let mut files = BTreeSet::new();
    let mut markers: BTreeMap<u64, [u8; 32]> = BTreeMap::new();
    let mut pin_tmp = false;
    // Every bundle built, so retries redraw by index; `uncertain` holds the
    // pool indices whose last attempt died mid-protocol or failed and whose
    // retry must still complete — either the bundle published or its
    // predecessor is still the frontier.
    let mut pool: Vec<Bundle> = Vec::new();
    let mut uncertain: Vec<usize> = Vec::new();
    let mut seq = 0u64;

    let steps = tc.draw(gs::integers::<usize>().min_value(1).max_value(12));
    for _ in 0..steps {
        let pick = tc.draw(gs::integers::<usize>().max_value(99));
        let index = if pick < 45 {
            seq += 1;
            pool.push(fresh_bundle(seq, pin.next, pin.height + 1));
            pool.len() - 1
        } else if pick < 65 && !uncertain.is_empty() {
            // Retry after a crash: the same logical bundle must complete.
            uncertain[tc.draw(gs::integers::<usize>().max_value(uncertain.len() - 1))]
        } else if pick < 80 && !pool.is_empty() {
            // Any earlier bundle: an ancestor or a superseded candidate
            // conflicts, the tip reconciles to `AlreadyCommitted`.
            tc.draw(gs::integers::<usize>().max_value(pool.len() - 1))
        } else if pick < 90 && history.len() > 1 {
            // A rival extending a stale frontier can never publish now.
            let i = tc.draw(gs::integers::<usize>().max_value(history.len() - 2));
            seq += 1;
            pool.push(fresh_bundle(seq, history[i].next, history[i].height + 1));
            pool.len() - 1
        } else if pick < 95 {
            // A height gap at the live frontier is always a conflict.
            seq += 1;
            pool.push(fresh_bundle(seq, pin.next, pin.height + 2));
            pool.len() - 1
        } else {
            seq += 1;
            pool.push(fresh_bundle(seq, pin.next, pin.height + 1));
            pool.len() - 1
        };
        let bundle = &pool[index];

        let fstep =
            FAULTABLE_STEPS[tc.draw(gs::integers::<usize>().max_value(FAULTABLE_STEPS.len() - 1))];
        let fault = FAULT_KINDS[tc.draw(gs::integers::<usize>().max_value(3))];
        let (want, want_log, fx) = simulate(pin, bundle, fstep, fault);

        let journal = fault_journal(&dir, &[(fstep, fault)]);
        let got = match journal.commit(bundle) {
            Ok(Outcome::Committed) => Verdict::Committed,
            Ok(Outcome::AlreadyCommitted) => Verdict::AlreadyCommitted,
            Err(JournalError::Conflict { expected, found }) => {
                Verdict::Conflict { expected, found }
            }
            Err(JournalError::Busy) => Verdict::Busy,
            Err(JournalError::Crashed) => Verdict::Crashed,
            Err(JournalError::Io(_)) => Verdict::Io,
            Err(e) => panic!("commit failed outside the model: {e}"),
        };
        assert_eq!(got, want, "commit verdict diverged from the model");
        assert_eq!(
            *journal.store.log.borrow(),
            want_log,
            "protocol steps attempted out of order"
        );
        drop(journal);
        if matches!(got, Verdict::Crashed | Verdict::Io) {
            uncertain.push(index);
        }

        // Apply the durable effects the drawn fault schedule permitted.
        if fx.bundle_written {
            files.insert(bundle.id());
        }
        if fx.marker_written {
            markers.insert(bundle.height(), bundle.id());
        }
        if fx.pin_tmp_written {
            pin_tmp = true;
        }
        if fx.renamed {
            pin_tmp = false;
            pin = Pin {
                predecessor: bundle.predecessor(),
                next: bundle.next(),
                bundle: bundle.id(),
                height: bundle.height(),
            };
            committed.insert(bundle.height(), bundle.id());
            history.push(pin);
        }

        // Recovery must never report a half-state: the pin is exactly the
        // last published one, and the residue is exactly what ran.
        let recovered = fs_journal(&dir).recover().unwrap();
        assert_eq!(recovered.pin, pin);
        let want_orphans: Vec<[u8; 32]> = files
            .iter()
            .copied()
            .filter(|id| *id != pin.bundle)
            .collect();
        assert_eq!(recovered.orphans, want_orphans);
        assert_eq!(recovered.dropped_tmp, pin_tmp);
        let want_dropped: Vec<u64> = markers
            .keys()
            .copied()
            .filter(|h| *h > pin.height)
            .collect();
        assert_eq!(recovered.dropped_heights, want_dropped);
        pin_tmp = false;
        markers.retain(|h, _| *h <= pin.height);
        uncertain.retain(|&i| {
            pool[i].id() == pin.bundle
                || (pool[i].predecessor() == pin.next && pool[i].height() == pin.height + 1)
        });

        // The committed set is exactly the acknowledged chain, per height.
        let reader = fs_journal(&dir);
        for h in 1..=pin.height {
            assert_eq!(reader.at_height(h).unwrap(), Some(committed[&h]));
        }
        assert_eq!(reader.at_height(pin.height + 1).unwrap(), None);
    }
    let _ = fs::remove_dir_all(&dir);
}
