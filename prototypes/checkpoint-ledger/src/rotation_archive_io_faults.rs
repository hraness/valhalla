// Only compiled into native-store unit tests. Fail the actual append operations
// while forwarding all successful operations to the real locked archive file.
use super::*;
use crate::certificate_realm;
use crate::rotation::{RotationStatement, Side};
use ed25519_dalek::{Signer, SigningKey};
use std::format;
use std::os::unix::fs::DirBuilderExt;
use std::sync::atomic::{AtomicU64, Ordering};
use valhalla_checkpoint_proof_prototype::{wire, Approval, CheckpointProof, TrustConfig};
use vhalla_core::{Epoch, PeerId, RealmId, Sequence};
use vhalla_ledger::Event;

#[derive(Clone, Copy, Debug)]
enum Point {
    Seek,
    Write(usize), // write exactly this many prefix bytes, then return an error
    SyncBefore,
    SyncAfter, // even a successful sync with a lost acknowledgement is uncertain
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Calls {
    seeks: usize,
    writes: usize,
    bytes: usize,
    syncs: usize,
}

pub(super) struct Fault {
    point: Point,
    calls: Calls,
}

impl Fault {
    fn new(point: Point) -> Self {
        Self {
            point,
            calls: Calls::default(),
        }
    }
}

pub(super) struct FaultIo<'a> {
    file: &'a mut File,
    fault: &'a mut Fault,
}

impl<'a> FaultIo<'a> {
    pub(super) fn new(file: &'a mut File, fault: &'a mut Fault) -> Self {
        Self { file, fault }
    }
}

fn injected() -> io::Error {
    io::Error::other("injected archive I/O error")
}

impl Seek for FaultIo<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.fault.calls.seeks += 1;
        if matches!(self.fault.point, Point::Seek) {
            return Err(injected());
        }
        self.file.seek(pos)
    }
}

impl Write for FaultIo<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.fault.calls.writes += 1;
        if let Point::Write(prefix) = self.fault.point {
            let prefix = prefix.min(buf.len());
            self.file.write_all(&buf[..prefix])?;
            self.fault.calls.bytes += prefix;
            return Err(injected());
        }
        let written = self.file.write(buf)?;
        self.fault.calls.bytes += written;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl AppendIo for FaultIo<'_> {
    fn sync_file(&mut self) -> io::Result<()> {
        self.fault.calls.syncs += 1;
        match self.fault.point {
            Point::SyncBefore => Err(injected()),
            Point::SyncAfter => {
                self.file.sync_all()?;
                Err(injected())
            }
            _ => self.file.sync_all(),
        }
    }
}

const REALM: RealmId = RealmId(42);
const EPOCH: Epoch = Epoch(7);
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Sandbox(PathBuf);

impl Sandbox {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "vhalla-rotation-io-faults-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }

    fn archive(&self) -> PathBuf {
        self.0.join("archive-home")
    }

    fn bytes(&self) -> Vec<u8> {
        fs::read(self.archive().join(DATA)).unwrap()
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn policy(epoch: Epoch, seeds: &[u8]) -> RotationPolicy {
    RotationPolicy::new(
        REALM,
        epoch,
        seeds.iter().map(|s| key(*s).verifying_key()),
        2,
        seeds.len(),
        4096,
    )
    .unwrap()
}

fn old() -> RotationPolicy {
    policy(EPOCH, &[1, 2, 3])
}

fn next(seeds: &[u8]) -> RotationPolicy {
    policy(Epoch(8), seeds)
}

fn configured(digest: Digest32) -> Option<RotationPolicy> {
    [[4, 5, 6], [4, 5, 7], [4, 5, 8]]
        .into_iter()
        .map(|seeds| next(&seeds))
        .find(|policy| policy.digest() == digest)
}

fn checked() -> CertifiedLedger {
    let trust = TrustConfig::new(
        certificate_realm(REALM),
        EPOCH.0,
        [1, 2, 3].map(|s| key(s).verifying_key()),
        2,
        3,
        4096,
    )
    .unwrap();
    let mut ledger = CertifiedLedger::new(REALM, EPOCH, trust, 10).unwrap();
    ledger
        .append(Event::new(
            None,
            REALM,
            EPOCH,
            PeerId(1),
            Sequence(1),
            b"genesis".to_vec(),
        ))
        .unwrap();
    let statement = ledger.propose_tip().unwrap();
    let proof = CheckpointProof {
        approvals: [1, 2]
            .map(|seed| Approval::sign(&key(seed), statement.clone()).unwrap())
            .to_vec(),
        statement,
    };
    ledger.admit(&wire::encode(&proof).unwrap()).unwrap();
    ledger
}

// Test signers are never available to the archive or recovery implementation.
fn certificate(statement: &RotationStatement, new: &[u8]) -> Vec<u8> {
    let mut raw = statement.transcript(Side::Old);
    raw.pop();
    for (side, seeds) in [(Side::Old, &[1, 2][..]), (Side::New, new)] {
        let mut approvals: Vec<_> = seeds
            .iter()
            .map(|seed| {
                let signer = key(*seed);
                (
                    signer.verifying_key().to_bytes(),
                    signer.sign(&statement.transcript(side)).to_bytes(),
                )
            })
            .collect();
        approvals.sort_unstable_by_key(|(id, _)| *id);
        raw.extend_from_slice(&(approvals.len() as u16).to_be_bytes());
        for (id, signature) in approvals {
            raw.extend_from_slice(&id);
            raw.extend_from_slice(&signature);
        }
    }
    raw
}

fn candidates(ledger: &CertifiedLedger) -> Vec<(RotationPolicy, Vec<u8>)> {
    let observer = RotationObserver::new(ledger, old(), 2).unwrap();
    [[4, 5, 6], [4, 5, 7], [4, 5, 8]]
        .map(|seeds| {
            let policy = next(&seeds);
            let raw = certificate(&observer.proposal(&policy).unwrap(), &[4, 5]);
            (policy, raw)
        })
        .to_vec()
}

fn open<'a>(
    fixture: &Sandbox,
    ledger: &'a CertifiedLedger,
    expected: Commitment,
) -> Result<RotationArchive<'a>, Error> {
    RotationArchive::reopen(fixture.archive(), ledger, old(), 2, expected, configured)
}

// This only models a hostile guess from disk, never an independent anchor.
fn guessed_from_disk(bytes: &[u8]) -> Commitment {
    let mut digest = Sha256::new();
    digest.update(b"valhalla/rotation-archive/commit/v1");
    digest.update(bytes);
    Commitment::from_bytes(digest.finalize().into())
}

fn assert_poisoned_without_retry_write(
    live: &mut RotationArchive<'_>,
    fixture: &Sandbox,
    certificate: &(RotationPolicy, Vec<u8>),
) -> Calls {
    assert!(matches!(
        live.append(&certificate.1, &certificate.0),
        Err(Error::UncertainWrite)
    ));
    assert!(live.blocked());
    assert_eq!(live.observed_commitment(), None);
    let bytes = fixture.bytes();
    assert!(bytes.len() <= MAX_ARCHIVE_BYTES);
    let calls = live.fault.as_ref().unwrap().calls;
    assert_eq!(calls.seeks, 1);
    assert!(matches!(
        live.append(&certificate.1, &certificate.0),
        Err(Error::Poisoned)
    ));
    assert_eq!(live.fault.as_ref().unwrap().calls, calls);
    assert_eq!(fixture.bytes(), bytes);
    calls
}

#[test]
fn real_record_append_seek_partial_write_and_sync_faults_require_reconciliation() {
    let ledger = checked();
    let claims = candidates(&ledger);
    let template = Sandbox::new();
    let (mut good, initial) =
        RotationArchive::create_new(template.archive(), &ledger, old(), 2).unwrap();
    let full = match good.append(&claims[0].1, &claims[0].0).unwrap() {
        Append::Recorded(pin) => pin,
        other => panic!("{other:?}"),
    };
    let complete_bytes = template.bytes();
    let prefix_len = complete_bytes.len() - FRAME_BYTES - claims[0].1.len();
    assert_eq!(prefix_len, HEADER_BYTES);
    drop(good);

    for point in [
        Point::Seek,
        Point::Write(0),
        Point::Write(1),
        Point::Write(2),
        Point::Write(17),
        Point::Write(FRAME_BYTES + claims[0].1.len() - 1),
        Point::SyncBefore,
        Point::SyncAfter,
    ] {
        let fixture = Sandbox::new();
        let (mut live, held_initial) =
            RotationArchive::create_new(fixture.archive(), &ledger, old(), 2).unwrap();
        assert_eq!(held_initial, initial);
        live.fault = Some(Fault::new(point));
        let calls = assert_poisoned_without_retry_write(&mut live, &fixture, &claims[0]);
        let bytes = fixture.bytes();
        assert_eq!(&bytes[..prefix_len], &complete_bytes[..prefix_len]);
        let written = match point {
            Point::Seek | Point::Write(0) => 0,
            Point::Write(n) => n,
            Point::SyncBefore | Point::SyncAfter => complete_bytes.len() - prefix_len,
        };
        assert_eq!(bytes.len(), prefix_len + written, "{point:?}");
        assert_eq!(bytes, complete_bytes[..bytes.len()]);
        assert_eq!(calls.writes, usize::from(!matches!(point, Point::Seek)));
        assert_eq!(calls.bytes, written);
        assert_eq!(
            calls.syncs,
            usize::from(matches!(point, Point::SyncBefore | Point::SyncAfter))
        );
        drop(live);
        if written == 0 {
            assert_eq!(
                open(&fixture, &ledger, initial).unwrap().evidence().len(),
                0
            );
        } else {
            assert!(matches!(
                open(&fixture, &ledger, initial),
                Err(Error::CommitmentMismatch)
            ));
        }
        if written == complete_bytes.len() - prefix_len {
            let reopened = open(&fixture, &ledger, full).unwrap();
            assert_eq!(reopened.evidence()[0].bytes(), claims[0].1);
            drop(reopened);
            assert!(matches!(
                RotationArchive::reopen(fixture.archive(), &ledger, old(), 2, full, |_| None),
                Err(Error::MissingPolicy)
            ));
        } else {
            assert!(matches!(
                open(&fixture, &ledger, full),
                Err(Error::CommitmentMismatch)
            ));
            if written != 0 {
                // Even if a bad caller re-pins the partial bytes, framing must fail.
                assert!(matches!(
                    open(&fixture, &ledger, guessed_from_disk(&bytes)),
                    Err(Error::InvalidArchive)
                ));
            }
        }
    }
}

#[test]
fn capacity_marker_faults_preserve_ordered_evidence_and_exact_pins() {
    let ledger = checked();
    let claims = candidates(&ledger);
    let template = Sandbox::new();
    let (mut good, initial) =
        RotationArchive::create_new(template.archive(), &ledger, old(), 2).unwrap();
    let _ = good.append(&claims[0].1, &claims[0].0).unwrap();
    let conflict = match good.append(&claims[1].1, &claims[1].0).unwrap() {
        Append::Conflict(pin) => pin,
        other => panic!("{other:?}"),
    };
    let full = match good.append(&claims[2].1, &claims[2].0).unwrap() {
        Append::Capacity(pin) => pin,
        other => panic!("{other:?}"),
    };
    let complete_bytes = template.bytes();
    assert_eq!(complete_bytes.last(), Some(&EXHAUSTED));
    drop(good);

    for point in [
        Point::Seek,
        Point::Write(0),
        Point::SyncBefore,
        Point::SyncAfter,
    ] {
        let fixture = Sandbox::new();
        let (mut live, pin) =
            RotationArchive::create_new(fixture.archive(), &ledger, old(), 2).unwrap();
        assert_eq!(pin, initial);
        let _ = live.append(&claims[0].1, &claims[0].0).unwrap();
        assert_eq!(
            live.append(&claims[1].1, &claims[1].0).unwrap(),
            Append::Conflict(conflict)
        );
        live.fault = Some(Fault::new(point));
        let calls = assert_poisoned_without_retry_write(&mut live, &fixture, &claims[2]);
        assert_eq!(
            calls.bytes,
            usize::from(matches!(point, Point::SyncBefore | Point::SyncAfter))
        );
        let bytes = fixture.bytes();
        assert_eq!(bytes, complete_bytes[..bytes.len()]);
        assert_eq!(
            bytes.len(),
            complete_bytes.len() - usize::from(calls.bytes == 0)
        );
        drop(live);
        assert!(matches!(
            open(&fixture, &ledger, initial),
            Err(Error::CommitmentMismatch)
        ));
        let expected = if calls.bytes == 0 { conflict } else { full };
        let mut reopened = open(&fixture, &ledger, expected).unwrap();
        assert!(reopened.blocked());
        assert_eq!(reopened.evidence().len(), 2);
        assert_eq!(reopened.evidence()[0].bytes(), claims[0].1);
        assert_eq!(reopened.evidence()[1].bytes(), claims[1].1);
        // Conflict alone also reports blocked; prove that a recovered marker
        // specifically keeps refusing overflow without appending another byte.
        if calls.bytes == 1 {
            assert!(matches!(
                reopened.append(&claims[2].1, &claims[2].0),
                Err(Error::Rotation(Reject::Capacity))
            ));
            assert_eq!(reopened.observed_commitment(), Some(full));
            assert_eq!(fixture.bytes(), bytes);
        }
        drop(reopened);
        let stale = if calls.bytes == 0 { full } else { conflict };
        assert!(matches!(
            open(&fixture, &ledger, stale),
            Err(Error::CommitmentMismatch)
        ));
    }
}

#[test]
fn known_bad_clear_poison_and_guess_from_disk_mutants() {
    let ledger = checked();
    let claims = candidates(&ledger);
    let fixture = Sandbox::new();
    let (mut live, held_initial) =
        RotationArchive::create_new(fixture.archive(), &ledger, old(), 2).unwrap();
    live.fault = Some(Fault::new(Point::Seek));
    assert_poisoned_without_retry_write(&mut live, &fixture, &claims[0]);
    let before = fixture.bytes();
    // Known-bad mutant: clearing poison after a failed seek would permit a
    // second append. The real handle never exposes this escape hatch.
    live.fault = None;
    live.poisoned = false;
    assert!(matches!(
        live.append(&claims[0].1, &claims[0].0),
        Ok(Append::Repeated(_))
    ));
    // The observer was advanced before I/O failed; this mutant falsely acks a
    // replay even though the file still contains only the empty header.
    assert_eq!(fixture.bytes(), before);
    drop(live);
    assert_eq!(
        open(&fixture, &ledger, held_initial)
            .unwrap()
            .evidence()
            .len(),
        0
    );

    let fixture = Sandbox::new();
    let (mut live, stale) =
        RotationArchive::create_new(fixture.archive(), &ledger, old(), 2).unwrap();
    live.fault = Some(Fault::new(Point::SyncBefore));
    assert_poisoned_without_retry_write(&mut live, &fixture, &claims[0]);
    let guessed = guessed_from_disk(&fixture.bytes());
    drop(live);
    assert!(matches!(
        open(&fixture, &ledger, stale),
        Err(Error::CommitmentMismatch)
    ));
    // Known-bad guessed-pin mutant: valid bytes can be reopened under a hash
    // copied from the same disk, but that hash proves no independently held pin
    // and no physical durability. The API never computes the supplied pin.
    assert_eq!(
        open(&fixture, &ledger, guessed).unwrap().evidence().len(),
        1
    );
}
