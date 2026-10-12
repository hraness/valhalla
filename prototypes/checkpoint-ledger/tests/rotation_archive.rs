#![cfg(all(feature = "native-store", unix))]

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use valhalla_checkpoint_ledger_prototype::{
    certificate_realm,
    rotation::{RotationObserver, RotationPolicy, RotationStatement, Side, MAX_ROTATION_BYTES},
    rotation_archive::{Append, Commitment, Error, RotationArchive},
    CertifiedLedger,
};
use valhalla_checkpoint_proof_prototype::{wire, Approval, CheckpointProof, Digest32, TrustConfig};
use vhalla_core::{Epoch, PeerId, RealmId, Sequence};
use vhalla_ledger::Event;

const REALM: RealmId = RealmId(42);
const EPOCH: Epoch = Epoch(7);
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Sandbox(PathBuf);
impl Sandbox {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "vhalla-rotation-archive-{}-{}",
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
        fs::read(self.archive().join("archive")).unwrap()
    }
    fn replace(&self, bytes: &[u8]) {
        fs::write(self.archive().join("archive"), bytes).unwrap();
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
fn policy(realm: RealmId, epoch: Epoch, seeds: &[u8]) -> RotationPolicy {
    RotationPolicy::new(
        realm,
        epoch,
        seeds.iter().map(|s| key(*s).verifying_key()),
        2,
        seeds.len(),
        4096,
    )
    .unwrap()
}
fn old() -> RotationPolicy {
    policy(REALM, EPOCH, &[1, 2, 3])
}
fn next(seeds: &[u8]) -> RotationPolicy {
    policy(REALM, Epoch(8), seeds)
}
fn configured(digest: Digest32) -> Option<RotationPolicy> {
    [[4, 5, 6], [4, 5, 7], [4, 5, 8]]
        .into_iter()
        .map(|seeds| next(&seeds))
        .find(|p| p.digest() == digest)
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
            .map(|s| Approval::sign(&key(s), statement.clone()).unwrap())
            .to_vec(),
        statement,
    };
    ledger.admit(&wire::encode(&proof).unwrap()).unwrap();
    ledger
}

// Test-only signer; the archive and observer cannot sign or install a policy.
fn certificate(statement: &RotationStatement, new: &[u8]) -> Vec<u8> {
    let mut raw = statement.transcript(Side::Old);
    raw.pop();
    for (side, seeds) in [(Side::Old, &[1, 2][..]), (Side::New, new)] {
        let mut approvals: Vec<_> = seeds
            .iter()
            .map(|s| {
                let signer = key(*s);
                (
                    signer.verifying_key().to_bytes(),
                    signer.sign(&statement.transcript(side)).to_bytes(),
                )
            })
            .collect();
        approvals.sort_unstable_by_key(|(id, _)| *id);
        raw.extend_from_slice(&(approvals.len() as u16).to_be_bytes());
        for (id, sig) in approvals {
            raw.extend_from_slice(&id);
            raw.extend_from_slice(&sig);
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
    path: &Path,
    ledger: &'a CertifiedLedger,
    anchor: Commitment,
) -> Result<RotationArchive<'a>, Error> {
    RotationArchive::reopen(path, ledger, old(), 2, anchor, configured)
}
fn anchored(bytes: &[u8]) -> Commitment {
    // Deliberately independent commitment calculation for malformed-input tests.
    let mut h = Sha256::new();
    h.update(b"valhalla/rotation-archive/commit/v1");
    h.update(bytes);
    Commitment::from_bytes(h.finalize().into())
}

#[test]
fn reopen_reverifies_each_configured_quorum_and_retains_conflicts() {
    let fixture = Sandbox::new();
    let ledger = checked();
    let claims = candidates(&ledger);
    let (mut archive, initial) =
        RotationArchive::create_new(fixture.archive(), &ledger, old(), 2).unwrap();
    assert_eq!(archive.observed_commitment(), Some(initial));
    assert!(matches!(
        open(&fixture.archive(), &ledger, initial),
        Err(Error::Busy)
    ));
    let a = match archive.append(&claims[0].1, &claims[0].0).unwrap() {
        Append::Recorded(value) => value,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        archive.append(&claims[0].1, &claims[0].0).unwrap(),
        Append::Repeated(a)
    );
    assert!(archive.append(&claims[0].1, &claims[1].0).is_err());
    let b = match archive.append(&claims[1].1, &claims[1].0).unwrap() {
        Append::Conflict(value) => value,
        other => panic!("{other:?}"),
    };
    assert!(archive.blocked());
    assert_eq!(
        archive.append(&claims[0].1, &claims[0].0).unwrap(),
        Append::Repeated(b)
    );
    drop(archive);
    assert!(matches!(
        open(&fixture.archive(), &ledger, initial),
        Err(Error::CommitmentMismatch)
    ));
    assert!(matches!(
        open(&fixture.archive(), &ledger, a),
        Err(Error::CommitmentMismatch)
    ));
    let mut reopened = open(&fixture.archive(), &ledger, b).unwrap();
    assert!(reopened.blocked());
    assert_eq!(
        reopened
            .evidence()
            .iter()
            .map(|c| c.bytes())
            .collect::<Vec<_>>(),
        vec![claims[0].1.as_slice(), claims[1].1.as_slice()]
    );
    assert_eq!(
        reopened.append(&claims[0].1, &claims[0].0).unwrap(),
        Append::Repeated(b)
    );
    assert!(reopened.blocked());
    assert!(matches!(
        reopened.append(&claims[0].1, &next(&[4, 5, 9])),
        Err(Error::Rotation(_))
    ));
    drop(reopened);
    assert!(matches!(
        RotationArchive::reopen(fixture.archive(), &ledger, old(), 2, b, |_| None),
        Err(Error::MissingPolicy)
    ));
    assert!(matches!(
        RotationArchive::reopen(fixture.archive(), &ledger, old(), 2, b, |_| Some(next(&[
            4, 5, 9
        ]))),
        Err(Error::MissingPolicy)
    ));
    assert!(matches!(
        RotationArchive::reopen(
            fixture.archive(),
            &ledger,
            policy(REALM, EPOCH, &[1, 2, 4]),
            2,
            b,
            configured
        ),
        Err(Error::Rotation(_))
    ));
    assert!(matches!(
        RotationArchive::reopen(fixture.archive(), &ledger, old(), 3, b, configured),
        Err(Error::InvalidArchive)
    ));
    assert_eq!(ledger.accepted().unwrap().checkpoint().epoch, EPOCH);
}

#[test]
fn missing_erased_changed_and_reordered_bytes_never_bootstrap_clean() {
    let fixture = Sandbox::new();
    let ledger = checked();
    let claims = candidates(&ledger);
    assert!(matches!(
        open(&fixture.archive(), &ledger, Commitment::from_bytes([0; 32])),
        Err(Error::Io(_))
    ));
    let (mut archive, _) =
        RotationArchive::create_new(fixture.archive(), &ledger, old(), 2).unwrap();
    let a = match archive.append(&claims[0].1, &claims[0].0).unwrap() {
        Append::Recorded(c) => c,
        _ => unreachable!(),
    };
    let b = match archive.append(&claims[1].1, &claims[1].0).unwrap() {
        Append::Conflict(c) => c,
        _ => unreachable!(),
    };
    assert!(archive.blocked());
    let original = fixture.bytes();
    drop(archive);
    let first = original
        .windows(claims[0].1.len())
        .position(|s| s == claims[0].1)
        .unwrap();
    let second = original
        .windows(claims[1].1.len())
        .position(|s| s == claims[1].1)
        .unwrap();
    let mut changed = original.clone();
    changed[first] ^= 1;
    fixture.replace(&changed);
    assert!(matches!(
        open(&fixture.archive(), &ledger, b),
        Err(Error::CommitmentMismatch)
    ));
    assert!(open(&fixture.archive(), &ledger, anchored(&changed)).is_err()); // even a repinned forged certificate
    changed = original.clone();
    // Swap the full fixed-size frames (tag, length, digest and certificate).
    let frame = claims[0].1.len() + 35;
    changed[first - 35..first - 35 + frame]
        .copy_from_slice(&original[second - 35..second - 35 + frame]);
    changed[second - 35..second - 35 + frame]
        .copy_from_slice(&original[first - 35..first - 35 + frame]);
    fixture.replace(&changed);
    assert!(matches!(
        open(&fixture.archive(), &ledger, b),
        Err(Error::CommitmentMismatch)
    ));
    fixture.replace(&original[..second - 35]);
    assert!(matches!(
        open(&fixture.archive(), &ledger, b),
        Err(Error::CommitmentMismatch)
    ));
    assert!(open(&fixture.archive(), &ledger, a).is_ok()); // only if independently re-anchored to old bytes
    fs::remove_file(fixture.archive().join("archive")).unwrap();
    assert!(matches!(
        open(&fixture.archive(), &ledger, b),
        Err(Error::Io(_))
    ));
}

#[test]
fn capacity_marker_and_uncertain_ack_stay_blocked_after_reopen() {
    let fixture = Sandbox::new();
    let ledger = checked();
    let claims = candidates(&ledger);
    let (mut archive, initial) =
        RotationArchive::create_new(fixture.archive(), &ledger, old(), 2).unwrap();
    let a = match archive.append(&claims[0].1, &claims[0].0).unwrap() {
        Append::Recorded(c) => c,
        _ => unreachable!(),
    };
    let b = match archive.append(&claims[1].1, &claims[1].0).unwrap() {
        Append::Conflict(c) => c,
        _ => unreachable!(),
    };
    let full = match archive.append(&claims[2].1, &claims[2].0).unwrap() {
        Append::Capacity(c) => c,
        _ => unreachable!(),
    };
    assert!(archive.blocked());
    assert!(matches!(
        archive.append(&claims[0].1, &claims[0].0),
        Err(Error::Rotation(_))
    ));
    assert_eq!(archive.evidence().len(), 2);
    drop(archive); // simulate lost acknowledgement: separately held b was not advanced
    for stale in [initial, a, b] {
        assert!(matches!(
            open(&fixture.archive(), &ledger, stale),
            Err(Error::CommitmentMismatch)
        ));
    }
    let reopened = open(&fixture.archive(), &ledger, full).unwrap();
    assert!(reopened.blocked());
    assert_eq!(reopened.evidence().len(), 2);
    drop(reopened);
    let bytes = fixture.bytes();
    fixture.replace(&bytes[..bytes.len() - 1]); // cut before marker publication/sync
    assert!(matches!(
        open(&fixture.archive(), &ledger, full),
        Err(Error::CommitmentMismatch)
    ));
    assert!(open(&fixture.archive(), &ledger, b).unwrap().blocked()); // conflict is still retained
    fixture.replace(&bytes);
    let mut malformed = bytes.clone();
    malformed.push(2); // noncanonical second marker
    fixture.replace(&malformed);
    assert!(matches!(
        open(&fixture.archive(), &ledger, anchored(&malformed)),
        Err(Error::InvalidArchive)
    ));
}

#[test]
fn interrupted_record_and_marker_writes_require_exact_anchor() {
    let ledger = checked();
    let claims = candidates(&ledger);
    let template = Sandbox::new();
    let (mut archive, initial) =
        RotationArchive::create_new(template.archive(), &ledger, old(), 2).unwrap();
    let header_len = template.bytes().len();
    // Independently constructed with Python struct/hashlib from the README's
    // fixed old-head/root/policy fixtures (realm 42, epoch 7, height 0).
    assert_eq!(header_len, 159);
    assert_eq!(
        initial.bytes(),
        [
            0xc7, 0xcc, 0xac, 0x48, 0xff, 0xbf, 0x19, 0x81, 0xbf, 0x9b, 0x60, 0xef, 0x38, 0xd6,
            0x51, 0xff, 0x7e, 0x48, 0x2e, 0xeb, 0x2a, 0x46, 0x9b, 0x57, 0x6b, 0x0e, 0xcb, 0x09,
            0x70, 0x67, 0x4b, 0xd6
        ]
    );
    let full = match archive.append(&claims[0].1, &claims[0].0).unwrap() {
        Append::Recorded(c) => c,
        _ => unreachable!(),
    };
    let suffix = template.bytes()[header_len..].to_vec();
    drop(archive);
    for cut in [0, 1, 2, 17, suffix.len() - 1, suffix.len()] {
        let fixture = Sandbox::new();
        let (archive, empty) =
            RotationArchive::create_new(fixture.archive(), &ledger, old(), 2).unwrap();
        assert_eq!(empty, initial);
        drop(archive);
        // Controlled test-only cut: write bytes but deliberately omit file sync.
        let mut file = OpenOptions::new()
            .append(true)
            .open(fixture.archive().join("archive"))
            .unwrap();
        file.write_all(&suffix[..cut]).unwrap();
        drop(file);
        if cut == 0 {
            assert!(open(&fixture.archive(), &ledger, initial).is_ok());
        } else {
            assert!(matches!(
                open(&fixture.archive(), &ledger, initial),
                Err(Error::CommitmentMismatch)
            ));
        }
        if cut == suffix.len() {
            assert!(open(&fixture.archive(), &ledger, full).is_ok());
        } else {
            assert!(open(&fixture.archive(), &ledger, full).is_err());
        }
    }
    // A file changed beneath a live lock poisons the handle, not a clean retry.
    let fixture = Sandbox::new();
    let (mut live, _) = RotationArchive::create_new(fixture.archive(), &ledger, old(), 2).unwrap();
    fs::write(
        fixture.archive().join("archive"),
        vec![0; MAX_ROTATION_BYTES + 1],
    )
    .unwrap();
    assert!(live.append(&claims[0].1, &claims[0].0).is_err());
    assert!(live.blocked());
    assert!(matches!(
        live.append(&claims[0].1, &claims[0].0),
        Err(Error::Poisoned)
    ));
}
