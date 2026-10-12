//! Generated local archive histories; the model owns the expected bytes and pin.
//! Disk cuts here are test-only byte edits, not physical power-loss evidence.
#![cfg(all(feature = "native-store", unix))]

use ed25519_dalek::{Signer, SigningKey};
use hegel::{generators as gs, TestCase};
use sha2::{Digest, Sha256};
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use valhalla_checkpoint_ledger_prototype::{
    certificate_realm,
    rotation::{RotationObserver, RotationPolicy, RotationStatement, Side},
    rotation_archive::{Append, Commitment, Error, RotationArchive},
    CertifiedLedger,
};
use valhalla_checkpoint_proof_prototype::{wire, Approval, CheckpointProof, Digest32, TrustConfig};
use vhalla_core::{Epoch, PeerId, RealmId, Sequence};
use vhalla_ledger::Event;

const REALM: RealmId = RealmId(42);
const EPOCH: Epoch = Epoch(7);
const CAPACITY: usize = 2;
const HEADER_BYTES: usize = 159;
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Sandbox(PathBuf);
impl Sandbox {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "vhalla-rotation-hegel-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn archive(&self) -> PathBuf {
        self.0.join("archive-home")
    }
    fn data(&self) -> PathBuf {
        self.archive().join("archive")
    }
    fn replace(&self, bytes: &[u8]) {
        if self.data().exists() {
            fs::write(self.data(), bytes).unwrap();
        } else {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(self.data())
                .unwrap()
                .write_all(bytes)
                .unwrap();
        }
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

// Fixed public test keys only; neither the archive nor observer can sign.
fn certificate(statement: &RotationStatement) -> Vec<u8> {
    let mut raw = statement.transcript(Side::Old);
    raw.pop();
    for (side, seeds) in [(Side::Old, &[1, 2][..]), (Side::New, &[4, 5][..])] {
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
fn claims(ledger: &CertifiedLedger) -> Vec<(RotationPolicy, Vec<u8>)> {
    let observer = RotationObserver::new(ledger, old(), CAPACITY).unwrap();
    [[4, 5, 6], [4, 5, 7], [4, 5, 8]]
        .map(|seeds| {
            let p = next(&seeds);
            let raw = certificate(&observer.proposal(&p).unwrap());
            (p, raw)
        })
        .to_vec()
}
fn open<'a>(
    path: &Path,
    ledger: &'a CertifiedLedger,
    anchor: Commitment,
) -> Result<RotationArchive<'a>, Error> {
    RotationArchive::reopen(path, ledger, old(), CAPACITY, anchor, configured)
}

// Deliberately separate from the archive's private commitment implementation.
fn hash(raw: &[u8]) -> Commitment {
    let mut sha = Sha256::new();
    sha.update(b"valhalla/rotation-archive/commit/v1");
    sha.update(raw);
    Commitment::from_bytes(sha.finalize().into())
}

struct Model {
    raw: Vec<u8>, // retained in the model, not reread from disk on reopen
    anchor: Commitment,
    disk: Option<Vec<u8>>,
    snapshots: Vec<Vec<u8>>,
    evidence: Vec<usize>,
    exhausted: bool,
}
impl Model {
    fn new(raw: Vec<u8>, initial: Commitment) -> Self {
        assert_eq!(raw.len(), HEADER_BYTES);
        assert_eq!(hash(&raw), initial);
        assert_eq!(
            initial.bytes(),
            [
                0xc7, 0xcc, 0xac, 0x48, 0xff, 0xbf, 0x19, 0x81, 0xbf, 0x9b, 0x60, 0xef, 0x38, 0xd6,
                0x51, 0xff, 0x7e, 0x48, 0x2e, 0xeb, 0x2a, 0x46, 0x9b, 0x57, 0x6b, 0x0e, 0xcb, 0x09,
                0x70, 0x67, 0x4b, 0xd6
            ]
        );
        Self {
            snapshots: vec![raw.clone()],
            disk: Some(raw.clone()),
            raw,
            anchor: initial,
            evidence: Vec::new(),
            exhausted: false,
        }
    }
    fn changed(&mut self) {
        self.anchor = hash(&self.raw);
        self.disk = Some(self.raw.clone());
        self.snapshots.push(self.raw.clone());
        assert!(self.snapshots.len() <= CAPACITY + 2);
    }
    fn blocked(&self) -> bool {
        self.exhausted || self.evidence.len() > 1
    }
}

fn check(
    fixture: &Sandbox,
    live: &Option<RotationArchive<'_>>,
    model: &Model,
    claims: &[(RotationPolicy, Vec<u8>)],
) {
    assert_eq!(fs::read(fixture.data()).ok(), model.disk);
    if let Some(archive) = live {
        assert_eq!(model.disk.as_deref(), Some(model.raw.as_slice()));
        assert_eq!(archive.observed_commitment(), Some(model.anchor));
        assert_eq!(archive.blocked(), model.blocked());
        assert_eq!(
            archive
                .evidence()
                .iter()
                .map(|e| e.bytes())
                .collect::<Vec<_>>(),
            model
                .evidence
                .iter()
                .map(|&i| claims[i].1.as_slice())
                .collect::<Vec<_>>()
        );
    }
}

fn append_valid(
    live: &mut Option<RotationArchive<'_>>,
    model: &mut Model,
    claims: &[(RotationPolicy, Vec<u8>)],
    index: usize,
) {
    let Some(archive) = live.as_mut() else { return };
    let (policy, bytes) = &claims[index];
    let result = archive.append(bytes, policy);
    if model.exhausted {
        assert!(matches!(result, Err(Error::Rotation(_))));
    } else if model.evidence.contains(&index) {
        assert_eq!(result.unwrap(), Append::Repeated(model.anchor));
    } else if model.evidence.len() == CAPACITY {
        model.raw.push(2); // sticky capacity marker; overflowing claim is NOT retained
        model.exhausted = true;
        model.changed();
        assert_eq!(result.unwrap(), Append::Capacity(model.anchor));
    } else {
        model.raw.push(1);
        model
            .raw
            .extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        model.raw.extend_from_slice(&Sha256::digest(bytes));
        model.raw.extend_from_slice(bytes);
        let first = model.evidence.is_empty();
        model.evidence.push(index);
        model.changed();
        assert_eq!(
            result.unwrap(),
            if first {
                Append::Recorded(model.anchor)
            } else {
                Append::Conflict(model.anchor)
            }
        );
    }
}

fn append_invalid(
    live: &mut Option<RotationArchive<'_>>,
    claims: &[(RotationPolicy, Vec<u8>)],
    index: usize,
    kind: u8,
) {
    let Some(archive) = live.as_mut() else { return };
    let (policy, cert) = &claims[index];
    let mut altered = cert.clone();
    let result = match kind {
        0 => {
            altered.pop();
            archive.append(&altered, policy)
        } // truncated quorum
        1 => {
            *altered.last_mut().unwrap() ^= 1;
            archive.append(&altered, policy)
        } // bad signature
        _ => archive.append(cert, &claims[(index + 1) % claims.len()].0), // wrong configured policy
    };
    assert!(matches!(result, Err(Error::Rotation(_))));
}

fn reopen_latest<'a>(
    live: &mut Option<RotationArchive<'a>>,
    fixture: &Sandbox,
    ledger: &'a CertifiedLedger,
    model: &Model,
) {
    *live = None; // release the cooperating writer lock before recovery
    let result = open(&fixture.archive(), ledger, model.anchor);
    match &model.disk {
        None => assert!(matches!(result, Err(Error::Io(_)))),
        Some(bytes) if bytes != &model.raw => {
            assert!(matches!(result, Err(Error::CommitmentMismatch)));
        }
        Some(_) => *live = Some(result.unwrap()),
    }
}

fn reopen_stale<'a>(
    live: &mut Option<RotationArchive<'a>>,
    fixture: &Sandbox,
    ledger: &'a CertifiedLedger,
    model: &Model,
) {
    // Only compare against a latest disk: a stale *matching* external pin is
    // outside this prototype's freshness guarantees.
    if model.snapshots.len() < 2 || model.disk.as_ref() != Some(&model.raw) {
        return;
    }
    *live = None;
    let stale = hash(&model.snapshots[0]); // independently saved before any append
    assert_ne!(stale, model.anchor);
    assert!(matches!(
        open(&fixture.archive(), ledger, stale),
        Err(Error::CommitmentMismatch)
    ));
    reopen_latest(live, fixture, ledger, model);
}

fn cut<'a>(
    live: &mut Option<RotationArchive<'a>>,
    fixture: &Sandbox,
    ledger: &'a CertifiedLedger,
    model: &mut Model,
    rollback: bool,
) {
    *live = None;
    let bytes = if rollback && model.snapshots.len() > 1 {
        model.snapshots[0].clone() // complete old version, not a partial frame
    } else {
        model.raw[..model.raw.len() - 1].to_vec() // torn frame or marker
    };
    fixture.replace(&bytes);
    model.disk = Some(bytes);
    reopen_latest(live, fixture, ledger, model); // retained latest pin must refuse
}
fn erase<'a>(
    live: &mut Option<RotationArchive<'a>>,
    fixture: &Sandbox,
    ledger: &'a CertifiedLedger,
    model: &mut Model,
) {
    *live = None;
    if fixture.data().exists() {
        fs::remove_file(fixture.data()).unwrap();
    }
    model.disk = None;
    reopen_latest(live, fixture, ledger, model);
}
fn restore<'a>(
    live: &mut Option<RotationArchive<'a>>,
    fixture: &Sandbox,
    ledger: &'a CertifiedLedger,
    model: &mut Model,
) {
    *live = None;
    // Controlled fixture repair using the model's exact bytes; never an archive
    // fallback, witness, or recommended operator recovery procedure.
    fixture.replace(&model.raw);
    model.disk = Some(model.raw.clone());
    reopen_latest(live, fixture, ledger, model);
}

#[hegel::test(test_cases = 64)]
fn interleaved_archive_histories(tc: TestCase) {
    let fixture = Sandbox::new();
    let ledger = checked();
    let claims = claims(&ledger);
    let (archive, initial) =
        RotationArchive::create_new(fixture.archive(), &ledger, old(), CAPACITY).unwrap();
    let mut live = Some(archive);
    let mut model = Model::new(fs::read(fixture.data()).unwrap(), initial);

    // Minimal useful prefix; the following commands are drawn at execution time.
    for kind in 0..3 {
        append_invalid(&mut live, &claims, 0, kind);
        check(&fixture, &live, &model, &claims);
    }
    append_valid(&mut live, &mut model, &claims, 0);
    append_valid(&mut live, &mut model, &claims, 0);
    check(&fixture, &live, &model, &claims);
    let steps = tc.draw(gs::integers::<usize>().min_value(1).max_value(12));
    for _ in 0..steps {
        if live.is_none() {
            // After a cut or missing file, draw a recovery action from the
            // current state rather than silently dropping append commands.
            if tc.draw(gs::booleans()) {
                restore(&mut live, &fixture, &ledger, &mut model);
            } else {
                reopen_latest(&mut live, &fixture, &ledger, &model);
            }
            check(&fixture, &live, &model, &claims);
            continue;
        }
        match tc.draw(gs::integers::<u8>().max_value(11)) {
            0..=2 => {
                let i = tc.draw(gs::integers::<usize>().max_value(claims.len() - 1));
                append_valid(&mut live, &mut model, &claims, i);
            }
            3 => {
                let i = tc.draw(gs::integers::<usize>().max_value(model.evidence.len() - 1));
                let claim = model.evidence[i];
                append_valid(&mut live, &mut model, &claims, claim);
            }
            4..=6 => {
                let i = tc.draw(gs::integers::<usize>().max_value(claims.len() - 1));
                let kind = tc.draw(gs::integers::<u8>().max_value(2));
                append_invalid(&mut live, &claims, i, kind);
            }
            7 => reopen_latest(&mut live, &fixture, &ledger, &model),
            8 => reopen_stale(&mut live, &fixture, &ledger, &model),
            9 => cut(
                &mut live,
                &fixture,
                &ledger,
                &mut model,
                tc.draw(gs::booleans()),
            ),
            10 => restore(&mut live, &fixture, &ledger, &mut model),
            _ => erase(&mut live, &fixture, &ledger, &mut model),
        }
        check(&fixture, &live, &model, &claims);
    }

    // Deterministic tail makes every generated case cover conflict, capacity,
    // stale pin, torn/rolled-back bytes and absence despite shrinking.
    restore(&mut live, &fixture, &ledger, &mut model);
    while model.evidence.len() < CAPACITY {
        let i = (0..claims.len())
            .find(|i| !model.evidence.contains(i))
            .unwrap();
        append_valid(&mut live, &mut model, &claims, i);
    }
    if !model.exhausted {
        let i = (0..claims.len())
            .find(|i| !model.evidence.contains(i))
            .unwrap();
        append_valid(&mut live, &mut model, &claims, i);
    }
    assert!(model.blocked());
    check(&fixture, &live, &model, &claims);
    reopen_stale(&mut live, &fixture, &ledger, &model);
    cut(&mut live, &fixture, &ledger, &mut model, false);
    cut(&mut live, &fixture, &ledger, &mut model, true);
    restore(&mut live, &fixture, &ledger, &mut model);
    erase(&mut live, &fixture, &ledger, &mut model);
    restore(&mut live, &fixture, &ledger, &mut model);
    check(&fixture, &live, &model, &claims);
}

// Minimized known-bad model mutation: "on stale pin, silently create empty".
// One valid record and a reopen with the previously saved empty pin kills it.
#[test]
fn stale_pin_must_not_reset_to_empty_mutant() {
    let fixture = Sandbox::new();
    let ledger = checked();
    let claims = claims(&ledger);
    let (mut archive, empty) =
        RotationArchive::create_new(fixture.archive(), &ledger, old(), CAPACITY).unwrap();
    let retained = archive.append(&claims[0].1, &claims[0].0).unwrap();
    assert!(matches!(retained, Append::Recorded(_)));
    drop(archive);
    // Known-bad oracle mutant: mismatch silently bootstraps from the old empty pin.
    // The real oracle refuses; its expected record is still held independently.
    let disk = fs::read(fixture.data()).unwrap();
    let mutant_records: Vec<usize> = if hash(&disk) != empty {
        vec![]
    } else {
        vec![0]
    };
    assert!(mutant_records.is_empty());
    assert_ne!(mutant_records, vec![0]);
    assert!(matches!(
        open(&fixture.archive(), &ledger, empty),
        Err(Error::CommitmentMismatch)
    ));
    assert_eq!(
        fs::read(fixture.data()).unwrap().len(),
        HEADER_BYTES + 35 + claims[0].1.len()
    );
}
