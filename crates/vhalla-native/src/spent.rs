//! Durable bounded single-use tracking for invitation nonces.
//!
//! `vhalla_session::SpentInvitationNonces` is deliberately in-memory; this
//! file-backed variant persists consumed nonces so an invitation cannot be
//! redeemed twice by one local identity across process restarts. The nonce
//! never reaches the wire, so single-use is necessarily a local
//! authorization boundary: the caller consumes at redemption, before
//! dialing. Each consume atomically republishes the whole bounded set —
//! `VSN1` followed by strictly ascending 32-byte nonces — through a
//! temporary sibling, a file sync, a rename and a directory sync.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 4] = b"VSN1";
/// Hard bound on distinct consumed nonces: 1024 ids = 32,772-byte file.
pub const SPENT_CAPACITY: usize = 1024;

/// Failure opening or consuming through a durable spent-nonce file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpentError {
    /// Filesystem operation failed.
    Io,
    /// The file is not a canonical spent set.
    Malformed,
    /// This nonce was consumed previously.
    AlreadySpent,
    /// The file already holds `SPENT_CAPACITY` distinct nonces.
    Capacity,
}

/// A durable bounded set of redeemed invitation nonces.
///
/// Missing files open empty; the file is created on the first consume.
/// Consumption is atomic within the process and durable across crashes:
/// the replacement file is fully synced before it is renamed over the old.
pub struct SpentFile {
    path: PathBuf,
    spent: BTreeSet<[u8; 32]>,
}

impl SpentFile {
    /// Open a spent set, decoding an existing file strictly or starting
    /// empty. Foreign entries, symlinks and noncanonical layouts fail closed.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SpentError> {
        let path = path.as_ref().to_path_buf();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            return Ok(Self {
                path,
                spent: BTreeSet::new(),
            });
        };
        if !meta.file_type().is_file() || meta.len() > (4 + 32 * SPENT_CAPACITY) as u64 {
            return Err(SpentError::Malformed);
        }
        let raw = fs::read(&path).map_err(|_| SpentError::Io)?;
        if raw.len() < 4 || raw.len() % 32 != 4 || &raw[..4] != MAGIC {
            return Err(SpentError::Malformed);
        }
        let mut spent = BTreeSet::new();
        for nonce in raw[4..].as_chunks::<32>().0 {
            if *nonce == [0; 32] || !spent.insert(*nonce) {
                // Reserved zero value or a duplicate entry is noncanonical.
                return Err(SpentError::Malformed);
            }
        }
        if raw[4..]
            .as_chunks::<32>()
            .0
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(SpentError::Malformed);
        }
        Ok(Self { path, spent })
    }

    /// The persisted set's hard admission bound.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        SPENT_CAPACITY
    }

    /// Distinct nonces currently recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.spent.len()
    }

    /// Whether no nonce has been consumed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.spent.is_empty()
    }

    /// Whether a nonce is already recorded spent.
    #[must_use]
    pub fn contains(&self, nonce: &[u8; 32]) -> bool {
        self.spent.contains(nonce)
    }

    /// Atomically record one nonce and republish the set durably.
    ///
    /// Duplicate, reserved and capacity-overflow nonces are rejected before
    /// any write; a consumed nonce is never evicted to admit a new one.
    pub fn consume(&mut self, nonce: [u8; 32]) -> Result<(), SpentError> {
        if nonce == [0; 32] {
            return Err(SpentError::Malformed);
        }
        if self.spent.contains(&nonce) {
            return Err(SpentError::AlreadySpent);
        }
        if self.spent.len() >= SPENT_CAPACITY {
            return Err(SpentError::Capacity);
        }
        self.spent.insert(nonce);
        self.publish()
    }

    fn publish(&self) -> Result<(), SpentError> {
        let mut raw = Vec::with_capacity(4 + 32 * self.spent.len());
        raw.extend_from_slice(MAGIC);
        for nonce in &self.spent {
            raw.extend_from_slice(nonce);
        }
        let tmp = self.path.with_extension("spent.tmp");
        {
            let mut file = File::create(&tmp).map_err(|_| SpentError::Io)?;
            file.write_all(&raw).map_err(|_| SpentError::Io)?;
            file.sync_all().map_err(|_| SpentError::Io)?;
        }
        fs::rename(&tmp, &self.path).map_err(|_| SpentError::Io)?;
        if let Some(parent) = self.path.parent() {
            File::open(parent)
                .and_then(|d| d.sync_all())
                .map_err(|_| SpentError::Io)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hegel::{generators as gs, HealthCheck, TestCase};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn dir() -> PathBuf {
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "spent-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn consumed_nonces_survive_reopen_and_never_repeat() {
        let dir = dir();
        let path = dir.join("identity.spent");
        let mut file = SpentFile::open(&path).unwrap();
        assert!(!file.contains(&[7; 32]));
        file.consume([7; 32]).unwrap();
        file.consume([9; 32]).unwrap();
        assert_eq!(file.len(), 2);
        drop(file);

        // A fresh process view sees the durable set.
        let mut file = SpentFile::open(&path).unwrap();
        assert!(file.contains(&[7; 32]) && file.contains(&[9; 32]));
        assert_eq!(file.consume([7; 32]), Err(SpentError::AlreadySpent));
        file.consume([5; 32]).unwrap();
        assert_eq!(file.len(), 3);
        assert_eq!(file.consume([0; 32]), Err(SpentError::Malformed));
    }

    #[test]
    fn malformed_and_capacity_fail_closed_without_mutation() {
        let dir = dir();
        let path = dir.join("identity.spent");
        std::fs::write(&path, b"not a spent set").unwrap();
        assert_eq!(
            SpentFile::open(&path).map(|_| ()),
            Err(SpentError::Malformed)
        );
        // Unsorted entries are noncanonical.
        let mut raw = b"VSN1".to_vec();
        raw.extend_from_slice(&[9; 32]);
        raw.extend_from_slice(&[7; 32]);
        std::fs::write(&path, &raw).unwrap();
        assert_eq!(
            SpentFile::open(&path).map(|_| ()),
            Err(SpentError::Malformed)
        );
        // Capacity fails closed and preserves existing entries.
        let mut raw = b"VSN1".to_vec();
        for i in 0..SPENT_CAPACITY {
            let mut nonce = [0u8; 32];
            nonce[..16].copy_from_slice(&(i as u128 + 1).to_be_bytes());
            raw.extend_from_slice(&nonce);
        }
        std::fs::write(&path, &raw).unwrap();
        let mut file = SpentFile::open(&path).unwrap();
        assert_eq!(file.consume([250; 32]), Err(SpentError::Capacity));
        assert_eq!(file.len(), SPENT_CAPACITY);
        assert!(!file.contains(&[9; 32]));
    }

    // -------------------------------------------------------------------
    // Generative Hegel properties over the durable spent set. Each case
    // draws an interleaved command sequence — consumes of fresh, repeated,
    // reserved and arbitrary nonces, mid-sequence reopens, malformed or
    // foreign on-disk state, and fast-forwards toward the capacity bound —
    // with generators fed from the state accumulated so far (the consumed
    // pool, the model set, the remaining slack). The oracle is exact:
    // `consume` returns precisely the verdict the model mandates and the
    // live and persisted sets are always exactly the model's consumed set.
    // `recovery_hegel.rs` in vhalla-ledger is the reference for the
    // draw-inside-the-loop style.
    // -------------------------------------------------------------------

    /// Small nonce-tag pool for drawn commands: tight enough that repeats
    /// are common; tag 0 encodes the reserved all-zero nonce.
    const POOL: u64 = 31;
    /// Namespace for nonces the test writes to disk directly; disjoint
    /// from `POOL` tags so a seeded or merged nonce is always fresh.
    const SEED_BASE: u64 = 1 << 40;

    /// A tag-encoded nonce: the tag fills the first eight bytes
    /// big-endian, so tag order is byte order.
    fn nonce(tag: u64) -> [u8; 32] {
        let mut nonce = [0u8; 32];
        nonce[..8].copy_from_slice(&tag.to_be_bytes());
        nonce
    }

    /// The exact byte layout `publish` emits for a spent set.
    fn canonical_bytes(spent: &BTreeSet<[u8; 32]>) -> Vec<u8> {
        let mut raw = Vec::with_capacity(4 + 32 * spent.len());
        raw.extend_from_slice(MAGIC);
        for nonce in spent {
            raw.extend_from_slice(nonce);
        }
        raw
    }

    /// Independent specification of the layout `open` accepts: the `VSN1`
    /// marker, a 4 mod 32 length inside the size bound, and strictly
    /// ascending nonzero entries.
    fn canonical(raw: &[u8]) -> Option<BTreeSet<[u8; 32]>> {
        if raw.len() < 4 || raw.len() % 32 != 4 || raw.len() > 4 + 32 * SPENT_CAPACITY {
            return None;
        }
        if &raw[..4] != MAGIC {
            return None;
        }
        let mut spent = BTreeSet::new();
        let mut previous = [0u8; 32];
        for (i, nonce) in raw[4..].as_chunks::<32>().0.iter().enumerate() {
            if *nonce == [0; 32] || (i > 0 && previous >= *nonce) {
                return None;
            }
            previous = *nonce;
            spent.insert(*nonce);
        }
        Some(spent)
    }

    /// The first tag-encoded nonce outside the model; always exists
    /// because the model never exceeds `SPENT_CAPACITY`.
    fn fresh_nonce(model: &BTreeSet<[u8; 32]>) -> [u8; 32] {
        (1u64..).map(nonce).find(|n| !model.contains(n)).unwrap()
    }

    /// The live handle and the persisted bytes are exactly the model set.
    fn audit(path: &Path, file: &SpentFile, model: &BTreeSet<[u8; 32]>) {
        assert_eq!(file.capacity(), SPENT_CAPACITY);
        assert_eq!(file.len(), model.len());
        assert_eq!(file.is_empty(), model.is_empty());
        for nonce in model {
            assert!(file.contains(nonce));
        }
        match fs::read(path) {
            Ok(raw) => assert_eq!(raw, canonical_bytes(model)),
            Err(_) => assert!(model.is_empty(), "consumed nonces left no file"),
        }
    }

    /// Guaranteed-malformed file contents: each drawn recipe violates one
    /// specific admission rule — marker, length modulo, ordering,
    /// uniqueness, the reserved zero, or the size bound.
    fn malformed_bytes(tc: &TestCase) -> Vec<u8> {
        match tc.draw(gs::integers::<u8>().max_value(5)) {
            // A foreign marker on an otherwise plausible layout.
            0 => {
                let mut raw = b"XSN1".to_vec();
                for _ in 0..tc.draw(gs::integers::<usize>().max_value(3)) {
                    raw.extend_from_slice(&nonce(
                        tc.draw(gs::integers::<u64>().min_value(1).max_value(POOL)),
                    ));
                }
                raw
            }
            // Fewer bytes than the marker.
            1 => b"VSN"[..tc.draw(gs::integers::<usize>().max_value(3))].to_vec(),
            // A length that is not 4 mod 32.
            2 => {
                let mut raw = MAGIC.to_vec();
                raw.resize(
                    4 + tc.draw(gs::integers::<usize>().min_value(1).max_value(31)),
                    7,
                );
                raw
            }
            // An out-of-order or duplicated entry pair.
            3 => {
                let a = tc.draw(gs::integers::<u64>().min_value(1).max_value(POOL));
                let b = tc.draw(gs::integers::<u64>().min_value(1).max_value(POOL));
                let mut raw = MAGIC.to_vec();
                raw.extend_from_slice(&nonce(a.max(b)));
                raw.extend_from_slice(&nonce(a.min(b)));
                raw
            }
            // The reserved all-zero nonce as an entry.
            4 => {
                let mut raw = MAGIC.to_vec();
                raw.extend_from_slice(&[0; 32]);
                raw.extend_from_slice(&nonce(
                    tc.draw(gs::integers::<u64>().min_value(1).max_value(POOL)),
                ));
                raw
            }
            // More entries than the bound admits: the size check fails
            // before a byte is decoded.
            _ => {
                let mut raw = Vec::with_capacity(4 + 32 * (SPENT_CAPACITY + 1));
                raw.extend_from_slice(MAGIC);
                for i in 0..=SPENT_CAPACITY as u64 {
                    raw.extend_from_slice(&nonce(SEED_BASE + i));
                }
                raw
            }
        }
    }

    /// Drawn command sequences against a real file: every `consume`
    /// returns exactly the model's verdict — `AlreadySpent` for a nonce
    /// the model holds, `Malformed` for the reserved zero, `Capacity` at
    /// the bound, `Ok` otherwise — a consumed nonce is still rejected
    /// after every reopen, malformed on-disk state fails closed without
    /// mutating a byte, and the live and persisted sets are always
    /// exactly the model's consumed set. Each step does real filesystem
    /// I/O, so only the `TooSlow` health check is suppressed.
    #[hegel::test(test_cases = 64, suppress_health_check = [HealthCheck::TooSlow])]
    fn interleaved_consume_reopen_corruption_preserves_spent_set(tc: TestCase) {
        let dir = dir();
        let path = dir.join("identity.spent");
        let mut file = SpentFile::open(&path).unwrap();
        // The exact durable model: every nonce the file must hold, plus an
        // insertion-ordered pool to draw guaranteed repeats from.
        let mut model = BTreeSet::new();
        let mut consumed: Vec<[u8; 32]> = Vec::new();
        let mut seed = SEED_BASE;
        for _ in 0..tc.draw(gs::integers::<usize>().max_value(23)) {
            match tc.draw(gs::integers::<u8>().max_value(99)) {
                // Consume a drawn nonce: a forced repeat, an arbitrary 32
                // bytes, or a pool tag (tag 0 is the reserved nonce).
                0..=49 => {
                    let n: [u8; 32] = if !consumed.is_empty() && tc.draw(gs::booleans()) {
                        consumed[tc.draw(gs::integers::<usize>().max_value(consumed.len() - 1))]
                    } else if tc.draw(gs::integers::<u8>().max_value(4)) == 4 {
                        tc.draw(gs::arrays(gs::integers::<u8>()))
                    } else {
                        // One in eight pool draws is the reserved zero tag.
                        let tag = if tc.draw(gs::integers::<u8>().max_value(7)) == 0 {
                            0
                        } else {
                            tc.draw(gs::integers::<u64>().min_value(1).max_value(POOL))
                        };
                        nonce(tag)
                    };
                    let want = if n == [0; 32] {
                        Err(SpentError::Malformed)
                    } else if model.contains(&n) {
                        Err(SpentError::AlreadySpent)
                    } else if model.len() >= SPENT_CAPACITY {
                        Err(SpentError::Capacity)
                    } else {
                        Ok(())
                    };
                    assert_eq!(file.consume(n), want);
                    if want.is_ok() {
                        model.insert(n);
                        consumed.push(n);
                    }
                    assert_eq!(file.len(), model.len());
                    assert_eq!(file.contains(&n), model.contains(&n));
                }
                // Reopen mid-sequence: the durable set is exactly the
                // model and a drawn consumed nonce is still rejected.
                50..=69 => {
                    drop(file);
                    file = SpentFile::open(&path).unwrap();
                    audit(&path, &file, &model);
                    if !consumed.is_empty() {
                        let n = consumed
                            [tc.draw(gs::integers::<usize>().max_value(consumed.len() - 1))];
                        assert_eq!(file.consume(n), Err(SpentError::AlreadySpent));
                    }
                }
                // Malformed or foreign on-disk state behind a dropped
                // handle fails closed and leaves every byte untouched;
                // restoring the canonical model encoding reopens exactly
                // the model set.
                70..=89 => {
                    drop(file);
                    match tc.draw(gs::integers::<u8>().max_value(9)) {
                        // Foreign entries are refused before any decode.
                        0 => {
                            if fs::symlink_metadata(&path).is_ok() {
                                fs::remove_file(&path).unwrap();
                            }
                            fs::create_dir(&path).unwrap();
                            assert_eq!(
                                SpentFile::open(&path).map(|_| ()),
                                Err(SpentError::Malformed)
                            );
                            assert!(fs::symlink_metadata(&path).unwrap().is_dir());
                            fs::remove_dir(&path).unwrap();
                        }
                        1 => {
                            if fs::symlink_metadata(&path).is_ok() {
                                fs::remove_file(&path).unwrap();
                            }
                            std::os::unix::fs::symlink(dir.join("target"), &path).unwrap();
                            assert_eq!(
                                SpentFile::open(&path).map(|_| ()),
                                Err(SpentError::Malformed)
                            );
                            assert!(fs::symlink_metadata(&path)
                                .unwrap()
                                .file_type()
                                .is_symlink());
                            fs::remove_file(&path).unwrap();
                        }
                        // Crash residue: a leftover publish sibling does
                        // not affect admission and is not disturbed.
                        2 => {
                            let tmp = path.with_extension("spent.tmp");
                            let garbage = tc.draw(gs::binary().min_size(1).max_size(64));
                            fs::write(&tmp, &garbage).unwrap();
                            if fs::symlink_metadata(&path).is_err() {
                                fs::write(&path, canonical_bytes(&model)).unwrap();
                            }
                            let reopened = SpentFile::open(&path).unwrap();
                            audit(&path, &reopened, &model);
                            drop(reopened);
                            assert_eq!(fs::read(&tmp).unwrap(), garbage);
                            fs::remove_file(&tmp).unwrap();
                        }
                        _ => {
                            let raw = malformed_bytes(&tc);
                            fs::write(&path, &raw).unwrap();
                            assert_eq!(
                                SpentFile::open(&path).map(|_| ()),
                                Err(SpentError::Malformed)
                            );
                            assert_eq!(fs::read(&path).unwrap(), raw);
                        }
                    }
                    fs::write(&path, canonical_bytes(&model)).unwrap();
                    file = SpentFile::open(&path).unwrap();
                    audit(&path, &file, &model);
                }
                // A canonical file holding foreign entries on top of the
                // model — an operator restore — is adopted exactly: the
                // set still grows only and stays exactly the model.
                90..=94 => {
                    drop(file);
                    for _ in 0..tc.draw(gs::integers::<usize>().max_value(4)) {
                        if model.len() < SPENT_CAPACITY {
                            let n = nonce(seed);
                            seed += 1;
                            model.insert(n);
                            consumed.push(n);
                        }
                    }
                    fs::write(&path, canonical_bytes(&model)).unwrap();
                    file = SpentFile::open(&path).unwrap();
                    audit(&path, &file, &model);
                }
                // Fast-forward to a drawn distance below the bound, then
                // fill the remainder through the API: the first nonce
                // past `SPENT_CAPACITY` is refused and nothing mutates.
                _ => {
                    let slack = SPENT_CAPACITY - model.len();
                    let leave = tc.draw(gs::integers::<usize>().max_value(slack.min(3)));
                    if slack > 0 {
                        drop(file);
                        while model.len() + leave < SPENT_CAPACITY {
                            let n = nonce(seed);
                            seed += 1;
                            model.insert(n);
                            consumed.push(n);
                        }
                        fs::write(&path, canonical_bytes(&model)).unwrap();
                        file = SpentFile::open(&path).unwrap();
                        audit(&path, &file, &model);
                    }
                    for _ in 0..leave {
                        let n = fresh_nonce(&model);
                        assert_eq!(file.consume(n), Ok(()));
                        model.insert(n);
                        consumed.push(n);
                    }
                    assert_eq!(file.len(), SPENT_CAPACITY);
                    assert_eq!(file.consume(fresh_nonce(&model)), Err(SpentError::Capacity));
                    assert_eq!(file.len(), SPENT_CAPACITY);
                }
            }
        }
        // A fresh process view of the final durable state is the model.
        drop(file);
        let file = SpentFile::open(&path).unwrap();
        audit(&path, &file, &model);
        let _ = fs::remove_dir_all(&dir);
    }

    /// The decode boundary is exact: drawn bytes open if and only if they
    /// are the canonical encoding — `VSN1` plus strictly ascending
    /// nonzero entries inside the size bound — and then contain exactly
    /// those entries. A rejected file is never mutated. Each case writes
    /// and reopens a real file, so only `TooSlow` is suppressed.
    #[hegel::test(test_cases = 64, suppress_health_check = [HealthCheck::TooSlow])]
    fn open_decodes_exactly_the_canonical_encoding(tc: TestCase) {
        let dir = dir();
        let path = dir.join("identity.spent");
        // Entries in drawn order: duplicates, the reserved zero and
        // descending pairs all occur in the raw candidate bytes.
        let mut raw = MAGIC.to_vec();
        let mut built = BTreeSet::new();
        for _ in 0..tc.draw(gs::integers::<usize>().max_value(5)) {
            let n = nonce(tc.draw(gs::integers::<u64>().max_value(POOL)));
            raw.extend_from_slice(&n);
            built.insert(n);
        }
        match tc.draw(gs::integers::<u8>().max_value(5)) {
            // As drawn: canonical or not, the oracle decides.
            0 => {}
            // A foreign marker.
            1 => raw[0] = b'X',
            // Truncation to a drawn length.
            2 => raw.truncate(tc.draw(gs::integers::<usize>().max_value(raw.len()))),
            // Trailing junk of a drawn length.
            3 => raw.extend_from_slice(&tc.draw(gs::binary().min_size(1).max_size(33))),
            // Scrambled entry bytes.
            4 => raw[4..].reverse(),
            // The canonical encoding of the drawn nonces.
            _ => {
                built.remove(&[0; 32]);
                raw = canonical_bytes(&built);
            }
        }
        fs::write(&path, &raw).unwrap();
        match (canonical(&raw), SpentFile::open(&path)) {
            (Some(spent), Ok(file)) => {
                assert_eq!(file.len(), spent.len());
                assert_eq!(file.is_empty(), spent.is_empty());
                for nonce in &spent {
                    assert!(file.contains(nonce));
                }
            }
            (None, Err(SpentError::Malformed)) => {}
            (want, got) => panic!("decode diverged: {want:?} vs {:?}", got.map(|_| ())),
        }
        assert_eq!(fs::read(&path).unwrap(), raw, "open must never mutate");
        let _ = fs::remove_dir_all(&dir);
    }
}
