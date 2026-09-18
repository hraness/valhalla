#![cfg(unix)]
//! Generative custody properties under Hegel's interleaved draw model.
//!
//! `custody.rs` pins each custody rule with a fixed trace; these properties
//! draw the trace instead — interleaved command sequences over a small pool
//! of identity directories: creates, opens, drops, sign operations, drawn
//! corruption/tampering of the on-disk records, interrupted publication
//! residue, permission/link changes and stale session material. A
//! filesystem-level model replaying `Identity::open`'s exact check order —
//! including inode-level link tracking — predicts every verdict, so an
//! order-dependent divergence (a silently repaired record, a substituted
//! key, an accepted stale nonce, a signature under a foreign key) fails the
//! case and shrinks.
//!
//! `recovery_hegel.rs` in vhalla-ledger is the reference for the
//! draw-inside-the-loop style.

use std::{
    collections::BTreeMap,
    fs::{self, DirBuilder, OpenOptions},
    io::Write,
    os::unix::fs::{symlink, DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use hegel::{generators as gs, HealthCheck, TestCase};
use sha2::{Digest, Sha256};
use vhalla_core::{Epoch, EventId, PeerId, RealmId, RoomId, Sequence};
use vhalla_crypto::{
    peer_id_from_key, verifying_key_from_seed, ReplayWindow, SessionId, SignError,
    VerificationContext, VerifyError, VerifyingKey,
};
use vhalla_identity::{Identity, IdentityError};
use vhalla_session::{ChatSession, Pairing, Reject};
use vhalla_wire::Envelope;

/// Identity slots inside one case's scratch directory.
const SLOTS: [&str; 3] = ["a", "b", "c"];

/// On-disk record layout, mirrored from the implementation for test-side
/// crafting/substitution: magic, seed, then the SHA-256 content checksum.
const MAGIC: &[u8; 8] = b"VHID0001";
const RECORD_BYTES: usize = 72;

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!(
            "vhalla-identity-hegel-{:032x}",
            u128::from_be_bytes(nonce)
        ));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A syntactically valid identity record for `seed`, exactly what
/// `create_new` publishes — or what a hostile host could plant.
fn crafted_record(seed: [u8; 32]) -> Vec<u8> {
    let mut record = vec![0; RECORD_BYTES];
    record[..8].copy_from_slice(MAGIC);
    record[8..40].copy_from_slice(&seed);
    let digest = Sha256::digest(&record[..40]);
    record[40..].copy_from_slice(&digest);
    record
}

fn seed_key(seed: [u8; 32]) -> [u8; 32] {
    verifying_key_from_seed(seed).to_bytes()
}

fn create_private_file(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}

/// Rewrite a file regardless of its current mode, then restore the mode.
/// The fault model treats the host as privileged over its own files, so
/// a prior `expose-record` that set a file read-only must not prevent a
/// later hostile rewrite.
fn overwrite(path: &Path, bytes: &[u8]) {
    let original = path.metadata().unwrap().permissions();
    let mut writable = original.clone();
    writable.set_mode(0o600);
    fs::set_permissions(path, writable).unwrap();
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, original).unwrap();
}

/// One directory entry as `open` sees it through `symlink_metadata` plus the
/// record decoder. `inode` groups names sharing one filesystem object —
/// content and mode changes propagate across hardlinks; `file` is a property
/// of the name itself (a symlink entry is never a file).
#[derive(Clone)]
struct Entry {
    file: bool,
    inode: u64,
    mode: u32,
    len: u64,
    /// `Some(key)` iff the content is a 72-byte record decoding to that key.
    good_key: Option<[u8; 32]>,
}

impl Entry {
    fn lock(inode: u64) -> Self {
        Self {
            file: true,
            inode,
            mode: 0o600,
            len: 0,
            good_key: None,
        }
    }
    fn record(inode: u64, key: Option<[u8; 32]>) -> Self {
        Self {
            file: true,
            inode,
            mode: 0o600,
            len: RECORD_BYTES as u64,
            good_key: key,
        }
    }
    fn symlink(inode: u64) -> Self {
        Self {
            file: false,
            inode,
            mode: 0o777,
            len: 0,
            good_key: None,
        }
    }
}

/// The durable model of one identity slot. Every tamper lands here first and
/// the real filesystem is driven to match, so `predict` sees exactly what
/// `Identity::open` will.
#[derive(Default)]
struct DirModel {
    /// The path exists at all (as directory or injected plain file).
    exists: bool,
    /// A plain file sits at the directory path.
    is_file: bool,
    dir_mode: u32,
    /// Generation of the lock inode; bumped whenever the lock path is
    /// replaced. flock is bound to the inode, so a live handle only blocks
    /// opens while the same lock inode is intact.
    lock_gen: u64,
    entries: BTreeMap<&'static str, Entry>,
    /// Most recent decodable record bytes and key, for test-side repair.
    last_good: Option<(Vec<u8>, [u8; 32])>,
    /// The key `create_new` first minted at this slot — distinguishes an
    /// opened original from a substituted record in coverage events.
    origin: Option<[u8; 32]>,
    /// Inodes and paths this slot's tampers parked outside the directory
    /// (hardlink aliases, symlink stash targets); they share link counts.
    outside: Vec<(u64, PathBuf)>,
}

impl DirModel {
    /// Total link count an entry's inode reports: in-directory names plus
    /// outside links to the same inode.
    fn nlink(&self, inode: u64) -> u64 {
        (self.entries.values().filter(|e| e.inode == inode).count()
            + self.outside.iter().filter(|(i, _)| *i == inode).count()) as u64
    }
}

/// The exact verdict `Identity::open` must produce.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Open {
    Key([u8; 32]),
    Io,
    Unsafe,
    Corrupt,
    Busy,
}

/// The same decision procedure as `Identity::open`, run over the model:
/// directory metadata, lock metadata, the held-lock check, the exact
/// {lock, identity} entry set, then record metadata and content decode.
fn predict(dir: &DirModel, held: bool) -> Open {
    if !dir.exists {
        return Open::Io;
    }
    if dir.is_file || dir.dir_mode & 0o7777 != 0o700 {
        return Open::Unsafe;
    }
    match dir.entries.get("lock") {
        None => return Open::Io,
        Some(lock) => {
            if !lock.file || lock.mode & 0o7777 != 0o600 || dir.nlink(lock.inode) != 1 {
                return Open::Unsafe;
            }
            if lock.len != 0 {
                return Open::Corrupt;
            }
        }
    }
    if held {
        return Open::Busy;
    }
    if dir.entries.len() != 2
        || !dir.entries.contains_key("lock")
        || !dir.entries.contains_key("identity")
    {
        return Open::Corrupt;
    }
    let record = &dir.entries["identity"];
    if !record.file || record.mode & 0o7777 != 0o600 || dir.nlink(record.inode) != 1 {
        return Open::Unsafe;
    }
    if record.len != RECORD_BYTES as u64 {
        return Open::Corrupt;
    }
    match record.good_key {
        Some(key) => Open::Key(key),
        None => Open::Corrupt,
    }
}

/// Assert `Identity::open` produced exactly `want`; on a lawful success the
/// handle is returned and its key must equal the predicted one.
fn attempt_open(path: &Path, want: Open) -> Option<Identity> {
    match (Identity::open(path), want) {
        (Ok(identity), Open::Key(key)) => {
            assert_eq!(
                identity.public_key(),
                key,
                "open succeeded but returned a substituted key"
            );
            Some(identity)
        }
        (Ok(_), want) => panic!("open unexpectedly succeeded over {want:?} state"),
        (Err(IdentityError::UnsafePath), Open::Unsafe)
        | (Err(IdentityError::Corrupt), Open::Corrupt)
        | (Err(IdentityError::Busy), Open::Busy)
        | (Err(IdentityError::Io(_)), Open::Io) => None,
        (Err(error), want) => {
            panic!("open verdict diverged from the model: {error:?} vs {want:?}")
        }
    }
}

/// A live custodian handle: the key it was created/opened with and the lock
/// generation it holds. Signing custody follows the retained in-memory key,
/// never the current record bytes.
struct Handle {
    identity: Identity,
    key: [u8; 32],
    lock_gen: u64,
}

struct Case {
    temp: Temp,
    dirs: [DirModel; 3],
    live: [Vec<Handle>; 3],
    /// Fresh inode and lock-generation supply for the whole case.
    next: u64,
}

impl Case {
    fn new() -> Self {
        Self {
            temp: Temp::new(),
            dirs: [
                DirModel::default(),
                DirModel::default(),
                DirModel::default(),
            ],
            live: [Vec::new(), Vec::new(), Vec::new()],
            next: 0,
        }
    }

    fn fresh(&mut self) -> u64 {
        self.next += 1;
        self.next
    }

    fn path(&self, i: usize) -> PathBuf {
        self.temp.0.join(SLOTS[i])
    }

    /// A lock held by a live handle blocks opens only while the directory
    /// still shows the same lock inode.
    fn held(&self, i: usize) -> bool {
        self.live[i]
            .iter()
            .any(|h| h.lock_gen == self.dirs[i].lock_gen)
    }

    fn record_is_file(&self, i: usize) -> bool {
        self.dirs[i].entries.get("identity").is_some_and(|e| e.file)
    }

    /// Content write through a directory name: propagate length and decoded
    /// key to every in-directory name sharing the inode.
    fn wrote(&mut self, i: usize, inode: u64, len: u64, key: Option<[u8; 32]>) {
        for entry in self.dirs[i].entries.values_mut() {
            if entry.inode == inode {
                entry.len = len;
                entry.good_key = key;
            }
        }
    }

    /// Mode change through a directory name propagates across the inode.
    fn chmod(&mut self, i: usize, inode: u64, mode: u32) {
        for entry in self.dirs[i].entries.values_mut() {
            if entry.inode == inode {
                entry.mode = mode;
            }
        }
    }

    /// Open is never a repair: run it against the model's verdict and keep
    /// any lawful handle with its predicted key.
    fn open(&mut self, tc: &TestCase, i: usize) {
        let want = predict(&self.dirs[i], self.held(i));
        tc.event(match want {
            Open::Key(key) if self.dirs[i].origin == Some(key) => "open:original-key",
            Open::Key(_) => "open:substituted-key",
            Open::Io => "open:io",
            Open::Unsafe => "open:unsafe",
            Open::Corrupt => "open:corrupt",
            Open::Busy => "open:busy",
        });
        if let Some(identity) = attempt_open(&self.path(i), want) {
            let key = identity.public_key();
            let lock_gen = self.dirs[i].lock_gen;
            self.live[i].push(Handle {
                identity,
                key,
                lock_gen,
            });
        }
    }

    /// Creation succeeds only on an absent path; an existing path — whole,
    /// torn or hostile — is never reused.
    fn create(&mut self, tc: &TestCase, i: usize) {
        let path = self.path(i);
        if self.dirs[i].exists {
            tc.event("create:refused-existing");
            assert!(matches!(
                Identity::create_new(&path),
                Err(IdentityError::Io(_))
            ));
            return;
        }
        tc.event("create:ok");
        let identity = Identity::create_new(&path).unwrap();
        let key = identity.public_key();
        let lock_gen = self.fresh();
        let lock_inode = self.fresh();
        let record_inode = self.fresh();
        let bytes = fs::read(path.join("identity")).unwrap();
        let dir = &mut self.dirs[i];
        dir.exists = true;
        dir.is_file = false;
        dir.dir_mode = 0o700;
        dir.lock_gen = lock_gen;
        dir.entries.insert("lock", Entry::lock(lock_inode));
        dir.entries
            .insert("identity", Entry::record(record_inode, Some(key)));
        dir.last_good = Some((bytes, key));
        dir.origin = Some(key);
        self.live[i].push(Handle {
            identity,
            key,
            lock_gen,
        });
    }

    fn drop(&mut self, tc: &TestCase, i: usize) {
        if self.live[i].is_empty() {
            return self.open(tc, i);
        }
        let h = tc.draw(gs::integers::<usize>().max_value(self.live[i].len() - 1));
        tc.event("drop:handle");
        self.live[i].swap_remove(h);
    }

    /// Opening through a symlink alias is always `UnsafePath`, whatever the
    /// target's state — `symlink_metadata` never follows the link.
    fn alias_open(&mut self, tc: &TestCase, i: usize) {
        let alias = self.temp.0.join(format!("alias-{i}"));
        if fs::symlink_metadata(&alias).is_err() {
            symlink(self.path(i), &alias).unwrap();
        }
        tc.event("open:alias-unsafe");
        assert!(attempt_open(&alias, Open::Unsafe).is_none());
    }

    /// Interrupted `create_new` residue at a drawn publication stage. The
    /// debris must fail `open` without repair and block `create_new` forever.
    fn interrupted_create(&mut self, tc: &TestCase, i: usize) {
        if self.dirs[i].exists {
            return self.open(tc, i);
        }
        let path = self.path(i);
        let stage = tc.draw(gs::integers::<u8>().max_value(3));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        let lock_gen = self.fresh();
        let lock_inode = self.fresh();
        let tmp_inode = self.fresh();
        let dir = &mut self.dirs[i];
        dir.exists = true;
        dir.dir_mode = 0o700;
        dir.lock_gen = lock_gen;
        if stage >= 1 {
            create_private_file(&path.join("lock"), &[]);
            dir.entries.insert("lock", Entry::lock(lock_inode));
        }
        if stage >= 2 {
            let seed = [tc.draw(gs::integers::<u8>()); 32];
            let bytes = crafted_record(seed);
            create_private_file(&path.join("identity.tmp"), &bytes);
            let tmp = Entry::record(tmp_inode, Some(seed_key(seed)));
            dir.entries.insert("identity.tmp", tmp);
            dir.last_good = Some((bytes, seed_key(seed)));
        }
        if stage == 3 {
            // Publication ran; the temporary name was never cleaned. The
            // published name shares the temporary file's inode.
            fs::hard_link(path.join("identity.tmp"), path.join("identity")).unwrap();
            let inode = self.dirs[i].entries["identity.tmp"].inode;
            let key = self.dirs[i].entries["identity.tmp"].good_key;
            self.dirs[i]
                .entries
                .insert("identity", Entry::record(inode, key));
        }
        tc.event(format!("interrupted:stage-{stage}"));
        let want = predict(&self.dirs[i], false);
        assert!(attempt_open(&path, want).is_none());
        assert!(matches!(
            Identity::create_new(&path),
            Err(IdentityError::Io(_))
        ));
    }

    /// One drawn hostile mutation, mirrored into the model. Fallbacks keep
    /// every step meaningful when the drawn op's precondition is absent.
    fn tamper(&mut self, tc: &TestCase, i: usize) {
        if !self.dirs[i].exists {
            return self.create(tc, i);
        }
        let path = self.path(i);
        let record = path.join("identity");
        match tc.draw(gs::integers::<u8>().max_value(11)) {
            // A single bit anywhere breaks magic, seed or checksum.
            0 if self.record_is_file(i) => {
                tc.event("tamper:bit-flip");
                let mut bytes = fs::read(&record).unwrap();
                let offset = tc.draw(gs::integers::<usize>().max_value(bytes.len() - 1));
                let bit = tc.draw(gs::integers::<u8>().max_value(7));
                bytes[offset] ^= 1 << bit;
                overwrite(&record, &bytes);
                let inode = self.dirs[i].entries["identity"].inode;
                self.wrote(i, inode, bytes.len() as u64, None);
            }
            // Truncated, partial or oversized records.
            1 if self.record_is_file(i) => {
                const LENS: [usize; 7] = [0, 7, 39, 71, 72, 73, 1024];
                let len = LENS[tc.draw(gs::integers::<usize>().max_value(6))];
                let fill = tc.draw(gs::integers::<u8>());
                tc.event("tamper:rewrite");
                overwrite(&record, &vec![fill; len]);
                let inode = self.dirs[i].entries["identity"].inode;
                self.wrote(i, inode, len as u64, None);
            }
            // A syntactically valid record for a drawn foreign seed — a
            // hostile host can substitute keys; open must then return exactly
            // that planted key, never the original.
            2 if self.record_is_file(i) => {
                let seed = [tc.draw(gs::integers::<u8>()); 32];
                let bytes = crafted_record(seed);
                tc.event("tamper:substitute");
                overwrite(&record, &bytes);
                let key = seed_key(seed);
                let inode = self.dirs[i].entries["identity"].inode;
                self.wrote(i, inode, RECORD_BYTES as u64, Some(key));
                self.dirs[i].last_good = Some((bytes, key));
            }
            3 if self.record_is_file(i) => {
                const MODES: [u32; 4] = [0o640, 0o644, 0o400, 0o777];
                let mode = MODES[tc.draw(gs::integers::<usize>().max_value(3))];
                tc.event("tamper:expose-record");
                fs::set_permissions(&record, fs::Permissions::from_mode(mode)).unwrap();
                let inode = self.dirs[i].entries["identity"].inode;
                self.chmod(i, inode, mode);
            }
            4 if !self.dirs[i].is_file => {
                const MODES: [u32; 3] = [0o750, 0o755, 0o777];
                let mode = MODES[tc.draw(gs::integers::<usize>().max_value(2))];
                tc.event("tamper:expose-dir");
                fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
                self.dirs[i].dir_mode = mode;
            }
            // An unexpected directory entry: junk, or a torn `identity.tmp`.
            5 if !self.dirs[i].is_file => {
                const NAMES: [&str; 3] = ["extra", "identity.tmp", "junk"];
                tc.event("tamper:junk-entry");
                let name = NAMES[tc.draw(gs::integers::<usize>().max_value(2))];
                let (bytes, key) = if name == "identity.tmp" {
                    let seed = [tc.draw(gs::integers::<u8>()); 32];
                    (crafted_record(seed), Some(seed_key(seed)))
                } else {
                    (Vec::new(), None)
                };
                let target = path.join(name);
                if let Some(existing) = self.dirs[i].entries.get(name) {
                    // Overwrite in place: inode sharing stays intact.
                    overwrite(&target, &bytes);
                    let inode = existing.inode;
                    self.wrote(i, inode, bytes.len() as u64, key);
                } else {
                    create_private_file(&target, &bytes);
                    let mut entry = Entry::lock(self.fresh());
                    entry.len = bytes.len() as u64;
                    entry.good_key = key;
                    self.dirs[i].entries.insert(name, entry);
                }
            }
            // The published name moved back to the temporary one; the inode
            // and its content are untouched by the rename.
            6 if self.record_is_file(i) && !self.dirs[i].entries.contains_key("identity.tmp") => {
                tc.event("tamper:rename-to-tmp");
                fs::rename(&record, path.join("identity.tmp")).unwrap();
                let entry = self.dirs[i].entries.remove("identity").unwrap();
                self.dirs[i].entries.insert("identity.tmp", entry);
            }
            // An extra hardlink to the record inode from outside the dir.
            7 if self.record_is_file(i) => {
                let alias = self.temp.0.join(format!("link-{i}-{}", self.next + 1));
                tc.event("tamper:link-out");
                fs::hard_link(&record, &alias).unwrap();
                let inode = self.dirs[i].entries["identity"].inode;
                self.fresh();
                self.dirs[i].outside.push((inode, alias));
            }
            // The record path swapped for a symlink to a stashed inode.
            8 if self.record_is_file(i) => {
                let stash = self.temp.0.join(format!("stash-{i}-{}", self.next + 1));
                tc.event("tamper:symlink-record");
                fs::rename(&record, &stash).unwrap();
                symlink(&stash, &record).unwrap();
                let inode = self.dirs[i].entries["identity"].inode;
                self.fresh();
                self.dirs[i].outside.push((inode, stash));
                let slink = Entry::symlink(self.fresh());
                self.dirs[i].entries.insert("identity", slink);
            }
            9 if self.dirs[i].entries.contains_key("identity") => {
                tc.event("tamper:drop-record");
                fs::remove_file(&record).unwrap();
                self.dirs[i].entries.remove("identity");
            }
            // Lock tampering: garbage content, exposed permissions, removal,
            // a symlink — or replacement, which severs Busy on the old inode.
            10 if !self.dirs[i].is_file => {
                match tc.draw(gs::integers::<u8>().max_value(4)) {
                    0 => {
                        tc.event("tamper:lock-write");
                        let len = tc.draw(gs::integers::<u64>().min_value(1).max_value(8));
                        let lock = path.join("lock");
                        match self.dirs[i].entries.get("lock") {
                            Some(entry) if entry.file => {
                                overwrite(&lock, &vec![7; len as usize]);
                                let inode = entry.inode;
                                self.wrote(i, inode, len, None);
                            }
                            // A symlinked lock: the write flows to the stash
                            // inode outside; the entry itself is unchanged.
                            Some(_) => {
                                let _ = fs::write(&lock, vec![7; len as usize]);
                            }
                            None => {
                                create_private_file(&lock, &vec![7; len as usize]);
                                let mut entry = Entry::lock(self.fresh());
                                entry.len = len;
                                self.dirs[i].entries.insert("lock", entry);
                            }
                        }
                    }
                    1 if self.dirs[i].entries.get("lock").is_some_and(|e| e.file) => {
                        const MODES: [u32; 3] = [0o640, 0o400, 0o644];
                        let mode = MODES[tc.draw(gs::integers::<usize>().max_value(2))];
                        tc.event("tamper:lock-mode");
                        fs::set_permissions(path.join("lock"), fs::Permissions::from_mode(mode))
                            .unwrap();
                        let inode = self.dirs[i].entries["lock"].inode;
                        self.chmod(i, inode, mode);
                    }
                    2 if self.dirs[i].entries.get("lock").is_some_and(|e| e.file) => {
                        let stash = self.temp.0.join(format!("lstash-{i}-{}", self.next + 1));
                        tc.event("tamper:lock-symlink");
                        fs::rename(path.join("lock"), &stash).unwrap();
                        symlink(&stash, path.join("lock")).unwrap();
                        let inode = self.dirs[i].entries["lock"].inode;
                        self.fresh();
                        self.dirs[i].outside.push((inode, stash));
                        let slink = Entry::symlink(self.fresh());
                        self.dirs[i].entries.insert("lock", slink);
                    }
                    3 if self.dirs[i].entries.contains_key("lock") => {
                        tc.event("tamper:lock-remove");
                        fs::remove_file(path.join("lock")).unwrap();
                        self.dirs[i].entries.remove("lock");
                    }
                    // A fresh lock inode: a held handle no longer blocks.
                    _ => {
                        let lock = path.join("lock");
                        if fs::symlink_metadata(&lock).is_ok() {
                            fs::remove_file(&lock).unwrap();
                        }
                        tc.event("tamper:lock-replace");
                        create_private_file(&lock, &[]);
                        self.gen_lock(i);
                    }
                }
            }
            // The whole directory path replaced by a plain file.
            _ if !self.dirs[i].is_file => {
                tc.event("tamper:dir-to-file");
                fs::remove_dir_all(&path).unwrap();
                create_private_file(&path, b"not-a-directory");
                let gen = self.fresh();
                let dir = &mut self.dirs[i];
                dir.is_file = true;
                dir.entries.clear();
                dir.outside.clear();
                dir.lock_gen = gen;
            }
            _ => self.open(tc, i),
        }
    }

    /// Replace the lock path with a fresh empty private file and bump the
    /// lock generation: the inode the live handles hold is severed.
    fn gen_lock(&mut self, i: usize) {
        let gen = self.fresh();
        let inode = self.fresh();
        let dir = &mut self.dirs[i];
        dir.entries.insert("lock", Entry::lock(inode));
        dir.lock_gen = gen;
    }

    /// Test-side repair — never the implementation's. Each op restores one
    /// modeled aspect; the next `open` still has to match `predict`.
    fn heal(&mut self, tc: &TestCase, i: usize) {
        if !self.dirs[i].exists {
            return self.create(tc, i);
        }
        let path = self.path(i);
        match tc.draw(gs::integers::<u8>().max_value(6)) {
            // Rewrite the most recent decodable record as a fresh inode.
            0 if self.dirs[i].last_good.is_some() && !self.dirs[i].is_file => {
                let record = path.join("identity");
                if fs::symlink_metadata(&record).is_ok() {
                    fs::remove_file(&record).unwrap();
                }
                let (bytes, key) = self.dirs[i].last_good.clone().unwrap();
                tc.event("heal:restore-record");
                create_private_file(&record, &bytes);
                let entry = Entry::record(self.fresh(), Some(key));
                self.dirs[i].entries.insert("identity", entry);
            }
            1 if self.record_is_file(i) => {
                tc.event("heal:record-mode");
                fs::set_permissions(path.join("identity"), fs::Permissions::from_mode(0o600))
                    .unwrap();
                let inode = self.dirs[i].entries["identity"].inode;
                self.chmod(i, inode, 0o600);
            }
            2 if !self.dirs[i].is_file => {
                tc.event("heal:dir-mode");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
                self.dirs[i].dir_mode = 0o700;
            }
            // Drop every unexpected name (torn `identity.tmp`, junk); link
            // counts on shared inodes drop with the removed names.
            3 if !self.dirs[i].is_file => {
                tc.event("heal:clean-entries");
                let extra: Vec<&'static str> = self.dirs[i]
                    .entries
                    .keys()
                    .filter(|n| **n != "lock" && **n != "identity")
                    .copied()
                    .collect();
                for name in extra {
                    fs::remove_file(path.join(name)).unwrap();
                    self.dirs[i].entries.remove(name);
                }
            }
            // A fresh lock inode — repairs absence and severs held locks.
            4 if !self.dirs[i].is_file => {
                let lock = path.join("lock");
                if fs::symlink_metadata(&lock).is_ok() {
                    fs::remove_file(&lock).unwrap();
                }
                tc.event("heal:fresh-lock");
                create_private_file(&lock, &[]);
                self.gen_lock(i);
            }
            // Unlink every outside alias; in-directory link counts shrink.
            5 => {
                tc.event("heal:unlink-outside");
                let outside = std::mem::take(&mut self.dirs[i].outside);
                for (_, alias) in outside {
                    let _ = fs::remove_file(alias);
                }
            }
            // Rebuild a replaced directory path as an empty private dir.
            6 if self.dirs[i].is_file => {
                fs::remove_file(&path).unwrap();
                tc.event("heal:restore-dir");
                DirBuilder::new().mode(0o700).create(&path).unwrap();
                let dir = &mut self.dirs[i];
                dir.is_file = false;
                dir.dir_mode = 0o700;
            }
            _ => self.open(tc, i),
        }
    }

    /// Sign a drawn envelope with a live handle. Custody binds the retained
    /// key: a foreign author handle is refused, a correct one verifies only
    /// under exactly that key and exactly the drawn context — never a wrong
    /// key, another session, an expired window, a replay, or a forged
    /// signature.
    fn sign(&mut self, tc: &TestCase, i: usize) {
        if self.live[i].is_empty() {
            return self.open(tc, i);
        }
        let h = tc.draw(gs::integers::<usize>().max_value(self.live[i].len() - 1));
        let handle = &self.live[i][h];
        let key = VerifyingKey::from_bytes(&handle.key).unwrap();
        let author = peer_id_from_key(&key);
        let claimed = if tc.draw(gs::booleans()) {
            author
        } else {
            PeerId(author.0 ^ (1u128 << tc.draw(gs::integers::<u32>().max_value(127))))
        };
        let context = VerificationContext {
            audience: PeerId(tc.draw(gs::integers::<u128>())),
            realm: RealmId(tc.draw(gs::integers::<u128>())),
            room: RoomId(tc.draw(gs::integers::<u128>())),
            epoch: Epoch(tc.draw(gs::integers::<u64>())),
            session: SessionId(tc.draw(gs::integers::<u128>())),
        };
        let body = tc.draw(gs::vecs(gs::integers::<u8>()).max_size(23));
        let envelope = Envelope::chat(
            claimed,
            context.realm,
            context.room,
            EventId(tc.draw(gs::integers::<u128>())),
            Sequence(tc.draw(gs::integers::<u64>().min_value(1).max_value(4))),
            &body,
        )
        .unwrap();
        let expires_at = tc.draw(gs::integers::<u64>().min_value(4).max_value(100));
        match handle.identity.sign_envelope(envelope, context, expires_at) {
            Ok(signed) => {
                tc.event("sign:ok");
                assert_eq!(claimed, author, "custody signed for a foreign author");
                let now = tc.draw(gs::integers::<u64>().max_value(expires_at));
                let mut window = ReplayWindow::new(context, 4).unwrap();
                let verified = window.verify_and_accept(signed.clone(), &key, now).unwrap();
                assert_eq!(verified.envelope().body(), body);
                assert_eq!(verified.signer_key(), &handle.key);
                // The same frame is admitted exactly once.
                assert!(matches!(
                    window.verify_and_accept(signed.clone(), &key, now),
                    Err(VerifyError::Replay)
                ));
                // No other key can have produced this signature.
                let wrong = verifying_key_from_seed([77; 32]);
                let mut foreign = ReplayWindow::new(context, 4).unwrap();
                assert!(matches!(
                    foreign.verify_and_accept(signed.clone(), &wrong, now),
                    Err(VerifyError::AuthorMismatch)
                ));
                // A neighbouring session context rejects the signature.
                let other = VerificationContext {
                    session: SessionId(context.session.0 ^ 1),
                    ..context
                };
                let mut alien = ReplayWindow::new(other, 4).unwrap();
                assert!(matches!(
                    alien.verify_and_accept(signed.clone(), &key, now),
                    Err(VerifyError::SessionMismatch)
                ));
                // The signed expiry bound holds.
                let mut late = ReplayWindow::new(context, 4).unwrap();
                assert!(matches!(
                    late.verify_and_accept(signed.clone(), &key, expires_at + 1),
                    Err(VerifyError::Expired)
                ));
                // A tampered signature never verifies.
                let mut forged = signed;
                forged.signature[0] ^= 1;
                let mut fresh = ReplayWindow::new(context, 4).unwrap();
                assert!(matches!(
                    fresh.verify_and_accept(forged, &key, now),
                    Err(VerifyError::InvalidSignature)
                ));
            }
            Err(SignError::AuthorMismatch) => {
                tc.event("sign:author-mismatch");
                assert_ne!(claimed, author)
            }
            Err(error) => panic!("unexpected signing failure: {error:?}"),
        }
    }
}

/// Drawn interleavings of creates, opens, drops, hostile record/lock/dir
/// mutations, test-side repairs and sign operations over three identity
/// slots. The oracle asserts after every step that `Identity::open`'s exact
/// verdict — including which key it returns — equals the durable model, so
/// corrupted records are never silently repaired, a substituted valid record
/// yields exactly its planted key, held locks report `Busy` only while their
/// inode is intact, and signing custody never escapes the bound key.
///
/// Each step performs real filesystem I/O, so only `TooSlow` is suppressed.
#[hegel::test(test_cases = 128, suppress_health_check = [HealthCheck::TooSlow])]
fn interleaved_faults_preserve_exact_open_and_sign_semantics(tc: TestCase) {
    let mut case = Case::new();
    let steps = tc.draw(gs::integers::<usize>().min_value(1).max_value(24));
    for _ in 0..steps {
        let i = tc.draw(gs::integers::<usize>().max_value(2));
        match tc.draw(gs::integers::<usize>().max_value(99)) {
            0..=11 => case.create(&tc, i),
            12..=26 => case.open(&tc, i),
            27..=34 => case.drop(&tc, i),
            35..=64 => case.tamper(&tc, i),
            65..=71 => case.heal(&tc, i),
            72..=79 => case.interrupted_create(&tc, i),
            80..=89 => case.sign(&tc, i),
            _ => case.alias_open(&tc, i),
        }
    }
}

// ---------------------------------------------------------------------------
// Session custody: reopened identities keep their key but every stale
// handshake/chat artifact stays rejected.

const TRANSPORT_SEEDS: [[u8; 32]; 2] = [[3; 32], [4; 32]];

fn transport_key(n: usize) -> [u8; 32] {
    verifying_key_from_seed(TRANSPORT_SEEDS[n]).to_bytes()
}

/// One completed handshake generation and the raw material it produced.
struct Generation {
    a: ChatSession,
    b: ChatSession,
    hello: Vec<u8>,
    confirm: Vec<u8>,
}

/// A signed chat frame captured for replay attempts: its generation, the
/// encoded bytes and whether the live responder already consumed it.
struct Frame {
    generation: usize,
    sequence: u64,
    raw: Vec<u8>,
}

struct SessionCase {
    _temp: Temp,
    paths: [PathBuf; 3],
    keys: [[u8; 32]; 3],
    live: [Option<Identity>; 3],
    pairing: Pairing,
    generations: Vec<Generation>,
    /// Highest sequence each generation's responder has admitted.
    max_accepted: Vec<u64>,
    frames: Vec<Frame>,
    now: u64,
}

impl SessionCase {
    fn new() -> Self {
        let temp = Temp::new();
        let paths = [
            temp.0.join("initiator"),
            temp.0.join("responder"),
            temp.0.join("stranger"),
        ];
        let mut case = Self {
            _temp: temp,
            paths,
            keys: [[0; 32]; 3],
            live: [None, None, None],
            pairing: Pairing {
                initiator: [0; 32],
                responder: [0; 32],
                initiator_transport: transport_key(0),
                responder_transport: transport_key(1),
                realm: RealmId(1),
                room: RoomId(2),
                epoch: Epoch(3),
                expires_at: 1000,
            },
            generations: Vec::new(),
            max_accepted: Vec::new(),
            frames: Vec::new(),
            now: 10,
        };
        for i in 0..3 {
            case.ensure(i);
        }
        case.pairing.initiator = case.keys[0];
        case.pairing.responder = case.keys[1];
        case
    }

    fn ensure(&mut self, i: usize) {
        if self.live[i].is_some() {
            return;
        }
        let path = &self.paths[i];
        let identity = if path.exists() {
            Identity::open(path).unwrap()
        } else {
            Identity::create_new(path).unwrap()
        };
        let key = identity.public_key();
        if self.keys[i] == [0; 32] {
            self.keys[i] = key;
        }
        assert_eq!(key, self.keys[i], "reopen changed the identity's key");
        self.live[i] = Some(identity);
    }

    fn tick(&mut self, tc: &TestCase) {
        self.now += tc.draw(gs::integers::<u64>().max_value(3));
    }

    /// A handshake attempt with a drawn fault. Only the clean variant
    /// establishes a generation; every injected fault is refused at exactly
    /// the stage the protocol checks it.
    fn handshake(&mut self, tc: &TestCase) {
        self.ensure(0);
        self.ensure(1);
        self.tick(tc);
        let now = self.now;
        let deadline = now + 50;
        match tc.draw(gs::integers::<u8>().max_value(9)) {
            // A stranger key cannot initiate as the pinned initiator.
            0 => {
                let result = self.live[2].as_ref().unwrap().initiate_session(
                    self.pairing,
                    transport_key(0),
                    transport_key(1),
                    now,
                    deadline,
                );
                tc.event("handshake:reject-local-key");
                assert!(matches!(
                    result,
                    Err(IdentityError::Session(Reject::LocalKey))
                ));
            }
            // Observed transport keys must match the pairing exactly.
            1 => {
                let result = self.live[0].as_ref().unwrap().initiate_session(
                    self.pairing,
                    transport_key(1),
                    transport_key(0),
                    now,
                    deadline,
                );
                tc.event("handshake:reject-transport");
                assert!(matches!(
                    result,
                    Err(IdentityError::Session(Reject::Transport))
                ));
            }
            // A handshake at its deadline is already expired.
            2 => {
                let result = self.live[0].as_ref().unwrap().initiate_session(
                    self.pairing,
                    transport_key(0),
                    transport_key(1),
                    now,
                    now,
                );
                tc.event("handshake:reject-expired");
                assert!(matches!(
                    result,
                    Err(IdentityError::Session(Reject::Expired))
                ));
            }
            // Garbage bytes are not a Hello.
            3 => {
                let result = self.live[1].as_ref().unwrap().respond_session(
                    self.pairing,
                    transport_key(1),
                    transport_key(0),
                    &[9; 133],
                    now,
                    deadline,
                );
                tc.event("handshake:reject-malformed");
                assert!(matches!(
                    result,
                    Err(IdentityError::Session(Reject::Malformed))
                ));
            }
            // A Hello minted under a different pairing never matches.
            4 => {
                let other = Pairing {
                    responder: self.keys[2],
                    ..self.pairing
                };
                let (_, hello) = self.live[0]
                    .as_ref()
                    .unwrap()
                    .initiate_session(other, transport_key(0), transport_key(1), now, deadline)
                    .unwrap();
                let result = self.live[1].as_ref().unwrap().respond_session(
                    self.pairing,
                    transport_key(1),
                    transport_key(0),
                    &hello,
                    now,
                    deadline,
                );
                tc.event("handshake:reject-context");
                assert!(matches!(
                    result,
                    Err(IdentityError::Session(Reject::Context))
                ));
            }
            // The initiator's key cannot take the responder role.
            5 => {
                let result = self.live[0].as_ref().unwrap().respond_session(
                    self.pairing,
                    transport_key(0),
                    transport_key(1),
                    &[9; 133],
                    now,
                    deadline,
                );
                tc.event("handshake:reject-role");
                assert!(matches!(
                    result,
                    Err(IdentityError::Session(Reject::LocalKey))
                ));
            }
            _ => {
                let a = self.live[0].as_ref().unwrap();
                let b = self.live[1].as_ref().unwrap();
                let (pending_a, hello) = a
                    .initiate_session(
                        self.pairing,
                        transport_key(0),
                        transport_key(1),
                        now,
                        deadline,
                    )
                    .unwrap();
                let (pending_b, response) = b
                    .respond_session(
                        self.pairing,
                        transport_key(1),
                        transport_key(0),
                        &hello,
                        now,
                        deadline,
                    )
                    .unwrap();
                let (session_a, confirm) = a.confirm_session(pending_a, &response, now).unwrap();
                let session_b = pending_b.finish(&confirm, now).unwrap();
                tc.event("handshake:ok");
                self.generations.push(Generation {
                    a: session_a,
                    b: session_b,
                    hello,
                    confirm,
                });
                self.max_accepted.push(0);
            }
        }
    }

    /// Send one signed chat frame on the newest generation; a drawn fraction
    /// is held back as in-flight material for replay draws.
    fn chat(&mut self, tc: &TestCase) {
        if self.generations.is_empty() {
            return self.handshake(tc);
        }
        self.ensure(0);
        self.tick(tc);
        let now = self.now;
        let generation = self.generations.len() - 1;
        let body = tc.draw(gs::vecs(gs::integers::<u8>()).max_size(23));
        let gen = &mut self.generations[generation];
        let envelope = gen.a.prepare_chat(&body, now).unwrap();
        let sequence = envelope.sequence().0;
        let signed = self.live[0]
            .as_ref()
            .unwrap()
            .sign_envelope(envelope, gen.a.outbound_context(), self.pairing.expires_at)
            .unwrap()
            .encode()
            .unwrap();
        let deliver = tc.draw(gs::integers::<u8>().max_value(4)) != 0;
        if deliver {
            tc.event("chat:delivered");
            let verified = gen.b.receive(&signed, now).unwrap();
            assert_eq!(verified.envelope().body(), body);
            self.max_accepted[generation] = sequence;
        } else {
            tc.event("chat:held");
        }
        self.frames.push(Frame {
            generation,
            sequence,
            raw: signed,
        });
    }

    /// Re-deliver a drawn captured frame to the current responder. Frames
    /// from an older generation die on `SessionMismatch`; current-generation
    /// frames at or below the admitted sequence watermark die on `Replay`;
    /// only a frame ahead of the watermark may verify — and advances it.
    fn replay_chat(&mut self, tc: &TestCase) {
        if self.frames.is_empty() {
            return self.chat(tc);
        }
        self.tick(tc);
        let now = self.now;
        let index = tc.draw(gs::integers::<usize>().max_value(self.frames.len() - 1));
        let (generation, sequence, raw) = {
            let frame = &self.frames[index];
            (frame.generation, frame.sequence, frame.raw.clone())
        };
        let current = self.generations.len() - 1;
        let gen = &mut self.generations[current];
        match gen.b.receive(&raw, now) {
            Ok(_) => {
                assert_eq!(generation, current, "a stale-generation frame verified");
                assert!(
                    sequence > self.max_accepted[current],
                    "a sequence at or below the admitted watermark verified"
                );
                tc.event("replay:ok");
                self.max_accepted[current] = sequence;
            }
            Err(Reject::Verify(VerifyError::SessionMismatch)) => {
                tc.event("replay:session-mismatch");
                assert_ne!(generation, current)
            }
            Err(Reject::Verify(VerifyError::Replay)) => {
                tc.event("replay:replay");
                assert_eq!(generation, current);
                assert!(
                    sequence <= self.max_accepted[current],
                    "a live-sequence frame was rejected as replay"
                );
            }
            Err(error) => panic!("unexpected receive failure: {error:?}"),
        }
    }

    /// Replay a drawn old Hello: the responder issues a fresh challenge (its
    /// OS nonce is new), but the captured old confirmation can never finish
    /// it — the nonce binding changed.
    fn replay_hello(&mut self, tc: &TestCase) {
        if self.generations.is_empty() {
            return self.handshake(tc);
        }
        self.ensure(1);
        self.tick(tc);
        let now = self.now;
        let index = tc.draw(gs::integers::<usize>().max_value(self.generations.len() - 1));
        let (hello, confirm) = {
            let gen = &self.generations[index];
            (gen.hello.clone(), gen.confirm.clone())
        };
        let (pending, _response) = self.live[1]
            .as_ref()
            .unwrap()
            .respond_session(
                self.pairing,
                transport_key(1),
                transport_key(0),
                &hello,
                now,
                now + 50,
            )
            .unwrap();
        tc.event("replay:stale-confirm");
        assert!(matches!(
            pending.finish(&confirm, now),
            Err(Reject::Context)
        ));
    }

    /// Drop and reopen a drawn identity; the key is stable and a second open
    /// while held is `Busy`.
    fn reopen(&mut self, tc: &TestCase, i: usize) {
        if self.live[i].is_some() {
            tc.event("reopen:busy");
            assert!(matches!(
                Identity::open(&self.paths[i]),
                Err(IdentityError::Busy)
            ));
            self.live[i] = None;
        }
        tc.event("reopen:stable-key");
        self.ensure(i);
    }
}

/// Interleaved handshakes — clean and faulted — chat sends, captured-frame
/// replays, stale-Hello re-challenges and identity reopens. Reopened
/// identities keep their public key, yet every piece of stale session
/// material stays rejected: old confirmations never complete a fresh
/// challenge, old-generation frames fail `SessionMismatch`, redelivered
/// frames fail `Replay`, and faulted handshake roles fail with the exact
/// rejection the protocol prescribes.
///
/// Handshakes and receives are cheap, but creates/reopens do real I/O, so
/// only `TooSlow` is suppressed.
#[hegel::test(test_cases = 64, suppress_health_check = [HealthCheck::TooSlow])]
fn reopened_identities_never_accept_stale_session_material(tc: TestCase) {
    let mut case = SessionCase::new();
    let steps = tc.draw(gs::integers::<usize>().min_value(1).max_value(16));
    for _ in 0..steps {
        match tc.draw(gs::integers::<usize>().max_value(99)) {
            0..=29 => case.handshake(&tc),
            30..=54 => case.chat(&tc),
            55..=74 => case.replay_chat(&tc),
            75..=89 => case.replay_hello(&tc),
            _ => case.reopen(&tc, tc.draw(gs::integers::<usize>().max_value(2))),
        }
    }
}

// ---------------------------------------------------------------------------
// Social custody: the custodian's signature set contains only the exact
// primary and acknowledgement keys, whatever order operations arrive in.

#[cfg(feature = "social")]
mod social {
    use super::{Temp, SLOTS};
    use hegel::{generators as gs, TestCase};
    use vhalla_core::RealmId;
    use vhalla_identity::Identity;
    use vhalla_social::{
        AgentId, Body, ControlAction, Error, OwnerId, RecordId, Rights, UnsignedRecord,
    };

    struct SocialCase {
        _temp: Temp,
        live: Vec<Identity>,
        keys: [[u8; 32]; 3],
        owner_id: Option<OwnerId>,
        /// Owner control-chain basis for `previous` fields.
        head: Option<RecordId>,
        agents: Vec<AgentId>,
    }

    impl SocialCase {
        fn new() -> Self {
            let temp = Temp::new();
            let live: Vec<Identity> = SLOTS
                .iter()
                .map(|slot| Identity::create_new(temp.0.join(slot)).unwrap())
                .collect();
            let keys = [
                live[0].public_key(),
                live[1].public_key(),
                live[2].public_key(),
            ];
            Self {
                _temp: temp,
                live,
                keys,
                owner_id: None,
                head: None,
                agents: Vec::new(),
            }
        }

        /// Sign an `OwnerGenesis` with a drawn custodian: only the owner key
        /// may produce the primary signature, and no acknowledgement can be
        /// attached to a record that requires none.
        fn owner_genesis(&mut self, tc: &TestCase) {
            let signer = tc.draw(gs::integers::<usize>().max_value(2));
            let recovery = if tc.draw(gs::booleans()) {
                Some(self.keys[tc.draw(gs::integers::<usize>().max_value(2))])
            } else {
                None
            };
            let nonce = [tc.draw(gs::integers::<u8>()); 32];
            let request = UnsignedRecord::new(
                self.keys[0],
                Body::OwnerGenesis {
                    controller: self.keys[0],
                    recovery,
                    nonce,
                },
            )
            .unwrap();
            match self.live[signer].sign_social(request.clone()) {
                Ok(primary) => {
                    tc.event("social:owner-primary-ok");
                    assert_eq!(signer, 0, "a foreign key produced a primary");
                    // A single-signature record never takes a countersign.
                    let stray = tc.draw(gs::integers::<usize>().max_value(2));
                    assert!(matches!(
                        self.live[stray].countersign_social(primary),
                        Err(Error::SigningKey)
                    ));
                    let verified = self.live[0]
                        .sign_social(request)
                        .unwrap()
                        .finish()
                        .unwrap()
                        .verify()
                        .unwrap();
                    assert_eq!(verified.primary_key(), &self.keys[0]);
                    self.owner_id = Some(OwnerId::from_bytes(*verified.id().as_bytes()));
                    self.head = Some(verified.id());
                }
                Err(Error::SigningKey) => {
                    tc.event("social:owner-primary-wrong");
                    assert_ne!(signer, 0)
                }
                Err(error) => panic!("unexpected owner-genesis failure: {error:?}"),
            }
        }

        /// An `AgentGenesis` binds the owner primary plus exactly the drawn
        /// agent key as acknowledgement — nobody else can countersign, and
        /// the record cannot finish without the second signature.
        fn agent_genesis(&mut self, tc: &TestCase) {
            let Some(owner) = self.owner_id else {
                return self.owner_genesis(tc);
            };
            let head = self.head.unwrap();
            let agent = tc.draw(gs::integers::<usize>().max_value(2));
            let signer = tc.draw(gs::integers::<usize>().max_value(2));
            let nonce = [tc.draw(gs::integers::<u8>()); 32];
            let body = Body::AgentGenesis {
                owner,
                control: head,
                key: self.keys[agent],
                nonce,
            };
            let request = UnsignedRecord::new(self.keys[0], body).unwrap();
            match self.live[signer].sign_social(request.clone()) {
                Ok(primary) => {
                    assert_eq!(signer, 0);
                    tc.event("social:ack-required");
                    assert!(matches!(
                        primary.finish(),
                        Err(Error::AcknowledgementRequired)
                    ));
                    let countersigner = tc.draw(gs::integers::<usize>().max_value(2));
                    let primary = self.live[0].sign_social(request).unwrap();
                    match self.live[countersigner].countersign_social(primary) {
                        Ok(record) => {
                            tc.event("social:ack-ok");
                            assert_eq!(countersigner, agent);
                            let verified = record.verify().unwrap();
                            assert_eq!(verified.primary_key(), &self.keys[0]);
                            self.agents
                                .push(AgentId::from_bytes(*verified.id().as_bytes()));
                        }
                        Err(Error::SigningKey) => {
                            tc.event("social:ack-wrong");
                            assert_ne!(countersigner, agent)
                        }
                        Err(error) => {
                            panic!("unexpected countersign failure: {error:?}")
                        }
                    }
                }
                Err(Error::SigningKey) => {
                    tc.event("social:primary-wrong");
                    assert_ne!(signer, 0)
                }
                Err(error) => panic!("unexpected agent-genesis failure: {error:?}"),
            }
        }

        /// A `Rotate` control record binds the old controller as primary and
        /// the drawn replacement key as acknowledgement — the same two-role
        /// custody as `AgentGenesis` over a different family.
        fn rotate(&mut self, tc: &TestCase) {
            let Some(owner) = self.owner_id else {
                return self.owner_genesis(tc);
            };
            let head = self.head.unwrap();
            let new_key = tc.draw(gs::integers::<usize>().max_value(2));
            let signer = tc.draw(gs::integers::<usize>().max_value(2));
            let request = UnsignedRecord::new(
                self.keys[0],
                Body::Control {
                    owner,
                    previous: head,
                    action: ControlAction::Rotate {
                        new_key: self.keys[new_key],
                    },
                },
            )
            .unwrap();
            match self.live[signer].sign_social(request.clone()) {
                Ok(primary) => {
                    assert_eq!(signer, 0);
                    tc.event("social:ack-required");
                    assert!(matches!(
                        primary.finish(),
                        Err(Error::AcknowledgementRequired)
                    ));
                    let countersigner = tc.draw(gs::integers::<usize>().max_value(2));
                    let primary = self.live[0].sign_social(request).unwrap();
                    match self.live[countersigner].countersign_social(primary) {
                        Ok(record) => {
                            tc.event("social:ack-ok");
                            assert_eq!(countersigner, new_key);
                            let verified = record.verify().unwrap();
                            assert_eq!(verified.primary_key(), &self.keys[0]);
                            self.head = Some(verified.id());
                        }
                        Err(Error::SigningKey) => {
                            tc.event("social:ack-wrong");
                            assert_ne!(countersigner, new_key)
                        }
                        Err(error) => panic!("unexpected rotate failure: {error:?}"),
                    }
                }
                Err(Error::SigningKey) => {
                    tc.event("social:primary-wrong");
                    assert_ne!(signer, 0)
                }
                Err(error) => panic!("unexpected control failure: {error:?}"),
            }
        }

        /// A `Grant` control record carries the owner primary alone.
        fn grant(&mut self, tc: &TestCase) {
            let (Some(owner), Some(head), false) =
                (self.owner_id, self.head, self.agents.is_empty())
            else {
                return self.agent_genesis(tc);
            };
            let agent =
                self.agents[tc.draw(gs::integers::<usize>().max_value(self.agents.len() - 1))];
            let signer = tc.draw(gs::integers::<usize>().max_value(2));
            let rights =
                Rights::from_bits(tc.draw(gs::integers::<u8>().min_value(1).max_value(63)))
                    .unwrap();
            let request = UnsignedRecord::new(
                self.keys[0],
                Body::Control {
                    owner,
                    previous: head,
                    action: ControlAction::Grant {
                        agent,
                        realm: RealmId(tc.draw(gs::integers::<u128>().max_value(9))),
                        rights,
                        expires_at: tc.draw(gs::integers::<u64>().min_value(1)),
                        nonce: [tc.draw(gs::integers::<u8>()); 32],
                    },
                },
            )
            .unwrap();
            match self.live[signer].sign_social(request) {
                Ok(primary) => {
                    assert_eq!(signer, 0);
                    tc.event("social:grant-ok");
                    let verified = primary.finish().unwrap().verify().unwrap();
                    assert_eq!(verified.primary_key(), &self.keys[0]);
                    self.head = Some(verified.id());
                }
                Err(Error::SigningKey) => {
                    tc.event("social:grant-wrong");
                    assert_ne!(signer, 0)
                }
                Err(error) => panic!("unexpected grant failure: {error:?}"),
            }
        }
    }

    /// Drawn sequences of owner/agent control records across three custody
    /// handles: `sign_social` produces a primary iff the handle is the exact
    /// primary key, `countersign_social` succeeds iff the handle is the
    /// exact acknowledgement key, `finish` is refused while a second
    /// signature is owed, and every completed record verifies under the
    /// owner key alone.
    #[hegel::test(test_cases = 64)]
    fn custodian_signatures_bind_only_the_drawn_role_keys(tc: TestCase) {
        let mut case = SocialCase::new();
        let steps = tc.draw(gs::integers::<usize>().min_value(1).max_value(12));
        for _ in 0..steps {
            match tc.draw(gs::integers::<usize>().max_value(99)) {
                0..=29 => case.owner_genesis(&tc),
                30..=54 => case.agent_genesis(&tc),
                55..=69 => case.rotate(&tc),
                _ => case.grant(&tc),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Rooms custody: the same bound-key roles over the rooms record families.
// `OwnerId`/`AgentId`/`RecordId` are social types, so this needs both
// features — CI runs `--all-features`.

#[cfg(all(feature = "rooms", feature = "social"))]
mod rooms {
    use super::{Temp, SLOTS};
    use hegel::{generators as gs, TestCase};
    use vhalla_core::RealmId;
    use vhalla_identity::Identity;
    use vhalla_rooms::{
        CreateAction, CreationIntent, Description, DirectoryId, Error, PolicyId, RoomControl,
        RoomGenesisId, RoomRecordId, RoomUpdate, Slug, UpdateAction,
    };
    use vhalla_social::{AgentId, OwnerId, RecordId};

    struct RoomsCase {
        _temp: Temp,
        live: Vec<Identity>,
        keys: [[u8; 32]; 3],
        nonce: u64,
    }

    impl RoomsCase {
        fn new() -> Self {
            let temp = Temp::new();
            let live: Vec<Identity> = SLOTS
                .iter()
                .map(|slot| Identity::create_new(temp.0.join(slot)).unwrap())
                .collect();
            let keys = [
                live[0].public_key(),
                live[1].public_key(),
                live[2].public_key(),
            ];
            Self {
                _temp: temp,
                live,
                keys,
                nonce: 0,
            }
        }

        fn salt(&mut self, tc: &TestCase) -> [u8; 32] {
            self.nonce += 1;
            let mut salt = [tc.draw(gs::integers::<u8>()); 32];
            salt[..8].copy_from_slice(&self.nonce.to_be_bytes());
            salt
        }

        /// `sign_room_control` binds exactly the claimed controller key.
        fn control(&mut self, tc: &TestCase) {
            let controller = tc.draw(gs::integers::<usize>().max_value(2));
            let signer = tc.draw(gs::integers::<usize>().max_value(2));
            let action = if tc.draw(gs::booleans()) {
                CreateAction::GrantCreate {
                    agent: AgentId::from_bytes(self.salt(tc)),
                    agent_key: self.keys[tc.draw(gs::integers::<usize>().max_value(2))],
                    expires_at: tc.draw(gs::integers::<u64>().min_value(1)),
                    maximum_charge: tc.draw(gs::integers::<u64>().min_value(1)),
                    nonce: self.salt(tc),
                }
            } else {
                CreateAction::RevokeGrant {
                    grant: RoomRecordId::from_bytes(self.salt(tc)),
                }
            };
            let control = RoomControl {
                directory: DirectoryId::from_bytes(self.salt(tc)),
                realm: RealmId(tc.draw(gs::integers::<u128>().max_value(9))),
                owner: OwnerId::from_bytes(self.salt(tc)),
                social_control: RecordId::from_bytes(self.salt(tc)),
                controller_key: self.keys[controller],
                previous: None,
                sequence: 0,
                action,
            };
            match self.live[signer].sign_room_control(control) {
                Ok(record) => {
                    tc.event("rooms:control-ok");
                    assert_eq!(signer, controller);
                    record.verify().unwrap();
                }
                Err(Error::SigningKey) => {
                    tc.event("rooms:control-wrong");
                    assert_ne!(signer, controller)
                }
                Err(error) => panic!("unexpected control failure: {error:?}"),
            }
        }

        /// The two-room creation roles: `sign_room_permit` binds exactly the
        /// drawn owner key, `sign_room_proposal` binds exactly the drawn
        /// agent key — each refuses every other custodian.
        fn proposal(&mut self, tc: &TestCase) {
            let owner = tc.draw(gs::integers::<usize>().max_value(2));
            let agent = tc.draw(gs::integers::<usize>().max_value(2));
            let intent = CreationIntent {
                directory: DirectoryId::from_bytes(self.salt(tc)),
                realm: RealmId(tc.draw(gs::integers::<u128>().max_value(9))),
                policy: PolicyId::from_bytes(self.salt(tc)),
                initial_settings: PolicyId::from_bytes(self.salt(tc)),
                owner: OwnerId::from_bytes(self.salt(tc)),
                agent: AgentId::from_bytes(self.salt(tc)),
                social_control: RecordId::from_bytes(self.salt(tc)),
                owner_key: self.keys[owner],
                agent_key: self.keys[agent],
                room_control: RoomRecordId::from_bytes(self.salt(tc)),
                grant: RoomRecordId::from_bytes(self.salt(tc)),
                slug: Slug::new("drawn-room").unwrap(),
                description: Description::new("d").unwrap(),
                slot: tc.draw(gs::integers::<u32>().min_value(1).max_value(9)),
                charge: tc.draw(gs::integers::<u64>().min_value(1)),
                expires_at: tc.draw(gs::integers::<u64>().min_value(1)),
                nonce: self.salt(tc),
            };
            let owner_signer = tc.draw(gs::integers::<usize>().max_value(2));
            let permit = match self.live[owner_signer].sign_room_permit(intent.clone()) {
                Ok(permit) => {
                    tc.event("rooms:permit-ok");
                    assert_eq!(owner_signer, owner);
                    permit
                }
                Err(Error::SigningKey) => {
                    tc.event("rooms:permit-wrong");
                    assert_ne!(owner_signer, owner);
                    self.live[owner].sign_room_permit(intent).unwrap()
                }
                Err(error) => panic!("unexpected permit failure: {error:?}"),
            };
            let genesis = permit.genesis_id();
            let agent_signer = tc.draw(gs::integers::<usize>().max_value(2));
            match self.live[agent_signer].sign_room_proposal(permit) {
                Ok(record) => {
                    tc.event("rooms:proposal-ok");
                    assert_eq!(agent_signer, agent);
                    let verified = record.verify().unwrap();
                    assert_eq!(verified.genesis_id(), Some(genesis));
                }
                Err(Error::SigningKey) => {
                    tc.event("rooms:proposal-wrong");
                    assert_ne!(agent_signer, agent)
                }
                Err(error) => panic!("unexpected proposal failure: {error:?}"),
            }
        }

        /// `sign_room_update` binds exactly the claimed controller key.
        fn update(&mut self, tc: &TestCase) {
            let controller = tc.draw(gs::integers::<usize>().max_value(2));
            let signer = tc.draw(gs::integers::<usize>().max_value(2));
            let update = RoomUpdate {
                directory: DirectoryId::from_bytes(self.salt(tc)),
                realm: RealmId(tc.draw(gs::integers::<u128>().max_value(9))),
                genesis: RoomGenesisId::from_bytes(self.salt(tc)),
                previous: RoomRecordId::from_bytes(self.salt(tc)),
                owner: OwnerId::from_bytes(self.salt(tc)),
                social_control: RecordId::from_bytes(self.salt(tc)),
                controller_key: self.keys[controller],
                expires_at: tc.draw(gs::integers::<u64>().min_value(1)),
                nonce: self.salt(tc),
                action: if tc.draw(gs::booleans()) {
                    UpdateAction::Archive
                } else {
                    UpdateAction::Describe(Description::new("archived").unwrap())
                },
            };
            match self.live[signer].sign_room_update(update) {
                Ok(record) => {
                    tc.event("rooms:update-ok");
                    assert_eq!(signer, controller);
                    record.verify().unwrap();
                }
                Err(Error::SigningKey) => {
                    tc.event("rooms:update-wrong");
                    assert_ne!(signer, controller)
                }
                Err(error) => panic!("unexpected update failure: {error:?}"),
            }
        }
    }

    /// Drawn room-control, permit+proposal and update signings across three
    /// custody handles: each `sign_room_*` produces evidence iff the handle
    /// holds the exact role key, and completed records verify.
    #[hegel::test(test_cases = 64)]
    fn room_records_bind_only_the_drawn_role_keys(tc: TestCase) {
        let mut case = RoomsCase::new();
        let steps = tc.draw(gs::integers::<usize>().min_value(1).max_value(12));
        for _ in 0..steps {
            match tc.draw(gs::integers::<usize>().max_value(99)) {
                0..=39 => case.control(&tc),
                40..=69 => case.proposal(&tc),
                _ => case.update(&tc),
            }
        }
    }
}
