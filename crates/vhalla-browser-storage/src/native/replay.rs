//! Private, bounded, locally authenticated certified replay progress.
//!
//! This profile is a replaceable replay cache, never an author sequence store.
//! It owns a storage-only secret, accepts no arbitrary snapshot import, and
//! retains one verified client/anchor. All journal and outbox evidence stays in
//! its original store. Complete hostile rollback of this private profile/key is
//! outside the cooperating OS-owner custody contract. No network I/O occurs.

use crate::Error;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use vhalla_custody::{self as custody, Owner};
use vhalla_public_client::{
    checkpoint::{
        incomplete_successor, AuthenticatedCheckpoint, CheckpointHead, MAX_CHECKPOINT_BYTES,
    },
    Bootstrap, CertifiedClient,
};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"VHNREP01";
const FORMAT_BYTES: usize = 72;

#[cfg(test)]
#[path = "replay/tests.rs"]
mod tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Point {
    Created,
    Partial,
    Written,
    Synced,
    Renamed,
    DirectorySynced,
    CleanSync,
}

/// One exclusively owned verified replica and its authenticated durable prefix.
pub struct NativeReplay {
    path: PathBuf,
    owner: Owner,
    directory: File,
    _lock: File,
    key: Zeroizing<[u8; 32]>,
    client: CertifiedClient,
    raw: Vec<u8>,
    generation: u64,
    poisoned: bool,
    dirty: bool,
    #[cfg(test)]
    fault: Option<Point>,
}
fn io(_: std::io::Error) -> Error {
    Error::Storage
}
fn custody_error(error: custody::Error) -> Error {
    match error {
        custody::Error::Capacity => Error::Bounds,
        custody::Error::UnsafePath | custody::Error::Corrupt => Error::Corrupt,
        _ => Error::Storage,
    }
}
fn client_error(error: vhalla_public_client::Error) -> Error {
    match error {
        vhalla_public_client::Error::Bounds => Error::Bounds,
        vhalla_public_client::Error::BootstrapPin | vhalla_public_client::Error::Network => {
            Error::WrongScope
        }
        vhalla_public_client::Error::Anchor => Error::Stale,
        _ => Error::Corrupt,
    }
}
fn format(network: [u8; 32], pin: [u8; 32]) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&network);
    out.extend_from_slice(&pin);
    out
}
impl NativeReplay {
    /// Create a never-existing profile from independently pinned genesis only.
    /// This creates no application identity, author floor, listener, or post.
    pub fn create_new(
        path: impl AsRef<Path>,
        bootstrap: Bootstrap,
        pin: [u8; 32],
    ) -> Result<Self, Error> {
        let client = CertifiedClient::new(bootstrap, pin).map_err(client_error)?;
        let path = custody::absolute(path.as_ref()).map_err(custody_error)?;
        let (directory, owner) = custody::create_private_directory(&path).map_err(custody_error)?;
        let lock = custody::create_private_file(&path.join("lock")).map_err(custody_error)?;
        custody::acquire_exclusive(&lock).map_err(custody_error)?;
        lock.sync_all().map_err(io)?;
        let mut key = Zeroizing::new([0; 32]);
        getrandom::fill(key.as_mut()).map_err(|_| Error::Storage)?;
        for (name, bytes) in [
            ("FORMAT", format(client.network_id(), pin)),
            ("KEY", key.to_vec()),
        ] {
            let bytes = Zeroizing::new(bytes);
            let mut file = custody::create_private_file(&path.join(name)).map_err(custody_error)?;
            file.write_all(&bytes).map_err(io)?;
            file.sync_all().map_err(io)?;
        }
        directory.sync_all().map_err(io)?;
        File::open(path.parent().ok_or(Error::Corrupt)?)
            .and_then(|p| p.sync_all())
            .map_err(io)?;
        let raw = client
            .checkpoint_image()
            .map_err(client_error)?
            .seal(&key, 0, [0; 32]);
        let mut out = Self {
            path,
            owner,
            directory,
            _lock: lock,
            key,
            client,
            raw: Vec::new(),
            generation: 0,
            poisoned: true,
            dirty: false,
            #[cfg(test)]
            fault: None,
        };
        out.publish(&raw)?;
        out.raw = raw;
        out.poisoned = false;
        Ok(out)
    }
    /// Open an existing exact network/configuration profile. Authenticate before
    /// snapshot decoding or scratch reconciliation. Never reset missing state.
    pub fn open(
        path: impl AsRef<Path>,
        bootstrap: Bootstrap,
        pin: [u8; 32],
    ) -> Result<Self, Error> {
        if bootstrap.pin() != pin {
            return Err(Error::WrongScope);
        }
        let network = bootstrap.network_id();
        let path = custody::absolute(path.as_ref()).map_err(custody_error)?;
        let (directory, owner) = custody::open_private_directory(&path).map_err(custody_error)?;
        let lock =
            custody::open_private_file(&path.join("lock"), owner, 0).map_err(custody_error)?;
        custody::acquire_exclusive(&lock).map_err(custody_error)?;
        if custody::read_private_file(&path.join("FORMAT"), owner, FORMAT_BYTES)
            .map_err(custody_error)?
            != format(network, pin)
        {
            return Err(Error::WrongScope);
        }
        let key_raw = Zeroizing::new(
            custody::read_private_file(&path.join("KEY"), owner, 32).map_err(custody_error)?,
        );
        let key =
            Zeroizing::new(<[u8; 32]>::try_from(key_raw.as_slice()).map_err(|_| Error::Corrupt)?);
        let present = |name: &str| {
            custody::private_file_present(&path.join(name), owner, MAX_CHECKPOINT_BYTES)
                .map_err(custody_error)
        };
        let read = |name: &str| {
            custody::read_private_file(&path.join(name), owner, MAX_CHECKPOINT_BYTES)
                .map_err(custody_error)
        };
        let current = if present("STATE")? {
            Some(read("STATE")?)
        } else {
            None
        };
        let scratch = if present("STATE.tmp")? {
            Some(read("STATE.tmp")?)
        } else {
            None
        };
        let (raw, client, generation) = if let Some(raw) = current {
            let authenticated =
                AuthenticatedCheckpoint::open(&raw, &key, network, pin).map_err(client_error)?;
            let generation = authenticated.generation();
            let client = authenticated
                .restore(bootstrap.clone(), pin)
                .map_err(client_error)?;
            (raw, client, generation)
        } else {
            // Only exact deterministic initial scratch is recoverable without a
            // retained STATE. Missing state/scratch never means a fresh profile.
            let staged = scratch.as_ref().ok_or(Error::RecoveryRequired)?;
            let client = CertifiedClient::new(bootstrap.clone(), pin).map_err(client_error)?;
            let raw = client
                .checkpoint_image()
                .map_err(client_error)?
                .seal(&key, 0, [0; 32]);
            if staged.len() > raw.len() || staged != &raw[..staged.len()] {
                return Err(Error::Corrupt);
            }
            (Vec::new(), client, 0)
        };
        let mut out = Self {
            path,
            owner,
            directory,
            _lock: lock,
            key,
            client,
            raw,
            generation,
            poisoned: true,
            dirty: false,
            #[cfg(test)]
            fault: None,
        };
        if let Some(staged) = scratch {
            if out.raw.is_empty() {
                let expected = out
                    .client
                    .checkpoint_image()
                    .map_err(client_error)?
                    .seal(&out.key, 0, [0; 32]);
                out.complete_initial(&expected)?;
                out.raw = expected;
            } else {
                let next = out.generation.checked_add(1).ok_or(Error::Bounds)?;
                let previous = Sha256::digest(&out.raw).into();
                if incomplete_successor(&staged, network, pin, next, previous)
                    .map_err(client_error)?
                {
                    out.remove_scratch()?;
                } else {
                    let authenticated =
                        AuthenticatedCheckpoint::open(&staged, &out.key, network, pin)
                            .map_err(client_error)?;
                    if authenticated.generation() != next || authenticated.previous() != previous {
                        return Err(Error::Stale);
                    }
                    let candidate = authenticated
                        .restore(bootstrap, pin)
                        .map_err(client_error)?;
                    let before = out.client.checkpoint_head();
                    let after = candidate.checkpoint_head();
                    if after.frontier().height < before.frontier().height
                        || (after.frontier().height == before.frontier().height && after != before)
                    {
                        return Err(Error::Stale);
                    }
                    out.promote(&staged)?;
                    out.raw = staged;
                    out.client = candidate;
                    out.generation = next;
                }
            }
        }
        // An observed rename/unlink is not evidence of durable directory state.
        out.resync("STATE", MAX_CHECKPOINT_BYTES)?;
        out.resync("KEY", 32)?;
        out.resync("FORMAT", FORMAT_BYTES)?;
        File::open(out.path.parent().ok_or(Error::Corrupt)?)
            .and_then(|p| p.sync_all())
            .map_err(io)?;
        out.poisoned = false;
        Ok(out)
    }
    /// Read-only in-memory projection, never itself an authoring permission.
    /// After an uncertain write, drop/reopen before any further operation.
    pub const fn client(&self) -> &CertifiedClient {
        &self.client
    }
    /// Authenticated durable local generation.
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    /// Whether this handle must be reopened before use.
    pub const fn needs_reopen(&self) -> bool {
        self.poisoned
    }
    fn ready(&self) -> Result<(), Error> {
        if self.poisoned {
            Err(Error::NeedsReopen)
        } else {
            Ok(())
        }
    }
    /// Require exact retained policy ancestry without moving any author state.
    pub fn require_anchor(&mut self, head: CheckpointHead) -> Result<(), Error> {
        self.ready()?;
        let before = self.client.retained_anchor();
        self.client.require_anchor(head).map_err(client_error)?;
        self.dirty |= before != self.client.retained_anchor();
        Ok(())
    }
    /// Verify and apply exact canonical bytes already read from a published
    /// journal. The caller owns that publication assertion. Cache persistence is
    /// separate; cancellation before checkpoint loses only unacknowledged work.
    pub fn apply_published_bundle(&mut self, raw: &[u8]) -> Result<(), Error> {
        self.ready()?;
        let candidate = self
            .client
            .prepare(self.client.network_id(), raw)
            .map_err(client_error)?;
        self.client
            .commit_after_persist(candidate)
            .map_err(client_error)?;
        self.dirty = true;
        Ok(())
    }
    /// Atomically authenticate/publish this handle's verified client. No arbitrary
    /// snapshot input exists. Uncertainty poisons the handle until exact reopen.
    pub fn checkpoint(&mut self) -> Result<(), Error> {
        self.ready()?;
        self.poisoned = true;
        if self.read("STATE")? != self.raw {
            self.poisoned = true;
            return Err(Error::Stale);
        }
        if !self.dirty {
            self.hit(Point::CleanSync)?;
            self.resync("STATE", MAX_CHECKPOINT_BYTES)?;
            self.poisoned = false;
            return Ok(());
        }
        let generation = self.generation.checked_add(1).ok_or(Error::Bounds)?;
        let next = self.client.checkpoint_image().map_err(client_error)?.seal(
            &self.key,
            generation,
            Sha256::digest(&self.raw).into(),
        );
        self.poisoned = true;
        self.publish(&next)?;
        self.raw = next;
        self.generation = generation;
        self.poisoned = false;
        self.dirty = false;
        Ok(())
    }
    fn read(&self, name: &str) -> Result<Vec<u8>, Error> {
        custody::read_private_file(&self.path.join(name), self.owner, MAX_CHECKPOINT_BYTES)
            .map_err(custody_error)
    }
    fn present(&self, name: &str) -> Result<bool, Error> {
        custody::private_file_present(&self.path.join(name), self.owner, MAX_CHECKPOINT_BYTES)
            .map_err(custody_error)
    }
    fn resync(&self, name: &str, max: usize) -> Result<(), Error> {
        custody::open_private_file(&self.path.join(name), self.owner, max)
            .map_err(custody_error)?
            .sync_all()
            .map_err(io)?;
        self.directory.sync_all().map_err(io)
    }
    fn remove_scratch(&self) -> Result<(), Error> {
        if self.present("STATE.tmp")? {
            fs::remove_file(self.path.join("STATE.tmp")).map_err(io)?;
        }
        self.directory.sync_all().map_err(io)
    }
    fn hit(&mut self, point: Point) -> Result<(), Error> {
        #[cfg(test)]
        if self.fault == Some(point) {
            self.fault = None;
            return Err(Error::Storage);
        }
        let _ = point;
        Ok(())
    }
    fn complete_initial(&mut self, expected: &[u8]) -> Result<(), Error> {
        let current = self.read("STATE.tmp")?;
        if current.len() > expected.len() || current != expected[..current.len()] {
            return Err(Error::Corrupt);
        }
        let mut file = custody::open_private_file(
            &self.path.join("STATE.tmp"),
            self.owner,
            MAX_CHECKPOINT_BYTES,
        )
        .map_err(custody_error)?;
        if file.seek(SeekFrom::End(0)).map_err(io)? != current.len() as u64 {
            return Err(Error::Corrupt);
        }
        // Preserve the sole genesis-recovery prefix across every interrupted append.
        file.write_all(&expected[current.len()..]).map_err(io)?;
        file.sync_all().map_err(io)?;
        self.promote(expected)
    }
    fn publish(&mut self, raw: &[u8]) -> Result<(), Error> {
        if raw.len() > MAX_CHECKPOINT_BYTES {
            return Err(Error::Bounds);
        }
        if self.present("STATE.tmp")? {
            return Err(Error::RecoveryRequired);
        }
        let mut file =
            custody::create_private_file(&self.path.join("STATE.tmp")).map_err(custody_error)?;
        self.hit(Point::Created)?;
        file.write_all(&raw[..raw.len() / 2]).map_err(io)?;
        self.hit(Point::Partial)?;
        file.write_all(&raw[raw.len() / 2..]).map_err(io)?;
        self.hit(Point::Written)?;
        file.sync_all().map_err(io)?;
        self.hit(Point::Synced)?;
        self.promote(raw)
    }
    fn promote(&mut self, raw: &[u8]) -> Result<(), Error> {
        if self.read("STATE.tmp")? != raw {
            return Err(Error::Corrupt);
        }
        // Reassert scratch durability even on the recovery path.
        self.resync("STATE.tmp", MAX_CHECKPOINT_BYTES)?;
        if self.raw.is_empty() {
            if self.present("STATE")? {
                return Err(Error::Stale);
            }
        } else if self.read("STATE")? != self.raw {
            return Err(Error::Stale);
        }
        fs::rename(self.path.join("STATE.tmp"), self.path.join("STATE")).map_err(io)?;
        self.hit(Point::Renamed)?;
        self.directory.sync_all().map_err(io)?;
        self.hit(Point::DirectorySynced)
    }
}
