//! Bounded local rotation evidence, not policy activation or protected freshness.
//!
//! Reopen always requires an independently retained exact commitment, a checked
//! current old ledger tip, its configured policy, and independently configured
//! proposed policies. No missing file or old commitment becomes a clean archive.
//! The owner must control this directory and its ancestors on a local filesystem
//! supporting locks and file/directory sync. All cooperating writers use the
//! lifetime lock. These path checks are not a sandbox against a hostile owner;
//! a hash held on the same disk is not a rollback-resistant external anchor.
//! Sync success and cut tests do not establish physical power-loss durability.

use crate::rotation::{
    proposed_policy_digest, Observation, Reject, RotationObserver, RotationPolicy,
    MAX_ROTATION_BYTES, MAX_TRANSITIONS,
};
use crate::CertifiedLedger;
use alloc::vec::Vec;
use sha2::{Digest, Sha256};
use std::fs::{self, DirBuilder, File, Metadata, OpenOptions, TryLockError};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use valhalla_checkpoint_proof_prototype::Digest32;

const DOMAIN: &[u8] = b"valhalla/rotation-archive/v1";
const VERSION: u16 = 1;
const HEADER_BYTES: usize = DOMAIN.len() + 2 + 16 + 8 + 32 + 32 + 8 + 32 + 1;
const FRAME_BYTES: usize = 1 + 2 + 32;
const MAX_ARCHIVE_BYTES: usize =
    HEADER_BYTES + MAX_TRANSITIONS * (FRAME_BYTES + MAX_ROTATION_BYTES) + 1;
const DATA: &str = "archive";
const LOCK: &str = "archive.lock";
const EVIDENCE: u8 = 1;
const EXHAUSTED: u8 = 2;

// The same seek/write_all/sync path is used for real files and the unit-test
// fault wrapper. No fault configuration is present in a normal library build.
trait AppendIo: Seek + Write {
    fn sync_file(&mut self) -> io::Result<()>;
}

impl AppendIo for File {
    fn sync_file(&mut self) -> io::Result<()> {
        self.sync_all()
    }
}

fn append_bytes(io: &mut impl AppendIo, suffix: &[u8]) -> Result<(), Error> {
    io.seek(SeekFrom::End(0))
        .map_err(|_| Error::UncertainWrite)?;
    io.write_all(suffix).map_err(|_| Error::UncertainWrite)?;
    io.sync_file().map_err(|_| Error::UncertainWrite)
}

/// Hash of the exact versioned archive bytes; only an independently retained
/// copy detects erasure or rollback. This value alone supplies no policy or
/// host authority. No default or missing-file fallback is provided.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Commitment(Digest32);

impl Commitment {
    /// Restore a previously retained commitment from independently controlled
    /// input, not from the archive about to be reopened.
    #[must_use]
    pub fn from_bytes(bytes: Digest32) -> Self {
        Self(bytes)
    }

    /// Bytes to retain independently of the archive.
    #[must_use]
    pub fn bytes(self) -> Digest32 {
        self.0
    }
}

fn commitment(raw: &[u8]) -> Commitment {
    let mut digest = Sha256::new();
    digest.update(b"valhalla/rotation-archive/commit/v1");
    digest.update(raw);
    Commitment(digest.finalize().into())
}

/// A local write result, never an approval to activate a policy. Persist the
/// returned commitment separately before depending on this observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Append {
    /// First valid certificate was appended and synced.
    Recorded(Commitment),
    /// Byte-identical certificate already retained; no write was needed.
    Repeated(Commitment),
    /// Another valid transition was retained and synced; selection is blocked.
    Conflict(Commitment),
    /// Valid distinct transition at capacity; a sticky refusal marker was synced.
    Capacity(Commitment),
}

/// A refusal never means that a partial write was rolled back.
#[derive(Debug)]
pub enum Error {
    /// A current ledger, policy, or certificate failed verification.
    Rotation(Reject),
    /// A filesystem error; during creation this may leave an incomplete directory.
    Io(io::Error),
    /// Another cooperating writer owns the lifetime lock.
    Busy,
    /// A symlink, unexpected entry, or non-private file/directory was found.
    UnsafePath,
    /// Wrong version, bound, framing, digest, duplicate, or marker placement.
    InvalidArchive,
    /// Archive bytes do not match the independently supplied expectation.
    CommitmentMismatch,
    /// A proposed policy was not independently configured for this digest.
    MissingPolicy,
    /// File changed outside the locked handle. It cannot be used for a retry.
    Changed,
    /// Write or sync outcome is indeterminate; drop and reconcile with an anchor.
    UncertainWrite,
    /// This handle saw an uncertain write and refuses all further operations.
    Poisoned,
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<Reject> for Error {
    fn from(reject: Reject) -> Self {
        Self::Rotation(reject)
    }
}

/// Locked, append-only local evidence for one checked old frontier. The ledger
/// borrow prevents appends to that ledger while this handle is live. It exposes
/// evidence and refusal only, never a selected new policy or activation token.
pub struct RotationArchive<'a> {
    path: PathBuf,
    _lock: File,
    file: File,
    observer: RotationObserver<'a>,
    raw: Vec<u8>,
    exhausted: bool,
    poisoned: bool,
    #[cfg(test)]
    fault: Option<io_faults::Fault>,
}

impl<'a> RotationArchive<'a> {
    /// Explicitly initialize a previously nonexistent owner-private directory.
    /// The caller must retain the initial commitment independently before use.
    /// A failed initialization must never be retried as an empty archive.
    pub fn create_new(
        path: impl AsRef<Path>,
        ledger: &'a CertifiedLedger,
        old_policy: RotationPolicy,
        max_transitions: usize,
    ) -> Result<(Self, Commitment), Error> {
        let observer = RotationObserver::new(ledger, old_policy, max_transitions)?;
        let path = path.as_ref();
        DirBuilder::new().mode(0o700).create(path)?;
        let path = fs::canonicalize(path)?;
        validate_directory(&fs::symlink_metadata(&path)?)?;
        let directory = File::open(&path)?;
        let lock = create_private(&path.join(LOCK))?;
        acquire(&lock)?;
        lock.sync_all()?;
        let mut file = create_private(&path.join(DATA))?;
        let raw = header(&observer, max_transitions);
        file.write_all(&raw)?;
        file.sync_all()?;
        directory.sync_all()?;
        File::open(path.parent().ok_or(Error::UnsafePath)?)?.sync_all()?;
        let expected = commitment(&raw);
        Ok((
            Self {
                path,
                _lock: lock,
                file,
                observer,
                raw,
                exhausted: false,
                poisoned: false,
                #[cfg(test)]
                fault: None,
            },
            expected,
        ))
    }

    /// Open an existing archive. Neither absence nor malformed/altered evidence
    /// may be reinterpreted as empty. The resolver must use independent config;
    /// the digest extracted from a record is UNVERIFIED lookup input only.
    pub fn reopen(
        path: impl AsRef<Path>,
        ledger: &'a CertifiedLedger,
        old_policy: RotationPolicy,
        max_transitions: usize,
        expected: Commitment,
        mut policy_for_digest: impl FnMut(Digest32) -> Option<RotationPolicy>,
    ) -> Result<Self, Error> {
        let mut observer = RotationObserver::new(ledger, old_policy, max_transitions)?;
        let path = path.as_ref();
        validate_directory(&fs::symlink_metadata(path)?)?;
        let path = fs::canonicalize(path)?;
        let lock = open_private(&path.join(LOCK))?;
        acquire(&lock)?;
        for entry in fs::read_dir(&path)? {
            let name = entry?.file_name();
            if name != DATA && name != LOCK {
                return Err(Error::UnsafePath);
            }
        }
        validate_regular(&fs::symlink_metadata(path.join(DATA))?)?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path.join(DATA))?;
        validate_regular(&file.metadata()?)?;
        let raw = read_bounded(&mut file)?;
        // Compare first, including against reordered or deleted valid records.
        // A local recomputation of the expected value would not detect erasure.
        if commitment(&raw) != expected {
            return Err(Error::CommitmentMismatch);
        }
        let prefix = header(&observer, max_transitions);
        let mut remaining = raw
            .strip_prefix(prefix.as_slice())
            .ok_or(Error::InvalidArchive)?;
        let mut exhausted = false;
        while let Some((&tag, tail)) = remaining.split_first() {
            remaining = tail;
            if tag == EXHAUSTED
                && observer.evidence().len() == max_transitions
                && remaining.is_empty()
            {
                exhausted = true;
                break;
            }
            if tag != EVIDENCE
                || observer.evidence().len() == max_transitions
                || remaining.len() < FRAME_BYTES - 1
            {
                return Err(Error::InvalidArchive);
            }
            let len = u16::from_be_bytes(
                remaining[..2]
                    .try_into()
                    .map_err(|_| Error::InvalidArchive)?,
            ) as usize;
            let digest = &remaining[2..34];
            remaining = &remaining[34..];
            if len == 0 || len > MAX_ROTATION_BYTES || remaining.len() < len {
                return Err(Error::InvalidArchive);
            }
            let (certificate, rest) = remaining.split_at(len);
            remaining = rest;
            if Sha256::digest(certificate).as_slice() != digest {
                return Err(Error::InvalidArchive);
            }
            let lookup = proposed_policy_digest(certificate)?;
            let policy = policy_for_digest(lookup).ok_or(Error::MissingPolicy)?;
            if policy.digest() != lookup {
                return Err(Error::MissingPolicy);
            }
            let count = observer.evidence().len();
            match observer.observe(certificate, &policy) {
                Ok(Observation::Recorded) | Err(Reject::ConflictingTransitions)
                    if observer.evidence().len() == count + 1 => {}
                Ok(_) | Err(Reject::ConflictingTransitions) => return Err(Error::InvalidArchive),
                Err(error) => return Err(error.into()),
            }
        }
        Ok(Self {
            path,
            _lock: lock,
            file,
            observer,
            raw,
            exhausted,
            poisoned: false,
            #[cfg(test)]
            fault: None,
        })
    }

    /// Authenticate both quorums with a caller-configured policy, then append
    /// the canonical frame or capacity marker. Once writing begins, any I/O
    /// error poisons this handle and demands independent reconciliation.
    pub fn append(
        &mut self,
        certificate: &[u8],
        new_policy: &RotationPolicy,
    ) -> Result<Append, Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if self.exhausted {
            return Err(Reject::Capacity.into());
        }
        self.check_file()?;
        let before = self.observer.evidence().len();
        let observation = self.observer.observe(certificate, new_policy);
        let current = commitment(&self.raw);
        match observation {
            Ok(Observation::Repeated) | Err(Reject::ConflictingTransitions)
                if self.observer.evidence().len() == before =>
            {
                if !self
                    .observer
                    .evidence()
                    .iter()
                    .any(|item| item.bytes() == certificate)
                {
                    return Err(Error::InvalidArchive);
                }
                // A replay after a conflict remains blocked, but it did not
                // persist another transition or change the commitment.
                return Ok(Append::Repeated(current));
            }
            Err(Reject::Capacity) => {
                // A valid distinct certificate reached capacity. The observer is
                // already permanently blocked; persist the marker before return.
                self.write_suffix(&[EXHAUSTED])?;
                self.exhausted = true;
                return Ok(Append::Capacity(commitment(&self.raw)));
            }
            Ok(Observation::Recorded) | Err(Reject::ConflictingTransitions)
                if self.observer.evidence().len() == before + 1 => {}
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(Error::InvalidArchive),
        }
        let len = u16::try_from(certificate.len()).map_err(|_| Error::InvalidArchive)?;
        let mut suffix = Vec::with_capacity(FRAME_BYTES + certificate.len());
        suffix.push(EVIDENCE);
        suffix.extend_from_slice(&len.to_be_bytes());
        suffix.extend_from_slice(&Sha256::digest(certificate));
        suffix.extend_from_slice(certificate);
        self.write_suffix(&suffix)?;
        let next = commitment(&self.raw);
        if before == 0 {
            Ok(Append::Recorded(next))
        } else {
            Ok(Append::Conflict(next))
        }
    }

    /// Retained validated claims. No caller may select a policy from this view.
    #[must_use]
    pub fn evidence(&self) -> &[crate::rotation::TransitionEvidence] {
        self.observer.evidence()
    }

    /// Conflict, capacity, or uncertain write: no transition can be selected.
    #[must_use]
    pub fn blocked(&self) -> bool {
        self.poisoned || self.exhausted || self.observer.blocked()
    }

    /// Current observed commitment, only after a known successful local sync.
    /// This value is not independently anchored by this API.
    #[must_use]
    pub fn observed_commitment(&self) -> Option<Commitment> {
        (!self.poisoned).then(|| commitment(&self.raw))
    }

    fn check_file(&mut self) -> Result<(), Error> {
        let name = self.path.join(DATA);
        // Any file-read/path failure poisons the handle, including an oversized
        // replacement. A later restoration must not turn it into a clean retry.
        let checked = (|| {
            let metadata = fs::symlink_metadata(name)?;
            validate_regular(&metadata)?;
            let open = self.file.metadata()?;
            if metadata.dev() != open.dev()
                || metadata.ino() != open.ino()
                || read_bounded(&mut self.file)? != self.raw
            {
                return Err(Error::Changed);
            }
            Ok(())
        })();
        if checked.is_err() {
            self.poisoned = true;
        }
        checked
    }

    fn write_suffix(&mut self, suffix: &[u8]) -> Result<(), Error> {
        self.poisoned = true;
        #[cfg(test)]
        let result = match self.fault.as_mut() {
            Some(fault) => {
                append_bytes(&mut io_faults::FaultIo::new(&mut self.file, fault), suffix)
            }
            None => append_bytes(&mut self.file, suffix),
        };
        #[cfg(not(test))]
        let result = append_bytes(&mut self.file, suffix);
        result?;
        self.raw.extend_from_slice(suffix);
        self.poisoned = false;
        Ok(())
    }
}

fn header(observer: &RotationObserver<'_>, capacity: usize) -> Vec<u8> {
    let old = observer.old_frontier();
    let mut out = Vec::with_capacity(HEADER_BYTES);
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.extend_from_slice(&old.realm.0.to_be_bytes());
    out.extend_from_slice(&old.epoch.0.to_be_bytes());
    out.extend_from_slice(&old.head.0);
    out.extend_from_slice(&old.state_root.0);
    out.extend_from_slice(&old.height.to_be_bytes());
    out.extend_from_slice(&observer.old_policy_digest());
    out.push(capacity as u8);
    out
}

fn validate_directory(meta: &Metadata) -> Result<(), Error> {
    if !meta.is_dir() || meta.permissions().mode() & 0o7777 != 0o700 {
        Err(Error::UnsafePath)
    } else {
        Ok(())
    }
}

fn validate_regular(meta: &Metadata) -> Result<(), Error> {
    if !meta.is_file() || meta.permissions().mode() & 0o7777 != 0o600 || meta.nlink() != 1 {
        Err(Error::UnsafePath)
    } else {
        Ok(())
    }
}

fn create_private(path: &Path) -> Result<File, Error> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    validate_regular(&file.metadata()?)?;
    Ok(file)
}

fn open_private(path: &Path) -> Result<File, Error> {
    validate_regular(&fs::symlink_metadata(path)?)?;
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    validate_regular(&file.metadata()?)?;
    Ok(file)
}

fn acquire(file: &File) -> Result<(), Error> {
    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(TryLockError::WouldBlock) => Err(Error::Busy),
        Err(TryLockError::Error(error)) => Err(Error::Io(error)),
    }
}

fn read_bounded(file: &mut File) -> Result<Vec<u8>, Error> {
    file.seek(SeekFrom::Start(0))?;
    let mut raw = Vec::new();
    file.take((MAX_ARCHIVE_BYTES + 1) as u64)
        .read_to_end(&mut raw)?;
    if raw.len() > MAX_ARCHIVE_BYTES {
        return Err(Error::InvalidArchive);
    }
    Ok(raw)
}

#[cfg(test)]
#[path = "rotation_archive_io_faults.rs"]
mod io_faults;
