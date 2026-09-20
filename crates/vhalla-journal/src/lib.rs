#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Durable commit journal: the acknowledgement boundary for consensus-driven
//! application state.
//!
//! Commit protocol, in order: write and fsync a bounded private scratch bundle,
//! publish its immutable content name with an exclusive hard link, unlink the
//! scratch name, fsync the bundle and its containing directory, write `heights/<n>` binding
//! the bundle's height to its id and fsync it and its containing directory,
//! write `pin.tmp` carrying predecessor/next/bundle/height,
//! fsync it, rename `pin.tmp` over `HEAD` (the atomic publication point),
//! fsync the directory, then acknowledge. Recovery trusts only what is
//! actually on disk: a renamed pin is committed, a leftover `pin.tmp` is
//! discarded, a height marker above the committed pin is unpublished
//! residue, an orphan bundle carries no authority, and a corrupt pin fails
//! closed. The one `bundles/.bundle.tmp` scratch has no publication authority;
//! a later locked commit may unlink and replace that exact private regular file.
//! It never truncates its inode, which may still link a committed bundle. Unknown
//! scratch path kinds/custody and existing corrupt final bundles are preserved.
//!
//! This crate is the order authority, not consensus: it qualifies
//! filesystem ordering, retry reconciliation and restart behavior. It does
//! not verify certificates, admit values, or decide anything — the caller
//! binds verified certificate bytes and resulting state commitments into
//! each bundle.

#[cfg(unix)]
mod atomic;
#[cfg(unix)]
mod read;
#[cfg(unix)]
pub use read::{
    PublishedPage, PublishedRange, PublishedReadError, MAX_PUBLISHED_PAGE_BUNDLES,
    MAX_PUBLISHED_PAGE_BYTES,
};

use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::cell::RefCell;
#[cfg(unix)]
use std::collections::BTreeMap;
use std::fmt;
#[cfg(unix)]
use std::fs::{self, File, OpenOptions};
use std::io;
#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::path::{Path, PathBuf};

#[cfg(unix)]
const HEAD_MAGIC: &[u8; 4] = b"VHP1";
const BUNDLE_MAGIC: &[u8; 4] = b"VJB1";
#[cfg(unix)]
const HEAD_FILE: &str = "HEAD";
#[cfg(unix)]
const HEAD_TMP: &str = "HEAD.tmp";
#[cfg(unix)]
const LOCK_FILE: &str = "commit.lock";
#[cfg(unix)]
const BUNDLES: &str = "bundles";
#[cfg(unix)]
const HEIGHTS: &str = "heights";
const MAX_FIELD_BYTES: usize = 64 * 1024;
/// Maximum canonical serialized bundle: nine length headers, six bounded
/// opaque fields, two 32-byte frontiers, and one eight-byte height.
pub const MAX_BUNDLE_BYTES: usize = 4 + 9 * 8 + 6 * MAX_FIELD_BYTES + 2 * 32 + 8;
#[cfg(unix)]
const PIN_BYTES: usize = 4 + 104;
#[cfg(unix)]
const ZERO: [u8; 32] = [0; 32];

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in parts {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part);
    }
    h.finalize().into()
}

/// Immutable record the journal persists. The remaining fields live only
/// inside the canonical `bytes`; the journal exposes the frontier, height,
/// identity and bytes, and treats the rest as opaque.
pub struct Bundle {
    predecessor: [u8; 32],
    next: [u8; 32],
    height: u64,
    id: [u8; 32],
    bytes: Vec<u8>,
}

/// The fields a [`Bundle`] binds into its content identity. Plain input —
/// the constructor, not the caller, computes the id.
pub struct BundleParts {
    /// Verified engine certificate bytes.
    pub certificate: Vec<u8>,
    /// Complete 256-bit frontier before the commit.
    pub predecessor: [u8; 32],
    /// Complete 256-bit frontier after it.
    pub next: [u8; 32],
    /// The committed operation batch.
    pub batch: Vec<u8>,
    /// The resulting value/state commitment.
    pub value: Vec<u8>,
    /// The configuration identity in force.
    pub configuration: Vec<u8>,
    /// The control record the batch was admitted under.
    pub control_record: Vec<u8>,
    /// The allowance debit marker the batch consumed.
    pub debit_marker: Vec<u8>,
    /// The consensus height this bundle commits.
    pub height: u64,
}

impl Bundle {
    /// Builds a bundle, binding every field into the content identity and the
    /// canonical serialized form. `predecessor`/`next` are complete 256-bit
    /// frontier pins, never prefixes.
    pub fn new(parts: BundleParts) -> Result<Self, JournalError> {
        let height_bytes = parts.height.to_le_bytes();
        let fields = [
            &parts.certificate[..],
            &parts.predecessor[..],
            &parts.next[..],
            &parts.batch[..],
            &parts.value[..],
            &parts.configuration[..],
            &parts.control_record[..],
            &parts.debit_marker[..],
            &height_bytes[..],
        ];
        for field in fields {
            if field.len() > MAX_FIELD_BYTES {
                return Err(JournalError::Oversized);
            }
        }
        let id = sha256(&fields);
        let mut bytes = Vec::with_capacity(4 + fields.iter().map(|f| f.len() + 8).sum::<usize>());
        bytes.extend_from_slice(BUNDLE_MAGIC);
        for field in fields {
            bytes.extend_from_slice(&(field.len() as u64).to_le_bytes());
            bytes.extend_from_slice(field);
        }
        if bytes.len() > MAX_BUNDLE_BYTES {
            return Err(JournalError::Oversized);
        }
        Ok(Bundle {
            predecessor: parts.predecessor,
            next: parts.next,
            height: parts.height,
            id,
            bytes,
        })
    }

    /// The content identity: SHA-256 over every length-prefixed field.
    pub fn id(&self) -> [u8; 32] {
        self.id
    }

    /// The complete predecessor frontier this commit extends.
    pub fn predecessor(&self) -> [u8; 32] {
        self.predecessor
    }

    /// The next frontier this commit establishes.
    pub fn next(&self) -> [u8; 32] {
        self.next
    }

    /// The consensus height this bundle commits.
    pub fn height(&self) -> u64 {
        self.height
    }

    /// Canonical serialized bytes as stored on disk.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The canonical stored byte length of this bundle.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the stored encoding is empty (never true for a bundle).
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Reads back one field by index (`certificate` is 0, `predecessor` 1,
    /// `next` 2, `batch` 3, `value` 4, `configuration` 5, `control_record` 6,
    /// `debit_marker` 7, `height` 8). Parsed on demand from the canonical
    /// bytes.
    pub fn field(&self, index: usize) -> Option<&[u8]> {
        if self.bytes.len() < 4 || &self.bytes[..4] != BUNDLE_MAGIC {
            return None;
        }
        let mut rest = &self.bytes[4..];
        for i in 0..9 {
            if rest.len() < 8 {
                return None;
            }
            let len = usize::try_from(u64::from_le_bytes(rest[..8].try_into().unwrap())).ok()?;
            rest = &rest[8..];
            if rest.len() < len {
                return None;
            }
            if i == index {
                return Some(&rest[..len]);
            }
            rest = &rest[len..];
        }
        None
    }

    /// Re-derives a bundle from stored bytes, recomputing the identity so a
    /// corrupted or substituted file cannot impersonate the expected id.
    pub fn decode(bytes: &[u8]) -> Result<Self, JournalError> {
        if bytes.len() > MAX_BUNDLE_BYTES || bytes.len() < 4 || &bytes[..4] != BUNDLE_MAGIC {
            return Err(JournalError::Corrupt);
        }
        let mut rest = &bytes[4..];
        let mut fields: Vec<Vec<u8>> = Vec::with_capacity(9);
        for _ in 0..9 {
            if rest.len() < 8 {
                return Err(JournalError::Corrupt);
            }
            let declared = u64::from_le_bytes(rest[..8].try_into().unwrap());
            // Validate before narrowing: on wasm32 a length of 2^32 + n
            // must not alias n and admit a noncanonical encoding.
            if declared > MAX_FIELD_BYTES as u64 {
                return Err(JournalError::Corrupt);
            }
            let len = usize::try_from(declared).map_err(|_| JournalError::Corrupt)?;
            rest = &rest[8..];
            if rest.len() < len {
                return Err(JournalError::Corrupt);
            }
            fields.push(rest[..len].to_vec());
            rest = &rest[len..];
        }
        if !rest.is_empty() {
            return Err(JournalError::Corrupt);
        }
        let predecessor: [u8; 32] = fields[1]
            .as_slice()
            .try_into()
            .map_err(|_| JournalError::Corrupt)?;
        let next: [u8; 32] = fields[2]
            .as_slice()
            .try_into()
            .map_err(|_| JournalError::Corrupt)?;
        if fields[8].len() != 8 {
            return Err(JournalError::Corrupt);
        }
        let height = u64::from_le_bytes(fields[8].as_slice().try_into().unwrap());
        // Re-hash the parsed fields: the returned identity is derived from
        // content, never trusted from the filename or a header.
        let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
        let id = sha256(&refs);
        Ok(Bundle {
            predecessor,
            next,
            height,
            id,
            bytes: bytes.to_vec(),
        })
    }
}

impl fmt::Debug for Bundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bundle(id={})", hex(&self.id))
    }
}

/// The committed frontier as recorded in the pin file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pin {
    /// Frontier before the committed bundle.
    pub predecessor: [u8; 32],
    /// Frontier after it.
    pub next: [u8; 32],
    /// Identity of the committed bundle; zero at genesis.
    pub bundle: [u8; 32],
    /// Consensus height of the committed bundle; zero at genesis.
    pub height: u64,
}

#[cfg(unix)]
impl Pin {
    fn encode(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 104);
        out.extend_from_slice(HEAD_MAGIC);
        out.extend_from_slice(&self.predecessor);
        out.extend_from_slice(&self.next);
        out.extend_from_slice(&self.bundle);
        out.extend_from_slice(&self.height.to_le_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, JournalError> {
        if bytes.len() != 4 + 104 || &bytes[..4] != HEAD_MAGIC {
            return Err(JournalError::Corrupt);
        }
        Ok(Pin {
            predecessor: bytes[4..36].try_into().unwrap(),
            next: bytes[36..68].try_into().unwrap(),
            bundle: bytes[68..100].try_into().unwrap(),
            height: u64::from_le_bytes(bytes[100..108].try_into().unwrap()),
        })
    }
}

/// The fixed genesis frontier; a directory with no pin starts here.
pub const GENESIS_NEXT: [u8; 32] = [0xA5; 32];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// What a commit returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The bundle was published and the durable pin advanced.
    Committed,
    /// The exact bundle was already committed by an earlier attempt; the
    /// retry reconciled the uncertain outcome and re-established durability.
    AlreadyCommitted,
}

/// What recovery observed on disk.
#[cfg(unix)]
#[derive(Debug)]
pub struct Recovered {
    /// The committed pin as of the last durable rename.
    pub pin: Pin,
    /// Bundle ids present on disk but not referenced by the pin. They carry
    /// no authority: either a crashed commit's residue or a losing candidate.
    pub orphans: Vec<[u8; 32]>,
    /// A leftover unpublished `pin.tmp` was discarded.
    pub dropped_tmp: bool,
    /// Height markers above the committed pin that were discarded as
    /// unpublished residue (a crash between marker write and pin rename).
    pub dropped_heights: Vec<u64>,
}

/// Errors the journal reports. `Crashed` is emitted only by injected fault
/// points and models a process death: the caller must abandon the instance.
#[derive(Debug)]
pub enum JournalError {
    /// The pin no longer names the predecessor this bundle extends, or the
    /// bundle's height is not exactly the next height — which includes a
    /// different bundle claiming an already-committed height.
    Conflict {
        /// The predecessor frontier the rejected bundle claimed.
        expected: [u8; 32],
        /// The frontier the durable pin actually holds.
        found: [u8; 32],
    },
    /// Durable bytes failed parse or content verification. Never overwritten.
    Corrupt,
    /// A field or the serialized bundle exceeded a bound.
    Oversized,
    /// Another live writer holds the commit lock.
    Busy,
    /// Underlying filesystem failure.
    Io(io::Error),
    /// Injected process death at a protocol step.
    Crashed,
}

impl fmt::Display for JournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JournalError::Conflict { expected, found } => {
                write!(
                    f,
                    "conflict: expected predecessor {}, found {}",
                    hex(expected),
                    hex(found)
                )
            }
            JournalError::Corrupt => write!(f, "corrupt durable state"),
            JournalError::Oversized => write!(f, "bundle exceeds bound"),
            JournalError::Busy => write!(f, "commit lock is held"),
            JournalError::Io(e) => write!(f, "io: {e}"),
            JournalError::Crashed => write!(f, "process crashed at fault point"),
        }
    }
}

impl std::error::Error for JournalError {}

impl From<io::Error> for JournalError {
    fn from(e: io::Error) -> Self {
        JournalError::Io(e)
    }
}

/// The labeled protocol steps a store performs. Tests program faults against
/// these names and assert the observed order.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Step {
    /// Acquire the exclusive writer lock.
    Lock,
    /// Read the current pin under the lock.
    ReadPin,
    /// Stage, sync and publish the immutable bundle without replacing a name.
    CreateBundle,
    /// fsync the bundle file.
    SyncBundle,
    /// fsync the bundle's containing directory before publishing a pin.
    SyncBundlesDir,
    /// Write the `heights/<n>` marker binding the height to the bundle id.
    WriteHeightMarker,
    /// fsync the height marker.
    SyncHeightMarker,
    /// fsync the height marker's containing directory before publishing a pin.
    SyncHeightsDir,
    /// Write the `pin.tmp` file.
    WritePinTmp,
    /// fsync `pin.tmp`.
    SyncPinTmp,
    /// Atomic rename `pin.tmp` over `HEAD` — the publication point.
    RenamePin,
    /// fsync the journal directory so the pin rename is durable.
    SyncDir,
}

/// Failure behavior a test programs at a step.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// Step runs normally.
    Pass,
    /// The process dies before the step's filesystem effect.
    CrashBefore,
    /// The filesystem effect lands, then the process dies — the caller cannot
    /// distinguish this from success until it re-reads the disk.
    CrashAfter,
    /// The step fails with an I/O error without performing its effect.
    FailIo,
}

/// The storage operations the protocol needs, split into individually
/// faultable steps.
#[cfg(unix)]
pub trait Store {
    /// Acquire the exclusive writer lock; released when the returned handle
    /// drops, including on process death.
    fn lock(&self, dir: &Path) -> Result<File, JournalError>;
    /// Read the current pin bytes, or `None` when absent.
    fn read_pin(&self, dir: &Path) -> Result<Option<Vec<u8>>, JournalError>;
    /// Read `pin.tmp` bytes when present.
    fn read_pin_tmp(&self, dir: &Path) -> Result<Option<Vec<u8>>, JournalError>;
    /// Discard a leftover `pin.tmp`.
    fn remove_pin_tmp(&self, dir: &Path) -> Result<(), JournalError>;
    /// Atomically publish complete `bundles/<id>` bytes without replacing an
    /// existing name. Returns `false` when it exists; the caller verifies it.
    fn create_bundle(&self, dir: &Path, id: [u8; 32], bytes: &[u8]) -> Result<bool, JournalError>;
    /// fsync the bundle file.
    fn sync_bundle(&self, dir: &Path, id: [u8; 32]) -> Result<(), JournalError>;
    /// fsync the directory containing immutable bundles.
    fn sync_bundles_dir(&self, dir: &Path) -> Result<(), JournalError>;
    /// Read a stored bundle.
    fn read_bundle(&self, dir: &Path, id: [u8; 32]) -> Result<Vec<u8>, JournalError>;
    /// List bundle ids present on disk.
    fn list_bundles(&self, dir: &Path) -> Result<Vec<[u8; 32]>, JournalError>;
    /// Write `heights/<n>` binding the height to a bundle id.
    fn write_height_marker(
        &self,
        dir: &Path,
        height: u64,
        id: [u8; 32],
    ) -> Result<(), JournalError>;
    /// fsync the height marker file.
    fn sync_height_marker(&self, dir: &Path, height: u64) -> Result<(), JournalError>;
    /// fsync the directory containing height markers.
    fn sync_heights_dir(&self, dir: &Path) -> Result<(), JournalError>;
    /// Read the height marker for `height`, when present.
    fn read_height_marker(&self, dir: &Path, height: u64)
        -> Result<Option<[u8; 32]>, JournalError>;
    /// List height markers present on disk, ascending.
    fn list_height_markers(&self, dir: &Path) -> Result<Vec<u64>, JournalError>;
    /// Discard a height marker.
    fn remove_height_marker(&self, dir: &Path, height: u64) -> Result<(), JournalError>;
    /// Write `pin.tmp` bytes.
    fn write_pin_tmp(&self, dir: &Path, bytes: &[u8]) -> Result<(), JournalError>;
    /// fsync `pin.tmp`.
    fn sync_pin_tmp(&self, dir: &Path) -> Result<(), JournalError>;
    /// Rename `pin.tmp` over `HEAD`.
    fn rename_pin(&self, dir: &Path) -> Result<(), JournalError>;
    /// fsync the directory itself.
    fn sync_dir(&self, dir: &Path) -> Result<(), JournalError>;
}

/// Real filesystem store used in production-shaped runs.
#[cfg(unix)]
pub struct FsStore;

#[cfg(unix)]
impl FsStore {
    fn bundle_path(dir: &Path, id: [u8; 32]) -> PathBuf {
        dir.join(BUNDLES).join(hex(&id))
    }

    fn height_path(dir: &Path, height: u64) -> PathBuf {
        dir.join(HEIGHTS).join(format!("{height:016x}"))
    }
}

#[cfg(unix)]
impl Store for FsStore {
    fn lock(&self, dir: &Path) -> Result<File, JournalError> {
        // Create missing ancestors one at a time and durably publish each
        // before creating its children. A retry also re-syncs an existing
        // directory's parent after an uncertain earlier creation.
        create_directory_durable(&std::path::absolute(dir)?)?;
        fs::create_dir_all(dir.join(BUNDLES))?;
        fs::create_dir_all(dir.join(HEIGHTS))?;
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(dir.join(LOCK_FILE))?;
        flock_exclusive(&file).map_err(|_| JournalError::Busy)?;
        File::open(dir)?.sync_all()?;
        Ok(file)
    }

    fn read_pin(&self, dir: &Path) -> Result<Option<Vec<u8>>, JournalError> {
        read_opt(&dir.join(HEAD_FILE), PIN_BYTES)
    }

    fn read_pin_tmp(&self, dir: &Path) -> Result<Option<Vec<u8>>, JournalError> {
        read_opt(&dir.join(HEAD_TMP), PIN_BYTES)
    }

    fn remove_pin_tmp(&self, dir: &Path) -> Result<(), JournalError> {
        match fs::remove_file(dir.join(HEAD_TMP)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn create_bundle(&self, dir: &Path, id: [u8; 32], bytes: &[u8]) -> Result<bool, JournalError> {
        atomic::create_bundle(dir, id, bytes, |_| Ok(()))
    }

    fn sync_bundle(&self, dir: &Path, id: [u8; 32]) -> Result<(), JournalError> {
        Ok(OpenOptions::new()
            .read(true)
            .open(Self::bundle_path(dir, id))?
            .sync_all()?)
    }

    fn sync_bundles_dir(&self, dir: &Path) -> Result<(), JournalError> {
        Ok(File::open(dir.join(BUNDLES))?.sync_all()?)
    }

    fn read_bundle(&self, dir: &Path, id: [u8; 32]) -> Result<Vec<u8>, JournalError> {
        read_bounded(&Self::bundle_path(dir, id), MAX_BUNDLE_BYTES)
    }

    fn list_bundles(&self, dir: &Path) -> Result<Vec<[u8; 32]>, JournalError> {
        let mut out = Vec::new();
        let path = dir.join(BUNDLES);
        if !path.is_dir() {
            return Ok(out);
        }
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit()) {
                let mut id = [0; 32];
                for (i, byte) in id.iter_mut().enumerate() {
                    *byte = u8::from_str_radix(&name[i * 2..i * 2 + 2], 16)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                }
                out.push(id);
            }
        }
        out.sort();
        Ok(out)
    }

    fn write_height_marker(
        &self,
        dir: &Path,
        height: u64,
        id: [u8; 32],
    ) -> Result<(), JournalError> {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(Self::height_path(dir, height))?;
        Ok(file.write_all(&id)?)
    }

    fn sync_height_marker(&self, dir: &Path, height: u64) -> Result<(), JournalError> {
        Ok(OpenOptions::new()
            .read(true)
            .open(Self::height_path(dir, height))?
            .sync_all()?)
    }

    fn sync_heights_dir(&self, dir: &Path) -> Result<(), JournalError> {
        sync_existing_directory(&dir.join(HEIGHTS))
    }

    fn read_height_marker(
        &self,
        dir: &Path,
        height: u64,
    ) -> Result<Option<[u8; 32]>, JournalError> {
        match read_opt(&Self::height_path(dir, height), 32)? {
            None => Ok(None),
            Some(bytes) if bytes.len() == 32 => Ok(Some(bytes.try_into().unwrap())),
            Some(_) => Err(JournalError::Corrupt),
        }
    }

    fn list_height_markers(&self, dir: &Path) -> Result<Vec<u64>, JournalError> {
        let mut out = Vec::new();
        let path = dir.join(HEIGHTS);
        if !path.is_dir() {
            return Ok(out);
        }
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.len() == 16 && name.bytes().all(|b| b.is_ascii_hexdigit()) {
                let height = u64::from_str_radix(&name, 16)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                out.push(height);
            }
        }
        out.sort_unstable();
        Ok(out)
    }

    fn remove_height_marker(&self, dir: &Path, height: u64) -> Result<(), JournalError> {
        match fs::remove_file(Self::height_path(dir, height)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn write_pin_tmp(&self, dir: &Path, bytes: &[u8]) -> Result<(), JournalError> {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(dir.join(HEAD_TMP))?;
        Ok(file.write_all(bytes)?)
    }

    fn sync_pin_tmp(&self, dir: &Path) -> Result<(), JournalError> {
        Ok(OpenOptions::new()
            .read(true)
            .open(dir.join(HEAD_TMP))?
            .sync_all()?)
    }

    fn rename_pin(&self, dir: &Path) -> Result<(), JournalError> {
        Ok(fs::rename(dir.join(HEAD_TMP), dir.join(HEAD_FILE))?)
    }

    fn sync_dir(&self, dir: &Path) -> Result<(), JournalError> {
        sync_existing_directory(dir)
    }
}

#[cfg(unix)]
fn create_directory_durable(path: &Path) -> io::Result<()> {
    if !path.is_dir() {
        if let Some(parent) = path.parent() {
            create_directory_durable(parent)?;
        }
        match fs::create_dir(path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && path.is_dir() => {}
            Err(e) => return Err(e),
        }
    }
    File::open(path)?.sync_all()?;
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(unix)]
fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>, JournalError> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > max as u64 {
        return Err(JournalError::Corrupt);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    // Metadata is only a preflight; cap the read as well in case the file
    // grows between checking its length and consuming its contents.
    file.take(max as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > max {
        return Err(JournalError::Corrupt);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn read_opt(path: &Path, max: usize) -> Result<Option<Vec<u8>>, JournalError> {
    match read_bounded(path, max) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(JournalError::Io(e)) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(unix)]
fn sync_existing_directory(path: &Path) -> Result<(), JournalError> {
    match File::open(path) {
        Ok(directory) => Ok(directory.sync_all()?),
        // Recovering a pristine journal must not create directories. Commit
        // creates this layout under its writer lock before reaching a sync.
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(unix)]
fn flock_exclusive(file: &File) -> io::Result<()> {
    // Exclusive nonblocking advisory lock; the OS releases it when the
    // descriptor closes, including on process death. Required so a crashed
    // writer cannot strand the journal.
    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(fs::TryLockError::WouldBlock) => {
            Err(io::Error::new(io::ErrorKind::WouldBlock, "lock held"))
        }
        Err(fs::TryLockError::Error(e)) => Err(e),
    }
}

/// A store wrapper that records step order and injects programmed faults.
#[cfg(unix)]
pub struct FaultingStore<S: Store> {
    inner: S,
    faults: BTreeMap<Step, Fault>,
    /// Every step attempted, in order — the ordering evidence.
    pub log: RefCell<Vec<Step>>,
}

#[cfg(unix)]
impl<S: Store> FaultingStore<S> {
    /// Wraps a store with the given per-step fault program.
    pub fn new(inner: S, faults: &[(Step, Fault)]) -> Self {
        FaultingStore {
            inner,
            faults: faults.iter().copied().collect(),
            log: RefCell::new(Vec::new()),
        }
    }

    fn apply<T>(
        &self,
        step: Step,
        op: impl FnOnce() -> Result<T, JournalError>,
    ) -> Result<T, JournalError> {
        self.log.borrow_mut().push(step);
        match self.faults.get(&step).copied().unwrap_or(Fault::Pass) {
            Fault::Pass => op(),
            Fault::CrashBefore => Err(JournalError::Crashed),
            Fault::FailIo => Err(JournalError::Io(io::Error::other("injected"))),
            Fault::CrashAfter => {
                op()?;
                Err(JournalError::Crashed)
            }
        }
    }
}

#[cfg(unix)]
impl<S: Store> Store for FaultingStore<S> {
    fn lock(&self, dir: &Path) -> Result<File, JournalError> {
        self.apply(Step::Lock, || self.inner.lock(dir))
    }
    fn read_pin(&self, dir: &Path) -> Result<Option<Vec<u8>>, JournalError> {
        self.apply(Step::ReadPin, || self.inner.read_pin(dir))
    }
    fn read_pin_tmp(&self, dir: &Path) -> Result<Option<Vec<u8>>, JournalError> {
        self.inner.read_pin_tmp(dir)
    }
    fn remove_pin_tmp(&self, dir: &Path) -> Result<(), JournalError> {
        self.inner.remove_pin_tmp(dir)
    }
    fn create_bundle(&self, dir: &Path, id: [u8; 32], bytes: &[u8]) -> Result<bool, JournalError> {
        self.apply(Step::CreateBundle, || {
            self.inner.create_bundle(dir, id, bytes)
        })
    }
    fn sync_bundle(&self, dir: &Path, id: [u8; 32]) -> Result<(), JournalError> {
        self.apply(Step::SyncBundle, || self.inner.sync_bundle(dir, id))
    }
    fn sync_bundles_dir(&self, dir: &Path) -> Result<(), JournalError> {
        self.apply(Step::SyncBundlesDir, || self.inner.sync_bundles_dir(dir))
    }
    fn read_bundle(&self, dir: &Path, id: [u8; 32]) -> Result<Vec<u8>, JournalError> {
        self.inner.read_bundle(dir, id)
    }
    fn list_bundles(&self, dir: &Path) -> Result<Vec<[u8; 32]>, JournalError> {
        self.inner.list_bundles(dir)
    }
    fn write_height_marker(
        &self,
        dir: &Path,
        height: u64,
        id: [u8; 32],
    ) -> Result<(), JournalError> {
        self.apply(Step::WriteHeightMarker, || {
            self.inner.write_height_marker(dir, height, id)
        })
    }
    fn sync_height_marker(&self, dir: &Path, height: u64) -> Result<(), JournalError> {
        self.apply(Step::SyncHeightMarker, || {
            self.inner.sync_height_marker(dir, height)
        })
    }
    fn sync_heights_dir(&self, dir: &Path) -> Result<(), JournalError> {
        self.apply(Step::SyncHeightsDir, || self.inner.sync_heights_dir(dir))
    }
    fn read_height_marker(
        &self,
        dir: &Path,
        height: u64,
    ) -> Result<Option<[u8; 32]>, JournalError> {
        self.inner.read_height_marker(dir, height)
    }
    fn list_height_markers(&self, dir: &Path) -> Result<Vec<u64>, JournalError> {
        self.inner.list_height_markers(dir)
    }
    fn remove_height_marker(&self, dir: &Path, height: u64) -> Result<(), JournalError> {
        self.inner.remove_height_marker(dir, height)
    }
    fn write_pin_tmp(&self, dir: &Path, bytes: &[u8]) -> Result<(), JournalError> {
        self.apply(Step::WritePinTmp, || self.inner.write_pin_tmp(dir, bytes))
    }
    fn sync_pin_tmp(&self, dir: &Path) -> Result<(), JournalError> {
        self.apply(Step::SyncPinTmp, || self.inner.sync_pin_tmp(dir))
    }
    fn rename_pin(&self, dir: &Path) -> Result<(), JournalError> {
        self.apply(Step::RenamePin, || self.inner.rename_pin(dir))
    }
    fn sync_dir(&self, dir: &Path) -> Result<(), JournalError> {
        self.apply(Step::SyncDir, || self.inner.sync_dir(dir))
    }
}

/// The durable journal. One instance serializes commits through an exclusive
/// lock; process death releases the lock and recovery re-reads only disk.
#[cfg(unix)]
pub struct Journal<S: Store> {
    dir: PathBuf,
    /// The frontier an empty journal starts from. Callers bind their
    /// application's genesis commitment here; a stored pin supersedes it.
    genesis_next: [u8; 32],
    store: S,
}

#[cfg(unix)]
impl<S: Store> Journal<S> {
    /// Opens (or creates on first commit) a journal directory, starting an
    /// empty journal at [`GENESIS_NEXT`].
    pub fn new(dir: impl Into<PathBuf>, store: S) -> Self {
        Self::with_genesis(dir, store, GENESIS_NEXT)
    }

    /// Opens a journal whose empty-directory frontier is `genesis_next` —
    /// the adapter binds its application's genesis frontier commitment here.
    pub fn with_genesis(dir: impl Into<PathBuf>, store: S, genesis_next: [u8; 32]) -> Self {
        Journal {
            dir: dir.into(),
            genesis_next,
            store,
        }
    }

    fn genesis(&self) -> Pin {
        Pin {
            predecessor: ZERO,
            next: self.genesis_next,
            bundle: ZERO,
            height: 0,
        }
    }

    /// The directory this journal manages.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Reads and verifies a stored bundle by identity. `None` when absent.
    pub fn bundle(&self, id: [u8; 32]) -> Result<Option<Bundle>, JournalError> {
        match self.store.read_bundle(&self.dir, id) {
            Ok(bytes) => {
                let bundle = Bundle::decode(&bytes)?;
                if bundle.id() != id {
                    return Err(JournalError::Corrupt);
                }
                Ok(Some(bundle))
            }
            Err(JournalError::Io(e)) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Re-reads durable state: verifies the pin's bundle, discards a leftover
    /// `pin.tmp`, and reports orphan bundles. Fails closed on any corruption.
    ///
    /// Writer-side boot recovery only: it also drops height markers above the
    /// committed pin as residue from an interrupted commit, so callers must
    /// never run it while a live writer may be mid-commit — the marker of an
    /// in-flight commit lands before its pin, and dropping it strands the
    /// height. Pure readers use `at_height`/`bundle` without `recover`.
    pub fn recover(&self) -> Result<Recovered, JournalError> {
        let pin = match self.store.read_pin(&self.dir)? {
            None => self.genesis(),
            Some(bytes) => {
                let pin = Pin::decode(&bytes)?;
                if pin.bundle != ZERO {
                    let stored = self
                        .store
                        .read_bundle(&self.dir, pin.bundle)
                        .map_err(|_| JournalError::Corrupt)?;
                    let bundle = Bundle::decode(&stored)?;
                    if bundle.id() != pin.bundle
                        || bundle.predecessor() != pin.predecessor
                        || bundle.next() != pin.next
                    {
                        return Err(JournalError::Corrupt);
                    }
                }
                pin
            }
        };
        // A committed pin must agree with its height marker.
        if pin.height > 0 {
            match self.store.read_height_marker(&self.dir, pin.height)? {
                Some(id) if id == pin.bundle => {}
                Some(_) | None => return Err(JournalError::Corrupt),
            }
        }
        let dropped_tmp = self.store.read_pin_tmp(&self.dir)?.is_some();
        if dropped_tmp {
            self.store.remove_pin_tmp(&self.dir)?;
        }
        // Markers above the committed height are unpublished residue; drop
        // them so a different bundle can still claim that height later.
        let mut dropped_heights = Vec::new();
        for height in self.store.list_height_markers(&self.dir)? {
            if height > pin.height {
                self.store.remove_height_marker(&self.dir, height)?;
                dropped_heights.push(height);
            }
        }
        // Also re-sync when no residue remains: a prior recovery may have
        // removed it and then failed before its directory sync completed.
        self.store.sync_heights_dir(&self.dir)?;
        self.store.sync_dir(&self.dir)?;
        let orphans = self
            .store
            .list_bundles(&self.dir)?
            .into_iter()
            .filter(|id| *id != pin.bundle)
            .collect();
        Ok(Recovered {
            pin,
            orphans,
            dropped_tmp,
            dropped_heights,
        })
    }

    /// The bundle id committed at `height`, when the marker survives.
    pub fn at_height(&self, height: u64) -> Result<Option<[u8; 32]>, JournalError> {
        self.store.read_height_marker(&self.dir, height)
    }

    /// Attempts to commit `bundle`. The predecessor is re-read under the lock,
    /// so a crash that already published this exact bundle reconciles to
    /// `AlreadyCommitted` instead of applying twice. Exact retries revalidate
    /// the complete retained pin, bounded bundle bytes and height marker first;
    /// missing or altered accepted evidence is never repaired or acknowledged.
    pub fn commit(&self, bundle: &Bundle) -> Result<Outcome, JournalError> {
        let lock = self.store.lock(&self.dir).map_err(|_| JournalError::Busy)?;
        let current = match self.store.read_pin(&self.dir)? {
            None => self.genesis(),
            Some(bytes) => Pin::decode(&bytes)?,
        };
        if current.bundle == bundle.id() {
            // The id alone is not evidence that the accepted record remains
            // intact. Revalidate the complete tip and its exact indexed bytes
            // before resyncing directory entries or acknowledging this retry.
            if current.predecessor != bundle.predecessor()
                || current.next != bundle.next()
                || current.height != bundle.height()
            {
                return Err(JournalError::Corrupt);
            }
            let stored =
                self.store
                    .read_bundle(&self.dir, bundle.id())
                    .map_err(|error| match error {
                        JournalError::Io(error) if error.kind() == io::ErrorKind::NotFound => {
                            JournalError::Corrupt
                        }
                        other => other,
                    })?;
            if stored != bundle.bytes()
                || self.store.read_height_marker(&self.dir, current.height)? != Some(bundle.id())
            {
                return Err(JournalError::Corrupt);
            }
            self.store.sync_bundles_dir(&self.dir)?;
            self.store.sync_heights_dir(&self.dir)?;
            self.store.sync_dir(&self.dir)?;
            return Ok(Outcome::AlreadyCommitted);
        }
        if current.next != bundle.predecessor() || bundle.height() != current.height + 1 {
            return Err(JournalError::Conflict {
                expected: bundle.predecessor(),
                found: current.next,
            });
        }
        let created = self
            .store
            .create_bundle(&self.dir, bundle.id(), bundle.bytes())?;
        if !created {
            let stored = self.store.read_bundle(&self.dir, bundle.id())?;
            if stored != bundle.bytes() {
                return Err(JournalError::Corrupt);
            }
        }
        self.store.sync_bundle(&self.dir, bundle.id())?;
        self.store.sync_bundles_dir(&self.dir)?;
        self.store
            .write_height_marker(&self.dir, bundle.height(), bundle.id())?;
        self.store.sync_height_marker(&self.dir, bundle.height())?;
        self.store.sync_heights_dir(&self.dir)?;
        let pin = Pin {
            predecessor: bundle.predecessor(),
            next: bundle.next(),
            bundle: bundle.id(),
            height: bundle.height(),
        };
        self.store.write_pin_tmp(&self.dir, &pin.encode())?;
        self.store.sync_pin_tmp(&self.dir)?;
        self.store.rename_pin(&self.dir)?;
        self.store.sync_dir(&self.dir)?;
        drop(lock);
        Ok(Outcome::Committed)
    }
}

#[cfg(all(test, unix))]
mod tests;

#[cfg(test)]
mod codec_tests {
    use super::*;

    #[test]
    fn field_lengths_cannot_alias_through_a_narrow_pointer_width() {
        let original = Bundle::new(BundleParts {
            certificate: vec![1, 2, 3],
            predecessor: [4; 32],
            next: [5; 32],
            batch: vec![],
            value: vec![],
            configuration: vec![],
            control_record: vec![],
            debit_marker: vec![],
            height: 1,
        })
        .unwrap();
        let decoded = Bundle::decode(original.bytes()).unwrap();
        assert_eq!(decoded.id(), original.id());
        assert_eq!(decoded.bytes(), original.bytes());
        for length in [MAX_FIELD_BYTES as u64 + 1, (1u64 << 32) + 3, u64::MAX] {
            let mut malformed = original.bytes().to_vec();
            malformed[4..12].copy_from_slice(&length.to_le_bytes());
            assert!(matches!(
                Bundle::decode(&malformed),
                Err(JournalError::Corrupt)
            ));
        }
    }
}

/// Kani bounded model-checking harnesses (`cargo kani -p vhalla-journal`).
///
/// Covers the pure decoder surface: a byte string past the scratch bound is
/// rejected without panicking or allocating unbounded state.
#[cfg(kani)]
mod proofs {
    use super::*;

    /// A byte string past the scratch bound is rejected before parsing.
    #[kani::proof]
    fn decode_rejects_oversized_input() {
        let raw = std::vec![0u8; MAX_BUNDLE_BYTES + 1];
        assert!(matches!(Bundle::decode(&raw), Err(JournalError::Corrupt)));
    }
}
