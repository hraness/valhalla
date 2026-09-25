//! Shared local-custody primitives.
//!
//! This crate ports the portable contract in [`local-custody`](https://github.com/hraness/local-custody)
//! to Rust for the Valhalla workspace. It is intentionally product-neutral: no
//! product names, wire formats, or domain semantics. Callers keep their own error
//! payloads and lifecycle policies.
//!
//! The contract is the same on every supported platform: private directories and
//! files are created exclusively and refused when the name already exists, they
//! admit only their owner, links and reparse points are refused, the opened
//! handle is re-validated against the metadata observed before the open, reads
//! are bounded to an exact declared length, and locks are retried briefly rather
//! than awaited.
//!
//! On Unix the owner is a uid and privacy is an exact `0700`/`0600` mode. On
//! Windows the owner is a SID and privacy is a protected DACL holding exactly
//! one ACE — full control granted to the object's owner — attached at creation
//! so a name never exists with a wider inherited grant; identity after open uses
//! the volume serial and file index like Unix `dev`/`ino`, which requires NTFS
//! semantics (FAT-family filesystems cannot satisfy this contract).

#![cfg(any(unix, windows))]

use std::{
    fs::{self, File, Metadata},
    io::{self, Read},
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
use unix as platform;
#[cfg(windows)]
use windows as platform;

/// Product-neutral custody failure.
#[derive(Debug)]
pub enum Error {
    /// A raw filesystem or syscall failed.
    Io(io::Error),
    /// A path, type, link, owner, or privacy check failed.
    UnsafePath,
    /// Another cooperating process holds the requested lock.
    Busy,
    /// A bounded value exceeded its declared limit.
    Capacity,
    /// A read returned inconsistent or truncated bytes.
    Corrupt,
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// The owner identity a custody check requires.
///
/// `Owner` is a platform token for "the user who must own this object": a uid
/// on Unix, the owner's SID bytes on Windows. [`Owner::current`] is the running
/// process's user; the directory opens return the owner observed on disk. The
/// only portable operation is equality.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Owner {
    uid: u32,
}
/// The owner identity a custody check requires (Windows representation; see
/// the cfg'd Unix field for the shared contract).
#[cfg(windows)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Owner {
    // Windows SIDs never exceed `SECURITY_MAX_SID_SIZE` (68) bytes.
    len: u8,
    sid: [u8; 68],
}

impl Owner {
    /// The owner identity of the running process's user.
    ///
    /// On Unix this is the effective uid. On Windows it is the user SID of the
    /// process token; a token that cannot be queried fails rather than guessing.
    pub fn current() -> Result<Owner, Error> {
        platform::current_owner()
    }
}

/// Resolve a path relative to the current working directory.
pub fn absolute(path: &Path) -> Result<PathBuf, Error> {
    Ok(if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    })
}

/// Create a fresh owner-private directory.
///
/// Fails if the path already exists, matching the existing Valhalla stores'
/// `create` semantics. Returns the opened directory file and its owner.
/// On Unix the mode is `0700`; on Windows the directory is created with a
/// protected DACL granting full control to the current user and nothing else.
pub fn create_private_directory(path: &Path) -> Result<(File, Owner), Error> {
    platform::create_private_directory(path)
}

/// Open a private directory, creating it if necessary.
///
/// Returns the opened directory file and the owner identity observed on disk;
/// it does not require that owner to be the current process — callers decide.
/// The caller is responsible for any ancestor syncs.
pub fn ensure_private_directory(path: &Path) -> Result<(File, Owner), Error> {
    platform::ensure_private_directory(path)
}

/// Open an existing private directory for inspection or `sync_all`.
///
/// On Windows the directory handle is opened through `FILE_FLAG_BACKUP_SEMANTICS`
/// (the only way to open a directory) and `FILE_FLAG_OPEN_REPARSE_POINT`, so a
/// junction or link is inspected rather than followed and then refused. The
/// handle is writable so `sync_all` reaches `FlushFileBuffers`; NTFS journals
/// directory metadata, so the sync commits pending name changes the same way a
/// Unix directory `fsync` does.
pub fn open_private_directory(path: &Path) -> Result<(File, Owner), Error> {
    platform::open_private_directory(path)
}

/// Create a new private file with exclusive create (`O_CREAT | O_EXCL`).
///
/// On Unix the mode is `0600`; on Windows the file is created with a protected
/// DACL granting full control to the current user and nothing else — never the
/// parent directory's inherited ACEs, which commonly include SYSTEM and the
/// Administrators group.
pub fn create_private_file(path: &Path) -> Result<File, Error> {
    platform::create_private_file(path)
}

/// Open an existing private regular file with TOCTOU identity checks.
///
/// `owner` is the expected owner; `max_bytes` is the inclusive size bound.
pub fn open_private_file(path: &Path, owner: Owner, max_bytes: usize) -> Result<File, Error> {
    platform::open_private_file(path, owner, max_bytes)
}

/// Read a private regular file with the stable-read contract.
///
/// The file is opened, re-validated after open, read exactly to its observed
/// length, and checked for trailing bytes (a growth indicator).
pub fn read_private_file(path: &Path, owner: Owner, max_bytes: usize) -> Result<Vec<u8>, Error> {
    let mut file = open_private_file(path, owner, max_bytes)?;
    let len = usize::try_from(file.metadata()?.len()).map_err(|_| Error::Capacity)?;
    if len > max_bytes {
        return Err(Error::Capacity);
    }
    let mut buf = vec![0; len];
    file.read_exact(&mut buf)?;
    if file.read(&mut [0; 1])? != 0 {
        return Err(Error::Corrupt);
    }
    Ok(buf)
}

/// Validate metadata for a private regular file.
///
/// Checks the object is a regular file, not a link or reparse point, linked
/// exactly once, owned by `owner`, private to that owner, and within
/// `max_bytes`. `path` is used where a check cannot be answered from `meta`
/// alone: on Unix `Metadata` already carries the owner uid, while on Windows
/// the owner SID, DACL and link count live behind a live handle, so `path` is
/// opened (read-only, never following a reparse point) to answer them. The
/// post-open checks in `open_private_file` remain the enforcement point that
/// binds the result to the actual object.
pub fn check_regular_file(
    path: &Path,
    meta: &Metadata,
    owner: Owner,
    max_bytes: usize,
) -> Result<(), Error> {
    platform::check_regular_file(path, meta, owner, max_bytes)
}

/// Whether `path` currently names the same filesystem object as the open
/// `file`.
///
/// The post-open identity check behind `open_private_directory` and
/// `open_private_file`, exposed for callers that validated a name and hold the
/// opened object: the name must still resolve to the same object. Unix
/// compares `dev`/`ino` of the name's metadata and the handle's metadata;
/// Windows compares the volume serial and file index of two live handles.
pub fn same_file(path: &Path, file: &File) -> Result<bool, Error> {
    platform::same_file(path, file)
}

/// Whether two open handles refer to the same filesystem object.
///
/// Unix compares `dev`/`ino` of the handles' metadata; Windows compares the
/// volume serial and file index of the two handles.
pub fn same_open_file(first: &File, second: &File) -> Result<bool, Error> {
    platform::same_open_file(first, second)
}

/// Acquire an exclusive advisory lock, retrying briefly before failing `Busy`.
///
/// A flock-style lock belongs to the open file description: a process spawning
/// a child transiently shares every inherited descriptor, so a peer's `close`
/// can appear to lag while a concurrent spawn is between fork and exec. The
/// retry bound (20 attempts × 25 ms ≈ 500 ms) absorbs that transient release
/// window; a genuinely held lock still refuses within the bound, never blocks.
pub fn acquire_exclusive(file: &File) -> Result<(), Error> {
    for _ in 0..20 {
        match file.try_lock() {
            Ok(()) => return Ok(()),
            Err(fs::TryLockError::WouldBlock) => {
                thread::sleep(Duration::from_millis(25));
            }
            Err(fs::TryLockError::Error(e)) => return Err(Error::Io(e)),
        }
    }
    Err(Error::Busy)
}

/// Acquire a shared advisory lock, retrying briefly before failing `Busy`.
///
/// The default bound (600 attempts × 50 ms ≈ 30 s) matches the longest realistic
/// writer hold in the Valhalla stores.
pub fn acquire_shared(file: &File) -> Result<(), Error> {
    for _ in 0..600 {
        match file.try_lock_shared() {
            Ok(()) => return Ok(()),
            Err(fs::TryLockError::WouldBlock) => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(fs::TryLockError::Error(e)) => return Err(Error::Io(e)),
        }
    }
    Err(Error::Busy)
}

/// Check whether a private regular file exists at `path`.
pub fn private_file_present(path: &Path, owner: Owner, max_bytes: usize) -> Result<bool, Error> {
    platform::private_file_present(path, owner, max_bytes)
}

#[cfg(test)]
mod tests;
