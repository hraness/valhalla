//! Shared Unix local-custody primitives.
//!
//! This crate ports the portable contract in [`local-custody`](https://github.com/hraness/local-custody)
//! to Rust for the Valhalla workspace. It is intentionally product-neutral: no
//! product names, wire formats, or domain semantics. Callers keep their own error
//! payloads and lifecycle policies.

#![cfg(unix)]

use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

/// Product-neutral custody failure.
#[derive(Debug)]
pub enum Error {
    /// A raw filesystem or syscall failed.
    Io(io::Error),
    /// A path, type, link, owner, or mode check failed.
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

/// Resolve a path relative to the current working directory.
pub fn absolute(path: &Path) -> Result<PathBuf, Error> {
    Ok(if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    })
}

/// Create a fresh private directory with mode `0700`.
///
/// Fails if the path already exists, matching the existing Valhalla stores'
/// `create` semantics. Returns the opened directory file and owner uid.
pub fn create_private_directory(path: &Path) -> Result<(File, u32), Error> {
    let path = absolute(path)?;
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
        Ok(_) => {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "private directory already exists",
            )));
        }
    }
    fs::DirBuilder::new().mode(0o700).create(&path)?;
    open_private_directory(&path)
}

/// Open a private directory, creating it if necessary with mode `0700`.
///
/// Returns the opened directory file and the owner uid observed on disk. The
/// caller is responsible for any ancestor syncs.
pub fn ensure_private_directory(path: &Path) -> Result<(File, u32), Error> {
    let path = absolute(path)?;
    if fs::symlink_metadata(&path)
        .is_err_and(|e| e.kind() == io::ErrorKind::NotFound)
    {
        fs::DirBuilder::new().mode(0o700).create(&path)?;
    }
    open_private_directory(&path)
}

/// Open an existing private directory for inspection or `fsync`.
pub fn open_private_directory(path: &Path) -> Result<(File, u32), Error> {
    let path = absolute(path)?;
    let before = fs::symlink_metadata(&path)?;
    if !before.is_dir() || before.mode() & 0o7777 != 0o700 {
        return Err(Error::UnsafePath);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(
            libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_DIRECTORY | libc::O_NOCTTY,
        )
        .open(&path)?;
    let after = file.metadata()?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || after.mode() & 0o7777 != 0o700
    {
        return Err(Error::UnsafePath);
    }
    Ok((file, after.uid()))
}

/// Create a new private file with `O_CREAT | O_EXCL` and mode `0600`.
pub fn create_private_file(path: &Path) -> Result<File, Error> {
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)?)
}

/// Open an existing private regular file with TOCTOU identity checks.
///
/// `uid` is the expected owner; `max_bytes` is the inclusive size bound.
pub fn open_private_file(path: &Path, uid: u32, max_bytes: usize) -> Result<File, Error> {
    let before = fs::symlink_metadata(path)?;
    check_regular_file(&before, uid, max_bytes)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)?;
    let after = file.metadata()?;
    check_regular_file(&after, uid, max_bytes)?;
    if before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(Error::UnsafePath);
    }
    Ok(file)
}

/// Read a private regular file with the stable-read contract.
///
/// The file is opened, re-validated after open, read exactly to its observed
/// length, and checked for trailing bytes (a growth indicator).
pub fn read_private_file(path: &Path, uid: u32, max_bytes: usize) -> Result<Vec<u8>, Error> {
    let mut file = open_private_file(path, uid, max_bytes)?;
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
pub fn check_regular_file(meta: &Metadata, uid: u32, max_bytes: usize) -> Result<(), Error> {
    if !meta.is_file() || meta.mode() & 0o7777 != 0o600 || meta.nlink() != 1 || meta.uid() != uid {
        return Err(Error::UnsafePath);
    }
    if meta.len() > max_bytes as u64 {
        return Err(Error::Capacity);
    }
    Ok(())
}

/// Acquire an exclusive advisory lock, failing `Busy` instead of blocking.
pub fn acquire_exclusive(file: &File) -> Result<(), Error> {
    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(fs::TryLockError::WouldBlock) => Err(Error::Busy),
        Err(fs::TryLockError::Error(e)) => Err(Error::Io(e)),
    }
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
pub fn private_file_present(path: &Path, uid: u32, max_bytes: usize) -> Result<bool, Error> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            check_regular_file(&meta, uid, max_bytes)?;
            Ok(true)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(Error::Io(e)),
    }
}

#[cfg(test)]
mod tests;
