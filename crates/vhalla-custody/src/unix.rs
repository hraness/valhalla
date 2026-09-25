//! Unix backend: uid owners, `0700`/`0600` modes, `O_NOFOLLOW` opens and
//! `dev`/`ino` identity.

use std::{
    fs::{self, File, Metadata, OpenOptions},
    io,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::Path,
};

use crate::{absolute, Error, Owner};

/// Open flags kept identical for every Unix custody open.
const OPEN_FLAGS: i32 = libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY;

pub(crate) fn current_owner() -> Result<Owner, Error> {
    Ok(Owner {
        uid: rustix::process::geteuid().as_raw(),
    })
}

pub(crate) fn create_private_directory(path: &Path) -> Result<(File, Owner), Error> {
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

pub(crate) fn ensure_private_directory(path: &Path) -> Result<(File, Owner), Error> {
    let path = absolute(path)?;
    if fs::symlink_metadata(&path).is_err_and(|e| e.kind() == io::ErrorKind::NotFound) {
        fs::DirBuilder::new().mode(0o700).create(&path)?;
    }
    open_private_directory(&path)
}

pub(crate) fn open_private_directory(path: &Path) -> Result<(File, Owner), Error> {
    let path = absolute(path)?;
    let before = fs::symlink_metadata(&path)?;
    if !before.is_dir() || before.mode() & 0o7777 != 0o700 {
        return Err(Error::UnsafePath);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(OPEN_FLAGS | libc::O_DIRECTORY)
        .open(&path)?;
    let after = file.metadata()?;
    if before.dev() != after.dev() || before.ino() != after.ino() || after.mode() & 0o7777 != 0o700
    {
        return Err(Error::UnsafePath);
    }
    Ok((file, Owner { uid: after.uid() }))
}

pub(crate) fn create_private_file(path: &Path) -> Result<File, Error> {
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(OPEN_FLAGS)
        .open(path)?)
}

pub(crate) fn open_private_file(
    path: &Path,
    owner: Owner,
    max_bytes: usize,
) -> Result<File, Error> {
    let before = fs::symlink_metadata(path)?;
    check_regular_file(path, &before, owner, max_bytes)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(OPEN_FLAGS)
        .open(path)?;
    let after = file.metadata()?;
    check_regular_file(path, &after, owner, max_bytes)?;
    if before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(Error::UnsafePath);
    }
    Ok(file)
}

pub(crate) fn check_regular_file(
    _path: &Path,
    meta: &Metadata,
    owner: Owner,
    max_bytes: usize,
) -> Result<(), Error> {
    if !meta.is_file()
        || meta.mode() & 0o7777 != 0o600
        || meta.nlink() != 1
        || meta.uid() != owner.uid
    {
        return Err(Error::UnsafePath);
    }
    if meta.len() > max_bytes as u64 {
        return Err(Error::Capacity);
    }
    Ok(())
}

pub(crate) fn same_file(path: &Path, file: &File) -> Result<bool, Error> {
    let named = fs::symlink_metadata(path)?;
    let held = file.metadata()?;
    Ok(named.dev() == held.dev() && named.ino() == held.ino())
}

pub(crate) fn same_open_file(first: &File, second: &File) -> Result<bool, Error> {
    let first = first.metadata()?;
    let second = second.metadata()?;
    Ok(first.dev() == second.dev() && first.ino() == second.ino())
}

pub(crate) fn private_file_present(
    path: &Path,
    owner: Owner,
    max_bytes: usize,
) -> Result<bool, Error> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            check_regular_file(path, &meta, owner, max_bytes)?;
            Ok(true)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(Error::Io(e)),
    }
}
