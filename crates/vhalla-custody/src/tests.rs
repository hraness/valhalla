use std::{
    fs,
    io::Write,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(unix)]
use std::{fs::Permissions, os::unix::fs::PermissionsExt};

use crate::*;

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        path.push(format!("vhalla-custody-test-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &PathBuf {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn ensure_private_directory_creates_missing() {
    let root = TempDir::new();
    let target = root.path().join("fresh");
    let (file, owner) = ensure_private_directory(&target).unwrap();
    assert!(file.metadata().unwrap().is_dir());
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(file.metadata().unwrap().mode() & 0o777, 0o700);
    }
    assert_eq!(owner, Owner::current().unwrap());
}

/// A directory made by the plain filesystem is not private: on Unix it carries
/// a permissive mode, on Windows it inherits the parent's wider DACL.
#[cfg(unix)]
#[test]
fn open_private_directory_rejects_permissive() {
    let root = TempDir::new();
    let target = root.path().join("loose");
    fs::create_dir(&target).unwrap();
    fs::set_permissions(&target, Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        open_private_directory(&target),
        Err(Error::UnsafePath)
    ));
}

#[cfg(windows)]
#[test]
fn open_private_directory_rejects_inherited_acl() {
    let root = TempDir::new();
    let target = root.path().join("inherited");
    fs::create_dir(&target).unwrap();
    assert!(matches!(
        open_private_directory(&target),
        Err(Error::UnsafePath)
    ));
}

#[cfg(unix)]
#[test]
fn open_private_directory_rejects_symlink() {
    use std::os::unix::fs::symlink;
    let root = TempDir::new();
    let real = root.path().join("real");
    let link = root.path().join("link");
    fs::create_dir(&real).unwrap();
    fs::set_permissions(&real, Permissions::from_mode(0o700)).unwrap();
    symlink(&real, &link).unwrap();
    assert!(matches!(
        open_private_directory(&link),
        Err(Error::UnsafePath)
    ));
}

#[test]
fn create_and_read_private_file_roundtrip() {
    let root = TempDir::new();
    let dir = root.path().join("store");
    ensure_private_directory(&dir).unwrap();
    let path = dir.join("record");
    {
        let mut file = create_private_file(&path).unwrap();
        file.write_all(b"hello").unwrap();
        file.sync_all().unwrap();
    }
    let owner = Owner::current().unwrap();
    let bytes = read_private_file(&path, owner, 64).unwrap();
    assert_eq!(bytes, b"hello");
}

#[cfg(unix)]
#[test]
fn read_private_file_rejects_group_readable() {
    let root = TempDir::new();
    let dir = root.path().join("store");
    ensure_private_directory(&dir).unwrap();
    let path = dir.join("leaky");
    fs::write(&path, b"x").unwrap();
    fs::set_permissions(&path, Permissions::from_mode(0o640)).unwrap();
    let owner = Owner::current().unwrap();
    assert!(matches!(
        read_private_file(&path, owner, 64),
        Err(Error::UnsafePath)
    ));
}

/// A file created by the plain filesystem inside an ordinary directory
/// inherits the directory's DACL — user, SYSTEM and Administrators — which is
/// not the owner-only grant the contract requires.
#[cfg(windows)]
#[test]
fn read_private_file_rejects_inherited_acl() {
    let root = TempDir::new();
    let path = root.path().join("inherited");
    fs::write(&path, b"x").unwrap();
    let owner = Owner::current().unwrap();
    assert!(matches!(
        read_private_file(&path, owner, 64),
        Err(Error::UnsafePath)
    ));
}

#[test]
fn private_file_present_detects_existing_and_missing() {
    let root = TempDir::new();
    let dir = root.path().join("store");
    ensure_private_directory(&dir).unwrap();
    let present = dir.join("present");
    let missing = dir.join("missing");
    create_private_file(&present).unwrap();
    let owner = Owner::current().unwrap();
    assert!(private_file_present(&present, owner, 64).unwrap());
    assert!(!private_file_present(&missing, owner, 64).unwrap());
}

/// A second link is a hardlink on Unix and a hard link on NTFS alike: the
/// link count is the refusal, and both names refuse.
#[test]
fn private_file_rejects_extra_link() {
    let root = TempDir::new();
    let dir = root.path().join("store");
    ensure_private_directory(&dir).unwrap();
    let path = dir.join("linked");
    {
        let mut file = create_private_file(&path).unwrap();
        file.write_all(b"x").unwrap();
    }
    let second = dir.join("second");
    fs::hard_link(&path, &second).unwrap();
    let owner = Owner::current().unwrap();
    assert!(matches!(
        read_private_file(&path, owner, 64),
        Err(Error::UnsafePath)
    ));
    assert!(matches!(
        read_private_file(&second, owner, 64),
        Err(Error::UnsafePath)
    ));
}

#[test]
fn read_private_file_rejects_oversize() {
    let root = TempDir::new();
    let dir = root.path().join("store");
    ensure_private_directory(&dir).unwrap();
    let path = dir.join("big");
    {
        let mut file = create_private_file(&path).unwrap();
        file.write_all(&[0u8; 200]).unwrap();
    }
    let owner = Owner::current().unwrap();
    assert!(matches!(
        read_private_file(&path, owner, 64),
        Err(Error::Capacity)
    ));
}

#[cfg(unix)]
#[test]
fn read_private_file_rejects_symlink() {
    use std::os::unix::fs::symlink;
    let root = TempDir::new();
    let dir = root.path().join("store");
    ensure_private_directory(&dir).unwrap();
    let real = dir.join("real");
    let link = dir.join("link");
    fs::write(&real, b"x").unwrap();
    fs::set_permissions(&real, Permissions::from_mode(0o600)).unwrap();
    symlink(&real, &link).unwrap();
    let owner = Owner::current().unwrap();
    assert!(matches!(
        read_private_file(&link, owner, 64),
        Err(Error::UnsafePath)
    ));
}

/// Custody-created objects satisfy the owner token equality checks on both
/// platforms; on Windows that exercises the SID query and DACL walk.
#[cfg(windows)]
#[test]
fn custody_created_objects_return_current_owner() {
    let root = TempDir::new();
    let dir = root.path().join("owned");
    let (_, dir_owner) = create_private_directory(&dir).unwrap();
    assert_eq!(dir_owner, Owner::current().unwrap());
    let file = dir.join("record");
    create_private_file(&file).unwrap();
    assert!(private_file_present(&file, dir_owner, 64).unwrap());
}

#[test]
fn acquire_locks_roundtrip() {
    let root = TempDir::new();
    let dir = root.path().join("store");
    ensure_private_directory(&dir).unwrap();
    let path = dir.join("lock");
    let file = create_private_file(&path).unwrap();
    acquire_exclusive(&file).unwrap();
    file.unlock().unwrap();
    acquire_shared(&file).unwrap();
    file.unlock().unwrap();
}
