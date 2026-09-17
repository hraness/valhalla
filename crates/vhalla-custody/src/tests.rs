use std::{
    fs::{self, Permissions},
    io::Write,
    os::unix::fs::{symlink, PermissionsExt},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::*;

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "vhalla-custody-test-{}-{n}",
            std::process::id()
        ));
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

fn current_uid() -> u32 {
    let root = TempDir::new();
    let probe = root.path().join("probe");
    fs::write(&probe, b"").unwrap();
    fs::metadata(&probe).unwrap().uid()
}

#[test]
fn ensure_private_directory_creates_missing() {
    let root = TempDir::new();
    let target = root.path().join("fresh");
    let (file, uid) = ensure_private_directory(&target).unwrap();
    assert!(file.metadata().unwrap().is_dir());
    assert_eq!(file.metadata().unwrap().mode() & 0o777, 0o700);
    assert_eq!(uid, current_uid());
}

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

#[test]
fn open_private_directory_rejects_symlink() {
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
    let uid = current_uid();
    let bytes = read_private_file(&path, uid, 64).unwrap();
    assert_eq!(bytes, b"hello");
}

#[test]
fn read_private_file_rejects_group_readable() {
    let root = TempDir::new();
    let dir = root.path().join("store");
    ensure_private_directory(&dir).unwrap();
    let path = dir.join("leaky");
    fs::write(&path, b"x").unwrap();
    fs::set_permissions(&path, Permissions::from_mode(0o640)).unwrap();
    let uid = current_uid();
    assert!(matches!(
        read_private_file(&path, uid, 64),
        Err(Error::UnsafePath)
    ));
}

#[test]
fn read_private_file_rejects_symlink() {
    let root = TempDir::new();
    let dir = root.path().join("store");
    ensure_private_directory(&dir).unwrap();
    let real = dir.join("real");
    let link = dir.join("link");
    fs::write(&real, b"x").unwrap();
    fs::set_permissions(&real, Permissions::from_mode(0o600)).unwrap();
    symlink(&real, &link).unwrap();
    let uid = current_uid();
    assert!(matches!(
        read_private_file(&link, uid, 64),
        Err(Error::UnsafePath)
    ));
}

#[test]
fn read_private_file_rejects_oversize() {
    let root = TempDir::new();
    let dir = root.path().join("store");
    ensure_private_directory(&dir).unwrap();
    let path = dir.join("big");
    fs::write(&path, vec![0u8; 200]).unwrap();
    fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
    let uid = current_uid();
    assert!(matches!(
        read_private_file(&path, uid, 64),
        Err(Error::Capacity)
    ));
}

#[test]
fn private_file_present_detects_existing_and_missing() {
    let root = TempDir::new();
    let dir = root.path().join("store");
    ensure_private_directory(&dir).unwrap();
    let present = dir.join("present");
    let missing = dir.join("missing");
    fs::write(&present, b"x").unwrap();
    fs::set_permissions(&present, Permissions::from_mode(0o600)).unwrap();
    let uid = current_uid();
    assert!(private_file_present(&present, uid, 64).unwrap());
    assert!(!private_file_present(&missing, uid, 64).unwrap());
}
