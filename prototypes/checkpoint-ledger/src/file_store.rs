//! Optional Unix filesystem adapter for the persistence experiment.
//!
//! The directory and all ancestors must be owned and controlled by the local
//! operator, on a local filesystem that implements file locks, atomic rename,
//! hard links, and file/directory synchronization. Other writers must use this
//! adapter's lock. Path checks reject existing symlinks; they are not a sandbox
//! against an owner or root replacing paths between system calls. The directory
//! is mode 0700 and records mode 0600. This adapter neither checks OS ownership
//! nor supplies malicious-disk rollback protection: the pin is on the same disk.
//!
//! Immutable bundles are synced before publication through a hard link, followed
//! by a directory sync. A pin is written and synced at a temporary path, renamed,
//! then directory-synced. I/O errors may leave an uncertain committed outcome;
//! callers must reconcile and re-sync a retry. Orphans consume capacity and are
//! never pruned automatically. Only fixed temporary files are replaced/removed.
//! The live tests exercise API-level operations, not physical power-loss behavior.

use crate::persistence::{bundle_id, BundleId, Pin, Storage, MAX_BUNDLE_BYTES, PIN_BYTES};
use alloc::{string::String, vec, vec::Vec};
use core::fmt;
use std::fs::{self, DirBuilder, File, Metadata, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Maximum retained bundle files, including unreferenced crash leftovers.
pub const MAX_BUNDLES: usize = 64;
const LOCK: &str = "store.lock";
const PIN: &str = "pin";
const PIN_TEMP: &str = "pin.tmp";
const BUNDLE_TEMP: &str = "bundle.tmp";

/// Storage failures preserve missing files, malformed data, and lock contention
/// as distinct outcomes. Any I/O error during publication can be indeterminate.
#[derive(Debug)]
pub enum Error {
    /// An operating system error, retaining its original error kind.
    Io(io::Error),
    /// Capacity must be between one and [`MAX_BUNDLES`].
    InvalidBound,
    /// A symlink, unexpected entry/type, or non-private permissions were found.
    UnsafePath,
    /// Another adapter currently holds the directory's lifetime lock.
    Busy,
    /// The pin exists but does not have its exact canonical representation.
    MalformedPin,
    /// A record has the wrong digest, different immutable bytes, or wrong size.
    CorruptBundle,
    /// The configured bundle-file capacity has been reached.
    Capacity,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "filesystem error: {error}"),
            Self::InvalidBound => f.write_str("invalid bundle capacity"),
            Self::UnsafePath => f.write_str("unsafe store path or permissions"),
            Self::Busy => f.write_str("store is already locked"),
            Self::MalformedPin => f.write_str("malformed persistent pin"),
            Self::CorruptBundle => f.write_str("corrupt or oversized bundle"),
            Self::Capacity => f.write_str("bundle capacity reached"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// One exclusive lifetime lock over an owner-private directory.
///
/// No public handle escapes and the lock is released on drop. A missing pin is
/// represented as `None`; corrupt pins and missing store directories are errors.
/// Explicit initialization remains the persistence protocol caller's decision.
#[derive(Debug)]
pub struct FileStore {
    path: PathBuf,
    directory: File,
    _lock: File,
    max_bundles: usize,
}

impl FileStore {
    /// Create a previously nonexistent directory and acquire its lifetime lock.
    ///
    /// Existing directories are always rejected, even when empty. A failed
    /// creation may leave a partial directory; no automatic cleanup or rebootstrap
    /// occurs. The parent directory must already exist and be owner-controlled.
    pub fn create_new(path: impl AsRef<Path>, max_bundles: usize) -> Result<Self, Error> {
        validate_bound(max_bundles)?;
        let path = path.as_ref();
        DirBuilder::new().mode(0o700).create(path)?;
        let path = fs::canonicalize(path)?;
        let metadata = fs::symlink_metadata(&path)?;
        validate_directory(&metadata)?;
        let directory = File::open(&path)?;
        let lock = create_private(&path.join(LOCK))?;
        acquire_lock(&lock)?;
        lock.sync_all()?;
        directory.sync_all()?;
        File::open(path.parent().ok_or(Error::UnsafePath)?)?.sync_all()?;
        Ok(Self {
            path,
            directory,
            _lock: lock,
            max_bundles,
        })
    }

    /// Open an existing store without creating a directory, lock file, or pin.
    ///
    /// A truncated/corrupt pin fails here, rather than being treated as an empty
    /// store. Stale regular temporary files are ignored until the next write.
    pub fn open(path: impl AsRef<Path>, max_bundles: usize) -> Result<Self, Error> {
        validate_bound(max_bundles)?;
        let path = path.as_ref();
        validate_directory(&fs::symlink_metadata(path)?)?;
        let path = fs::canonicalize(path)?;
        let directory = File::open(&path)?;
        let lock_path = path.join(LOCK);
        validate_regular(&fs::symlink_metadata(&lock_path)?)?;
        let lock = OpenOptions::new().read(true).write(true).open(lock_path)?;
        validate_regular(&lock.metadata()?)?;
        acquire_lock(&lock)?;
        let mut store = Self {
            path,
            directory,
            _lock: lock,
            max_bundles,
        };
        store.bundle_count()?;
        store.read_pin()?;
        Ok(store)
    }

    fn bundle_path(&self, id: BundleId) -> PathBuf {
        self.path.join(bundle_name(id))
    }

    fn bundle_count(&self) -> Result<usize, Error> {
        let mut count = 0;
        for entry in fs::read_dir(&self.path)? {
            let entry = entry?;
            validate_regular(&fs::symlink_metadata(entry.path())?)?;
            let name = entry.file_name();
            let name = name.to_str().ok_or(Error::UnsafePath)?;
            if matches!(name, LOCK | PIN | PIN_TEMP | BUNDLE_TEMP) {
                continue;
            }
            if !is_bundle_name(name) {
                return Err(Error::UnsafePath);
            }
            count += 1;
            if count > self.max_bundles {
                return Err(Error::Capacity);
            }
        }
        Ok(count)
    }

    // Removing only fixed temporary names avoids truncating an inode that may
    // still be linked as an immutable bundle after an interrupted publication.
    fn fresh_temp(&self, name: &str) -> Result<File, Error> {
        let path = self.path.join(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                validate_regular(&metadata)?;
                fs::remove_file(&path)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        create_private(&path)
    }

    fn sync_bundle(&self, id: BundleId) -> Result<(), Error> {
        let file = open_private(&self.bundle_path(id))?;
        file.sync_all()?;
        self.directory.sync_all()?;
        Ok(())
    }
}

impl Storage for FileStore {
    type Error = Error;

    fn read_pin(&mut self) -> Result<Option<Pin>, Error> {
        let path = self.path.join(PIN);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => validate_regular(&metadata)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        let raw = read_bounded(&path, PIN_BYTES, Error::MalformedPin)?;
        let pin = Pin::decode(&raw).map_err(|_| Error::MalformedPin)?;
        if pin.encode() != raw {
            return Err(Error::MalformedPin);
        }
        Ok(Some(pin))
    }

    fn read_bundle(&mut self, id: BundleId) -> Result<Vec<u8>, Error> {
        let raw = read_bounded(
            &self.bundle_path(id),
            MAX_BUNDLE_BYTES,
            Error::CorruptBundle,
        )?;
        if bundle_id(&raw) != id {
            return Err(Error::CorruptBundle);
        }
        Ok(raw)
    }

    fn put_bundle(&mut self, id: BundleId, raw: &[u8]) -> Result<(), Error> {
        if raw.len() > MAX_BUNDLE_BYTES || bundle_id(raw) != id {
            return Err(Error::CorruptBundle);
        }
        let count = self.bundle_count()?;
        let path = self.bundle_path(id);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                if self.read_bundle(id)? != raw {
                    return Err(Error::CorruptBundle);
                }
                // Even identical visible bytes may come from a prior attempt
                // whose directory sync failed. Retry the durability boundary.
                return self.sync_bundle(id);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        if count >= self.max_bundles {
            return Err(Error::Capacity);
        }
        let mut temporary = self.fresh_temp(BUNDLE_TEMP)?;
        temporary.write_all(raw)?;
        temporary.sync_all()?;
        drop(temporary);
        // Hard-link publication is atomic and refuses to overwrite any existing
        // destination. The temporary inode was fully synced before it is named.
        fs::hard_link(self.path.join(BUNDLE_TEMP), &path)?;
        self.directory.sync_all()?;
        fs::remove_file(self.path.join(BUNDLE_TEMP))?;
        self.directory.sync_all()?;
        Ok(())
    }

    fn compare_exchange_pin(&mut self, expected: Option<&Pin>, next: &Pin) -> Result<bool, Error> {
        let current = self.read_pin()?;
        if current.as_ref() != expected {
            return Ok(false);
        }
        let raw = next.encode();
        if raw.len() != PIN_BYTES || Pin::decode(&raw).ok().as_ref() != Some(next) {
            return Err(Error::MalformedPin);
        }
        // A pin never becomes discoverable before its content-addressed bundle.
        self.read_bundle(next.bundle())?;
        self.sync_bundle(next.bundle())?;
        let mut temporary = self.fresh_temp(PIN_TEMP)?;
        temporary.write_all(&raw)?;
        temporary.sync_all()?;
        drop(temporary);
        fs::rename(self.path.join(PIN_TEMP), self.path.join(PIN))?;
        // After rename, any error is indeterminate, never a false CAS result.
        // Identical-pin retries deliberately repeat rename and directory sync.
        self.directory.sync_all()?;
        Ok(true)
    }
}

fn validate_bound(max_bundles: usize) -> Result<(), Error> {
    if !(1..=MAX_BUNDLES).contains(&max_bundles) {
        return Err(Error::InvalidBound);
    }
    Ok(())
}

fn validate_directory(metadata: &Metadata) -> Result<(), Error> {
    if !metadata.is_dir() || metadata.permissions().mode() & 0o7777 != 0o700 {
        return Err(Error::UnsafePath);
    }
    Ok(())
}

fn validate_regular(metadata: &Metadata) -> Result<(), Error> {
    if !metadata.is_file() || metadata.permissions().mode() & 0o7777 != 0o600 {
        return Err(Error::UnsafePath);
    }
    Ok(())
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
    let file = File::open(path)?;
    validate_regular(&file.metadata()?)?;
    Ok(file)
}

fn acquire_lock(lock: &File) -> Result<(), Error> {
    match lock.try_lock() {
        Ok(()) => Ok(()),
        Err(TryLockError::WouldBlock) => Err(Error::Busy),
        Err(TryLockError::Error(error)) => Err(Error::Io(error)),
    }
}

fn read_bounded(path: &Path, max_bytes: usize, invalid: Error) -> Result<Vec<u8>, Error> {
    let mut file = open_private(path)?;
    let length = file.metadata()?.len();
    if length > max_bytes as u64 {
        return Err(invalid);
    }
    let mut raw = vec![0; length as usize];
    file.read_exact(&mut raw)?;
    let mut extra = [0];
    if file.read(&mut extra)? != 0 {
        return Err(invalid);
    }
    Ok(raw)
}

fn bundle_name(id: BundleId) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::with_capacity(71);
    for byte in id.0 {
        name.push(HEX[usize::from(byte >> 4)] as char);
        name.push(HEX[usize::from(byte & 15)] as char);
    }
    name.push_str(".bundle");
    name
}

fn is_bundle_name(name: &str) -> bool {
    name.len() == 71
        && name.ends_with(".bundle")
        && name.as_bytes()[..64]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Sandbox(PathBuf);

    impl Sandbox {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "vhalla-filestore-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            // Exact generated test directory; create_new prevents reuse of any
            // preexisting directory. Cleanup is restricted to this test fixture.
            DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }

        fn store(&self) -> PathBuf {
            self.0.join("store")
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn pin_for(generation: u64, id: BundleId) -> Pin {
        // Deliberately unauthenticated record: backend tests exercise storage,
        // while the persistence module separately verifies certified history.
        let mut raw = b"vhalla/checkpoint-store/pin/v1".to_vec();
        raw.extend_from_slice(&1u16.to_be_bytes());
        raw.extend_from_slice(&generation.to_be_bytes());
        raw.extend_from_slice(&id.0);
        raw.resize(PIN_BYTES, 0);
        Pin::decode(&raw).unwrap()
    }

    #[test]
    fn file_store_pin_cas_retries_and_reopens_without_fallback() {
        let sandbox = Sandbox::new();
        let mut store = FileStore::create_new(sandbox.store(), 2).unwrap();
        let first = b"first bundle";
        let first_id = bundle_id(first);
        let first_pin = pin_for(1, first_id);
        store.put_bundle(first_id, first).unwrap();
        assert!(store.compare_exchange_pin(None, &first_pin).unwrap());
        assert_eq!(store.read_pin().unwrap(), Some(first_pin.clone()));
        let second = b"second bundle";
        let second_id = bundle_id(second);
        let second_pin = pin_for(2, second_id);
        store.put_bundle(second_id, second).unwrap();
        assert!(!store.compare_exchange_pin(None, &second_pin).unwrap());
        assert_eq!(store.read_pin().unwrap(), Some(first_pin.clone()));
        assert!(store
            .compare_exchange_pin(Some(&first_pin), &second_pin)
            .unwrap());
        // A retry must rerun the durability sequence, even if bytes are equal.
        assert!(store
            .compare_exchange_pin(Some(&second_pin), &second_pin)
            .unwrap());
        create_private(&store.path.join(PIN_TEMP))
            .unwrap()
            .write_all(b"partial interrupted pin")
            .unwrap();
        drop(store);
        let mut store = FileStore::open(sandbox.store(), 2).unwrap();
        assert_eq!(store.read_pin().unwrap(), Some(second_pin.clone()));
        assert!(store
            .compare_exchange_pin(Some(&second_pin), &second_pin)
            .unwrap());
        assert!(!store.path.join(PIN_TEMP).exists());
        // Removal of current data produces a missing-data error, never selection
        // of the older retained bundle. Test corruption is explicit and local.
        fs::remove_file(store.bundle_path(second_id)).unwrap();
        assert!(
            matches!(store.read_bundle(second_id), Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound)
        );
        assert_eq!(store.read_pin().unwrap(), Some(second_pin));
        assert_eq!(store.read_bundle(first_id).unwrap(), first);
    }

    #[test]
    fn file_store_cas_requires_a_bundle_and_refuses_temporary_symlinks() {
        let sandbox = Sandbox::new();
        let mut store = FileStore::create_new(sandbox.store(), 2).unwrap();
        let raw = b"candidate bundle";
        let id = bundle_id(raw);
        let pin = pin_for(1, id);
        assert!(
            matches!(store.compare_exchange_pin(None, &pin), Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound)
        );
        assert_eq!(store.read_pin().unwrap(), None);
        store.put_bundle(id, raw).unwrap();
        let outside = sandbox.0.join("outside");
        create_private(&outside)
            .unwrap()
            .write_all(b"untouched")
            .unwrap();
        symlink(&outside, store.path.join(PIN_TEMP)).unwrap();
        assert!(matches!(
            store.compare_exchange_pin(None, &pin),
            Err(Error::UnsafePath)
        ));
        assert_eq!(store.read_pin().unwrap(), None);
        assert_eq!(fs::read(&outside).unwrap(), b"untouched");
        fs::remove_file(store.path.join(PIN_TEMP)).unwrap();
        symlink(&outside, store.path.join(BUNDLE_TEMP)).unwrap();
        assert!(matches!(
            store.put_bundle(bundle_id(b"another"), b"another"),
            Err(Error::UnsafePath)
        ));
        assert_eq!(fs::read(&outside).unwrap(), b"untouched");
    }

    #[test]
    fn file_store_creation_absence_lock_and_reopen_are_distinct() {
        let sandbox = Sandbox::new();
        assert!(
            matches!(FileStore::open(sandbox.store(), 2), Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound)
        );
        assert!(matches!(
            FileStore::create_new(sandbox.store(), 0),
            Err(Error::InvalidBound)
        ));
        let mut first = FileStore::create_new(sandbox.store(), 2).unwrap();
        assert_eq!(first.read_pin().unwrap(), None);
        assert!(matches!(
            FileStore::open(sandbox.store(), 2),
            Err(Error::Busy)
        ));
        assert!(
            matches!(FileStore::create_new(sandbox.store(), 2), Err(Error::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists)
        );
        drop(first);
        assert_eq!(
            FileStore::open(sandbox.store(), 2)
                .unwrap()
                .read_pin()
                .unwrap(),
            None
        );
    }

    #[test]
    fn file_store_immutable_bundles_include_orphans_in_capacity() {
        let sandbox = Sandbox::new();
        let mut store = FileStore::create_new(sandbox.store(), 1).unwrap();
        let first = b"first orphan";
        let id = bundle_id(first);
        store.put_bundle(id, first).unwrap();
        store.put_bundle(id, first).unwrap();
        assert_eq!(store.read_bundle(id).unwrap(), first);
        assert!(matches!(
            store.put_bundle(id, b"different"),
            Err(Error::CorruptBundle)
        ));
        let next = b"next orphan";
        assert!(matches!(
            store.put_bundle(bundle_id(next), next),
            Err(Error::Capacity)
        ));
        drop(store);
        let mut store = FileStore::open(sandbox.store(), 1).unwrap();
        assert_eq!(store.read_bundle(id).unwrap(), first);
        assert_eq!(store.read_pin().unwrap(), None);
    }

    #[test]
    fn file_store_reads_bound_sizes_and_reject_corrupt_digests() {
        let sandbox = Sandbox::new();
        let mut store = FileStore::create_new(sandbox.store(), 2).unwrap();
        let id = bundle_id(b"content");
        let mut file = create_private(&store.bundle_path(id)).unwrap();
        file.set_len(MAX_BUNDLE_BYTES as u64 + 1).unwrap();
        assert!(matches!(store.read_bundle(id), Err(Error::CorruptBundle)));
        file.set_len(0).unwrap();
        file.write_all(b"invalid").unwrap();
        assert!(matches!(store.read_bundle(id), Err(Error::CorruptBundle)));
        let mut pin = create_private(&store.path.join(PIN)).unwrap();
        pin.write_all(b"bad pin").unwrap();
        assert!(matches!(store.read_pin(), Err(Error::MalformedPin)));
        drop(store);
        assert!(matches!(
            FileStore::open(sandbox.store(), 2),
            Err(Error::MalformedPin)
        ));
    }

    #[test]
    fn file_store_refuses_symlink_files_and_world_readable_directories() {
        let sandbox = Sandbox::new();
        let mut store = FileStore::create_new(sandbox.store(), 2).unwrap();
        let outside = sandbox.0.join("outside");
        create_private(&outside)
            .unwrap()
            .write_all(b"private")
            .unwrap();
        symlink(&outside, store.path.join(PIN)).unwrap();
        assert!(matches!(store.read_pin(), Err(Error::UnsafePath)));
        fs::remove_file(store.path.join(PIN)).unwrap();
        let id = bundle_id(b"private");
        symlink(&outside, store.bundle_path(id)).unwrap();
        assert!(matches!(store.read_bundle(id), Err(Error::UnsafePath)));
        assert!(matches!(
            store.put_bundle(id, b"private"),
            Err(Error::UnsafePath)
        ));
        drop(store);
        fs::set_permissions(sandbox.store(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            FileStore::open(sandbox.store(), 2),
            Err(Error::UnsafePath)
        ));
    }

    #[test]
    fn file_store_stale_linked_temporary_is_unlinked_without_truncation() {
        let sandbox = Sandbox::new();
        let mut store = FileStore::create_new(sandbox.store(), 2).unwrap();
        let first = b"published before crash";
        let id = bundle_id(first);
        store.put_bundle(id, first).unwrap();
        fs::hard_link(store.bundle_path(id), store.path.join(BUNDLE_TEMP)).unwrap();
        drop(store);
        let mut store = FileStore::open(sandbox.store(), 2).unwrap();
        let next = b"after crash";
        store.put_bundle(bundle_id(next), next).unwrap();
        assert_eq!(store.read_bundle(id).unwrap(), first);
        assert_eq!(store.read_bundle(bundle_id(next)).unwrap(), next);
    }

    #[test]
    fn file_store_rejects_unrecognized_directory_entries_and_lock_symlinks() {
        let sandbox = Sandbox::new();
        let store = FileStore::create_new(sandbox.store(), 2).unwrap();
        create_private(&store.path.join("unrecognized")).unwrap();
        drop(store);
        assert!(matches!(
            FileStore::open(sandbox.store(), 2),
            Err(Error::UnsafePath)
        ));
        fs::remove_file(sandbox.store().join("unrecognized")).unwrap();
        fs::remove_file(sandbox.store().join(LOCK)).unwrap();
        let outside = sandbox.0.join("outside");
        create_private(&outside).unwrap();
        symlink(&outside, sandbox.store().join(LOCK)).unwrap();
        assert!(matches!(
            FileStore::open(sandbox.store(), 2),
            Err(Error::UnsafePath)
        ));
    }
}
