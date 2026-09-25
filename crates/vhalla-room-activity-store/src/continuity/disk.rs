//! Private local I/O. The store state machine supplies exact expected images.
//! Exclusive custody serializes cooperating writers; this is not a sandbox
//! against an owner/root replacing directory ancestors or rolling back files.
use crate::Error;
use std::{
    fs::{self, File},
    io::{self, Write},
    path::{Component, Path, PathBuf},
};
use vhalla_custody::{self as custody, Owner};

pub(super) const MAX_TRANSACTION_BYTES: usize = 256 * 1024;
const DIRECTORIES: [&str; 4] = ["pages", "evidence", "authors", "feed"];
const ROOT_FILES: [&str; 7] = [
    "format",
    "HEAD",
    "STAGES",
    "lock",
    "INTENT",
    "INTENT.tmp",
    "DATA.tmp",
];

pub(super) struct Disk {
    pub path: PathBuf,
    pub directory: File,
    pub owner: Owner,
    _lock: File,
    #[cfg(test)]
    pub fault: std::cell::RefCell<Option<(&'static str, &'static str)>>,
}
impl Disk {
    pub fn hit(&self, _target: &str, _point: &'static str) -> Result<(), Error> {
        #[cfg(test)]
        if self
            .fault
            .borrow()
            .is_some_and(|(target, point)| _target.starts_with(target) && _point == point)
        {
            self.fault.replace(None);
            return Err(Error::Indeterminate(io::Error::other(
                "injected continuity interruption",
            )));
        }
        Ok(())
    }
    pub fn create(path: &Path) -> Result<Self, Error> {
        let path = custody::absolute(path).map_err(map)?;
        let (directory, owner) = custody::create_private_directory(&path).map_err(map)?;
        let lock = custody::create_private_file(&path.join("lock")).map_err(map)?;
        custody::acquire_exclusive(&lock).map_err(map)?;
        lock.sync_all()?;
        for name in DIRECTORIES {
            let (child, child_owner) =
                custody::create_private_directory(&path.join(name)).map_err(map)?;
            if child_owner != owner {
                return Err(Error::UnsafePath);
            }
            child.sync_all()?;
        }
        directory.sync_all()?;
        if let Some(parent) = path.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(Self {
            path,
            directory,
            owner,
            _lock: lock,
            #[cfg(test)]
            fault: std::cell::RefCell::new(None),
        })
    }
    pub fn open(path: &Path) -> Result<Self, Error> {
        let path = custody::absolute(path).map_err(map)?;
        let (directory, owner) = custody::open_private_directory(&path).map_err(map)?;
        let lock = custody::open_private_file(&path.join("lock"), owner, 0).map_err(map)?;
        custody::acquire_exclusive(&lock).map_err(map)?;
        for name in DIRECTORIES {
            let (_, child_owner) =
                custody::open_private_directory(&path.join(name)).map_err(map)?;
            if child_owner != owner {
                return Err(Error::UnsafePath);
            }
        }
        // Only the finite root layout is inspected. History directories are
        // never enumerated or materialized during startup or paging.
        for (index, entry) in fs::read_dir(&path)?.enumerate() {
            if index >= ROOT_FILES.len() + DIRECTORIES.len() {
                return Err(Error::UnsafePath);
            }
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().ok_or(Error::UnsafePath)?;
            if !ROOT_FILES.contains(&name) && !DIRECTORIES.contains(&name) {
                return Err(Error::UnsafePath);
            }
        }
        Ok(Self {
            path,
            directory,
            owner,
            _lock: lock,
            #[cfg(test)]
            fault: std::cell::RefCell::new(None),
        })
    }
    fn checked_path(&self, name: &str) -> Result<(PathBuf, File), Error> {
        let relative = Path::new(name);
        let components: Vec<_> = relative.components().collect();
        if components.is_empty()
            || components.len() > 3
            || components
                .iter()
                .any(|p| !matches!(p, Component::Normal(_)))
        {
            return Err(Error::UnsafePath);
        }
        let parent = if components.len() >= 2 {
            let Component::Normal(first) = components[0] else {
                unreachable!()
            };
            if !DIRECTORIES.contains(&first.to_str().ok_or(Error::UnsafePath)?) {
                return Err(Error::UnsafePath);
            }
            let mut parent = self.path.join(first);
            if components.len() == 3 {
                if first != "authors" {
                    return Err(Error::UnsafePath);
                }
                let Component::Normal(author) = components[1] else {
                    unreachable!()
                };
                parent.push(author);
            }
            parent
        } else {
            self.path.clone()
        };
        let (directory, owner) = custody::open_private_directory(&parent).map_err(map)?;
        if owner != self.owner {
            return Err(Error::UnsafePath);
        }
        Ok((self.path.join(relative), directory))
    }
    pub fn has_author(&self, author: &str) -> Result<bool, Error> {
        if author.len() != 64
            || !author
                .bytes()
                .all(|v| v.is_ascii_hexdigit() && !v.is_ascii_uppercase())
        {
            return Err(Error::UnsafePath);
        }
        let path = self.path.join("authors").join(author);
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
            Ok(_) => {
                let (_, owner) = custody::open_private_directory(&path).map_err(map)?;
                if owner != self.owner {
                    return Err(Error::UnsafePath);
                }
                Ok(true)
            }
        }
    }
    /// Creation is valid only after a durable terminal intent protects its HEAD.
    pub fn ensure_author(&self, author: &str) -> Result<(), Error> {
        let path = self.path.join("authors").join(author);
        let (directory, owner) = if self.has_author(author)? {
            custody::open_private_directory(&path).map_err(map)?
        } else {
            custody::create_private_directory(&path).map_err(map)?
        };
        if owner != self.owner {
            return Err(Error::UnsafePath);
        }
        directory.sync_all()?;
        let (parent, _) =
            custody::open_private_directory(&self.path.join("authors")).map_err(map)?;
        parent.sync_all()?;
        Ok(())
    }
    pub fn read(&self, name: &str, max: usize) -> Result<Vec<u8>, Error> {
        let (path, _) = self.checked_path(name)?;
        custody::read_private_file(&path, self.owner, max).map_err(map)
    }
    pub fn optional(&self, name: &str, max: usize) -> Result<Option<Vec<u8>>, Error> {
        match self.read(name, max) {
            Ok(raw) => Ok(Some(raw)),
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }
    pub fn initial(&self, name: &str, bytes: &[u8]) -> Result<(), Error> {
        let (path, parent) = self.checked_path(name)?;
        let mut file = custody::create_private_file(&path).map_err(map)?;
        file.write_all(bytes)?;
        self.hit(name, "write")?;
        file.sync_all()?;
        self.hit(name, "file-sync")?;
        parent.sync_all()?;
        self.hit(name, "directory-sync")?;
        Ok(())
    }
    /// Only known unpublished duplicate temp files may be cleared. The caller
    /// must retain the source in protected INTENT/pages or establish that no
    /// authoritative INTENT was installed and no dependent writes began.
    pub fn clear_temp(&self, name: &str) -> Result<(), Error> {
        if !matches!(name, "DATA.tmp" | "INTENT.tmp") {
            return Err(Error::UnsafePath);
        }
        let (path, parent) = self.checked_path(name)?;
        if custody::private_file_present(&path, self.owner, MAX_TRANSACTION_BYTES).map_err(map)? {
            fs::remove_file(path)?;
            parent.sync_all()?;
        }
        Ok(())
    }
    fn staged_replace(&self, name: &str, bytes: &[u8], temp: &str) -> Result<(), Error> {
        if bytes.len() > MAX_TRANSACTION_BYTES {
            return Err(Error::Capacity);
        }
        self.clear_temp(temp)?;
        self.initial(temp, bytes)?;
        let (target, parent) = self.checked_path(name)?;
        let (source, _) = self.checked_path(temp)?;
        fs::rename(source, target)?;
        self.hit(name, "rename")?;
        parent.sync_all()?;
        self.directory.sync_all()?;
        self.hit(name, "rename-sync")?;
        Ok(())
    }
    /// Called only under lifetime custody and the exact retained transaction.
    /// Existing immutable final images must match; unknown bytes are preserved.
    pub fn immutable(&self, name: &str, bytes: &[u8]) -> Result<(), Error> {
        if let Some(existing) = self.optional(name, bytes.len())? {
            if existing != bytes {
                return Err(Error::Conflict);
            }
            let (path, parent) = self.checked_path(name)?;
            custody::open_private_file(&path, self.owner, bytes.len())
                .map_err(map)?
                .sync_all()?;
            parent.sync_all()?;
            return Ok(());
        }
        self.staged_replace(name, bytes, "DATA.tmp")
    }
    /// Atomic local metadata publication must match an expected or next image.
    pub fn replace(&self, name: &str, expected: &[u8], next: &[u8]) -> Result<(), Error> {
        let current = self.read(name, expected.len().max(next.len()))?;
        if current != expected && current != next {
            return Err(Error::Conflict);
        }
        if current == next {
            let (path, parent) = self.checked_path(name)?;
            custody::open_private_file(&path, self.owner, next.len())
                .map_err(map)?
                .sync_all()?;
            parent.sync_all()?;
            return Ok(());
        }
        self.staged_replace(name, next, "DATA.tmp")
    }
    pub fn replace_optional(
        &self,
        name: &str,
        expected: Option<&[u8]>,
        next: &[u8],
    ) -> Result<(), Error> {
        let current = self.optional(
            name,
            expected.map_or(next.len(), |v| v.len().max(next.len())),
        )?;
        if current.as_deref() != expected && current.as_deref() != Some(next) {
            return Err(Error::Conflict);
        }
        if current.as_deref() == Some(next) {
            let (path, parent) = self.checked_path(name)?;
            custody::open_private_file(&path, self.owner, next.len())
                .map_err(map)?
                .sync_all()?;
            parent.sync_all()?;
            return Ok(());
        }
        self.staged_replace(name, next, "DATA.tmp")
    }
    /// Reconfirm a retained intent before replay effects. Observing a renamed
    /// file after interruption does not prove its directory entry was durable.
    pub fn confirm_intent(&self, expected: &[u8]) -> Result<(), Error> {
        if self.read("INTENT", MAX_TRANSACTION_BYTES)? != expected {
            return Err(Error::Corrupt);
        }
        let (path, parent) = self.checked_path("INTENT")?;
        custody::open_private_file(&path, self.owner, expected.len())
            .map_err(map)?
            .sync_all()?;
        parent.sync_all()?;
        self.hit("INTENT", "confirmed")?;
        Ok(())
    }
    /// Install only after complete write+file sync; no dependent write precedes
    /// the final directory sync. Cooperating ownership makes the absence stable.
    pub fn install_intent(&self, bytes: &[u8]) -> Result<(), Error> {
        if self.optional("INTENT", MAX_TRANSACTION_BYTES)?.is_some() {
            return Err(Error::RecoveryRequired);
        }
        self.staged_replace("INTENT", bytes, "INTENT.tmp")
    }
    pub fn remove_exact(&self, name: &str, expected: &[u8], missing_ok: bool) -> Result<(), Error> {
        let existing = self.optional(name, expected.len())?;
        if existing.is_none() && missing_ok {
            let (_, parent) = self.checked_path(name)?;
            parent.sync_all()?;
            return Ok(());
        }
        if existing.as_deref() != Some(expected) {
            return Err(Error::Conflict);
        }
        let (path, parent) = self.checked_path(name)?;
        fs::remove_file(path)?;
        self.hit(name, "unlink")?;
        parent.sync_all()?;
        self.hit(name, "unlink-sync")?;
        Ok(())
    }
}
fn map(error: custody::Error) -> Error {
    match error {
        custody::Error::UnsafePath => Error::UnsafePath,
        custody::Error::Busy => Error::Busy,
        custody::Error::Io(error) => Error::Io(error),
        custody::Error::Capacity | custody::Error::Corrupt => Error::Corrupt,
    }
}
