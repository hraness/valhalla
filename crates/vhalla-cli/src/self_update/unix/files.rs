//! Descriptor-relative, in-process writes using the workspace's safe rustix APIs.
use anyhow::{bail, ensure, Context, Result};
use rustix::fs::{self as sys, AtFlags, FlockOperation, Mode, OFlags};
use rustix::io::Errno;
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fs::{File, Metadata};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static SERIAL: AtomicU64 = AtomicU64::new(0);

fn name(value: &OsStr) -> Result<&OsStr> {
    ensure!(
        matches!(
            Path::new(value).components().next(),
            Some(Component::Normal(_))
        ) && Path::new(value).components().count() == 1,
        "Expected one ordinary filename"
    );
    Ok(value)
}

fn check(meta: &Metadata, directory: bool, private: bool) -> Result<()> {
    let uid = rustix::process::geteuid().as_raw();
    ensure!(
        if directory {
            meta.is_dir()
        } else {
            meta.is_file()
        },
        "Installation path has the wrong file type"
    );
    let root_sticky = directory && meta.uid() == 0 && meta.mode() & 0o1000 != 0;
    ensure!(
        (meta.uid() == uid || (directory && !private && meta.uid() == 0))
            && (root_sticky || meta.mode() & 0o022 == 0)
            && (!private || meta.mode() & 0o077 == 0)
            && (directory || meta.nlink() == 1),
        "Installation paths must be owned by this user and not shared or writable by others"
    );
    Ok(())
}

fn same(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}

pub(super) struct Directory {
    pub path: PathBuf,
    file: File,
    private: bool,
}
impl Directory {
    pub fn open(path: &Path, create: bool, private: bool) -> Result<Self> {
        ensure!(
            path.is_absolute()
                && !path
                    .components()
                    .any(|c| matches!(c, Component::ParentDir | Component::CurDir)),
            "Installation path must be absolute without dot components"
        );
        let mut file = File::open("/")?;
        check(&file.metadata()?, true, false)?;
        let components: Vec<_> = path
            .components()
            .filter_map(|c| match c {
                Component::Normal(value) => Some(value),
                _ => None,
            })
            .collect();
        ensure!(
            !private || !components.is_empty(),
            "Filesystem root cannot hold private update state"
        );
        for (index, component) in components.iter().enumerate() {
            let component = name(component)?;
            let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let mut opened = sys::openat(&file, component, flags, Mode::empty());
            if create && matches!(opened, Err(Errno::NOENT)) {
                match sys::mkdirat(&file, component, Mode::from_raw_mode(0o700)) {
                    Ok(()) | Err(Errno::EXIST) => {}
                    Err(error) => return Err(error.into()),
                }
                opened = sys::openat(&file, component, flags, Mode::empty());
            }
            file = File::from(opened.context("Open install directory without symlinks")?);
            check(
                &file.metadata()?,
                true,
                private && index + 1 == components.len(),
            )?;
        }
        Ok(Self {
            path: path.into(),
            file,
            private,
        })
    }

    pub fn validate(&self) -> Result<()> {
        let now = Self::open(&self.path, false, self.private)?;
        ensure!(
            same(&self.file.metadata()?, &now.file.metadata()?),
            "Install directory changed during verification"
        );
        Ok(())
    }

    pub fn mkdir(&self, filename: &str) -> Result<bool> {
        self.validate()?;
        match sys::mkdirat(
            &self.file,
            name(OsStr::new(filename))?,
            Mode::from_raw_mode(0o700),
        ) {
            Ok(()) => {
                self.file.sync_all()?;
                Ok(true)
            }
            Err(Errno::EXIST) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    fn open_file(
        &self,
        filename: &OsStr,
        flags: OFlags,
        mode: Mode,
        private: bool,
    ) -> Result<Option<File>> {
        self.validate()?;
        let opened = sys::openat(
            &self.file,
            name(filename)?,
            flags | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            mode,
        );
        let file = match opened {
            Ok(fd) => File::from(fd),
            Err(Errno::NOENT) if !flags.contains(OFlags::CREATE) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        check(&file.metadata()?, false, private)?;
        Ok(Some(file))
    }

    pub fn read(&self, filename: &str, limit: usize) -> Result<Option<Vec<u8>>> {
        let Some(file) =
            self.open_file(OsStr::new(filename), OFlags::RDONLY, Mode::empty(), false)?
        else {
            return Ok(None);
        };
        ensure!(
            file.metadata()?.len() <= limit as u64,
            "Install file exceeds its size limit"
        );
        let mut bytes = Vec::new();
        file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= limit,
            "Install file grew beyond its size limit"
        );
        Ok(Some(bytes))
    }

    pub fn write_new(&self, filename: &str, bytes: &[u8], executable: bool) -> Result<()> {
        let mut file = self
            .open_file(
                OsStr::new(filename),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
                Mode::from_raw_mode(0o600),
                true,
            )?
            .context("Create staged file")?;
        file.write_all(bytes)?;
        if executable {
            sys::fchmod(&file, Mode::from_raw_mode(0o755))?;
        }
        file.sync_all()?;
        self.file.sync_all()?;
        Ok(())
    }

    pub fn copy_mode(&self, target: &str, source: &Directory, filename: &str) -> Result<()> {
        let original = source
            .open_file(OsStr::new(filename), OFlags::RDONLY, Mode::empty(), false)?
            .context("Original executable disappeared")?;
        let staged = self
            .open_file(OsStr::new(target), OFlags::RDONLY, Mode::empty(), false)?
            .context("Backup executable disappeared")?;
        staged.set_permissions(std::fs::Permissions::from_mode(
            original.metadata()?.mode() & 0o777,
        ))?;
        staged.sync_all()?;
        Ok(())
    }

    pub fn rename(&self, source: &str, destination: &Self, target: &str) -> Result<()> {
        self.validate()?;
        destination.validate()?;
        sys::renameat(
            &self.file,
            name(OsStr::new(source))?,
            &destination.file,
            name(OsStr::new(target))?,
        )?;
        destination.file.sync_all()?;
        self.file.sync_all()?;
        Ok(())
    }

    pub fn remove(&self, filename: &str, directory: bool) -> Result<()> {
        self.validate()?;
        match sys::unlinkat(
            &self.file,
            name(OsStr::new(filename))?,
            if directory {
                AtFlags::REMOVEDIR
            } else {
                AtFlags::empty()
            },
        ) {
            Ok(()) | Err(Errno::NOENT) => {}
            Err(error) => return Err(error.into()),
        }
        self.file.sync_all()?;
        Ok(())
    }

    pub fn lock(&self) -> Result<Lock<'_>> {
        let file = self
            .open_file(
                OsStr::new("activity.lock"),
                OFlags::RDWR | OFlags::CREATE,
                Mode::from_raw_mode(0o600),
                true,
            )?
            .context("Create activity lock")?;
        if sys::flock(&file, FlockOperation::NonBlockingLockExclusive).is_err() {
            bail!("Valhalla is running or another installer is active; retry when it finishes");
        }
        let lock = Lock {
            directory: self,
            file,
            owner: std::process::id(),
        };
        lock.validate()?;
        Ok(lock)
    }
}

pub(super) struct Lock<'a> {
    directory: &'a Directory,
    file: File,
    owner: u32,
}
impl Lock<'_> {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.owner == std::process::id(),
            "Install lock belongs to another process"
        );
        let now = self
            .directory
            .open_file(
                OsStr::new("activity.lock"),
                OFlags::RDONLY,
                Mode::empty(),
                true,
            )?
            .context("Activity lock disappeared")?;
        ensure!(
            same(&now.metadata()?, &self.file.metadata()?),
            "Activity lock changed during installation"
        );
        Ok(())
    }
}
impl Drop for Lock<'_> {
    fn drop(&mut self) {
        if self.owner == std::process::id() {
            let _ = sys::flock(&self.file, FlockOperation::Unlock);
        }
    }
}

pub(super) struct Stage<'a> {
    pub directory: Directory,
    parent: &'a Directory,
    name: String,
    pub preserve: bool,
}
impl<'a> Stage<'a> {
    pub fn new(parent: &'a Directory) -> Result<Self> {
        for _ in 0..100 {
            let name = format!(
                ".vhalla-update-{}-{}",
                std::process::id(),
                SERIAL.fetch_add(1, Ordering::Relaxed)
            );
            if parent.mkdir(&name)? {
                return Ok(Self {
                    directory: Directory::open(&parent.path.join(&name), false, true)?,
                    parent,
                    name,
                    preserve: false,
                });
            }
        }
        bail!("Could not create a fresh private staging directory")
    }
}
impl Drop for Stage<'_> {
    fn drop(&mut self) {
        if self.preserve || self.directory.validate().is_err() {
            return;
        }
        for filename in [
            "archive",
            "checksum",
            "vhalla",
            "previous",
            "old-receipt",
            "new-receipt",
        ] {
            let _ = self.directory.remove(filename, false);
        }
        let _ = self.parent.remove(&self.name, true);
    }
}

pub(super) fn read_path(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let directory = Directory::open(path.parent().context("File has no parent")?, false, false)?;
    directory
        .read(
            path.file_name()
                .and_then(OsStr::to_str)
                .context("File needs a Unicode name")?,
            limit,
        )?
        .context("Install file is missing")
}
pub(super) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
