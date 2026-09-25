use super::{
    codec::{MAX_INTENT, MAX_STATE},
    Error, MAX_DELIVERY_RECORD_BYTES, MAX_EVENT_BYTES,
};
use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};
use vhalla_custody::{self as custody, Owner};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Point {
    IntentCreated,
    IntentPartial,
    IntentStageSynced,
    IntentRenamed,
    IntentWritten,
    IntentSynced,
    RecordSynced,
    RecordRenamed,
    StateSynced,
    StateRenamed,
    IntentRemoved,
}
pub(super) struct Disk {
    path: PathBuf,
    owner: Owner,
    directory: File,
    #[cfg(test)]
    pub fault: Option<Point>,
    #[cfg(test)]
    pub syncs: std::cell::RefCell<Vec<String>>,
}
fn io(_: std::io::Error) -> Error {
    Error::Storage
}
fn check(error: custody::Error) -> Error {
    match error {
        custody::Error::Capacity => Error::Bounds,
        custody::Error::UnsafePath | custody::Error::Corrupt => Error::Corrupt,
        custody::Error::Busy | custody::Error::Io(_) => Error::Storage,
    }
}
impl Disk {
    pub fn create(path: &Path) -> Result<(Self, File), Error> {
        let path = custody::absolute(path).map_err(check)?;
        let (directory, owner) = custody::create_private_directory(&path).map_err(check)?;
        let lock = custody::create_private_file(&path.join("lock")).map_err(check)?;
        custody::acquire_exclusive(&lock).map_err(check)?;
        lock.sync_all().map_err(io)?;
        Ok((
            Self {
                path,
                owner,
                directory,
                #[cfg(test)]
                fault: None,
                #[cfg(test)]
                syncs: Default::default(),
            },
            lock,
        ))
    }
    pub fn open(path: &Path) -> Result<(Self, File), Error> {
        let path = custody::absolute(path).map_err(check)?;
        let (directory, owner) = custody::open_private_directory(&path).map_err(check)?;
        let lock = custody::open_private_file(&path.join("lock"), owner, 0).map_err(check)?;
        custody::acquire_exclusive(&lock).map_err(check)?;
        Ok((
            Self {
                path,
                owner,
                directory,
                #[cfg(test)]
                fault: None,
                #[cfg(test)]
                syncs: Default::default(),
            },
            lock,
        ))
    }
    pub fn hit(&mut self, point: Point) -> Result<(), Error> {
        #[cfg(test)]
        if self.fault == Some(point) {
            self.fault = None;
            return Err(Error::Storage);
        }
        let _ = point;
        Ok(())
    }
    pub fn present(&self, name: &str, max: usize) -> Result<bool, Error> {
        custody::private_file_present(&self.path.join(name), self.owner, max).map_err(check)
    }
    pub fn optional(&self, name: &str, max: usize) -> Result<Option<Vec<u8>>, Error> {
        if self.present(name, max)? {
            self.read(name, max).map(Some)
        } else {
            Ok(None)
        }
    }
    pub fn read(&self, name: &str, max: usize) -> Result<Vec<u8>, Error> {
        custody::read_private_file(&self.path.join(name), self.owner, max).map_err(check)
    }
    pub fn sync(&self) -> Result<(), Error> {
        self.directory.sync_all().map_err(io)?;
        #[cfg(test)]
        self.syncs.borrow_mut().push("directory".into());
        Ok(())
    }
    pub fn sync_parent(&self) -> Result<(), Error> {
        File::open(self.path.parent().ok_or(Error::Corrupt)?)
            .and_then(|p| p.sync_all())
            .map_err(io)
    }
    pub fn resync(&self, name: &str, max: usize) -> Result<(), Error> {
        custody::open_private_file(&self.path.join(name), self.owner, max)
            .map_err(check)?
            .sync_all()
            .map_err(io)?;
        #[cfg(test)]
        self.syncs.borrow_mut().push(name.into());
        self.sync()
    }
    pub fn create_file(&mut self, name: &str, raw: &[u8]) -> Result<(), Error> {
        let mut file = custody::create_private_file(&self.path.join(name)).map_err(check)?;
        file.write_all(raw).map_err(io)?;
        if name == "INTENT" {
            self.hit(Point::IntentWritten)?;
        }
        file.sync_all().map_err(io)?;
        self.sync()
    }
    fn temp(&mut self, name: &str, raw: &[u8], max: usize) -> Result<(), Error> {
        // Only a verified protected intent authorizes replacement of its scratch
        // file. A partial scratch file is never treated as accepted evidence.
        let mut file = if self.present(name, max)? {
            custody::open_private_file(&self.path.join(name), self.owner, max).map_err(check)?
        } else {
            custody::create_private_file(&self.path.join(name)).map_err(check)?
        };
        file.set_len(0).map_err(io)?;
        file.write_all(raw).map_err(io)?;
        file.sync_all().map_err(io)
    }
    fn remove_temp(&self, name: &str, max: usize) -> Result<(), Error> {
        if self.present(name, max)? {
            fs::remove_file(self.path.join(name)).map_err(io)?;
        }
        self.sync()
    }
    pub fn immutable(&mut self, name: &str, raw: &[u8]) -> Result<(), Error> {
        let max = MAX_EVENT_BYTES.max(MAX_DELIVERY_RECORD_BYTES);
        if let Some(existing) = self.optional(name, max)? {
            if existing != raw {
                return Err(Error::Corrupt);
            }
            self.resync(name, max)?;
            return self.remove_temp("RECORD.tmp", max);
        }
        self.temp("RECORD.tmp", raw, max)?;
        self.hit(Point::RecordSynced)?;
        // The exclusive cooperating-owner lock covers the absence check and
        // rename. A hostile local process modifying this private dir is outside
        // this contract; existing names are never intentionally overwritten.
        if self.present(name, max)? {
            return Err(Error::Corrupt);
        }
        fs::rename(self.path.join("RECORD.tmp"), self.path.join(name)).map_err(io)?;
        self.hit(Point::RecordRenamed)?;
        self.sync()
    }
    pub fn replace_state(&mut self, before: &[u8], after: &[u8]) -> Result<(), Error> {
        let current = self.read("STATE", MAX_STATE)?;
        if current == after {
            self.resync("STATE", MAX_STATE)?;
            return self.remove_temp("STATE.tmp", MAX_STATE);
        }
        if current != before {
            return Err(Error::Corrupt);
        }
        self.temp("STATE.tmp", after, MAX_STATE)?;
        self.hit(Point::StateSynced)?;
        fs::rename(self.path.join("STATE.tmp"), self.path.join("STATE")).map_err(io)?;
        self.hit(Point::StateRenamed)?;
        self.sync()
    }
    // New operations stage an unpublished scratch before publishing the existing
    // authoritative INTENT name. No effects precede rename + directory sync.
    pub fn stage_intent(&mut self, raw: &[u8]) -> Result<(), Error> {
        if raw.len() > MAX_INTENT {
            return Err(Error::Bounds);
        }
        if self.present("INTENT", MAX_INTENT)? || self.present("INTENT.tmp", MAX_INTENT)? {
            return Err(Error::RecoveryRequired);
        }
        let mut file =
            custody::create_private_file(&self.path.join("INTENT.tmp")).map_err(check)?;
        self.hit(Point::IntentCreated)?;
        let split = raw.len() / 2;
        file.write_all(&raw[..split]).map_err(io)?;
        self.hit(Point::IntentPartial)?;
        file.write_all(&raw[split..]).map_err(io)?;
        self.hit(Point::IntentWritten)?;
        file.sync_all().map_err(io)?;
        self.hit(Point::IntentStageSynced)?;
        self.promote_staged_intent(raw)
    }
    pub fn promote_staged_intent(&mut self, raw: &[u8]) -> Result<(), Error> {
        if self.present("INTENT", MAX_INTENT)? || self.read("INTENT.tmp", MAX_INTENT)? != raw {
            return Err(Error::Corrupt);
        }
        self.resync("INTENT.tmp", MAX_INTENT)?;
        fs::rename(self.path.join("INTENT.tmp"), self.path.join("INTENT")).map_err(io)?;
        self.hit(Point::IntentRenamed)?;
        self.sync()?;
        self.hit(Point::IntentSynced)
    }
    // Caller must first validate current scope/state and prove this is incomplete
    // nonauthoritative scratch with no final intent or post-intent effects.
    pub fn discard_staged_intent(&self) -> Result<(), Error> {
        if self.present("INTENT", MAX_INTENT)? {
            return Err(Error::Corrupt);
        }
        self.remove_temp("INTENT.tmp", MAX_INTENT)
    }

    pub fn remove_intent(&mut self) -> Result<(), Error> {
        if !self.present("INTENT", MAX_INTENT)? {
            return Err(Error::Corrupt);
        }
        fs::remove_file(self.path.join("INTENT")).map_err(io)?;
        self.hit(Point::IntentRemoved)?;
        self.sync()
    }
}
