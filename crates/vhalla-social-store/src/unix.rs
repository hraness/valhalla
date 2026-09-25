use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, Metadata},
    io::{self, Write},
    path::{Path, PathBuf},
};
use vhalla_core::RealmId;
use vhalla_custody::{self as custody, Error as CustodyError, Owner};
use vhalla_social::{
    archive::{Archive, Limits, MAX_SNAPSHOT_BYTES},
    EvidenceRoot,
};

const PIN_MAGIC: &[u8; 8] = b"VHSP\0\0\0\x01";
const INTENT_MAGIC: &[u8; 8] = b"VHSI\0\0\0\x01";
/// Canonical exact-anchor encoding size, including its integrity checksum.
pub const PIN_BYTES: usize = 112;
const INTENT_HEADER: usize = 8 + 2 * PIN_BYTES + 4;
const MAX_INTENT_BYTES: usize = INTENT_HEADER + MAX_SNAPSHOT_BYTES + 32;
const MAX_FILES: usize = 8;
const LOCK: &str = "lock";
const PIN: &str = "pin";
const INTENT: &str = "intent";
// Unpublished scratch: never an authority for post-intent effects.
const INTENT_TEMP: &str = "intent.tmp";
const BUNDLE_TEMP: &str = "bundle.tmp";
const PIN_TEMP: &str = "pin.tmp";

/// Failures never authorize deleting evidence, resetting a store, or reusing a writer sequence.
#[derive(Debug)]
pub enum Error {
    /// A path/type/link/permission or unexpected directory entry is unsafe.
    UnsafePath,
    /// Another cooperating process or handle holds the lifetime exclusive lock.
    Busy,
    /// A record, partial intent, checksum, or immutable bundle is corrupt.
    Corrupt,
    /// A candidate would truncate history, change context, or use a stale basis.
    Conflict,
    /// The optional externally retained exact anchor differs from disk.
    Freshness,
    /// Reconcile the retained exact intent before constructing a different publication.
    RecoveryRequired,
    /// A filesystem or arithmetic resource ceiling was reached.
    Capacity,
    /// Bounded signed archive validation failed.
    Social(vhalla_social::Error),
    /// A read/open/create operation failed; failed creation may leave partial state.
    Io(io::Error),
    /// Publication outcome may be durable. Reopen and reconcile the exact intent/pin.
    Indeterminate(io::Error),
}
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<vhalla_social::Error> for Error {
    fn from(error: vhalla_social::Error) -> Self {
        Self::Social(error)
    }
}
fn map_custody(error: CustodyError) -> Error {
    match error {
        CustodyError::Io(e) => Error::Io(e),
        CustodyError::UnsafePath => Error::UnsafePath,
        CustodyError::Busy => Error::Busy,
        CustodyError::Capacity => Error::Corrupt,
        CustodyError::Corrupt => Error::Corrupt,
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "social store: {self:?}")
    }
}
impl std::error::Error for Error {}

/// An exact durable archive anchor. Its generation is local bookkeeping, not consensus.
/// Keep this outside the store to detect replacement with a different coherent snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pin {
    generation: u64,
    physical: [u8; 32],
    logical: EvidenceRoot,
}
impl Pin {
    fn for_archive(generation: u64, archive: &Archive) -> Self {
        Self {
            generation,
            physical: archive.physical_digest(),
            logical: archive.root(),
        }
    }
    /// Local successful-publication count; it is not a trusted timestamp.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }
    /// Exact stored snapshot checksum, including retained signature proof bytes.
    #[must_use]
    pub const fn physical(self) -> [u8; 32] {
        self.physical
    }
    /// Logical realm/protocol/sorted-event-ID commitment.
    #[must_use]
    pub const fn logical(self) -> EvidenceRoot {
        self.logical
    }
    /// Encode for caller-managed independent retention. No path or secret is included.
    #[must_use]
    pub fn encode(self) -> [u8; PIN_BYTES] {
        let mut raw = [0; PIN_BYTES];
        raw[..8].copy_from_slice(PIN_MAGIC);
        raw[8..16].copy_from_slice(&self.generation.to_be_bytes());
        raw[16..48].copy_from_slice(&self.physical);
        raw[48..80].copy_from_slice(self.logical.as_bytes());
        let digest = checksum(b"vhalla/social/store/pin/v1\0", &raw[..80]);
        raw[80..].copy_from_slice(&digest);
        raw
    }
    /// Decode a canonical pin. Its authenticity depends on where the caller retained it.
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() != PIN_BYTES
            || raw.get(..8) != Some(PIN_MAGIC.as_slice())
            || checksum(b"vhalla/social/store/pin/v1\0", &raw[..80]) != raw[80..]
        {
            return Err(Error::Corrupt);
        }
        Ok(Self {
            generation: u64::from_be_bytes(raw[8..16].try_into().map_err(|_| Error::Corrupt)?),
            physical: raw[16..48].try_into().map_err(|_| Error::Corrupt)?,
            logical: EvidenceRoot::from_bytes(raw[48..80].try_into().map_err(|_| Error::Corrupt)?),
        })
    }
}

/// A sealed result returned only after the exact archive is durably published.
/// Exported social bytes remain inert signed data, never a host capability.
#[derive(Debug)]
pub struct Publication {
    pin: Pin,
    snapshot: Vec<u8>,
    reconciled: bool,
}
impl Publication {
    /// Exact durable result suitable for independent caller retention.
    #[must_use]
    pub const fn pin(&self) -> Pin {
        self.pin
    }
    /// Full canonical signed archive, now eligible for the caller's outbound delivery.
    #[must_use]
    pub fn snapshot(&self) -> &[u8] {
        &self.snapshot
    }
    /// True when this call reconciled an existing intent or an already-present result.
    #[must_use]
    pub const fn reconciled(&self) -> bool {
        self.reconciled
    }
}
struct Intent {
    expected: Pin,
    next: Pin,
    archive: Archive,
}
impl Intent {
    fn encode(&self) -> Vec<u8> {
        let snapshot = self.archive.snapshot();
        let mut raw = Vec::with_capacity(INTENT_HEADER + snapshot.len() + 32);
        raw.extend_from_slice(INTENT_MAGIC);
        raw.extend_from_slice(&self.expected.encode());
        raw.extend_from_slice(&self.next.encode());
        raw.extend_from_slice(&(snapshot.len() as u32).to_be_bytes());
        raw.extend_from_slice(&snapshot);
        let digest = checksum(b"vhalla/social/store/intent/v1\0", &raw);
        raw.extend_from_slice(&digest);
        raw
    }
    fn decode(raw: &[u8], realm: RealmId, limits: Limits) -> Result<Self, Error> {
        if raw.len() < INTENT_HEADER + 32
            || raw.len() > MAX_INTENT_BYTES
            || raw.get(..8) != Some(INTENT_MAGIC.as_slice())
        {
            return Err(Error::Corrupt);
        }
        let expected = Pin::decode(&raw[8..8 + PIN_BYTES])?;
        let next = Pin::decode(&raw[8 + PIN_BYTES..8 + 2 * PIN_BYTES])?;
        let len = u32::from_be_bytes(
            raw[INTENT_HEADER - 4..INTENT_HEADER]
                .try_into()
                .map_err(|_| Error::Corrupt)?,
        ) as usize;
        if len > MAX_SNAPSHOT_BYTES
            || INTENT_HEADER + len + 32 != raw.len()
            || checksum(b"vhalla/social/store/intent/v1\0", &raw[..raw.len() - 32])
                != raw[raw.len() - 32..]
            || expected.generation.checked_add(1) != Some(next.generation)
        {
            return Err(Error::Corrupt);
        }
        let archive =
            Archive::from_snapshot(realm, limits, &raw[INTENT_HEADER..INTENT_HEADER + len])?;
        if Pin::for_archive(next.generation, &archive) != next {
            return Err(Error::Corrupt);
        }
        Ok(Self {
            expected,
            next,
            archive,
        })
    }
}

/// One owner-private directory and lifetime exclusive lock. No file/key handle escapes.
///
/// The adapter requires cooperating writers and owner-controlled path ancestors.
/// Checks reject observed symlinks/hardlinks and inconsistent ownership; they are
/// not a sandbox against the directory owner/root replacing paths between calls.
pub struct Store {
    path: PathBuf,
    directory: File,
    _lock: File,
    owner: Owner,
    archive: Archive,
    pin: Pin,
    #[cfg(test)]
    fault: Option<Step>,
}
impl Store {
    /// Explicitly initialize a previously nonexistent private directory and empty archive.
    /// Existing or partially created directories are never reset or reused.
    pub fn create(path: impl AsRef<Path>, realm: RealmId, limits: Limits) -> Result<Self, Error> {
        let archive = Archive::new(realm, limits)?;
        let path = absolute(path.as_ref())?;
        let (directory, owner) = custody::create_private_directory(&path).map_err(map_custody)?;
        let lock = create_private(&path.join(LOCK))?;
        acquire(&lock)?;
        lock.sync_all()?;
        let pin = Pin::for_archive(0, &archive);
        let mut bundle = create_private(&path.join(bundle_name(pin.physical)))?;
        bundle.write_all(&archive.snapshot())?;
        bundle.sync_all()?;
        let mut pin_file = create_private(&path.join(PIN))?;
        pin_file.write_all(&pin.encode())?;
        pin_file.sync_all()?;
        directory.sync_all()?;
        File::open(path.parent().ok_or(Error::UnsafePath)?)?.sync_all()?;
        Ok(Self {
            path,
            directory,
            _lock: lock,
            owner,
            archive,
            pin,
            #[cfg(test)]
            fault: None,
        })
    }
    /// Open existing evidence without creating/repairing files. A valid pending
    /// intent or unpublished scratch is retained for explicit `recover`; a torn
    /// authoritative intent and malformed complete scratch fail closed.
    /// The optional external anchor requires exact equality, including generation.
    pub fn open(
        path: impl AsRef<Path>,
        realm: RealmId,
        limits: Limits,
        expected: Option<Pin>,
    ) -> Result<Self, Error> {
        let path = absolute(path.as_ref())?;
        let (directory, owner) = custody::open_private_directory(&path).map_err(map_custody)?;
        let lock = open_private(&path.join(LOCK), owner, 0)?;
        if lock.metadata()?.len() != 0 {
            return Err(Error::Corrupt);
        }
        acquire(&lock)?;
        let pin = Pin::decode(&read_bounded(&path.join(PIN), owner, PIN_BYTES)?)?;
        if expected.is_some_and(|expected| expected != pin) {
            return Err(Error::Freshness);
        }
        let raw = read_bounded(
            &path.join(bundle_name(pin.physical)),
            owner,
            MAX_SNAPSHOT_BYTES,
        )?;
        let archive = Archive::from_snapshot(realm, limits, &raw)?;
        if Pin::for_archive(pin.generation, &archive) != pin {
            return Err(Error::Corrupt);
        }
        let store = Self {
            path,
            directory,
            _lock: lock,
            owner,
            archive,
            pin,
            #[cfg(test)]
            fault: None,
        };
        store.inventory()?;
        if store.exists(INTENT_TEMP)? {
            store.validate_staged_intent()?;
        }
        let intent = if store.exists(INTENT)? {
            Some(store.validate_intent()?)
        } else {
            if store.exists(BUNDLE_TEMP)? || store.exists(PIN_TEMP)? {
                return Err(Error::RecoveryRequired);
            }
            None
        };
        store.audit_copies(intent.as_ref())?;
        Ok(store)
    }
    /// Borrow the last pinned complete archive. A pending publication is not outbound-ready.
    #[must_use]
    pub fn archive(&self) -> &Archive {
        &self.archive
    }
    /// Exact owned directory path for adapters that must keep private state
    /// outside this store's strict file layout. This grants no filesystem handle.
    #[must_use]
    pub fn directory_path(&self) -> &Path {
        &self.path
    }
    /// Last reconciled local durable basis; retain independently for exact freshness checking.
    #[must_use]
    pub const fn pin(&self) -> Pin {
        self.pin
    }
    /// Whether an exact retained publication intent needs reconciliation.
    pub fn recovery_required(&self) -> Result<bool, Error> {
        Ok(self.exists(INTENT)? || self.exists(INTENT_TEMP)?)
    }
    /// Publish a union-only candidate under an exact current basis. No record is
    /// returned for outbound delivery until all relevant file/directory syncs pass.
    /// Retrying the same retained intent reconciles it; a different one is rejected.
    pub fn commit(&mut self, candidate: Archive, expected: Pin) -> Result<Publication, Error> {
        self.commit_inner(candidate, expected)
            .map_err(indeterminate)
    }
    fn commit_inner(&mut self, candidate: Archive, expected: Pin) -> Result<Publication, Error> {
        self.inventory()?;
        self.check_pin()?;
        if self.exists(INTENT_TEMP)? {
            if let Some(intent) = self.validate_staged_intent()? {
                if expected != intent.expected || candidate.snapshot() != intent.archive.snapshot()
                {
                    return Err(Error::RecoveryRequired);
                }
            }
            self.reconcile_staged_intent()?;
        }
        if self.exists(INTENT)? {
            let intent = self.validate_intent()?;
            if expected != intent.expected
                || candidate.snapshot() != intent.archive.snapshot()
                || candidate.limits() != self.archive.limits()
            {
                return Err(Error::RecoveryRequired);
            }
            return self.finish_intent(intent, true);
        }
        if self.exists(BUNDLE_TEMP)? || self.exists(PIN_TEMP)? {
            return Err(Error::RecoveryRequired);
        }
        if !candidate.is_extension_of(&self.archive) {
            return Err(Error::Conflict);
        }
        if candidate.physical_digest() == self.pin.physical && candidate.root() == self.pin.logical
        {
            // An exact already-published result is a readback, not a new CAS.
            self.cleanup_obsolete()?;
            return Ok(self.publication(true));
        }
        if expected != self.pin {
            return Err(Error::Conflict);
        }
        self.cleanup_obsolete()?;
        let generation = self.pin.generation.checked_add(1).ok_or(Error::Capacity)?;
        let intent = Intent {
            expected,
            next: Pin::for_archive(generation, &candidate),
            archive: candidate,
        };
        let mut file = create_private(&self.path.join(INTENT_TEMP))?;
        self.step(Step::IntentCreated)?;
        file.write_all(&intent.encode())?;
        self.step(Step::IntentWritten)?;
        file.sync_all()?;
        self.step(Step::IntentSynced)?;
        fs::rename(self.path.join(INTENT_TEMP), self.path.join(INTENT))?;
        self.step(Step::IntentRenamed)?;
        self.directory.sync_all()?;
        self.step(Step::IntentDurable)?;
        self.finish_intent(intent, false)
    }
    /// Resume only the exact complete retained signed intent, or reclaim verified
    /// obsolete physical copies after an already resolved publication. Torn intent
    /// bytes are preserved and rejected; this never invents replacement history.
    pub fn recover(&mut self) -> Result<Publication, Error> {
        self.recover_inner().map_err(indeterminate)
    }
    fn recover_inner(&mut self) -> Result<Publication, Error> {
        self.inventory()?;
        self.check_pin()?;
        if self.exists(INTENT_TEMP)? {
            self.reconcile_staged_intent()?;
        }
        if self.exists(INTENT)? {
            let intent = self.validate_intent()?;
            self.finish_intent(intent, true)
        } else {
            if self.exists(BUNDLE_TEMP)? || self.exists(PIN_TEMP)? {
                return Err(Error::RecoveryRequired);
            }
            self.cleanup_obsolete()?;
            Ok(self.publication(true))
        }
    }
    // Called only after the pinned state and inventory have been validated.
    // Scratch is discardable only before every post-intent effect. A complete
    // frame still has to pass canonical validation and exact-basis checks.
    fn validate_staged_intent(&self) -> Result<Option<Intent>, Error> {
        self.check_pin()?;
        if self.exists(INTENT)? || self.exists(BUNDLE_TEMP)? || self.exists(PIN_TEMP)? {
            return Err(Error::Corrupt);
        }
        self.audit_copies(None)?;
        let raw = read_bounded(&self.path.join(INTENT_TEMP), self.owner, MAX_INTENT_BYTES)?;
        let generation = self.pin.generation.checked_add(1).ok_or(Error::Capacity)?;
        let mut prefix = Vec::new();
        prefix.extend_from_slice(INTENT_MAGIC);
        prefix.extend_from_slice(&self.pin.encode());
        prefix.extend_from_slice(PIN_MAGIC);
        prefix.extend_from_slice(&generation.to_be_bytes());
        let checked = raw.len().min(prefix.len());
        if raw[..checked] != prefix[..checked] {
            return Err(Error::Corrupt);
        }
        if raw.len() >= 8 + 2 * PIN_BYTES {
            let next = Pin::decode(&raw[8 + PIN_BYTES..8 + 2 * PIN_BYTES])?;
            if next.generation != generation {
                return Err(Error::Corrupt);
            }
        }
        if raw.len() < INTENT_HEADER {
            return Ok(None);
        }
        let len = u32::from_be_bytes(
            raw[INTENT_HEADER - 4..INTENT_HEADER]
                .try_into()
                .map_err(|_| Error::Corrupt)?,
        ) as usize;
        if len > MAX_INTENT_BYTES - INTENT_HEADER - 32 {
            return Err(Error::Corrupt);
        }
        if raw.len() < INTENT_HEADER + len + 32 {
            return Ok(None);
        }
        let intent = Intent::decode(&raw, self.archive.realm(), self.archive.limits())?;
        if intent.expected != self.pin || !intent.archive.is_extension_of(&self.archive) {
            return Err(Error::Conflict);
        }
        Ok(Some(intent))
    }
    fn reconcile_staged_intent(&mut self) -> Result<(), Error> {
        if self.validate_staged_intent()?.is_some() {
            // Establish scratch durability again after an uncertain original
            // write/sync before making it the authoritative intent.
            open_private(&self.path.join(INTENT_TEMP), self.owner, MAX_INTENT_BYTES)?.sync_all()?;
            self.step(Step::IntentSynced)?;
            fs::rename(self.path.join(INTENT_TEMP), self.path.join(INTENT))?;
            self.step(Step::IntentRenamed)?;
            self.directory.sync_all()?;
            self.step(Step::IntentDurable)?;
        } else {
            // No authoritative intent or successor effects exist. This is an
            // interrupted preparation, not a published decision to invent.
            fs::remove_file(self.path.join(INTENT_TEMP))?;
            self.directory.sync_all()?;
        }
        Ok(())
    }
    fn validate_intent(&self) -> Result<Intent, Error> {
        let raw = read_bounded(&self.path.join(INTENT), self.owner, MAX_INTENT_BYTES)?;
        let intent = Intent::decode(&raw, self.archive.realm(), self.archive.limits())?;
        if self.pin != intent.expected && self.pin != intent.next {
            return Err(Error::Conflict);
        }
        let old = if self.pin == intent.expected {
            self.archive.clone()
        } else {
            self.load_bundle(intent.expected)?
        };
        if !intent.archive.is_extension_of(&old) {
            return Err(Error::Conflict);
        }
        Ok(intent)
    }
    fn finish_intent(&mut self, intent: Intent, reconciled: bool) -> Result<Publication, Error> {
        // A retry after an uncertain initial sync must establish durability again.
        open_private(&self.path.join(INTENT), self.owner, MAX_INTENT_BYTES)?.sync_all()?;
        self.directory.sync_all()?;
        let snapshot = intent.archive.snapshot();
        let bundle = bundle_name(intent.next.physical);
        if self.exists(&bundle)? {
            if read_bounded(&self.path.join(&bundle), self.owner, MAX_SNAPSHOT_BYTES)? != snapshot {
                return Err(Error::Corrupt);
            }
            open_private(&self.path.join(&bundle), self.owner, MAX_SNAPSHOT_BYTES)?.sync_all()?;
            if self.exists(BUNDLE_TEMP)? {
                self.remove_matching_temp(BUNDLE_TEMP, &snapshot)?;
            }
        } else {
            self.write_temp(
                BUNDLE_TEMP,
                &snapshot,
                Step::BundleWritten,
                Step::BundleSynced,
            )?;
            fs::rename(self.path.join(BUNDLE_TEMP), self.path.join(&bundle))?;
        }
        self.step(Step::BundleRenamed)?;
        self.directory.sync_all()?;
        self.step(Step::BundleDurable)?;
        self.check_pin()?;
        if self.pin == intent.expected {
            self.write_temp(
                PIN_TEMP,
                &intent.next.encode(),
                Step::PinWritten,
                Step::PinSynced,
            )?;
            fs::rename(self.path.join(PIN_TEMP), self.path.join(PIN))?;
            self.step(Step::PinRenamed)?;
        } else if self.pin != intent.next {
            return Err(Error::Conflict);
        }
        self.directory.sync_all()?;
        self.step(Step::PinDurable)?;
        let disk = self.read_pin()?;
        if disk != intent.next {
            return Err(Error::Conflict);
        }
        self.pin = disk;
        self.archive = intent.archive;
        if self.exists(PIN_TEMP)? {
            self.remove_matching_temp(PIN_TEMP, &self.pin.encode())?;
        }
        // Intent removal follows durable pin readback. Old physical copies remain
        // available until that exact intent has been resolved and directory-synced.
        fs::remove_file(self.path.join(INTENT))?;
        self.directory.sync_all()?;
        self.step(Step::IntentRemoved)?;
        self.cleanup_obsolete()?;
        self.step(Step::CleanupDurable)?;
        Ok(self.publication(reconciled))
    }
    fn publication(&self, reconciled: bool) -> Publication {
        Publication {
            pin: self.pin,
            snapshot: self.archive.snapshot(),
            reconciled,
        }
    }
    fn write_temp(
        &mut self,
        name: &str,
        bytes: &[u8],
        written: Step,
        synced: Step,
    ) -> Result<(), Error> {
        if self.exists(name)? {
            let retained = read_bounded(&self.path.join(name), self.owner, bytes.len())?;
            if !bytes.starts_with(&retained) {
                return Err(Error::Corrupt);
            }
            // Complete only a known prefix of the exact retained intent. Neither
            // unrelated bytes nor a different signed candidate is overwritten.
            let mut file = open_private(&self.path.join(name), self.owner, bytes.len())?;
            file.write_all(bytes)?;
            file.set_len(bytes.len() as u64)?;
            self.step(written)?;
            file.sync_all()?;
        } else {
            let mut file = create_private(&self.path.join(name))?;
            file.write_all(bytes)?;
            self.step(written)?;
            file.sync_all()?;
        }
        self.step(synced)
    }
    fn remove_matching_temp(&self, name: &str, bytes: &[u8]) -> Result<(), Error> {
        let retained = read_bounded(&self.path.join(name), self.owner, bytes.len())?;
        if !bytes.starts_with(&retained) {
            return Err(Error::Corrupt);
        }
        fs::remove_file(self.path.join(name))?;
        Ok(())
    }
    fn cleanup_obsolete(&self) -> Result<(), Error> {
        self.check_pin()?;
        if self.exists(INTENT)? {
            return Err(Error::RecoveryRequired);
        }
        let current = bundle_name(self.pin.physical);
        let names = self.inventory()?;
        // Validate every candidate before removing any: a corrupt or unrelated
        // copy must not trigger a partial cleanup that obscures its context.
        let mut obsolete = Vec::new();
        for name in names
            .into_iter()
            .filter(|name| is_bundle(name) && *name != current)
        {
            let raw = read_bounded(&self.path.join(&name), self.owner, MAX_SNAPSHOT_BYTES)?;
            let old = Archive::from_snapshot(self.archive.realm(), self.archive.limits(), &raw)?;
            if bundle_name(old.physical_digest()) != name {
                return Err(Error::Corrupt);
            }
            if !self.archive.is_extension_of(&old) {
                return Err(Error::Conflict);
            }
            obsolete.push(name);
        }
        for name in obsolete {
            self.check_pin()?;
            check_regular(
                &self.path.join(&name),
                &fs::symlink_metadata(self.path.join(&name))?,
                self.owner,
                MAX_SNAPSHOT_BYTES,
            )?;
            fs::remove_file(self.path.join(name))?;
        }
        self.directory.sync_all()?;
        Ok(())
    }
    fn inventory(&self) -> Result<Vec<String>, Error> {
        let mut names = Vec::new();
        for entry in fs::read_dir(&self.path)? {
            if names.len() == MAX_FILES {
                return Err(Error::Capacity);
            }
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| Error::UnsafePath)?;
            if !matches!(
                name.as_str(),
                LOCK | PIN | INTENT | INTENT_TEMP | BUNDLE_TEMP | PIN_TEMP
            ) && !is_bundle(&name)
            {
                return Err(Error::UnsafePath);
            }
            let bound = if matches!(name.as_str(), INTENT | INTENT_TEMP) {
                MAX_INTENT_BYTES
            } else if matches!(name.as_str(), LOCK | PIN | PIN_TEMP) {
                PIN_BYTES
            } else {
                MAX_SNAPSHOT_BYTES
            };
            check_regular(
                &entry.path(),
                &fs::symlink_metadata(entry.path())?,
                self.owner,
                bound,
            )?;
            names.push(name);
        }
        Ok(names)
    }
    fn audit_copies(&self, intent: Option<&Intent>) -> Result<(), Error> {
        let current = bundle_name(self.pin.physical);
        for name in self
            .inventory()?
            .into_iter()
            .filter(|name| is_bundle(name) && *name != current)
        {
            let raw = read_bounded(&self.path.join(&name), self.owner, MAX_SNAPSHOT_BYTES)?;
            let copy = Archive::from_snapshot(self.archive.realm(), self.archive.limits(), &raw)?;
            if bundle_name(copy.physical_digest()) != name {
                return Err(Error::Corrupt);
            }
            if intent.is_some_and(|i| {
                name == bundle_name(i.next.physical) && copy.snapshot() == i.archive.snapshot()
            }) {
                continue;
            }
            if !self.archive.is_extension_of(&copy) {
                return Err(Error::Conflict);
            }
        }
        Ok(())
    }
    fn exists(&self, name: &str) -> Result<bool, Error> {
        match fs::symlink_metadata(self.path.join(name)) {
            Ok(meta) => {
                check_regular(&self.path.join(name), &meta, self.owner, MAX_INTENT_BYTES)?;
                Ok(true)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
    fn load_bundle(&self, pin: Pin) -> Result<Archive, Error> {
        let raw = read_bounded(
            &self.path.join(bundle_name(pin.physical)),
            self.owner,
            MAX_SNAPSHOT_BYTES,
        )?;
        let archive = Archive::from_snapshot(self.archive.realm(), self.archive.limits(), &raw)?;
        if Pin::for_archive(pin.generation, &archive) != pin {
            return Err(Error::Corrupt);
        }
        Ok(archive)
    }
    fn read_pin(&self) -> Result<Pin, Error> {
        Pin::decode(&read_bounded(&self.path.join(PIN), self.owner, PIN_BYTES)?)
    }
    fn check_pin(&self) -> Result<(), Error> {
        if self.read_pin()? != self.pin {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    fn step(&mut self, step: Step) -> Result<(), Error> {
        #[cfg(test)]
        if self.fault == Some(step) {
            self.fault = None;
            return Err(Error::Indeterminate(io::Error::other(
                "injected publication interruption",
            )));
        }
        let _ = step;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Step {
    IntentCreated,
    IntentWritten,
    IntentSynced,
    IntentRenamed,
    IntentDurable,
    BundleWritten,
    BundleSynced,
    BundleRenamed,
    BundleDurable,
    PinWritten,
    PinSynced,
    PinRenamed,
    PinDurable,
    IntentRemoved,
    CleanupDurable,
}
fn indeterminate(error: Error) -> Error {
    match error {
        Error::Io(e) => Error::Indeterminate(e),
        e => e,
    }
}
fn checksum(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    hash.finalize().into()
}
fn absolute(path: &Path) -> Result<PathBuf, Error> {
    custody::absolute(path).map_err(map_custody)
}
fn bundle_name(digest: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::from("bundle-");
    for byte in digest {
        name.push(HEX[(byte >> 4) as usize] as char);
        name.push(HEX[(byte & 15) as usize] as char);
    }
    name
}
fn is_bundle(name: &str) -> bool {
    name.len() == 71
        && name.starts_with("bundle-")
        && name.as_bytes()[7..]
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}
fn create_private(path: &Path) -> Result<File, Error> {
    custody::create_private_file(path).map_err(map_custody)
}
fn check_regular(path: &Path, meta: &Metadata, owner: Owner, max: usize) -> Result<(), Error> {
    custody::check_regular_file(path, meta, owner, max).map_err(map_custody)
}
fn open_private(path: &Path, owner: Owner, max: usize) -> Result<File, Error> {
    custody::open_private_file(path, owner, max).map_err(map_custody)
}
fn read_bounded(path: &Path, owner: Owner, max: usize) -> Result<Vec<u8>, Error> {
    custody::read_private_file(path, owner, max).map_err(map_custody)
}
fn acquire(lock: &File) -> Result<(), Error> {
    custody::acquire_exclusive(lock).map_err(map_custody)
}

/// The committed archive under a shared hold: concurrent readers proceed
/// together while a writer's exclusive lock keeps its whole command atomic.
/// A writer's hold is waited out across the bound; a wedged holder still
/// fails `Busy` rather than blocking a reader forever. The verified
/// pin/bundle pair makes the returned snapshot a real committed state.
/// A retained intent or torn publication temps are not a reader's to
/// reconcile: they fail `RecoveryRequired` for explicit `recover` first.
pub fn read_archive(
    path: impl AsRef<Path>,
    realm: RealmId,
    limits: Limits,
) -> Result<Archive, Error> {
    let path = absolute(path.as_ref())?;
    let (_, owner) = custody::open_private_directory(&path).map_err(map_custody)?;
    let lock = open_private(&path.join(LOCK), owner, 0)?;
    if lock.metadata()?.len() != 0 {
        return Err(Error::Corrupt);
    }
    acquire_shared(&lock)?;
    let pin = Pin::decode(&read_bounded(&path.join(PIN), owner, PIN_BYTES)?)?;
    let raw = read_bounded(
        &path.join(bundle_name(pin.physical)),
        owner,
        MAX_SNAPSHOT_BYTES,
    )?;
    let archive = Archive::from_snapshot(realm, limits, &raw)?;
    if Pin::for_archive(pin.generation, &archive) != pin {
        return Err(Error::Corrupt);
    }
    if present(&path, owner, INTENT, MAX_INTENT_BYTES)?
        || present(&path, owner, INTENT_TEMP, MAX_INTENT_BYTES)?
        || present(&path, owner, BUNDLE_TEMP, MAX_SNAPSHOT_BYTES)?
        || present(&path, owner, PIN_TEMP, PIN_BYTES)?
    {
        return Err(Error::RecoveryRequired);
    }
    Ok(archive)
}

fn acquire_shared(lock: &File) -> Result<(), Error> {
    custody::acquire_shared(lock).map_err(map_custody)
}

fn present(path: &Path, owner: Owner, name: &str, max: usize) -> Result<bool, Error> {
    custody::private_file_present(&path.join(name), owner, max).map_err(map_custody)
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
