use sha2::{Digest, Sha256};
use std::{
    fs::{self, DirBuilder, File, Metadata, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use vhalla_core::RealmId;
use vhalla_rooms::{
    registry::{DirectoryPolicy, Registry},
    DirectoryId,
};
use vhalla_social::OwnerId;

const PIN_MAGIC: &[u8; 8] = b"VHRP\0\0\0\x01";
const INTENT_MAGIC: &[u8; 8] = b"VHRI\0\0\0\x01";
/// Canonical exact-anchor encoding size, including its integrity checksum.
pub const PIN_BYTES: usize = 112;
const INTENT_HEADER: usize = 8 + 2 * PIN_BYTES + 4;
const MAX_INTENT_BYTES: usize = INTENT_HEADER + vhalla_rooms::registry::MAX_SNAPSHOT_BYTES + 32;
/// Directory entry ceiling: lock, pin, intent, two temps and retained bundles.
/// Strict-ancestor bundles are reclaimed at each publish; retained revisions
/// beyond this bound stop the store rather than silently growing.
const MAX_FILES: usize = 16;
const LOCK: &str = "lock";
const PIN: &str = "pin";
const INTENT: &str = "intent";
const BUNDLE_TEMP: &str = "bundle.tmp";
const PIN_TEMP: &str = "pin.tmp";

/// Failures never authorize deleting evidence, resetting a store, or reusing a
/// publication sequence.
#[derive(Debug)]
pub enum Error {
    /// A path/type/link/permission or unexpected directory entry is unsafe.
    UnsafePath,
    /// Another cooperating process or handle holds the lifetime exclusive lock.
    Busy,
    /// A snapshot, partial intent, checksum, or immutable bundle is corrupt.
    Corrupt,
    /// A candidate is stale, divergent, or built on a different pin.
    Conflict,
    /// The optional externally retained exact anchor differs from disk.
    Freshness,
    /// Reconcile the retained exact intent before constructing a different publication.
    RecoveryRequired,
    /// A filesystem or arithmetic resource ceiling was reached.
    Capacity,
    /// The registry rejected a snapshot candidate or restore payload.
    Registry(vhalla_rooms::RegistryError),
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
impl From<vhalla_rooms::RegistryError> for Error {
    fn from(error: vhalla_rooms::RegistryError) -> Self {
        Self::Registry(error)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rooms store: {self:?}")
    }
}
impl std::error::Error for Error {}

/// An exact durable registry anchor. Its generation is local bookkeeping, not
/// consensus.
/// Keep this outside the store to detect replacement with a different
/// coherent snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pin {
    generation: u64,
    physical: [u8; 32],
    logical: [u8; 32],
}
impl Pin {
    fn for_registry(generation: u64, registry: &Registry) -> Self {
        Self {
            generation,
            physical: bundle_digest(&registry.snapshot()),
            logical: registry.digest(),
        }
    }
    /// Local successful-publication count; it is not a trusted timestamp.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }
    /// Exact stored snapshot checksum, including retained proof bytes.
    #[must_use]
    pub const fn physical(self) -> [u8; 32] {
        self.physical
    }
    /// Semantic registry-state commitment.
    #[must_use]
    pub const fn logical(self) -> [u8; 32] {
        self.logical
    }
    /// Encode for caller-managed independent retention. No path or secret is included.
    #[must_use]
    pub fn encode(self) -> [u8; PIN_BYTES] {
        let mut raw = [0; PIN_BYTES];
        raw[..8].copy_from_slice(PIN_MAGIC);
        raw[8..16].copy_from_slice(&self.generation.to_be_bytes());
        raw[16..48].copy_from_slice(&self.physical);
        raw[48..80].copy_from_slice(&self.logical);
        let digest = checksum(b"vhalla/rooms/store/pin/v1\0", &raw[..80]);
        raw[80..].copy_from_slice(&digest);
        raw
    }
    /// Decode a canonical pin. Its authenticity depends on where the caller retained it.
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() != PIN_BYTES
            || raw.get(..8) != Some(PIN_MAGIC.as_slice())
            || checksum(b"vhalla/rooms/store/pin/v1\0", &raw[..80]) != raw[80..]
        {
            return Err(Error::Corrupt);
        }
        Ok(Self {
            generation: u64::from_be_bytes(raw[8..16].try_into().map_err(|_| Error::Corrupt)?),
            physical: raw[16..48].try_into().map_err(|_| Error::Corrupt)?,
            logical: raw[48..80].try_into().map_err(|_| Error::Corrupt)?,
        })
    }
}

/// A sealed result returned only after the exact registry is durably published.
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
    /// Full canonical registry snapshot, now eligible for outbound delivery.
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
    registry: Registry,
}
impl Intent {
    fn encode(&self) -> Vec<u8> {
        let snapshot = self.registry.snapshot();
        let mut raw = Vec::with_capacity(INTENT_HEADER + snapshot.len() + 32);
        raw.extend_from_slice(INTENT_MAGIC);
        raw.extend_from_slice(&self.expected.encode());
        raw.extend_from_slice(&self.next.encode());
        raw.extend_from_slice(&(snapshot.len() as u32).to_be_bytes());
        raw.extend_from_slice(&snapshot);
        let digest = checksum(b"vhalla/rooms/store/intent/v1\0", &raw);
        raw.extend_from_slice(&digest);
        raw
    }
    fn decode(raw: &[u8]) -> Result<Self, Error> {
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
        if len > vhalla_rooms::registry::MAX_SNAPSHOT_BYTES
            || INTENT_HEADER + len + 32 != raw.len()
            || checksum(b"vhalla/rooms/store/intent/v1\0", &raw[..raw.len() - 32])
                != raw[raw.len() - 32..]
            || expected.generation.checked_add(1) != Some(next.generation)
        {
            return Err(Error::Corrupt);
        }
        let registry = Registry::restore(&raw[INTENT_HEADER..INTENT_HEADER + len])
            .map_err(|_| Error::Corrupt)?;
        if Pin::for_registry(next.generation, &registry) != next {
            return Err(Error::Corrupt);
        }
        Ok(Self {
            expected,
            next,
            registry,
        })
    }
}

/// One owner-private directory and lifetime exclusive lock. No file/key handle escapes.
///
/// The adapter requires cooperating writers and owner-controlled path ancestors.
/// Checks reject observed symlinks/hardlinks and inconsistent ownership; they are
/// not a sandbox against the directory owner/root replacing paths between calls.
/// Lineage is revision-monotone and pin-compare-and-swap: a candidate that
/// rewinds or forks the applied order is rejected rather than merged.
pub struct Store {
    path: PathBuf,
    directory: File,
    _lock: File,
    uid: u32,
    registry: Registry,
    pin: Pin,
    #[cfg(test)]
    fault: Option<Step>,
}
impl Store {
    /// Explicitly initialize a previously nonexistent private directory and an
    /// empty registry pinned to one directory identity, realm, policy and
    /// eligible-source set. Existing or partially created directories are
    /// never reset or reused.
    pub fn create(
        path: impl AsRef<Path>,
        directory: DirectoryId,
        realm: RealmId,
        policy: DirectoryPolicy,
        eligible: &[OwnerId],
    ) -> Result<Self, Error> {
        let registry = Registry::new(directory, realm, policy, eligible)?;
        let path = absolute(path.as_ref())?;
        DirBuilder::new().mode(0o700).create(&path)?;
        let directory_file = File::open(&path)?;
        let uid = check_directory(&path)?;
        let lock = create_private(&path.join(LOCK))?;
        acquire(&lock)?;
        lock.sync_all()?;
        let pin = Pin::for_registry(0, &registry);
        let mut bundle = create_private(&path.join(bundle_name(pin.physical)))?;
        bundle.write_all(&registry.snapshot())?;
        bundle.sync_all()?;
        let mut pin_file = create_private(&path.join(PIN))?;
        pin_file.write_all(&pin.encode())?;
        pin_file.sync_all()?;
        directory_file.sync_all()?;
        File::open(path.parent().ok_or(Error::UnsafePath)?)?.sync_all()?;
        Ok(Self {
            path,
            directory: directory_file,
            _lock: lock,
            uid,
            registry,
            pin,
            #[cfg(test)]
            fault: None,
        })
    }
    /// Open existing evidence without creating/repairing files. A valid pending
    /// intent is retained for explicit `recover`; a torn intent fails closed.
    /// The optional external anchor requires exact equality, including generation.
    pub fn open(path: impl AsRef<Path>, expected: Option<Pin>) -> Result<Self, Error> {
        let path = absolute(path.as_ref())?;
        let uid = check_directory(&path)?;
        let directory = File::open(&path)?;
        let lock = open_private(&path.join(LOCK), uid, 0)?;
        if lock.metadata()?.len() != 0 {
            return Err(Error::Corrupt);
        }
        acquire(&lock)?;
        let pin = Pin::decode(&read_bounded(&path.join(PIN), uid, PIN_BYTES)?)?;
        if expected.is_some_and(|expected| expected != pin) {
            return Err(Error::Freshness);
        }
        let raw = read_bounded(
            &path.join(bundle_name(pin.physical)),
            uid,
            vhalla_rooms::registry::MAX_SNAPSHOT_BYTES,
        )?;
        let registry = Registry::restore(&raw).map_err(|_| Error::Corrupt)?;
        if Pin::for_registry(pin.generation, &registry) != pin {
            return Err(Error::Corrupt);
        }
        let store = Self {
            path,
            directory,
            _lock: lock,
            uid,
            registry,
            pin,
            #[cfg(test)]
            fault: None,
        };
        store.inventory()?;
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
    /// Borrow the last pinned complete registry. A pending publication is not outbound-ready.
    #[must_use]
    pub const fn registry(&self) -> &Registry {
        &self.registry
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
        self.exists(INTENT)
    }
    /// Publish a revision-descendant candidate under an exact current basis. No
    /// snapshot is returned for outbound delivery until all relevant file and
    /// directory syncs pass. Retrying the same retained intent reconciles it;
    /// a different one is rejected.
    pub fn commit(&mut self, candidate: Registry, expected: Pin) -> Result<Publication, Error> {
        self.commit_inner(candidate, expected)
            .map_err(indeterminate)
    }
    fn commit_inner(&mut self, candidate: Registry, expected: Pin) -> Result<Publication, Error> {
        self.inventory()?;
        self.check_pin()?;
        if self.exists(INTENT)? {
            let intent = self.validate_intent()?;
            if expected != intent.expected || candidate.snapshot() != intent.registry.snapshot() {
                return Err(Error::RecoveryRequired);
            }
            return self.finish_intent(intent, true);
        }
        if self.exists(BUNDLE_TEMP)? || self.exists(PIN_TEMP)? {
            return Err(Error::RecoveryRequired);
        }
        if candidate.revision() <= self.registry.revision() {
            if candidate.revision() == self.registry.revision()
                && candidate.digest() == self.pin.logical
            {
                // An exact already-published result is a readback, not a new CAS.
                self.cleanup_obsolete()?;
                return Ok(self.publication(true));
            }
            // Rewound or divergent-at-same-revision: never merged.
            return Err(Error::Conflict);
        }
        if expected != self.pin {
            return Err(Error::Conflict);
        }
        self.cleanup_obsolete()?;
        let generation = self.pin.generation.checked_add(1).ok_or(Error::Capacity)?;
        let intent = Intent {
            expected,
            next: Pin::for_registry(generation, &candidate),
            registry: candidate,
        };
        let mut file = create_private(&self.path.join(INTENT))?;
        self.step(Step::IntentCreated)?;
        file.write_all(&intent.encode())?;
        self.step(Step::IntentWritten)?;
        file.sync_all()?;
        self.directory.sync_all()?;
        self.step(Step::IntentDurable)?;
        self.finish_intent(intent, false)
    }
    /// Resume only the exact complete retained intent, or reclaim verified
    /// obsolete bundles after an already resolved publication. Torn intent
    /// bytes are preserved and rejected; this never invents replacement history.
    pub fn recover(&mut self) -> Result<Publication, Error> {
        self.recover_inner().map_err(indeterminate)
    }
    fn recover_inner(&mut self) -> Result<Publication, Error> {
        self.inventory()?;
        self.check_pin()?;
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
    fn validate_intent(&self) -> Result<Intent, Error> {
        let raw = read_bounded(&self.path.join(INTENT), self.uid, MAX_INTENT_BYTES)?;
        let intent = Intent::decode(&raw)?;
        if self.pin != intent.expected && self.pin != intent.next {
            return Err(Error::Conflict);
        }
        let old_revision = if self.pin == intent.expected {
            self.registry.revision()
        } else {
            self.load_bundle(intent.expected)?.revision()
        };
        // The intent must extend the state its expected pin names; equal or
        // rewound revision would complete a stale or divergent publication.
        if intent.registry.revision() <= old_revision {
            return Err(Error::Conflict);
        }
        Ok(intent)
    }
    fn finish_intent(&mut self, intent: Intent, reconciled: bool) -> Result<Publication, Error> {
        // A retry after an uncertain initial sync must establish durability again.
        open_private(&self.path.join(INTENT), self.uid, MAX_INTENT_BYTES)?.sync_all()?;
        self.directory.sync_all()?;
        let snapshot = intent.registry.snapshot();
        let bundle = bundle_name(intent.next.physical);
        if self.exists(&bundle)? {
            if read_bounded(
                &self.path.join(&bundle),
                self.uid,
                vhalla_rooms::registry::MAX_SNAPSHOT_BYTES,
            )? != snapshot
            {
                return Err(Error::Corrupt);
            }
            open_private(
                &self.path.join(&bundle),
                self.uid,
                vhalla_rooms::registry::MAX_SNAPSHOT_BYTES,
            )?
            .sync_all()?;
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
        self.registry = intent.registry;
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
            snapshot: self.registry.snapshot(),
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
            let retained = read_bounded(&self.path.join(name), self.uid, bytes.len())?;
            if !bytes.starts_with(&retained) {
                return Err(Error::Corrupt);
            }
            // Complete only a known prefix of the exact retained intent. Neither
            // unrelated bytes nor a different candidate is overwritten.
            let mut file = open_private(&self.path.join(name), self.uid, bytes.len())?;
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
        let retained = read_bounded(&self.path.join(name), self.uid, bytes.len())?;
        if !bytes.starts_with(&retained) {
            return Err(Error::Corrupt);
        }
        fs::remove_file(self.path.join(name))?;
        Ok(())
    }
    /// Reclaim verified strict ancestors of the pinned revision. A retained
    /// bundle is content-addressed evidence: only a decodable snapshot whose
    /// revision the pin has strictly passed is removed. A bundle newer than or
    /// divergent from the pin is regression evidence and stops the store.
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
            let raw = read_bounded(
                &self.path.join(&name),
                self.uid,
                vhalla_rooms::registry::MAX_SNAPSHOT_BYTES,
            )?;
            let old = Registry::restore(&raw).map_err(|_| Error::Corrupt)?;
            if bundle_name(bundle_digest(&raw)) != name {
                return Err(Error::Corrupt);
            }
            if old.revision() >= self.registry.revision() {
                return Err(Error::Conflict);
            }
            obsolete.push(name);
        }
        for name in obsolete {
            self.check_pin()?;
            check_regular(
                &fs::symlink_metadata(self.path.join(&name))?,
                self.uid,
                vhalla_rooms::registry::MAX_SNAPSHOT_BYTES,
            )?;
            fs::remove_file(self.path.join(name))?;
        }
        self.directory.sync_all()?;
        Ok(())
    }
    fn inventory(&self) -> Result<Vec<String>, Error> {
        let mut names = Vec::new();
        for entry in fs::read_dir(&self.path)? {
            if names.len() >= MAX_FILES {
                return Err(Error::Capacity);
            }
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| Error::UnsafePath)?;
            if !matches!(name.as_str(), LOCK | PIN | INTENT | BUNDLE_TEMP | PIN_TEMP)
                && !is_bundle(&name)
            {
                return Err(Error::UnsafePath);
            }
            let bound = if name == INTENT {
                MAX_INTENT_BYTES
            } else if matches!(name.as_str(), LOCK | PIN | PIN_TEMP) {
                PIN_BYTES
            } else {
                vhalla_rooms::registry::MAX_SNAPSHOT_BYTES
            };
            check_regular(&fs::symlink_metadata(entry.path())?, self.uid, bound)?;
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
            let raw = read_bounded(
                &self.path.join(&name),
                self.uid,
                vhalla_rooms::registry::MAX_SNAPSHOT_BYTES,
            )?;
            let copy = Registry::restore(&raw).map_err(|_| Error::Corrupt)?;
            if bundle_name(bundle_digest(&raw)) != name {
                return Err(Error::Corrupt);
            }
            if intent.is_some_and(|i| {
                name == bundle_name(i.next.physical) && copy.snapshot() == i.registry.snapshot()
            }) {
                continue;
            }
            if copy.revision() > self.registry.revision() {
                return Err(Error::Conflict);
            }
        }
        Ok(())
    }
    fn exists(&self, name: &str) -> Result<bool, Error> {
        match fs::symlink_metadata(self.path.join(name)) {
            Ok(meta) => {
                check_regular(&meta, self.uid, MAX_INTENT_BYTES)?;
                Ok(true)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
    fn load_bundle(&self, pin: Pin) -> Result<Registry, Error> {
        let raw = read_bounded(
            &self.path.join(bundle_name(pin.physical)),
            self.uid,
            vhalla_rooms::registry::MAX_SNAPSHOT_BYTES,
        )?;
        let registry = Registry::restore(&raw).map_err(|_| Error::Corrupt)?;
        if Pin::for_registry(pin.generation, &registry) != pin {
            return Err(Error::Corrupt);
        }
        Ok(registry)
    }
    fn read_pin(&self) -> Result<Pin, Error> {
        Pin::decode(&read_bounded(&self.path.join(PIN), self.uid, PIN_BYTES)?)
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
fn bundle_digest(snapshot: &[u8]) -> [u8; 32] {
    checksum(b"vhalla/rooms/store/bundle/v1\0", snapshot)
}
fn absolute(path: &Path) -> Result<PathBuf, Error> {
    Ok(if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    })
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
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?)
}
fn check_directory(path: &Path) -> Result<u32, Error> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir() || meta.mode() & 0o7777 != 0o700 {
        return Err(Error::UnsafePath);
    }
    Ok(meta.uid())
}
fn check_regular(meta: &Metadata, uid: u32, max: usize) -> Result<(), Error> {
    if !meta.is_file() || meta.mode() & 0o7777 != 0o600 || meta.nlink() != 1 || meta.uid() != uid {
        return Err(Error::UnsafePath);
    }
    if meta.len() > max as u64 {
        return Err(Error::Corrupt);
    }
    Ok(())
}
fn open_private(path: &Path, uid: u32, max: usize) -> Result<File, Error> {
    let before = fs::symlink_metadata(path)?;
    check_regular(&before, uid, max)?;
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    let after = file.metadata()?;
    check_regular(&after, uid, max)?;
    if before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(Error::UnsafePath);
    }
    Ok(file)
}
fn read_bounded(path: &Path, uid: u32, max: usize) -> Result<Vec<u8>, Error> {
    let mut file = open_private(path, uid, max)?;
    let len = usize::try_from(file.metadata()?.len()).map_err(|_| Error::Corrupt)?;
    let mut raw = vec![0; len];
    file.read_exact(&mut raw)?;
    if file.read(&mut [0; 1])? != 0 {
        return Err(Error::Corrupt);
    }
    Ok(raw)
}
fn acquire(lock: &File) -> Result<(), Error> {
    match lock.try_lock() {
        Ok(()) => Ok(()),
        Err(fs::TryLockError::WouldBlock) => Err(Error::Busy),
        Err(fs::TryLockError::Error(e)) => Err(e.into()),
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
