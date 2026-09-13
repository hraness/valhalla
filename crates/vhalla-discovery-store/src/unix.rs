use sha2::{Digest, Sha256};
use std::{
    fs::{self, DirBuilder, File, Metadata, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use vhalla_attention::{Attention, ReaderScope};
use vhalla_discovery::DiscoveryState;
use vhalla_social::RecordId;
use vhalla_social_store::Store as SocialStore;

const MAX_BYTES: usize =
    vhalla_attention::MAX_STATE_BYTES + vhalla_discovery::MAX_STATE_BYTES + 1024;
const MAX_INTENT_BYTES: usize = MAX_BYTES + 120;
const IMAGE_MAGIC: &[u8; 8] = b"VHDSP\0\0\x01";
const INTENT_MAGIC: &[u8; 8] = b"VHDSI\0\0\x01";
const PIN_MAGIC: &[u8; 8] = b"VHDPN\0\0\x01";
const PIN_BYTES: usize = 80;
const LOCK: &str = "lock";
const STATE: &str = "state";
const INTENT: &str = "intent";
const TEMP: &str = "state.tmp";

/// Private publication errors never authorize resetting either store.
#[derive(Debug)]
pub enum Error {
    /// Unexpected path, permissions, links, ownership, or directory entries.
    UnsafePath,
    /// A cooperating process already holds the lifetime exclusive lock.
    Busy,
    /// Malformed, truncated, noncanonical, or damaged private evidence.
    Corrupt,
    /// Stale publication basis, namespace mismatch, or component generation conflict.
    Conflict,
    /// An externally retained exact private pin differs from the opened state.
    Freshness,
    /// Reconcile the retained exact intent before constructing another publication.
    RecoveryRequired,
    /// New private source claims lack durable canonical evidence.
    MissingSource,
    /// A fixed count/size/generation ceiling was reached.
    Capacity,
    /// A bounded attention value could not be validated.
    Attention(vhalla_attention::Error),
    /// A bounded discovery value could not be validated.
    Discovery(vhalla_discovery::Error),
    /// The canonical social store is not ready or readable.
    Social(vhalla_social_store::Error),
    /// Read/open/create failed; no reset or automatic deletion is implied.
    Io(io::Error),
    /// Publication may be durable; reopen and reconcile the exact intent/state.
    Indeterminate(io::Error),
}
impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<vhalla_attention::Error> for Error {
    fn from(value: vhalla_attention::Error) -> Self {
        Self::Attention(value)
    }
}
impl From<vhalla_discovery::Error> for Error {
    fn from(value: vhalla_discovery::Error) -> Self {
        Self::Discovery(value)
    }
}
impl From<vhalla_social_store::Error> for Error {
    fn from(value: vhalla_social_store::Error) -> Self {
        Self::Social(value)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "private discovery store: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Typed private components sharing one admitted local namespace.
#[derive(Clone, Debug)]
pub struct PrivateState {
    scope: ReaderScope,
    attention: Attention,
    discovery: DiscoveryState,
}
impl PrivateState {
    /// Empty local preferences and exact read history.
    #[must_use]
    pub fn new(scope: ReaderScope) -> Self {
        Self {
            scope,
            attention: Attention::new(scope),
            discovery: DiscoveryState::new(scope.digest()),
        }
    }
    /// Explicit expected local reader.
    #[must_use]
    pub const fn scope(&self) -> ReaderScope {
        self.scope
    }
    /// Borrow exact notification-read state; reading does not acknowledge.
    #[must_use]
    pub const fn attention(&self) -> &Attention {
        &self.attention
    }
    /// Borrow local preferences, observations, bookmarks and seen state.
    #[must_use]
    pub const fn discovery(&self) -> &DiscoveryState {
        &self.discovery
    }
    /// Replace a typed component only within the same reader namespace.
    pub fn with_attention(&self, attention: Attention) -> Result<Self, Error> {
        if attention.reader() != self.scope {
            return Err(Error::Conflict);
        };
        let attention = Attention::decode(&attention.encode(), self.scope)?;
        Ok(Self {
            scope: self.scope,
            attention,
            discovery: self.discovery.clone(),
        })
    }
    /// Replace a typed component only within the same reader namespace.
    pub fn with_discovery(&self, discovery: DiscoveryState) -> Result<Self, Error> {
        if *discovery.reader() != self.scope.digest() {
            return Err(Error::Conflict);
        };
        let discovery = DiscoveryState::decode(&discovery.encode(), self.scope.digest())?;
        Ok(Self {
            scope: self.scope,
            attention: self.attention.clone(),
            discovery,
        })
    }
    fn payload(&self) -> Vec<u8> {
        let attention = self.attention.encode();
        let discovery = self.discovery.encode();
        let mut raw = Vec::new();
        raw.extend_from_slice(&self.scope.digest());
        raw.extend_from_slice(&(attention.len() as u32).to_be_bytes());
        raw.extend_from_slice(&attention);
        raw.extend_from_slice(&(discovery.len() as u32).to_be_bytes());
        raw.extend_from_slice(&discovery);
        raw
    }
    fn from_payload(raw: &[u8], scope: ReaderScope) -> Result<Self, Error> {
        if raw.len() > MAX_BYTES || raw.len() < 40 || raw[..32] != scope.digest() {
            return Err(Error::Corrupt);
        };
        let attention_len =
            u32::from_be_bytes(raw[32..36].try_into().map_err(|_| Error::Corrupt)?) as usize;
        if attention_len > vhalla_attention::MAX_STATE_BYTES {
            return Err(Error::Capacity);
        };
        let end = 36usize.checked_add(attention_len).ok_or(Error::Capacity)?;
        let attention = Attention::decode(raw.get(36..end).ok_or(Error::Corrupt)?, scope)?;
        let len_end = end.checked_add(4).ok_or(Error::Capacity)?;
        let discovery_len = u32::from_be_bytes(
            raw.get(end..len_end)
                .ok_or(Error::Corrupt)?
                .try_into()
                .map_err(|_| Error::Corrupt)?,
        ) as usize;
        if discovery_len > vhalla_discovery::MAX_STATE_BYTES
            || len_end.checked_add(discovery_len) != Some(raw.len())
        {
            return Err(Error::Corrupt);
        };
        let discovery = DiscoveryState::decode(&raw[len_end..], scope.digest())?;
        Ok(Self {
            scope,
            attention,
            discovery,
        })
    }
}

/// Exact private-state anchor. Keep independently if private rollback detection is
/// required; the canonical social pin does not protect this separate state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pin {
    generation: u64,
    digest: [u8; 32],
}
impl Pin {
    /// Successful local publication generation; not a trusted time or consensus.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }
    /// Exact current private-image digest, including both typed components.
    #[must_use]
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }
    /// Portable exact private anchor for independent retention.
    #[must_use]
    pub fn encode(self) -> [u8; PIN_BYTES] {
        let mut raw = [0; PIN_BYTES];
        raw[..8].copy_from_slice(PIN_MAGIC);
        raw[8..16].copy_from_slice(&self.generation.to_be_bytes());
        raw[16..48].copy_from_slice(&self.digest);
        let digest = checksum(b"vhalla/discovery-store/pin/v1\0", &raw[..48]);
        raw[48..].copy_from_slice(&digest);
        raw
    }
    /// Strict decode; authenticity depends on how the caller retained this anchor.
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() != PIN_BYTES
            || &raw[..8] != PIN_MAGIC
            || checksum(b"vhalla/discovery-store/pin/v1\0", &raw[..48]) != raw[48..]
        {
            return Err(Error::Corrupt);
        };
        Ok(Self {
            generation: u64::from_be_bytes(raw[8..16].try_into().map_err(|_| Error::Corrupt)?),
            digest: raw[16..48].try_into().map_err(|_| Error::Corrupt)?,
        })
    }
}
/// Sealed durable private result; it deliberately contains no public export bytes.
#[derive(Clone, Copy, Debug)]
pub struct Publication {
    pin: Pin,
    reconciled: bool,
}
impl Publication {
    /// Exact durable private anchor.
    #[must_use]
    pub const fn pin(self) -> Pin {
        self.pin
    }
    /// This call completed an existing intent or read back an identical state.
    #[must_use]
    pub const fn reconciled(self) -> bool {
        self.reconciled
    }
}
struct Image {
    generation: u64,
    state: PrivateState,
}
impl Image {
    fn encode(&self) -> Vec<u8> {
        let payload = self.state.payload();
        let mut raw = Vec::new();
        raw.extend_from_slice(IMAGE_MAGIC);
        raw.extend_from_slice(&self.generation.to_be_bytes());
        raw.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        raw.extend_from_slice(&payload);
        let digest = checksum(b"vhalla/discovery-store/state/v1\0", &raw);
        raw.extend_from_slice(&digest);
        assert!(raw.len() <= MAX_BYTES);
        raw
    }
    fn decode(raw: &[u8], scope: ReaderScope) -> Result<Self, Error> {
        if raw.len() < 52
            || raw.len() > MAX_BYTES
            || &raw[..8] != IMAGE_MAGIC
            || checksum(b"vhalla/discovery-store/state/v1\0", &raw[..raw.len() - 32])
                != raw[raw.len() - 32..]
        {
            return Err(Error::Corrupt);
        };
        let size = u32::from_be_bytes(raw[16..20].try_into().map_err(|_| Error::Corrupt)?) as usize;
        if size.checked_add(52) != Some(raw.len()) {
            return Err(Error::Corrupt);
        };
        Ok(Self {
            generation: u64::from_be_bytes(raw[8..16].try_into().map_err(|_| Error::Corrupt)?),
            state: PrivateState::from_payload(&raw[20..20 + size], scope)?,
        })
    }
    fn pin(&self) -> Pin {
        Pin {
            generation: self.generation,
            digest: checksum(b"vhalla/discovery-store/image-pin/v1\0", &self.encode()),
        }
    }
}
struct Intent {
    expected: Pin,
    next: Image,
}
impl Intent {
    fn encode(&self) -> Vec<u8> {
        let next = self.next.encode();
        let mut raw = Vec::new();
        raw.extend_from_slice(INTENT_MAGIC);
        raw.extend_from_slice(&self.expected.encode());
        raw.extend_from_slice(&next);
        let digest = checksum(b"vhalla/discovery-store/intent/v1\0", &raw);
        raw.extend_from_slice(&digest);
        raw
    }
    fn decode(raw: &[u8], scope: ReaderScope) -> Result<Self, Error> {
        if raw.len() < 8 + PIN_BYTES + 52 + 32
            || raw.len() > MAX_INTENT_BYTES
            || &raw[..8] != INTENT_MAGIC
            || checksum(
                b"vhalla/discovery-store/intent/v1\0",
                &raw[..raw.len() - 32],
            ) != raw[raw.len() - 32..]
        {
            return Err(Error::Corrupt);
        };
        let expected = Pin::decode(&raw[8..8 + PIN_BYTES])?;
        let next = Image::decode(&raw[8 + PIN_BYTES..raw.len() - 32], scope)?;
        if expected.generation.checked_add(1) != Some(next.generation) {
            return Err(Error::Conflict);
        };
        Ok(Self { expected, next })
    }
}

/// One explicit private directory, separate from the strict canonical social
/// store. Requires cooperating writers and owner-controlled local path ancestors.
pub struct Store {
    path: PathBuf,
    directory: File,
    _lock: File,
    uid: u32,
    image: Image,
    #[cfg(test)]
    fault: Option<Step>,
}
impl Store {
    /// Initialize a nonexistent private directory after checking the source-store
    /// scope and that the destination is neither that store nor a descendant.
    pub fn create(
        path: impl AsRef<Path>,
        scope: ReaderScope,
        sources: &SocialStore,
    ) -> Result<Self, Error> {
        check_source_ready(scope, sources)?;
        let path = absolute(path.as_ref())?;
        let parent = path.parent().ok_or(Error::UnsafePath)?.canonicalize()?;
        let canonical_source = sources.directory_path().canonicalize()?;
        if parent.starts_with(&canonical_source)
            || parent.join(path.file_name().ok_or(Error::UnsafePath)?) == canonical_source
        {
            return Err(Error::UnsafePath);
        };
        let path = parent.join(path.file_name().ok_or(Error::UnsafePath)?);
        DirBuilder::new().mode(0o700).create(&path)?;
        let (directory, uid) = directory(&path)?;
        let lock = create_private(&path.join(LOCK))?;
        acquire(&lock)?;
        lock.sync_all()?;
        let image = Image {
            generation: 0,
            state: PrivateState::new(scope),
        };
        let mut file = create_private(&path.join(STATE))?;
        file.write_all(&image.encode())?;
        file.sync_all()?;
        directory.sync_all()?;
        File::open(parent)?.sync_all()?;
        Ok(Self {
            path,
            directory,
            _lock: lock,
            uid,
            image,
            #[cfg(test)]
            fault: None,
        })
    }
    /// Open typed private state without silently repairing pending or torn intent.
    /// A complete intent is retained for explicit source-checked recovery.
    pub fn open(
        path: impl AsRef<Path>,
        scope: ReaderScope,
        expected: Option<Pin>,
    ) -> Result<Self, Error> {
        let path = absolute(path.as_ref())?;
        let (directory, uid) = directory(&path)?;
        let lock = open_private(&path.join(LOCK), uid, 0)?;
        acquire(&lock)?;
        let image = Image::decode(&read_bounded(&path.join(STATE), uid, MAX_BYTES)?, scope)?;
        if expected.is_some_and(|expected| expected != image.pin()) {
            return Err(Error::Freshness);
        };
        let result = Self {
            path,
            directory,
            _lock: lock,
            uid,
            image,
            #[cfg(test)]
            fault: None,
        };
        result.inventory()?;
        if result.exists(INTENT)? {
            result.intent()?;
        } else if result.exists(TEMP)? {
            return Err(Error::RecoveryRequired);
        };
        Ok(result)
    }
    /// Last durably published typed private state. Querying does not acknowledge.
    #[must_use]
    pub const fn state(&self) -> &PrivateState {
        &self.image.state
    }
    /// Exact current private anchor, distinct from a canonical archive pin.
    #[must_use]
    pub fn pin(&self) -> Pin {
        self.image.pin()
    }
    /// Whether an exact publication needs explicit reconciliation.
    pub fn recovery_required(&self) -> Result<bool, Error> {
        self.exists(INTENT)
    }
    /// Publish one typed candidate under exact private CAS, only after newly
    /// claimed canonical source IDs are durable in the independently locked store.
    pub fn commit(
        &mut self,
        candidate: PrivateState,
        expected: Pin,
        sources: &SocialStore,
    ) -> Result<Publication, Error> {
        self.commit_inner(candidate, expected, sources)
            .map_err(indeterminate)
    }
    fn commit_inner(
        &mut self,
        candidate: PrivateState,
        expected: Pin,
        sources: &SocialStore,
    ) -> Result<Publication, Error> {
        self.inventory()?;
        self.check_disk()?;
        check_source_ready(self.image.state.scope, sources)?;
        if self.exists(INTENT)? {
            let intent = self.intent()?;
            if expected != intent.expected || candidate.payload() != intent.next.state.payload() {
                return Err(Error::RecoveryRequired);
            };
            return self.finish(intent, sources, true);
        }
        if self.exists(TEMP)? {
            return Err(Error::RecoveryRequired);
        };
        if candidate.payload() == self.image.state.payload() {
            return Ok(Publication {
                pin: self.pin(),
                reconciled: true,
            });
        };
        if expected != self.pin() {
            return Err(Error::Conflict);
        };
        validate_candidate(&self.image.state, &candidate, sources)?;
        let intent = Intent {
            expected,
            next: Image {
                generation: self
                    .image
                    .generation
                    .checked_add(1)
                    .ok_or(Error::Capacity)?,
                state: candidate,
            },
        };
        let mut file = create_private(&self.path.join(INTENT))?;
        self.step(Step::IntentCreated)?;
        file.write_all(&intent.encode())?;
        self.step(Step::IntentWritten)?;
        file.sync_all()?;
        self.directory.sync_all()?;
        self.step(Step::IntentDurable)?;
        self.finish(intent, sources, false)
    }
    /// Recover only the retained complete exact intent. Missing new source claims
    /// block promotion while already-published missing claims remain unresolved.
    pub fn recover(&mut self, sources: &SocialStore) -> Result<Publication, Error> {
        self.inventory()?;
        self.check_disk()?;
        check_source_ready(self.image.state.scope, sources)?;
        if self.exists(INTENT)? {
            let intent = self.intent()?;
            self.finish(intent, sources, true).map_err(indeterminate)
        } else if self.exists(TEMP)? {
            Err(Error::RecoveryRequired)
        } else {
            Ok(Publication {
                pin: self.pin(),
                reconciled: true,
            })
        }
    }
    fn intent(&self) -> Result<Intent, Error> {
        let intent = Intent::decode(
            &read_bounded(&self.path.join(INTENT), self.uid, MAX_INTENT_BYTES)?,
            self.image.state.scope,
        )?;
        if self.pin() != intent.expected && self.pin() != intent.next.pin() {
            return Err(Error::Conflict);
        };
        Ok(intent)
    }
    fn finish(
        &mut self,
        intent: Intent,
        sources: &SocialStore,
        reconciled: bool,
    ) -> Result<Publication, Error> {
        self.inventory()?;
        self.check_disk()?;
        validate_candidate(&self.image.state, &intent.next.state, sources)?;
        let next_bytes = intent.next.encode();
        if self.pin() == intent.expected {
            let mut file = if self.exists(TEMP)? {
                let retained = read_bounded(&self.path.join(TEMP), self.uid, MAX_BYTES)?;
                if !next_bytes.starts_with(&retained) {
                    return Err(Error::Corrupt);
                };
                open_private(&self.path.join(TEMP), self.uid, MAX_BYTES)?
            } else {
                create_private(&self.path.join(TEMP))?
            };
            file.write_all(&next_bytes)?;
            file.set_len(next_bytes.len() as u64)?;
            self.step(Step::TempWritten)?;
            file.sync_all()?;
            self.step(Step::TempDurable)?;
            fs::rename(self.path.join(TEMP), self.path.join(STATE))?;
            self.step(Step::StateRenamed)?;
            self.directory.sync_all()?;
            self.step(Step::StateDurable)?;
        } else if self.pin() != intent.next.pin() {
            return Err(Error::Conflict);
        };
        let disk = Image::decode(
            &read_bounded(&self.path.join(STATE), self.uid, MAX_BYTES)?,
            self.image.state.scope,
        )?;
        if disk.pin() != intent.next.pin() {
            return Err(Error::Conflict);
        };
        self.image = disk;
        if self.exists(TEMP)? {
            let retained = read_bounded(&self.path.join(TEMP), self.uid, MAX_BYTES)?;
            if !next_bytes.starts_with(&retained) {
                return Err(Error::Corrupt);
            };
            fs::remove_file(self.path.join(TEMP))?;
        }
        let retained = read_bounded(&self.path.join(INTENT), self.uid, MAX_INTENT_BYTES)?;
        if retained != intent.encode() {
            return Err(Error::Conflict);
        };
        fs::remove_file(self.path.join(INTENT))?;
        self.step(Step::IntentRemoved)?;
        self.directory.sync_all()?;
        self.step(Step::CleanupDurable)?;
        Ok(Publication {
            pin: self.pin(),
            reconciled,
        })
    }
    fn check_disk(&self) -> Result<(), Error> {
        if Image::decode(
            &read_bounded(&self.path.join(STATE), self.uid, MAX_BYTES)?,
            self.image.state.scope,
        )?
        .pin()
            != self.pin()
        {
            Err(Error::Conflict)
        } else {
            Ok(())
        }
    }
    fn exists(&self, name: &str) -> Result<bool, Error> {
        match fs::symlink_metadata(self.path.join(name)) {
            Ok(meta) => {
                regular(&meta, self.uid, MAX_INTENT_BYTES)?;
                Ok(true)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
    fn inventory(&self) -> Result<(), Error> {
        for (count, entry) in fs::read_dir(&self.path)?.enumerate() {
            if count >= 4 {
                return Err(Error::Capacity);
            };
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| Error::UnsafePath)?;
            let max = match name.as_str() {
                LOCK => 0,
                STATE | TEMP => MAX_BYTES,
                INTENT => MAX_INTENT_BYTES,
                _ => return Err(Error::UnsafePath),
            };
            regular(&fs::symlink_metadata(entry.path())?, self.uid, max)?;
        }
        Ok(())
    }
    fn step(&mut self, step: Step) -> Result<(), Error> {
        #[cfg(test)]
        if self.fault == Some(step) {
            self.fault = None;
            return Err(Error::Io(io::Error::other("injected publication boundary")));
        };
        let _ = step;
        Ok(())
    }
}

fn validate_candidate(
    previous: &PrivateState,
    next: &PrivateState,
    sources: &SocialStore,
) -> Result<(), Error> {
    if previous.scope != next.scope {
        return Err(Error::Conflict);
    };
    check_source_ready(next.scope, sources)?;
    let before = [
        (previous.attention.generation(), previous.attention.encode()),
        (previous.discovery.generation(), previous.discovery.encode()),
    ];
    let after = [
        (next.attention.generation(), next.attention.encode()),
        (next.discovery.generation(), next.discovery.encode()),
    ];
    for ((old_gen, old), (new_gen, new)) in before.iter().zip(after.iter()) {
        if new_gen < old_gen || (new_gen == old_gen && new != old) {
            return Err(Error::Conflict);
        };
    }
    let new_attention = next.attention.new_claim_sources(&previous.attention)?;
    let new_discovery = next.discovery.new_claim_sources(&previous.discovery)?;
    if new_attention
        .into_iter()
        .chain(new_discovery)
        .any(|id| sources.archive().get(id).is_none())
    {
        return Err(Error::MissingSource);
    };
    // Decode both bounded components at the persistence boundary even though their
    // public constructors already validate them; disk never stores opaque blobs.
    PrivateState::from_payload(&next.payload(), next.scope)?;
    Ok(())
}
fn check_source_ready(scope: ReaderScope, sources: &SocialStore) -> Result<(), Error> {
    if sources.archive().realm() != scope.realm() {
        return Err(Error::Conflict);
    };
    if sources.recovery_required()? {
        return Err(Error::RecoveryRequired);
    };
    if sources
        .archive()
        .get(RecordId::from_bytes(*scope.owner().as_bytes()))
        .is_none()
        || scope.agent().is_some_and(|agent| {
            sources
                .archive()
                .get(RecordId::from_bytes(*agent.as_bytes()))
                .is_none()
        })
    {
        return Err(Error::MissingSource);
    };
    Ok(())
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Step {
    IntentCreated,
    IntentWritten,
    IntentDurable,
    TempWritten,
    TempDurable,
    StateRenamed,
    StateDurable,
    IntentRemoved,
    CleanupDurable,
}
fn checksum(domain: &[u8], raw: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(raw);
    hash.finalize().into()
}
fn indeterminate(error: Error) -> Error {
    match error {
        Error::Io(e) => Error::Indeterminate(e),
        other => other,
    }
}
fn absolute(path: &Path) -> Result<PathBuf, Error> {
    Ok(if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    })
}
fn directory(path: &Path) -> Result<(File, u32), Error> {
    let before = fs::symlink_metadata(path)?;
    if !before.is_dir() || before.mode() & 0o7777 != 0o700 {
        return Err(Error::UnsafePath);
    };
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_DIRECTORY | libc::O_NOCTTY)
        .open(path)?;
    let after = file.metadata()?;
    if before.dev() != after.dev() || before.ino() != after.ino() || after.mode() & 0o7777 != 0o700
    {
        return Err(Error::UnsafePath);
    };
    Ok((file, after.uid()))
}
fn regular(meta: &Metadata, uid: u32, max: usize) -> Result<(), Error> {
    if !meta.is_file() || meta.mode() & 0o7777 != 0o600 || meta.nlink() != 1 || meta.uid() != uid {
        return Err(Error::UnsafePath);
    };
    if meta.len() > max as u64 {
        return Err(Error::Capacity);
    };
    Ok(())
}
fn create_private(path: &Path) -> Result<File, Error> {
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)?)
}
fn open_private(path: &Path, uid: u32, max: usize) -> Result<File, Error> {
    let before = fs::symlink_metadata(path)?;
    regular(&before, uid, max)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)?;
    let after = file.metadata()?;
    regular(&after, uid, max)?;
    if before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(Error::UnsafePath);
    };
    Ok(file)
}
fn read_bounded(path: &Path, uid: u32, max: usize) -> Result<Vec<u8>, Error> {
    let mut file = open_private(path, uid, max)?;
    let len = usize::try_from(file.metadata()?.len()).map_err(|_| Error::Capacity)?;
    let mut raw = vec![0; len];
    file.read_exact(&mut raw)?;
    if file.read(&mut [0])? != 0 {
        return Err(Error::Corrupt);
    };
    Ok(raw)
}
fn acquire(file: &File) -> Result<(), Error> {
    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(fs::TryLockError::WouldBlock) => Err(Error::Busy),
        Err(fs::TryLockError::Error(e)) => Err(e.into()),
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
