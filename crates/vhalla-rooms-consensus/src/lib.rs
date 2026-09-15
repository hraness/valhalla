#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Consensus-facing adapter from an engine's decided/finalized boundary to
//! the real room-registry application layer, gated by the durable commit
//! journal.
//!
//! The application authority is `vhalla_rooms::Registry` plus the
//! `vhalla_social::Archive` it reads evidence from. A decided `Batch`
//! carries canonical signed record bytes: social evidence (ingested into a
//! candidate archive, then harvested through `Registry::award`) and room
//! records (`Registry::apply`), all under the batch's agreed clock. The
//! batch commits to the resulting `registry.digest()`, `archive.root()`
//! and committed control snapshot; `validate` replays on clones and
//! compares the claims before anything is durable.
//!
//! Durability order is fixed: journal first (the order authority), then
//! the social snapshot store, then the rooms snapshot store, then memory;
//! the acknowledgement is emitted only after all of them succeed. Because
//! journal commit precedes the store publications, a crash anywhere after
//! it leaves journal-decided batches that `open` re-derives and re-publishes
//! idempotently (archive ingest is a set-union; an already-published exact
//! store candidate is a readback). Store state can never run ahead of the
//! journal, and the rooms store can never run ahead of the social store.

use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::collections::BTreeMap;
use std::fmt;
#[cfg(unix)]
use std::path::{Path, PathBuf};
use vhalla_core::RealmId;
#[cfg(unix)]
use vhalla_journal::{Bundle, BundleParts, FsStore, Journal, JournalError, Outcome, Store};
use vhalla_rooms::registry::{DirectoryPolicy, Registry, RegistryError};
use vhalla_rooms::DirectoryId;
use vhalla_social::archive::{Archive, Budget, Limits};
use vhalla_social::control::ControlView;
use vhalla_social::OwnerId;

/// Deterministic signed-record scenario builders shared by this crate's
/// tests and engine-level integration tests in `vhalla-rooms-node`.
#[cfg(any(test, feature = "fixture"))]
pub mod fixture;
#[cfg(all(test, unix))]
mod tests;

/// Maximum canonical `Batch::encode` bytes — must fit the journal's 64KiB
/// field bound with room to spare.
pub const MAX_BATCH_BYTES: usize = 48 * 1024;
/// Maximum records per class in one batch.
pub const MAX_BATCH_ITEMS: usize = 32;
/// Maximum advance of the committed clock in one batch. Once the first
/// committed batch anchors the clock, later batches may not regress it and
/// may not jump more than a day ahead — a stalled clock ratchets back toward
/// real time at one day per committed height, never freezing.
pub const MAX_TIME_DRIFT: u64 = 86_400;

const FRONTIER_BYTES: usize = 8 + 32 + 32 + 32 + 32 + 8;
const BATCH_MAGIC: &[u8; 4] = b"VRB1";

fn take<'a>(rest: &mut &'a [u8], n: usize) -> Result<&'a [u8], ApplyError> {
    if rest.len() < n {
        return Err(ApplyError::Decode);
    }
    let (head, tail) = rest.split_at(n);
    *rest = tail;
    Ok(head)
}

fn sha256(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}

/// The consensus-visible application commitment: height, last decided value
/// id, resulting registry digest, resulting social root, the committed
/// control snapshot digest and the agreed clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frontier {
    /// Consensus height this frontier was produced at (0 at genesis).
    pub height: u64,
    /// Value id of the decided batch that produced it.
    pub value: [u8; 32],
    /// `Registry::digest()` of the resulting state.
    pub registry: [u8; 32],
    /// `Archive::root()` of the resulting evidence set.
    pub social: [u8; 32],
    /// `RoomAuthority::snapshot` over the resulting state and view — the R1b
    /// committed control commitment.
    pub control: [u8; 32],
    /// Agreed clock at the producing batch.
    pub time: u64,
}

impl Frontier {
    fn encode(&self) -> [u8; FRONTIER_BYTES] {
        let mut raw = [0u8; FRONTIER_BYTES];
        raw[..8].copy_from_slice(&self.height.to_be_bytes());
        raw[8..40].copy_from_slice(&self.value);
        raw[40..72].copy_from_slice(&self.registry);
        raw[72..104].copy_from_slice(&self.social);
        raw[104..136].copy_from_slice(&self.control);
        raw[136..].copy_from_slice(&self.time.to_be_bytes());
        raw
    }
    fn decode(raw: &[u8]) -> Result<Self, ApplyError> {
        if raw.len() != FRONTIER_BYTES {
            return Err(ApplyError::Decode);
        }
        Ok(Self {
            height: u64::from_be_bytes(raw[..8].try_into().unwrap()),
            value: raw[8..40].try_into().unwrap(),
            registry: raw[40..72].try_into().unwrap(),
            social: raw[72..104].try_into().unwrap(),
            control: raw[104..136].try_into().unwrap(),
            time: u64::from_be_bytes(raw[136..].try_into().unwrap()),
        })
    }
    /// The 256-bit commitment a journal bundle pins as predecessor/next.
    #[must_use]
    pub fn commitment(&self) -> [u8; 32] {
        sha256(b"vhalla/rooms/live-frontier/v1\0", &[&self.encode()])
    }
}

/// One consensus-carried batch: canonical signed social evidence and room
/// records plus the claimed post-state digests, prepared against an exact
/// parent frontier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch {
    /// The complete frontier this batch extends.
    pub parent: Frontier,
    /// The agreed consensus clock for this batch.
    pub time: u64,
    /// Canonical `vhalla_social::SignedRecord` bytes — ingested into the
    /// candidate archive, then harvested through `Registry::award`.
    pub evidence: Vec<Vec<u8>>,
    /// Canonical `vhalla_rooms::SignedRecord` bytes — applied in order.
    pub records: Vec<Vec<u8>>,
    /// Claimed post-apply `Registry::digest()`.
    pub result_registry: [u8; 32],
    /// Claimed post-merge `Archive::root()`.
    pub result_social: [u8; 32],
    /// Claimed post-apply committed control snapshot.
    pub result_control: [u8; 32],
}

impl Batch {
    /// Canonical encoding bound by `MAX_BATCH_BYTES`.
    pub fn encode(&self) -> Vec<u8> {
        let mut raw = Vec::with_capacity(256);
        raw.extend_from_slice(BATCH_MAGIC);
        raw.extend_from_slice(&self.parent.encode());
        raw.extend_from_slice(&self.time.to_be_bytes());
        raw.extend_from_slice(&(self.evidence.len() as u32).to_be_bytes());
        for item in &self.evidence {
            raw.extend_from_slice(&(item.len() as u32).to_be_bytes());
            raw.extend_from_slice(item);
        }
        raw.extend_from_slice(&(self.records.len() as u32).to_be_bytes());
        for item in &self.records {
            raw.extend_from_slice(&(item.len() as u32).to_be_bytes());
            raw.extend_from_slice(item);
        }
        raw.extend_from_slice(&self.result_registry);
        raw.extend_from_slice(&self.result_social);
        raw.extend_from_slice(&self.result_control);
        raw
    }
    /// Strict bounded decode of `encode` output.
    pub fn decode(raw: &[u8]) -> Result<Self, ApplyError> {
        if raw.len() < 4 + FRONTIER_BYTES + 8 + 4 + 4 + 96
            || raw.len() > MAX_BATCH_BYTES
            || raw.get(..4) != Some(BATCH_MAGIC.as_slice())
        {
            return Err(ApplyError::Decode);
        }
        let mut rest = &raw[4..];
        let parent = Frontier::decode(take(&mut rest, FRONTIER_BYTES)?)?;
        let time = u64::from_be_bytes(take(&mut rest, 8)?.try_into().unwrap());
        let items = |rest: &mut &[u8]| -> Result<Vec<Vec<u8>>, ApplyError> {
            let count = u32::from_be_bytes(take(rest, 4)?.try_into().unwrap()) as usize;
            if count > MAX_BATCH_ITEMS {
                return Err(ApplyError::Decode);
            }
            let mut out = Vec::with_capacity(count);
            for _ in 0..count {
                let len = u32::from_be_bytes(take(rest, 4)?.try_into().unwrap()) as usize;
                if len > vhalla_social::MAX_RECORD_BYTES {
                    return Err(ApplyError::Decode);
                }
                out.push(take(rest, len)?.to_vec());
            }
            Ok(out)
        };
        let evidence = items(&mut rest)?;
        let records = items(&mut rest)?;
        let result_registry = take(&mut rest, 32)?.try_into().unwrap();
        let result_social = take(&mut rest, 32)?.try_into().unwrap();
        let result_control = take(&mut rest, 32)?.try_into().unwrap();
        if !rest.is_empty() {
            return Err(ApplyError::Decode);
        }
        Ok(Self {
            parent,
            time,
            evidence,
            records,
            result_registry,
            result_social,
            result_control,
        })
    }
    /// The value commitment certificates name: a hash of the full canonical
    /// batch, including the claimed result digests.
    #[must_use]
    pub fn value_id(&self) -> [u8; 32] {
        sha256(b"vhalla/rooms/live-batch/v1\0", &[&self.encode()])
    }
}

/// A submission body: the parts of a batch a producer owns — agreed clock,
/// canonical social evidence and room records — without the frontier or
/// claimed result digests, which only the node holding the current state
/// can compute. The node's intake drains these and assembles the full
/// batch against its own frontier at proposal time, so a producer never
/// fabricates parent or result claims.
pub struct BatchBody {
    /// The agreed consensus clock for the assembled batch.
    pub time: u64,
    /// Canonical `vhalla_social::SignedRecord` bytes.
    pub evidence: Vec<Vec<u8>>,
    /// Canonical `vhalla_rooms::SignedRecord` bytes.
    pub records: Vec<Vec<u8>>,
}

const BODY_MAGIC: &[u8; 4] = b"VBB1";

impl BatchBody {
    /// Canonical bounded encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut raw = Vec::with_capacity(64);
        raw.extend_from_slice(BODY_MAGIC);
        raw.extend_from_slice(&self.time.to_be_bytes());
        for items in [&self.evidence, &self.records] {
            raw.extend_from_slice(&(items.len() as u32).to_be_bytes());
            for item in items {
                raw.extend_from_slice(&(item.len() as u32).to_be_bytes());
                raw.extend_from_slice(item);
            }
        }
        raw
    }
    /// Strict bounded decode of `encode` output.
    pub fn decode(raw: &[u8]) -> Result<Self, ApplyError> {
        if raw.len() < 4 + 8 + 4 + 4
            || raw.len() > MAX_BATCH_BYTES
            || raw.get(..4) != Some(BODY_MAGIC.as_slice())
        {
            return Err(ApplyError::Decode);
        }
        let mut rest = &raw[4..];
        let time = u64::from_be_bytes(take(&mut rest, 8)?.try_into().unwrap());
        let items = |rest: &mut &[u8]| -> Result<Vec<Vec<u8>>, ApplyError> {
            let count = u32::from_be_bytes(take(rest, 4)?.try_into().unwrap()) as usize;
            if count > MAX_BATCH_ITEMS {
                return Err(ApplyError::Decode);
            }
            let mut out = Vec::with_capacity(count);
            for _ in 0..count {
                let len = u32::from_be_bytes(take(rest, 4)?.try_into().unwrap()) as usize;
                if len > vhalla_social::MAX_RECORD_BYTES {
                    return Err(ApplyError::Decode);
                }
                out.push(take(rest, len)?.to_vec());
            }
            Ok(out)
        };
        let evidence = items(&mut rest)?;
        let records = items(&mut rest)?;
        if !rest.is_empty() {
            return Err(ApplyError::Decode);
        }
        Ok(BatchBody {
            time,
            evidence,
            records,
        })
    }
}

/// A batch validated against the pinned frontier, carrying the replayed
/// candidate states for publication.
pub struct Checked {
    batch: Batch,
    social: Archive,
    registry: Registry,
    next: Frontier,
}

impl Checked {
    /// The validated batch.
    pub fn batch(&self) -> &Batch {
        &self.batch
    }
    /// The frontier this batch establishes once published.
    pub fn next(&self) -> Frontier {
        self.next
    }
}

/// The real application pair: the social evidence archive plus the room
/// registry that reads committed control and mature awards from it.
pub struct Application {
    social: Archive,
    registry: Registry,
    frontier: Frontier,
}

fn control_of(social: &Archive, registry: &Registry, time: u64) -> [u8; 32] {
    registry
        .authority()
        .snapshot(&ControlView::new(social, time))
}

impl Application {
    /// The genesis pair: both states exactly as their stores pin them.
    pub fn genesis(social: Archive, registry: Registry) -> Self {
        let control = control_of(&social, &registry, 0);
        let value = sha256(
            b"vhalla/rooms/live-genesis/v1\0",
            &[&registry.digest(), social.root().as_bytes(), &control],
        );
        Self {
            frontier: Frontier {
                height: 0,
                value,
                registry: registry.digest(),
                social: *social.root().as_bytes(),
                control,
                time: 0,
            },
            social,
            registry,
        }
    }
    /// Resume from store-loaded states under a frontier reconstructed from
    /// the journal — the reopen path, where the states are already durable
    /// and only the in-memory frontier is rebuilt.
    fn resume(social: Archive, registry: Registry, frontier: Frontier) -> Self {
        Self {
            social,
            registry,
            frontier,
        }
    }
    /// The pinned frontier the next decided batch must extend.
    #[must_use]
    pub fn frontier(&self) -> Frontier {
        self.frontier
    }
    /// The current evidence archive.
    #[must_use]
    pub fn social(&self) -> &Archive {
        &self.social
    }
    /// The current room registry.
    #[must_use]
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Replays `evidence` + `records` against clones at the agreed clock:
    /// archive merge, deterministic award harvest, ordered room applies.
    fn replay(
        &self,
        time: u64,
        evidence: &[Vec<u8>],
        records: &[Vec<u8>],
    ) -> Result<(Archive, Registry), ApplyError> {
        let mut social = self.social.clone();
        let mut budget = Budget::new(evidence.len() * 2, evidence.iter().map(Vec::len).sum())
            .map_err(ApplyError::Ingest)?;
        for raw in evidence {
            social
                .ingest(raw, &mut budget)
                .map_err(ApplyError::Ingest)?;
        }
        let mut registry = self.registry.clone();
        let view = ControlView::new(&social, time);
        // Awards are derived, not commanded: every evidence record gets one
        // deterministic award attempt. A committed qualifying reaction
        // credits; a duplicate or non-qualifying record is a no-op — the
        // same inputs yield the same outcome on every validator.
        for raw in evidence {
            let record = vhalla_social::SignedRecord::decode(raw)
                .and_then(|r| r.verify())
                .map_err(ApplyError::Social)?;
            let _ = registry.award(&record, &view, time);
        }
        for raw in records {
            let record = vhalla_rooms::SignedRecord::decode(raw)
                .and_then(|r| r.verify())
                .map_err(ApplyError::Rooms)?;
            registry
                .apply(&record, &view, time)
                .map_err(ApplyError::Registry)?;
        }
        Ok((social, registry))
    }

    /// Builds a decided-candidate batch against the current frontier:
    /// replays, then fills in the claimed result digests.
    pub fn prepare(
        &self,
        time: u64,
        evidence: Vec<Vec<u8>>,
        records: Vec<Vec<u8>>,
    ) -> Result<Checked, ApplyError> {
        if evidence.len() > MAX_BATCH_ITEMS || records.len() > MAX_BATCH_ITEMS {
            return Err(ApplyError::Bounds);
        }
        let time = self.bound_time(time);
        let (social, registry) = self.replay(time, &evidence, &records)?;
        let batch = Batch {
            parent: self.frontier,
            time,
            evidence,
            records,
            result_registry: registry.digest(),
            result_social: *social.root().as_bytes(),
            result_control: control_of(&social, &registry, time),
        };
        if batch.encode().len() > MAX_BATCH_BYTES {
            return Err(ApplyError::Bounds);
        }
        let next = Frontier {
            height: self.frontier.height + 1,
            value: batch.value_id(),
            registry: batch.result_registry,
            social: batch.result_social,
            control: batch.result_control,
            time,
        };
        Ok(Checked {
            batch,
            social,
            registry,
            next,
        })
    }

    /// Validates a proposed batch: exact parent frontier, full replay, and
    /// the claimed post-state digests must equal the replayed ones.
    pub fn validate(&self, batch: &Batch) -> Result<Checked, ApplyError> {
        if batch.parent != self.frontier {
            return Err(ApplyError::Parent);
        }
        if batch.evidence.len() > MAX_BATCH_ITEMS || batch.records.len() > MAX_BATCH_ITEMS {
            return Err(ApplyError::Bounds);
        }
        if batch.time != self.bound_time(batch.time) {
            return Err(ApplyError::Clock);
        }
        let (social, registry) = self.replay(batch.time, &batch.evidence, &batch.records)?;
        if registry.digest() != batch.result_registry
            || *social.root().as_bytes() != batch.result_social
            || control_of(&social, &registry, batch.time) != batch.result_control
        {
            return Err(ApplyError::Result);
        }
        Ok(Checked {
            batch: batch.clone(),
            social,
            registry,
            next: Frontier {
                height: self.frontier.height + 1,
                value: batch.value_id(),
                registry: batch.result_registry,
                social: batch.result_social,
                control: batch.result_control,
                time: batch.time,
            },
        })
    }

    /// The committed-clock window for the next batch. The genesis frontier
    /// carries `time: 0` — before the anchor any clock is admitted (the first
    /// proposer is as trusted as the genesis inputs); afterwards the clock is
    /// monotonic and advances at most `MAX_TIME_DRIFT` per height.
    fn bound_time(&self, time: u64) -> u64 {
        if self.frontier.time == 0 {
            return time;
        }
        time.clamp(
            self.frontier.time,
            self.frontier.time.saturating_add(MAX_TIME_DRIFT),
        )
    }

    /// Installs the replayed states and their frontier. Infallible: the
    /// states were already validated and durably published by the caller.
    pub fn apply_locally(&mut self, checked: Checked) {
        self.social = checked.social;
        self.registry = checked.registry;
        self.frontier = checked.next;
    }
}

/// Whether the live states already reflect this batch's claimed results —
/// the replay skip check. `result_control` is implied: it is a pure
/// function of the registry authority and archive the other two digests pin.
fn reflected(app: &Application, batch: &Batch) -> bool {
    app.registry.digest() == batch.result_registry
        && *app.social.root().as_bytes() == batch.result_social
}

/// The engine side of the channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineMsg {
    /// Commit acknowledgement for a height — only after the durable pin
    /// recorded it and the application state advanced (or provably already
    /// held it).
    CommitAck {
        /// The consensus height acknowledged.
        height: u64,
    },
    /// `Finalized` reply carrying the next height to start.
    NextHeightReply {
        /// The height the engine should start next.
        height: u64,
    },
}

/// Bounded record of emitted engine messages.
#[derive(Debug, Default)]
pub struct EngineSink {
    /// Every message sent, in send order.
    pub sent: Vec<EngineMsg>,
}

impl EngineSink {
    /// Records an emitted engine message.
    pub fn send(&mut self, msg: EngineMsg) {
        self.sent.push(msg);
    }
}

/// A decided/finalized certificate surface as the adapter consumes it. The
/// certificate bytes remain opaque here — verification parity was qualified
/// by the earlier receipt spikes.
#[derive(Debug, Clone)]
pub struct CommitCertificate {
    /// Canonical certificate bytes, stored verbatim in the bundle.
    pub bytes: Vec<u8>,
    /// The `Batch::value_id` the certificate decides.
    pub value_commitment: [u8; 32],
    /// Consensus height of the decision.
    pub height: u64,
}

/// What a decided/finalized message concluded with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecidedOutcome {
    /// Durable and applied; the reply was emitted.
    Acked,
    /// Rejected: unknown value, replay failure, equivocation at a committed
    /// height, height gap, or pin conflict. Nothing was emitted.
    Rejected,
    /// The durable write is uncertain or failed; nothing was emitted and the
    /// adapter must be restarted and reconciled.
    Withheld,
}

/// The genesis inputs both durable stores and the empty journal are
/// seeded from. `archive` carries the committed social fixture; the
/// registry is derived as `Registry::new`.
#[derive(Clone)]
pub struct Genesis {
    /// Directory identity the registry is pinned to.
    pub directory: DirectoryId,
    /// Shared realm.
    pub realm: RealmId,
    /// Admitted directory policy.
    pub policy: DirectoryPolicy,
    /// Eligible award-source owners.
    pub eligible: Vec<OwnerId>,
    /// Social archive bounds for store creation/open.
    pub limits: Limits,
    /// The committed genesis evidence set.
    pub archive: Archive,
}

impl Genesis {
    /// The fresh genesis registry every node's rooms store starts from.
    pub fn registry(&self) -> Result<Registry, RegistryError> {
        Registry::new(self.directory, self.realm, self.policy, &self.eligible)
    }
}

/// The adapter: engine channel → real application replay → durable journal
/// → durable snapshot stores → in-memory apply → ack.
#[cfg(unix)]
pub struct Adapter<S: Store> {
    journal: Journal<S>,
    app: Application,
    social: vhalla_social_store::Store,
    rooms: vhalla_rooms_store::Store,
    /// Full batches held pending commit, keyed by `value_id`.
    pending: BTreeMap<[u8; 32], Batch>,
}

#[cfg(unix)]
impl Adapter<FsStore> {
    /// Opens on a real filesystem journal and both real snapshot stores.
    pub fn open(dir: impl Into<PathBuf>, genesis: &Genesis) -> Result<Self, AdapterError> {
        Self::open_with(dir, FsStore, genesis)
    }
}

#[cfg(unix)]
impl<S: Store> Adapter<S> {
    /// Opens `journal/` plus the `social/` and `rooms/` snapshot stores
    /// under `dir`, then rebuilds the exact application state the journal
    /// pin records. On first open the genesis archive is published into the
    /// fresh social store and the fresh rooms store pins `Registry::new`;
    /// on reopen both stores load their pinned states and every retained
    /// committed batch is reconciled in height order — already-reflected
    /// batches are skipped by digest comparison, unreflected ones are
    /// re-validated, re-published and re-applied. Any divergence between
    /// journal order and store state fails closed.
    pub fn open_with(
        dir: impl Into<PathBuf>,
        store: S,
        genesis: &Genesis,
    ) -> Result<Self, AdapterError> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        let genesis_registry = genesis
            .registry()
            .map_err(|e| AdapterError::Apply(ApplyError::Registry(e)))?;
        let genesis_app = Application::genesis(genesis.archive.clone(), genesis_registry);
        let journal = Journal::with_genesis(
            dir.join("journal"),
            store,
            genesis_app.frontier().commitment(),
        );
        let recovered = journal.recover()?;

        let social_dir = dir.join("social");
        let mut social = if social_dir.exists() {
            vhalla_social_store::Store::open(&social_dir, genesis.realm, genesis.limits, None)?
        } else {
            let mut store =
                vhalla_social_store::Store::create(&social_dir, genesis.realm, genesis.limits)?;
            store.commit(genesis.archive.clone(), store.pin())?;
            store
        };
        if social.recovery_required()? {
            social.recover()?;
        }

        let rooms_dir = dir.join("rooms");
        let mut rooms = if rooms_dir.exists() {
            vhalla_rooms_store::Store::open(&rooms_dir, None)?
        } else {
            vhalla_rooms_store::Store::create(
                &rooms_dir,
                genesis.directory,
                genesis.realm,
                genesis.policy,
                &genesis.eligible,
            )?
        };
        if rooms.recovery_required()? {
            rooms.recover()?;
        }

        // Locate the applied prefix: the rooms store trails the journal by at
        // most the in-flight publish (social commits before rooms), so find
        // the unique height whose claimed digests match the stored states.
        // Store state ahead of the journal, or matching no decided batch at
        // all, is corruption — fail closed.
        let batch_at = |height: u64| -> Result<Batch, AdapterError> {
            let id = journal
                .at_height(height)?
                .ok_or(AdapterError::MissingHeight(height))?;
            let bundle = journal
                .bundle(id)?
                .ok_or(AdapterError::MissingHeight(height))?;
            Batch::decode(bundle.field(3).ok_or(AdapterError::Corrupt)?)
                .map_err(AdapterError::Apply)
        };
        let mut rooms_height = 0u64;
        let mut social_height = 0u64;
        for height in (1..=recovered.pin.height).rev() {
            let batch = batch_at(height)?;
            if rooms_height == 0 && rooms.registry().digest() == batch.result_registry {
                rooms_height = height;
            }
            if social_height == 0 && *social.archive().root().as_bytes() == batch.result_social {
                social_height = height;
            }
            if rooms_height != 0 && social_height != 0 {
                break;
            }
        }
        // Unmatched nonzero stores are only honest at genesis.
        if rooms_height == 0
            && recovered.pin.height > 0
            && rooms.registry().digest() != genesis_app.registry().digest()
        {
            return Err(AdapterError::Corrupt);
        }
        if social_height == 0
            && recovered.pin.height > 0
            && social.archive().root() != genesis_app.social().root()
        {
            return Err(AdapterError::Corrupt);
        }
        // The publication order bounds the skew: rooms <= social <= rooms + 1.
        if social_height < rooms_height || social_height > rooms_height + 1 {
            return Err(AdapterError::Corrupt);
        }
        // The frontier the next undecided batch must extend: rebuilt from the
        // batch that produced the stored rooms state — its claimed result
        // fields were consensus-verified at commit.
        let frontier = if rooms_height == 0 {
            genesis_app.frontier()
        } else {
            let batch = batch_at(rooms_height)?;
            Frontier {
                height: rooms_height,
                value: batch.value_id(),
                registry: batch.result_registry,
                social: batch.result_social,
                control: batch.result_control,
                time: batch.time,
            }
        };
        let mut app =
            Application::resume(social.archive().clone(), rooms.registry().clone(), frontier);
        for height in rooms_height + 1..=recovered.pin.height {
            let batch = batch_at(height)?;
            if reflected(&app, &batch) {
                continue;
            }
            let checked = app.validate(&batch).map_err(AdapterError::Apply)?;
            Self::publish(&mut social, &mut rooms, &checked)?;
            app.apply_locally(checked);
        }
        // The journal's last pinned next-frontier is the authority on the
        // final state: rebuilt state must reproduce it exactly.
        if recovered.pin.next != app.frontier().commitment() {
            return Err(AdapterError::Corrupt);
        }
        Ok(Adapter {
            journal,
            app,
            social,
            rooms,
            pending: BTreeMap::new(),
        })
    }

    /// Publishes the validated candidate states — social first, then rooms,
    /// so the rooms store can never reflect a batch whose evidence is not
    /// yet durable.
    fn publish(
        social: &mut vhalla_social_store::Store,
        rooms: &mut vhalla_rooms_store::Store,
        checked: &Checked,
    ) -> Result<(), AdapterError> {
        social.commit(checked.social.clone(), social.pin())?;
        rooms.commit(checked.registry.clone(), rooms.pin())?;
        Ok(())
    }

    /// The complete durable frontier the application currently occupies.
    pub fn frontier(&self) -> Frontier {
        self.app.frontier()
    }

    /// The rebuilt application, for state inspection in tests.
    pub fn application(&self) -> &Application {
        &self.app
    }

    /// Validates a proposed batch against the pinned frontier — the
    /// engine's vote verdict path.
    pub fn validate(&self, batch: &Batch) -> Result<Checked, ApplyError> {
        self.app.validate(batch)
    }

    /// Journal directory.
    pub fn dir(&self) -> &Path {
        self.journal.dir()
    }

    /// The journal's recovery report.
    pub fn recover(&self) -> Result<vhalla_journal::Recovered, JournalError> {
        self.journal.recover()
    }

    /// Registers a full batch the engine holds, keyed by its value
    /// commitment.
    pub fn hold(&mut self, batch: Batch) {
        self.pending.insert(batch.value_id(), batch);
    }

    /// Whether durable evidence already commits `certificate.height` to the
    /// same decided value.
    fn committed_at(&self, certificate: &CommitCertificate) -> Result<Option<bool>, JournalError> {
        let pin = self.journal.recover()?.pin;
        if certificate.height > pin.height {
            return Ok(None);
        }
        let Some(id) = self.journal.at_height(certificate.height)? else {
            return Ok(Some(false));
        };
        let bundle = self.journal.bundle(id)?;
        let bound = bundle.and_then(|b| b.field(4).map(|v| v.to_vec()));
        Ok(Some(
            bound.as_deref() == Some(&certificate.value_commitment[..]),
        ))
    }

    /// A journaled height whose publication/apply may have been cut short:
    /// re-derive from the retained batch, re-publish (idempotent — an exact
    /// already-published store candidate is a readback) and apply.
    fn reconcile_committed(&mut self, certificate: &CommitCertificate) -> DecidedOutcome {
        // Heights strictly below the frontier were applied in order already.
        if certificate.height <= self.app.frontier().height {
            return DecidedOutcome::Acked;
        }
        let batch = self
            .journal
            .at_height(certificate.height)
            .ok()
            .flatten()
            .and_then(|id| self.journal.bundle(id).ok().flatten())
            .and_then(|bundle| bundle.field(3).map(|raw| raw.to_vec()))
            .and_then(|raw| Batch::decode(&raw).ok());
        let Some(batch) = batch else {
            return DecidedOutcome::Withheld;
        };
        if reflected(&self.app, &batch) {
            return DecidedOutcome::Acked;
        }
        let checked = match self.app.validate(&batch) {
            Ok(checked) => checked,
            // A retained decided batch that no longer validates means durable
            // divergence — withhold rather than acknowledge a lie.
            Err(_) => return DecidedOutcome::Withheld,
        };
        match Self::publish(&mut self.social, &mut self.rooms, &checked) {
            Ok(()) => {
                self.app.apply_locally(checked);
                DecidedOutcome::Acked
            }
            Err(_) => DecidedOutcome::Withheld,
        }
    }

    /// The shared decide path, exposed to the certificate-translation spike
    /// crate that verifies real engine certificates upstream of this.
    pub fn decide(&mut self, certificate: &CommitCertificate) -> DecidedOutcome {
        match self.committed_at(certificate) {
            Ok(Some(true)) => return self.reconcile_committed(certificate),
            Ok(Some(false)) => return DecidedOutcome::Rejected,
            Ok(None) => {}
            Err(_) => return DecidedOutcome::Withheld,
        }
        let Some(batch) = self.pending.get(&certificate.value_commitment) else {
            return DecidedOutcome::Rejected;
        };
        // Real replay against the complete pinned frontier — a certificate
        // never substitutes for this check.
        let checked = match self.app.validate(batch) {
            Ok(checked) => checked,
            Err(_) => return DecidedOutcome::Rejected,
        };
        let next = checked.next();
        let bundle = match Bundle::new(BundleParts {
            certificate: certificate.bytes.clone(),
            predecessor: self.app.frontier().commitment(),
            next: next.commitment(),
            batch: batch.encode(),
            value: certificate.value_commitment.to_vec(),
            configuration: self.app.registry().policy().id().as_bytes().to_vec(),
            control_record: next.control.to_vec(),
            debit_marker: next.value.to_vec(),
            height: certificate.height,
        }) {
            Ok(bundle) => bundle,
            Err(_) => return DecidedOutcome::Rejected,
        };
        match self.journal.commit(&bundle) {
            Ok(Outcome::Committed) | Ok(Outcome::AlreadyCommitted) => {}
            Err(JournalError::Conflict { .. }) => return DecidedOutcome::Rejected,
            Err(_) => return DecidedOutcome::Withheld,
        }
        // The durable pin advanced; now publish the snapshots and advance
        // memory. A failure leaves the journal ahead of the stores — the
        // redelivery/restart reconcile path converges it.
        match Self::publish(&mut self.social, &mut self.rooms, &checked) {
            Ok(()) => {
                self.app.apply_locally(checked);
                DecidedOutcome::Acked
            }
            Err(_) => DecidedOutcome::Withheld,
        }
    }

    /// Handles `Decided`: replay, durable commit, durable publish, apply,
    /// then acknowledge.
    pub fn on_decided(
        &mut self,
        engine: &mut EngineSink,
        certificate: &CommitCertificate,
    ) -> DecidedOutcome {
        match self.decide(certificate) {
            DecidedOutcome::Acked => {
                engine.send(EngineMsg::CommitAck {
                    height: certificate.height,
                });
                DecidedOutcome::Acked
            }
            other => other,
        }
    }

    /// Handles `Finalized`: the same durable path, then the next-height
    /// reply.
    pub fn on_finalized(
        &mut self,
        engine: &mut EngineSink,
        certificate: &CommitCertificate,
    ) -> DecidedOutcome {
        match self.decide(certificate) {
            DecidedOutcome::Acked => {
                engine.send(EngineMsg::NextHeightReply {
                    height: certificate.height + 1,
                });
                DecidedOutcome::Acked
            }
            other => other,
        }
    }

    /// Absorb one committed bundle fetched from a peer into this replica —
    /// the data plane for value availability beyond the deciding quorum.
    ///
    /// `verify` is the caller's certificate check: certificate formats are
    /// engine-owned, so this crate accepts a hook. It must confirm the
    /// certificate's quorum over the validator set for `bundle.height()`.
    /// A bundle that fails verification, binds a different value than its
    /// batch, or decodes badly is rejected before any durable write;
    /// otherwise the batch joins `pending` and the shared `decide` path
    /// replays, journals, publishes and applies it exactly like a local
    /// decision — the journaled bundle is byte-identical to the absorbed
    /// one, since every field is deterministic.
    ///
    /// Bundles must be absorbed in height order: a batch whose parent
    /// frontier is not yet applied fails replay and is rejected — fetch
    /// the earlier bundles first.
    pub fn absorb<V>(&mut self, bundle: &Bundle, verify: V) -> DecidedOutcome
    where
        V: FnOnce(&[u8], u64, &[u8; 32]) -> bool,
    {
        let (Some(cert_raw), Some(batch_raw), Some(value)) =
            (bundle.field(0), bundle.field(3), bundle.field(4))
        else {
            return DecidedOutcome::Rejected;
        };
        let Ok(batch) = Batch::decode(batch_raw) else {
            return DecidedOutcome::Rejected;
        };
        let Ok(value_commitment) = <[u8; 32]>::try_from(value) else {
            return DecidedOutcome::Rejected;
        };
        if value_commitment != batch.value_id() {
            return DecidedOutcome::Rejected;
        }
        if !verify(cert_raw, bundle.height(), &value_commitment) {
            return DecidedOutcome::Rejected;
        }
        self.hold(batch);
        self.decide(&CommitCertificate {
            bytes: cert_raw.to_vec(),
            value_commitment,
            height: bundle.height(),
        })
    }
}

/// Failures of the batch/application layer.
#[derive(Debug)]
pub enum ApplyError {
    /// Batch or frontier bytes did not decode within bounds.
    Decode,
    /// The batch's parent is not the pinned frontier.
    Parent,
    /// The replayed result digests differ from the batch's claims.
    Result,
    /// Evidence ingest into the candidate archive failed.
    Ingest(vhalla_social::Error),
    /// A social record failed canonical decode/verify.
    Social(vhalla_social::Error),
    /// A room record failed canonical decode/verify.
    Rooms(vhalla_rooms::Error),
    /// `Registry::apply` denied a room record.
    Registry(RegistryError),
    /// Batch exceeds item or byte bounds.
    Bounds,
    /// The batch's clock regressed the committed frontier or advanced more
    /// than `MAX_TIME_DRIFT`.
    Clock,
}

/// Errors opening, publishing or rebuilding the adapter.
#[cfg(unix)]
#[derive(Debug)]
pub enum AdapterError {
    /// Journal operation failed.
    Journal(JournalError),
    /// Application replay or construction failed.
    Apply(ApplyError),
    /// The social snapshot store failed.
    SocialStore(vhalla_social_store::Error),
    /// The rooms snapshot store failed.
    RoomsStore(vhalla_rooms_store::Error),
    /// A committed height lacked its retained bundle.
    MissingHeight(u64),
    /// Journal and store state diverged, or genesis mismatched.
    Corrupt,
    /// An I/O error creating the adapter directory.
    Io(std::io::Error),
}

#[cfg(unix)]
impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdapterError::Journal(e) => write!(f, "journal: {e}"),
            AdapterError::Apply(e) => write!(f, "application: {e:?}"),
            AdapterError::SocialStore(e) => write!(f, "social store: {e}"),
            AdapterError::RoomsStore(e) => write!(f, "rooms store: {e}"),
            AdapterError::MissingHeight(h) => {
                write!(f, "missing retained bundle at height {h}")
            }
            AdapterError::Corrupt => write!(f, "journal/store state divergence"),
            AdapterError::Io(e) => write!(f, "io: {e}"),
        }
    }
}

#[cfg(unix)]
impl std::error::Error for AdapterError {}

#[cfg(unix)]
impl From<JournalError> for AdapterError {
    fn from(e: JournalError) -> Self {
        AdapterError::Journal(e)
    }
}
#[cfg(unix)]
impl From<vhalla_social_store::Error> for AdapterError {
    fn from(e: vhalla_social_store::Error) -> Self {
        AdapterError::SocialStore(e)
    }
}
#[cfg(unix)]
impl From<vhalla_rooms_store::Error> for AdapterError {
    fn from(e: vhalla_rooms_store::Error) -> Self {
        AdapterError::RoomsStore(e)
    }
}
#[cfg(unix)]
impl From<std::io::Error> for AdapterError {
    fn from(e: std::io::Error) -> Self {
        AdapterError::Io(e)
    }
}
