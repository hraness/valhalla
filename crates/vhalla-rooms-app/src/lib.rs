#![forbid(unsafe_code)]
//! Renderer-agnostic room-directory service.
//!
//! A `Service` is a read replica of a hosted `vhalla-rooms-node`: it
//! absorbs committed journal bundles out of the node's home (immutable,
//! content-addressed files safe to read while the node runs) into its own
//! stores under `replica_home`, verifies every certificate against the
//! trusted validator sets, and answers typed `Screen` projections.
//! Submissions are `*.body` drops into the node's `intake/` — the node
//! assembles the batch against its own frontier, so the service never
//! fabricates parent or result claims. Signing stays outside: callers
//! pass canonical signed record bytes; no private key enters the service.
//!
//! The projection types (`Screen`, `Projection`, `RoomRow`, `Pending`,
//! `PendingState`, `Error`) are platform-neutral so browser and native
//! renderers share them; the replica machinery is unix-only.

use vhalla_rooms::registry::Account;
use vhalla_social::OwnerId;

#[cfg(unix)]
use std::collections::BTreeMap;
#[cfg(unix)]
use std::path::{Path, PathBuf};

#[cfg(unix)]
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use vhalla_core::RealmId;
#[cfg(unix)]
use vhalla_journal::{Bundle, FsStore, Store as _};
#[cfg(unix)]
use vhalla_rooms::registry::{DirectoryPolicy, Registry};
#[cfg(unix)]
use vhalla_rooms::{Body, DirectoryId, RoomGenesisId, RoomRecordId, SignedRecord, Slug};
#[cfg(unix)]
use vhalla_rooms_consensus::{Adapter, BatchBody, Genesis};
#[cfg(unix)]
use vhalla_rooms_node::PublicKey;
#[cfg(unix)]
use vhalla_rooms_node::{
    cert::verify_canonical_certificate, RoomValidator, RoomValidatorSet, RoomValueId,
};
#[cfg(unix)]
use vhalla_social::archive::{Archive, Limits};

/// The shared genesis plus trust configuration — the same fields the
/// node file carries, so one JSON document serves a validator and every
/// replica reader (`serde` ignores the node-only keys).
#[cfg(unix)]
#[derive(Deserialize)]
pub struct ServiceConfig {
    /// Shared realm, 32 lowercase hex characters.
    pub realm: String,
    /// Shared directory identifier, 64 hex characters.
    pub directory: String,
    /// The admitted directory policy.
    pub policy: PolicyJson,
    /// Eligible award-source owners, 64 hex each.
    #[serde(default)]
    pub eligible: Vec<String>,
    /// The shared archive bounds.
    pub limits: LimitsJson,
    /// Validator activations: `{from, key, power}` entries.
    pub validators: Vec<ValidatorJson>,
}

/// Policy fields as they appear in the JSON config.
#[cfg(unix)]
#[derive(Deserialize)]
pub struct PolicyJson {
    /// Base slot cost before the quadratic factor.
    pub base_cost: u64,
    /// Rolling creation window, seconds.
    pub window_seconds: u64,
    /// Maximum creations per window.
    pub max_in_window: u16,
    /// Award support epoch, seconds.
    pub support_epoch_seconds: u64,
    /// Lifetime finalized rooms per owner.
    pub max_lifetime_rooms: u32,
}

/// Archive-limit fields as they appear in the JSON config.
#[cfg(unix)]
#[derive(Deserialize)]
pub struct LimitsJson {
    /// Total retained records.
    pub records: usize,
    /// Reserved control capacity before global closure.
    pub control_reserve: usize,
    /// Per-owner data bound.
    pub data_per_owner: usize,
    /// Per-writer data bound.
    pub data_per_writer: usize,
    /// Per-owner control bound.
    pub control_per_owner: usize,
    /// Pending-record bound.
    pub pending: usize,
    /// Per-signer pending bound.
    pub pending_per_signer: usize,
}

/// One validator activation entry in the JSON config.
#[cfg(unix)]
#[derive(Deserialize)]
pub struct ValidatorJson {
    /// Activation height.
    pub from: u64,
    /// Ed25519 public key, 64 hex characters.
    pub key: String,
    /// Voting power.
    pub power: u64,
}

/// Closed service errors.
#[derive(Debug)]
pub enum Error {
    /// A config, hex, or JSON value failed to parse or verify.
    Config(String),
    /// A filesystem or durable-store operation failed.
    Io(String),
    /// The requested screen or value is outside the bounded contract.
    Bounds,
    /// The signed record is invalid or denies under the current replica.
    Record(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(e) => write!(f, "config: {e}"),
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Bounds => write!(f, "bound exceeded"),
            Self::Record(e) => write!(f, "record: {e}"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(unix)]
fn hex32(text: &str) -> Result<[u8; 32], Error> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::Config(format!(
            "expected 64 hex characters: {text:?}"
        )));
    }
    let mut out = [0; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
            .map_err(|e| Error::Config(e.to_string()))?;
    }
    Ok(out)
}

#[cfg(unix)]
fn hex128(text: &str) -> Result<u128, Error> {
    if text.len() != 32 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::Config(format!(
            "expected 32 hex characters: {text:?}"
        )));
    }
    u128::from_str_radix(text, 16).map_err(|e| Error::Config(e.to_string()))
}

#[cfg(unix)]
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(unix)]
impl ServiceConfig {
    /// Parses the shared config; unknown keys (the node's own fields) are
    /// ignored so one file serves every role.
    pub fn parse(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() > 64 * 1024 {
            return Err(Error::Config("config exceeds 64KiB".into()));
        }
        serde_json::from_slice(raw).map_err(|e| Error::Config(e.to_string()))
    }
    /// The shared realm.
    pub fn realm_id(&self) -> Result<RealmId, Error> {
        Ok(RealmId(hex128(&self.realm)?))
    }
    /// The shared archive limits.
    pub fn archive_limits(&self) -> Limits {
        Limits {
            records: self.limits.records,
            control_reserve: self.limits.control_reserve,
            data_per_owner: self.limits.data_per_owner,
            data_per_writer: self.limits.data_per_writer,
            control_per_owner: self.limits.control_per_owner,
            pending: self.limits.pending,
            pending_per_signer: self.limits.pending_per_signer,
        }
    }
    /// The admitted directory policy.
    pub fn directory_policy(&self) -> DirectoryPolicy {
        DirectoryPolicy {
            base_cost: self.policy.base_cost,
            window_seconds: self.policy.window_seconds,
            max_in_window: self.policy.max_in_window,
            support_epoch_seconds: self.policy.support_epoch_seconds,
            max_lifetime_rooms: self.policy.max_lifetime_rooms,
        }
    }
    /// Activation height → trusted validator set, for certificate checks.
    pub fn validator_sets(&self) -> Result<BTreeMap<u64, RoomValidatorSet>, Error> {
        let mut map: BTreeMap<u64, Vec<RoomValidator>> = BTreeMap::new();
        for entry in &self.validators {
            let key = PublicKey::from_bytes(hex32(&entry.key)?)
                .map_err(|e| Error::Config(format!("validator key: {e}")))?;
            map.entry(entry.from)
                .or_default()
                .push(RoomValidator::new(key, entry.power));
        }
        if map.is_empty() {
            return Err(Error::Config("config names no validators".into()));
        }
        Ok(map
            .into_iter()
            .map(|(from, set)| (from, RoomValidatorSet::new(set)))
            .collect())
    }
    /// The trusted set active at `height`, or `None` when no set has
    /// activated yet.
    pub fn validators_at(
        sets: &BTreeMap<u64, RoomValidatorSet>,
        height: u64,
    ) -> Option<&RoomValidatorSet> {
        sets.range(..=height).next_back().map(|(_, set)| set)
    }
}

/// A typed view the UI renders — no raw registry access crosses the
/// service boundary.
#[derive(Clone, Debug)]
pub enum Screen {
    /// Bounded literal directory scan; empty query lists everything.
    Directory {
        /// Literal terms, ASCII-folded AND semantics (the registry's own).
        query: String,
    },
    /// One room by canonical slug.
    Room {
        /// The slug to resolve.
        slug: String,
    },
    /// One owner's account and open rooms.
    Account {
        /// The owner to inspect.
        owner: OwnerId,
    },
}

/// Where a locally dropped submission stands against committed state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PendingState {
    /// The body file still waits in the node's intake directory.
    Queued,
    /// The node consumed the drop; the value is in its pending queue or
    /// in flight toward a decision.
    Submitted,
    /// The registry cites this exact record.
    Committed,
    /// A different record claimed the slug or moved the room head first.
    Collision,
    /// The node's intake rejected the drop (decode or prepare failure).
    Rejected,
}

/// One locally submitted body and its current resolution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pending {
    /// The submission marker name (hex record id of the effect record).
    pub name: String,
    /// The slug the submission names, when it names one.
    pub slug: Option<String>,
    /// Current resolution against committed state.
    pub state: PendingState,
}

/// One directory row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoomRow {
    /// Canonical slug.
    pub slug: String,
    /// Owning owner id, hex.
    pub owner: String,
    /// Finalizing agent id, hex.
    pub agent: String,
    /// Current description text.
    pub description: String,
    /// Slot the creation paid for.
    pub slot: u32,
    /// Charge paid.
    pub charge: u64,
    /// Whether the room is a tombstone (retained, out of search).
    pub archived: bool,
    /// Creation record id, hex — the room's source proof key.
    pub record: String,
    /// Current revision-chain head, hex.
    pub head: String,
    /// Number of applied revisions.
    pub revisions: usize,
    /// Creation time.
    pub created_at: u64,
}

/// The rendered projection for one screen.
#[derive(Clone, Debug)]
pub struct Projection {
    /// The directory rows the screen shows.
    pub rooms: Vec<RoomRow>,
    /// Account summary when the screen names an owner.
    pub account: Option<Account>,
    /// Quoted next slot and charge for `Account` screens.
    pub quote: Option<(u32, u64)>,
    /// Whether the scan hit a bound before exhausting the directory.
    pub partial: bool,
    /// Registry revision the projection reflects.
    pub revision: u64,
    /// Committed consensus height the replica has absorbed.
    pub height: u64,
    /// Local submissions and their resolutions.
    pub pending: Vec<Pending>,
}

/// Everything a create-intent form needs from committed replica state.
/// Produced by `Service::create_context`; the signer assembles the
/// `CreationIntent` from these typed fields plus the form's answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateContext {
    /// The shared directory id.
    pub directory: String,
    /// The shared realm, 32 lowercase hex characters.
    pub realm: String,
    /// The admitted directory policy id, hex.
    pub policy: String,
    /// Quoted slot for the owner's next room.
    pub slot: u32,
    /// Quoted charge for the owner's next room.
    pub charge: u64,
    /// The owner's accepted social head, hex — the create's basis.
    pub social_control: String,
    /// The owner's room-control chain head, hex, when a grant is
    /// already committed; a first room carries the grant in-body.
    pub room_head: Option<String>,
    /// The next room-control sequence number.
    pub sequence: u64,
    /// Unspent credit: `earned - spent`.
    pub balance: u64,
}

/// Everything an update form needs for one committed room.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateContext {
    /// The shared directory id.
    pub directory: String,
    /// The shared realm, 32 lowercase hex characters.
    pub realm: String,
    /// The room's genesis id, hex.
    pub genesis: String,
    /// The room's current revision head, hex.
    pub previous: String,
    /// The room's owner id, hex.
    pub owner: String,
    /// The owner's accepted social head, hex — the update's basis.
    pub social_control: String,
}

/// A durable pending marker under `replica_home/pending/`.
#[derive(Serialize, Deserialize)]
#[cfg(unix)]
struct Marker {
    /// Effect record id, hex.
    record: String,
    /// Effect record kind: "create" or "update".
    kind: String,
    /// Slug the submission names — creates only.
    slug: Option<String>,
    /// Room genesis the update binds, hex — updates only.
    genesis: Option<String>,
    /// The room head the update chained from, hex — updates only.
    base: Option<String>,
    /// The intake filename stem used for the drop.
    intake: String,
}

/// The room-directory service: replica state plus the intake contract.
#[cfg(unix)]
pub struct Service {
    adapter: Adapter<vhalla_journal::FsStore>,
    /// `<node_home>/app/journal` — read-only source of committed bundles.
    journal_dir: PathBuf,
    /// `<node_home>/intake` — the submission drop point.
    intake_dir: PathBuf,
    /// `<replica_home>/pending` — local submission markers.
    pending_dir: PathBuf,
    /// Activation-height → validator set, for certificate checks.
    validators: BTreeMap<u64, RoomValidatorSet>,
}

#[cfg(unix)]
impl Service {
    /// Opens the replica under `replica_home`, seeding genesis from the
    /// committed `social_store` snapshot (opened under the configured
    /// limits, then released). `node_home` names the running validator's
    /// home: its `app/journal` is the committed source and its `intake/`
    /// is the submission drop. Neither is locked by this process.
    pub fn open(
        social_store: &Path,
        node_home: &Path,
        replica_home: &Path,
        config: &ServiceConfig,
    ) -> Result<Self, Error> {
        let realm = config.realm_id()?;
        let limits = config.archive_limits();
        // The replica reads the committed snapshot under a shared hold:
        // a concurrent owner command's exclusive lock is waited out, not
        // raced — startup no longer dies on `Busy` mid-submission.
        let archive: Archive = vhalla_social_store::read_archive(social_store, realm, limits)
            .map_err(|e| match e {
                vhalla_social_store::Error::RecoveryRequired => {
                    Error::Io("social store requires explicit social recover first".into())
                }
                e => Error::Io(format!("{e}")),
            })?;
        let genesis = Genesis {
            directory: DirectoryId::from_bytes(hex32(&config.directory)?),
            realm,
            policy: config.directory_policy(),
            eligible: config
                .eligible
                .iter()
                .map(|id| hex32(id).map(OwnerId::from_bytes))
                .collect::<Result<_, _>>()?,
            limits,
            archive,
        };
        let adapter = Adapter::open(replica_home, &genesis)
            .map_err(|e| Error::Io(format!("replica: {e:?}")))?;
        let pending_dir = replica_home.join("pending");
        std::fs::create_dir_all(&pending_dir).map_err(|e| Error::Io(e.to_string()))?;
        Ok(Self {
            adapter,
            journal_dir: node_home.join("app").join("journal"),
            intake_dir: node_home.join("intake"),
            pending_dir,
            validators: config.validator_sets()?,
        })
    }

    /// The replica's committed height.
    pub fn height(&self) -> u64 {
        self.adapter.frontier().height
    }

    /// The replica registry — read-only projections use it; the service
    /// never mutates it outside `sync`.
    pub fn registry(&self) -> &Registry {
        self.adapter.application().registry()
    }

    /// The replica's committed social archive — read-only intent context.
    pub fn archive(&self) -> &Archive {
        self.adapter.application().social()
    }

    /// The committed context a create form needs: the current quote, the
    /// owner's accepted social head (checked against `key`), and the
    /// room-control chain head and sequence for grant synthesis.
    pub fn create_context(
        &self,
        owner: OwnerId,
        key: [u8; 32],
        now: u64,
    ) -> Result<CreateContext, Error> {
        let social_control = self.owner_head(owner, key, now)?;
        let registry = self.registry();
        let (slot, charge) = registry
            .quote(owner)
            .map_err(|e| Error::Record(format!("quote: {e:?}")))?;
        let account = registry.account(owner);
        Ok(CreateContext {
            directory: hex(registry.directory().as_bytes()),
            realm: format!("{:032x}", registry.realm().0),
            policy: hex(registry.policy().id().as_bytes()),
            slot,
            charge,
            social_control: hex(social_control.as_bytes()),
            room_head: registry.authority().head(owner).map(|h| hex(h.as_bytes())),
            sequence: registry.authority().sequence(owner),
            balance: account.earned.saturating_sub(account.spent),
        })
    }

    /// The committed context an update form needs for `slug`: genesis,
    /// head and owner from the room, plus the owner's social head.
    pub fn update_context(
        &self,
        slug: &str,
        key: [u8; 32],
        now: u64,
    ) -> Result<UpdateContext, Error> {
        let room = self
            .registry()
            .room(&Slug::new(slug).map_err(|e| Error::Record(format!("slug: {e:?}")))?)
            .ok_or_else(|| Error::Record("no committed room by that slug".into()))?;
        let social_control = self.owner_head(room.owner(), key, now)?;
        Ok(UpdateContext {
            directory: hex(self.registry().directory().as_bytes()),
            realm: format!("{:032x}", self.registry().realm().0),
            genesis: hex(room.genesis().as_bytes()),
            previous: hex(room.head().as_bytes()),
            owner: hex(room.owner().as_bytes()),
            social_control: hex(social_control.as_bytes()),
        })
    }

    /// The owner's accepted social head under the agreed clock, checked
    /// against the key that must control it — the same admission the
    /// registry will apply to the signed record.
    fn owner_head(
        &self,
        owner: OwnerId,
        key: [u8; 32],
        now: u64,
    ) -> Result<vhalla_social::RecordId, Error> {
        let view = vhalla_social::control::ControlView::new(self.archive(), now);
        let status = view
            .owner(owner)
            .ok_or_else(|| Error::Record("owner missing from committed social state".into()))?;
        if status.frozen() || status.incomplete() || status.capacity_blocked() {
            return Err(Error::Record(
                "owner authority is frozen, incomplete or capacity-blocked".into(),
            ));
        }
        if status.key() != Some(key) {
            return Err(Error::Record(
                "key directory does not control that owner".into(),
            ));
        }
        status
            .head()
            .ok_or_else(|| Error::Record("owner has no accepted head".into()))
    }

    /// Absorbs every committed journal bundle past the replica frontier.
    /// Returns the committed height reached. A torn concurrent write —
    /// a marker whose bundle is not yet durable, or a partial file —
    /// simply bounds this sync; the next call retries it. Anything the
    /// certificate check or ordered replay rejects halts the replica
    /// closed, exactly as a voter would.
    pub fn sync(&mut self) -> Result<u64, Error> {
        let store = FsStore;
        let markers = store
            .list_height_markers(&self.journal_dir)
            .map_err(|e| Error::Io(format!("journal: {e:?}")))?;
        for height in markers {
            if height <= self.height() {
                continue;
            }
            let Ok(Some(id)) = store.read_height_marker(&self.journal_dir, height) else {
                break;
            };
            let Ok(bytes) = store.read_bundle(&self.journal_dir, id) else {
                break;
            };
            let Ok(bundle) = Bundle::decode(&bytes) else {
                break;
            };
            let Some(set) = ServiceConfig::validators_at(&self.validators, height) else {
                break;
            };
            let outcome = self.adapter.absorb(&bundle, |cert, h, value| {
                verify_canonical_certificate(cert, h, &RoomValueId(*value), set)
            });
            match outcome {
                vhalla_rooms_consensus::DecidedOutcome::Acked => {}
                _ => break,
            }
        }
        Ok(self.height())
    }

    /// Signs nothing, sends nothing: writes the canonical `*.body` drop
    /// into the node's intake and records a pending marker under the
    /// replica. Returns the marker name (the effect record's hex id).
    /// The body must hold at least one room record.
    pub fn submit_body(
        &mut self,
        time: u64,
        evidence: Vec<Vec<u8>>,
        records: Vec<Vec<u8>>,
    ) -> Result<String, Error> {
        let effect = effect(&records)?;
        let name = hex(effect.record.as_bytes());
        let intake = name.clone();
        let path = self.intake_dir.join(format!("{intake}.body"));
        std::fs::create_dir_all(&self.intake_dir).map_err(|e| Error::Io(e.to_string()))?;
        let body = BatchBody {
            time,
            evidence,
            records,
            eligible: None,
        };
        let tmp = path.with_extension("body.tmp");
        std::fs::write(&tmp, body.encode()).map_err(|e| Error::Io(e.to_string()))?;
        std::fs::rename(&tmp, &path).map_err(|e| Error::Io(e.to_string()))?;
        let marker = Marker {
            record: name.clone(),
            kind: effect.kind.to_owned(),
            slug: effect.slug,
            genesis: effect.genesis,
            base: effect.base,
            intake,
        };
        let marker_path = self.pending_dir.join(format!("{name}.json"));
        let raw = serde_json::to_vec(&marker).map_err(|e| Error::Io(e.to_string()))?;
        std::fs::write(&marker_path, raw).map_err(|e| Error::Io(e.to_string()))?;
        Ok(name)
    }

    /// Every local submission marker with its current resolution.
    pub fn pending(&self) -> Result<Vec<Pending>, Error> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(&self.pending_dir) else {
            return Ok(out);
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Ok(raw) = std::fs::read(&path) else {
                continue;
            };
            let Ok(marker) = serde_json::from_slice::<Marker>(&raw) else {
                continue;
            };
            out.push(Pending {
                name: marker.record.clone(),
                slug: marker.slug.clone().or_else(|| {
                    marker
                        .genesis
                        .as_deref()
                        .and_then(|g| hex32(g).ok())
                        .map(RoomGenesisId::from_bytes)
                        .and_then(|g| self.registry().room_by_genesis(g))
                        .map(|room| room.slug().as_str().to_owned())
                }),
                state: self.resolve(&marker),
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Resolves one marker against committed state and the intake dir.
    fn resolve(&self, marker: &Marker) -> PendingState {
        let record_id = match hex32(&marker.record) {
            Ok(bytes) => RoomRecordId::from_bytes(bytes),
            Err(_) => return PendingState::Rejected,
        };
        let room = match marker.kind.as_str() {
            "create" => marker
                .slug
                .as_deref()
                .and_then(|s| Slug::new(s).ok())
                .and_then(|slug| self.registry().room(&slug)),
            "update" => marker
                .genesis
                .as_deref()
                .and_then(|g| hex32(g).ok())
                .map(RoomGenesisId::from_bytes)
                .and_then(|g| self.registry().room_by_genesis(g)),
            _ => None,
        };
        if let Some(room) = room {
            match marker.kind.as_str() {
                "create" => {
                    return if room.record().id() == record_id {
                        PendingState::Committed
                    } else {
                        PendingState::Collision
                    };
                }
                "update" => {
                    if room.revisions().iter().any(|r| r.id() == record_id)
                        || room.record().id() == record_id
                    {
                        return PendingState::Committed;
                    }
                    let base_ok = marker
                        .base
                        .as_deref()
                        .and_then(|b| hex32(b).ok())
                        .is_some_and(|b| room.head() == RoomRecordId::from_bytes(b));
                    return if base_ok {
                        PendingState::Submitted
                    } else {
                        PendingState::Collision
                    };
                }
                _ => {}
            }
        }
        if self
            .intake_dir
            .join(format!("{}.rejected", marker.intake))
            .exists()
        {
            return PendingState::Rejected;
        }
        if self
            .intake_dir
            .join(format!("{}.body", marker.intake))
            .exists()
        {
            return PendingState::Queued;
        }
        PendingState::Submitted
    }

    /// Projects one screen against the committed replica.
    pub fn project(&self, screen: &Screen) -> Result<Projection, Error> {
        let registry = self.registry();
        let mut projection = Projection {
            rooms: Vec::new(),
            account: None,
            quote: None,
            partial: false,
            revision: registry.revision(),
            height: self.height(),
            pending: self.pending()?,
        };
        match screen {
            Screen::Directory { query } => {
                let search = registry
                    .search(query, 64, 4096)
                    .map_err(|_| Error::Bounds)?;
                projection.partial = search.partial;
                projection.rooms = search.rooms.iter().map(|r| row(r)).collect();
            }
            Screen::Room { slug } => {
                let slug = Slug::new(slug).map_err(|_| Error::Bounds)?;
                if let Some(room) = registry.room(&slug) {
                    projection.rooms.push(row(room));
                }
            }
            Screen::Account { owner } => {
                projection.account = Some(registry.account(*owner));
                projection.quote = registry.quote(*owner).ok();
                let search = registry.search("", 64, 4096).map_err(|_| Error::Bounds)?;
                projection.partial = search.partial;
                projection.rooms = search
                    .rooms
                    .iter()
                    .filter(|r| r.owner() == *owner)
                    .map(|r| row(r))
                    .collect();
            }
        }
        Ok(projection)
    }
}

/// The marker fields one body's effect record resolves to.
#[cfg(unix)]
struct Effect {
    /// The effect record's content id — the pending marker's name.
    record: RoomRecordId,
    /// "create" or "update".
    kind: &'static str,
    /// Slug the submission names — creates only.
    slug: Option<String>,
    /// Room genesis the update binds, hex — updates only.
    genesis: Option<String>,
    /// The room head the update chained from, hex — updates only.
    base: Option<String>,
}

/// The effect record of a body: its last non-control room record decides
/// the pending marker's name, kind, slug or genesis, and update base.
#[cfg(unix)]
fn effect(records: &[Vec<u8>]) -> Result<Effect, Error> {
    let mut last: Option<Effect> = None;
    for raw in records {
        let record = SignedRecord::decode(raw)
            .map_err(|e| Error::Record(format!("decode: {e:?}")))?
            .verify()
            .map_err(|e| Error::Record(format!("verify: {e:?}")))?;
        let id = record.id();
        let entry = match record.body() {
            Body::Create(intent) => Effect {
                record: id,
                kind: "create",
                slug: Some(intent.slug.as_str().to_owned()),
                genesis: None,
                base: None,
            },
            Body::Update(update) => Effect {
                record: id,
                kind: "update",
                slug: None,
                genesis: Some(hex(update.genesis.as_bytes())),
                base: Some(hex(update.previous.as_bytes())),
            },
            Body::Control(_) => continue,
        };
        last = Some(entry);
    }
    last.ok_or(Error::Record("body names no room effect".into()))
}

#[cfg(unix)]
fn row(room: &vhalla_rooms::registry::Room) -> RoomRow {
    RoomRow {
        slug: room.slug().as_str().to_owned(),
        owner: hex(room.owner().as_bytes()),
        agent: hex(room.intent().agent.as_bytes()),
        description: room.description().as_str().to_owned(),
        slot: room.intent().slot,
        charge: room.intent().charge,
        archived: room.archived(),
        record: hex(room.record().id().as_bytes()),
        head: hex(room.head().as_bytes()),
        revisions: room.revisions().len(),
        created_at: room.created_at(),
    }
}

#[cfg(all(test, unix))]
mod tests;
