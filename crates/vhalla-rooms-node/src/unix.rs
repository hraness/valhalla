//! The hosted unix node: Malachite engines on libp2p networking deciding
//! room-registry batches, with the `Decided`/`Finalized` application
//! boundary gated by the durable commit journal in `vhalla-rooms-consensus`.
//!
//! Everything in this module is OS-coupled — sockets, filesystem, tokio
//! runtime — and stays behind `cfg(unix)` so the portable `context`/`cert`
//! surface compiles for wasm consumers.

use bytes::Bytes;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_malachitebft_app::config::NodeConfig;
use arc_malachitebft_app::spawn::spawn_wal_actor;
use arc_malachitebft_app::types::codec::Codec;
use arc_malachitebft_app::types::core::Validity;
use arc_malachitebft_app::types::sync::RawDecidedValue;
use arc_malachitebft_app::types::{LocallyProposedValue, PeerId, ProposedValue};
use arc_malachitebft_app_channel::{
    AppMsg, Channels, ConsensusContext, EngineBuilder, EngineHandle, NetworkContext, NetworkMsg,
    Reply, RequestContext, SyncContext, WalContext,
};
use arc_malachitebft_config::{
    ConsensusConfig, DiscoveryConfig, P2pConfig, PubSubProtocol, TransportProtocol, ValuePayload,
    ValueSyncConfig,
};
use arc_malachitebft_core_types::{HeightParams, LinearTimeouts, Round, VoteExtensionPolicy};
use arc_malachitebft_engine::host::{Next, SyncedValueOutcome};
use arc_malachitebft_engine::network::{
    Msg as NetActorMsg, NetworkEvent, NetworkIdentity, NetworkRef, Subscriber,
};
use arc_malachitebft_engine::node::NodeMsg;
use arc_malachitebft_engine::util::output_port::{OutputPort, OutputPortSubscriberTrait};
use arc_malachitebft_engine::util::streaming::{StreamContent, StreamId, StreamMessage};
use arc_malachitebft_engine::wal::{Msg as WalMsg, WalRef};
use arc_malachitebft_metrics::SharedRegistry;
use arc_malachitebft_signing::Signer;
use ractor::{Actor, ActorProcessingErr, ActorRef};
use vhalla_rooms_consensus::{
    decode_eligible_update, Adapter, Batch, BatchBody, CommitCertificate as RoomCertificate,
    DecidedOutcome, EngineSink, Genesis,
};

use crate::cert::{ext_certificate_from_canonical, verify_commit_certificate};
use crate::codec::RoomCodec;
use crate::context::*;
use crate::signing::{verify_fin, RoomSigner, RoomVerifier};

/// Minimal `NodeConfig` — the engine reads only these views.
#[derive(Clone)]
pub struct Config {
    /// The node's display name (peer identity label).
    pub moniker: String,
    /// Consensus + networking configuration.
    pub consensus: ConsensusConfig,
    /// Value-sync (decided-value catchup) configuration.
    pub value_sync: ValueSyncConfig,
}

impl NodeConfig for Config {
    fn moniker(&self) -> &str {
        &self.moniker
    }
    fn consensus(&self) -> &ConsensusConfig {
        &self.consensus
    }
    fn consensus_mut(&mut self) -> &mut ConsensusConfig {
        &mut self.consensus
    }
    fn value_sync(&self) -> &ValueSyncConfig {
        &self.value_sync
    }
    fn value_sync_mut(&mut self) -> &mut ValueSyncConfig {
        &mut self.value_sync
    }
}

fn height_params(validator_set: &RoomValidatorSet) -> HeightParams<RoomContext> {
    HeightParams::new(validator_set.clone(), LinearTimeouts::default(), None)
        .with_vote_extension_policy(VoteExtensionPolicy::Disabled)
}

/// A fully received proposal stream: header, the concatenated canonical
/// value bytes, and the proposer's `Fin` signature.
struct AssembledParts {
    init: ProposalInit,
    data: Vec<u8>,
    fin: ProposalFin,
}

/// Per-stream accumulation state: parts arrive inside `StreamContent::Data`
/// until the `StreamContent::Fin` marker closes the stream. `Data` chunks
/// are keyed by stream sequence so out-of-order delivery still assembles
/// in emission order.
#[derive(Default)]
struct StreamState {
    init: Option<ProposalInit>,
    data: BTreeMap<u64, Vec<u8>>,
    data_len: usize,
    fin: Option<ProposalFin>,
    closed: bool,
    /// When the first part of this stream arrived — the expiry clock for
    /// streams a dead connection never closes.
    first_seen: Option<std::time::Instant>,
}

/// One proposal this node observed at a height — locally proposed or
/// wire-received and verified. Persisted under `store/seen/` so a
/// restarted node can resupply the engine with the `ProposedValue`s it
/// had already seen: the WAL restores votes and locks, this store
/// restores the VALUE content those locks refer to.
#[derive(Clone)]
struct SeenProposal {
    round: Round,
    pol_round: Round,
    proposer: Address,
    value_id: RoomValueId,
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect(),
    )
}

/// Write `bytes` to `dir/name` with journal discipline: tmp file,
/// fsync file, rename, fsync directory. The record is durable before
/// the caller treats it as held.
fn store_write(dir: &Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    let target = dir.join(name);
    let tmp = dir.join(format!("{name}.tmp"));
    {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, &target)?;
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

/// Load the durable application store: every retained batch plus every
/// seen-proposal record. Records whose batch bytes are absent or fail
/// to decode are skipped — the resupply path re-validates anyway.
fn load_store(
    store: &Path,
) -> (
    BTreeMap<RoomValueId, Batch>,
    BTreeMap<u64, Vec<SeenProposal>>,
) {
    let mut held = BTreeMap::new();
    if let Ok(entries) = std::fs::read_dir(store.join("batches")) {
        for entry in entries.flatten() {
            let Ok(bytes) = std::fs::read(entry.path()) else {
                continue;
            };
            let Ok(batch) = Batch::decode(&bytes) else {
                continue;
            };
            held.insert(RoomValueId(batch.value_id()), batch);
        }
    }
    let mut seen: BTreeMap<u64, Vec<SeenProposal>> = BTreeMap::new();
    if let Ok(entries) = std::fs::read_dir(store.join("seen")) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let mut parts = name.split('_');
            let (Some(h), Some(r), Some(p), None) = (
                parts.next().and_then(|s| s.parse::<u64>().ok()),
                parts.next().and_then(|s| s.parse::<i64>().ok()),
                parts.next().and_then(unhex),
                parts.next(),
            ) else {
                continue;
            };
            let Ok(body) = std::fs::read(entry.path()) else {
                continue;
            };
            if body.len() != 40 || p.len() != 20 {
                continue;
            }
            let mut proposer = [0; 20];
            proposer.copy_from_slice(&p);
            let mut value_id = [0; 32];
            value_id.copy_from_slice(&body[..32]);
            let pol = i64::from_be_bytes(body[32..40].try_into().unwrap());
            let to_round = |v: i64| {
                if v < 0 {
                    Round::Nil
                } else {
                    Round::new(v as u32)
                }
            };
            seen.entry(h).or_default().push(SeenProposal {
                round: to_round(r),
                pol_round: to_round(pol),
                proposer: Address::new(proposer),
                value_id: RoomValueId(value_id),
            });
        }
    }
    (held, seen)
}

/// Per-node application state owned by the channel loop.
struct App {
    ctx: RoomContext,
    adapter: Arc<Mutex<Adapter<vhalla_journal::FsStore>>>,
    sink: Arc<Mutex<EngineSink>>,
    /// height -> validator set active at that height (activation map).
    validator_sets: BTreeMap<u64, RoomValidatorSet>,
    address: Address,
    private_key: PrivateKey,
    /// height -> value commitment of the batch this node proposes.
    proposals: BTreeMap<u64, RoomValueId>,
    /// Batches submitted at runtime awaiting a height assignment. FIFO:
    /// `GetValue` assigns the front to its height; a losing decision at
    /// that height leaves it queued for the next — only a commit of the
    /// batch's own value id removes it.
    pending_proposals: VecDeque<PendingEntry>,
    /// value id → pending marker name, for entries that began as bodies:
    /// the body bytes stay in the marker until commit so a lost proposal
    /// can be re-assembled against the new frontier rather than dropped.
    assigned_bodies: BTreeMap<RoomValueId, String>,
    /// value commitment -> the full held batch (local proposals and
    /// batches received over the wire alike).
    held_by_id: BTreeMap<RoomValueId, Batch>,
    /// (peer, stream) -> partially received proposal parts.
    streams: BTreeMap<(Vec<u8>, Vec<u8>), StreamState>,
    /// value commitment -> assembled parts, for restreams.
    parts_cache: BTreeMap<RoomValueId, Vec<RoomPart>>,
    decided: BTreeMap<u64, RawDecidedValue<RoomContext>>,
    stream_seq: u64,
    boundary_latency: Arc<Mutex<Vec<(u64, u128)>>>,
    /// Application-owned durable store (`batches/` + `seen/`).
    store: PathBuf,
    /// height -> proposals observed at that height (for `StartedRound`
    /// resupply). The durable half lives under `store/seen/`.
    seen: BTreeMap<u64, Vec<SeenProposal>>,
    /// Total `ProposedValue`s resupplied to the engine at round starts.
    resupplied: Arc<Mutex<u64>>,
    /// `GetValue` replies held open while no value is available for the
    /// requested height, each with the deadline the engine gave it. A
    /// dropped reply is a dropped oneshot — the app-channel connector's
    /// `rx.await` then errors and kills the host connector, wedging the
    /// engine. Held replies flush once a value for that height
    /// materializes; past the deadline they resolve with a tombstone so
    /// the connector's sequential message loop un-parks and its queued
    /// backlog (parts, decisions) can drain.
    held_replies: Vec<HeldReply>,
}

/// A `GetValue` request held open while no value is available, with the
/// deadline the engine gave it.
struct HeldReply {
    height: u64,
    round: Round,
    deadline: std::time::Instant,
    reply: Reply<LocallyProposedValue<RoomContext>>,
}

/// A held `GetValue` that can now be answered: `live` marks real values
/// whose parts may be published; a tombstone is reply-only and its parts
/// must never reach the wire, or peers could assemble and commit an
/// empty value.
struct AnswerableHeld {
    height: u64,
    round: Round,
    value: RoomValue,
    live: bool,
    reply: Reply<LocallyProposedValue<RoomContext>>,
}

/// One queued submission. Bodies are the honest runtime shape: a producer
/// owns evidence + records but cannot know the frontier, so the durable
/// marker holds the body bytes and assembly happens at assignment against
/// the live state — a lost or late proposal can never be committed stale.
/// `Value` entries are complete batches (test plans, direct submits) whose
/// parent was fixed at assembly; if the frontier has already moved past
/// that parent the entry can never commit and is dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
enum PendingEntry {
    /// `store/pending/<name>` holds the canonical `BatchBody` bytes.
    Body(String),
    /// `store/pending/<hex(id)>` is an empty marker; the batch is durable
    /// under `store/batches/` and loaded in `held_by_id`.
    Value(RoomValueId),
}

impl PendingEntry {
    /// The value commitment once an entry has an assembled batch.
    fn value_id(&self) -> Option<RoomValueId> {
        match self {
            PendingEntry::Value(id) => Some(*id),
            PendingEntry::Body(_) => None,
        }
    }
    /// The pending-marker name this entry persists under.
    fn name(&self) -> String {
        match self {
            PendingEntry::Body(name) => name.clone(),
            PendingEntry::Value(id) => hex(&id.0),
        }
    }
}

/// Raw payload bound for one `Data` proposal part. Codec and gossipsub
/// framing ride on top of each part, so the raw chunk stays well under
/// the ~1.2 KiB per-write ceiling observed on relayed transports (e.g.
/// tailcat over DERP), where a single larger write is truncated mid-frame.
const PROPOSAL_CHUNK_BYTES: usize = 768;

/// Slice canonical value bytes into ordered `Data` parts bounded by
/// `PROPOSAL_CHUNK_BYTES`.
fn data_parts(data: &[u8]) -> impl Iterator<Item = RoomPart> + '_ {
    data.chunks(PROPOSAL_CHUNK_BYTES)
        .map(|chunk| RoomPart::Data(chunk.to_vec().into()))
}

impl App {
    /// The validator set active at `height`: the entry at or before it.
    fn set_for(&self, height: u64) -> &RoomValidatorSet {
        self.validator_sets
            .range(..=height)
            .next_back()
            .map(|(_, s)| s)
            .unwrap_or_else(|| self.validator_sets.values().next().unwrap())
    }

    /// Registers a batch received over the wire: durable store first
    /// (fsync'd under `store/batches/`), then durable-adapter hold
    /// (keyed by the batch's own value commitment) plus the local table
    /// used to serve sync requests.
    fn register_batch(&mut self, batch: Batch) -> RoomValueId {
        let id = RoomValueId(batch.value_id());
        self.persist_batch(&id, &batch);
        self.adapter.lock().unwrap().hold(batch.clone());
        self.held_by_id.insert(id, batch);
        id
    }

    /// A locally produced batch entering the proposal pipeline: the same
    /// durable registration as wire-received values, plus a `store/pending/`
    /// marker so a restart re-queues it, then FIFO queueing for the next
    /// `GetValue` this node wins. The entry leaves only when its own value
    /// id commits. A batch that can no longer apply — already committed,
    /// stale-parented — writes no marker: nothing durable is owed it.
    fn submit(&mut self, batch: Batch) {
        if let Err(e) = self.adapter.lock().unwrap().application().validate(&batch) {
            tracing::debug!(id = %hex(&batch.value_id()), error = ?e, "submission dropped: invalid against live frontier");
            return;
        }
        let id = self.register_batch(batch);
        store_write(&self.store.join("pending"), &hex(&id.0), &[]).expect("pending marker write");
        if !self
            .pending_proposals
            .iter()
            .any(|e| e.value_id() == Some(id))
            && !self.proposals.values().any(|p| *p == id)
        {
            self.pending_proposals.push_back(PendingEntry::Value(id));
        }
    }

    /// A producer-supplied body: the marker holds the canonical body
    /// bytes under the file's stem, so assembly always happens against
    /// the live frontier at assignment — a dropped body can never carry
    /// a producer-fabricated parent or result claim.
    fn submit_body(&mut self, name: String, body: BatchBody) {
        store_write(&self.store.join("pending"), &name, &body.encode())
            .expect("pending body write");
        if !self.pending_proposals.iter().any(|e| e.name() == name) {
            self.pending_proposals.push_back(PendingEntry::Body(name));
        }
    }

    /// The cross-process submission contract under `home/intake/`:
    /// `*.batch` and `*.body` files both enter the queue as bodies —
    /// a complete batch's parent and result claims are recomputed at
    /// assignment, so a stale assembler's value is rescued rather than
    /// rejected outright and can never occupy the queue uncommittable.
    /// `*.eligible` files are operator-dropped `VBE1` updates: a bare
    /// replacement eligible-source set queued as a config-only body.
    /// The file stem becomes the pending-marker name (limited to 64
    /// bytes of `[a-zA-Z0-9._-]` so it can never escape the store).
    /// Accepted files unlink; malformed ones rename `.rejected`.
    /// Drained only at `GetValue`, the sole consumer of the queue.
    fn drain_intake(&mut self) {
        let dir = self
            .store
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("intake");
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Some(stem) = name
                .strip_suffix(".batch")
                .or_else(|| name.strip_suffix(".body"))
                .or_else(|| name.strip_suffix(".eligible"))
            else {
                continue;
            };
            let body = std::fs::read(&path).ok().and_then(|bytes| {
                if name.ends_with(".batch") {
                    Batch::decode(&bytes).ok().map(|b| BatchBody {
                        time: b.time,
                        evidence: b.evidence,
                        records: b.records,
                        games: b.games,
                        eligible: b.eligible,
                    })
                } else if name.ends_with(".eligible") {
                    // Operator-dropped eligible-set transition: a bare id list
                    // becomes a config-only body; the committed clock supplies
                    // the batch time at assembly.
                    decode_eligible_update(&bytes).ok().map(|set| BatchBody {
                        time: 0,
                        evidence: Vec::new(),
                        records: Vec::new(),
                        games: Vec::new(),
                        eligible: Some(set),
                    })
                } else {
                    BatchBody::decode(&bytes).ok()
                }
            });
            let safe = stem.len() <= 64
                && !stem.is_empty()
                && stem
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-' || c == b'_');
            match (safe, body) {
                (true, Some(body)) => {
                    self.submit_body(stem.to_owned(), body);
                    // An unlink race only means a duplicate enqueue next
                    // drain — the stem dedup makes that harmless.
                    let _ = std::fs::remove_file(&path);
                }
                (false, _) => {
                    tracing::warn!(file = %name, "intake rejected: unsafe file stem");
                    let _ = std::fs::rename(&path, path.with_extension("rejected"));
                }
                (true, None) => {
                    tracing::warn!(file = %name, "intake rejected: undecodable body");
                    let _ = std::fs::rename(&path, path.with_extension("rejected"));
                }
            }
        }
    }

    /// The queue front made committable for this height: bodies assemble
    /// against the live frontier via `Application::prepare`; a complete
    /// batch still validating goes as-is. A stale `Value` entry (lost
    /// height, fixed parent) either downgrades back to its body — the
    /// effect may still apply against the new frontier — or drops dead
    /// when it came from a direct submit. A body that can never apply is
    /// rejected to the producer and removed. Runs inside `GetValue`, so
    /// an uncommittable front can never stall the queue.
    fn next_pending(&mut self) -> Option<RoomValueId> {
        loop {
            match self.pending_proposals.front()?.clone() {
                PendingEntry::Value(id) => {
                    let valid = self.held_by_id.get(&id).is_some_and(|b| {
                        self.adapter
                            .lock()
                            .unwrap()
                            .application()
                            .validate(b)
                            .is_ok()
                    });
                    if valid {
                        return Some(id);
                    }
                    self.pending_proposals.pop_front();
                    match self.assigned_bodies.remove(&id) {
                        Some(name) => self.pending_proposals.push_back(PendingEntry::Body(name)),
                        None => {
                            let _ =
                                std::fs::remove_file(self.store.join("pending").join(hex(&id.0)));
                        }
                    }
                }
                PendingEntry::Body(name) => {
                    let body = std::fs::read(self.store.join("pending").join(&name))
                        .ok()
                        .and_then(|b| BatchBody::decode(&b).ok());
                    let checked = body.map(|b| {
                        self.adapter
                            .lock()
                            .unwrap()
                            .application()
                            .prepare_with_games(b.time, b.evidence, b.records, b.games, b.eligible)
                    });
                    match checked {
                        Some(Ok(checked)) => {
                            let batch = checked.batch().clone();
                            let id = self.register_batch(batch);
                            self.assigned_bodies.insert(id, name);
                            self.pending_proposals.pop_front();
                            self.pending_proposals.push_front(PendingEntry::Value(id));
                            return Some(id);
                        }
                        failed => {
                            match &failed {
                                Some(Err(e)) => tracing::warn!(
                                    marker = %name, error = ?e,
                                    "pending body rejected: prepare failed"
                                ),
                                _ => tracing::warn!(
                                    marker = %name,
                                    "pending body rejected: unreadable or undecodable"
                                ),
                            }
                            // The effect can never apply — mark it for the
                            // producer exactly like an intake rejection.
                            let intake = self
                                .store
                                .parent()
                                .unwrap_or_else(|| Path::new("."))
                                .join("intake");
                            let _ = std::fs::create_dir_all(&intake);
                            let _ = std::fs::write(intake.join(format!("{name}.rejected")), []);
                            let _ = std::fs::remove_file(self.store.join("pending").join(&name));
                            self.pending_proposals.pop_front();
                        }
                    }
                }
            }
        }
    }

    /// Drain held `GetValue` replies that can now be answered: a held
    /// request resolves once its height has an assigned, materializable
    /// value — assigning the oldest pending entry when the height has
    /// none yet. A request for an already-committed height is answered
    /// with the decided value: the engine discards it as stale, but the
    /// connector coroutine parked on the reply resumes. A request that
    /// is STILL valueless past its own deadline resolves with a
    /// tombstone — an empty value that can never validate — so a reply
    /// is sent within the contract's timeout rather than parking the
    /// sequential connector forever. A held reply is NEVER dropped — the
    /// dropped oneshot is what kills the connector. Only live, unexpired
    /// requests without a value stay held.
    fn drain_answerable_held(&mut self) -> Vec<AnswerableHeld> {
        let now = std::time::Instant::now();
        let frontier = self.adapter.lock().unwrap().frontier().height;
        let held = std::mem::take(&mut self.held_replies);
        let mut answered = Vec::new();
        for req in held {
            let resolved = if req.height <= frontier {
                self.decided
                    .get(&req.height)
                    .and_then(|raw| RoomCodec::decode_value(raw.value_bytes.clone()).ok())
                    .map(|v| (v, true))
            } else {
                if !self.proposals.contains_key(&req.height) {
                    if let Some(id) = self.next_pending() {
                        self.proposals.insert(req.height, id);
                    }
                }
                self.proposals
                    .get(&req.height)
                    .and_then(|id| self.held_by_id.get(id))
                    .map(|batch| {
                        (
                            RoomValue::new(batch.value_id(), batch.encode().into()),
                            true,
                        )
                    })
            };
            let resolved = resolved.or_else(|| {
                // Past the engine's own deadline the request is already
                // lost: an empty tombstone un-parks the connector; the
                // engine discards it or votes it down as undecodable.
                (now >= req.deadline).then(|| (self.tombstone(req.height, req.round), false))
            });
            match resolved {
                Some((value, live)) => answered.push(AnswerableHeld {
                    height: req.height,
                    round: req.round,
                    value,
                    live,
                    reply: req.reply,
                }),
                None => self.held_replies.push(req),
            }
        }
        answered
    }

    /// fsync the canonical batch bytes under `store/batches/<id>` —
    /// skipped when the file already exists (bytes are canonical).
    /// A write failure halts the app task: a node that cannot retain a
    /// verified value must not pretend it can resupply it later.
    fn persist_batch(&self, id: &RoomValueId, batch: &Batch) {
        let dir = self.store.join("batches");
        let name = hex(&id.0);
        if dir.join(&name).exists() {
            return;
        }
        store_write(&dir, &name, &batch.encode()).expect("batch store write");
    }

    /// Record an observed proposal under `store/seen/` and in memory.
    /// Dedup is on (round, proposer, value id): the same value re-proposed
    /// at a later round earns a second record, which the resupply path
    /// needs to report each round's proposal faithfully.
    fn record_seen(&mut self, init: &ProposalInit, value_id: RoomValueId) {
        let entry = self.seen.entry(init.height.as_u64()).or_default();
        if entry
            .iter()
            .any(|s| s.round == init.round && s.proposer == init.proposer && s.value_id == value_id)
        {
            return;
        }
        let record = SeenProposal {
            round: init.round,
            pol_round: init.pol_round,
            proposer: init.proposer,
            value_id,
        };
        let mut body = Vec::with_capacity(40);
        body.extend_from_slice(&value_id.0);
        body.extend_from_slice(&init.pol_round.as_i64().to_be_bytes());
        store_write(
            &self.store.join("seen"),
            &format!(
                "{}_{}_{}",
                init.height.as_u64(),
                init.round.as_i64(),
                hex(&init.proposer.into_inner())
            ),
            &body,
        )
        .expect("seen store write");
        entry.push(record);
    }

    /// The `StartedRound` resupply: every value this node observed at
    /// `height` and still retains, re-validated against the pinned
    /// frontier. Values whose batch bytes are gone or no longer
    /// validate are dropped rather than resupplied as valid.
    fn resupply_for(&mut self, height: Height) -> Vec<ProposedValue<RoomContext>> {
        let Some(seen) = self.seen.get(&height.as_u64()).cloned() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for record in seen {
            let Some(batch) = self.held_by_id.get(&record.value_id).cloned() else {
                continue;
            };
            let value = RoomValue::new(batch.value_id(), batch.encode().into());
            let validity = self.verdict_for(&value);
            out.push(ProposedValue {
                height,
                round: record.round,
                valid_round: record.pol_round,
                proposer: record.proposer,
                value,
                validity,
            });
        }
        out
    }

    /// A reply-only value for a `GetValue` that outlived its deadline.
    /// The id binds THIS node, height, and round — never `[0;32]` — so a
    /// slim consensus-channel proposal carrying the id can never collide
    /// with a peer's own tombstone and commit an empty value.
    fn tombstone(&self, height: u64, round: Round) -> RoomValue {
        use sha3::Digest;
        let mut hasher = sha3::Keccak256::new();
        hasher.update(b"VHTOMB");
        hasher.update(self.address.into_inner());
        hasher.update(height.to_be_bytes());
        hasher.update(round.as_u32().unwrap_or(u32::MAX).to_be_bytes());
        RoomValue::new(hasher.finalize().into(), Bytes::new())
    }

    /// The validity verdict for a wire-received value: the canonical bytes
    /// must decode to a `Batch` that validates against the current pinned
    /// frontier — and its `value_id` must match the proposed commitment.
    fn verdict_for(&mut self, value: &RoomValue) -> Validity {
        let Ok(batch) = Batch::decode(&value.bytes) else {
            tracing::debug!(id = %hex(&value.id.0), "value rejected: undecodable bytes");
            return Validity::Invalid;
        };
        if batch.value_id() != value.id.0 {
            tracing::debug!(id = %hex(&value.id.0), "value rejected: batch/id mismatch");
            return Validity::Invalid;
        }
        if let Err(e) = self.adapter.lock().unwrap().application().validate(&batch) {
            tracing::debug!(id = %hex(&value.id.0), error = ?e, "value rejected: replay failed");
            return Validity::Invalid;
        }
        self.register_batch(batch);
        Validity::Valid
    }

    fn stream_id(&mut self, height: Height, round: Round) -> StreamId {
        self.stream_seq += 1;
        let mut bytes = Vec::with_capacity(24);
        bytes.extend_from_slice(&height.as_u64().to_be_bytes());
        bytes.extend_from_slice(&round.as_i64().to_be_bytes());
        bytes.extend_from_slice(&self.stream_seq.to_be_bytes());
        StreamId::new(bytes.into())
    }

    /// Build signed proposal parts carrying the real canonical batch
    /// bytes: `Init`, `Data` chunks bounded by `PROPOSAL_CHUNK_BYTES`,
    /// and `Fin` signing `"RF1" || height || round || keccak256(data)`
    /// over the COMPLETE concatenated bytes — chunking is a transport
    /// detail invisible to the signature.
    fn build_parts(&mut self, proposed: &LocallyProposedValue<RoomContext>) -> Vec<RoomPart> {
        let data = proposed.value.bytes.clone();
        let signature = RoomSigner::new(self.private_key.clone()).sign(&fin_sign_bytes(
            proposed.height,
            proposed.round,
            &data,
        ));
        let mut parts = Vec::with_capacity(2 + data.len() / PROPOSAL_CHUNK_BYTES + 1);
        parts.push(RoomPart::Init(ProposalInit {
            height: proposed.height,
            round: proposed.round,
            pol_round: Round::Nil,
            proposer: self.address,
        }));
        parts.extend(data_parts(&data));
        parts.push(RoomPart::Fin(ProposalFin { signature }));
        parts
    }

    /// Fold a completed stream into `AssembledParts`: exactly `Init`,
    /// `Data`*, `Fin` — the `Data` chunks concatenated in stream-sequence
    /// order regardless of arrival order.
    fn assemble(state: StreamState) -> Option<AssembledParts> {
        let mut data = Vec::with_capacity(state.data_len);
        for chunk in state.data.values() {
            data.extend_from_slice(chunk);
        }
        Some(AssembledParts {
            init: state.init?,
            data,
            fin: state.fin?,
        })
    }

    /// Consume one streamed proposal part. `Init`/`Fin` are stored by
    /// kind; `Data` chunks are keyed by their stream sequence so any
    /// arrival order still concatenates in emission order. The transport
    /// `StreamContent::Fin` marker triggers assembly.
    /// Returns the complete `ProposedValue` once the stream closes, or
    /// `None` while the stream is incomplete or was closed oversized.
    fn handle_part(
        &mut self,
        from: PeerId,
        part: StreamMessage<RoomPart>,
    ) -> Option<ProposedValue<RoomContext>> {
        let key = (from.to_bytes(), part.stream_id.to_bytes().to_vec());
        let seq = part.sequence;
        let state = self.streams.entry(key.clone()).or_default();
        state.first_seen.get_or_insert_with(std::time::Instant::now);
        let done = match part.content {
            StreamContent::Data(RoomPart::Init(init)) => {
                state.init = Some(init);
                false
            }
            StreamContent::Data(RoomPart::Data(data)) => {
                if !state.data.contains_key(&seq) {
                    if state.data_len + data.len() > crate::MAX_VALUE_BYTES {
                        tracing::debug!(peer = %from, "proposal stream closed: exceeds MAX_VALUE_BYTES");
                        state.closed = true;
                    } else {
                        state.data_len += data.len();
                        state.data.insert(seq, data.to_vec());
                    }
                }
                false
            }
            StreamContent::Data(RoomPart::Fin(fin)) => {
                state.fin = Some(fin);
                false
            }
            StreamContent::Fin => true,
        };
        if !done || state.closed {
            return None;
        }
        let state = self.streams.remove(&key).unwrap();
        Self::assemble(state).map(|assembled| {
            if !self.verify_parts(&assembled) {
                tracing::debug!(
                    peer = %from, height = %assembled.init.height, round = %assembled.init.round,
                    "assembled stream failed verification: bad proposer or Fin signature"
                );
                return ProposedValue {
                    height: assembled.init.height,
                    round: assembled.init.round,
                    valid_round: Round::Nil,
                    proposer: assembled.init.proposer,
                    value: RoomValue::new([0; 32], Vec::new().into()),
                    validity: Validity::Invalid,
                };
            }
            let value = RoomValue::new(
                // The id arrives only via the decided certificate —
                // derive it from the decoded batch so the proposal
                // names the real commitment.
                Batch::decode(&assembled.data)
                    .map(|b| b.value_id())
                    .unwrap_or([0; 32]),
                assembled.data.clone().into(),
            );
            let validity = self.verdict_for(&value);
            if validity.is_valid() {
                let mut cached =
                    Vec::with_capacity(2 + assembled.data.len() / PROPOSAL_CHUNK_BYTES + 1);
                cached.push(RoomPart::Init(assembled.init.clone()));
                cached.extend(data_parts(&assembled.data));
                cached.push(RoomPart::Fin(assembled.fin.clone()));
                self.parts_cache.insert(value.id, cached);
                self.record_seen(&assembled.init, value.id);
            }
            ProposedValue {
                height: assembled.init.height,
                round: assembled.init.round,
                valid_round: assembled.init.pol_round,
                proposer: assembled.init.proposer,
                value,
                validity,
            }
        })
    }

    /// Verify a received part set: the stream's claimed proposer must be
    /// the EXPECTED proposer for (height, round) under the active set,
    /// and the `Fin` signature over the streamed content must verify
    /// against that proposer's key.
    fn verify_parts(&self, parts: &AssembledParts) -> bool {
        let set = self.set_for(parts.init.height.as_u64());
        let expected = self
            .ctx
            .select_proposer(set, parts.init.height, parts.init.round)
            .address;
        if parts.init.proposer != expected {
            return false;
        }
        let Some(proposer) = set
            .validators
            .iter()
            .find(|v| v.address == parts.init.proposer)
        else {
            return false;
        };
        verify_fin(
            &proposer.public_key,
            parts.init.height,
            parts.init.round,
            &parts.data,
            &parts.fin.signature,
        )
    }

    /// The shared decided path: verify the real certificate, then let the
    /// journal gate the commit. The certificate's `value_id` IS the
    /// batch's durable commitment — the adapter resolves it directly.
    fn decide(
        &mut self,
        certificate: &arc_malachitebft_app::types::core::CommitCertificate<RoomContext>,
    ) -> DecidedOutcome {
        let set = self.set_for(certificate.height.as_u64());
        let Ok(accepted) = verify_commit_certificate(certificate, set) else {
            return DecidedOutcome::Rejected;
        };
        // The adapter lock stays held across marker retirement: the
        // frontier advancing is already observable through
        // `committed_height`, so a release between `decide` and the
        // pending-dir cleanup would let a reader see "committed" while
        // the submission's marker still exists.
        let mut adapter = self.adapter.lock().unwrap();
        let outcome = adapter.decide(&RoomCertificate {
            bytes: accepted.bytes,
            value_commitment: accepted.value_id.0,
            height: accepted.height,
        });
        if !matches!(outcome, DecidedOutcome::Acked) {
            tracing::warn!(
                height = %certificate.height, value_id = %hex(&certificate.value_id.0),
                outcome = ?outcome,
                "decision did not commit durably"
            );
        }
        let height = certificate.height.as_u64();
        // The assignment for this height is dead regardless of outcome —
        // a rejected/withheld decision restarts the height and reassigns.
        self.proposals.remove(&height);
        if matches!(outcome, DecidedOutcome::Acked) {
            let id = certificate.value_id;
            let _ = std::fs::remove_file(self.store.join("pending").join(hex(&id.0)));
            if let Some(name) = self.assigned_bodies.remove(&id) {
                let _ = std::fs::remove_file(self.store.join("pending").join(name));
            }
            self.pending_proposals.retain(|p| p.value_id() != Some(id));
        }
        drop(adapter);
        outcome
    }

    /// Record a just-decided value into the sync-servable `decided` map,
    /// then retire per-height state that can never be consulted again:
    /// `seen` records at or below the decided height (resupply only ever
    /// serves the engine's CURRENT height), proposal streams and cached
    /// parts below it (the decided height's parts stay — a lagging peer
    /// may still request them), and `held_by_id` entries no longer
    /// referenced by any pending submission, live height assignment, or
    /// retained seen record. The committed value itself survives in
    /// `decided` and the journal.
    fn sweep_decided(&mut self, height: u64) {
        self.seen.retain(|h, _| *h > height);
        self.streams
            .retain(|_, s| s.init.as_ref().is_none_or(|i| i.height.as_u64() > height));
        self.parts_cache.retain(|_, parts| {
            parts
                .iter()
                .find_map(|p| match p {
                    RoomPart::Init(init) => Some(init.height.as_u64()),
                    _ => None,
                })
                .is_some_and(|h| h >= height)
        });
        let live: BTreeSet<RoomValueId> = self
            .proposals
            .values()
            .copied()
            .chain(self.pending_proposals.iter().filter_map(|e| e.value_id()))
            .chain(
                self.seen
                    .values()
                    .flat_map(|v| v.iter().map(|s| s.value_id)),
            )
            .collect();
        self.held_by_id.retain(|id, _| live.contains(id));
    }

    /// Insert the decided value into `decided` (the `GetDecidedValues`
    /// source), then sweep dead per-height state. Both `Decided` and
    /// `Finalized` take this path — the second call is an idempotent
    /// overwrite with the possibly richer extended certificate.
    fn record_decided(
        &mut self,
        certificate: &arc_malachitebft_app::types::core::CommitCertificate<RoomContext>,
        extensions: arc_malachitebft_core_types::VoteExtensions<RoomContext>,
    ) {
        if let Some(batch) = self.held_by_id.get(&certificate.value_id) {
            let value = RoomValue::new(batch.value_id(), batch.encode().into());
            let value_bytes = RoomCodec::encode_value(&value);
            self.decided.insert(
                certificate.height.as_u64(),
                RawDecidedValue::new(
                    value_bytes,
                    arc_malachitebft_app::types::core::ExtendedCommitCertificate::from_commit_certificate_and_extensions(
                        certificate.clone(), extensions,
                    ),
                ),
            );
        }
        self.sweep_decided(certificate.height.as_u64());
    }

    /// Drop proposal streams that never completed: a dead connection
    /// leaves `Init`/`Data` state behind with no transport `Fin` to close
    /// it. Anything older than the stale bound is either abandoned or
    /// will be re-streamed on request.
    fn expire_streams(&mut self) {
        let now = std::time::Instant::now();
        let before = self.streams.len();
        self.streams.retain(|_, s| {
            s.first_seen
                .is_none_or(|t| now.duration_since(t) < STREAM_STALE)
        });
        let dropped = before - self.streams.len();
        if dropped > 0 {
            tracing::debug!(dropped, "expired abandoned proposal streams");
        }
    }
}

/// Everything `RoomNode::start` needs, as one struct (keeps the call
/// sites legible and under the argument limit).
pub struct NodeSpec {
    /// Home directory: the engine WAL lives under `wal/`, the room
    /// journal under `journal/`.
    pub home: PathBuf,
    /// Engine + network configuration.
    pub config: Config,
    /// This node's consensus private key.
    pub node_key: PrivateKey,
    /// Activation-height -> validator set.
    pub validator_sets: BTreeMap<u64, RoomValidatorSet>,
    /// Height -> held batch this node may propose.
    pub held: BTreeMap<u64, Batch>,
    /// The genesis inputs every node shares: the committed social archive
    /// and the parameters the fresh registry and both stores derive from.
    pub genesis: Genesis,
    /// Optional WAL fault schedule: when set, the node's WAL is a
    /// fault-injecting proxy over the real file-backed WAL.
    pub wal_faults: Option<std::sync::Arc<Mutex<WalPlan>>>,
    /// Optional network gate: when set, the node's libp2p network runs
    /// behind a proxy the caller can close/reopen at runtime — a true
    /// mid-test partition (the process stays up, deaf and mute).
    pub net_gate: Option<NetGate>,
}

/// A WAL fault the proxy applies to the next matching message.
#[derive(Debug, Clone, Copy)]
pub enum WalFault {
    /// Reply `Err` — a reported failure. On the engine's safety path
    /// this must halt signing (`hang_on_safety_failure`), never be
    /// worked around.
    Fail,
    /// Reply `Ok` without forwarding — the write is silently absent on
    /// replay (the fsync-lie case). The engine proceeds believing the
    /// entry is durable.
    Drop,
}

/// Ordered per-kind fault schedule for one node's WAL proxy: the Nth
/// `Append` consumes `appends[N]`, the Nth `Flush` consumes
/// `flushes[N]`; an empty queue means no fault.
#[derive(Debug, Default)]
pub struct WalPlan {
    /// Faults consumed in order, one per `Append` the WAL receives.
    pub appends: VecDeque<WalFault>,
    /// Faults consumed in order, one per `Flush` the WAL receives.
    pub flushes: VecDeque<WalFault>,
}

/// `NodeMsg` sink for the proxied real WAL: the engine keeps the real
/// `Node`; this stand-in only absorbs the WAL worker's SafetyFailure
/// casts (none are expected — injected faults arrive as `Err` replies
/// on the consensus actor's safety path, which reports to the real
/// Node itself).
struct WalTestNode;

#[ractor::async_trait]
impl Actor for WalTestNode {
    type Msg = NodeMsg;
    type State = ();
    type Arguments = ();
    async fn pre_start(
        &self,
        _myself: ActorRef<Self::Msg>,
        _args: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        Ok(())
    }
    async fn handle(
        &self,
        _myself: ActorRef<Self::Msg>,
        _msg: Self::Msg,
        _state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        Ok(())
    }
}

/// An actor proxying the real WAL: every message forwards unless the
/// plan schedules a fault for it. The proxy sits inside the engine's
/// own machinery via `WalBuilder::Custom` — the injected failure is
/// indistinguishable from a real WAL write/flush error upstream.
struct FaultWal;

struct FaultWalState {
    inner: WalRef<RoomContext>,
    plan: std::sync::Arc<Mutex<WalPlan>>,
}

#[ractor::async_trait]
impl Actor for FaultWal {
    type Msg = WalMsg<RoomContext>;
    type State = FaultWalState;
    type Arguments = FaultWalState;
    async fn pre_start(
        &self,
        _myself: ActorRef<Self::Msg>,
        args: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        Ok(args)
    }
    async fn post_stop(
        &self,
        _myself: ActorRef<Self::Msg>,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        state.inner.stop(None);
        Ok(())
    }
    async fn handle(
        &self,
        _myself: ActorRef<Self::Msg>,
        msg: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match msg {
            WalMsg::StartedHeight(height, reply) => {
                let r = ractor::call!(state.inner, WalMsg::StartedHeight, height)
                    .unwrap_or_else(|e| Err(eyre::eyre!("wal transport: {e}")));
                let _ = reply.send(r);
            }
            WalMsg::Reset(height, reply) => {
                let r = ractor::call!(state.inner, WalMsg::Reset, height)
                    .unwrap_or_else(|e| Err(eyre::eyre!("wal transport: {e}")));
                let _ = reply.send(r);
            }
            WalMsg::Append(height, input, reply) => {
                let fault = state.plan.lock().unwrap().appends.pop_front();
                match fault {
                    Some(WalFault::Fail) => {
                        let _ = reply.send(Err(eyre::eyre!("injected wal append failure")));
                    }
                    Some(WalFault::Drop) => {
                        let _ = reply.send(Ok(()));
                    }
                    None => {
                        let r = ractor::call!(state.inner, WalMsg::Append, height, input)
                            .unwrap_or_else(|e| Err(eyre::eyre!("wal transport: {e}")));
                        let _ = reply.send(r);
                    }
                }
            }
            WalMsg::Flush(reply) => {
                let fault = state.plan.lock().unwrap().flushes.pop_front();
                match fault {
                    Some(WalFault::Fail) => {
                        let _ = reply.send(Err(eyre::eyre!("injected wal flush failure")));
                    }
                    Some(WalFault::Drop) => {
                        let _ = reply.send(Ok(()));
                    }
                    None => {
                        let r = ractor::call!(state.inner, WalMsg::Flush)
                            .unwrap_or_else(|e| Err(eyre::eyre!("wal transport: {e}")));
                        let _ = reply.send(r);
                    }
                }
            }
            WalMsg::Dump => {
                let _ = state.inner.cast(WalMsg::Dump);
            }
        }
        Ok(())
    }
}

/// Runtime network partition control: while `open` is false the node's
/// engine can neither publish nor receive consensus traffic — the
/// process keeps running, deaf and mute. This is a TRUE mid-test
/// partition: sockets stay up, the gate drops the messages.
#[derive(Clone)]
pub struct NetGate {
    open: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Inbound data-plane events from these peers drop while the gate is
    /// open — an island cut: gossip still leaves, the far island's events
    /// never land, so an island can campaign internally.
    blocked: std::sync::Arc<std::sync::RwLock<std::collections::HashSet<PeerId>>>,
}

impl Default for NetGate {
    fn default() -> Self {
        Self::new()
    }
}

impl NetGate {
    /// A new gate, fully open with an empty island blocklist.
    pub fn new() -> Self {
        Self {
            open: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            blocked: std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashSet::new())),
        }
    }

    /// Close the gate: all outbound publishes and inbound events drop.
    pub fn close(&self) {
        self.open.store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// Reopen the gate: traffic flows again on the still-live sockets.
    pub fn reopen(&self) {
        self.open.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// While open, drop inbound data-plane traffic from these peers —
    /// the asymmetric-island form of the partition.
    pub fn isolate_from(&self, peers: impl IntoIterator<Item = PeerId>) {
        self.blocked.write().unwrap().extend(peers);
    }

    /// Rejoin: clear the peer blocklist (links themselves never went down).
    pub fn reunite(&self) {
        self.blocked.write().unwrap().clear();
    }

    fn is_open(&self) -> bool {
        self.open.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Whether data-plane traffic to/from `peer` may pass: the gate must
    /// be open and the peer must not be on the island blocklist.
    fn allows(&self, peer: PeerId) -> bool {
        self.is_open() && !self.blocked.read().unwrap().contains(&peer)
    }
}

/// A `NetworkEvent` routed through the gating forwarder.
struct GateEvent(NetworkEvent<RoomContext>);

impl From<NetworkEvent<RoomContext>> for GateEvent {
    fn from(event: NetworkEvent<RoomContext>) -> Self {
        Self(event)
    }
}

/// Delivers network events to a subscriber only while the gate is open.
/// The real network actor's output port publishes here; a closed gate
/// drops the event before the engine's subscriber ever sees it.
struct GateForwarder;

struct GateForwarderState {
    inner: Box<dyn Subscriber<NetworkEvent<RoomContext>>>,
    gate: NetGate,
}

#[ractor::async_trait]
impl Actor for GateForwarder {
    type Msg = GateEvent;
    type State = GateForwarderState;
    type Arguments = GateForwarderState;
    async fn pre_start(
        &self,
        _myself: ActorRef<Self::Msg>,
        args: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        Ok(args)
    }
    async fn handle(
        &self,
        _myself: ActorRef<Self::Msg>,
        msg: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        // Link-layer facts are not consensus data: a gated node's links
        // stay up (and peers must stay known so healing has someone to
        // sync from) — only votes, proposals, certificates, status and
        // sync traffic are withheld. Every data-plane event names its
        // source peer, so an island cut drops by peer rather than all.
        let peer = match &msg.0 {
            NetworkEvent::Vote(p, _)
            | NetworkEvent::Proposal(p, _)
            | NetworkEvent::ProposalPart(p, _)
            | NetworkEvent::PolkaCertificate(p, _)
            | NetworkEvent::RoundCertificate(p, _)
            | NetworkEvent::Status(p, _)
            | NetworkEvent::SyncRequest(_, p, _)
            | NetworkEvent::SyncResponse(_, p, _)
            | NetworkEvent::SyncRequestFailed(_, p, _) => Some(*p),
            _ => None,
        };
        let pass = match peer {
            Some(p) => state.gate.allows(p),
            None => true,
        };
        if pass {
            state.inner.send(msg.0);
        }
        Ok(())
    }
}

/// The `Subscriber` the real network actor sees: the startup replay
/// (`send`) and the port subscription both route through the gate.
struct GateSubscriber {
    forwarder: ActorRef<GateEvent>,
}

impl Subscriber<NetworkEvent<RoomContext>> for GateSubscriber {
    fn send(&self, msg: NetworkEvent<RoomContext>) {
        let _ = self.forwarder.cast(GateEvent(msg));
    }
}

impl OutputPortSubscriberTrait<NetworkEvent<RoomContext>> for GateSubscriber {
    fn subscribe_to_port(&self, port: &OutputPort<NetworkEvent<RoomContext>>) {
        port.subscribe(self.forwarder.clone(), |event| Some(GateEvent(event)));
    }
}

/// An actor proxying the real libp2p network: every engine→network
/// message forwards unless the gate is closed, and every `Subscribe`
/// re-registers the subscriber behind a `GateForwarder` so inbound
/// events drop too. Both directions close under one flag — the proxy
/// sits inside the engine's own machinery via `NetworkBuilder::Custom`.
struct GateNetwork;

struct GateNetworkState {
    inner: NetworkRef<RoomContext>,
    gate: NetGate,
}

#[ractor::async_trait]
impl Actor for GateNetwork {
    type Msg = NetActorMsg<RoomContext>;
    type State = GateNetworkState;
    type Arguments = GateNetworkState;
    async fn pre_start(
        &self,
        _myself: ActorRef<Self::Msg>,
        args: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        Ok(args)
    }
    async fn post_stop(
        &self,
        _myself: ActorRef<Self::Msg>,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        state.inner.stop(None);
        Ok(())
    }
    async fn handle(
        &self,
        _myself: ActorRef<Self::Msg>,
        msg: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match msg {
            // Subscription wiring always passes — the gate lives in the
            // forwarder the subscriber is wrapped in.
            NetActorMsg::Subscribe(subscriber) => {
                let (forwarder, _) = Actor::spawn(
                    None,
                    GateForwarder,
                    GateForwarderState {
                        inner: subscriber,
                        gate: state.gate.clone(),
                    },
                )
                .await?;
                let _ = state
                    .inner
                    .cast(NetActorMsg::Subscribe(Box::new(GateSubscriber {
                        forwarder,
                    })));
            }
            // Local control-plane messages are not wire traffic: peer
            // bookkeeping, validator-set updates, proof results and
            // cancellation all proceed under a partition.
            NetActorMsg::UpdateValidatorSet(_)
            | NetActorMsg::ValidatorProofVerified { .. }
            | NetActorMsg::CancelRequest(_)
            | NetActorMsg::CancelInboundRequest(_)
            | NetActorMsg::UpdatePersistentPeers(..)
            | NetActorMsg::DumpState(_)
            | NetActorMsg::NewEvent(_) => {
                let _ = state.inner.cast(msg);
            }
            // Requests name their destination: under an island cut the
            // request dies here rather than waiting out a peer that will
            // never see it — the dropped reply port is still the caller's
            // own timeout answer.
            NetActorMsg::OutgoingRequest(peer, ..) => {
                if state.gate.allows(peer) {
                    let _ = state.inner.cast(msg);
                }
            }
            // Broadcast data-plane messages have no destination to
            // filter: they publish into the void and the far island's
            // inbound drop completes the cut. While the gate is fully
            // closed even broadcasts die here.
            _ => {
                if state.gate.is_open() {
                    let _ = state.inner.cast(msg);
                }
            }
        }
        Ok(())
    }
}

/// One real engine node: real libp2p networking, real WAL, real
/// certificates, journal-gated application boundary.
pub struct RoomNode {
    /// The node's home directory (`wal/`, `app/` journal, `store/`).
    pub home: PathBuf,
    /// The durable adapter behind the journal-gated boundary.
    pub adapter: Arc<Mutex<Adapter<vhalla_journal::FsStore>>>,
    /// Recorded post-commit engine messages (ack evidence).
    pub sink: Arc<Mutex<EngineSink>>,
    /// This node's consensus address.
    pub address: Address,
    /// (height, nanos) — wall time of the verify→journal→ack boundary
    /// per decided/finalized call, including the fsync ordering.
    pub boundary_latency: Arc<Mutex<Vec<(u64, u128)>>>,
    /// Total `ProposedValue`s resupplied at `StartedRound` — non-zero
    /// proves the application store is feeding the engine.
    pub resupplied: Arc<Mutex<u64>>,
    /// (batches, seen records) reloaded from `home/store/` at this
    /// start — non-zero only on a restart over retained state.
    pub loaded: (usize, usize),
    /// The runtime partition gate, when this node was started with one.
    pub gate: Option<NetGate>,
    /// Inbound channel for locally produced batches — [`RoomNode::submit`].
    submissions: tokio::sync::mpsc::Sender<Batch>,
    task: tokio::task::JoinHandle<()>,
    _engine: EngineHandle,
    /// The proxied real WAL actor, when this node runs under a fault
    /// plan. The engine links only the proxy; on crash the inner actor
    /// is stopped explicitly so its worker thread releases the file
    /// lock before a restart reopens the same path.
    inner_wal: Option<WalRef<RoomContext>>,
    /// The real network actor behind the gate proxy, when this node
    /// runs partitioned-capable networking — stopped on crash so its
    /// libp2p sockets release before a restart rebinds the port.
    inner_net: Option<NetworkRef<RoomContext>>,
}

impl RoomNode {
    /// Start a validator engine over `spec.config` with the durable
    /// adapter opened on `spec.home/journal`. `spec.held` maps height ->
    /// held batch this node may propose; `spec.validator_sets` maps
    /// activation height -> set.
    pub async fn start(spec: NodeSpec) -> Self {
        let NodeSpec {
            home,
            config,
            node_key,
            validator_sets,
            held,
            genesis,
            wal_faults,
            net_gate,
        } = spec;
        let public_key = node_key.public_key();
        let address = Address::from_public_key(&public_key);
        let signer = RoomSigner::new(node_key.clone());

        // Network identity: separate keypair, validator proof binding the
        // consensus public key to the peer id.
        let keypair = net_keypair(&address);
        let peer_id_bytes = keypair.public().to_peer_id().to_bytes();
        let proof = signer
            .sign_validator_proof(public_key.as_bytes().to_vec(), peer_id_bytes)
            .await
            .unwrap();
        let proof_bytes = <RoomCodec as Codec<_>>::encode(&RoomCodec, &proof).unwrap();
        let identity = NetworkIdentity::new_validator(
            config.moniker.clone(),
            keypair,
            address.to_string(),
            proof_bytes,
        );

        let wal_path = home.join("wal").join("consensus.wal");
        std::fs::create_dir_all(wal_path.parent().unwrap()).unwrap();
        check_wal_format(&wal_path);

        // When a gate is supplied the real libp2p actor is spawned
        // directly and wrapped in `GateNetwork`; the engine only ever
        // talks to the proxy. Must happen before `config` moves into
        // the builder.
        let gated = match &net_gate {
            Some(gate) => {
                let (real_net, _unused_tx) =
                    arc_malachitebft_app_channel::spawn::spawn_network_actor(
                        identity.clone(),
                        &config.consensus,
                        &config.value_sync,
                        SharedRegistry::global(),
                        RoomCodec,
                    )
                    .await
                    .expect("gated real network spawn");
                let (proxy, _) = Actor::spawn(
                    None,
                    GateNetwork,
                    GateNetworkState {
                        inner: real_net.clone(),
                        gate: gate.clone(),
                    },
                )
                .await
                .expect("gate proxy spawn");
                Some((real_net, proxy))
            }
            None => None,
        };

        // The network and WAL choices both sit behind typestate slots —
        // each combination must be built inside its own arm.
        macro_rules! build_engine {
            ($builder:expr) => {
                match wal_faults {
                    Some(plan) => {
                        let (node, _) = Actor::spawn(None, WalTestNode, ())
                            .await
                            .expect("wal test node");
                        let inner = spawn_wal_actor(
                            &RoomContext,
                            RoomCodec,
                            &wal_path,
                            SharedRegistry::global(),
                            node,
                        )
                        .await
                        .expect("inner wal spawn");
                        let (wal_ref, _) = Actor::spawn(
                            None,
                            FaultWal,
                            FaultWalState {
                                inner: inner.clone(),
                                plan,
                            },
                        )
                        .await
                        .expect("fault wal spawn");
                        let (channels, engine) = $builder
                            .with_custom_wal(wal_ref)
                            .build()
                            .await
                            .expect("engine build");
                        (channels, engine, Some(inner))
                    }
                    None => {
                        let (channels, engine) = $builder
                            .with_default_wal(WalContext::new(wal_path.clone(), RoomCodec))
                            .build()
                            .await
                            .expect("engine build");
                        (channels, engine, None)
                    }
                }
            };
        }

        let builder = EngineBuilder::new(RoomContext, config)
            .with_default_consensus(ConsensusContext::new_validator(
                address,
                Box::new(RoomVerifier),
                Box::new(RoomSigner::new(node_key.clone())),
            ))
            .with_default_sync(SyncContext::new(RoomCodec))
            .with_default_request(RequestContext::new(100));

        let (mut channels, engine, inner_wal, inner_net) = match gated {
            Some((real_net, proxy)) => {
                // The app-side sender the engine hands back as
                // `channels.network`: drained through the proxy so the
                // gate applies to proposal parts too.
                let (tx_net, mut rx_net) =
                    tokio::sync::mpsc::channel::<NetworkMsg<RoomContext>>(100);
                let forward = proxy.clone();
                tokio::spawn(async move {
                    while let Some(msg) = rx_net.recv().await {
                        let _ = forward.cast(NetActorMsg::from(msg));
                    }
                });
                let (channels, engine, inner_wal) =
                    build_engine!(builder.with_custom_network(proxy, tx_net));
                (channels, engine, inner_wal, Some(real_net))
            }
            None => {
                let (channels, engine, inner_wal) = build_engine!(
                    builder.with_default_network(NetworkContext::new(identity, RoomCodec))
                );
                (channels, engine, inner_wal, None)
            }
        };

        let adapter = Arc::new(Mutex::new(
            Adapter::open(home.join("app"), &genesis).expect("adapter open"),
        ));
        let sink = Arc::new(Mutex::new(EngineSink::default()));
        let boundary_latency = Arc::new(Mutex::new(Vec::new()));

        // Application-owned durable store: retained batch bytes plus
        // seen-proposal records. On restart this is what `StartedRound`
        // resupplies from — the spec `held` map is only the FIRST boot's
        // proposal source.
        let store = home.join("store");
        let batches_dir = store.join("batches");
        let seen_dir = store.join("seen");
        std::fs::create_dir_all(&batches_dir).unwrap();
        std::fs::create_dir_all(&seen_dir).unwrap();
        let frontier = adapter.lock().unwrap().frontier().height;
        let (mut held_by_id, mut seen) = load_store(&store);
        let loaded = (held_by_id.len(), seen.values().map(Vec::len).sum());
        // Seen records at or below the committed frontier can never be
        // resupplied — `StartedRound` only ever asks for the engine's
        // current height. The durable files stay; memory drops them.
        seen.retain(|h, _| *h > frontier);

        let pending_proposals = reload_pending(&store, &held_by_id, &adapter);

        let mut proposals = BTreeMap::new();
        {
            let mut guard = adapter.lock().unwrap();
            for (height, batch) in &held {
                let id = RoomValueId(batch.value_id());
                if !held_by_id.contains_key(&id) {
                    store_write(&batches_dir, &hex(&id.0), &batch.encode())
                        .expect("held batch store write");
                }
                held_by_id.insert(id, batch.clone());
                guard.hold(batch.clone());
                proposals.insert(*height, id);
            }
        }
        // Batches nothing can still reference — not queued, not seen at a
        // live height, not spec-held — are dead memory: committed values
        // live in the journal and the rebuilt `decided` map.
        let live: BTreeSet<RoomValueId> = pending_proposals
            .iter()
            .filter_map(|e| e.value_id())
            .chain(seen.values().flat_map(|v| v.iter().map(|s| s.value_id)))
            .chain(proposals.values().copied())
            .collect();
        held_by_id.retain(|id, _| live.contains(id));
        // Reloaded batches also re-enter the adapter's pending map so a
        // certificate for a pre-crash received value can still land.
        for batch in held_by_id.values() {
            adapter.lock().unwrap().hold(batch.clone());
        }
        // Rebuild the sync-servable decided history from the journal — a
        // restarted node must still answer `GetDecidedValues` for heights
        // its peers may not have reached.
        let decided = load_decided(&adapter.lock().unwrap());
        let resupplied = Arc::new(Mutex::new(0u64));

        let mut app = App {
            ctx: RoomContext,
            adapter: Arc::clone(&adapter),
            sink: Arc::clone(&sink),
            validator_sets,
            address,
            private_key: node_key.clone(),
            proposals,
            pending_proposals,
            assigned_bodies: BTreeMap::new(),
            held_by_id,
            streams: BTreeMap::new(),
            parts_cache: BTreeMap::new(),
            decided,
            stream_seq: 0,
            boundary_latency: Arc::clone(&boundary_latency),
            store,
            seen,
            resupplied: Arc::clone(&resupplied),
            held_replies: Vec::new(),
        };

        let (submission_tx, mut submission_rx) = tokio::sync::mpsc::channel::<Batch>(64);
        let task =
            tokio::spawn(async move { run(&mut app, &mut channels, &mut submission_rx).await });

        RoomNode {
            home,
            adapter,
            sink,
            address,
            boundary_latency,
            resupplied,
            loaded,
            gate: net_gate,
            submissions: submission_tx,
            task,
            _engine: engine,
            inner_wal,
            inner_net,
        }
    }

    /// Submit a locally produced batch for proposal: durable
    /// registration, then FIFO assignment to the next `GetValue` this
    /// node wins. The submission survives restart (`store/pending/`)
    /// and is retired only when its own value id commits — losing a
    /// height re-queues it automatically. Backpressures once 64
    /// uncommitted submissions queue.
    pub async fn submit(&self, batch: Batch) {
        let _ = self.submissions.send(batch).await;
    }

    /// Durable frontier height committed by the journal.
    pub fn committed_height(&self) -> u64 {
        self.adapter.lock().unwrap().frontier().height
    }

    /// Recorded post-commit engine messages.
    pub fn acks(&self) -> Vec<vhalla_rooms_consensus::EngineMsg> {
        self.sink.lock().unwrap().sent.clone()
    }

    /// Kills the application loop and the engine actors in place — the
    /// WAL and journal on disk survive, which is what a later `start`
    /// replays.
    /// Abrupt stop: abort the app task and kill the engine, then stop
    /// the orphaned inner WAL gracefully so its file lock is released
    /// before a same-home restart.
    pub async fn crash(self) {
        self.task.abort();
        let _ = self._engine.actor.kill_and_wait(None).await;
        if let Some(inner) = self.inner_wal {
            let _ = inner
                .stop_and_wait(None, Some(std::time::Duration::from_secs(5)))
                .await;
        }
        if let Some(inner) = self.inner_net {
            let _ = inner
                .stop_and_wait(None, Some(std::time::Duration::from_secs(5)))
                .await;
        }
    }
}

/// Re-queue durable submissions at start. A non-empty `store/pending/`
/// marker holds canonical body bytes and re-enters as `Body` — assembly
/// re-runs at assignment, so a body dropped before a crash is never
/// stale afterward. An empty marker names a direct-submit value id and
/// re-enters only when its batch still validates against the current
/// frontier; dead markers drop so none can stall `GetValue`. Restart
/// order is filename-sorted (deterministic), not strict FIFO.
fn reload_pending(
    store: &Path,
    held_by_id: &BTreeMap<RoomValueId, Batch>,
    adapter: &Arc<Mutex<Adapter<vhalla_journal::FsStore>>>,
) -> VecDeque<PendingEntry> {
    std::fs::create_dir_all(store.join("pending")).unwrap();
    let mut out = VecDeque::new();
    let Ok(entries) = std::fs::read_dir(store.join("pending")) else {
        return out;
    };
    let mut files: Vec<_> = entries.flatten().collect();
    files.sort_by_key(|e| e.file_name());
    for entry in files {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let bytes = std::fs::read(entry.path()).unwrap_or_default();
        if bytes.is_empty() {
            let id = unhex(&name)
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .map(RoomValueId);
            let keep = id
                .and_then(|id| held_by_id.get(&id).cloned())
                .is_some_and(|b| adapter.lock().unwrap().application().validate(&b).is_ok());
            match (keep, id) {
                (true, Some(id)) => out.push_back(PendingEntry::Value(id)),
                _ => {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        } else if BatchBody::decode(&bytes).is_ok() {
            out.push_back(PendingEntry::Body(name));
        } else {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    out
}

fn net_seed(address: &Address) -> [u8; 32] {
    let inner = address.into_inner();
    let mut seed = [0xA5; 32];
    let n = inner.len().min(32);
    seed[..n].copy_from_slice(&inner[..n]);
    seed
}

/// The libp2p keypair a node whose consensus address is `address`
/// presents on the wire: derived deterministically from the consensus
/// identity (`net_seed`), so two nodes computing it for the same
/// consensus key always agree on the peer id.
fn net_keypair(address: &Address) -> arc_malachitebft_app::types::Keypair {
    let net_key = PrivateKey::from(net_seed(address));
    arc_malachitebft_app::types::Keypair::ed25519_from_bytes(net_key.inner().to_bytes())
        .expect("net key is a valid ed25519 seed")
}

/// The libp2p peer id a node running consensus `public_key` presents,
/// rendered base58 — the form a `/p2p/<peer_id>` multiaddr component
/// carries. The network identity is derived deterministically from the
/// consensus key, so a peer pin naming the consensus key authenticates
/// exactly this id — no separate peer-id directory is needed.
pub fn net_peer_id(public_key: &PublicKey) -> String {
    net_keypair(&Address::from_public_key(public_key))
        .public()
        .to_peer_id()
        .to_base58()
}

/// Wire/WAL format epoch: bumped when the consensus codec's persisted
/// shape changes incompatibly. `wal/FORMAT` records the epoch a WAL was
/// written under; a mismatch — or a non-empty WAL with no marker —
/// means the log predates this binary and must be reset. Committed
/// state is safe either way: it lives in the journal and store, never
/// in the WAL.
const WAL_FORMAT: &[u8; 4] = b"VRW2";

/// Fail fast — with an actionable message — before the engine's WAL
/// replay can hit a cryptic codec error mid-stream and safety-hang.
fn check_wal_format(wal_path: &Path) {
    let marker = wal_path.parent().unwrap().join("FORMAT");
    match std::fs::read(&marker) {
        Ok(bytes) if bytes == WAL_FORMAT => {}
        Ok(bytes) => panic!(
            "WAL format mismatch at {}: marker {:?} was written by a different wire format \
             (this binary writes {:?}). Committed state is durable in the journal and store — \
             remove {} to restart on a fresh WAL.",
            marker.display(),
            String::from_utf8_lossy(&bytes),
            String::from_utf8_lossy(WAL_FORMAT),
            wal_path.display(),
        ),
        Err(_) => {
            // No marker: a non-empty WAL predates format epochs — its
            // entries cannot replay under this codec.
            let legacy = std::fs::metadata(wal_path).is_ok_and(|m| m.len() > 0);
            std::fs::create_dir_all(wal_path.parent().unwrap()).unwrap();
            if legacy {
                panic!(
                    "WAL at {} predates format versioning and cannot be replayed by this binary. \
                     Committed state is durable in the journal and store — remove it to restart \
                     on a fresh WAL.",
                    wal_path.display()
                );
            }
            std::fs::write(&marker, WAL_FORMAT).expect("wal format marker write");
        }
    }
}

/// Rebuild the sync-servable decided history from the durable journal:
/// every height marker resolves to a bundle carrying the canonical `VC2`
/// certificate and the committed batch, which together reconstruct the
/// `RawDecidedValue` a `GetDecidedValues` answer needs. A restarted node
/// must still serve heights its peers may not have reached — memory was
/// empty, the journal was not.
fn load_decided(
    adapter: &Adapter<vhalla_journal::FsStore>,
) -> BTreeMap<u64, RawDecidedValue<RoomContext>> {
    let mut decided = BTreeMap::new();
    for h in 1..=adapter.frontier().height {
        let Some(bundle) = adapter.committed_at_height(h) else {
            continue;
        };
        let (Some(cert_raw), Some(batch_raw)) = (bundle.field(0), bundle.field(3)) else {
            continue;
        };
        let (Some(cert), Ok(batch)) = (
            ext_certificate_from_canonical(cert_raw),
            Batch::decode(batch_raw),
        ) else {
            tracing::warn!(
                height = h,
                "journal bundle at committed height failed to decode — sync history gap"
            );
            continue;
        };
        let value = RoomValue::new(batch.value_id(), batch.encode().into());
        decided.insert(
            h,
            RawDecidedValue::new(RoomCodec::encode_value(&value), cert),
        );
    }
    if !decided.is_empty() {
        tracing::info!(
            heights = decided.len(),
            tip = adapter.frontier().height,
            "rebuilt decided history from journal"
        );
    }
    decided
}

/// How often the intake dir is polled while a `GetValue` reply is held.
/// A held reply parks the app-channel connector on its oneshot, so no
/// further `GetValue` arrives to drain intake — the poll is what lets a
/// cross-process producer's file resolve the stall.
const HELD_REPLY_POLL_MS: u64 = 250;

/// How long an incomplete proposal stream may linger before expiry.
/// Far beyond any publish pacing; a stream abandoned by a dead
/// connection can never assemble — a peer that still needs it
/// re-requests the parts and a fresh stream begins.
const STREAM_STALE: std::time::Duration = std::time::Duration::from_secs(60);

/// Cap on the observability latency ring — one entry per decided/finalized
/// height would otherwise grow without bound over the node's lifetime.
const BOUNDARY_LATENCY_CAP: usize = 4096;

/// Push one boundary-latency sample, dropping the oldest once past the cap.
fn push_boundary(latency: &Arc<Mutex<Vec<(u64, u128)>>>, height: u64, t0: std::time::Instant) {
    let mut v = latency.lock().unwrap();
    v.push((height, t0.elapsed().as_nanos()));
    if v.len() > BOUNDARY_LATENCY_CAP {
        let excess = v.len() - BOUNDARY_LATENCY_CAP;
        v.drain(..excess);
    }
}

/// Delay between proposal-part publishes. Gossipsub coalesces messages
/// queued within one swarm poll into a single RPC frame, and the tailcat
/// tunnel truncates any single TCP write above ~1.1KB — an un-paced part
/// burst dies on the wire. Yielding between sends gives each part its own
/// wire frame.
const PART_PUBLISH_SPACING: Duration = Duration::from_millis(20);

/// Publish one proposal-part stream (`parts` then `Fin`), spacing sends so
/// each message becomes its own wire write. Returns false when the network
/// channel is closed.
async fn send_part_stream(
    app: &mut App,
    channels: &mut Channels<RoomContext>,
    height: Height,
    round: Round,
    parts: &[RoomPart],
) -> bool {
    let stream_id = app.stream_id(height, round);
    let mut sequence = 0u64;
    for part in parts {
        let msg = StreamMessage::new(
            stream_id.clone(),
            sequence,
            StreamContent::Data(part.clone()),
        );
        sequence += 1;
        if channels
            .network
            .send(NetworkMsg::PublishProposalPart(msg))
            .await
            .is_err()
        {
            return false;
        }
        tokio::time::sleep(PART_PUBLISH_SPACING).await;
    }
    let fin = StreamMessage::new(stream_id, sequence, StreamContent::Fin);
    channels
        .network
        .send(NetworkMsg::PublishProposalPart(fin))
        .await
        .is_ok()
}

/// Build, cache, and publish the chunked parts stream for a locally
/// proposed value: `Init`, bounded `Data` chunks, `Fin`, then the stream
/// terminator. Returns false when the network channel is closed and the
/// node is shutting down.
async fn publish_local_parts(
    app: &mut App,
    channels: &mut Channels<RoomContext>,
    height: Height,
    round: Round,
    proposed: &LocallyProposedValue<RoomContext>,
) -> bool {
    let value_id = proposed.value.id;
    let parts = app.build_parts(proposed);
    if let RoomPart::Init(init) = &parts[0] {
        app.record_seen(init, value_id);
    }
    app.parts_cache.insert(value_id, parts.clone());
    send_part_stream(app, channels, height, round, &parts).await
}

/// Answer every held `GetValue` whose value now exists, publishing the
/// parts stream for each reply the engine is still awaiting. Returns
/// false when the network channel is closed.
async fn flush_held(app: &mut App, channels: &mut Channels<RoomContext>) -> bool {
    for req in app.drain_answerable_held() {
        let height = Height::new(req.height);
        let proposed = LocallyProposedValue::new(height, req.round, req.value);
        if req.reply.send(proposed.clone()).is_err() {
            continue;
        }
        // Tombstone replies un-park the connector only — their parts stay
        // off the wire so the empty value can never assemble and commit.
        if req.live && !publish_local_parts(app, channels, height, req.round, &proposed).await {
            return false;
        }
    }
    true
}

/// The application boundary loop: every reply that authorizes engine
/// progress is sent only after the durable layer permits it. Local batch
/// submissions interleave with engine messages on the same loop so the
/// proposal queue is never touched concurrently.
async fn run(
    app: &mut App,
    channels: &mut Channels<RoomContext>,
    submissions: &mut tokio::sync::mpsc::Receiver<Batch>,
) {
    /// Either side of the loop's select: a consensus `AppMsg`, a local
    /// batch submission, or the held-reply intake poll.
    enum Feed {
        Msg(Option<AppMsg<RoomContext>>),
        Submit(Option<Batch>),
        Tick,
    }
    let mut submissions_open = true;
    let mut held_tick = tokio::time::interval(std::time::Duration::from_millis(HELD_REPLY_POLL_MS));
    held_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let feed = if submissions_open {
            tokio::select! {
                msg = channels.consensus.recv() => Feed::Msg(msg),
                batch = submissions.recv() => Feed::Submit(batch),
                _ = held_tick.tick() => Feed::Tick,
            }
        } else {
            tokio::select! {
                msg = channels.consensus.recv() => Feed::Msg(msg),
                _ = held_tick.tick() => Feed::Tick,
            }
        };
        let msg = match feed {
            Feed::Submit(Some(batch)) => {
                app.submit(batch);
                // A newly valid submission may resolve a held `GetValue`.
                if !flush_held(app, channels).await {
                    return;
                }
                continue;
            }
            Feed::Submit(None) => {
                // The last sender dropped: keep serving consensus.
                submissions_open = false;
                continue;
            }
            Feed::Tick => {
                // Streams a dead connection abandoned can never assemble
                // — expire them whether or not anything else is pending.
                app.expire_streams();
                // While a `GetValue` reply is held the connector is
                // parked, so cross-process intake files would otherwise
                // never be drained to resolve it.
                if !app.held_replies.is_empty() {
                    app.drain_intake();
                    if !flush_held(app, channels).await {
                        return;
                    }
                }
                continue;
            }
            Feed::Msg(None) => return,
            Feed::Msg(Some(msg)) => msg,
        };
        match msg {
            AppMsg::ConsensusReady { reply } => {
                // Resume from the DURABLE frontier — the journal is the
                // authority on the next height, not memory.
                let next = app.adapter.lock().unwrap().frontier().height + 1;
                let _ = reply.send((Height::new(next), height_params(app.set_for(next))));
            }

            AppMsg::StartedRound {
                height,
                reply_value,
                ..
            } => {
                // Resupply undecided values from the application-owned
                // store: every proposal this node observed at the height
                // — locally proposed or received and verified — survives
                // restart under `store/`, so the engine gets the real
                // `ProposedValue`s back (WAL restores votes; the store
                // restores the content those votes locked on).
                let resupplied = app.resupply_for(height);
                *app.resupplied.lock().unwrap() += resupplied.len() as u64;
                let _ = reply_value.send(resupplied);
            }

            AppMsg::GetValue {
                height,
                round,
                timeout,
                reply,
            } => {
                // Cross-process submissions land here: drain the intake
                // dir before assigning this height's proposal.
                app.drain_intake();
                // No pre-planned batch for this height: assign the
                // oldest committable submission — bodies assemble here
                // against the live frontier; a losing height requeues.
                if !app.proposals.contains_key(&height.as_u64()) {
                    if let Some(id) = app.next_pending() {
                        app.proposals.insert(height.as_u64(), id);
                    }
                }
                let deadline = std::time::Instant::now()
                    .checked_add(timeout)
                    .unwrap_or_else(|| {
                        std::time::Instant::now() + std::time::Duration::from_secs(60)
                    });
                let Some(value_id) = app.proposals.get(&height.as_u64()).copied() else {
                    // Nothing held for this height: hold the reply open
                    // rather than drop it — a dropped oneshot kills the
                    // host connector. The request's own deadline bounds
                    // the hold; past it the reply resolves as a tombstone.
                    app.held_replies.push(HeldReply {
                        height: height.as_u64(),
                        round,
                        deadline,
                        reply,
                    });
                    continue;
                };
                let Some(batch) = app.held_by_id.get(&value_id).cloned() else {
                    app.held_replies.push(HeldReply {
                        height: height.as_u64(),
                        round,
                        deadline,
                        reply,
                    });
                    continue;
                };
                // Older held requests may resolve against the queue state
                // this materialization leaves behind — answer them first.
                if !flush_held(app, channels).await {
                    return;
                }
                let value = RoomValue::new(batch.value_id(), batch.encode().into());
                let proposed = LocallyProposedValue::new(height, round, value);
                let _ = reply.send(proposed.clone());
                if !publish_local_parts(app, channels, height, round, &proposed).await {
                    return;
                }
            }

            AppMsg::ReceivedProposalPart { from, part, reply } => {
                let _ = reply.send(app.handle_part(from, part));
            }

            AppMsg::Decided {
                certificate,
                extensions,
                reply,
                ..
            } => {
                let t0 = std::time::Instant::now();
                let outcome = app.decide(&certificate);
                {
                    let mut sink = app.sink.lock().unwrap();
                    if matches!(outcome, DecidedOutcome::Acked) {
                        sink.send(vhalla_rooms_consensus::EngineMsg::CommitAck {
                            height: certificate.height.as_u64(),
                        });
                    }
                }
                push_boundary(&app.boundary_latency, certificate.height.as_u64(), t0);
                if matches!(outcome, DecidedOutcome::Acked) {
                    // Serve the decided value to syncing peers now — do
                    // not wait for `Finalized`, which may lag or never
                    // arrive when a target time is configured.
                    app.record_decided(&certificate, extensions);
                    // The engine is acknowledged ONLY after the durable
                    // commit lands; any other outcome withholds the reply —
                    // the failed oneshot is the honest stall.
                    let _ = reply.send(());
                }
            }

            AppMsg::Finalized {
                certificate,
                extensions,
                reply,
                ..
            } => {
                let t0 = std::time::Instant::now();
                let outcome = app.decide(&certificate);
                {
                    let mut sink = app.sink.lock().unwrap();
                    if matches!(outcome, DecidedOutcome::Acked) {
                        sink.send(vhalla_rooms_consensus::EngineMsg::NextHeightReply {
                            height: certificate.height.as_u64() + 1,
                        });
                    }
                }
                push_boundary(&app.boundary_latency, certificate.height.as_u64(), t0);
                let height = certificate.height;
                // The NEXT height's params may activate a different set —
                // this is the finalized configuration transition.
                let params = height_params(app.set_for(height.as_u64() + 1));
                if matches!(outcome, DecidedOutcome::Acked) {
                    // Idempotent after the `Decided`-arm record — the
                    // extended certificate may carry more signatures.
                    app.record_decided(&certificate, extensions);
                    let _ = reply.send(Next::Start(height.increment(), params));
                } else {
                    let _ = reply.send(Next::Restart(height, params));
                }
            }

            AppMsg::ProcessSyncedValue {
                height,
                round,
                proposer,
                value_bytes,
                reply,
            } => {
                let outcome = match RoomCodec::decode_value(value_bytes) {
                    Ok(value) => SyncedValueOutcome::Verdict(ProposedValue {
                        height,
                        round,
                        valid_round: Round::Nil,
                        proposer,
                        validity: app.verdict_for(&value),
                        value,
                    }),
                    Err(_) => SyncedValueOutcome::PeerFault,
                };
                let _ = reply.send(outcome);
            }

            AppMsg::GetDecidedValues { range, reply } => {
                let values = app
                    .decided
                    .range(range.start().as_u64()..=range.end().as_u64())
                    .map(|(_, v)| v.clone())
                    .collect();
                let _ = reply.send(values);
            }

            AppMsg::GetHistoryMinHeight { reply } => {
                let _ = reply.send(Height::new(1));
            }

            AppMsg::RestreamProposal {
                height,
                round,
                value_id,
                ..
            } => match app.parts_cache.get(&value_id).cloned() {
                Some(parts) => {
                    if !send_part_stream(app, channels, height, round, &parts).await {
                        return;
                    }
                }
                None => {
                    tracing::debug!(
                        %height, %round, value_id = %hex(&value_id.0),
                        "restream requested for a value no longer cached"
                    );
                }
            },

            AppMsg::ExtendVote { reply, .. } => {
                let _ = reply.send(None);
            }

            AppMsg::VerifyVoteExtension { reply, .. } => {
                let _ = reply.send(Ok(()));
            }
        }
    }
}

/// A configured persistent peer. `key`, when present, is the peer
/// node's consensus public key: the node's libp2p identity is derived
/// deterministically from it (`net_peer_id`), so the persistent-peer
/// multiaddr carries a `/p2p/<peer_id>` component and the dial
/// authenticates that identity during the Noise handshake — a host at
/// the address presenting any other identity is rejected, and an
/// impostor at the address never inherits persistent-peer priority.
/// Without `key` the address alone is dialed and any peer there is
/// accepted, as before.
pub struct PeerSpec {
    /// IPv4 host literal (the multiaddr is `/ip4/{host}/tcp/{port}`).
    pub host: String,
    /// TCP port.
    pub port: usize,
    /// Optional consensus-key pin authenticating the peer's identity.
    pub key: Option<PublicKey>,
}

/// Service config for a hosted validator: libp2p TCP listening on
/// `listen` at `listen_port`, persistent peering to `peers`, value sync
/// enabled. This is the same shape `node_config` produces for tests,
/// without the index-derived ports.
///
/// A loopback `listen` keeps the per-IP connection ceiling lifted so a
/// single-host validator set still meshes; any other bind address keeps
/// malachite's default per-IP bound. `listen` is a bare host — an IP or
/// resolvable name — never `host:port`; the port is `listen_port`.
///
/// `peers_only` closes the mesh: connections to and from peers outside
/// the persistent set are rejected. It only makes sense when every peer
/// carries a key pin — an unpinned address cannot authenticate an
/// inbound peer (ephemeral source ports never match), so the config
/// layer rejects that combination before this is ever called.
pub fn service_config(
    moniker: &str,
    listen: &str,
    listen_port: usize,
    peers: &[PeerSpec],
    peers_only: bool,
) -> Config {
    let transport = TransportProtocol::Tcp;
    let loopback = listen
        .parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(listen == "localhost");
    Config {
        moniker: moniker.to_owned(),
        consensus: ConsensusConfig {
            value_payload: ValuePayload::ProposalAndParts,
            queue_capacity: 100,
            p2p: P2pConfig {
                protocol: PubSubProtocol::default(),
                discovery: DiscoveryConfig {
                    max_connections_per_ip: if loopback {
                        usize::MAX
                    } else {
                        DiscoveryConfig::default().max_connections_per_ip
                    },
                    ..DiscoveryConfig::default()
                },
                listen_addr: transport.multiaddr(listen, listen_port),
                persistent_peers: peers
                    .iter()
                    .map(|p| {
                        let addr = transport.multiaddr(&p.host, p.port);
                        match &p.key {
                            Some(key) => format!("{addr}/p2p/{}", net_peer_id(key))
                                .parse()
                                .expect("pinned multiaddr"),
                            None => addr,
                        }
                    })
                    .collect(),
                persistent_peers_only: peers_only,
                ..Default::default()
            },
            ..Default::default()
        },
        value_sync: ValueSyncConfig {
            enabled: true,
            status_update_interval: std::time::Duration::from_secs(2),
            request_timeout: std::time::Duration::from_secs(5),
            ..Default::default()
        },
    }
}

/// Node config: real libp2p TCP on localhost with full persistent-peering.
pub fn node_config(node: usize, nodes: usize, base_port: usize) -> Config {
    let transport = TransportProtocol::Tcp;
    let i = node - 1;
    Config {
        moniker: format!("room-node-{node}"),
        consensus: ConsensusConfig {
            value_payload: ValuePayload::ProposalAndParts,
            queue_capacity: 100,
            p2p: P2pConfig {
                protocol: PubSubProtocol::default(),
                discovery: DiscoveryConfig {
                    max_connections_per_ip: usize::MAX,
                    ..DiscoveryConfig::default()
                },
                listen_addr: transport.multiaddr("127.0.0.1", base_port + i),
                persistent_peers: (0..nodes)
                    .filter(|j| *j != i)
                    .map(|j| transport.multiaddr("127.0.0.1", base_port + j))
                    .collect(),
                ..Default::default()
            },
            ..Default::default()
        },
        value_sync: ValueSyncConfig {
            enabled: true,
            status_update_interval: std::time::Duration::from_secs(2),
            request_timeout: std::time::Duration::from_secs(5),
            ..Default::default()
        },
    }
}

#[cfg(test)]
mod tests;
