//! The hosted room node: Malachite engines on libp2p networking deciding
//! room-registry batches, with the `Decided`/`Finalized` application
//! boundary gated by the durable commit journal in
//! `vhalla-rooms-consensus`.
//!
//! Every node runs the full `EngineBuilder` stack (network, consensus,
//! sync, request, WAL actors) under [`context::RoomContext`] — the
//! context whose `Value` carries the bounded canonical batch bytes and
//! whose `ValueId` IS the batch's 32-byte value commitment. Proposal
//! parts stream the real batch bytes; `Decided`/`Finalized` certificates
//! name the real commitment and pass through [`cert::verify_commit_certificate`]
//! and the journal before the reply channel is touched. No
//! acknowledgement leaves the node before the durable commit lands.
//!
//! Undecided proposals replay from an application-owned store:
//! `home/store/batches/` retains every verified batch (fsync'd on
//! receipt) and `home/store/seen/` retains one record per observed
//! proposal (height, round, proposer -> value id + polka round), so a
//! restarted node answers `StartedRound` with the real `ProposedValue`s
//! it held rather than an empty set — the WAL restores votes, this
//! store restores the value content those votes locked on.
//!
//! `NetGate`, `WalPlan`/`WalFault` and the observation surfaces on
//! [`RoomNode`] are the qualification harness: they drive the runtime
//! partition, WAL fault-injection, and latency/resupply evidence in
//! `tests.rs`.

pub mod cert;
pub mod codec;
pub mod context;
pub mod signing;

pub use codec::RoomCodec;
pub use context::*;

use std::collections::{BTreeMap, VecDeque};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use arc_malachitebft_app::config::NodeConfig;
use arc_malachitebft_app::spawn::spawn_wal_actor;
use arc_malachitebft_app::types::codec::Codec;
use arc_malachitebft_app::types::core::Validity;
use arc_malachitebft_app::types::sync::RawDecidedValue;
use arc_malachitebft_app::types::{LocallyProposedValue, PeerId, ProposedValue};
use arc_malachitebft_app_channel::{
    AppMsg, Channels, ConsensusContext, EngineBuilder, EngineHandle, NetworkContext, NetworkMsg,
    RequestContext, SyncContext, WalContext,
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
    Adapter, Batch, CommitCertificate as RoomCertificate, DecidedOutcome, EngineSink, Genesis,
};

use crate::cert::verify_commit_certificate;
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
/// until the `StreamContent::Fin` marker closes the stream.
#[derive(Default)]
struct StreamState {
    init: Option<ProposalInit>,
    data: Vec<u8>,
    fin: Option<ProposalFin>,
    closed: bool,
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

    /// The validity verdict for a wire-received value: the canonical bytes
    /// must decode to a `Batch` that validates against the current pinned
    /// frontier — and its `value_id` must match the proposed commitment.
    fn verdict_for(&mut self, value: &RoomValue) -> Validity {
        let Ok(batch) = Batch::decode(&value.bytes) else {
            return Validity::Invalid;
        };
        if batch.value_id() != value.id.0 {
            return Validity::Invalid;
        }
        if self
            .adapter
            .lock()
            .unwrap()
            .application()
            .validate(&batch)
            .is_err()
        {
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
    /// bytes: `Init`, one `Data` part with the full bounded encoding, and
    /// `Fin` signing `"RF1" || height || round || keccak256(data)`.
    fn build_parts(&mut self, proposed: &LocallyProposedValue<RoomContext>) -> Vec<RoomPart> {
        let data = proposed.value.bytes.clone();
        let mut parts = vec![
            RoomPart::Init(ProposalInit {
                height: proposed.height,
                round: proposed.round,
                pol_round: Round::Nil,
                proposer: self.address,
            }),
            RoomPart::Data(data.clone()),
        ];
        let signature = RoomSigner::new(self.private_key.clone()).sign(&fin_sign_bytes(
            proposed.height,
            proposed.round,
            &data,
        ));
        parts.push(RoomPart::Fin(ProposalFin { signature }));
        parts
    }

    /// Fold a completed stream into `AssembledParts`: exactly `Init`,
    /// `Data`*, `Fin`, in that order.
    fn assemble(state: StreamState) -> Option<AssembledParts> {
        Some(AssembledParts {
            init: state.init?,
            data: state.data,
            fin: state.fin?,
        })
    }

    /// Consume one streamed proposal part. Parts are stored by kind, not
    /// by sequence number — Init/Data/Fin may arrive in any order, and
    /// the transport `StreamContent::Fin` marker triggers assembly.
    /// Returns the complete `ProposedValue` once the stream closes, or
    /// `None` while the stream is incomplete or was closed oversized.
    fn handle_part(
        &mut self,
        from: PeerId,
        part: StreamMessage<RoomPart>,
    ) -> Option<ProposedValue<RoomContext>> {
        let key = (from.to_bytes(), part.stream_id.to_bytes().to_vec());
        let state = self.streams.entry(key.clone()).or_default();
        let done = match part.content {
            StreamContent::Data(RoomPart::Init(init)) => {
                state.init = Some(init);
                false
            }
            StreamContent::Data(RoomPart::Data(data)) => {
                if state.data.len() + data.len() > crate::MAX_VALUE_BYTES {
                    state.closed = true;
                } else {
                    state.data.extend_from_slice(&data);
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
                self.parts_cache.insert(
                    value.id,
                    vec![
                        RoomPart::Init(assembled.init.clone()),
                        RoomPart::Data(assembled.data.clone().into()),
                        RoomPart::Fin(assembled.fin.clone()),
                    ],
                );
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
        self.adapter.lock().unwrap().decide(&RoomCertificate {
            bytes: accepted.bytes,
            value_commitment: accepted.value_id.0,
            height: accepted.height,
        })
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
        let net_key = PrivateKey::from(net_seed(&address));
        let keypair =
            arc_malachitebft_app::types::Keypair::ed25519_from_bytes(net_key.inner().to_bytes())
                .unwrap();
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
        let (mut held_by_id, seen) = load_store(&store);
        let loaded = (held_by_id.len(), seen.values().map(Vec::len).sum());

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
        // Reloaded batches also re-enter the adapter's pending map so a
        // certificate for a pre-crash received value can still land.
        for batch in held_by_id.values() {
            adapter.lock().unwrap().hold(batch.clone());
        }
        let resupplied = Arc::new(Mutex::new(0u64));

        let mut app = App {
            ctx: RoomContext,
            adapter: Arc::clone(&adapter),
            sink: Arc::clone(&sink),
            validator_sets,
            address,
            private_key: node_key.clone(),
            proposals,
            held_by_id,
            streams: BTreeMap::new(),
            parts_cache: BTreeMap::new(),
            decided: BTreeMap::new(),
            stream_seq: 0,
            boundary_latency: Arc::clone(&boundary_latency),
            store,
            seen,
            resupplied: Arc::clone(&resupplied),
        };

        let task = tokio::spawn(async move { run(&mut app, &mut channels).await });

        RoomNode {
            home,
            adapter,
            sink,
            address,
            boundary_latency,
            resupplied,
            loaded,
            gate: net_gate,
            task,
            _engine: engine,
            inner_wal,
            inner_net,
        }
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

fn net_seed(address: &Address) -> [u8; 32] {
    let inner = address.into_inner();
    let mut seed = [0xA5; 32];
    let n = inner.len().min(32);
    seed[..n].copy_from_slice(&inner[..n]);
    seed
}

/// The application boundary loop: every reply that authorizes engine
/// progress is sent only after the durable layer permits it.
async fn run(app: &mut App, channels: &mut Channels<RoomContext>) {
    while let Some(msg) = channels.consensus.recv().await {
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
                reply,
                ..
            } => {
                let Some(value_id) = app.proposals.get(&height.as_u64()).copied() else {
                    // Nothing held for this height: stall rather than
                    // invent a value. The timeout will prevote nil.
                    continue;
                };
                let Some(batch) = app.held_by_id.get(&value_id).cloned() else {
                    continue;
                };
                let value = RoomValue::new(batch.value_id(), batch.encode().into());
                let proposed = LocallyProposedValue::new(height, round, value);
                let _ = reply.send(proposed.clone());

                let parts = app.build_parts(&proposed);
                if let RoomPart::Init(init) = &parts[0] {
                    app.record_seen(init, value_id);
                }
                app.parts_cache.insert(value_id, parts.clone());
                let stream_id = app.stream_id(height, round);
                let mut sequence = 0u64;
                for part in &parts {
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
                        return;
                    }
                }
                let fin = StreamMessage::new(stream_id, sequence, StreamContent::Fin);
                let _ = channels
                    .network
                    .send(NetworkMsg::PublishProposalPart(fin))
                    .await;
            }

            AppMsg::ReceivedProposalPart { from, part, reply } => {
                let _ = reply.send(app.handle_part(from, part));
            }

            AppMsg::Decided {
                certificate, reply, ..
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
                app.boundary_latency
                    .lock()
                    .unwrap()
                    .push((certificate.height.as_u64(), t0.elapsed().as_nanos()));
                // The engine is acknowledged ONLY after the durable
                // commit lands; any other outcome withholds the reply —
                // the failed oneshot is the honest stall.
                if matches!(outcome, DecidedOutcome::Acked) {
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
                app.boundary_latency
                    .lock()
                    .unwrap()
                    .push((certificate.height.as_u64(), t0.elapsed().as_nanos()));
                let height = certificate.height;
                // The NEXT height's params may activate a different set —
                // this is the finalized configuration transition.
                let params = height_params(app.set_for(height.as_u64() + 1));
                if matches!(outcome, DecidedOutcome::Acked) {
                    if let Some(batch) = app.held_by_id.get(&certificate.value_id) {
                        let value = RoomValue::new(batch.value_id(), batch.encode().into());
                        let value_bytes = RoomCodec::encode_value(&value);
                        app.decided.insert(
                            height.as_u64(),
                            RawDecidedValue::new(
                                value_bytes,
                                arc_malachitebft_app::types::core::ExtendedCommitCertificate::from_commit_certificate_and_extensions(
                                    certificate.clone(), extensions,
                                ),
                            ),
                        );
                    }
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
            } => {
                if let Some(parts) = app.parts_cache.get(&value_id).cloned() {
                    let stream_id = app.stream_id(height, round);
                    let mut sequence = 0u64;
                    for part in &parts {
                        let msg = StreamMessage::new(
                            stream_id.clone(),
                            sequence,
                            StreamContent::Data(part.clone()),
                        );
                        sequence += 1;
                        let _ = channels
                            .network
                            .send(NetworkMsg::PublishProposalPart(msg))
                            .await;
                    }
                    let fin = StreamMessage::new(stream_id, sequence, StreamContent::Fin);
                    let _ = channels
                        .network
                        .send(NetworkMsg::PublishProposalPart(fin))
                        .await;
                }
            }

            AppMsg::ExtendVote { reply, .. } => {
                let _ = reply.send(None);
            }

            AppMsg::VerifyVoteExtension { reply, .. } => {
                let _ = reply.send(Ok(()));
            }
        }
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
