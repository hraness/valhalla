//! Bounded, read-only diagnostics for the crash/rejoin test. Never read
//! WAL contents or print keys, batch bodies, or absolute home paths.

use super::*;
use std::io::Read;

// Only this test's four fixed listener ports are inspected. /proc/net/tcp*
// reports TCP sockets from the network namespace, not authenticated Malachite
// peers or even necessarily sockets owned by this test. Client ports are
// ephemeral, so port direction does not establish who initiated a connection.
pub(super) const PORT_BASE: u16 = 27300;

#[derive(Default)]
struct SocketSummary {
    listeners: [bool; 4],
    established_local: [bool; 4],
    established_remote: [bool; 4],
}

impl SocketSummary {
    fn port_index(endpoint: &str) -> Option<usize> {
        let hex_port = endpoint.rsplit_once(':')?.1;
        let port = u16::from_str_radix(hex_port, 16).ok()?;
        let index = usize::from(port.checked_sub(PORT_BASE)?);
        (index < 4).then_some(index)
    }

    fn observe(&mut self, table: &str) {
        for line in table.lines().skip(1) {
            let mut fields = line.split_ascii_whitespace();
            let (Some(_slot), Some(local), Some(remote), Some(state)) =
                (fields.next(), fields.next(), fields.next(), fields.next())
            else {
                continue;
            };
            match state {
                "0A" => {
                    if let Some(local) = Self::port_index(local) {
                        self.listeners[local] = true;
                    }
                }
                "01" => {
                    if let Some(local) = Self::port_index(local) {
                        self.established_local[local] = true;
                    }
                    if let Some(remote) = Self::port_index(remote) {
                        self.established_remote[remote] = true;
                    }
                }
                _ => {}
            }
        }
    }

    fn report(&self, families: usize) -> String {
        format!(
            "tcp_families={families} listeners={:?} established_local={:?} established_remote={:?}",
            self.listeners, self.established_local, self.established_remote
        )
    }
}

#[cfg(target_os = "linux")]
fn socket_trace() -> String {
    const MAX_TABLE: u64 = 1_048_576;
    let mut summary = SocketSummary::default();
    let mut families = 0;
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(error)
                if path.ends_with("tcp6") && error.kind() == std::io::ErrorKind::NotFound =>
            {
                continue;
            }
            Err(_) => return "tcp=unavailable".into(),
        };
        let mut table = String::new();
        if file.take(MAX_TABLE + 1).read_to_string(&mut table).is_err() {
            return "tcp=unavailable".into();
        }
        if table.len() as u64 > MAX_TABLE {
            return "tcp=unavailable (table exceeds 1 MiB)".into();
        }
        summary.observe(&table);
        families += 1;
    }
    summary.report(families)
}

#[cfg(not(target_os = "linux"))]
fn socket_trace() -> String {
    "tcp=unavailable (not Linux)".into()
}

// A marker can change between metadata and read. Cap the diagnostic read at
// one byte past the expected format so even a replaced file stays bounded.
fn wal_marker_matches(path: &Path) -> bool {
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let mut bytes = Vec::with_capacity(WAL_FORMAT.len() + 1);
    file.take((WAL_FORMAT.len() + 1) as u64)
        .read_to_end(&mut bytes)
        .is_ok_and(|_| bytes.as_slice() == WAL_FORMAT)
}

fn home(label: &str, path: &Path) {
    // `recover()` mutates journal residue; NEVER call it on a live writer.
    let journal = vhalla_journal::Journal::new(path.join("app/journal"), vhalla_journal::FsStore);
    let indexed: Vec<_> = (1..=4)
        .map(|h| match journal.at_height(h) {
            Ok(Some(id)) => format!("{h}:{}", hex(&id[..8])),
            Ok(None) => format!("{h}:-"),
            Err(_) => format!("{h}:error"),
        })
        .collect();
    let wal_bytes = std::fs::metadata(path.join("wal/consensus.wal"))
        .map(|m| m.len())
        .ok();
    let wal_format_ok = wal_marker_matches(&path.join("wal/FORMAT"));
    // 4097 signals an overflow; no unbounded listing or filename disclosure.
    let count = |dir: &str| {
        std::fs::read_dir(path.join(dir))
            .map(|entries| entries.take(4097).count())
            .ok()
    };
    println!(
        "rejoin {label}: journal_index={indexed:?} wal_bytes={wal_bytes:?} wal_format_ok={wal_format_ok} batches={:?} seen={:?}",
        count("store/batches"),
        count("store/seen")
    );
}

/// Read only the four test heights. Check each indexed bundle's identity,
/// height and predecessor link, including the fixture's genesis frontier;
/// never run writer-side `recover()` on a live node. Keep full identities in
/// the assertion, not in diagnostic output.
pub(super) fn committed_chain(path: &Path, through: u64) -> Vec<([u8; 32], [u8; 32])> {
    assert!((1..=4).contains(&through));
    let journal = vhalla_journal::Journal::new(path.join("app/journal"), vhalla_journal::FsStore);
    let genesis_next = batch_plan(1)
        .get(&1)
        .expect("rejoin fixture has a first batch")
        .parent
        .commitment();
    let mut chain: Vec<([u8; 32], [u8; 32])> = Vec::with_capacity(through as usize);
    for h in 1..=through {
        let id = journal
            .at_height(h)
            .expect("journal height marker readable")
            .unwrap_or_else(|| panic!("missing journal height marker at {h}"));
        let bundle = journal
            .bundle(id)
            .expect("indexed journal bundle valid")
            .unwrap_or_else(|| panic!("missing indexed journal bundle at {h}"));
        assert_eq!(bundle.height(), h, "indexed bundle at wrong height");
        let expected_predecessor = chain.last().map_or(genesis_next, |(_, next)| *next);
        assert!(
            bundle.predecessor() == expected_predecessor,
            "journal predecessor mismatch at height {h}"
        );
        chain.push((id, bundle.next()));
    }
    chain
}

/// A read-only call to the same journal-backed page builder the sync host
/// uses. This establishes local serveability, NOT that a peer requested or
/// received a page. Never print the error: it can contain a home path.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum LocalHistory {
    Empty,
    Values(usize),
    Unavailable,
}

fn classify_history<T, E>(result: Result<Vec<T>, E>) -> LocalHistory {
    match result {
        Ok(values) if values.is_empty() => LocalHistory::Empty,
        Ok(values) => LocalHistory::Values(values.len()),
        Err(_) => LocalHistory::Unavailable,
    }
}

pub(super) fn local_history(node: &RoomNode, start: u64, end: u64) -> LocalHistory {
    // read_decided_range clamps to the applied frontier, bounds the page to
    // 32 values / 2 MiB, and never invokes journal recovery or changes files.
    let adapter = node.adapter.lock().unwrap();
    classify_history(read_decided_range(&adapter, start, end))
}

fn node(label: &str, node: &RoomNode) {
    let frontier = node.adapter.lock().unwrap().frontier();
    // Snapshot the ack evidence without holding the sink mutex across other
    // locks, logging, or filesystem reads; the engine needs it to record acks.
    let (ack_counts, ack_total) = {
        let acks = node.sink.lock().unwrap();
        let counts: Vec<_> = (1..=4)
            .map(|h| {
                acks.sent
                    .iter()
                    .filter(|m| match m {
                        vhalla_rooms_consensus::EngineMsg::CommitAck { height } => *height == h,
                        vhalla_rooms_consensus::EngineMsg::NextHeightReply { height } => {
                            height.checked_sub(1) == Some(h)
                        }
                    })
                    .count()
            })
            .collect();
        (counts, acks.sent.len())
    };
    let resupplied = *node.resupplied.lock().unwrap();
    // The fixed h3-h4 window reports Empty and Unavailable separately. A
    // positive count is source readiness, not proof of wire delivery.
    let history_h3_h4 = local_history(node, 3, 4);
    println!(
        "rejoin {label}: frontier={} commitment={} ack_counts={ack_counts:?} ack_total={} resupplied={} loaded={:?} local_history_h3_h4={history_h3_h4:?} app_done={} engine_done={}",
        frontier.height,
        hex(&frontier.commitment()[..8]),
        ack_total,
        resupplied,
        node.loaded,
        node.task.is_finished(),
        node._engine.handle.is_finished()
    );
    home(label, &node.home);
}

fn trace(stage: &str, peers: &[RoomNode], first_peer: usize, restarted: Option<&RoomNode>) {
    println!("rejoin stage={stage} {}", socket_trace());
    if let Some(restarted) = restarted {
        node("n1", restarted);
    }
    for (i, peer) in peers.iter().enumerate() {
        node(&format!("n{}", i + first_peer), peer);
    }
}

pub(super) fn after_crash(peers: &[RoomNode], stopped_home: &Path) {
    trace("after-crash", peers, 2, None);
    home("n1:stopped", stopped_home);
}

// Same predicates/deadlines as `wait_for`, with at most four snapshots per
// wait: start, 15s, 45s, and completion or timeout.
pub(super) async fn wait_for_rejoin<F: Fn() -> bool>(
    what: &str,
    f: F,
    timeout: Duration,
    peers: &[RoomNode],
    first_peer: usize,
    restarted: Option<&RoomNode>,
) {
    let start = Instant::now();
    trace(&format!("{what}:start"), peers, first_peer, restarted);
    let checkpoints = [Duration::from_secs(15), Duration::from_secs(45)];
    let mut next = 0;
    loop {
        // Match `wait_for`: a predicate first observed after the deadline
        // cannot turn a timed-out recovery into a success.
        if start.elapsed() >= timeout {
            trace(&format!("{what}:timeout"), peers, first_peer, restarted);
            panic!("timed out waiting for {what}");
        }
        if f() {
            trace(&format!("{what}:complete"), peers, first_peer, restarted);
            return;
        }
        if next < checkpoints.len()
            && checkpoints[next] < timeout
            && start.elapsed() >= checkpoints[next]
        {
            trace(
                &format!("{what}:{}s", checkpoints[next].as_secs()),
                peers,
                first_peer,
                restarted,
            );
            next += 1;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[test]
fn wal_marker_diagnostic_rejects_missing_or_trailing_bytes() {
    let dir = fixture("rejoin-wal-marker");
    let marker = dir.join("FORMAT");
    assert!(!wal_marker_matches(&marker));
    std::fs::write(&marker, WAL_FORMAT).unwrap();
    assert!(wal_marker_matches(&marker));
    let mut extended = WAL_FORMAT.to_vec();
    extended.push(b'X');
    std::fs::write(&marker, extended).unwrap();
    assert!(!wal_marker_matches(&marker));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn local_history_distinguishes_empty_values_and_unavailable_without_error_details() {
    assert_eq!(
        classify_history(Ok::<Vec<u8>, &str>(vec![])),
        LocalHistory::Empty
    );
    assert_eq!(
        classify_history(Ok::<Vec<u8>, &str>(vec![1, 2])),
        LocalHistory::Values(2)
    );
    assert_eq!(
        classify_history(Err::<Vec<u8>, &str>("secret absolute home path")),
        LocalHistory::Unavailable
    );
}

#[test]
fn socket_table_reports_only_test_ports_and_established_links() {
    let port = |n: u16| format!("{:04X}", PORT_BASE + n);
    let mut summary = SocketSummary::default();
    summary.observe(&format!(
        "sl local_address rem_address st\n\
         0: 0100007F:{} 00000000:0000 0A\n\
         1: 0100007F:{} 0100007F:CAFE 01\n\
         2: 0100007F:CAFF 0100007F:{} 01\n\
         3: 0100007F:{} 0100007F:{} 06\n\
         4: 0100007F:FFFF 0100007F:FFFF 01\n",
        port(0),
        port(0),
        port(1),
        port(2),
        port(3)
    ));
    assert_eq!(summary.listeners, [true, false, false, false]);
    assert_eq!(summary.established_local, [true, false, false, false]);
    assert_eq!(summary.established_remote, [false, true, false, false]);
    assert!(summary
        .report(1)
        .contains("established_local=[true, false, false, false]"));
}

#[test]
fn committed_chain_reads_bounded_history_without_recovery() {
    use vhalla_journal::{Bundle, BundleParts, Outcome};

    let base = fixture("rejoin-chain");
    let genesis_next = batch_plan(1).get(&1).unwrap().parent.commitment();
    let journal = vhalla_journal::Journal::with_genesis(
        base.join("app/journal"),
        vhalla_journal::FsStore,
        genesis_next,
    );
    let mut predecessor = genesis_next;
    let mut ids = Vec::new();
    for h in 1..=4 {
        let next = [h as u8; 32];
        let bundle = Bundle::new(BundleParts {
            certificate: vec![h as u8],
            predecessor,
            next,
            batch: Vec::new(),
            value: Vec::new(),
            configuration: Vec::new(),
            control_record: Vec::new(),
            debit_marker: Vec::new(),
            height: h,
        })
        .unwrap();
        assert_eq!(journal.commit(&bundle).unwrap(), Outcome::Committed);
        ids.push((bundle.id(), next));
        predecessor = next;
    }
    for h in 1..=4 {
        assert_eq!(committed_chain(&base, h), ids[..h as usize]);
    }
    let _ = std::fs::remove_dir_all(base);

    // A valid journal under a different genesis must not be treated as this
    // scenario's history, even when its height marker and bundle id agree.
    let foreign = fixture("rejoin-chain-foreign-genesis");
    let foreign_genesis = [0xF1; 32];
    assert_ne!(foreign_genesis, genesis_next);
    let journal = vhalla_journal::Journal::with_genesis(
        foreign.join("app/journal"),
        vhalla_journal::FsStore,
        foreign_genesis,
    );
    let bundle = Bundle::new(BundleParts {
        certificate: vec![1],
        predecessor: foreign_genesis,
        next: [1; 32],
        batch: Vec::new(),
        value: Vec::new(),
        configuration: Vec::new(),
        control_record: Vec::new(),
        debit_marker: Vec::new(),
        height: 1,
    })
    .unwrap();
    assert_eq!(journal.commit(&bundle).unwrap(), Outcome::Committed);
    let result = std::panic::catch_unwind(|| committed_chain(&foreign, 1));
    let _ = std::fs::remove_dir_all(foreign);
    assert!(
        result.is_err(),
        "foreign genesis was accepted as rejoin history"
    );
}

#[tokio::test]
#[should_panic(expected = "timed out waiting for expired predicate")]
async fn expired_predicate_cannot_pass() {
    // Even a true predicate cannot turn an expired wait into a green result.
    wait_for_rejoin("expired predicate", || true, Duration::ZERO, &[], 1, None).await;
}

// The real network actor's output port, not a local journal read, reports
// decoded sync requests and replies. Record only test node indices, bounded
// ranges and page lengths; no peer IDs, raw values, keys, paths or errors.
#[derive(Debug, Clone, PartialEq, Eq)]
enum WireFact {
    Connected {
        node: usize,
        peer: usize,
    },
    Disconnected {
        node: usize,
        peer: usize,
    },
    Request {
        node: usize,
        peer: usize,
        start: u64,
        end: u64,
    },
    Page {
        node: usize,
        peer: usize,
        start: u64,
        heights: Vec<u64>,
    },
    Empty {
        node: usize,
        peer: usize,
        start: u64,
    },
    Unavailable {
        node: usize,
        peer: usize,
    },
    Failed {
        node: usize,
        peer: usize,
    },
}

#[derive(Default)]
struct WireEvents {
    facts: Vec<WireFact>,
    overflow: usize,
}

struct WireCollector {
    node: usize,
    peers: std::sync::Arc<Vec<PeerId>>,
    events: std::sync::Arc<std::sync::Mutex<WireEvents>>,
}

#[ractor::async_trait]
impl Actor for WireCollector {
    type Msg = NetworkEvent<RoomContext>;
    type State = Self;
    type Arguments = Self;

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
        use arc_malachitebft_sync::{Request, Response};
        let peer_of = |peer: PeerId| state.peers.iter().position(|p| *p == peer).map(|i| i + 1);
        let fact = match msg {
            NetworkEvent::PeerConnected(peer) => peer_of(peer).map(|peer| WireFact::Connected {
                node: state.node,
                peer,
            }),
            NetworkEvent::PeerDisconnected(peer) => {
                peer_of(peer).map(|peer| WireFact::Disconnected {
                    node: state.node,
                    peer,
                })
            }
            NetworkEvent::SyncRequest(_, peer, Request::ValueRequest(request)) => peer_of(peer)
                .map(|peer| WireFact::Request {
                    node: state.node,
                    peer,
                    start: request.range.start().as_u64(),
                    end: request.range.end().as_u64(),
                }),
            NetworkEvent::SyncResponse(_, peer, Some(Response::ValueResponse(response))) => {
                peer_of(peer).map(|peer| {
                    let start = response.start_height.as_u64();
                    if response.values.is_empty() {
                        WireFact::Empty {
                            node: state.node,
                            peer,
                            start,
                        }
                    } else {
                        WireFact::Page {
                            node: state.node,
                            peer,
                            start,
                            heights: response
                                .values
                                .iter()
                                .take(32)
                                .map(|v| v.height().as_u64())
                                .collect(),
                        }
                    }
                })
            }
            NetworkEvent::SyncResponse(_, peer, None) => {
                peer_of(peer).map(|peer| WireFact::Unavailable {
                    node: state.node,
                    peer,
                })
            }
            NetworkEvent::SyncRequestFailed(_, peer, _) => {
                peer_of(peer).map(|peer| WireFact::Failed {
                    node: state.node,
                    peer,
                })
            }
            _ => None,
        };
        if let Some(fact) = fact {
            let mut events = state.events.lock().unwrap();
            if events.facts.len() < 128 {
                events.facts.push(fact);
            } else {
                events.overflow += 1;
            }
        }
        Ok(())
    }
}

// Filter before the observer actor mailbox: consensus gossip is not copied.
struct SelectedWireEvents(ActorRef<NetworkEvent<RoomContext>>);

impl OutputPortSubscriberTrait<NetworkEvent<RoomContext>> for SelectedWireEvents {
    fn subscribe_to_port(&self, port: &OutputPort<NetworkEvent<RoomContext>>) {
        port.subscribe(self.0.clone(), |event| match event {
            NetworkEvent::PeerConnected(_)
            | NetworkEvent::PeerDisconnected(_)
            | NetworkEvent::SyncRequest(..)
            | NetworkEvent::SyncResponse(..)
            | NetworkEvent::SyncRequestFailed(..) => Some(event),
            _ => None,
        });
    }
}

impl Subscriber<NetworkEvent<RoomContext>> for SelectedWireEvents {
    fn send(&self, event: NetworkEvent<RoomContext>) {
        if matches!(
            event,
            NetworkEvent::PeerConnected(_)
                | NetworkEvent::PeerDisconnected(_)
                | NetworkEvent::SyncRequest(..)
                | NetworkEvent::SyncResponse(..)
                | NetworkEvent::SyncRequestFailed(..)
        ) {
            let _ = self.0.cast(event);
        }
    }
}

pub(super) struct WireTrace {
    events: std::sync::Arc<std::sync::Mutex<WireEvents>>,
    peers: std::sync::Arc<Vec<PeerId>>,
    observers: Vec<ActorRef<NetworkEvent<RoomContext>>>,
}

impl WireTrace {
    pub(super) fn new(keys: &[PrivateKey]) -> Self {
        assert_eq!(keys.len(), 4);
        Self {
            events: Default::default(),
            peers: std::sync::Arc::new(
                keys.iter()
                    .map(|key| {
                        net_peer_id(&key.public_key())
                            .parse()
                            .expect("test peer id")
                    })
                    .collect(),
            ),
            observers: Vec::new(),
        }
    }

    pub(super) async fn attach(&mut self, node: &RoomNode, index: usize) {
        let (actor, _) = Actor::spawn(
            None,
            WireCollector {
                node: index,
                peers: self.peers.clone(),
                events: self.events.clone(),
            },
            WireCollector {
                node: index,
                peers: self.peers.clone(),
                events: self.events.clone(),
            },
        )
        .await
        .expect("wire observer");
        node.inner_net
            .as_ref()
            .expect("trace needs real gated network")
            .cast(NetActorMsg::Subscribe(Box::new(SelectedWireEvents(
                actor.clone(),
            ))))
            .expect("wire subscribe");
        // DumpState follows Subscribe on the same real-network mailbox, so it
        // also acts as the bounded subscription barrier before releasing n1.
        let _ = self.dump(node).await;
        self.observers.push(actor);
    }

    async fn dump(&self, node: &RoomNode) -> arc_malachitebft_engine::network::NetworkStateDump {
        let (tx, rx) = tokio::sync::oneshot::channel();
        node.inner_net
            .as_ref()
            .expect("real network")
            .cast(NetActorMsg::DumpState(tx.into()))
            .expect("network dump request");
        tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .expect("network dump deadline")
            .expect("network dump response")
            .expect("running real network")
    }

    pub(super) async fn assert_causal_page(
        &self,
        restarted: &RoomNode,
        sources: &[RoomNode],
        keys: &[PrivateKey],
    ) -> Vec<usize> {
        let responders = {
            let snapshot = self.events.lock().unwrap();
            println!(
                "rejoin wire facts={:?} overflow={}",
                snapshot.facts, snapshot.overflow
            );
            assert_eq!(
                snapshot.overflow, 0,
                "wire trace saturated; cannot prove page delivery"
            );
            let mut responders = std::collections::BTreeSet::new();
            for height in 3..=4 {
                let source = (2..=4)
                    .find(|source| {
                        snapshot.facts.iter().any(|f| {
                            matches!(f, WireFact::Request { node, peer: 1, start, end }
                    if node == source && *start <= height && *end >= height)
                        }) && snapshot.facts.iter().any(|f| {
                            matches!(f, WireFact::Page { node: 1, peer, heights, .. }
                    if peer == source && heights.contains(&height))
                        })
                    })
                    .unwrap_or_else(|| {
                        panic!("no correlated request and received decided page for h{height}")
                    });
                responders.insert(source);
            }
            responders
        };
        let victim_dump = self.dump(restarted).await;
        let mut verified = Vec::new();
        for source in responders {
            let source_key = keys[source - 1].public_key();
            let source_peer =
                libp2p_identity::PeerId::from_bytes(&self.peers[source - 1].to_bytes())
                    .expect("test source peer id");
            let victim_key = keys[0].public_key();
            let source_dump = self.dump(&sources[source - 2]).await;
            assert!(
                victim_dump
                    .peers
                    .get(&source_peer)
                    .is_some_and(|p| p.consensus_public_key.as_deref()
                        == Some(source_key.as_bytes().as_slice())),
                "restarted victim lacks the source's verified validator proof"
            );
            assert!(
                source_dump
                    .peers
                    .get(
                        &libp2p_identity::PeerId::from_bytes(&self.peers[0].to_bytes())
                            .expect("test victim peer id")
                    )
                    .is_some_and(|p| p.consensus_public_key.as_deref()
                        == Some(victim_key.as_bytes().as_slice())),
                "decided-page source lacks the victim's verified validator proof"
            );
            println!("rejoin verified peer lifecycle: n1<->n{source} validator proofs match");
            verified.push(source);
        }
        verified
    }

    // Nextest captures passing tests' stdout. Write the same capped, redacted
    // test facts to the GitHub job summary ONLY after all recovery assertions
    // pass; do not report the prior intermittent timeout as explained.
    pub(super) fn write_ci_receipt(&self, wal_path: &str, verified: &[usize]) {
        if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true") {
            return;
        }
        let path = std::env::var_os("GITHUB_STEP_SUMMARY")
            .expect("GitHub Actions must provide its job summary path");
        let events = self.events.lock().unwrap();
        assert_eq!(events.overflow, 0, "wire summary cannot omit events");
        let facts = format!("{:?}", events.facts);
        assert!(facts.len() <= 16_384, "redacted wire summary too long");
        let receipt = format!(
            "\n### Rooms-node crash/rejoin diagnostic (test-only)\n\n\
             - Restarted n1 WAL startup at h3: {wal_path}.\n\
             - Source/victim pairs with matching verified validator proofs: {verified:?}.\n\
             - Wire facts (node numbers and heights only): `{facts}`.\n\
             - Same-home n1 stopped at h2 without preloaded h3–h4 bodies, then reached h4; journal prefix, peer state, planned effects, and stopped-store reopen matched.\n\
             - A passing run does not explain the earlier intermittent h4 timeout or prove application-call count.\n"
        );
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open GitHub test summary");
        std::io::Write::write_all(&mut file, receipt.as_bytes())
            .expect("write bounded GitHub test summary");
    }
}

impl Drop for WireTrace {
    fn drop(&mut self) {
        let snapshot = self
            .events
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        // Failure snapshots also include this bounded, redacted wire ledger.
        println!(
            "rejoin wire final={:?} overflow={}",
            snapshot.facts, snapshot.overflow
        );
        for observer in &self.observers {
            observer.stop(None);
        }
    }
}

// A minimal test-only tracing subscriber for the pinned consensus actor. It
// never formats arbitrary log fields (WAL entries can contain private data).
// It records only whitelisted startup branches at h3 after all live peers
// reached h4; the restarted n1 is the sole actor starting that height.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WalFact {
    EmptyFetch,
    NonemptyFetch,
    Deferred,
    Replaying,
    Superseded,
    DelayElapsed,
    Running,
    Error,
}

#[derive(Default)]
struct WalEvents {
    facts: Vec<WalFact>,
    overflow: usize,
}

thread_local! {
    static WAL_SPAN_STACK: std::cell::RefCell<Vec<u64>> = const { std::cell::RefCell::new(Vec::new()) };
}

struct SafeFields {
    capture_text: bool,
    height: Option<String>,
    message: Option<String>,
    new: Option<String>,
}

impl tracing::field::Visit for SafeFields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "height"
            || (self.capture_text && matches!(field.name(), "message" | "new"))
        {
            let value = format!("{value:?}");
            if value.len() <= 128 {
                match field.name() {
                    "height" => self.height = Some(value),
                    "message" => self.message = Some(value),
                    "new" => self.new = Some(value),
                    _ => {}
                }
            }
        }
    }
}

struct WalSubscriber {
    next: std::sync::atomic::AtomicU64,
    height3_spans: std::sync::Mutex<std::collections::HashSet<u64>>,
    armed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    events: std::sync::Arc<std::sync::Mutex<WalEvents>>,
}

impl tracing::Subscriber for WalSubscriber {
    fn enabled(&self, meta: &tracing::Metadata<'_>) -> bool {
        meta.is_span()
            || (meta.target().contains("consensus") && *meta.level() <= tracing::Level::DEBUG)
    }

    fn new_span(&self, attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        let mut fields = SafeFields {
            capture_text: false,
            height: None,
            message: None,
            new: None,
        };
        attrs.record(&mut fields);
        let parent = attrs
            .parent()
            .map(tracing::span::Id::into_u64)
            .or_else(|| WAL_SPAN_STACK.with(|stack| stack.borrow().last().copied()));
        let height_is_three = fields
            .height
            .as_deref()
            .is_some_and(|v| v.trim_matches('"') == "3");
        if height_is_three
            || (fields.height.is_none()
                && parent
                    .is_some_and(|parent| self.height3_spans.lock().unwrap().contains(&parent)))
        {
            self.height3_spans.lock().unwrap().insert(id);
        }
        tracing::span::Id::from_u64(id)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        if !self.armed.load(Ordering::Relaxed) || !event.metadata().target().contains("consensus") {
            return;
        }
        let parent = event
            .parent()
            .map(tracing::span::Id::into_u64)
            .or_else(|| WAL_SPAN_STACK.with(|stack| stack.borrow().last().copied()));
        // At this pinned Malachite revision, only these consensus.rs
        // callsites contain fixed startup labels or bounded entry counts.
        // Never format arbitrary consensus messages (they may contain WAL
        // entry bytes or home paths), even temporarily.
        let meta = event.metadata();
        let pinned_startup = meta
            .file()
            .is_some_and(|f| f.ends_with("/engine/src/consensus.rs"))
            && meta
                .line()
                .is_some_and(|line| [314, 529, 820, 945, 952, 980, 1143].contains(&line));
        let synthetic_test = meta
            .file()
            .is_some_and(|f| f.ends_with("/unix/rejoin_trace.rs"))
            && meta.target() == "consensus";
        let mut fields = SafeFields {
            capture_text: pinned_startup || synthetic_test,
            height: None,
            message: None,
            new: None,
        };
        event.record(&mut fields);
        let height_is_three = fields
            .height
            .as_deref()
            .is_some_and(|v| v.trim_matches('"') == "3");
        if !height_is_three
            && !parent.is_some_and(|parent| self.height3_spans.lock().unwrap().contains(&parent))
        {
            return;
        }
        let message = fields.message.as_deref().unwrap_or("").trim_matches('"');
        let fact = if message == "No WAL entries to replay" {
            Some(WalFact::EmptyFetch)
        } else if message.starts_with("Found ") && message.ends_with(" WAL entries") {
            Some(WalFact::NonemptyFetch)
        } else if message == "Deferring WAL replay to wait for sync" {
            Some(WalFact::Deferred)
        } else if message.starts_with("Replaying ") && message.ends_with(" WAL entries") {
            Some(WalFact::Replaying)
        } else if message == "Sync certificate applied; transitioning out of WaitingForSync" {
            Some(WalFact::Superseded)
        } else if message
            == "WAL replay delay elapsed without consensus reaching a decision, replaying WAL"
        {
            Some(WalFact::DelayElapsed)
        } else if message == "Phase transition"
            && fields.new.as_deref().is_some_and(|v| v.contains("Running"))
        {
            Some(WalFact::Running)
        } else if *event.metadata().level() == tracing::Level::ERROR {
            Some(WalFact::Error)
        } else {
            None
        };
        if let Some(fact) = fact {
            let mut events = self.events.lock().unwrap();
            if events.facts.len() < 32 {
                events.facts.push(fact);
            } else {
                events.overflow += 1;
            }
        }
    }
    fn enter(&self, id: &tracing::span::Id) {
        WAL_SPAN_STACK.with(|stack| stack.borrow_mut().push(id.into_u64()));
    }
    fn exit(&self, id: &tracing::span::Id) {
        WAL_SPAN_STACK.with(|stack| {
            let removed = stack.borrow_mut().pop();
            debug_assert_eq!(removed, Some(id.into_u64()));
        });
    }
}

pub(super) struct WalTrace {
    events: std::sync::Arc<std::sync::Mutex<WalEvents>>,
    armed: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl WalTrace {
    pub(super) fn install() -> Self {
        let events: std::sync::Arc<std::sync::Mutex<WalEvents>> = Default::default();
        let armed: std::sync::Arc<std::sync::atomic::AtomicBool> = Default::default();
        tracing::subscriber::set_global_default(WalSubscriber {
            next: Default::default(),
            height3_spans: Default::default(),
            armed: armed.clone(),
            events: events.clone(),
        })
        .expect("crash/rejoin test needs its own WAL path subscriber");
        Self { events, armed }
    }
    pub(super) fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }
    pub(super) fn assert_startup(&self) -> &'static str {
        let (facts, overflow) = {
            let trace = self.events.lock().unwrap();
            (trace.facts.clone(), trace.overflow)
        };
        println!("rejoin n1 WAL startup facts={facts:?} overflow={overflow}");
        assert_eq!(overflow, 0, "WAL startup trace saturated");
        let first_running = facts
            .iter()
            .position(|f| *f == WalFact::Running)
            .expect("restarted n1 never reached consensus Running");
        let startup = &facts[..=first_running];
        assert!(
            !startup.contains(&WalFact::Error),
            "restarted n1 reported consensus error"
        );
        let path = if startup.contains(&WalFact::EmptyFetch) {
            "valid empty WAL"
        } else if startup.contains(&WalFact::NonemptyFetch)
            && startup.contains(&WalFact::Deferred)
            && startup.contains(&WalFact::Superseded)
        {
            "sync certificate superseded delayed WAL"
        } else if startup.contains(&WalFact::NonemptyFetch) && startup.contains(&WalFact::Replaying)
        {
            "nonempty WAL replay completed"
        } else {
            panic!("restarted n1 WAL startup path not established: {startup:?}")
        };
        println!("rejoin n1 WAL startup path={path}");
        path
    }
}

impl Drop for WalTrace {
    fn drop(&mut self) {
        let trace = self
            .events
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        println!(
            "rejoin n1 WAL final={:?} overflow={}",
            trace.facts, trace.overflow
        );
        self.armed.store(false, Ordering::SeqCst);
    }
}

#[test]
fn wal_subscriber_scopes_startup_and_never_records_arbitrary_messages() {
    let events: std::sync::Arc<std::sync::Mutex<WalEvents>> = Default::default();
    let armed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let subscriber = WalSubscriber {
        next: Default::default(),
        height3_spans: Default::default(),
        armed: armed.clone(),
        events: events.clone(),
    };
    let dispatch = tracing::Dispatch::new(subscriber);
    tracing::dispatcher::with_default(&dispatch, || {
        let other = tracing::error_span!("consensus", height = %4);
        {
            let _guard = other.enter();
            tracing::debug!(target: "consensus", "No WAL entries to replay");
        }
        let consensus = tracing::error_span!("consensus", height = %3);
        let _guard = consensus.enter();
        tracing::debug!(target: "consensus", "No WAL entries to replay");
        tracing::info!(target: "consensus", prev = ?"Recovering", new = ?"Running", "Phase transition");
        tracing::info!(target: "consensus", "private home /tmp/secret WAL entry");
    });
    assert_eq!(
        events.lock().unwrap().facts,
        vec![WalFact::EmptyFetch, WalFact::Running]
    );
    WalTrace { events, armed }.assert_startup();
}
