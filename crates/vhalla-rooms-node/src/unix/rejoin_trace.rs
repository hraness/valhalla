//! Bounded, read-only diagnostics for the crash/rejoin test. Never read
//! WAL contents or print keys, batch bodies, or absolute home paths.

use super::*;

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
    use std::io::Read;
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
    let wal_format_ok = std::fs::metadata(path.join("wal/FORMAT")).is_ok_and(|m| m.len() == 4)
        && std::fs::read(path.join("wal/FORMAT")).is_ok_and(|bytes| bytes == WAL_FORMAT);
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

fn node(label: &str, node: &RoomNode) {
    let frontier = node.adapter.lock().unwrap().frontier();
    let acks = node.sink.lock().unwrap();
    let ack_counts: Vec<_> = (1..=4)
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
    println!(
        "rejoin {label}: frontier={} commitment={} ack_counts={ack_counts:?} ack_total={} resupplied={} loaded={:?} app_done={} engine_done={}",
        frontier.height,
        hex(&frontier.commitment()[..8]),
        acks.sent.len(),
        *node.resupplied.lock().unwrap(),
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
