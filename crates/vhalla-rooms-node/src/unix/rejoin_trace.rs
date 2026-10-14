//! Bounded, read-only diagnostics for the crash/rejoin test. Never read
//! WAL contents or print keys, batch bodies, or absolute home paths.

use super::*;

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
/// height and predecessor link; never run writer-side `recover()` on a live
/// node. Keep full identities in the assertion, not in diagnostic output.
pub(super) fn committed_chain(path: &Path, through: u64) -> Vec<([u8; 32], [u8; 32])> {
    assert!((1..=4).contains(&through));
    let journal = vhalla_journal::Journal::new(path.join("app/journal"), vhalla_journal::FsStore);
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
        if let Some((_, previous_next)) = chain.last() {
            assert!(
                bundle.predecessor() == *previous_next,
                "journal predecessor mismatch at height {h}"
            );
        }
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
    println!("rejoin stage={stage}");
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
fn committed_chain_reads_bounded_history_without_recovery() {
    use vhalla_journal::{Bundle, BundleParts, Outcome};

    let base = fixture("rejoin-chain");
    let journal = vhalla_journal::Journal::new(base.join("app/journal"), vhalla_journal::FsStore);
    let mut predecessor = vhalla_journal::GENESIS_NEXT;
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
}

#[tokio::test]
#[should_panic(expected = "timed out waiting for expired predicate")]
async fn expired_predicate_cannot_pass() {
    // Even a true predicate cannot turn an expired wait into a green result.
    wait_for_rejoin("expired predicate", || true, Duration::ZERO, &[], 1, None).await;
}
