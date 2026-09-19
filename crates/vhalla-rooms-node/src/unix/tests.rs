//! Real multi-validator runs: four Malachite engines over localhost
//! libp2p deciding real room-registry batches (canonical signed record
//! bytes through `vhalla_rooms::Registry` + both durable snapshot stores)
//! through the journal-gated acknowledgement boundary.

use super::*;
use crate::{RoomValidator, RoomValidatorSet};
use hegel::{generators as gs, HealthCheck, TestCase};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use vhalla_rooms_consensus::{
    encode_eligible_update, fixture, Batch, GameCommitment, GameCommitmentKind, OwnerId,
};

/// The shared batch plan: `heights` room creations over 8 beneficiary
/// owners and 16 eligible award sources — enough credits for two rooms
/// per owner across the longest run.
fn batch_plan(heights: u64) -> BTreeMap<u64, Batch> {
    fixture::plan(heights, 8, 16).batches
}

fn genesis() -> Genesis {
    fixture::plan(0, 8, 16).genesis
}

fn fixture(tag: &str) -> PathBuf {
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "room-engine-{tag}-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        SEQ.fetch_add(1, Ordering::Relaxed),
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn validators(n: usize) -> (Vec<PrivateKey>, RoomValidatorSet) {
    let keys: Vec<PrivateKey> = (1..=n as u8)
        .map(|i| PrivateKey::from([i * 9; 32]))
        .collect();
    let set = RoomValidatorSet::new(
        keys.iter()
            .map(|k| RoomValidator::new(k.public_key(), 1))
            .collect(),
    );
    (keys, set)
}

/// A single-set activation schedule.
fn sched(set: RoomValidatorSet) -> BTreeMap<u64, RoomValidatorSet> {
    BTreeMap::from([(1, set)])
}

async fn wait_for<F: Fn() -> bool>(what: &str, f: F, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for {what}");
}

/// Four real engines decide the same planned batches; every node
/// journal-commits each height and acknowledges only post-commit.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn four_validators_commit_planned_batches() {
    const HEIGHTS: u64 = 3;
    let plan = batch_plan(HEIGHTS);
    let (keys, set) = validators(4);
    let base = fixture("quorum");
    let base_port = 27100usize;

    let mut nodes = Vec::new();
    for (i, key) in keys.iter().enumerate().take(4) {
        nodes.push(
            RoomNode::start(NodeSpec {
                home: base.join(format!("n{}", i + 1)),
                config: node_config(i + 1, 4, base_port),
                node_key: key.clone(),
                validator_sets: sched(set.clone()),
                held: plan.clone(),
                genesis: genesis(),
                wal_faults: None,
                net_gate: None,
            })
            .await,
        );
    }

    // The journal frontier is the commit evidence; the ack sink records
    // the engine messages (CommitAck for `Decided`, NextHeightReply for
    // `Finalized`) — each names its decided height, so evidence for h is
    // CommitAck{h} or NextHeightReply{h+1}.
    fn evidenced(acks: &[vhalla_rooms_consensus::EngineMsg]) -> HashSet<u64> {
        acks.iter()
            .map(|m| match m {
                vhalla_rooms_consensus::EngineMsg::CommitAck { height } => *height,
                vhalla_rooms_consensus::EngineMsg::NextHeightReply { height } => height - 1,
            })
            .collect()
    }
    wait_for(
        "all four nodes to journal-commit and acknowledge height 3",
        || {
            nodes
                .iter()
                .all(|n| n.committed_height() >= HEIGHTS && evidenced(&n.acks()).contains(&HEIGHTS))
        },
        Duration::from_secs(90),
    )
    .await;

    for node in &nodes {
        let acks = node.acks();
        assert!(
            (1..=HEIGHTS).all(|h| evidenced(&acks).contains(&h)),
            "acks: {acks:?}"
        );
    }

    // Identical application state everywhere: same frontier commitment.
    let frontiers: Vec<_> = nodes
        .iter()
        .map(|n| {
            let g = n.adapter.lock().unwrap();
            (g.frontier().height, g.frontier().commitment())
        })
        .collect();
    assert!(frontiers.windows(2).all(|w| w[0] == w[1]), "{frontiers:?}");

    for node in nodes {
        node.crash().await;
    }
    let _ = std::fs::remove_dir_all(&base);
}

/// A node that never starts catches up through value sync and commits
/// through the SAME journal-gated path once it joins.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn late_joiner_syncs_and_commits() {
    const HEIGHTS: u64 = 3;
    let plan = batch_plan(HEIGHTS);
    let (keys, set) = validators(4);
    let base = fixture("sync");
    let base_port = 27200usize;

    let mut nodes = Vec::new();
    for (i, key) in keys.iter().enumerate().take(3) {
        nodes.push(
            RoomNode::start(NodeSpec {
                home: base.join(format!("n{}", i + 1)),
                config: node_config(i + 1, 4, base_port),
                node_key: key.clone(),
                validator_sets: sched(set.clone()),
                held: plan.clone(),
                genesis: genesis(),
                wal_faults: None,
                net_gate: None,
            })
            .await,
        );
    }

    wait_for(
        "three validators to commit height 3",
        || nodes.iter().all(|n| n.committed_height() >= HEIGHTS),
        Duration::from_secs(90),
    )
    .await;

    // The fourth node starts late with the same held plan.
    let late = RoomNode::start(NodeSpec {
        home: base.join("n4"),
        config: node_config(4, 4, base_port),
        node_key: keys[3].clone(),
        validator_sets: sched(set.clone()),
        held: plan.clone(),
        genesis: genesis(),
        wal_faults: None,
        net_gate: None,
    })
    .await;

    wait_for(
        "late joiner to commit height 3 via sync",
        || late.committed_height() >= HEIGHTS,
        Duration::from_secs(60),
    )
    .await;

    let late_state = late.adapter.lock().unwrap().frontier().commitment();
    let peer_state = nodes[0].adapter.lock().unwrap().frontier().commitment();
    assert_eq!(late_state, peer_state);

    for node in nodes {
        node.crash().await;
    }
    late.crash().await;
    let _ = std::fs::remove_dir_all(&base);
}

/// A crashed validator restarts on the SAME home directory: the engine
/// WAL replays its votes, `ConsensusReady` resumes from the durable
/// journal frontier, and the node rejoins progress without double-apply.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn crashed_validator_recovers_and_rejoins() {
    const HEIGHTS: u64 = 4;
    let plan = batch_plan(HEIGHTS);
    let (keys, set) = validators(4);
    let base = fixture("crash");
    let base_port = 27300usize;

    let mut nodes = Vec::new();
    for (i, key) in keys.iter().enumerate().take(4) {
        nodes.push(
            RoomNode::start(NodeSpec {
                home: base.join(format!("n{}", i + 1)),
                config: node_config(i + 1, 4, base_port),
                node_key: key.clone(),
                validator_sets: sched(set.clone()),
                held: plan.clone(),
                genesis: genesis(),
                wal_faults: None,
                net_gate: None,
            })
            .await,
        );
    }

    wait_for(
        "all four nodes to commit height 2",
        || nodes.iter().all(|n| n.committed_height() >= 2),
        Duration::from_secs(60),
    )
    .await;

    // Crash validator 1, wait a beat, restart on the same home.
    let victim = nodes.remove(0);
    victim.crash().await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let restarted = RoomNode::start(NodeSpec {
        home: base.join("n1"),
        config: node_config(1, 4, base_port),
        node_key: keys[0].clone(),
        validator_sets: sched(set.clone()),
        held: plan.clone(),
        genesis: genesis(),
        wal_faults: None,
        net_gate: None,
    })
    .await;

    // The application-owned store survived the crash: the four spec-held
    // batch bodies plus the seen-proposal records for the heights the
    // node voted on reloaded — the WAL restored votes; this restores the
    // value content.
    assert!(
        restarted.loaded.0 >= 4,
        "store/batches must reload retained batches, got {}",
        restarted.loaded.0
    );
    assert!(
        restarted.loaded.1 >= 2,
        "store/seen must reload observed proposals, got {}",
        restarted.loaded.1
    );

    wait_for(
        "restarted validator to reach height 4",
        || restarted.committed_height() >= HEIGHTS,
        Duration::from_secs(90),
    )
    .await;
    wait_for(
        "peers to reach height 4",
        || nodes.iter().all(|n| n.committed_height() >= HEIGHTS),
        Duration::from_secs(60),
    )
    .await;

    let restarted_state = restarted.adapter.lock().unwrap().frontier().commitment();
    for node in &nodes {
        assert_eq!(
            node.adapter.lock().unwrap().frontier().commitment(),
            restarted_state
        );
    }
    // Each height committed exactly once — the replay of the durable
    // marker deduplicates rather than re-applying.
    assert_eq!(restarted.adapter.lock().unwrap().frontier().height, HEIGHTS);

    for node in nodes {
        node.crash().await;
    }
    restarted.crash().await;
    let _ = std::fs::remove_dir_all(&base);
}

/// Two validators of a four-validator set cannot form a quorum: neither
/// side may finalize anything. This is the partition clause — a 2–2 split
/// finalizes no competing allocation.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn minority_partition_finalizes_nothing() {
    let plan = batch_plan(2);
    let (keys, set) = validators(4);
    let base = fixture("partition");
    let base_port = 27400usize;

    // Only validators 1 and 2 start; they can never reach 3-of-4.
    let mut nodes = Vec::new();
    for (i, key) in keys.iter().enumerate().take(2) {
        nodes.push(
            RoomNode::start(NodeSpec {
                home: base.join(format!("n{}", i + 1)),
                config: node_config(i + 1, 4, base_port),
                node_key: key.clone(),
                validator_sets: sched(set.clone()),
                held: plan.clone(),
                genesis: genesis(),
                wal_faults: None,
                net_gate: None,
            })
            .await,
        );
    }

    // Give the pair several timeout rounds, then assert the journals are
    // still empty — no CommitAck could have been emitted.
    tokio::time::sleep(Duration::from_secs(15)).await;
    for node in &nodes {
        assert_eq!(node.committed_height(), 0);
        assert!(node.acks().is_empty());
    }

    for node in nodes {
        node.crash().await;
    }
    let _ = std::fs::remove_dir_all(&base);
}

/// One explicitly finalized configuration transition: heights 1-2 run
/// under set1 {k1,k2,k3,k4}; from height 3 the active set is set2
/// {k1,k2,k3,k5} — k4 is rotated out. Certificates past the boundary
/// verify against the NEW set; k4's signatures no longer count.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn validator_set_rotates_at_activation_boundary() {
    const HEIGHTS: u64 = 4;
    let plan = batch_plan(HEIGHTS);
    let (keys, set1) = validators(4);
    // Rotated set: the fifth key replaces the fourth.
    let k5 = PrivateKey::from([99; 32]);
    let set2 = RoomValidatorSet::new(
        keys[..3]
            .iter()
            .chain(std::iter::once(&k5))
            .map(|k| RoomValidator::new(k.public_key(), 1))
            .collect(),
    );
    let schedule = BTreeMap::from([(1, set1.clone()), (3, set2.clone())]);

    let base = fixture("rotate");
    let base_port = 27500usize;
    let mut nodes = Vec::new();
    for (i, key) in keys.iter().enumerate() {
        nodes.push(
            RoomNode::start(NodeSpec {
                home: base.join(format!("n{}", i + 1)),
                config: node_config(i + 1, 4, base_port),
                node_key: key.clone(),
                validator_sets: schedule.clone(),
                held: plan.clone(),
                genesis: genesis(),
                wal_faults: None,
                net_gate: None,
            })
            .await,
        );
    }

    wait_for(
        "all four nodes to commit height 4 across the rotation",
        || nodes.iter().all(|n| n.committed_height() >= HEIGHTS),
        Duration::from_secs(120),
    )
    .await;

    let frontiers: Vec<_> = nodes
        .iter()
        .map(|n| n.adapter.lock().unwrap().frontier().commitment())
        .collect();
    assert!(frontiers.windows(2).all(|w| w[0] == w[1]));

    for node in nodes {
        node.crash().await;
    }
    let _ = std::fs::remove_dir_all(&base);
}

/// Measurement harness: per-height boundary latency (verify → journal →
/// ack, fsyncs included), canonical certificate bytes, bundle bytes and
/// engine WAL growth — the inputs the production limits need.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn measurement_report() {
    const HEIGHTS: u64 = 12;
    let plan = batch_plan(HEIGHTS);
    let (keys, set) = validators(4);
    let base = fixture("measure");
    let base_port = 27600usize;

    let mut nodes = Vec::new();
    for (i, key) in keys.iter().enumerate() {
        nodes.push(
            RoomNode::start(NodeSpec {
                home: base.join(format!("n{}", i + 1)),
                config: node_config(i + 1, 4, base_port),
                node_key: key.clone(),
                validator_sets: sched(set.clone()),
                held: plan.clone(),
                genesis: genesis(),
                wal_faults: None,
                net_gate: None,
            })
            .await,
        );
    }

    // Sample the WAL footprint after each committed height — the engine
    // resets the log per height, so a bounded tail (not growth) is the
    // expected shape.
    let mut wal_samples = Vec::new();
    for h in 1..=HEIGHTS {
        wait_for(
            "all four nodes to commit the next height",
            || nodes.iter().all(|n| n.committed_height() >= h),
            Duration::from_secs(90),
        )
        .await;
        wal_samples.push(walk_size(&nodes[0].home.join("wal")));
    }

    let (journal_dir, lat_snapshot, wal) = {
        let node = &nodes[0];
        let journal_dir = node.home.join("app").join("journal");
        let wal = walk_size(&node.home.join("wal"));
        let lat = node.boundary_latency.lock().unwrap().clone();
        (journal_dir, lat, wal)
    };
    let journal = vhalla_journal::Journal::new(&journal_dir, vhalla_journal::FsStore);
    let recovered = journal.recover().unwrap();
    assert_eq!(recovered.pin.height, HEIGHTS);

    println!("=== room-consensus-engine measurement report ===");
    let mut total_bundle = 0usize;
    for h in 1..=HEIGHTS {
        let id = journal.at_height(h).unwrap().unwrap();
        let bundle = journal.bundle(id).unwrap().unwrap();
        let cert = bundle.field(0).unwrap().len();
        total_bundle += bundle.len();
        println!("height {h}: cert={}B bundle={}B", cert, bundle.len());
    }
    let journal_bytes: u64 = walk_size(&journal_dir);
    let lat = &lat_snapshot;
    let per_height: Vec<u128> = (1..=HEIGHTS)
        .map(|h| {
            lat.iter()
                .filter(|(lh, _)| *lh == h)
                .map(|(_, n)| *n)
                .sum::<u128>()
        })
        .collect();
    println!("wal={wal}B journal_total={journal_bytes}B bundles={total_bundle}B");
    println!("wal_growth={:?}", wal_samples);
    let wal_max = *wal_samples.iter().max().unwrap();
    println!(
        "wal tail: min={}B max={}B last={}B over {HEIGHTS} heights",
        wal_samples.iter().min().unwrap(),
        wal_max,
        wal_samples.last().unwrap()
    );
    for (i, ns) in per_height.iter().enumerate() {
        println!("boundary h{}: {:.2}ms", i + 1, *ns as f64 / 1e6);
    }
    assert!(wal > 0);
    assert!(total_bundle > 0);
    // The WAL tail must stay bounded — it holds only the live height's
    // undecided entries, so a 3x run must not grow it materially.
    assert!(
        wal_max < 256 * 1024,
        "WAL grew to {wal_max}B across {HEIGHTS} heights"
    );

    for node in nodes {
        node.crash().await;
    }
    let _ = std::fs::remove_dir_all(&base);
}

/// WAL soak: the bounded-tail claim sampled over 32 heights rather than
/// the measurement report's 12. The engine resets the log per height, so
/// the live tail holds only undecided entries — a ~3x-longer run must not
/// grow it, and the journal must still recover the full prefix.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn wal_tail_stays_bounded_over_long_run() {
    // Four rooms per owner is the deepest plan a batch can fund: slot 4's
    // charge needs 16 award pairs = exactly MAX_BATCH_ITEMS. Under epoch-0
    // dedup that is 30 distinct sources per beneficiary.
    const HEIGHTS: u64 = 32;
    let plan = fixture::plan_with_limits(HEIGHTS, 8, 96, fixture::wide_limits());
    let (keys, set) = validators(4);
    let base = fixture("wal-soak");
    let base_port = 28900usize;

    let mut nodes = Vec::new();
    for (i, key) in keys.iter().enumerate() {
        nodes.push(
            RoomNode::start(NodeSpec {
                home: base.join(format!("n{}", i + 1)),
                config: node_config(i + 1, 4, base_port),
                node_key: key.clone(),
                validator_sets: sched(set.clone()),
                held: plan.batches.clone(),
                genesis: plan.genesis.clone(),
                wal_faults: None,
                net_gate: None,
            })
            .await,
        );
    }

    // Sample after every eighth height — the bounded-tail shape is the
    // claim, not per-height granularity. The per-sample deadline is
    // generous because shared CI runners run the debug build several
    // times slower than a local workstation.
    let mut wal_samples = Vec::new();
    for h in (8..=HEIGHTS).step_by(8) {
        wait_for(
            "all four nodes to commit the sampled height",
            || nodes.iter().all(|n| n.committed_height() >= h),
            Duration::from_secs(300),
        )
        .await;
        wal_samples.push(walk_size(&nodes[0].home.join("wal")));
    }

    let wal_max = *wal_samples.iter().max().unwrap();
    println!("wal soak over {HEIGHTS} heights: {wal_samples:?} (max {wal_max}B)");
    assert!(
        wal_max < 256 * 1024,
        "WAL grew to {wal_max}B across {HEIGHTS} heights"
    );

    let journal = vhalla_journal::Journal::new(
        nodes[0].home.join("app").join("journal"),
        vhalla_journal::FsStore,
    );
    assert_eq!(journal.recover().unwrap().pin.height, HEIGHTS);

    for node in nodes {
        node.crash().await;
    }
    let _ = std::fs::remove_dir_all(&base);
}

fn walk_size(dir: &Path) -> u64 {
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| {
                    let p = e.path();
                    if p.is_dir() {
                        walk_size(&p)
                    } else {
                        p.metadata().map(|m| m.len()).unwrap_or(0)
                    }
                })
                .sum()
        })
        .unwrap_or(0)
}

/// A node that never held the decided batch receives the real canonical
/// bytes inside the proposal stream itself: it decodes, validates and
/// registers the batch, votes, and journal-commits identically. There is
/// no side channel — the wire carries the value.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn unheld_batch_arrives_over_the_wire() {
    const HEIGHTS: u64 = 3;
    let plan = batch_plan(HEIGHTS);
    let (keys, set) = validators(4);
    let base = fixture("dataplane");
    let base_port = 27700usize;

    let mut nodes = Vec::new();
    for (i, key) in keys.iter().enumerate().take(4) {
        // Node 4 holds nothing: every decided batch arrives inside the
        // proposal stream over real libp2p gossip.
        let held = if i == 3 {
            BTreeMap::new()
        } else {
            plan.clone()
        };
        nodes.push(
            RoomNode::start(NodeSpec {
                home: base.join(format!("n{}", i + 1)),
                config: node_config(i + 1, 4, base_port),
                node_key: key.clone(),
                validator_sets: sched(set.clone()),
                held,
                genesis: genesis(),
                wal_faults: None,
                net_gate: None,
            })
            .await,
        );
    }

    wait_for(
        "all four nodes to commit height 3, including the empty holder",
        || nodes.iter().all(|n| n.committed_height() >= HEIGHTS),
        Duration::from_secs(90),
    )
    .await;

    let frontiers: Vec<_> = nodes
        .iter()
        .map(|n| n.adapter.lock().unwrap().frontier().commitment())
        .collect();
    assert!(frontiers.windows(2).all(|w| w[0] == w[1]));

    for node in nodes {
        node.crash().await;
    }
    let _ = std::fs::remove_dir_all(&base);
}

/// Competing-slug allocation under the real engine: two validators hold
/// different batches allocating the SAME slug, prepared against the same
/// genesis frontier. The h1 proposer's batch wins; the h2r0 proposer's
/// stale competing batch fails frontier validation everywhere, is voted
/// down, and the next round's fresh batch decides instead. The losing
/// allocation can never finalize.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn competing_slug_loser_never_finalizes() {
    let (keys, set) = validators(4);
    let base = fixture("compete");
    let base_port = 27800usize;

    // batch_a: slug "contested" against genesis — the winner at h=1.
    let mut s = fixture::scenario(8, 16);
    let mut s2 = fixture::scenario(8, 16);
    let mut cursor = 0usize;
    let (ev, rec, _) = fixture::first_create(
        &s.app,
        &s.owners[0],
        &mut s.sources,
        &mut cursor,
        "contested",
        1,
    );
    let batch_a = s.app.prepare(1, ev, rec, None).unwrap().batch().clone();

    // batch_b: SAME slug against the SAME genesis frontier (a second,
    // identical scenario) — stale the moment batch_a lands.
    let mut cursor_b = 0usize;
    let (ev_b, rec_b, _) = fixture::first_create(
        &s2.app,
        &s2.owners[1],
        &mut s2.sources,
        &mut cursor_b,
        "contested",
        2,
    );
    let batch_b = s2
        .app
        .prepare(1, ev_b, rec_b, None)
        .unwrap()
        .batch()
        .clone();
    assert_ne!(batch_a.value_id(), batch_b.value_id());

    // batch_c: the honest h=2 batch, prepared against genesis + batch_a.
    let checked = s.app.validate(&batch_a).unwrap();
    s.app.apply_locally(checked);
    let (ev_c, rec_c, _) = fixture::first_create(
        &s.app,
        &s.owners[2],
        &mut s.sources,
        &mut cursor,
        "fallback",
        3,
    );
    let batch_c = s.app.prepare(2, ev_c, rec_c, None).unwrap().batch().clone();

    // The selected proposer for (h, r) is validators[(h + r) % 4].
    // h1r0 -> index 1, h2r0 -> index 2 (the stale batch), h2r1 -> index 3.
    let mut held_for: Vec<BTreeMap<u64, Batch>> = set
        .validators
        .iter()
        .map(|_| BTreeMap::from([(1, batch_a.clone()), (2, batch_c.clone())]))
        .collect();
    held_for[2].insert(2, batch_b.clone());
    // Map sorted validator order back to key order.
    let mut nodes = Vec::new();
    for (i, key) in keys.iter().enumerate() {
        let address = Address::from_public_key(&key.public_key());
        let sorted = set
            .validators
            .iter()
            .position(|v| v.address == address)
            .unwrap();
        nodes.push(
            RoomNode::start(NodeSpec {
                home: base.join(format!("n{}", i + 1)),
                config: node_config(i + 1, 4, base_port),
                node_key: key.clone(),
                validator_sets: sched(set.clone()),
                held: held_for[sorted].clone(),
                genesis: genesis(),
                wal_faults: None,
                net_gate: None,
            })
            .await,
        );
    }

    wait_for(
        "all four nodes to commit height 2 after the stale round",
        || nodes.iter().all(|n| n.committed_height() >= 2),
        Duration::from_secs(120),
    )
    .await;

    // The committed value at h=2 is batch_c's real commitment on every
    // node — batch_b's stale allocation never entered a journal.
    for node in &nodes {
        let journal = vhalla_journal::Journal::new(
            node.home.join("app").join("journal"),
            vhalla_journal::FsStore,
        );
        let id = journal.at_height(2).unwrap().unwrap();
        let bundle = journal.bundle(id).unwrap().unwrap();
        assert_eq!(
            bundle.field(4).unwrap(),
            &batch_c.value_id()[..],
            "height-2 bundle must bind batch_c, not the stale competitor"
        );
        let expected = nodes[0].adapter.lock().unwrap().frontier().commitment();
        assert_eq!(
            node.adapter.lock().unwrap().frontier().commitment(),
            expected
        );
    }

    for node in nodes {
        node.crash().await;
    }
    let _ = std::fs::remove_dir_all(&base);
}

/// A forged batch with the CORRECT predecessor but an operation that
/// fails replay — a second creation for an owner whose account cannot
/// cover the quadratic slot charge — is voted Invalid by every validator,
/// and the round advances to an honest batch. This is the
/// semantically-invalid allocation case plus the faulty-proposer case:
/// the h=2 round-0 proposer emits a batch that no honest node can replay.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn sibling_slot_batch_voted_down_then_honest_batch_commits() {
    let (keys, set) = validators(4);
    let base = fixture("sibling");
    let base_port = 27900usize;

    // batch_a occupies owner 0's slot 1 at h=1.
    let mut s = fixture::scenario(8, 16);
    let mut cursor = 0usize;
    let (ev, rec, grant_a) = fixture::first_create(
        &s.app,
        &s.owners[0],
        &mut s.sources,
        &mut cursor,
        "alpha",
        1,
    );
    let batch_a = s.app.prepare(1, ev, rec, None).unwrap().batch().clone();
    let checked = s.app.validate(&batch_a).unwrap();
    s.app.apply_locally(checked);

    // Forged batch: correct parent (frontier after batch_a), but the
    // operation is a second creation for owner 0 with no funding
    // evidence — slot 2 costs 4 credits the account does not hold, so
    // replay fails Registry::apply on every node. Direct construction is
    // the byzantine path: `prepare` could never emit this batch.
    let forged = Batch {
        parent: s.app.frontier(),
        time: 2,
        evidence: Vec::new(),
        records: vec![
            fixture::creation_record(&s.owners[0], grant_a, grant_a, "beta", 2, 4, 9).encode(),
        ],
        games: Vec::new(),
        eligible: None,
        result_registry: [9; 32],
        result_social: [9; 32],
        result_control: [9; 32],
    };

    // batch_c: the honest h=2 batch against genesis + batch_a.
    let (ev_c, rec_c, _) = fixture::first_create(
        &s.app,
        &s.owners[1],
        &mut s.sources,
        &mut cursor,
        "fallback",
        3,
    );
    let batch_c = s.app.prepare(2, ev_c, rec_c, None).unwrap().batch().clone();

    // h2r0 -> sorted index 2 (forged), h2r1 -> sorted index 3 (honest).
    let mut held_for: Vec<BTreeMap<u64, Batch>> = set
        .validators
        .iter()
        .map(|_| BTreeMap::from([(1, batch_a.clone()), (2, batch_c.clone())]))
        .collect();
    held_for[2].insert(2, forged.clone());
    let mut nodes = Vec::new();
    for (i, key) in keys.iter().enumerate() {
        let address = Address::from_public_key(&key.public_key());
        let sorted = set
            .validators
            .iter()
            .position(|v| v.address == address)
            .unwrap();
        nodes.push(
            RoomNode::start(NodeSpec {
                home: base.join(format!("n{}", i + 1)),
                config: node_config(i + 1, 4, base_port),
                node_key: key.clone(),
                validator_sets: sched(set.clone()),
                held: held_for[sorted].clone(),
                genesis: genesis(),
                wal_faults: None,
                net_gate: None,
            })
            .await,
        );
    }

    wait_for(
        "all four nodes to commit height 2 after rejecting the sibling batch",
        || nodes.iter().all(|n| n.committed_height() >= 2),
        Duration::from_secs(120),
    )
    .await;

    for node in &nodes {
        let journal = vhalla_journal::Journal::new(
            node.home.join("app").join("journal"),
            vhalla_journal::FsStore,
        );
        let id = journal.at_height(2).unwrap().unwrap();
        let bundle = journal.bundle(id).unwrap().unwrap();
        assert_eq!(
            bundle.field(4).unwrap(),
            &batch_c.value_id()[..],
            "height-2 bundle must bind batch_c, not the forged sibling batch"
        );
        let expected = nodes[0].adapter.lock().unwrap().frontier().commitment();
        assert_eq!(
            node.adapter.lock().unwrap().frontier().commitment(),
            expected
        );
    }

    for node in nodes {
        node.crash().await;
    }
    let _ = std::fs::remove_dir_all(&base);
}

/// Withheld data is a bounded stall, not a halt: the h=2 round-0
/// proposer holds no batch for that height, never answers `GetValue`,
/// and the proposal timeout advances consensus to round 1, where the
/// honest proposer's batch commits. The liveness cost is one timed-out
/// round (~3 s under LinearTimeouts::default), not a stuck height.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn withheld_proposal_times_out_then_honest_batch_commits() {
    let (keys, set) = validators(4);
    let base = fixture("withheld");
    let base_port = 28000usize;

    let mut s = fixture::scenario(8, 16);
    let mut cursor = 0usize;
    let (ev, rec, _) = fixture::first_create(
        &s.app,
        &s.owners[0],
        &mut s.sources,
        &mut cursor,
        "alpha",
        1,
    );
    let batch_a = s.app.prepare(1, ev, rec, None).unwrap().batch().clone();
    let checked = s.app.validate(&batch_a).unwrap();
    s.app.apply_locally(checked);
    let (ev_c, rec_c, _) = fixture::first_create(
        &s.app,
        &s.owners[1],
        &mut s.sources,
        &mut cursor,
        "fallback",
        3,
    );
    let batch_c = s.app.prepare(2, ev_c, rec_c, None).unwrap().batch().clone();

    // h2r0 -> sorted index 2 holds ONLY the h=1 batch: it must produce
    // nothing for h=2. h2r1 -> sorted index 3 holds the honest batch.
    let mut held_for: Vec<BTreeMap<u64, Batch>> = set
        .validators
        .iter()
        .map(|_| BTreeMap::from([(1, batch_a.clone()), (2, batch_c.clone())]))
        .collect();
    held_for[2].remove(&2);
    let mut nodes = Vec::new();
    for (i, key) in keys.iter().enumerate() {
        let address = Address::from_public_key(&key.public_key());
        let sorted = set
            .validators
            .iter()
            .position(|v| v.address == address)
            .unwrap();
        nodes.push(
            RoomNode::start(NodeSpec {
                home: base.join(format!("n{}", i + 1)),
                config: node_config(i + 1, 4, base_port),
                node_key: key.clone(),
                validator_sets: sched(set.clone()),
                held: held_for[sorted].clone(),
                genesis: genesis(),
                wal_faults: None,
                net_gate: None,
            })
            .await,
        );
    }

    let started = Instant::now();
    wait_for(
        "all four nodes to commit height 2 past the withheld proposal",
        || nodes.iter().all(|n| n.committed_height() >= 2),
        Duration::from_secs(120),
    )
    .await;
    // The stall must be timeout-bounded: a withheld round costs seconds,
    // never the whole window.
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "withheld proposal stalled finalization for {:?}",
        started.elapsed()
    );

    for node in &nodes {
        let journal = vhalla_journal::Journal::new(
            node.home.join("app").join("journal"),
            vhalla_journal::FsStore,
        );
        let id = journal.at_height(2).unwrap().unwrap();
        let bundle = journal.bundle(id).unwrap().unwrap();
        assert_eq!(
            bundle.field(4).unwrap(),
            &batch_c.value_id()[..],
            "height-2 bundle must bind the honest batch"
        );
    }

    for node in nodes {
        node.crash().await;
    }
    let _ = std::fs::remove_dir_all(&base);
}

/// WAL append failure -> the engine's own safety halt, no bypass: the
/// faulted validator's first Append reports Err, `hang_on_safety_failure`
/// hangs its consensus actor, and it never signs or commits again. The
/// remaining three validators hold quorum and keep committing; a clean
/// restart on the same home replays the (unwritten) WAL and value-syncs
/// to the same frontier.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn wal_append_failure_safety_halts_then_recovers() {
    const HEIGHTS: u64 = 3;
    let plan = batch_plan(HEIGHTS + 1);
    let (keys, set) = validators(4);
    let base = fixture("wal-fail");
    let base_port = 28100usize;

    let mut nodes = Vec::new();
    for (i, key) in keys.iter().enumerate() {
        let wal_faults = (i == 0).then(|| {
            std::sync::Arc::new(Mutex::new(WalPlan {
                appends: VecDeque::from([WalFault::Fail]),
                flushes: VecDeque::new(),
            }))
        });
        nodes.push(
            RoomNode::start(NodeSpec {
                home: base.join(format!("n{}", i + 1)),
                config: node_config(i + 1, 4, base_port),
                node_key: key.clone(),
                validator_sets: sched(set.clone()),
                held: plan.clone(),
                genesis: genesis(),
                wal_faults,
                net_gate: None,
            })
            .await,
        );
    }

    // Three honest validators keep quorum and commit all heights.
    wait_for(
        "the three unfaulted validators to commit all heights",
        || nodes[1..].iter().all(|n| n.committed_height() >= HEIGHTS),
        Duration::from_secs(90),
    )
    .await;

    // The faulted node safety-halted: its journal stays empty and it
    // never emitted an ack.
    assert_eq!(nodes[0].committed_height(), 0);
    assert!(nodes[0].acks().is_empty());

    // Kill the halted engine and restart clean on the same home. The
    // journal frontier is empty, WAL replays nothing, value-sync
    // restores the committed heights, and the node rejoins at h=4.
    let victim = nodes.remove(0);
    victim.crash().await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let restarted = RoomNode::start(NodeSpec {
        home: base.join("n1"),
        config: node_config(1, 4, base_port),
        node_key: keys[0].clone(),
        validator_sets: sched(set.clone()),
        held: plan.clone(),
        genesis: genesis(),
        wal_faults: None,
        net_gate: None,
    })
    .await;

    wait_for(
        "restarted faulted validator to catch up and commit height 4",
        || restarted.committed_height() > HEIGHTS,
        Duration::from_secs(120),
    )
    .await;
    wait_for(
        "peers to reach height 4",
        || nodes.iter().all(|n| n.committed_height() > HEIGHTS),
        Duration::from_secs(60),
    )
    .await;

    let converged = restarted.adapter.lock().unwrap().frontier().commitment();
    for node in &nodes {
        assert_eq!(
            node.adapter.lock().unwrap().frontier().commitment(),
            converged
        );
    }
    assert_eq!(
        restarted.adapter.lock().unwrap().frontier().height,
        HEIGHTS + 1
    );

    restarted.crash().await;
    for node in nodes {
        node.crash().await;
    }
    let _ = std::fs::remove_dir_all(&base);
}

/// Silent WAL loss (the fsync-lie case): every Append replies Ok but is
/// never written. The faulted validator commits normally — the failure
/// is invisible until restart — then crashes into an EMPTY wal. Replay
/// reconstructs nothing, `ConsensusReady` resumes from the durable
/// journal frontier, and each height's marker reconciles the commit
/// exactly once rather than re-applying.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn wal_silent_append_loss_recovers_via_journal() {
    const HEIGHTS: u64 = 3;
    let plan = batch_plan(HEIGHTS + 1);
    let (keys, set) = validators(4);
    let base = fixture("wal-drop");
    let base_port = 28200usize;

    let mut nodes = Vec::new();
    for (i, key) in keys.iter().enumerate() {
        // Drop the victim's first 256 appends — comfortably beyond the
        // entry count of a four-height run.
        let wal_faults = (i == 0).then(|| {
            std::sync::Arc::new(Mutex::new(WalPlan {
                appends: VecDeque::from([WalFault::Drop; 256]),
                flushes: VecDeque::new(),
            }))
        });
        nodes.push(
            RoomNode::start(NodeSpec {
                home: base.join(format!("n{}", i + 1)),
                config: node_config(i + 1, 4, base_port),
                node_key: key.clone(),
                validator_sets: sched(set.clone()),
                held: plan.clone(),
                genesis: genesis(),
                wal_faults,
                net_gate: None,
            })
            .await,
        );
    }

    wait_for(
        "all four nodes (including the silently-lossy one) to commit height 3",
        || nodes.iter().all(|n| n.committed_height() >= HEIGHTS),
        Duration::from_secs(90),
    )
    .await;

    // The victim's WAL on disk contains no committed-vote entries —
    // replay after restart must not resurrect an undecided state.
    let victim = nodes.remove(0);
    let victim_wal = victim.home.join("wal").join("consensus.wal");
    victim.crash().await;
    let wal_bytes = std::fs::read(&victim_wal).unwrap_or_default();
    assert!(
        wal_bytes.len() < 1024,
        "dropped appends must leave a near-empty WAL, got {} B",
        wal_bytes.len()
    );

    tokio::time::sleep(Duration::from_secs(2)).await;
    let restarted = RoomNode::start(NodeSpec {
        home: base.join("n1"),
        config: node_config(1, 4, base_port),
        node_key: keys[0].clone(),
        validator_sets: sched(set.clone()),
        held: plan.clone(),
        genesis: genesis(),
        wal_faults: None,
        net_gate: None,
    })
    .await;

    // The restarted node resumes from the journal frontier and commits
    // h=4 with the group — each prior height stays applied exactly once.
    wait_for(
        "restarted node to resume from the journal frontier and commit height 4",
        || restarted.committed_height() > HEIGHTS,
        Duration::from_secs(120),
    )
    .await;
    wait_for(
        "peers to reach height 4",
        || nodes.iter().all(|n| n.committed_height() > HEIGHTS),
        Duration::from_secs(60),
    )
    .await;

    let converged = restarted.adapter.lock().unwrap().frontier().commitment();
    for node in &nodes {
        assert_eq!(
            node.adapter.lock().unwrap().frontier().commitment(),
            converged
        );
    }
    // Exactly-once: the journal's height index still holds one bundle id
    // per committed height.
    let journal = vhalla_journal::Journal::new(
        restarted.home.join("app").join("journal"),
        vhalla_journal::FsStore,
    );
    for h in 1..=HEIGHTS {
        assert!(journal.at_height(h).unwrap().is_some());
    }
    assert_eq!(
        restarted.adapter.lock().unwrap().frontier().height,
        HEIGHTS + 1
    );

    restarted.crash().await;
    for node in nodes {
        node.crash().await;
    }
    let _ = std::fs::remove_dir_all(&base);
}

/// Partition variant of the competing-slug case: a validator
/// partitioned through the h=1 decision (modelled as a late start — it
/// could not vote, same as an unreachable node; a runtime mid-test
/// partition is not expressible with static persistent peers) rejoins
/// holding a
/// concurrently-prepared batch whose parent is the PRE-partition
/// frontier. It syncs h=1, proposes its stale batch at h=2 round 0, and
/// every validator votes it down on the exact predecessor check; round
/// 1 finalizes the honest batch and the rejoined node's journal binds
/// the winner.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn partitioned_validator_rejoins_and_stale_competitor_loses() {
    const HEIGHTS: u64 = 2;
    let (keys, set) = validators(4);
    let base = fixture("partitioned-compete");
    let base_port = 28300usize;

    // batch_a: the winner committed by the connected side at h=1.
    let mut s = fixture::scenario(8, 16);
    let mut s2 = fixture::scenario(8, 16);
    let mut cursor = 0usize;
    let (ev, rec, _) = fixture::first_create(
        &s.app,
        &s.owners[0],
        &mut s.sources,
        &mut cursor,
        "contested",
        1,
    );
    let batch_a = s.app.prepare(1, ev, rec, None).unwrap().batch().clone();

    // batch_b: a competing allocation for the SAME slug, prepared
    // against genesis — valid when prepared, stale the moment batch_a
    // landed on the other side of the partition.
    let mut cursor_b = 0usize;
    let (ev_b, rec_b, _) = fixture::first_create(
        &s2.app,
        &s2.owners[1],
        &mut s2.sources,
        &mut cursor_b,
        "contested",
        2,
    );
    let batch_b = s2
        .app
        .prepare(1, ev_b, rec_b, None)
        .unwrap()
        .batch()
        .clone();

    // batch_c: the honest h=2 batch against genesis + batch_a.
    let checked = s.app.validate(&batch_a).unwrap();
    s.app.apply_locally(checked);
    let (ev_c, rec_c, _) = fixture::first_create(
        &s.app,
        &s.owners[2],
        &mut s.sources,
        &mut cursor,
        "fallback",
        3,
    );
    let batch_c = s.app.prepare(2, ev_c, rec_c, None).unwrap().batch().clone();

    // The connected side (sorted indices 0,1,3) starts with the honest
    // plan. The h2r0 proposer — sorted index 2 — is the partitioned
    // node: it starts late holding ONLY the stale competitor at h=2.
    let honest = BTreeMap::from([(1u64, batch_a.clone()), (2u64, batch_c.clone())]);
    let mut nodes = Vec::new();
    for (i, key) in keys.iter().enumerate() {
        let address = Address::from_public_key(&key.public_key());
        let sorted = set
            .validators
            .iter()
            .position(|v| v.address == address)
            .unwrap();
        if sorted == 2 {
            continue; // partitioned — starts after the h=1 decision
        }
        nodes.push(
            RoomNode::start(NodeSpec {
                home: base.join(format!("n{}", i + 1)),
                config: node_config(i + 1, 4, base_port),
                node_key: key.clone(),
                validator_sets: sched(set.clone()),
                held: honest.clone(),
                genesis: genesis(),
                wal_faults: None,
                net_gate: None,
            })
            .await,
        );
    }

    // The connected three commit h=1 alone.
    wait_for(
        "connected validators to commit height 1 during the partition",
        || nodes.iter().all(|n| n.committed_height() >= 1),
        Duration::from_secs(90),
    )
    .await;

    // The partition heals: the late node joins holding the stale
    // competitor at h=2 plus the committed batch_a for replay.
    let late_key = keys
        .iter()
        .enumerate()
        .find(|(_, key)| {
            let address = Address::from_public_key(&key.public_key());
            set.validators
                .iter()
                .position(|v| v.address == address)
                .unwrap()
                == 2
        })
        .map(|(i, key)| (i, key.clone()))
        .unwrap();
    let rejoined = RoomNode::start(NodeSpec {
        home: base.join(format!("n{}", late_key.0 + 1)),
        config: node_config(late_key.0 + 1, 4, base_port),
        node_key: late_key.1,
        validator_sets: sched(set.clone()),
        held: BTreeMap::from([(1, batch_a.clone()), (2, batch_b.clone())]),
        genesis: genesis(),
        wal_faults: None,
        net_gate: None,
    })
    .await;
    nodes.push(rejoined);

    // All four converge at h=2: the rejoined proposer's stale batch is
    // rejected, round 1 finalizes the honest batch.
    wait_for(
        "all four nodes to commit height 2 past the stale proposal",
        || nodes.iter().all(|n| n.committed_height() >= HEIGHTS),
        Duration::from_secs(120),
    )
    .await;

    for node in &nodes {
        let journal = vhalla_journal::Journal::new(
            node.home.join("app").join("journal"),
            vhalla_journal::FsStore,
        );
        let id = journal.at_height(2).unwrap().unwrap();
        let bundle = journal.bundle(id).unwrap().unwrap();
        assert_eq!(
            bundle.field(4).unwrap(),
            &batch_c.value_id()[..],
            "the stale partition-side allocation must never enter a journal"
        );
        // VC2 cert bytes: "VC2" || height(u64) || round(u32) || ...
        // The h=2 decision cannot be round 0 — that round's proposer was
        // the partitioned node, whose stale batch is either absent or
        // unanimously invalid.
        let cert = bundle.field(0).unwrap();
        let round = u32::from_be_bytes(cert[11..15].try_into().unwrap());
        assert!(
            round >= 1,
            "h=2 committed at round {round}; round 0 was the partitioned proposer's slot"
        );
        let expected = nodes[0].adapter.lock().unwrap().frontier().commitment();
        assert_eq!(
            node.adapter.lock().unwrap().frontier().commitment(),
            expected
        );
    }

    for node in nodes {
        node.crash().await;
    }
    let _ = std::fs::remove_dir_all(&base);
}

/// TRUE runtime partition: a `GateNetwork` proxy wraps the real libp2p
/// actor — while the gate is closed the node's data-plane traffic drops
/// in BOTH directions with the process still running (sockets stay up;
/// the node is deaf and mute, not absent). Unlike the late-start model
/// the partitioned validator is alive and spinning timeout rounds the
/// whole time; the majority keeps quorum, the isolated validator learns
/// nothing until the gate reopens, then value-syncs and rejoins with an
/// identical frontier.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn runtime_partition_isolates_then_heals_and_rejoins() {
    const HEIGHTS: u64 = 3;
    let plan = batch_plan(HEIGHTS);
    let (keys, set) = validators(4);
    let base = fixture("rt-partition");
    let base_port = 28400usize;

    // The gated node is sorted index 2 — the h2r0 proposer — so the
    // partition also spends the majority one timed-out round.
    let gate = NetGate::new();
    // Cut before any node starts: heights commit in ~tens of
    // milliseconds, so a post-start close could race the first
    // certificate. The gated node still boots, connects, and spins
    // timeout rounds — a live process, deaf and mute.
    gate.close();
    let mut gated_addr = None;
    let mut nodes = Vec::new();
    for (i, key) in keys.iter().enumerate() {
        let address = Address::from_public_key(&key.public_key());
        let sorted = set
            .validators
            .iter()
            .position(|v| v.address == address)
            .unwrap();
        let net_gate = (sorted == 2).then(|| gate.clone());
        if net_gate.is_some() {
            gated_addr = Some(address);
        }
        nodes.push(
            RoomNode::start(NodeSpec {
                home: base.join(format!("n{}", i + 1)),
                config: node_config(i + 1, 4, base_port),
                node_key: key.clone(),
                validator_sets: sched(set.clone()),
                held: plan.clone(),
                genesis: genesis(),
                wal_faults: None,
                net_gate,
            })
            .await,
        );
    }
    let gated_addr = gated_addr.unwrap();

    // The other three still hold quorum and decide two full heights:
    // h=1 at round 0 (its proposer is connected) and h=2 at a later
    // round (round 0's proposer is the gated node — its publish dies on
    // the gate and the timeout prevotes nil).
    wait_for(
        "the majority to commit heights 1-2 across the partition",
        || {
            nodes
                .iter()
                .filter(|n| n.address != gated_addr)
                .all(|n| n.committed_height() >= 2)
        },
        Duration::from_secs(90),
    )
    .await;

    // The isolated node is RUNNING the whole time: several sync
    // intervals pass after the majority lands h=2 and its durable
    // frontier still knows nothing.
    tokio::time::sleep(Duration::from_secs(8)).await;
    let isolated = nodes.iter().find(|n| n.address == gated_addr).unwrap();
    assert_eq!(
        isolated.committed_height(),
        0,
        "a gated validator must learn nothing during the partition"
    );

    // Heal: traffic flows again on the live sockets — the node
    // value-syncs h=1 and h=2 and rejoins the group for h=3.
    gate.reopen();
    wait_for(
        "all four nodes to converge at height 3 after the partition heals",
        || nodes.iter().all(|n| n.committed_height() >= HEIGHTS),
        Duration::from_secs(120),
    )
    .await;

    for node in &nodes {
        let journal = vhalla_journal::Journal::new(
            node.home.join("app").join("journal"),
            vhalla_journal::FsStore,
        );
        let id = journal.at_height(2).unwrap().unwrap();
        let bundle = journal.bundle(id).unwrap().unwrap();
        // h=2 could not commit at round 0 — that proposer was gated.
        let cert = bundle.field(0).unwrap();
        let round = u32::from_be_bytes(cert[11..15].try_into().unwrap());
        assert!(
            round >= 1,
            "h=2 committed at round {round}; round 0 belonged to the gated proposer"
        );
        let expected = nodes[0].adapter.lock().unwrap().frontier().commitment();
        assert_eq!(
            node.adapter.lock().unwrap().frontier().commitment(),
            expected
        );
    }

    for node in nodes {
        node.crash().await;
    }
    let _ = std::fs::remove_dir_all(&base);
}

/// The public validator pin used by the real transport.
fn peer_id_of(public_key: &PublicKey) -> PeerId {
    net_peer_id(public_key).parse().unwrap()
}

/// Asymmetric divergence at the fault bound: N=7 (f=2, quorum 5) splits
/// into a five-node majority island and a two-node minority island. The
/// minority holds the h=1 round-0/1 proposer slots and campaigns a REAL
/// competing batch between themselves — valid records, correct parent,
/// different slug — while the majority waits out two timed-out rounds
/// and commits the honest plan. On heal the minority's divergent
/// campaign is discarded wholesale: they value-sync the committed
/// heights and every journal binds the majority's value.
///
/// This is the largest divergence the protocol admits: two honest sides
/// can never both reach quorum (intersection forbids it), so the
/// contested case is a sized-f minority campaigning a value that can
/// never finalize against a majority that does.
#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
async fn asymmetric_island_minority_campaigns_then_converges() {
    const HEIGHTS: u64 = 3;
    let (keys, set) = validators(7);
    let base = fixture("asym-island");
    let base_port = 28800usize;

    // batch_a: the honest h=1 batch committed by the majority island.
    let mut s = fixture::scenario(8, 16);
    let mut s2 = fixture::scenario(8, 16);
    let mut cursor = 0usize;
    let (ev, rec, _) = fixture::first_create(
        &s.app,
        &s.owners[0],
        &mut s.sources,
        &mut cursor,
        "isle-a",
        1,
    );
    let batch_a = s.app.prepare(1, ev, rec, None).unwrap().batch().clone();

    // batch_b: the minority island's campaign value — a real batch with
    // the same parent frontier and a different slug, so the island's
    // rounds genuinely diverge rather than merely stall.
    let mut cursor_b = 0usize;
    let (ev_b, rec_b, _) = fixture::first_create(
        &s2.app,
        &s2.owners[1],
        &mut s2.sources,
        &mut cursor_b,
        "isle-b",
        2,
    );
    let batch_b = s2
        .app
        .prepare(1, ev_b, rec_b, None)
        .unwrap()
        .batch()
        .clone();
    assert_ne!(batch_a.value_id(), batch_b.value_id());

    // batch_c / batch_d: honest h=2 and h=3 against the batch_a line.
    let checked = s.app.validate(&batch_a).unwrap();
    s.app.apply_locally(checked);
    let (ev_c, rec_c, _) = fixture::first_create(
        &s.app,
        &s.owners[2],
        &mut s.sources,
        &mut cursor,
        "isle-c",
        3,
    );
    let batch_c = s.app.prepare(2, ev_c, rec_c, None).unwrap().batch().clone();
    let checked = s.app.validate(&batch_c).unwrap();
    s.app.apply_locally(checked);
    let (ev_d, rec_d, _) = fixture::first_create(
        &s.app,
        &s.owners[3],
        &mut s.sources,
        &mut cursor,
        "isle-d",
        4,
    );
    let batch_d = s.app.prepare(3, ev_d, rec_d, None).unwrap().batch().clone();

    // Sorted indices: proposer(h, r) = set[(h + r) % 7]. The minority
    // island {1, 2} owns h1r0, h1r1 AND h2r0 — the majority cannot
    // commit h=1 before round 2 and h=2 before round 1.
    let minority: HashSet<usize> = [1usize, 2].into_iter().collect();
    let sorted_addresses: Vec<Address> = set.validators.iter().map(|v| v.address).collect();
    let sorted_peers: Vec<PeerId> = set
        .validators
        .iter()
        .map(|validator| peer_id_of(&validator.public_key))
        .collect();

    let honest = BTreeMap::from([
        (1u64, batch_a.clone()),
        (2u64, batch_c.clone()),
        (3u64, batch_d.clone()),
    ]);
    let mut gates = Vec::new();
    let mut nodes = Vec::new();
    for (i, key) in keys.iter().enumerate() {
        let address = Address::from_public_key(&key.public_key());
        let sorted = sorted_addresses.iter().position(|a| *a == address).unwrap();
        // Island cut: each node blocks the OTHER island's peer ids, so
        // intra-island gossip flows and inter-island events drop.
        let in_minority = minority.contains(&sorted);
        let gate = NetGate::new();
        gate.isolate_from(
            (0..7)
                .filter(|s| minority.contains(s) != in_minority)
                .map(|s| sorted_peers[s]),
        );
        gates.push(gate.clone());
        let mut held = honest.clone();
        if in_minority {
            // Both minority validators campaign the rival h=1 batch:
            // sorted-1 proposes it at h1r0, sorted-2 re-proposes at h1r1.
            held.insert(1, batch_b.clone());
        }
        nodes.push(
            RoomNode::start(NodeSpec {
                home: base.join(format!("n{}", i + 1)),
                config: node_config(i + 1, 7, base_port),
                node_key: key.clone(),
                validator_sets: sched(set.clone()),
                held,
                genesis: genesis(),
                wal_faults: None,
                net_gate: Some(gate),
            })
            .await,
        );
    }
    let minority_addrs: HashSet<Address> = minority.iter().map(|s| sorted_addresses[*s]).collect();

    // The majority island spends rounds 0 and 1 of h=1 waiting out the
    // islanded proposers, then commits the honest plan.
    wait_for(
        "the five-node majority to commit heights 1-2 across the island cut",
        || {
            nodes
                .iter()
                .filter(|n| !minority_addrs.contains(&n.address))
                .all(|n| n.committed_height() >= 2)
        },
        Duration::from_secs(120),
    )
    .await;

    // The minority island is RUNNING and campaigning the whole time:
    // several sync intervals pass after the majority lands h=2 and its
    // durable frontier still knows nothing.
    tokio::time::sleep(Duration::from_secs(8)).await;
    for node in nodes.iter().filter(|n| minority_addrs.contains(&n.address)) {
        assert_eq!(
            node.committed_height(),
            0,
            "a two-node island can campaign but never finalize (quorum 5)"
        );
    }

    // Heal: every blocklist clears — the minority value-syncs the
    // committed heights and all seven join h=3.
    for gate in &gates {
        gate.reunite();
    }
    wait_for(
        "all seven nodes to converge at height 3 after reunification",
        || nodes.iter().all(|n| n.committed_height() >= HEIGHTS),
        Duration::from_secs(180),
    )
    .await;

    // Every journal — the minority's included — binds the majority's
    // batch_a at h=1; the island's campaign value never finalized.
    for node in &nodes {
        let journal = vhalla_journal::Journal::new(
            node.home.join("app").join("journal"),
            vhalla_journal::FsStore,
        );
        let id = journal.at_height(1).unwrap().unwrap();
        let bundle = journal.bundle(id).unwrap().unwrap();
        assert_eq!(
            bundle.field(4).unwrap(),
            &batch_a.value_id()[..],
            "height-1 bundle must bind the majority batch, not the island's rival"
        );
        // h=1 could not commit at round 0 or 1 — both proposers were
        // islanded; the majority's proposer first speaks at round 2.
        let cert = bundle.field(0).unwrap();
        let round = u32::from_be_bytes(cert[11..15].try_into().unwrap());
        assert!(
            round >= 2,
            "h=1 committed at round {round}; rounds 0-1 belonged to islanded proposers"
        );
        let expected = nodes[0].adapter.lock().unwrap().frontier().commitment();
        assert_eq!(
            node.adapter.lock().unwrap().frontier().commitment(),
            expected
        );
    }

    for node in nodes {
        node.crash().await;
    }
    let _ = std::fs::remove_dir_all(&base);
}

/// Reordered input: a proposal stream's Init/Data/Fin parts may arrive in
/// ANY order — the assembler keys state by part kind, not sequence —
/// and the completed stream still verifies and votes. This exercises the
/// reorder tolerance at the exact `ReceivedProposalPart` seam without a
/// network: parts built by a proposer App are fed back permuted.
#[test]
fn reordered_proposal_parts_still_assemble_and_verify() {
    let (keys, set) = validators(1);
    let base = fixture("reorder");
    let key = keys[0].clone();
    let address = Address::from_public_key(&key.public_key());

    let store = base.join("store");
    std::fs::create_dir_all(store.join("batches")).unwrap();
    std::fs::create_dir_all(store.join("seen")).unwrap();
    let mut app = App {
        ctx: RoomContext,
        adapter: Arc::new(Mutex::new(
            Adapter::open(base.join("app"), &genesis()).unwrap(),
        )),
        sink: Arc::new(Mutex::new(EngineSink::default())),
        validator_sets: sched(set),
        address,
        private_key: key.clone(),
        proposals: BTreeMap::new(),
        pending_proposals: VecDeque::new(),
        assigned_bodies: BTreeMap::new(),
        held_by_id: BTreeMap::new(),
        streams: BTreeMap::new(),
        parts_cache: BTreeMap::new(),
        decided: BTreeMap::new(),
        stream_seq: 0,
        boundary_latency: Arc::new(Mutex::new(Vec::new())),
        store,
        seen: BTreeMap::new(),
        resupplied: Arc::new(Mutex::new(0)),
        held_replies: Vec::new(),
    };

    let mut s = fixture::scenario(8, 16);
    let mut cursor = 0usize;
    let (ev, rec, _) = fixture::first_create(
        &s.app,
        &s.owners[0],
        &mut s.sources,
        &mut cursor,
        "alpha",
        1,
    );
    let batch = s.app.prepare(1, ev, rec, None).unwrap().batch().clone();
    let proposed = LocallyProposedValue::new(
        Height::new(1),
        Round::new(0),
        RoomValue::new(batch.value_id(), batch.encode().into()),
    );
    let parts = app.build_parts(&proposed);
    // Init + `Data` chunks bounded for small-transport writes + Fin.
    assert!(matches!(parts.first(), Some(RoomPart::Init(_))));
    assert!(matches!(parts.last(), Some(RoomPart::Fin(_))));
    let chunk_total: usize = parts[1..parts.len() - 1]
        .iter()
        .map(|p| match p {
            RoomPart::Data(d) => {
                assert!(
                    d.len() <= PROPOSAL_CHUNK_BYTES,
                    "Data chunk exceeds the transport-safe bound"
                );
                d.len()
            }
            other => panic!("middle part is not Data: {other:?}"),
        })
        .sum();
    assert_eq!(chunk_total, batch.encode().len());

    let stream = app.stream_id(Height::new(1), Round::new(0));
    let peer = PeerId::random();
    let msg = |seq, content| StreamMessage::new(stream.clone(), seq, content);

    // Deliver every part in reverse order but keep each part's ORIGINAL
    // stream sequence — the assembler must restore emission order, so
    // permuted Data chunks still concatenate into the canonical bytes.
    for (i, part) in parts.iter().enumerate().rev() {
        assert!(
            app.handle_part(peer, msg(i as u64, StreamContent::Data(part.clone())))
                .is_none(),
            "incomplete stream must not produce a value"
        );
    }
    let done = app
        .handle_part(peer, msg(parts.len() as u64, StreamContent::Fin))
        .expect("closed complete stream must assemble");
    assert!(done.validity.is_valid(), "reassembled stream must verify");
    assert_eq!(done.value.id.0, batch.value_id());
    assert_eq!(&done.value.bytes[..], &batch.encode()[..]);

    // A second stream keyed differently stays independent.
    let stream2 = app.stream_id(Height::new(1), Round::new(0));
    let msg2 = |seq, content| StreamMessage::new(stream2.clone(), seq, content);
    assert!(app
        .handle_part(peer, msg2(0, StreamContent::Data(parts[0].clone())))
        .is_none());
    assert!(
        app.handle_part(peer, msg2(1, StreamContent::Fin)).is_none(),
        "stream missing Data and Fin part must not assemble"
    );

    let _ = std::fs::remove_dir_all(&base);
}

/// Transport-bound chunking: a value larger than one relayed-write
/// ceiling (observed ~1.2 KiB over tailcat/DERP) must fan out into
/// multiple `Data` parts — each under `PROPOSAL_CHUNK_BYTES` of raw
/// payload so codec + gossipsub framing still fits — and the received
/// stream must reassemble the exact bytes in sequence order.
#[test]
fn large_values_chunk_into_bounded_data_parts() {
    let (keys, set) = validators(1);
    let base = fixture("chunked");
    let key = keys[0].clone();
    let address = Address::from_public_key(&key.public_key());

    let store = base.join("store");
    std::fs::create_dir_all(store.join("batches")).unwrap();
    std::fs::create_dir_all(store.join("seen")).unwrap();
    let mut app = App {
        ctx: RoomContext,
        adapter: Arc::new(Mutex::new(
            Adapter::open(base.join("app"), &genesis()).unwrap(),
        )),
        sink: Arc::new(Mutex::new(EngineSink::default())),
        validator_sets: sched(set),
        address,
        private_key: key.clone(),
        proposals: BTreeMap::new(),
        pending_proposals: VecDeque::new(),
        assigned_bodies: BTreeMap::new(),
        held_by_id: BTreeMap::new(),
        streams: BTreeMap::new(),
        parts_cache: BTreeMap::new(),
        decided: BTreeMap::new(),
        stream_seq: 0,
        boundary_latency: Arc::new(Mutex::new(Vec::new())),
        store,
        seen: BTreeMap::new(),
        resupplied: Arc::new(Mutex::new(0)),
        held_replies: Vec::new(),
    };

    // Three full chunks plus a tail — comfortably over the transport
    // ceiling that truncated a single 3071-byte frame.
    let data = vec![7u8; PROPOSAL_CHUNK_BYTES * 3 + 100];
    let proposed = LocallyProposedValue::new(
        Height::new(1),
        Round::new(0),
        RoomValue::new([9; 32], data.clone().into()),
    );
    let parts = app.build_parts(&proposed);
    assert_eq!(parts.len(), 2 + 4);
    let mut reassembled = Vec::new();
    for p in &parts[1..parts.len() - 1] {
        match p {
            RoomPart::Data(d) => {
                assert!(d.len() <= PROPOSAL_CHUNK_BYTES);
                reassembled.extend_from_slice(d);
            }
            other => panic!("middle part is not Data: {other:?}"),
        }
    }
    assert_eq!(reassembled, data);

    // In-order delivery of the chunked stream assembles the same bytes.
    let stream = app.stream_id(Height::new(1), Round::new(0));
    let peer = PeerId::random();
    let msg = |seq, content| StreamMessage::new(stream.clone(), seq, content);
    for (i, part) in parts.iter().enumerate() {
        assert!(app
            .handle_part(peer, msg(i as u64, StreamContent::Data(part.clone())))
            .is_none());
    }
    let done = app
        .handle_part(peer, msg(parts.len() as u64, StreamContent::Fin))
        .expect("chunked stream must assemble");
    assert_eq!(&done.value.bytes[..], &data[..]);

    let _ = std::fs::remove_dir_all(&base);
}

/// A `GetValue` that arrives while the queue is empty must be HELD, not
/// dropped: the connector awaiting its oneshot dies on `RecvError` and
/// wedges the whole node. The held reply resolves when a value
/// materializes — a late submission answers it at the held request's own
/// height and round — while a still-valueless request past its own
/// deadline resolves as an undecidable tombstone so the sequential
/// connector un-parks.
#[tokio::test]
async fn held_get_value_reply_resolves_on_late_submit() {
    let (keys, set) = validators(1);
    let base = fixture("held-reply");
    let key = keys[0].clone();
    let address = Address::from_public_key(&key.public_key());

    let home = base.join("home");
    let store = home.join("store");
    std::fs::create_dir_all(store.join("batches")).unwrap();
    std::fs::create_dir_all(store.join("seen")).unwrap();
    std::fs::create_dir_all(store.join("pending")).unwrap();
    let intake = home.join("intake");
    std::fs::create_dir_all(&intake).unwrap();

    let mut app = App {
        ctx: RoomContext,
        adapter: Arc::new(Mutex::new(
            Adapter::open(home.join("app"), &genesis()).unwrap(),
        )),
        sink: Arc::new(Mutex::new(EngineSink::default())),
        validator_sets: sched(set),
        address,
        private_key: key.clone(),
        proposals: BTreeMap::new(),
        pending_proposals: VecDeque::new(),
        assigned_bodies: BTreeMap::new(),
        held_by_id: BTreeMap::new(),
        streams: BTreeMap::new(),
        parts_cache: BTreeMap::new(),
        decided: BTreeMap::new(),
        stream_seq: 0,
        boundary_latency: Arc::new(Mutex::new(Vec::new())),
        store,
        seen: BTreeMap::new(),
        resupplied: Arc::new(Mutex::new(0)),
        held_replies: Vec::new(),
    };

    // The engine asks for (h=1, r=0), the same height again at r=1, and
    // a valueless h=9 whose deadline has already passed — while nothing
    // is pending. The live h=1 replies stay held, never dropped; the
    // expired h=9 request resolves immediately as a tombstone.
    let (tx0, rx0) = tokio::sync::oneshot::channel();
    let (tx1, rx1) = tokio::sync::oneshot::channel();
    let (tx9, rx9) = tokio::sync::oneshot::channel();
    let live = Instant::now() + Duration::from_secs(60);
    for (height, round, deadline, tx) in [
        (1u64, Round::new(0), live, tx0),
        (1u64, Round::new(1), live, tx1),
        (9u64, Round::new(0), Instant::now(), tx9),
    ] {
        app.held_replies.push(HeldReply {
            height,
            round,
            deadline,
            reply: tx,
        });
    }

    let answered = app.drain_answerable_held();
    assert_eq!(answered.len(), 1, "only the expired request resolves");
    assert_eq!(app.held_replies.len(), 2);
    let req9 = answered.into_iter().next().unwrap();
    assert_eq!(req9.height, 9);
    assert!(
        req9.value.bytes.is_empty(),
        "a deadline-expired request resolves as an empty tombstone"
    );
    assert!(!req9.live, "a tombstone's parts must never reach the wire");
    assert_ne!(
        req9.value.id.0, [0; 32],
        "tombstone ids bind (node, height, round) — a peer's own tombstone must never collide"
    );
    req9.reply
        .send(LocallyProposedValue::new(
            Height::new(9),
            Round::new(0),
            req9.value,
        ))
        .expect("the expired request's connector still awaits");
    rx9.await.expect("the tombstone reply lands");

    // A batch lands late through the in-process submission path: every
    // held request for its height resolves at the request's own round.
    let mut s = fixture::scenario(8, 16);
    let mut cursor = 0usize;
    let (ev, rec, _) = fixture::first_create(
        &s.app,
        &s.owners[0],
        &mut s.sources,
        &mut cursor,
        "alpha",
        1,
    );
    let batch = s.app.prepare(1, ev, rec, None).unwrap().batch().clone();
    app.submit(batch.clone());

    let answered = app.drain_answerable_held();
    assert_eq!(answered.len(), 2, "both held rounds resolve to the value");
    assert!(app.held_replies.is_empty());
    for req in answered {
        assert!(req.live, "a real value's parts may be published");
        assert_eq!(req.height, 1);
        assert_eq!(&req.value.bytes[..], &batch.encode()[..]);
        req.reply
            .send(LocallyProposedValue::new(
                Height::new(req.height),
                req.round,
                req.value,
            ))
            .expect("the parked connector still awaits its reply");
    }
    let got0 = rx0.await.expect("the r0 reply resolves, never dropped");
    let got1 = rx1.await.expect("the r1 reply resolves, never dropped");
    assert_eq!(got0.round, Round::new(0));
    assert_eq!(got1.round, Round::new(1));
    assert_eq!(&got0.value.bytes[..], &batch.encode()[..]);
    assert_eq!(&got1.value.bytes[..], &batch.encode()[..]);

    let _ = std::fs::remove_dir_all(&base);
}

/// Undecided-proposal replay: a value the node observed must be
/// resupplied to the engine at `StartedRound` — and must survive a
/// restart, because the store is the application-owned half of proposal
/// replay (the WAL restores votes, not value content). A record whose
/// batch bytes are missing must be skipped, not resurrected.
#[test]
fn undecided_values_resupply_from_durable_store() {
    let (keys, set) = validators(1);
    let base = fixture("resupply");
    let key = keys[0].clone();
    let address = Address::from_public_key(&key.public_key());

    let store = base.join("store");
    std::fs::create_dir_all(store.join("batches")).unwrap();
    std::fs::create_dir_all(store.join("seen")).unwrap();
    let make_app =
        |held: BTreeMap<RoomValueId, Batch>, seen: BTreeMap<u64, Vec<SeenProposal>>| App {
            ctx: RoomContext,
            adapter: Arc::new(Mutex::new(
                Adapter::open(base.join("app"), &genesis()).unwrap(),
            )),
            sink: Arc::new(Mutex::new(EngineSink::default())),
            validator_sets: sched(set.clone()),
            address,
            private_key: key.clone(),
            proposals: BTreeMap::new(),
            pending_proposals: VecDeque::new(),
            assigned_bodies: BTreeMap::new(),
            held_by_id: held,
            streams: BTreeMap::new(),
            parts_cache: BTreeMap::new(),
            decided: BTreeMap::new(),
            stream_seq: 0,
            boundary_latency: Arc::new(Mutex::new(Vec::new())),
            store: store.clone(),
            seen,
            resupplied: Arc::new(Mutex::new(0)),
            held_replies: Vec::new(),
        };

    let mut s = fixture::scenario(8, 16);
    let mut cursor = 0usize;
    let (ev, rec, _) = fixture::first_create(
        &s.app,
        &s.owners[0],
        &mut s.sources,
        &mut cursor,
        "held-room",
        1,
    );
    let batch = s.app.prepare(1, ev, rec, None).unwrap().batch().clone();

    let mut app = make_app(BTreeMap::new(), BTreeMap::new());
    let id = app.register_batch(batch.clone());
    app.record_seen(
        &ProposalInit {
            height: Height::new(5),
            round: Round::new(2),
            pol_round: Round::new(1),
            proposer: address,
        },
        id,
    );
    // A record at the same height whose batch never arrived: resupply
    // must skip it rather than fabricate a value.
    app.seen.entry(5).or_default().push(SeenProposal {
        round: Round::new(3),
        pol_round: Round::Nil,
        proposer: address,
        value_id: RoomValueId([0xEE; 32]),
    });

    let resupplied = app.resupply_for(Height::new(5));
    assert_eq!(resupplied.len(), 1, "only the retained value resupplies");
    let value = &resupplied[0];
    assert_eq!(value.round, Round::new(2));
    assert_eq!(value.valid_round, Round::new(1));
    assert_eq!(value.proposer, address);
    assert_eq!(value.value.id.0, batch.value_id());
    assert!(value.validity.is_valid());
    assert!(app.resupply_for(Height::new(6)).is_empty());

    // Restart: rebuild from the durable store alone — no spec `held`.
    drop(app);
    let (held, seen) = load_store(&store);
    assert_eq!(held.len(), 1, "the observed batch body was retained");
    assert_eq!(seen.get(&5).map(Vec::len), Some(1));
    let mut restarted = make_app(held, seen);
    let resupplied = restarted.resupply_for(Height::new(5));
    assert_eq!(resupplied.len(), 1);
    assert_eq!(resupplied[0].value.id.0, batch.value_id());
    assert_eq!(resupplied[0].round, Round::new(2));

    let _ = std::fs::remove_dir_all(&base);
}

/// A batch submitted at runtime — not pre-planned in `NodeSpec::held` —
/// must be proposed at the first height its queue reaches and committed
/// by every journal. Submitting to all validators lets whichever node
/// holds the proposer slot carry it; all four commit the same value id.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn runtime_submission_commits_after_start() {
    let plan = fixture::plan(2, 8, 16);
    let (keys, set) = validators(4);
    let base = fixture("submit");
    let base_port = 28500usize;

    let mut nodes = Vec::new();
    for (i, key) in keys.iter().enumerate().take(4) {
        nodes.push(
            RoomNode::start(NodeSpec {
                home: base.join(format!("n{i}")),
                config: node_config(i + 1, 4, base_port),
                node_key: key.clone(),
                validator_sets: sched(set.clone()),
                held: BTreeMap::new(),
                genesis: plan.genesis.clone(),
                wal_faults: None,
                net_gate: None,
            })
            .await,
        );
    }
    // First submission lands before the first height; the second arrives
    // while height 1 is in flight — FIFO order keeps them distinct.
    for node in &nodes {
        node.submit(plan.batches[&1].clone()).await;
    }
    wait_for(
        "all four nodes to journal-commit height 1",
        || nodes.iter().all(|n| n.committed_height() >= 1),
        Duration::from_secs(60),
    )
    .await;
    for node in &nodes {
        node.submit(plan.batches[&2].clone()).await;
    }
    wait_for(
        "all four nodes to journal-commit height 2",
        || nodes.iter().all(|n| n.committed_height() >= 2),
        Duration::from_secs(60),
    )
    .await;
    for node in &nodes {
        // The durable evidence is the journal frontier (asserted by the
        // waits) plus the pending queue's retirement: a committed
        // submission's marker must be gone from `store/pending/`.
        let pending: Vec<String> = std::fs::read_dir(node.home.join("store").join("pending"))
            .map(|d| {
                d.flatten()
                    .filter_map(|e| e.file_name().into_string().ok())
                    .collect()
            })
            .unwrap_or_default();
        assert!(
            pending.is_empty(),
            "committed submissions must retire their markers; left {pending:?}"
        );
    }
    for node in nodes {
        node.crash().await;
    }
    let _ = std::fs::remove_dir_all(&base);
}

/// `store/pending/` markers reload only while their batch is retained
/// and still validates against the current frontier: a marker with no
/// batch bytes, an undecodable name, and a marker for an already
/// committed batch are all dropped rather than re-queued.
#[test]
fn pending_markers_reload_only_uncommitted_submissions() {
    let base = fixture("pending");
    let store = base.join("store");
    std::fs::create_dir_all(store.join("batches")).unwrap();
    std::fs::create_dir_all(store.join("seen")).unwrap();
    std::fs::create_dir_all(store.join("pending")).unwrap();
    let adapter = Arc::new(Mutex::new(
        Adapter::open(base.join("app"), &genesis()).unwrap(),
    ));

    let mut s = fixture::scenario(8, 16);
    let mut cursor = 0usize;
    let (ev, rec, _) =
        fixture::first_create(&s.app, &s.owners[0], &mut s.sources, &mut cursor, "live", 1);
    let live = s.app.prepare(1, ev, rec, None).unwrap().batch().clone();
    let (ev2, rec2, _) =
        fixture::first_create(&s.app, &s.owners[1], &mut s.sources, &mut cursor, "gone", 2);
    let gone = s.app.prepare(1, ev2, rec2, None).unwrap().batch().clone();

    // Retained + validating: re-queued.
    store_write(
        &store.join("batches"),
        &hex(&live.value_id()),
        &live.encode(),
    )
    .unwrap();
    store_write(&store.join("pending"), &hex(&live.value_id()), &[]).unwrap();
    // Marker without batch bytes: dropped.
    store_write(&store.join("pending"), &hex(&gone.value_id()), &[]).unwrap();
    // Undecodable marker name: dropped.
    store_write(&store.join("pending"), "not-hex", &[]).unwrap();

    let mut held = BTreeMap::new();
    held.insert(RoomValueId(live.value_id()), live.clone());
    let pending = reload_pending(&store, &held, &adapter);
    assert_eq!(
        pending,
        VecDeque::from([PendingEntry::Value(RoomValueId(live.value_id()))])
    );
    assert!(store.join("pending").join(hex(&live.value_id())).exists());
    assert!(!store.join("pending").join(hex(&gone.value_id())).exists());
    assert!(!store.join("pending").join("not-hex").exists());

    // Commit the batch, then reload: its marker must drop.
    adapter.lock().unwrap().hold(live.clone());
    let outcome = adapter.lock().unwrap().decide(&RoomCertificate {
        bytes: b"cert".to_vec(),
        value_commitment: live.value_id(),
        height: 1,
    });
    assert!(matches!(outcome, DecidedOutcome::Acked));
    let pending = reload_pending(&store, &held, &adapter);
    assert!(pending.is_empty(), "a committed batch must not re-queue");
    assert!(!store.join("pending").join(hex(&live.value_id())).exists());

    let _ = std::fs::remove_dir_all(&base);
}

/// The intake contract at the application boundary: a `*.batch` file is
/// decoded, submitted (durable pending marker + FIFO queue) and unlinked;
/// undecodable content is renamed `.rejected` and never retried, and
/// non-`.batch` names are left alone.
#[test]
fn intake_files_submit_or_reject_deterministically() {
    let (keys, set) = validators(1);
    let base = fixture("intake");
    let key = keys[0].clone();
    let address = Address::from_public_key(&key.public_key());
    let home = base.join("home");
    let store = home.join("store");
    std::fs::create_dir_all(store.join("batches")).unwrap();
    std::fs::create_dir_all(store.join("seen")).unwrap();
    std::fs::create_dir_all(store.join("pending")).unwrap();
    let intake = home.join("intake");
    std::fs::create_dir_all(&intake).unwrap();

    let mut app = App {
        ctx: RoomContext,
        adapter: Arc::new(Mutex::new(
            Adapter::open(home.join("app"), &genesis()).unwrap(),
        )),
        sink: Arc::new(Mutex::new(EngineSink::default())),
        validator_sets: sched(set),
        address,
        private_key: key.clone(),
        proposals: BTreeMap::new(),
        pending_proposals: VecDeque::new(),
        assigned_bodies: BTreeMap::new(),
        held_by_id: BTreeMap::new(),
        streams: BTreeMap::new(),
        parts_cache: BTreeMap::new(),
        decided: BTreeMap::new(),
        stream_seq: 0,
        boundary_latency: Arc::new(Mutex::new(Vec::new())),
        store,
        seen: BTreeMap::new(),
        resupplied: Arc::new(Mutex::new(0)),
        held_replies: Vec::new(),
    };

    let mut s = fixture::scenario(8, 16);
    let mut cursor = 0usize;
    let (ev, rec, _) = fixture::first_create(
        &s.app,
        &s.owners[0],
        &mut s.sources,
        &mut cursor,
        "intake",
        1,
    );
    let batch = s.app.prepare(1, ev, rec, None).unwrap().batch().clone();

    std::fs::write(intake.join("good.batch"), batch.encode()).unwrap();
    std::fs::write(intake.join("bad.batch"), b"not a batch").unwrap();
    std::fs::write(intake.join("note.txt"), b"unrelated").unwrap();

    app.drain_intake();

    assert_eq!(
        app.pending_proposals,
        VecDeque::from([PendingEntry::Body("good".to_owned())]),
        "a valid .batch file enters the pending queue as a body"
    );
    assert!(!intake.join("good.batch").exists());
    assert!(!intake.join("bad.batch").exists());
    assert!(
        intake.join("bad.rejected").exists(),
        "undecodable input is renamed, not retried"
    );
    assert!(
        intake.join("note.txt").exists(),
        "non-.batch names are left alone"
    );
    assert!(
        app.store.join("pending").join("good").exists(),
        "the submission carries a durable pending marker"
    );
    // The body is assembled at assignment: the pending value commits.
    assert_eq!(
        app.next_pending().map(|id| id.0),
        Some(batch.value_id()),
        "the drained body assembles into the identical canonical batch"
    );

    let _ = std::fs::remove_dir_all(&base);
}

/// A queued entry that loses its height can never commit — its parent is
/// frozen at assembly. The queue must not livelock on it: a body-sourced
/// value downgrades back to its body and re-assembles against the live
/// frontier, and a body whose effect no longer applies is rejected to
/// the producer rather than occupying the front forever.
#[test]
fn losing_body_reassembles_against_live_frontier() {
    let (keys, set) = validators(1);
    let base = fixture("losing");
    let key = keys[0].clone();
    let address = Address::from_public_key(&key.public_key());
    let home = base.join("home");
    let store = home.join("store");
    std::fs::create_dir_all(store.join("batches")).unwrap();
    std::fs::create_dir_all(store.join("seen")).unwrap();
    std::fs::create_dir_all(store.join("pending")).unwrap();
    let intake = home.join("intake");
    std::fs::create_dir_all(&intake).unwrap();

    let mut app = App {
        ctx: RoomContext,
        adapter: Arc::new(Mutex::new(
            Adapter::open(home.join("app"), &genesis()).unwrap(),
        )),
        sink: Arc::new(Mutex::new(EngineSink::default())),
        validator_sets: sched(set),
        address,
        private_key: key.clone(),
        proposals: BTreeMap::new(),
        pending_proposals: VecDeque::new(),
        assigned_bodies: BTreeMap::new(),
        held_by_id: BTreeMap::new(),
        streams: BTreeMap::new(),
        parts_cache: BTreeMap::new(),
        decided: BTreeMap::new(),
        stream_seq: 0,
        boundary_latency: Arc::new(Mutex::new(Vec::new())),
        store,
        seen: BTreeMap::new(),
        resupplied: Arc::new(Mutex::new(0)),
        held_replies: Vec::new(),
    };

    let mut s = fixture::scenario(8, 16);
    let mut cursor = 0usize;
    // Three pending creates: alpha (owner0), beta (owner1), and a second
    // `alpha` from owner2 that must lose once the first commits.
    let (ev1, rec1, _) = fixture::first_create(
        &s.app,
        &s.owners[0],
        &mut s.sources,
        &mut cursor,
        "alpha",
        1,
    );
    let (ev2, rec2, _) =
        fixture::first_create(&s.app, &s.owners[1], &mut s.sources, &mut cursor, "beta", 2);
    let (ev3, rec3, _) = fixture::first_create(
        &s.app,
        &s.owners[2],
        &mut s.sources,
        &mut cursor,
        "alpha",
        3,
    );
    let bodies = [
        ("first", ev1, rec1),
        ("second", ev2, rec2),
        ("third", ev3, rec3),
    ];
    for (name, evidence, records) in bodies {
        let body = BatchBody {
            time: 1,
            evidence,
            records,
            games: Vec::new(),
            eligible: None,
        };
        std::fs::write(intake.join(format!("{name}.body")), body.encode()).unwrap();
    }
    app.drain_intake();
    assert_eq!(
        app.pending_proposals.len(),
        3,
        "all bodies queue as unassembled entries"
    );

    // Height 1: the first body assembles against the genesis frontier.
    let genesis_frontier = app.adapter.lock().unwrap().frontier();
    let id1 = app.next_pending().expect("a body assembles at assignment");
    let batch1 = app.held_by_id.get(&id1).unwrap().clone();
    assert_eq!(
        batch1.parent, genesis_frontier,
        "first assembly binds the genesis frontier"
    );

    // The batch commits at height 1: the queued value is now stale —
    // its parent no longer matches — and `third`'s slug is taken.
    app.adapter.lock().unwrap().hold(batch1.clone());
    let outcome = app.adapter.lock().unwrap().decide(&RoomCertificate {
        bytes: b"cert".to_vec(),
        value_commitment: batch1.value_id(),
        height: 1,
    });
    assert!(matches!(outcome, DecidedOutcome::Acked));

    // The second body must assemble against the LIVE frontier — parent
    // binds the post-height-1 state, not genesis — while the stale
    // value for `first` downgrades back to its body behind it.
    let id2 = app.next_pending().expect("second body re-assembles fresh");
    let batch2 = app.held_by_id.get(&id2).unwrap().clone();
    assert_eq!(
        batch2.parent,
        app.adapter.lock().unwrap().frontier(),
        "re-assembly binds the live frontier, never the stale one"
    );
    assert_ne!(id2.0, id1.0, "re-assembly produces a fresh value id");
    app.adapter.lock().unwrap().hold(batch2.clone());
    let outcome = app.adapter.lock().unwrap().decide(&RoomCertificate {
        bytes: b"cert".to_vec(),
        value_commitment: batch2.value_id(),
        height: 2,
    });
    assert!(matches!(outcome, DecidedOutcome::Acked));

    // Every remaining queued entry can never apply: `third`'s slug is
    // taken and the requeued bodies' effects are already committed.
    // Each fails assembly, writes a producer-visible `.rejected`, and
    // drains — the queue can never livelock on an uncommittable front.
    assert!(
        app.next_pending().is_none(),
        "unappliable bodies reject instead of stalling the queue"
    );
    assert!(
        app.pending_proposals.is_empty(),
        "the queue drains completely — no livelock"
    );
    for name in ["first", "second", "third"] {
        assert!(
            intake.join(format!("{name}.rejected")).exists(),
            "{name}'s producer sees a rejection marker"
        );
        assert!(!app.store.join("pending").join(name).exists());
    }

    let _ = std::fs::remove_dir_all(&base);
}

/// An operator-dropped `*.eligible` file enters the pending queue as a
/// config-only body and assembles into a batch carrying the transition.
#[test]
fn eligible_intake_file_queues_a_config_transition() {
    let (keys, set) = validators(1);
    let base = fixture("eligible-intake");
    let key = keys[0].clone();
    let address = Address::from_public_key(&key.public_key());
    let home = base.join("home");
    let store = home.join("store");
    std::fs::create_dir_all(store.join("batches")).unwrap();
    std::fs::create_dir_all(store.join("seen")).unwrap();
    std::fs::create_dir_all(store.join("pending")).unwrap();
    let intake = home.join("intake");
    std::fs::create_dir_all(&intake).unwrap();

    let mut app = App {
        ctx: RoomContext,
        adapter: Arc::new(Mutex::new(
            Adapter::open(home.join("app"), &genesis()).unwrap(),
        )),
        sink: Arc::new(Mutex::new(EngineSink::default())),
        validator_sets: sched(set),
        address,
        private_key: key.clone(),
        proposals: BTreeMap::new(),
        pending_proposals: VecDeque::new(),
        assigned_bodies: BTreeMap::new(),
        held_by_id: BTreeMap::new(),
        streams: BTreeMap::new(),
        parts_cache: BTreeMap::new(),
        decided: BTreeMap::new(),
        stream_seq: 0,
        boundary_latency: Arc::new(Mutex::new(Vec::new())),
        store,
        seen: BTreeMap::new(),
        resupplied: Arc::new(Mutex::new(0)),
        held_replies: Vec::new(),
    };

    let admitted = vec![OwnerId::from_bytes([7; 32]), OwnerId::from_bytes([9; 32])];
    std::fs::write(
        intake.join("growth.eligible"),
        encode_eligible_update(&admitted),
    )
    .unwrap();
    std::fs::write(intake.join("bad.eligible"), b"not a set").unwrap();

    app.drain_intake();

    assert_eq!(
        app.pending_proposals,
        VecDeque::from([PendingEntry::Body("growth".to_owned())]),
        "a valid .eligible file queues as a body under its stem"
    );
    assert!(!intake.join("growth.eligible").exists());
    assert!(
        intake.join("bad.rejected").exists(),
        "undecodable input is renamed, not retried"
    );

    let id = app.next_pending().unwrap();
    let batch = app.held_by_id.get(&id).unwrap();
    assert_eq!(batch.eligible, Some(admitted));
    assert!(batch.evidence.is_empty() && batch.records.is_empty());
}

/// A hosted `service_config` binds the configured listen host: loopback
/// keeps the single-host per-IP ceiling lift the test meshes rely on,
/// while any other address falls back to malachite's default per-IP
/// bound. Peers keep their explicit `host:port` targets either way.
#[test]
fn service_config_binds_listen_and_bounds_per_ip() {
    let local = service_config(
        "svc",
        "127.0.0.1",
        5000,
        &[PeerSpec {
            host: "100.64.1.2".to_owned(),
            port: 5001,
            key: None,
        }],
        false,
    );
    assert_eq!(
        local.consensus.p2p.discovery.max_connections_per_ip,
        usize::MAX
    );
    assert_eq!(
        local.consensus.p2p.listen_addr.to_string(),
        "/ip4/127.0.0.1/tcp/5000"
    );
    assert_eq!(
        local.consensus.p2p.persistent_peers[0].to_string(),
        "/ip4/100.64.1.2/tcp/5001"
    );
    assert!(!local.consensus.p2p.persistent_peers_only);

    for listen in ["192.0.2.10", "0.0.0.0", "100.64.1.7"] {
        let config = service_config("svc", listen, 5000, &[], false);
        assert_eq!(
            config.consensus.p2p.discovery.max_connections_per_ip,
            DiscoveryConfig::default().max_connections_per_ip,
            "non-loopback listen {listen} must keep the default per-IP bound"
        );
        assert!(config
            .consensus
            .p2p
            .listen_addr
            .to_string()
            .contains(listen));
    }
}

/// A pinned peer names the peer node's consensus key: the persistent
/// multiaddr carries the `/p2p/` component of the peer id the remote's
/// network keypair deterministically derives from that same key — the
/// derivation is one source of truth (`net_peer_id`), so the pin
/// authenticates exactly the identity the peer will present.
#[test]
fn service_config_pins_peer_identity_and_closes_the_mesh() {
    let key = PrivateKey::from([7; 32]).public_key();
    let config = service_config(
        "svc",
        "127.0.0.1",
        5000,
        &[PeerSpec {
            host: "100.64.1.2".to_owned(),
            port: 5001,
            key: Some(key),
        }],
        true,
    );
    let expected = format!("/ip4/100.64.1.2/tcp/5001/p2p/{}", net_peer_id(&key));
    assert_eq!(
        config.consensus.p2p.persistent_peers[0].to_string(),
        expected
    );
    assert!(config.consensus.p2p.persistent_peers_only);
}

/// An `App` wired to a fresh store dir for unit-level state tests.
fn test_app(tag: &str, key: &PrivateKey, set: &RoomValidatorSet) -> App {
    let base = fixture(tag);
    let home = base.join("home");
    let store = home.join("store");
    std::fs::create_dir_all(store.join("batches")).unwrap();
    std::fs::create_dir_all(store.join("seen")).unwrap();
    std::fs::create_dir_all(store.join("pending")).unwrap();
    App {
        ctx: RoomContext,
        adapter: Arc::new(Mutex::new(
            Adapter::open(home.join("app"), &genesis()).unwrap(),
        )),
        sink: Arc::new(Mutex::new(EngineSink::default())),
        validator_sets: sched(set.clone()),
        address: Address::from_public_key(&key.public_key()),
        private_key: key.clone(),
        proposals: BTreeMap::new(),
        pending_proposals: VecDeque::new(),
        assigned_bodies: BTreeMap::new(),
        held_by_id: BTreeMap::new(),
        streams: BTreeMap::new(),
        parts_cache: BTreeMap::new(),
        decided: BTreeMap::new(),
        stream_seq: 0,
        boundary_latency: Arc::new(Mutex::new(Vec::new())),
        store,
        seen: BTreeMap::new(),
        resupplied: Arc::new(Mutex::new(0)),
        held_replies: Vec::new(),
    }
}

#[test]
fn game_commitment_body_survives_intake_and_live_frontier_assembly() {
    let (keys, set) = validators(1);
    let mut app = test_app("game-intake", &keys[0], &set);
    let intake = app.store.parent().unwrap().join("intake");
    std::fs::create_dir_all(&intake).unwrap();
    let commitment = GameCommitment {
        realm: vhalla_rooms_consensus::RealmId(11),
        room: vhalla_rooms_consensus::RoomId(12),
        session: [13; 32],
        epoch: 14,
        kind: GameCommitmentKind::Event,
        object: [15; 32],
    };
    let body = BatchBody {
        time: 1,
        evidence: Vec::new(),
        records: Vec::new(),
        games: vec![commitment],
        eligible: None,
    };
    std::fs::write(intake.join("game.body"), body.encode()).unwrap();

    app.drain_intake();
    assert_eq!(
        app.pending_proposals,
        VecDeque::from([PendingEntry::Body("game".to_owned())])
    );
    let id = app.next_pending().unwrap();
    let batch = app.held_by_id.get(&id).unwrap();
    assert_eq!(batch.games, vec![commitment]);
    assert_eq!(&batch.encode()[..4], b"VRB3");
    assert_eq!(id.0, batch.value_id());
}

/// Deciding a height retires per-height state that can never be
/// consulted again: seen records and open streams at or below it,
/// parts-cache entries below it, and retained batches nothing
/// references. Anything still live — a queued value, a live-height
/// assignment, a seen record above the decision — survives.
#[test]
fn sweep_decided_retires_dead_state() {
    let (keys, set) = validators(1);
    let mut app = test_app("sweep", &keys[0], &set);
    let proposer = app.address;

    let plan = batch_plan(4);
    let ids: Vec<RoomValueId> = (1..=4).map(|h| RoomValueId(plan[&h].value_id())).collect();
    for (i, id) in ids.iter().enumerate() {
        app.held_by_id.insert(*id, plan[&(i as u64 + 1)].clone());
    }
    // id1: committed at h1 — nothing references it after the sweep.
    // id2: queued pending. id3: seen at h3. id4: assigned to h5.
    app.pending_proposals.push_back(PendingEntry::Value(ids[1]));
    app.proposals.insert(5, ids[3]);
    for (h, id) in [(1u64, ids[0]), (2, ids[1]), (3, ids[2])] {
        app.seen.entry(h).or_default().push(SeenProposal {
            round: Round::new(0),
            pol_round: Round::Nil,
            proposer,
            value_id: id,
        });
    }
    app.streams.insert(
        (b"peer".to_vec(), b"old".to_vec()),
        StreamState {
            init: Some(ProposalInit {
                height: Height::new(1),
                round: Round::new(0),
                pol_round: Round::Nil,
                proposer,
            }),
            ..Default::default()
        },
    );
    app.streams.insert(
        (b"peer".to_vec(), b"headless".to_vec()),
        StreamState::default(),
    );
    app.parts_cache.insert(
        ids[0],
        vec![RoomPart::Init(ProposalInit {
            height: Height::new(1),
            round: Round::new(0),
            pol_round: Round::Nil,
            proposer,
        })],
    );
    app.parts_cache.insert(
        ids[2],
        vec![RoomPart::Init(ProposalInit {
            height: Height::new(3),
            round: Round::new(0),
            pol_round: Round::Nil,
            proposer,
        })],
    );

    app.sweep_decided(2);

    assert!(
        !app.seen.contains_key(&1) && !app.seen.contains_key(&2),
        "decided heights never resupply"
    );
    assert_eq!(app.seen[&3][0].value_id, ids[2]);
    assert_eq!(
        app.streams.len(),
        1,
        "the init-less stream stays until aged"
    );
    assert!(app
        .streams
        .contains_key(&(b"peer".to_vec(), b"headless".to_vec())));
    assert!(
        !app.parts_cache.contains_key(&ids[0]),
        "parts below the decided height are dead"
    );
    assert!(app.parts_cache.contains_key(&ids[2]));
    assert!(
        !app.held_by_id.contains_key(&ids[0]),
        "the committed batch's copy is dead — `decided` and the journal keep it"
    );
    assert!(app.held_by_id.contains_key(&ids[1]), "pending stays");
    assert!(
        app.held_by_id.contains_key(&ids[2]),
        "seen-at-live-height stays"
    );
    assert!(app.held_by_id.contains_key(&ids[3]), "assigned stays");
}

/// A stream whose transport `Fin` never arrives — the common signature
/// of a dead tunnel connection — must not linger forever.
#[test]
fn expire_streams_drops_abandoned_streams() {
    let (keys, set) = validators(1);
    let mut app = test_app("expire", &keys[0], &set);
    app.streams.insert(
        (b"a".to_vec(), b"old".to_vec()),
        StreamState {
            first_seen: Some(Instant::now() - STREAM_STALE - Duration::from_secs(1)),
            ..Default::default()
        },
    );
    app.streams.insert(
        (b"a".to_vec(), b"new".to_vec()),
        StreamState {
            first_seen: Some(Instant::now()),
            ..Default::default()
        },
    );
    app.expire_streams();
    assert_eq!(app.streams.len(), 1);
    assert!(app.streams.contains_key(&(b"a".to_vec(), b"new".to_vec())));
}

/// Tombstone ids bind (node, height, round): two nodes resolving the
/// same request slot MUST produce different ids — a shared id is what
/// let a peer's slim proposal pair with a local tombstone and commit an
/// empty value.
#[test]
fn tombstone_ids_are_unique_per_node_height_round() {
    let (keys, set) = validators(2);
    let a = test_app("tomb-a", &keys[0], &set);
    let b = test_app("tomb-b", &keys[1], &set);
    let ta = a.tombstone(7, Round::new(3));
    assert_ne!(
        ta.id.0,
        b.tombstone(7, Round::new(3)).id.0,
        "same slot across nodes must differ"
    );
    assert_ne!(ta.id.0, a.tombstone(8, Round::new(3)).id.0);
    assert_ne!(ta.id.0, a.tombstone(7, Round::new(4)).id.0);
    assert_eq!(ta.id.0, a.tombstone(7, Round::new(3)).id.0, "deterministic");
    assert!(ta.bytes.is_empty());
}

/// A restarted node serves decided values out of the journal, not
/// memory: commit a batch through the durable path, then `load_decided`
/// must rebuild the `RawDecidedValue` — value bytes plus an extended
/// certificate decoded from the stored `VC2` — so `GetDecidedValues`
/// still answers for heights the process never saw in memory.
#[test]
fn decided_history_rebuilds_from_the_journal() {
    let (keys, _set) = validators(1);
    let base = fixture("load-decided");
    let mut adapter = Adapter::open(base.join("app"), &genesis()).unwrap();

    let plan = batch_plan(1);
    let batch = plan[&1].clone();
    adapter.hold(batch.clone());

    // Fabricate the canonical VC2 bytes the bundle stores: the journal
    // records them verbatim — quorum verification happens upstream.
    let address = Address::from_public_key(&keys[0].public_key());
    let mut cert = Vec::new();
    cert.extend_from_slice(b"VC2");
    cert.extend_from_slice(&1u64.to_be_bytes());
    cert.extend_from_slice(&0u32.to_be_bytes());
    cert.extend_from_slice(&batch.value_id());
    cert.extend_from_slice(&1u16.to_be_bytes());
    cert.extend_from_slice(&address.into_inner());
    cert.extend_from_slice(&[9u8; 64]);

    let outcome = adapter.decide(&RoomCertificate {
        bytes: cert,
        value_commitment: batch.value_id(),
        height: 1,
    });
    assert_eq!(outcome, DecidedOutcome::Acked);
    assert_eq!(adapter.frontier().height, 1);

    let decided = load_decided(&adapter);
    let raw = decided.get(&1).expect("a committed height serves sync");
    let value = RoomCodec::decode_value(raw.value_bytes.clone()).unwrap();
    assert_eq!(&value.bytes[..], &batch.encode()[..]);
    assert_eq!(raw.certificate.height, Height::new(1));
    assert_eq!(raw.certificate.value_id.0, batch.value_id());
    assert_eq!(raw.certificate.commit_signatures.len(), 1);
    assert_eq!(raw.certificate.commit_signatures[0].address, address);

    let _ = std::fs::remove_dir_all(&base);
}

/// A WAL written before format epochs — or by a different wire format —
/// must fail fast with an actionable message instead of a cryptic
/// mid-replay codec error that safety-hangs the engine.
#[test]
fn wal_format_marker_guards_incompatible_replay() {
    let base = fixture("wal-format");
    let wal = base.join("wal").join("consensus.wal");

    // Fresh dir: marker is written, no panic.
    check_wal_format(&wal);
    assert_eq!(
        std::fs::read(base.join("wal").join("FORMAT")).unwrap(),
        b"VRW2"
    );
    // Idempotent on restart.
    check_wal_format(&wal);
    // An empty legacy WAL is safe to adopt.
    std::fs::remove_file(base.join("wal").join("FORMAT")).unwrap();
    std::fs::write(&wal, []).unwrap();
    check_wal_format(&wal);
    assert_eq!(
        std::fs::read(base.join("wal").join("FORMAT")).unwrap(),
        b"VRW2"
    );

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
#[should_panic(expected = "predates format versioning")]
fn wal_format_rejects_unversioned_nonempty_log() {
    let base = fixture("wal-legacy");
    let wal = base.join("wal").join("consensus.wal");
    std::fs::create_dir_all(wal.parent().unwrap()).unwrap();
    std::fs::write(&wal, b"legacy entry bytes").unwrap();
    check_wal_format(&wal);
}

#[test]
#[should_panic(expected = "WAL format mismatch")]
fn wal_format_rejects_foreign_marker() {
    let base = fixture("wal-foreign");
    let wal = base.join("wal").join("consensus.wal");
    std::fs::create_dir_all(wal.parent().unwrap()).unwrap();
    std::fs::write(wal.parent().unwrap().join("FORMAT"), b"VRW1").unwrap();
    check_wal_format(&wal);
}

/// Generative companion to `tombstone_ids_are_unique_per_node_height_round`:
/// over any drawn set of (node, height, round) slots the ids stay pairwise
/// distinct, an identical slot reproduces its id, and the value is always
/// empty — a shared or nonempty tombstone is what let an empty value commit.
/// Drawn rounds stay below u32::MAX, which `tombstone` reserves for Nil.
/// Each case builds three real Apps (store I/O), so generation time
/// scales with machine load — TooSlow suppression keeps coverage fixed.
#[hegel::test(test_cases = 64, suppress_health_check = [HealthCheck::TooSlow])]
fn tombstone_ids_stay_injected_across_drawn_slots(tc: TestCase) {
    let (keys, set) = validators(3);
    let apps: Vec<App> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| test_app(&format!("tomb-gen-{i}"), k, &set))
        .collect();
    let mut ids: BTreeMap<(usize, u64, u32), [u8; 32]> = BTreeMap::new();
    let slots = tc.draw(gs::integers::<usize>().min_value(1).max_value(16));
    for _ in 0..slots {
        let node = tc.draw(gs::integers::<usize>().max_value(2));
        let height = tc.draw(gs::integers::<u64>().min_value(1).max_value(64));
        let round = if tc.draw(gs::booleans()) {
            Round::Nil
        } else {
            Round::new(tc.draw(gs::integers::<u32>().max_value(1024)))
        };
        let value = apps[node].tombstone(height, round);
        assert!(value.bytes.is_empty(), "tombstones never carry bytes");
        let slot = (node, height, round.as_u32().unwrap_or(u32::MAX));
        if let Some(previous) = ids.insert(slot, value.id.0) {
            assert_eq!(previous, value.id.0, "the same slot must replay its id");
        }
    }
    let distinct: HashSet<[u8; 32]> = ids.values().copied().collect();
    assert_eq!(
        ids.len(),
        distinct.len(),
        "distinct slots must never share a tombstone id"
    );
}

/// Generative companion to `expire_streams_drops_abandoned_streams`: over any
/// drawn stream set the survivors are exactly the entries with no expiry
/// clock or an age below `STREAM_STALE`.
#[hegel::test(test_cases = 64)]
fn expire_streams_retires_exactly_the_stale(tc: TestCase) {
    let (keys, set) = validators(1);
    let mut app = test_app("expire-gen", &keys[0], &set);
    let mut expected: BTreeMap<(Vec<u8>, Vec<u8>), bool> = BTreeMap::new();
    let count = tc.draw(gs::integers::<usize>().max_value(16));
    for i in 0..count {
        let key = (b"peer".to_vec(), format!("s{i}").into_bytes());
        let first_seen = if tc.draw(gs::booleans()) {
            let age = Duration::from_secs(tc.draw(gs::integers::<u64>().max_value(120)));
            Some(Instant::now().checked_sub(age).unwrap_or_else(Instant::now))
        } else {
            None
        };
        app.streams.insert(
            key.clone(),
            StreamState {
                first_seen,
                ..Default::default()
            },
        );
        expected.insert(key, first_seen.is_none_or(|t| t.elapsed() < STREAM_STALE));
    }
    app.expire_streams();
    for (key, live) in &expected {
        assert_eq!(
            app.streams.contains_key(key),
            *live,
            "stream {key:?} retention"
        );
    }
}

/// Generative companion to `sweep_decided_retires_dead_state`: draw a live
/// height and an arbitrary interleaving of seen records, held batches,
/// pending entries, assignments, streams, and parts — after the sweep the
/// retained state is exactly what the live references justify and nothing
/// below the decided height lingers.
#[hegel::test(test_cases = 64)]
fn sweep_decided_retires_exactly_dead_state(tc: TestCase) {
    let (keys, set) = validators(1);
    let mut app = test_app("sweep-gen", &keys[0], &set);
    let proposer = app.address;
    let plan = batch_plan(8);
    let ids: Vec<RoomValueId> = (1..=8).map(|h| RoomValueId(plan[&h].value_id())).collect();
    let pick = |tc: &TestCase| ids[tc.draw(gs::integers::<usize>().max_value(7))];

    let height = tc.draw(gs::integers::<u64>().min_value(1).max_value(6));
    for _ in 0..tc.draw(gs::integers::<usize>().max_value(10)) {
        let h = tc.draw(gs::integers::<u64>().max_value(8));
        app.seen.entry(h).or_default().push(SeenProposal {
            round: Round::new(0),
            pol_round: Round::Nil,
            proposer,
            value_id: pick(&tc),
        });
    }
    let mut pre_held = HashSet::new();
    for (i, id) in ids.iter().enumerate() {
        if tc.draw(gs::booleans()) {
            app.held_by_id.insert(*id, plan[&(i as u64 + 1)].clone());
            pre_held.insert(*id);
        }
    }
    let mut pending = 0usize;
    for _ in 0..tc.draw(gs::integers::<usize>().max_value(4)) {
        let entry = if tc.draw(gs::booleans()) {
            PendingEntry::Value(pick(&tc))
        } else {
            PendingEntry::Body(format!("body-{}", tc.draw(gs::integers::<u32>())))
        };
        app.pending_proposals.push_back(entry);
        pending += 1;
    }
    let mut assigned = 0usize;
    for _ in 0..tc.draw(gs::integers::<usize>().max_value(4)) {
        let h = tc.draw(gs::integers::<u64>().max_value(8));
        if app.proposals.insert(h, pick(&tc)).is_none() {
            assigned += 1;
        }
    }
    for i in 0..tc.draw(gs::integers::<usize>().max_value(6)) {
        let init = if tc.draw(gs::booleans()) {
            Some(ProposalInit {
                height: Height::new(tc.draw(gs::integers::<u64>().max_value(8))),
                round: Round::new(0),
                pol_round: Round::Nil,
                proposer,
            })
        } else {
            None
        };
        app.streams.insert(
            (b"peer".to_vec(), format!("gs{i}").into_bytes()),
            StreamState {
                init,
                ..Default::default()
            },
        );
    }
    for _ in 0..tc.draw(gs::integers::<usize>().max_value(6)) {
        let id = pick(&tc);
        let parts = if tc.draw(gs::booleans()) {
            vec![RoomPart::Init(ProposalInit {
                height: Height::new(tc.draw(gs::integers::<u64>().max_value(8))),
                round: Round::new(0),
                pol_round: Round::Nil,
                proposer,
            })]
        } else {
            Vec::new()
        };
        app.parts_cache.insert(id, parts);
    }

    app.sweep_decided(height);

    assert!(
        app.seen.keys().all(|h| *h > height),
        "seen records at or below the decided height are dead"
    );
    assert!(
        app.streams
            .values()
            .all(|s| s.init.as_ref().is_none_or(|i| i.height.as_u64() > height)),
        "streams keep no init at or below the decided height"
    );
    assert!(
        app.parts_cache.values().all(|parts| {
            parts
                .iter()
                .find_map(|p| match p {
                    RoomPart::Init(init) => Some(init.height.as_u64()),
                    _ => None,
                })
                .is_some_and(|h| h >= height)
        }),
        "parts entries survive only with an init at or above the decision"
    );
    let live: HashSet<RoomValueId> = app
        .proposals
        .values()
        .copied()
        .chain(app.pending_proposals.iter().filter_map(|e| e.value_id()))
        .chain(app.seen.values().flat_map(|v| v.iter().map(|s| s.value_id)))
        .collect();
    for id in app.held_by_id.keys() {
        assert!(live.contains(id), "a held batch must have a live referent");
    }
    for id in &pre_held {
        assert_eq!(
            app.held_by_id.contains_key(id),
            live.contains(id),
            "held retention must match live references exactly"
        );
    }
    assert_eq!(app.pending_proposals.len(), pending);
    assert_eq!(app.proposals.len(), assigned);
}

/// Generative companion to `decided_history_rebuilds_from_the_journal`:
/// interleave drawn commits with drawn restarts, then require the reopened
/// `load_decided` to serve exactly the committed heights — value bytes and
/// certificates intact — whatever the crash schedule was. Each case runs real
/// journal reopen + store reconciliation, so the TooSlow check is suppressed.
#[hegel::test(test_cases = 32, suppress_health_check = [HealthCheck::TooSlow])]
fn decided_history_survives_interleaved_restarts(tc: TestCase) {
    let (keys, _set) = validators(1);
    let base = fixture("load-decided-gen");
    let plan = batch_plan(6);
    let address = Address::from_public_key(&keys[0].public_key());
    let mut adapter = Adapter::open(base.join("app"), &genesis()).unwrap();
    let mut committed: Vec<u64> = Vec::new();

    for _ in 0..tc.draw(gs::integers::<usize>().min_value(1).max_value(8)) {
        let restart = tc.draw(gs::booleans());
        if restart && adapter.frontier().height > 0 {
            drop(adapter);
            adapter = Adapter::open(base.join("app"), &genesis()).unwrap();
            continue;
        }
        let height = adapter.frontier().height + 1;
        if height > 6 {
            continue;
        }
        let batch = plan[&height].clone();
        adapter.hold(batch.clone());
        let mut cert = Vec::new();
        cert.extend_from_slice(b"VC2");
        cert.extend_from_slice(&height.to_be_bytes());
        cert.extend_from_slice(&0u32.to_be_bytes());
        cert.extend_from_slice(&batch.value_id());
        cert.extend_from_slice(&1u16.to_be_bytes());
        cert.extend_from_slice(&address.into_inner());
        cert.extend_from_slice(&[9u8; 64]);
        let outcome = adapter.decide(&RoomCertificate {
            bytes: cert,
            value_commitment: batch.value_id(),
            height,
        });
        assert_eq!(outcome, DecidedOutcome::Acked);
        committed.push(height);
    }

    drop(adapter);
    let adapter = Adapter::open(base.join("app"), &genesis()).unwrap();
    let decided = load_decided(&adapter);
    assert_eq!(
        decided.keys().copied().collect::<Vec<_>>(),
        committed,
        "reopened decided history must be exactly the committed heights"
    );
    for h in &committed {
        let raw = &decided[h];
        let value = RoomCodec::decode_value(raw.value_bytes.clone()).unwrap();
        assert_eq!(&value.bytes[..], &plan[h].encode()[..]);
        assert_eq!(raw.certificate.height, Height::new(*h));
        assert_eq!(raw.certificate.value_id.0, plan[h].value_id());
        assert_eq!(raw.certificate.commit_signatures.len(), 1);
        assert_eq!(raw.certificate.commit_signatures[0].address, address);
    }
    let _ = std::fs::remove_dir_all(&base);
}
