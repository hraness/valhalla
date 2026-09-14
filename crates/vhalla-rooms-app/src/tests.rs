//! End-to-end: a real in-process validator commits intake bodies while a
//! `Service` replica absorbs journal bundles, projects screens, and
//! resolves local submission markers — no engine access, no signing.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use vhalla_rooms_consensus::fixture;
use vhalla_rooms_node::{service_config, NodeSpec, PrivateKey, RoomNode};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn temp(tag: &str) -> PathBuf {
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "rooms-app-{tag}-{}-{}-{}",
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

async fn wait_for(what: &str, f: impl Fn() -> bool, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while !f() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// The shared config as a JSON document — the same shape the node's own
/// config file carries — parsed through `ServiceConfig::parse` so the
/// test exercises the real boundary.
fn config_json(s: &fixture::Scenario, key: &PrivateKey) -> Vec<u8> {
    serde_json::json!({
        "realm": format!("{:032x}", s.genesis.realm.0),
        "directory": hex(s.genesis.directory.as_bytes()),
        "policy": {
            "base_cost": s.genesis.policy.base_cost,
            "window_seconds": s.genesis.policy.window_seconds,
            "max_in_window": s.genesis.policy.max_in_window,
            "support_epoch_seconds": s.genesis.policy.support_epoch_seconds,
            "max_lifetime_rooms": s.genesis.policy.max_lifetime_rooms,
        },
        "eligible": s
            .genesis
            .eligible
            .iter()
            .map(|id| hex(id.as_bytes()))
            .collect::<Vec<_>>(),
        "limits": {
            "records": s.genesis.limits.records,
            "control_reserve": s.genesis.limits.control_reserve,
            "data_per_owner": s.genesis.limits.data_per_owner,
            "data_per_writer": s.genesis.limits.data_per_writer,
            "control_per_owner": s.genesis.limits.control_per_owner,
            "pending": s.genesis.limits.pending,
            "pending_per_signer": s.genesis.limits.pending_per_signer,
        },
        "validators": [{
            "from": 1,
            "key": hex(key.public_key().as_bytes()),
            "power": 1,
        }],
        // Node-only keys a service config may sit alongside.
        "node_key": "00".repeat(32),
        "port": 0,
        "peers": [],
    })
    .to_string()
    .into_bytes()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replica_syncs_commits_and_resolves_pending() {
    let base = temp("e2e");
    let mut s = fixture::scenario(4, 8);

    // The committed social archive both sides seed from.
    let social_dir = base.join("social-store");
    {
        let mut social =
            SocialStore::create(&social_dir, s.genesis.realm, s.genesis.limits).unwrap();
        social
            .commit(s.genesis.archive.clone(), social.pin())
            .unwrap();
    }

    // One validator, no pre-planned batches — submissions flow only
    // through the intake contract.
    let key = PrivateKey::from([7; 32]);
    let node_home = base.join("node");
    std::fs::create_dir_all(node_home.join("intake")).unwrap();
    let set = RoomValidatorSet::new(vec![RoomValidator::new(key.public_key(), 1)]);
    let node = RoomNode::start(NodeSpec {
        home: node_home.clone(),
        config: service_config("svc-test", 0, &[]),
        node_key: key.clone(),
        validator_sets: BTreeMap::from([(1, set)]),
        held: BTreeMap::new(),
        genesis: s.genesis.clone(),
        wal_faults: None,
        net_gate: None,
    })
    .await;

    let replica_home = base.join("replica");
    let config = ServiceConfig::parse(&config_json(&s, &key)).unwrap();
    let mut service = Service::open(&social_dir, &node_home, &replica_home, &config).unwrap();
    assert_eq!(service.height(), 0, "a fresh replica starts at genesis");

    // A funded create drops as a body — never an assembled batch.
    let mut cursor = 0usize;
    let (ev, rec, _) = fixture::first_create(
        &s.app,
        &s.owners[0],
        &mut s.sources,
        &mut cursor,
        "parlor",
        1,
    );
    let marker = service.submit_body(1, ev, rec).unwrap();
    let pending = service.pending().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].name, marker);
    assert_eq!(pending[0].slug.as_deref(), Some("parlor"));
    assert!(
        matches!(
            pending[0].state,
            PendingState::Queued | PendingState::Submitted
        ),
        "fresh drop is queued or in flight: {:?}",
        pending[0].state
    );

    // The node commits it; the replica absorbs the journal bundle.
    wait_for(
        "node to commit height 1",
        || node.committed_height() >= 1,
        Duration::from_secs(60),
    )
    .await;
    assert_eq!(service.sync().unwrap(), 1);
    let pending = service.pending().unwrap();
    assert_eq!(
        pending[0].state,
        PendingState::Committed,
        "committed record resolves against the replica registry"
    );

    // The directory projection shows the committed room.
    let directory = service
        .project(&Screen::Directory {
            query: String::new(),
        })
        .unwrap();
    assert_eq!(directory.height, 1);
    assert_eq!(directory.rooms.len(), 1);
    let room = &directory.rooms[0];
    assert_eq!(room.slug, "parlor");
    assert_eq!(room.owner, hex(s.owners[0].id.as_bytes()));
    assert_eq!(room.slot, 1);
    assert!(!room.archived);
    assert!(!directory.partial);

    // Literal search and the single-room and account screens.
    let found = service
        .project(&Screen::Directory {
            query: "parlor".into(),
        })
        .unwrap();
    assert_eq!(found.rooms.len(), 1);
    let missed = service
        .project(&Screen::Directory {
            query: "no-such-room".into(),
        })
        .unwrap();
    assert!(missed.rooms.is_empty());
    let detail = service
        .project(&Screen::Room {
            slug: "parlor".into(),
        })
        .unwrap();
    assert_eq!(detail.rooms[0].record, room.record);
    let account = service
        .project(&Screen::Account {
            owner: s.owners[0].id,
        })
        .unwrap();
    assert!(account.account.is_some());
    assert!(account.quote.is_some(), "a funded owner quotes a next slot");

    // A losing create for the same slug: the node rejects it at
    // assembly, and the registry explains the marker first — the slug
    // is held by a different record, so the resolution is Collision.
    let (ev2, rec2, _) = fixture::first_create(
        &s.app,
        &s.owners[1],
        &mut s.sources,
        &mut cursor,
        "parlor",
        2,
    );
    let loser = service.submit_body(1, ev2, rec2).unwrap();
    let rejected = node_home.join("intake").join(format!("{loser}.rejected"));
    wait_for(
        "the losing body's rejection marker",
        || rejected.exists(),
        Duration::from_secs(60),
    )
    .await;
    let pending = service.pending().unwrap();
    let loser_pending = pending.iter().find(|p| p.name == loser).unwrap();
    assert_eq!(loser_pending.state, PendingState::Collision);

    // A create that can never apply — a charge far off the real quote —
    // is rejected by the node outright: the marker resolves Rejected.
    let grant3 = fixture::grant_create_record(&s.owners[2], 3);
    let grant3_id = grant3.id();
    let bad_create =
        fixture::creation_record(&s.owners[2], grant3_id, grant3_id, "den", 1, 999_999, 3);
    let bad = service
        .submit_body(1, Vec::new(), vec![grant3.encode(), bad_create.encode()])
        .unwrap();
    let rejected = node_home.join("intake").join(format!("{bad}.rejected"));
    wait_for(
        "the unappliable body's rejection marker",
        || rejected.exists(),
        Duration::from_secs(60),
    )
    .await;
    let pending = service.pending().unwrap();
    let bad_pending = pending.iter().find(|p| p.name == bad).unwrap();
    assert_eq!(bad_pending.state, PendingState::Rejected);

    // A marker whose drop never landed, against a slug another record
    // claimed, resolves as a collision — not a false pending.
    let ghost = Marker {
        record: hex(&[9; 32]),
        kind: "create".into(),
        slug: Some("parlor".into()),
        genesis: None,
        base: None,
        intake: "ghost".into(),
    };
    std::fs::write(
        replica_home
            .join("pending")
            .join(format!("{}.json", ghost.record)),
        serde_json::to_vec(&ghost).unwrap(),
    )
    .unwrap();
    let pending = service.pending().unwrap();
    let ghost = pending.iter().find(|p| p.name == hex(&[9; 32])).unwrap();
    assert_eq!(ghost.state, PendingState::Collision);

    node.crash().await;
    let _ = std::fs::remove_dir_all(&base);
}
