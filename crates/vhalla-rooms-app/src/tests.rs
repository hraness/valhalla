//! End-to-end: a real in-process validator commits intake bodies while a
//! `Service` replica absorbs journal bundles, projects screens, and
//! resolves local submission markers — no engine access, no signing.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use vhalla_rooms_consensus::fixture;
use vhalla_rooms_node::{service_config, NodeSpec, PrivateKey, RoomNode};
use vhalla_social_store::Store as SocialStore;

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
        config: service_config("svc-test", "127.0.0.1", 0, &[], false, false),
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

/// `create_context`/`update_context` read only committed state — a
/// replica with no running node still reports the genesis quote, the
/// owner's social head, and denies a key that does not control the owner.
#[test]
fn context_helpers_report_committed_state() {
    let base = temp("ctx");
    let s = fixture::scenario(4, 8);
    let social_dir = base.join("social-store");
    {
        let mut social =
            SocialStore::create(&social_dir, s.genesis.realm, s.genesis.limits).unwrap();
        social
            .commit(s.genesis.archive.clone(), social.pin())
            .unwrap();
    }
    let node_home = base.join("node");
    std::fs::create_dir_all(node_home.join("app").join("journal")).unwrap();
    std::fs::create_dir_all(node_home.join("intake")).unwrap();
    let key = PrivateKey::from([9; 32]);
    let config = ServiceConfig::parse(&config_json(&s, &key)).unwrap();
    let service = Service::open(&social_dir, &node_home, &base.join("replica"), &config).unwrap();

    let owner = &s.owners[0];
    let owner_key = owner.key.verifying_key().to_bytes();
    let ctx = service.create_context(owner.id, owner_key, 1).unwrap();
    assert_eq!(ctx.directory, hex(s.genesis.directory.as_bytes()));
    assert_eq!(ctx.realm, format!("{:032x}", s.genesis.realm.0));
    assert_eq!(ctx.slot, 1, "a first room quotes slot one");
    assert_eq!(ctx.charge, s.genesis.policy.base_cost);
    assert_eq!(ctx.social_control, hex(owner.head.as_bytes()));
    assert_eq!(ctx.room_head, None, "no room-control chain at genesis");
    assert_eq!(ctx.sequence, 0);
    assert_eq!(ctx.balance, 0, "no finalized awards at genesis");

    // A key that does not control the owner is refused.
    let other_key = s.owners[1].key.verifying_key().to_bytes();
    assert!(service.create_context(owner.id, other_key, 1).is_err());

    // An unknown slug has no update context.
    assert!(service.update_context("ghost", owner_key, 1).is_err());

    let _ = std::fs::remove_dir_all(&base);
}

fn rotation(from: u64, key: &PrivateKey, power: u64) -> vhalla_rooms_consensus::CommittedRotation {
    vhalla_rooms_consensus::CommittedRotation {
        from,
        validators: vec![vhalla_rooms_consensus::ValidatorMember {
            key: *key.public_key().as_bytes(),
            power,
        }],
    }
}

/// Produce actual signed VC2 certificates without running a consensus
/// engine. Adapter::decide trusts its caller's certificate check, allowing
/// negative tests to publish a source journal signed by an unauthorized key;
/// Service::sync must independently reject that journal's certificates.
fn commit_signed(
    source: &mut Adapter<FsStore>,
    key: &PrivateKey,
    rotation: Option<vhalla_rooms_consensus::CommittedRotation>,
) {
    let height = source.frontier().height + 1;
    let batch = source
        .application()
        .prepare_with_games(height, vec![], vec![], vec![], None, rotation)
        .unwrap()
        .batch()
        .clone();
    let value = batch.value_id();
    let address = vhalla_rooms_node::Address::from_public_key(&key.public_key()).into_inner();
    // RV1 precommit: height, round zero, non-nil value, signer address.
    let mut vote = b"RV1\x01".to_vec();
    vote.extend_from_slice(&height.to_be_bytes());
    vote.extend_from_slice(&0u32.to_be_bytes());
    vote.push(1);
    vote.extend_from_slice(&value);
    vote.extend_from_slice(&address);
    let mut certificate = b"VC2".to_vec();
    certificate.extend_from_slice(&height.to_be_bytes());
    certificate.extend_from_slice(&0u32.to_be_bytes());
    certificate.extend_from_slice(&value);
    certificate.extend_from_slice(&1u16.to_be_bytes());
    certificate.extend_from_slice(&address);
    certificate.extend_from_slice(&key.sign(&vote).to_bytes());
    assert!(verify_canonical_certificate(
        &certificate,
        height,
        &RoomValueId(value),
        &RoomValidatorSet::new(vec![RoomValidator::new(key.public_key(), 1)]),
    ));
    source.hold(batch);
    assert_eq!(
        source.decide(&vhalla_rooms_consensus::CommitCertificate {
            bytes: certificate,
            value_commitment: value,
            height,
        }),
        vhalla_rooms_consensus::DecidedOutcome::Acked,
    );
}

fn rotation_replica_config(
    base: &Path,
    scenario: &fixture::Scenario,
    initial: &PrivateKey,
    file_future: &PrivateKey,
) -> (PathBuf, ServiceConfig) {
    let social_dir = base.join("social");
    let mut social =
        SocialStore::create(&social_dir, scenario.genesis.realm, scenario.genesis.limits).unwrap();
    social
        .commit(scenario.genesis.archive.clone(), social.pin())
        .unwrap();
    let mut raw: serde_json::Value =
        serde_json::from_slice(&config_json(scenario, initial)).unwrap();
    raw["validators"] = serde_json::json!([
        {"from": 1, "key": hex(initial.public_key().as_bytes()), "power": 1},
        {"from": 2, "key": hex(initial.public_key().as_bytes()), "power": 2},
        {"from": 4, "key": hex(file_future.public_key().as_bytes()), "power": 9},
        {"from": 5, "key": hex(initial.public_key().as_bytes()), "power": 1},
        {"from": 8, "key": hex(file_future.public_key().as_bytes()), "power": 9},
    ]);
    (
        social_dir,
        ServiceConfig::parse(&serde_json::to_vec(&raw).unwrap()).unwrap(),
    )
}

#[test]
fn replica_follows_committed_rotations_and_restores_effective_schedule_on_reopen() {
    let base = temp("rotations");
    let scenario = fixture::scenario(2, 4);
    let [initial, first, second, file_future] =
        [7, 9, 11, 13].map(|seed| PrivateKey::from([seed; 32]));
    let (social, config) = rotation_replica_config(&base, &scenario, &initial, &file_future);
    let node = base.join("node");
    let replica = base.join("replica");
    let mut source = Adapter::open(node.join("app"), &scenario.genesis).unwrap();
    let mut service = Service::open(&social, &node, &replica, &config).unwrap();

    // The old committee certifies a future rotation. The effective status
    // immediately reports it, retaining file activations only below four.
    commit_signed(&mut source, &initial, Some(rotation(4, &first, 3)));
    assert_eq!(service.sync().unwrap(), 1);
    assert_eq!(
        service
            .validator_schedule()
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        vec![1, 2, 4]
    );
    assert_eq!(service.quorum().unwrap().total_power, 1);
    drop(service);
    let mut service = Service::open(&social, &node, &replica, &config).unwrap();
    assert_eq!(
        service
            .validator_schedule()
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        vec![1, 2, 4]
    );
    assert_eq!(
        service.validator_schedule()[&4].validators[0].public_key,
        first.public_key()
    );

    commit_signed(&mut source, &initial, None);
    commit_signed(&mut source, &initial, Some(rotation(7, &second, 5)));
    // These heights cross both activations within one sync call. In
    // particular, file entries at five and eight must not regain control.
    for (height, key) in [
        (4, &first),
        (5, &first),
        (6, &first),
        (7, &second),
        (8, &second),
    ] {
        commit_signed(&mut source, key, None);
        assert_eq!(source.frontier().height, height);
    }
    assert_eq!(service.sync().unwrap(), 8);
    let expected_schedule = BTreeMap::from([
        (
            1,
            RoomValidatorSet::new(vec![RoomValidator::new(initial.public_key(), 1)]),
        ),
        (
            2,
            RoomValidatorSet::new(vec![RoomValidator::new(initial.public_key(), 2)]),
        ),
        (
            4,
            RoomValidatorSet::new(vec![RoomValidator::new(first.public_key(), 3)]),
        ),
        (
            7,
            RoomValidatorSet::new(vec![RoomValidator::new(second.public_key(), 5)]),
        ),
    ]);
    assert_eq!(service.validator_schedule(), &expected_schedule);
    let expected_quorum = Quorum {
        height: 8,
        total_power: 5,
        threshold: 4,
        validators: vec![(hex(second.public_key().as_bytes()), 5)],
    };
    assert_eq!(service.quorum(), Some(expected_quorum.clone()));
    drop(service);
    let mut reopened = Service::open(&social, &node, &replica, &config).unwrap();
    assert_eq!(reopened.validator_schedule(), &expected_schedule);
    assert_eq!(reopened.quorum(), Some(expected_quorum.clone()));
    assert_eq!(reopened.sync().unwrap(), 8);

    // A fresh replica must also cross every rotation in one journal scan.
    let mut fresh = Service::open(&social, &node, &base.join("fresh"), &config).unwrap();
    assert_eq!(fresh.sync().unwrap(), 8);
    assert_eq!(fresh.validator_schedule(), &expected_schedule);
    assert_eq!(fresh.quorum(), Some(expected_quorum));
    drop((source, reopened, fresh));
    let _ = std::fs::remove_dir_all(base);
}

#[test]
fn replica_rotations_never_authorize_their_own_or_retired_certificates() {
    let scenario = fixture::scenario(2, 4);
    let [initial, rotated, file_future] = [17, 19, 21].map(|seed| PrivateKey::from([seed; 32]));
    for (case, signer, accepted_prefix) in [
        ("self-authorized", &rotated, 0),
        ("retired", &initial, 3),
        ("file-future", &file_future, 3),
    ] {
        let base = temp(case);
        let (social, config) = rotation_replica_config(&base, &scenario, &initial, &file_future);
        let node = base.join("node");
        let replica = base.join("replica");
        let mut source = Adapter::open(node.join("app"), &scenario.genesis).unwrap();
        if accepted_prefix == 3 {
            commit_signed(&mut source, &initial, Some(rotation(4, &rotated, 3)));
            commit_signed(&mut source, &initial, None);
            commit_signed(&mut source, &initial, None);
        }
        commit_signed(&mut source, signer, Some(rotation(9, signer, 7)));
        let mut service = Service::open(&social, &node, &replica, &config).unwrap();
        assert_eq!(service.sync().unwrap(), accepted_prefix, "{case}");
        assert!(
            !service.registry().validator_schedule().contains_key(&9),
            "{case}"
        );
        if accepted_prefix == 3 {
            assert_eq!(
                service.validator_schedule()[&4].validators[0].public_key,
                rotated.public_key()
            );
            assert!(!service.validator_schedule().contains_key(&5));
            assert!(!service.validator_schedule().contains_key(&8));
            assert_eq!(service.quorum().unwrap().total_power, 2);
        }
        drop(service);
        let mut reopened = Service::open(&social, &node, &replica, &config).unwrap();
        assert_eq!(reopened.sync().unwrap(), accepted_prefix, "reopened {case}");
        assert!(!reopened.registry().validator_schedule().contains_key(&9));
        drop((source, reopened));
        let _ = std::fs::remove_dir_all(base);
    }
}

#[test]
fn replica_rejects_journal_markers_that_do_not_bind_the_bundle() {
    let scenario = fixture::scenario(2, 4);
    let [initial, rotated] = [23, 25].map(|seed| PrivateKey::from([seed; 32]));
    for wrong_height in [true, false] {
        let base = temp("unbound-marker");
        let (social, config) = rotation_replica_config(&base, &scenario, &initial, &rotated);
        let node = base.join("node");
        let mut source = Adapter::open(node.join("app"), &scenario.genesis).unwrap();
        commit_signed(&mut source, &initial, Some(rotation(4, &rotated, 3)));
        let signer = if wrong_height { &rotated } else { &initial };
        commit_signed(&mut source, signer, None);
        let bundle = source.committed_at_height(2).unwrap();
        let journal = node.join("app/journal");
        drop(source);
        if wrong_height {
            // A height-four marker points to a height-two bundle signed
            // by the new committee. Selecting trust by the marker alone
            // would activate that committee two heights prematurely.
            FsStore.remove_height_marker(&journal, 2).unwrap();
            FsStore
                .write_height_marker(&journal, 4, bundle.id())
                .unwrap();
        } else {
            let wrong_id = [42; 32];
            assert_ne!(bundle.id(), wrong_id);
            assert!(FsStore
                .create_bundle(&journal, wrong_id, bundle.bytes())
                .unwrap());
            FsStore.write_height_marker(&journal, 2, wrong_id).unwrap();
        }
        let mut service = Service::open(&social, &node, &base.join("replica"), &config).unwrap();
        assert_eq!(service.sync().unwrap(), 1, "wrong height: {wrong_height}");
        assert_eq!(
            service.quorum().unwrap().validators,
            vec![(hex(initial.public_key().as_bytes()), 1)]
        );
        drop(service);
        let _ = std::fs::remove_dir_all(base);
    }
}
