#![cfg(all(unix, feature = "quorum", feature = "oracle"))]
//! Live qualification for `Authority::Quorum`: a real in-process validator
//! mesh decides the rooms-consensus game-commitment lane and issues the
//! `VC2` certificates that open, order, settle, and attest a quorum session.
//! The validator set rotates mid-session — pre-rotation records are proven
//! under the first set, the seal and settlement under the replacement set —
//! so the certificate verify hook is exercised against real issuance at
//! every height it consumes, never a fixture signature.

mod common;

use std::collections::BTreeMap;
use std::time::Duration;

use common::{live_manifest, passed_by_plain_run, policy, Signer, REALM, ROOM};
use vhalla_core::{Epoch, Sequence};
use vhalla_game_platonik::ids::{CheckpointHash, GameEventDigest, RulesetId};
use vhalla_game_platonik::manifest::{GameManifest, MissingMember};
use vhalla_game_platonik::oracle::convert::convert;
use vhalla_game_platonik::platonik::PlatonikV1;
use vhalla_game_platonik::quorum::{attest, commitment, open as quorum_open, open_commitment};
use vhalla_game_platonik::receiver::Receiver;
use vhalla_game_platonik::record::{GameRecord, RecordKind};
use vhalla_game_platonik::session::{
    bind_commit, derive_seed, fill_salt, quorum_actor, seed_commitment, Session,
};
use vhalla_game_platonik::wire::{
    encode_game_event, encode_settlement, Authority, EventBody, GameEvent, Player, SessionOpen,
    Settlement,
};
use vhalla_journal::{FsStore, Journal};
use vhalla_rooms_consensus::{
    fixture, Application, Batch, CommitCertificate, Frontier, GameCommitment,
};
use vhalla_rooms_node::cert::verify_canonical_certificate;
use vhalla_rooms_node::{
    node_config, NodeSpec, PrivateKey, RoomNode, RoomValidator, RoomValidatorSet, RoomValueId,
};
use vhalla_witness::hash::ProgramHash;
use vhalla_witness::manifest::{TaskManifest, ValidManifest};
use vhalla_witness::platform::{ClaimedReceipt, ReceiptBinding, WorkAllowance};
use vhalla_witness::world::EventKind;

/// The session shape this mesh decides: five heights of game commitments.
/// Heights 1-2 are certified by the first single-validator set, heights 3-5
/// by the replacement set — the rotation boundary sits between `input` and
/// `seal`, so the final seal and the settlement are quorum evidence issued
/// by a different validator than the session opened under.
const HEIGHTS: u64 = 5;
const ROTATE: u64 = 3;

struct Parts {
    manifest: GameManifest,
    template: TaskManifest,
    open: SessionOpen,
    slot: u16,
    program: vhalla_witness::model::Program,
    host_salt: [u8; 32],
    actor: [u8; 32],
}

fn parts() -> Parts {
    let scheme = ProgramHash::of(b"vhalla/game/live-quorum-scheme/v1").0;
    let player = Signer::new(2);
    let converted =
        convert(&platonik_core::fixtures::experiment("opening-normal").unwrap()).unwrap();
    let publisher = ProgramHash::of(b"vhalla/game/live-quorum-publisher/v1").0;
    let (manifest, template) = live_manifest(&converted, publisher, 64, MissingMember::Pause, None);
    let slot = converted.programs[0].0;
    let program = converted.programs[0].1.clone();
    let host_salt = ProgramHash::of(b"vhalla/game/live-quorum-host-salt/v1").0;
    let open = SessionOpen {
        realm: REALM,
        room: ROOM,
        manifest: manifest.hash(),
        ruleset: RulesetId::V1,
        seed_commitment: seed_commitment(&host_salt, manifest.world),
        authority: Authority::Quorum { scheme },
        players: vec![Player {
            key: player.public(),
            slots: vec![slot],
        }],
        epoch: Epoch(0),
        nonce: ProgramHash::of(b"vhalla/game/live-quorum-nonce/v1").0,
    };
    Parts {
        manifest,
        template,
        open,
        slot,
        program,
        host_salt,
        actor: quorum_actor(&scheme),
    }
}

/// A scratch decided batch: the plan phase only needs position-bearing
/// proofs, which `prove` mints against any batch whose lane matches.
fn decided(games: Vec<GameCommitment>, height: u64) -> (Batch, CommitCertificate) {
    let batch = Batch {
        parent: Frontier {
            height: height - 1,
            value: [1; 32],
            registry: [2; 32],
            social: [3; 32],
            control: [4; 32],
            time: 100,
        },
        time: 101,
        evidence: Vec::new(),
        records: Vec::new(),
        games,
        eligible: None,
        result_registry: [5; 32],
        result_social: [6; 32],
        result_control: [7; 32],
    };
    let certificate = CommitCertificate {
        bytes: Vec::new(),
        value_commitment: batch.value_id(),
        height,
    };
    (batch, certificate)
}

/// The quorum actor's event record: unsigned — its authority is the decided
/// commitment, not a signature.
fn actor_event(
    actor: [u8; 32],
    session: &Session,
    sequence: u64,
    body: EventBody,
) -> (GameRecord, GameEventDigest) {
    let event = GameEvent {
        session: session.key(),
        epoch: session.epoch(),
        author: actor,
        sequence: Sequence(sequence),
        parents: Vec::new(),
        body,
    };
    let digest = event.digest();
    let record = GameRecord::unsigned(
        RecordKind::Event,
        session.key(),
        actor,
        encode_game_event(&event),
    )
    .unwrap();
    (record, digest)
}

/// The quorum actor's seal, derived like an honest host's through a scratch
/// receiver, carried unsigned.
fn actor_seal(
    actor: [u8; 32],
    session: &Session,
    sequence: u64,
    through_tick: u32,
    order: Vec<GameEventDigest>,
) -> (GameRecord, CheckpointHash) {
    let draft = GameEvent {
        session: session.key(),
        epoch: session.epoch(),
        author: actor,
        sequence: Sequence(sequence),
        parents: Vec::new(),
        body: EventBody::Seal {
            segment: 0,
            through_tick,
            order: order.clone(),
            checkpoint: CheckpointHash([0; 32]),
        },
    };
    let plan = session.plan_seal(&draft).unwrap();
    let mut scratch = Receiver::new(PlatonikV1, policy());
    let checkpoint = scratch.derive(session, &plan).unwrap().hash();
    let (record, _) = actor_event(
        actor,
        session,
        sequence,
        EventBody::Seal {
            segment: plan.segment,
            through_tick: plan.through_tick,
            order,
            checkpoint,
        },
    );
    (record, checkpoint)
}

/// The full record plan: every game record the session will need, minted
/// through a scratch session driven by synthetic proofs, and the per-height
/// game lanes the mesh should decide. Records carry no consensus state, so
/// the same bytes the scratch session admits are the bytes the live mesh
/// orders.
struct Planned {
    parts: Parts,
    /// (record, height, lane position, receiver step) in session order.
    admissions: Vec<(GameRecord, u64, usize, u64)>,
    settlement: GameRecord,
    /// Height -> game commitments for the node's held batches.
    lanes: Vec<(u64, Vec<GameCommitment>)>,
}

fn plan() -> Planned {
    let parts = parts();
    let (b0, c0) = decided(vec![open_commitment(&parts.open)], 1);
    let mut session = quorum_open(
        parts.manifest.clone(),
        parts.open.clone(),
        REALM,
        &c0,
        &b0,
        0,
        |_, _, _| true,
    )
    .unwrap();
    let mut receiver = Receiver::new(PlatonikV1, policy());
    let mut player = Signer::new(2);
    let key = session.key();
    let mut scratch_height = 1_000_u64;
    let mut admit = |session: &mut Session, record: &GameRecord, step: u64| {
        let named = commitment(session, record).unwrap();
        let (b, c) = decided(vec![named], scratch_height);
        scratch_height += 1;
        receiver
            .admit_quorum(session, record, &c, &b, 0, step, |_, _, _| true)
            .unwrap()
    };

    let salt = fill_salt(ProgramHash::of(&key.0), parts.slot);
    let commit = bind_commit(key, parts.slot, &parts.program, &salt);
    let mut order_digests = Vec::new();

    let (bind, d) = player.event(
        key,
        Epoch(0),
        EventBody::BindCommit {
            slot: parts.slot,
            commit,
        },
    );
    admit(&mut session, &bind, 1);
    order_digests.push(d);

    let (close, d) = actor_event(
        parts.actor,
        &session,
        1,
        EventBody::BindClose {
            commits: vec![(parts.slot, commit)],
        },
    );
    admit(&mut session, &close, 1);
    order_digests.push(d);

    let (reveal_bind, d) = player.event(
        key,
        Epoch(0),
        EventBody::BindReveal {
            slot: parts.slot,
            program: parts.program.clone(),
            salt,
        },
    );
    admit(&mut session, &reveal_bind, 1);
    order_digests.push(d);

    let mut task = parts.template.clone();
    task.cases[0].seed = derive_seed(&parts.host_salt, &[salt], 0);
    let (reveal, d) = actor_event(
        parts.actor,
        &session,
        2,
        EventBody::Reveal {
            task: task.clone(),
            host_salt: parts.host_salt,
        },
    );
    admit(&mut session, &reveal, 2);
    order_digests.push(d);

    let (input, d) = player.event(
        key,
        Epoch(0),
        EventBody::Input {
            case: 0,
            tick: 2,
            kind: EventKind::ClearMemory { cell: parts.slot },
        },
    );
    admit(&mut session, &input, 3);
    order_digests.push(d);

    let (seal, final_checkpoint) =
        actor_seal(parts.actor, &session, 3, task.cases[0].ticks, order_digests);
    let verified = admit(&mut session, &seal, 4).unwrap();
    assert!(verified.is_final());

    let mut full = task.clone();
    full.cases[0].events = vec![vhalla_witness::world::Event {
        tick: 2,
        event: EventKind::ClearMemory { cell: parts.slot },
    }];
    let passed = passed_by_plain_run(&full, vec![(parts.slot, parts.program.clone())]);
    let (task_final, candidate, through) = session.final_plan().cloned().unwrap();
    let valid = ValidManifest::validate(task_final).unwrap();
    let evidence = vhalla_game_platonik::engine::GameEngine::replay(
        &PlatonikV1,
        session.world(),
        &valid,
        candidate,
        WorkAllowance {
            max_total: valid.fuel_total(),
        },
        through,
        ReceiptBinding {
            challenge_id: key.0,
            subject_key: parts.actor,
        },
    )
    .unwrap();
    let settlement = GameRecord::unsigned(
        RecordKind::Settlement,
        key,
        parts.actor,
        encode_settlement(&Settlement::Result {
            session: key,
            epoch: Epoch(0),
            checkpoint: final_checkpoint,
            receipt: ClaimedReceipt::decode(&evidence.receipt.encode()).unwrap(),
            passed,
        }),
    )
    .unwrap();

    let lane = |records: &[&GameRecord]| {
        records
            .iter()
            .map(|r| commitment(&session, r).unwrap())
            .collect::<Vec<_>>()
    };
    let lanes = vec![
        (1, vec![open_commitment(&parts.open)]),
        (2, lane(&[&bind, &close, &reveal_bind])),
        (3, lane(&[&reveal, &input])),
        (4, lane(&[&seal])),
        (5, lane(&[&settlement])),
    ];
    let admissions = vec![
        (bind, 2, 0, 1),
        (close, 2, 1, 1),
        (reveal_bind, 2, 2, 1),
        (reveal, 3, 0, 2),
        (input, 3, 1, 3),
        (seal, 4, 0, 4),
    ];
    Planned {
        parts,
        admissions,
        settlement,
        lanes,
    }
}

/// The validator set active at `height` under a `BTreeMap` schedule.
fn set_at(schedule: &BTreeMap<u64, RoomValidatorSet>, height: u64) -> RoomValidatorSet {
    schedule.range(..=height).next_back().unwrap().1.clone()
}

async fn wait_for(what: &str, mut ready: impl FnMut() -> bool, timeout: Duration) {
    let deadline = std::time::Instant::now() + timeout;
    while !ready() {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Real certificate issuance and rotation: two validators, the second
/// replacing the first at `ROTATE`. Every height of the session's game
/// lane is decided by the mesh and journaled with an engine certificate;
/// admission consumes proofs verified by `verify_canonical_certificate`
/// under the set active at that height.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn live_quorum_certificates_admit_a_session_across_rotation() {
    let planned = plan();
    let genesis = fixture::plan(0, 8, 16).genesis;

    // The held batches: a parent-chained games-only lane built against the
    // genesis frontier — the same bytes every node proposes at its height.
    let mut app = Application::genesis(genesis.archive.clone(), genesis.registry().unwrap());
    let mut held = BTreeMap::new();
    for (h, games) in &planned.lanes {
        let checked = app
            .prepare_with_games(*h, Vec::new(), Vec::new(), games.clone(), None)
            .unwrap();
        held.insert(*h, checked.batch().clone());
        app.apply_locally(checked);
    }

    let ka = PrivateKey::from([41; 32]);
    let kb = PrivateKey::from([87; 32]);
    let set1 = RoomValidatorSet::new(vec![RoomValidator::new(ka.public_key(), 1)]);
    let set2 = RoomValidatorSet::new(vec![RoomValidator::new(kb.public_key(), 1)]);
    let schedule = BTreeMap::from([(1_u64, set1.clone()), (ROTATE, set2.clone())]);

    let base = std::env::temp_dir().join(format!(
        "live-quorum-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let base_port = 31_000
        + (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
            % 1_000) as usize;

    let mut nodes = Vec::new();
    for (i, key) in [&ka, &kb].into_iter().enumerate() {
        nodes.push(
            RoomNode::start(NodeSpec {
                home: base.join(format!("n{i}")),
                config: node_config(i + 1, 2, base_port),
                node_key: key.clone(),
                validator_sets: schedule.clone(),
                held: held.clone(),
                genesis: genesis.clone(),
                wal_faults: None,
                net_gate: None,
            })
            .await,
        );
    }
    wait_for(
        "both nodes to journal-commit every game height",
        || nodes.iter().all(|n| n.committed_height() >= HEIGHTS),
        Duration::from_secs(120),
    )
    .await;

    // The verify hook a quorum consumer runs: the trusted set is the one
    // the schedule activates at the certificate's height.
    let schedule_verify = schedule.clone();
    let verify = move |bytes: &[u8], height: u64, value: &[u8; 32]| {
        verify_canonical_certificate(
            bytes,
            height,
            &RoomValueId(*value),
            &set_at(&schedule_verify, height),
        )
    };

    // Every decided height carries a real certificate under its active set.
    let journal = Journal::new(nodes[0].home.join("app").join("journal"), FsStore);
    journal.recover().unwrap();
    let decided_at = |height: u64| {
        let id = journal.at_height(height).unwrap().unwrap();
        let bundle = journal.bundle(id).unwrap().unwrap();
        let batch = Batch::decode(bundle.field(3).unwrap()).unwrap();
        assert_eq!(bundle.height(), height);
        assert_eq!(&batch, held.get(&height).unwrap());
        (
            CommitCertificate {
                bytes: bundle.field(0).unwrap().to_vec(),
                height,
                value_commitment: batch.value_id(),
            },
            batch,
        )
    };
    for h in 1..=HEIGHTS {
        let (cert, _) = decided_at(h);
        assert!(
            verify(&cert.bytes, cert.height, &cert.value_commitment),
            "height {h} certificate must verify under its active set"
        );
    }

    // Open under the first set's certificate, order every record under the
    // set active at its height, settle and attest under the rotated set.
    let (c1, b1) = decided_at(1);
    let mut session = quorum_open(
        planned.parts.manifest.clone(),
        planned.parts.open.clone(),
        REALM,
        &c1,
        &b1,
        0,
        &verify,
    )
    .unwrap();
    let mut receiver = Receiver::new(PlatonikV1, policy());
    for (record, height, position, step) in &planned.admissions {
        let (cert, batch) = decided_at(*height);
        receiver
            .admit_quorum(
                &mut session,
                record,
                &cert,
                &batch,
                *position,
                *step,
                &verify,
            )
            .unwrap();
    }
    assert_eq!(
        session.state(),
        vhalla_game_platonik::session::State::Finished
    );

    let (c5, b5) = decided_at(HEIGHTS);
    let verified = receiver
        .settle_quorum(&mut session, &planned.settlement, &c5, &b5, 0, 5, &verify)
        .unwrap();
    let attested = attest(&verified, &c5, &b5.encode(), &verify).unwrap();
    assert_eq!(attested.hash(), verified.hash());

    // The rotated-out set cannot vouch for post-rotation heights.
    let stale = set_at(&schedule, 1);
    assert!(attest(&verified, &c5, &b5.encode(), |bytes, h, v| {
        verify_canonical_certificate(bytes, h, &RoomValueId(*v), &stale)
    })
    .is_err());

    for node in nodes {
        node.crash().await;
    }
    let _ = std::fs::remove_dir_all(&base);
}
