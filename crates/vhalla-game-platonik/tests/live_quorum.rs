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
use vhalla_game_platonik::settlement::VerifiedSettlement;
use vhalla_game_platonik::wire::{
    encode_game_event, encode_settlement, Authority, EventBody, GameEvent, Player, SessionOpen,
    Settlement,
};
use vhalla_journal::{FsStore, Journal};
use vhalla_rooms_consensus::{
    fixture, Application, Batch, BatchBody, CommitCertificate, Frontier, GameCommitment, Genesis,
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

/// A node's `app/journal` store, recovered and ready to read.
fn open_journal(home: &std::path::Path) -> Journal<FsStore> {
    let journal = Journal::new(home.join("app").join("journal"), FsStore);
    journal.recover().unwrap();
    journal
}

/// A journaled (certificate, batch) pair at `height`: the real `VC2`
/// certificate bytes and the decided batch, read back out of the node's
/// own journal store.
fn decided_at(journal: &Journal<FsStore>, height: u64) -> (CommitCertificate, Batch) {
    let id = journal.at_height(height).unwrap().unwrap();
    let bundle = journal.bundle(id).unwrap().unwrap();
    let batch = Batch::decode(bundle.field(3).unwrap()).unwrap();
    assert_eq!(bundle.height(), height);
    (
        CommitCertificate {
            bytes: bundle.field(0).unwrap().to_vec(),
            height,
            value_commitment: batch.value_id(),
        },
        batch,
    )
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

/// The canonical per-height batches a plan expects the mesh to decide:
/// games-only lanes chained against the genesis frontier — the same bytes
/// every node must propose or re-assemble at its height.
fn canonical_batches(planned: &Planned, genesis: &Genesis) -> BTreeMap<u64, Batch> {
    let mut app = Application::genesis(genesis.archive.clone(), genesis.registry().unwrap());
    let mut held = BTreeMap::new();
    for (h, games) in &planned.lanes {
        let checked = app
            .prepare_with_games(*h, Vec::new(), Vec::new(), games.clone(), None)
            .unwrap();
        held.insert(*h, checked.batch().clone());
        app.apply_locally(checked);
    }
    held
}

/// The two-validator rotation this suite runs: `ka` alone certifies heights
/// 1-2, `kb` alone certifies heights 3-5 under the whole-set replacement at
/// `ROTATE` — so the session's seal and settlement are quorum evidence
/// issued by a different validator than it opened under.
fn rotation() -> (PrivateKey, PrivateKey, BTreeMap<u64, RoomValidatorSet>) {
    let ka = PrivateKey::from([41; 32]);
    let kb = PrivateKey::from([87; 32]);
    let set1 = RoomValidatorSet::new(vec![RoomValidator::new(ka.public_key(), 1)]);
    let set2 = RoomValidatorSet::new(vec![RoomValidator::new(kb.public_key(), 1)]);
    (ka, kb, BTreeMap::from([(1_u64, set1), (ROTATE, set2)]))
}

/// A unique temp dir and a base port in a band disjoint across this file's
/// concurrently running tests.
fn mesh_base(tag: &str, port_band: usize) -> (std::path::PathBuf, usize) {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    (
        std::env::temp_dir().join(format!("live-quorum-{tag}-{}-{nanos}", std::process::id())),
        port_band + (nanos % 1_000) as usize,
    )
}

/// Spawn the two-node mesh on the rotation schedule. `held` pre-loads the
/// batches a node may propose; an empty map leaves every value to the
/// `home/intake/` producer contract.
async fn spawn_mesh(
    base: &std::path::Path,
    base_port: usize,
    keys: [&PrivateKey; 2],
    schedule: &BTreeMap<u64, RoomValidatorSet>,
    held: &BTreeMap<u64, Batch>,
    genesis: &Genesis,
) -> Vec<RoomNode> {
    let mut nodes = Vec::new();
    for (i, key) in keys.into_iter().enumerate() {
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
    nodes
}

/// One node's `home/intake/` dir, created before the mesh starts — a drop
/// is then a plain file write into the producer contract.
fn intake_dirs(base: &std::path::Path, count: usize) -> Vec<std::path::PathBuf> {
    (0..count)
        .map(|i| {
            let dir = base.join(format!("n{i}")).join("intake");
            std::fs::create_dir_all(&dir).unwrap();
            dir
        })
        .collect()
}

/// The certificate verify hook a quorum consumer runs: the trusted set is
/// the one the schedule activates at the certificate's height.
fn verify_for(schedule: BTreeMap<u64, RoomValidatorSet>) -> impl Fn(&[u8], u64, &[u8; 32]) -> bool {
    move |bytes, height, value| {
        verify_canonical_certificate(
            bytes,
            height,
            &RoomValueId(*value),
            &set_at(&schedule, height),
        )
    }
}

/// Assert a journal serves every height with the canonical batch and a
/// certificate that verifies under its schedule-active set.
fn check_journal(
    journal: &Journal<FsStore>,
    held: &BTreeMap<u64, Batch>,
    verify: &impl Fn(&[u8], u64, &[u8; 32]) -> bool,
) {
    for h in 1..=HEIGHTS {
        let (cert, batch) = decided_at(journal, h);
        assert_eq!(
            &batch,
            held.get(&h).unwrap(),
            "height {h} must journal the canonical batch"
        );
        assert!(
            verify(&cert.bytes, cert.height, &cert.value_commitment),
            "height {h} certificate must verify under its active set"
        );
    }
}

/// Drive a plan's complete quorum path against one journal's evidence:
/// open under height 1's certificate, admit every record at its own height
/// and lane position, settle and attest under the final height.
fn drive_session(
    planned: &Planned,
    journal: &Journal<FsStore>,
    verify: &impl Fn(&[u8], u64, &[u8; 32]) -> bool,
) -> VerifiedSettlement {
    let (c1, b1) = decided_at(journal, 1);
    let mut session = quorum_open(
        planned.parts.manifest.clone(),
        planned.parts.open.clone(),
        REALM,
        &c1,
        &b1,
        0,
        verify,
    )
    .unwrap();
    let mut receiver = Receiver::new(PlatonikV1, policy());
    for (record, height, position, step) in &planned.admissions {
        let (cert, batch) = decided_at(journal, *height);
        receiver
            .admit_quorum(
                &mut session,
                record,
                &cert,
                &batch,
                *position,
                *step,
                verify,
            )
            .unwrap();
    }
    assert_eq!(
        session.state(),
        vhalla_game_platonik::session::State::Finished
    );
    let (c5, b5) = decided_at(journal, HEIGHTS);
    let verified = receiver
        .settle_quorum(&mut session, &planned.settlement, &c5, &b5, 0, 5, verify)
        .unwrap();
    let attested = attest(&verified, &c5, &b5.encode(), verify).unwrap();
    assert_eq!(attested.hash(), verified.hash());
    verified
}

/// A `.body` producer file for one batch's lane — the native format an
/// external producer writes when it owns only body fields.
fn body_file(batch: &Batch) -> Vec<u8> {
    BatchBody {
        time: batch.time,
        evidence: batch.evidence.clone(),
        records: batch.records.clone(),
        games: batch.games.clone(),
        eligible: batch.eligible.clone(),
    }
    .encode()
}

/// One height's producer drop: the file lands in the active proposer's
/// intake, the mesh drains it at `GetValue`, and that node journal-commits
/// the height before the next drop. One file per drain keeps queue order
/// deterministic — the honest cadence for a producer that only learns its
/// lane's height by watching commits.
async fn drop_and_commit(
    nodes: &[RoomNode],
    intakes: &[std::path::PathBuf],
    schedule: &BTreeMap<u64, RoomValidatorSet>,
    height: u64,
    name: &str,
    bytes: Vec<u8>,
) {
    let proposer = if set_at(schedule, height)
        .validators
        .iter()
        .any(|v| v.address == nodes[0].address)
    {
        0
    } else {
        1
    };
    std::fs::write(intakes[proposer].join(name), bytes).unwrap();
    wait_for(
        "the dropped body to decide at its height",
        || nodes[proposer].committed_height() >= height,
        Duration::from_secs(60),
    )
    .await;
}

/// Crash the node at `index`, leaving its home and retained store behind.
async fn crash_node(nodes: &mut Vec<RoomNode>, index: usize) {
    let victim = nodes.remove(index);
    victim.crash().await;
}

/// Restart the crashed node on the same home — the WAL replays its votes,
/// `ConsensusReady` resumes from the durable journal frontier, and the
/// retained store feeds `StartedRound` resupply.
async fn restart_node(
    base: &std::path::Path,
    index: usize,
    base_port: usize,
    key: &PrivateKey,
    schedule: &BTreeMap<u64, RoomValidatorSet>,
    genesis: &Genesis,
) -> RoomNode {
    RoomNode::start(NodeSpec {
        home: base.join(format!("n{index}")),
        config: node_config(index + 1, 2, base_port),
        node_key: key.clone(),
        validator_sets: schedule.clone(),
        held: BTreeMap::new(),
        genesis: genesis.clone(),
        wal_faults: None,
        net_gate: None,
    })
    .await
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
    let held = canonical_batches(&planned, &genesis);
    let (ka, kb, schedule) = rotation();
    let (base, base_port) = mesh_base("certs", 31_000);

    let mut nodes = spawn_mesh(&base, base_port, [&ka, &kb], &schedule, &held, &genesis).await;
    wait_for(
        "both nodes to journal-commit every game height",
        || nodes.iter().all(|n| n.committed_height() >= HEIGHTS),
        Duration::from_secs(120),
    )
    .await;

    let verify = verify_for(schedule.clone());
    let journal = open_journal(&nodes[0].home);
    check_journal(&journal, &held, &verify);
    let verified = drive_session(&planned, &journal, &verify);

    // The rotated-out set cannot vouch for post-rotation heights.
    let (c5, b5) = decided_at(&journal, HEIGHTS);
    let stale = set_at(&schedule, 1);
    assert!(attest(&verified, &c5, &b5.encode(), |bytes, h, v| {
        verify_canonical_certificate(bytes, h, &RoomValueId(*v), &stale)
    })
    .is_err());

    for node in nodes.drain(..) {
        node.crash().await;
    }
    let _ = std::fs::remove_dir_all(&base);
}

/// The producer submission contract and boundary recovery: `NodeSpec::held`
/// is empty, so every value enters through `home/intake/` file drops — the
/// same path an external game daemon uses. Each drop carries only the body
/// fields; parent and result claims are re-assembled at proposal time, so a
/// file with fabricated claims still commits the canonical batch. Validator
/// B (the rotated-in set) crashes after its first certified height and
/// restarts on the same home, resuming from the journal frontier to decide
/// the session's last two heights — its journaled certificates survive.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn live_quorum_intake_drops_drive_admission_through_restart() {
    let planned = plan();
    let genesis = fixture::plan(0, 8, 16).genesis;
    let held = canonical_batches(&planned, &genesis);
    let (ka, kb, schedule) = rotation();
    let (base, base_port) = mesh_base("intake", 32_000);
    let intakes = intake_dirs(&base, 2);
    let mut nodes = spawn_mesh(
        &base,
        base_port,
        [&ka, &kb],
        &schedule,
        &BTreeMap::new(),
        &genesis,
    )
    .await;

    // Heights 1-2 are A's: the h2 `.batch` drop carries fabricated parent and
    // result claims — discarded at intake and re-assembled, so the canonical
    // batch still commits.
    drop_and_commit(
        &nodes,
        &intakes,
        &schedule,
        1,
        "h1.batch",
        held[&1].encode(),
    )
    .await;
    let mut forged = held[&2].clone();
    forged.parent.value = [9; 32];
    forged.result_registry = [8; 32];
    forged.result_social = [7; 32];
    forged.result_control = [6; 32];
    drop_and_commit(&nodes, &intakes, &schedule, 2, "h2.batch", forged.encode()).await;

    // Height 3 is B's first certified height, dropped in the native `.body`
    // producer format (body fields only — the node computes every claim).
    // Then B crashes and restarts on the same home: h4's file waits in the
    // crashed node's intake and is drained when the restarted engine asks
    // for h4's value.
    drop_and_commit(
        &nodes,
        &intakes,
        &schedule,
        3,
        "h3.body",
        body_file(&held[&3]),
    )
    .await;
    // The h4 file lands while B is down — it waits in the crashed node's
    // intake and drains when the restarted engine asks for h4's value.
    crash_node(&mut nodes, 1).await;
    std::fs::write(intakes[1].join("h4.batch"), held[&4].encode()).unwrap();
    let restarted = restart_node(&base, 1, base_port, &kb, &schedule, &genesis).await;
    assert!(
        restarted.loaded.0 >= 3,
        "the retained batch store must reload the three decided batches, got {}",
        restarted.loaded.0
    );
    nodes.push(restarted);
    wait_for(
        "the restarted validator to commit the waiting intake height",
        || nodes[1].committed_height() >= 4,
        Duration::from_secs(90),
    )
    .await;
    drop_and_commit(
        &nodes,
        &intakes,
        &schedule,
        5,
        "h5.batch",
        held[&5].encode(),
    )
    .await;
    wait_for(
        "both nodes to journal-commit every game height",
        || nodes.iter().all(|n| n.committed_height() >= HEIGHTS),
        Duration::from_secs(60),
    )
    .await;

    // Both journals serve every height: A's (issuer at 1-2, follower after)
    // and the restarted B's (issuer at 3-5 over a crash boundary). Every
    // journaled batch is byte-equal to the canonical plan — the fabricated
    // h2 claims were rescued, not committed.
    let verify = verify_for(schedule.clone());
    let journal_a = open_journal(&nodes[0].home);
    let journal_b = open_journal(&nodes[1].home);
    check_journal(&journal_a, &held, &verify);
    check_journal(&journal_b, &held, &verify);

    // The session consumes the restarted node's evidence end to end.
    drive_session(&planned, &journal_b, &verify);

    for node in nodes.drain(..) {
        node.crash().await;
    }
    let _ = std::fs::remove_dir_all(&base);
}

/// Crash recovery mid-height: B's `GetValue` for h3 is held on an empty
/// queue — no file is dropped — so the engine cycles h3 rounds past their
/// request deadlines with live open-height WAL state. B crashes mid-hold
/// and restarts on the same home: the WAL replays the partial height, the
/// engine resumes h3, the `.body` drop drains at the next `GetValue`, and
/// the canonical batch — never a tombstone — decides and certifies.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn live_quorum_mid_height_crash_replays_wal() {
    let planned = plan();
    let genesis = fixture::plan(0, 8, 16).genesis;
    let held = canonical_batches(&planned, &genesis);
    let (ka, kb, schedule) = rotation();
    let (base, base_port) = mesh_base("wal", 33_000);
    let intakes = intake_dirs(&base, 2);
    let mut nodes = spawn_mesh(
        &base,
        base_port,
        [&ka, &kb],
        &schedule,
        &BTreeMap::new(),
        &genesis,
    )
    .await;

    drop_and_commit(
        &nodes,
        &intakes,
        &schedule,
        1,
        "h1.batch",
        held[&1].encode(),
    )
    .await;
    drop_and_commit(
        &nodes,
        &intakes,
        &schedule,
        2,
        "h2.batch",
        held[&2].encode(),
    )
    .await;
    wait_for(
        "validator B to sync the pre-rotation heights",
        || nodes[1].committed_height() >= 2,
        Duration::from_secs(60),
    )
    .await;

    // h3 stalls with the WAL mid-height: B's queue is empty, so its
    // `GetValue` reply holds and each round dies at the request deadline.
    // A few seconds of stall leaves StartedHeight and round entries in the
    // WAL — the crash lands inside an open height, not at a boundary.
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(
        nodes[1].committed_height(),
        2,
        "h3 must still be open when B crashes"
    );
    crash_node(&mut nodes, 1).await;
    // The h3 body lands while B is down; the restarted engine resumes the
    // replayed height and drains it at the next `GetValue`.
    std::fs::write(intakes[1].join("h3.body"), body_file(&held[&3])).unwrap();
    let restarted = restart_node(&base, 1, base_port, &kb, &schedule, &genesis).await;
    assert!(
        restarted.loaded.0 >= 2,
        "the retained batch store must reload decided batches, got {}",
        restarted.loaded.0
    );
    nodes.push(restarted);
    wait_for(
        "the restarted validator to decide h3 over the replayed WAL",
        || nodes[1].committed_height() >= 3,
        Duration::from_secs(90),
    )
    .await;
    drop_and_commit(
        &nodes,
        &intakes,
        &schedule,
        4,
        "h4.batch",
        held[&4].encode(),
    )
    .await;
    drop_and_commit(
        &nodes,
        &intakes,
        &schedule,
        5,
        "h5.batch",
        held[&5].encode(),
    )
    .await;
    wait_for(
        "both nodes to journal-commit every game height",
        || nodes.iter().all(|n| n.committed_height() >= HEIGHTS),
        Duration::from_secs(60),
    )
    .await;

    let verify = verify_for(schedule.clone());
    let journal_a = open_journal(&nodes[0].home);
    let journal_b = open_journal(&nodes[1].home);
    check_journal(&journal_a, &held, &verify);
    check_journal(&journal_b, &held, &verify);
    drive_session(&planned, &journal_b, &verify);

    for node in nodes.drain(..) {
        node.crash().await;
    }
    let _ = std::fs::remove_dir_all(&base);
}
