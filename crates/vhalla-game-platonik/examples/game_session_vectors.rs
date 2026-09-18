//! Writes the two frozen v1 session vectors into `tests/vectors/`: a `Replay`
//! session of the `opening-normal` fixture sealed once, and a `Live` session
//! on the same world with one player, the two-phase bind, two inputs, a
//! mid-tick seal, and a final seal.
//!
//! Every key, salt, and nonce here is a fixed constant, so the vectors are
//! reproducible. Run:
//! `cargo run -p vhalla-game-platonik --example game_session_vectors --features oracle --offline`.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use ed25519_dalek::SigningKey;
use vhalla_core::{Epoch, RealmId, RoomId, Sequence};
use vhalla_game_platonik::engine::GameEngine;
use vhalla_game_platonik::ids::{CheckpointHash, GameEventDigest, RulesetId, SessionKey};
use vhalla_game_platonik::manifest::{
    GameManifest, GameSlot, MissingMember, SessionKind, SessionLimits, SlotRole,
    VerificationAllowance, MAX_ARTIFACT_BYTES,
};
use vhalla_game_platonik::oracle::convert::{convert, Converted};
use vhalla_game_platonik::oracle::corpus::replay_manifest;
use vhalla_game_platonik::platonik::PlatonikV1;
use vhalla_game_platonik::receiver::{Receiver, ReceiverPolicy};
use vhalla_game_platonik::record::{GameRecord, RecordKind};
use vhalla_game_platonik::session::{
    bind_commit, derive_seed, seed_commitment, Session, INPUT_ENCODED_BYTES,
};
use vhalla_game_platonik::wire::{
    encode_checkpoint, encode_game_event, encode_game_manifest, encode_session_open, Authority,
    Checkpoint, EventBody, GameEvent, Player, SessionOpen,
};
use vhalla_witness::codec;
use vhalla_witness::manifest::{ProgramSlot, TaskManifest, ValidManifest, WorkContract};
use vhalla_witness::platform::{ReceiptBinding, WorkAllowance};
use vhalla_witness::vectors::hex;
use vhalla_witness::world::EventKind;

const REALM: RealmId = RealmId(3);
const ROOM: RoomId = RoomId(4);
const HOST_SEED: [u8; 32] = [1; 32];
const PLAYER_SEED: [u8; 32] = [2; 32];
const PUBLISHER: [u8; 32] = [11; 32];
const NONCE: [u8; 32] = [5; 32];
const HOST_SALT: [u8; 32] = [7; 32];
const PLAYER_SALT: [u8; 32] = [3; 32];

fn policy() -> ReceiverPolicy {
    ReceiverPolicy {
        max_replays: 64,
        max_work: u64::MAX,
        max_steps: u64::MAX,
    }
}

/// A fixed-key author that keeps its own sequence, as a real participant does.
struct Signer {
    key: SigningKey,
    sequence: u64,
}

impl Signer {
    fn new(seed: [u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(&seed),
            sequence: 0,
        }
    }
    fn public(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
    fn unsigned(&self, session: SessionKey, epoch: Epoch, body: EventBody) -> GameEvent {
        GameEvent {
            session,
            epoch,
            author: self.public(),
            sequence: Sequence(self.sequence + 1),
            parents: Vec::new(),
            body,
        }
    }
    fn sign(&mut self, event: &GameEvent) -> (GameRecord, GameEventDigest) {
        self.sequence += 1;
        let digest = event.digest();
        let record = GameRecord::sign(
            RecordKind::Event,
            event.session,
            encode_game_event(event),
            &self.key,
        )
        .unwrap();
        (record, digest)
    }
    fn event(
        &mut self,
        session: SessionKey,
        epoch: Epoch,
        body: EventBody,
    ) -> (GameRecord, GameEventDigest) {
        let event = self.unsigned(session, epoch, body);
        self.sign(&event)
    }
    /// An honest host's seal: plan it against the receiver-visible session,
    /// derive the checkpoint the way a receiver does, then sign that hash.
    fn seal(
        &mut self,
        session: &Session,
        segment: u8,
        through_tick: u32,
        order: Vec<GameEventDigest>,
    ) -> (GameRecord, GameEvent, Checkpoint) {
        let draft = self.unsigned(
            session.key(),
            session.epoch(),
            EventBody::Seal {
                segment,
                through_tick,
                order: order.clone(),
                checkpoint: CheckpointHash([0; 32]),
            },
        );
        let plan = session.plan_seal(&draft).unwrap();
        let mut scratch = Receiver::new(PlatonikV1, policy());
        let checkpoint = scratch.derive(session, &plan).unwrap();
        let event = self.unsigned(
            session.key(),
            session.epoch(),
            EventBody::Seal {
                segment,
                through_tick,
                order,
                checkpoint: checkpoint.hash(),
            },
        );
        let (record, _) = self.sign(&event);
        (record, event, checkpoint)
    }
}

/// The receipt the final seal's replay produces, re-derived the way the
/// receiver derives it. The engine seam is public, so nothing is added to the
/// crate's API for this.
fn final_receipt(session: &Session, seal: &GameEvent) -> Vec<u8> {
    let plan = session.plan_seal(seal).unwrap();
    let manifest = ValidManifest::validate(plan.manifest.clone()).unwrap();
    let allowance = WorkAllowance {
        max_total: manifest
            .fuel_total()
            .min(session.manifest().limits.replay.max_total),
    };
    let binding = ReceiptBinding {
        challenge_id: session.key().0,
        subject_key: session.host(),
    };
    let evidence = PlatonikV1
        .replay(
            session.world(),
            &manifest,
            plan.candidate.clone(),
            allowance,
            plan.through_tick,
            binding,
        )
        .unwrap();
    evidence.receipt.encode()
}

/// The `key: value` lines of one vector file.
struct Vector {
    header: String,
    records: String,
    count: usize,
}

impl Vector {
    fn new(id: &str, kind: &str, world: &str, manifest: &GameManifest, open: &SessionOpen) -> Self {
        let mut header = String::new();
        writeln!(header, "id: {id}").unwrap();
        writeln!(header, "session_kind: {kind}").unwrap();
        writeln!(header, "world: {world}").unwrap();
        writeln!(
            header,
            "game_manifest: {}",
            hex(&encode_game_manifest(manifest))
        )
        .unwrap();
        writeln!(header, "game_manifest_hash: {}", hex(&manifest.hash().0)).unwrap();
        writeln!(header, "session_open: {}", hex(&encode_session_open(open))).unwrap();
        writeln!(header, "session_key: {}", hex(&open.key().0)).unwrap();
        Self {
            header,
            records: String::new(),
            count: 0,
        }
    }
    fn record(&mut self, body: &str, record: &GameRecord, digest: GameEventDigest) {
        let index = self.count;
        self.count += 1;
        let out = &mut self.records;
        writeln!(out, "record[{index}].kind: {}", record.kind as u8).unwrap();
        writeln!(out, "record[{index}].body: {body}").unwrap();
        writeln!(out, "record[{index}].signer: {}", hex(&record.signer)).unwrap();
        writeln!(out, "record[{index}].event_digest: {}", hex(&digest.0)).unwrap();
        writeln!(out, "record[{index}].record: {}", hex(&record.encode())).unwrap();
    }
    fn seal(
        &mut self,
        record: &GameRecord,
        digest: GameEventDigest,
        checkpoint: &Checkpoint,
        is_final: bool,
    ) {
        let index = self.count;
        self.record("seal", record, digest);
        let out = &mut self.records;
        writeln!(out, "record[{index}].final: {}", u8::from(is_final)).unwrap();
        writeln!(
            out,
            "record[{index}].checkpoint: {}",
            hex(&encode_checkpoint(checkpoint))
        )
        .unwrap();
        writeln!(
            out,
            "record[{index}].checkpoint_hash: {}",
            hex(&checkpoint.hash().0)
        )
        .unwrap();
    }
    fn write(self, dir: &Path, name: &str, receipt: &[u8]) {
        let mut text = self.header;
        writeln!(text, "record_count: {}", self.count).unwrap();
        text.push_str(&self.records);
        writeln!(text, "receipt: {}", hex(receipt)).unwrap();
        writeln!(
            text,
            "receipt_hash: {}",
            hex(&vhalla_witness::hash::digest(
                vhalla_witness::hash::RECEIPT_DOMAIN,
                receipt
            ))
        )
        .unwrap();
        let path = dir.join(name);
        fs::write(&path, text).unwrap();
        println!("{}", path.display());
    }
}

/// The `Replay` session: the fixture's own seed and events, one final seal.
fn replay_vector(dir: &Path, converted: &Converted) {
    let mut host = Signer::new(HOST_SEED);
    let manifest = replay_manifest(converted, PUBLISHER);
    let open = SessionOpen {
        realm: REALM,
        room: ROOM,
        manifest: manifest.hash(),
        ruleset: RulesetId::V1,
        seed_commitment: [0; 32],
        authority: Authority::Host { key: host.public() },
        players: Vec::new(),
        epoch: Epoch(0),
        nonce: NONCE,
    };
    let mut vector = Vector::new(
        "game-v1-session-replay",
        "replay",
        "opening-normal",
        &manifest,
        &open,
    );
    let mut session = Session::open(manifest, open, REALM).unwrap();
    let mut receiver = Receiver::new(PlatonikV1, policy());
    let key = session.key();
    let mut task = converted.template.clone();
    task.cases[0].seed = converted.task.cases[0].seed;
    task.cases[0].events = converted.task.cases[0].events.clone();
    let ticks = task.cases[0].ticks;
    let (reveal, reveal_digest) = host.event(
        key,
        Epoch(0),
        EventBody::Reveal {
            task,
            host_salt: [0; 32],
        },
    );
    receiver.admit(&mut session, &reveal, 1).unwrap();
    vector.record("reveal", &reveal, reveal_digest);
    let (seal, seal_event, checkpoint) = host.seal(&session, 0, ticks, vec![reveal_digest]);
    let receipt = final_receipt(&session, &seal_event);
    let verified = receiver.admit(&mut session, &seal, 2).unwrap().unwrap();
    assert_eq!(verified.hash(), checkpoint.hash());
    assert!(verified.is_final());
    vector.seal(&seal, seal_event.digest(), &checkpoint, true);
    vector.write(dir, "game-v1-session-replay.txt", &receipt);
}

/// A live manifest over the `opening-normal` world: the single cell is an open
/// slot the player binds.
fn live_manifest(converted: &Converted) -> (GameManifest, TaskManifest) {
    let mut template = TaskManifest {
        world: converted.task.world.clone(),
        slots: converted
            .programs
            .iter()
            .map(|(cell, _)| ProgramSlot {
                cell: *cell,
                fixed: None,
            })
            .collect(),
        cases: {
            let mut case = converted.task.cases[0].clone();
            case.seed = 0;
            case.events.clear();
            vec![case]
        },
        contract: WorkContract {
            useful_floor: 0,
            total_ceiling: converted.task.cases[0].fuel,
            require_passed: false,
        },
    };
    let template_len = codec::encode_manifest(&template).len() as u64;
    let max_events = 64;
    template.cases[0].loading_work = template_len + u64::from(max_events) * INPUT_ENCODED_BYTES;
    let valid = ValidManifest::validate(template.clone()).unwrap();
    let manifest = GameManifest {
        ruleset: RulesetId::V1,
        world: valid.hash(),
        slots: converted
            .programs
            .iter()
            .map(|(cell, _)| GameSlot {
                cell: *cell,
                role: SlotRole::Open { fallback: None },
            })
            .collect(),
        contract: template.contract,
        loading_work: vec![template.cases[0].loading_work],
        artifacts: Vec::new(),
        limits: SessionLimits {
            max_events,
            max_segments: 8,
            replay: WorkAllowance {
                max_total: valid.fuel_total(),
            },
            verification: VerificationAllowance {
                max_replays: 64,
                max_work: u64::MAX,
                max_event_bytes: 64 * 24_576,
                max_artifact_bytes: MAX_ARTIFACT_BYTES,
            },
            missing_member: MissingMember::Pause,
            kind: SessionKind::Live,
        },
        publisher: PUBLISHER,
    };
    (manifest, template)
}

/// The `Live` session: commit, close, reveal the bind, reveal the task, one
/// input, a mid-tick seal, a second input, the final seal.
fn live_vector(dir: &Path, converted: &Converted) {
    let mut host = Signer::new(HOST_SEED);
    let mut player = Signer::new(PLAYER_SEED);
    let (manifest, template) = live_manifest(converted);
    let slot = converted.programs[0].0;
    let program = converted.programs[0].1.clone();
    let open = SessionOpen {
        realm: REALM,
        room: ROOM,
        manifest: manifest.hash(),
        ruleset: RulesetId::V1,
        seed_commitment: seed_commitment(&HOST_SALT, manifest.world),
        authority: Authority::Host { key: host.public() },
        players: vec![Player {
            key: player.public(),
            slots: vec![slot],
        }],
        epoch: Epoch(0),
        nonce: NONCE,
    };
    let mut vector = Vector::new(
        "game-v1-session-live",
        "live",
        "opening-normal",
        &manifest,
        &open,
    );
    let mut session = Session::open(manifest, open, REALM).unwrap();
    let mut receiver = Receiver::new(PlatonikV1, policy());
    let key = session.key();
    let commit = bind_commit(key, slot, &program, &PLAYER_SALT);
    let (bind, bind_digest) = player.event(key, Epoch(0), EventBody::BindCommit { slot, commit });
    receiver.admit(&mut session, &bind, 1).unwrap();
    vector.record("bind_commit", &bind, bind_digest);
    let (close, close_digest) = host.event(
        key,
        Epoch(0),
        EventBody::BindClose {
            commits: vec![(slot, commit)],
        },
    );
    receiver.admit(&mut session, &close, 2).unwrap();
    vector.record("bind_close", &close, close_digest);
    let (reveal_bind, reveal_bind_digest) = player.event(
        key,
        Epoch(0),
        EventBody::BindReveal {
            slot,
            program,
            salt: PLAYER_SALT,
        },
    );
    receiver.admit(&mut session, &reveal_bind, 3).unwrap();
    vector.record("bind_reveal", &reveal_bind, reveal_bind_digest);
    let mut task = template;
    task.cases[0].seed = derive_seed(&HOST_SALT, &[PLAYER_SALT], 0);
    let ticks = task.cases[0].ticks;
    let (reveal, reveal_digest) = host.event(
        key,
        Epoch(0),
        EventBody::Reveal {
            task,
            host_salt: HOST_SALT,
        },
    );
    receiver.admit(&mut session, &reveal, 4).unwrap();
    vector.record("reveal", &reveal, reveal_digest);
    let (input_a, input_a_digest) = player.event(
        key,
        Epoch(0),
        EventBody::Input {
            case: 0,
            tick: 3,
            kind: EventKind::ClearMemory { cell: slot },
        },
    );
    receiver.admit(&mut session, &input_a, 5).unwrap();
    vector.record("input", &input_a, input_a_digest);
    let mid = ticks / 2;
    let (seal_0, seal_0_event, checkpoint_0) = host.seal(
        &session,
        0,
        mid,
        vec![
            bind_digest,
            close_digest,
            reveal_bind_digest,
            reveal_digest,
            input_a_digest,
        ],
    );
    let verified_0 = receiver.admit(&mut session, &seal_0, 6).unwrap().unwrap();
    assert_eq!(verified_0.hash(), checkpoint_0.hash());
    assert!(!verified_0.is_final());
    vector.seal(&seal_0, seal_0_event.digest(), &checkpoint_0, false);
    let (input_b, input_b_digest) = player.event(
        key,
        Epoch(0),
        EventBody::Input {
            case: 0,
            tick: mid + 1,
            kind: EventKind::ClearMemory { cell: slot },
        },
    );
    receiver.admit(&mut session, &input_b, 7).unwrap();
    vector.record("input", &input_b, input_b_digest);
    let (seal_1, seal_1_event, checkpoint_1) = host.seal(&session, 1, ticks, vec![input_b_digest]);
    let receipt = final_receipt(&session, &seal_1_event);
    let verified_1 = receiver.admit(&mut session, &seal_1, 8).unwrap().unwrap();
    assert_eq!(verified_1.hash(), checkpoint_1.hash());
    assert!(verified_1.is_final());
    vector.seal(&seal_1, seal_1_event.digest(), &checkpoint_1, true);
    vector.write(dir, "game-v1-session-live.txt", &receipt);
}

fn main() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
    fs::create_dir_all(&dir).unwrap();
    let converted =
        convert(&platonik_core::fixtures::experiment("opening-normal").unwrap()).unwrap();
    replay_vector(&dir, &converted);
    live_vector(&dir, &converted);
}
