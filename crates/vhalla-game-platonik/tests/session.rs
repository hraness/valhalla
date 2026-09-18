//! End to end at one receiver: a `Replay` session of a fixture, a `Live`
//! session with the two-phase bind, inputs, two seals, a prefix check, and
//! the rejection paths.

use ed25519_dalek::SigningKey;
use vhalla_core::{Epoch, RealmId, RoomId, Sequence};
use vhalla_game_platonik::ids::{CheckpointHash, GameEventDigest, RulesetId, SessionKey};
use vhalla_game_platonik::manifest::{
    GameManifest, GameSlot, MissingMember, SessionKind, SessionLimits, SlotRole,
    VerificationAllowance, MAX_ARTIFACT_BYTES,
};
use vhalla_game_platonik::oracle::convert::convert;
use vhalla_game_platonik::oracle::corpus::replay_manifest;
use vhalla_game_platonik::platonik::PlatonikV1;
use vhalla_game_platonik::receiver::{Receiver, ReceiverError, ReceiverPolicy};
use vhalla_game_platonik::record::{GameRecord, RecordKind};
use vhalla_game_platonik::session::{
    bind_commit, derive_seed, seed_commitment, template_of, Rejection, Session, State,
    INPUT_ENCODED_BYTES,
};
use vhalla_game_platonik::wire::{
    encode_game_event, Authority, EventBody, ForkReason, GameEvent, Player, SessionOpen,
};
use vhalla_witness::bounds::MAX_EVENTS;
use vhalla_witness::codec;
use vhalla_witness::manifest::{ProgramSlot, TaskManifest, ValidManifest, WorkContract};
use vhalla_witness::platform::WorkAllowance;
use vhalla_witness::world::EventKind;

const REALM: RealmId = RealmId(3);
const ROOM: RoomId = RoomId(4);

struct Signer {
    key: SigningKey,
    sequence: u64,
}

impl Signer {
    fn new(seed: u8) -> Self {
        Self {
            key: SigningKey::from_bytes(&[seed; 32]),
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
    fn sign(&mut self, event: GameEvent) -> (GameRecord, GameEventDigest) {
        self.sequence += 1;
        let digest = event.digest();
        let record = GameRecord::sign(
            RecordKind::Event,
            event.session,
            encode_game_event(&event),
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
        self.sign(event)
    }
    /// An honest host's seal: plan it against the receiver-visible session,
    /// derive the checkpoint the way a receiver does, then sign it.
    fn seal(
        &mut self,
        session: &Session,
        segment: u8,
        through_tick: u32,
        order: Vec<GameEventDigest>,
    ) -> (GameRecord, CheckpointHash) {
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
        let checkpoint = scratch.derive(session, &plan).unwrap().hash();
        let event = self.unsigned(
            session.key(),
            session.epoch(),
            EventBody::Seal {
                segment,
                through_tick,
                order,
                checkpoint,
            },
        );
        let (record, _) = self.sign(event);
        (record, checkpoint)
    }
}

fn policy() -> ReceiverPolicy {
    ReceiverPolicy {
        max_replays: 64,
        max_work: u64::MAX,
        max_steps: u64::MAX,
    }
}

fn passed_by_plain_run(
    task: &TaskManifest,
    candidate: Vec<(u16, vhalla_witness::model::Program)>,
) -> bool {
    let valid = ValidManifest::validate(task.clone()).unwrap();
    let assignment = valid.assign(candidate).unwrap();
    let program = vhalla_witness::hash::ProgramHash::of(&codec::encode_assignment(&assignment));
    #[allow(clippy::disallowed_methods)]
    let cap = vhalla_witness::platform::RunCapability::mint(
        valid.hash(),
        program,
        WorkAllowance {
            max_total: valid.fuel_total(),
        },
        vhalla_witness::platform::RunRole::Replay,
    );
    vhalla_witness::platform::run(&valid, &assignment, cap)
        .unwrap()
        .passed()
}

#[test]
fn a_replay_session_of_a_fixture_seals_once_and_finishes() {
    let mut host = Signer::new(1);
    let converted =
        convert(&platonik_core::fixtures::experiment("opening-normal").unwrap()).unwrap();
    let manifest = replay_manifest(&converted, [11; 32]);
    let open = SessionOpen {
        realm: REALM,
        room: ROOM,
        manifest: manifest.hash(),
        ruleset: RulesetId::V1,
        seed_commitment: [0; 32],
        authority: Authority::Host { key: host.public() },
        players: Vec::new(),
        epoch: Epoch(0),
        nonce: [5; 32],
    };
    let mut session = Session::open(manifest.clone(), open, REALM).unwrap();
    assert_eq!(session.state(), State::Opened);
    let mut receiver = Receiver::new(PlatonikV1, policy());
    // The replay task: the fixed template with the experiment's real seed and events.
    let mut task = converted.template.clone();
    task.cases[0].seed = converted.task.cases[0].seed;
    task.cases[0].events = converted.task.cases[0].events.clone();
    let (reveal, reveal_digest) = host.event(
        session.key(),
        Epoch(0),
        EventBody::Reveal {
            task: task.clone(),
            host_salt: [0; 32],
        },
    );
    assert!(receiver.admit(&mut session, &reveal, 1).unwrap().is_none());
    assert_eq!(session.state(), State::Revealed);
    assert_eq!(
        receiver.admit(&mut session, &reveal, 2).err(),
        Some(ReceiverError::Session(Rejection::Duplicate))
    );
    let ticks = task.cases[0].ticks;
    // A lying host: a seal naming a checkpoint the receiver cannot reproduce.
    {
        let mut probe = Session::open(manifest.clone(), session.opening().clone(), REALM).unwrap();
        let mut probe_receiver = Receiver::new(PlatonikV1, policy());
        probe_receiver.admit(&mut probe, &reveal, 1).unwrap();
        let mut liar = Signer {
            key: host.key.clone(),
            sequence: host.sequence,
        };
        let (bad, _) = liar.event(
            session.key(),
            Epoch(0),
            EventBody::Seal {
                segment: 0,
                through_tick: ticks,
                order: vec![reveal_digest],
                checkpoint: CheckpointHash([9; 32]),
            },
        );
        assert_eq!(
            probe_receiver.admit(&mut probe, &bad, 2).err(),
            Some(ReceiverError::Session(Rejection::ReplayMismatch))
        );
        assert_eq!(probe.state(), State::Unresolved(ForkReason::ReplayMismatch));
        assert_eq!(
            probe.retained().len(),
            1,
            "the seal is retained as evidence"
        );
    }
    // An honest host.
    let (seal, expected) = host.seal(&session, 0, ticks, vec![reveal_digest]);
    let verified = receiver.admit(&mut session, &seal, 3).unwrap().unwrap();
    assert_eq!(verified.hash(), expected);
    assert!(verified.is_final());
    assert_eq!(verified.passed(), passed_by_plain_run(&task, Vec::new()));
    assert_eq!(session.state(), State::Finished);
    assert_eq!(
        session.ledger().height(),
        1,
        "genesis plus the one sealed event"
    );
    assert_eq!(session.pending(), 0);
    assert_eq!(receiver.replays_left(session.key()), Some(7));
    // Nothing is admissible after the final seal.
    let (late, _) = host.event(
        session.key(),
        Epoch(0),
        EventBody::Reveal {
            task,
            host_salt: [0; 32],
        },
    );
    assert_eq!(
        receiver.admit(&mut session, &late, 4).err(),
        Some(ReceiverError::Session(Rejection::Terminal))
    );
}

/// A live manifest over the opening-normal world: the single cell is an open
/// slot the player binds.
fn live_manifest(
    converted: &vhalla_game_platonik::oracle::convert::Converted,
    publisher: [u8; 32],
) -> (GameManifest, TaskManifest) {
    let template = TaskManifest {
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
    let mut template = template;
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
        publisher,
    };
    (manifest, template)
}

#[test]
fn a_live_session_binds_reveals_inputs_and_seals_twice() {
    let mut host = Signer::new(1);
    let mut player = Signer::new(2);
    let converted =
        convert(&platonik_core::fixtures::experiment("opening-normal").unwrap()).unwrap();
    let (manifest, template) = live_manifest(&converted, [11; 32]);
    let slot = converted.programs[0].0;
    let program = converted.programs[0].1.clone();
    let host_salt = [7; 32];
    let open = SessionOpen {
        realm: REALM,
        room: ROOM,
        manifest: manifest.hash(),
        ruleset: RulesetId::V1,
        seed_commitment: seed_commitment(&host_salt, manifest.world),
        authority: Authority::Host { key: host.public() },
        players: vec![Player {
            key: player.public(),
            slots: vec![slot],
        }],
        epoch: Epoch(0),
        nonce: [5; 32],
    };
    let mut session = Session::open(manifest.clone(), open, REALM).unwrap();
    let mut receiver = Receiver::new(PlatonikV1, policy());
    let key = session.key();
    // A reveal before any close is refused; a bind from the host is refused.
    let salt = [3; 32];
    let commit = bind_commit(key, slot, &program, &salt);
    let (host_bind, _) = host.event(key, Epoch(0), EventBody::BindCommit { slot, commit });
    assert_eq!(
        receiver.admit(&mut session, &host_bind, 1).err(),
        Some(ReceiverError::Session(Rejection::NotPlayer))
    );
    let (early_reveal, _) = player.event(
        key,
        Epoch(0),
        EventBody::BindReveal {
            slot,
            program: program.clone(),
            salt,
        },
    );
    assert_eq!(
        receiver.admit(&mut session, &early_reveal, 2).err(),
        Some(ReceiverError::Session(Rejection::RevealBeforeClose))
    );
    // Commit, close, reveal.
    let (bind, bind_digest) = player.event(key, Epoch(0), EventBody::BindCommit { slot, commit });
    receiver.admit(&mut session, &bind, 3).unwrap();
    assert_eq!(session.state(), State::Binding);
    let (close, close_digest) = host.event(
        key,
        Epoch(0),
        EventBody::BindClose {
            commits: vec![(slot, commit)],
        },
    );
    receiver.admit(&mut session, &close, 4).unwrap();
    let (late_commit, _) = player.event(key, Epoch(0), EventBody::BindCommit { slot, commit });
    assert_eq!(
        receiver.admit(&mut session, &late_commit, 5).err(),
        Some(ReceiverError::Session(Rejection::BindAfterClose))
    );
    let (wrong_salt, _) = player.event(
        key,
        Epoch(0),
        EventBody::BindReveal {
            slot,
            program: program.clone(),
            salt: [4; 32],
        },
    );
    assert_eq!(
        receiver.admit(&mut session, &wrong_salt, 6).err(),
        Some(ReceiverError::Session(Rejection::CommitMismatch))
    );
    let (reveal_bind, reveal_bind_digest) = player.event(
        key,
        Epoch(0),
        EventBody::BindReveal {
            slot,
            program: program.clone(),
            salt,
        },
    );
    receiver.admit(&mut session, &reveal_bind, 7).unwrap();
    // The host reveals the task with the derived seed.
    let mut task = template.clone();
    task.cases[0].seed = derive_seed(&host_salt, &[salt], 0);
    let mut wrong_seed = task.clone();
    wrong_seed.cases[0].seed ^= 1;
    let (bad_reveal, _) = host.event(
        key,
        Epoch(0),
        EventBody::Reveal {
            task: wrong_seed,
            host_salt,
        },
    );
    assert_eq!(
        receiver.admit(&mut session, &bad_reveal, 8).err(),
        Some(ReceiverError::Session(Rejection::RevealMismatch))
    );
    let (reveal, reveal_digest) = host.event(
        key,
        Epoch(0),
        EventBody::Reveal {
            task: task.clone(),
            host_salt,
        },
    );
    receiver.admit(&mut session, &reveal, 9).unwrap();
    assert_eq!(session.state(), State::Revealed);
    assert_eq!(template_of(&task), template);
    // Inputs: a stale tick is refused later; a clear-memory on the own cell is admitted.
    let ticks = task.cases[0].ticks;
    let (input_a, input_a_digest) = player.event(
        key,
        Epoch(0),
        EventBody::Input {
            case: 0,
            tick: 3,
            kind: EventKind::ClearMemory { cell: slot },
        },
    );
    receiver.admit(&mut session, &input_a, 10).unwrap();
    let (beyond, _) = player.event(
        key,
        Epoch(0),
        EventBody::Input {
            case: 0,
            tick: ticks + 1,
            kind: EventKind::ClearMemory { cell: slot },
        },
    );
    assert_eq!(
        receiver.admit(&mut session, &beyond, 11).err(),
        Some(ReceiverError::Session(Rejection::TickBeyondHorizon))
    );
    // Seal segment 0 at a mid tick with every admitted event in order.
    let mid = ticks / 2;
    let order = vec![
        bind_digest,
        close_digest,
        reveal_bind_digest,
        reveal_digest,
        input_a_digest,
    ];
    let (seal_0, checkpoint_0) = host.seal(&session, 0, mid, order.clone());
    let verified_0 = receiver.admit(&mut session, &seal_0, 12).unwrap().unwrap();
    assert_eq!(verified_0.hash(), checkpoint_0);
    assert!(!verified_0.is_final());
    assert_eq!(session.state(), State::Running(1));
    assert_eq!(
        session.ledger().height(),
        order.len() as u64 + 1,
        "|order_1| plus the Seal event"
    );
    // An exact resend of the committed seal is a duplicate, a seal for a
    // segment this session has not reached is refused on its index, and an
    // input at or below the sealed tick is stale. A second, different seal
    // for the committed segment is a fork; `spike5` drives that one.
    assert_eq!(
        receiver.admit(&mut session, &seal_0, 13).err(),
        Some(ReceiverError::Session(Rejection::Duplicate))
    );
    let (ahead, _) = host.event(
        key,
        Epoch(0),
        EventBody::Seal {
            segment: 3,
            through_tick: mid + 1,
            order,
            checkpoint: checkpoint_0,
        },
    );
    assert_eq!(
        receiver.admit(&mut session, &ahead, 13).err(),
        Some(ReceiverError::Session(Rejection::SealSegment))
    );
    let (stale, _) = player.event(
        key,
        Epoch(0),
        EventBody::Input {
            case: 0,
            tick: mid,
            kind: EventKind::ClearMemory { cell: slot },
        },
    );
    assert_eq!(
        receiver.admit(&mut session, &stale, 14).err(),
        Some(ReceiverError::Session(Rejection::StaleTick))
    );
    let (input_b, input_b_digest) = player.event(
        key,
        Epoch(0),
        EventBody::Input {
            case: 0,
            tick: mid + 1,
            kind: EventKind::ClearMemory { cell: slot },
        },
    );
    receiver.admit(&mut session, &input_b, 15).unwrap();
    // The final seal: the prefix check re-replays at the previous tick with
    // the new input declared and must reproduce checkpoint 0's fields with the
    // ledger offset of one.
    let (seal_1, checkpoint_1) = host.seal(&session, 1, ticks, vec![input_b_digest]);
    let verified_1 = receiver.admit(&mut session, &seal_1, 16).unwrap().unwrap();
    assert_eq!(verified_1.hash(), checkpoint_1);
    assert!(verified_1.is_final());
    assert_eq!(session.state(), State::Finished);
    assert_eq!(
        session.ledger().height(),
        5 + 1 + 1,
        "|order_1| + 1 + |order_2|"
    );
    let mut full = task.clone();
    full.cases[0].events = vec![
        vhalla_witness::world::Event {
            tick: 3,
            event: EventKind::ClearMemory { cell: slot },
        },
        vhalla_witness::world::Event {
            tick: mid + 1,
            event: EventKind::ClearMemory { cell: slot },
        },
    ];
    assert_eq!(
        verified_1.passed(),
        passed_by_plain_run(&full, vec![(slot, program)])
    );
    assert_eq!(
        receiver.replays_left(key),
        Some(64 - 3),
        "two seals, one prefix re-check"
    );
    let _ = MAX_EVENTS;
}

#[test]
fn equivocation_freezes_the_author_and_a_seal_admitting_it_is_refused() {
    let mut host = Signer::new(1);
    let converted =
        convert(&platonik_core::fixtures::experiment("opening-normal").unwrap()).unwrap();
    let manifest = replay_manifest(&converted, [11; 32]);
    let open = SessionOpen {
        realm: REALM,
        room: ROOM,
        manifest: manifest.hash(),
        ruleset: RulesetId::V1,
        seed_commitment: [0; 32],
        authority: Authority::Host { key: host.public() },
        players: Vec::new(),
        epoch: Epoch(0),
        nonce: [5; 32],
    };
    let mut session = Session::open(manifest, open, REALM).unwrap();
    let key = session.key();
    let mut task = converted.template.clone();
    task.cases[0].seed = converted.task.cases[0].seed;
    task.cases[0].events = converted.task.cases[0].events.clone();
    let (reveal, reveal_digest) = host.event(
        key,
        Epoch(0),
        EventBody::Reveal {
            task: task.clone(),
            host_salt: [0; 32],
        },
    );
    assert!(session.admit(&reveal).is_ok());
    // A second, different event at the same host sequence.
    let mut twin = Signer {
        key: host.key.clone(),
        sequence: host.sequence - 1,
    };
    let (other, _) = twin.event(
        key,
        Epoch(0),
        EventBody::Reveal {
            task,
            host_salt: [1; 32],
        },
    );
    assert_eq!(session.admit(&other).err(), Some(Rejection::Equivocation));
    assert_eq!(session.retained().len(), 2, "both digests retained");
    let ticks = converted.task.cases[0].ticks;
    let (seal, _) = host.event(
        key,
        Epoch(0),
        EventBody::Seal {
            segment: 0,
            through_tick: ticks,
            order: vec![reveal_digest],
            checkpoint: CheckpointHash([0; 32]),
        },
    );
    assert_eq!(
        session.admit(&seal).err(),
        Some(Rejection::Frozen),
        "the frozen author cannot even seal"
    );
}
