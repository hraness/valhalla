//! Spike 5, the state-machine schedule: does `Seal.order` survive a lossy
//! relay and a partition without unbounded buffering, and is every host fork
//! detected once both seals are seen?
//!
//! Live sessions of the `opening-normal` fixture (one player) and the
//! `ark-plan-a` fixture (two players, links and a valve) are driven through a
//! relay that drops, duplicates, reorders, and partitions delivery to two
//! receivers, and then resends the whole log. A seeded generator drives the
//! schedule so every run is reproducible from its seed alone.
//!
//! The relay reorders freely across authors and holds a record whose
//! per-author sequence is ahead of what that receiver has seen, the way a
//! per-stream ordered transport does. That is a requirement the claim table
//! places on the transport rather than a weakness of the schedule: the
//! per-author sequence is strictly increasing, so admitting a later record
//! first makes the earlier one permanently inadmissible at that receiver, and
//! the last test here pins that boundary.

use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use vhalla_core::{Epoch, RealmId, RoomId, Sequence};
use vhalla_game_platonik::ids::{CheckpointHash, GameEventDigest, RulesetId, SessionKey};
use vhalla_game_platonik::manifest::{
    GameManifest, GameSlot, MissingMember, SessionKind, SessionLimits, SlotRole,
    VerificationAllowance, MAX_ARTIFACT_BYTES,
};
use vhalla_game_platonik::oracle::convert::convert;
use vhalla_game_platonik::platonik::PlatonikV1;
use vhalla_game_platonik::receiver::{Receiver, ReceiverError, ReceiverPolicy};
use vhalla_game_platonik::record::{GameRecord, RecordKind};
use vhalla_game_platonik::session::{
    bind_commit, derive_seed, seed_commitment, Rejection, Session, State, INPUT_ENCODED_BYTES,
    MAX_PENDING, MAX_PENDING_PER_AUTHOR,
};
use vhalla_game_platonik::wire::{
    encode_game_event, Authority, EventBody, ForkReason, GameEvent, Player, SessionOpen,
    MAX_PLAYERS,
};
use vhalla_witness::bounds::MAX_EVENTS;
use vhalla_witness::codec;
use vhalla_witness::manifest::{ProgramSlot, TaskManifest, ValidManifest, WorkContract};
use vhalla_witness::model::Program;
use vhalla_witness::platform::WorkAllowance;
use vhalla_witness::world::EventKind;

const REALM: RealmId = RealmId(3);
const ROOM: RoomId = RoomId(4);
/// Session limit on admitted events. It is the live loading rule's multiplier
/// and, through `SessionLedger::bound`, the per-epoch ledger capacity: a
/// session that seals sixty-four inputs for one case plus its binds, reveals,
/// and seals needs more room than sixty-four.
const MAX_SESSION_EVENTS: u32 = 128;

// ---------------------------------------------------------------- generator

/// A seeded xorshift generator: every schedule is reproducible from its seed.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound.max(1)
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

// ------------------------------------------------------------------ signing

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
    fn sign(&mut self, event: GameEvent) -> Produced {
        self.sequence += 1;
        let digest = event.digest();
        let record = GameRecord::sign(
            RecordKind::Event,
            event.session,
            encode_game_event(&event),
            &self.key,
        )
        .unwrap();
        Produced {
            record,
            digest,
            author: event.author,
            sequence: event.sequence.0,
        }
    }
    fn event(&mut self, session: SessionKey, epoch: Epoch, body: EventBody) -> Produced {
        let event = self.unsigned(session, epoch, body);
        self.sign(event)
    }
    /// An honest host's seal: plan it against the host's own session, derive
    /// the checkpoint the way a receiver does, then sign it.
    fn seal(
        &mut self,
        session: &Session,
        segment: u8,
        through_tick: u32,
        order: Vec<GameEventDigest>,
    ) -> Produced {
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
        self.sign(event)
    }
}

/// One signed record with what the relay needs to order it.
#[derive(Clone)]
struct Produced {
    record: GameRecord,
    digest: GameEventDigest,
    author: [u8; 32],
    sequence: u64,
}

fn policy() -> ReceiverPolicy {
    ReceiverPolicy {
        max_replays: 64,
        max_work: u64::MAX,
        max_steps: u64::MAX,
    }
}

// -------------------------------------------------------------- live worlds

/// A live game over a converted fixture: every world cell is an open slot.
struct Live {
    manifest: GameManifest,
    template: TaskManifest,
    programs: Vec<(u16, Program)>,
    links: Vec<u16>,
    valves: Vec<u16>,
    ticks: u32,
}

fn live(fixture: &str, fuel: Option<u64>) -> Live {
    let converted = convert(&platonik_core::fixtures::experiment(fixture).unwrap()).unwrap();
    let mut case = converted.task.cases[0].clone();
    case.seed = 0;
    case.events.clear();
    if let Some(fuel) = fuel {
        case.fuel = fuel;
    }
    let contract = WorkContract {
        useful_floor: 0,
        total_ceiling: case.fuel,
        require_passed: false,
    };
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
        cases: vec![case],
        contract,
    };
    let template_len = codec::encode_manifest(&template).len() as u64;
    template.cases[0].loading_work =
        template_len + u64::from(MAX_SESSION_EVENTS) * INPUT_ENCODED_BYTES;
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
        contract,
        loading_work: vec![template.cases[0].loading_work],
        artifacts: Vec::new(),
        limits: SessionLimits {
            max_events: MAX_SESSION_EVENTS,
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
        publisher: [11; 32],
    };
    Live {
        manifest,
        template,
        links: converted.task.world.links.iter().map(|l| l.id).collect(),
        valves: converted.task.world.valves.iter().map(|v| v.id).collect(),
        ticks: converted.task.cases[0].ticks,
        programs: converted.programs,
    }
}

// --------------------------------------------------------------------- game

/// The host's own view: it admits everything it produces, in production
/// order, and commits its own seals through its own receiver.
struct Game {
    host: Signer,
    players: Vec<Signer>,
    /// Slots each player owns, in the order it binds them.
    owned: Vec<Vec<u16>>,
    live: Live,
    host_salt: [u8; 32],
    session: Session,
    receiver: Receiver<PlatonikV1>,
    step: u64,
    log: Vec<Produced>,
    unsealed: Vec<GameEventDigest>,
    key: SessionKey,
}

impl Game {
    fn open(live: Live, players: usize) -> Self {
        let host = Signer::new(1);
        let players: Vec<Signer> = (0..players).map(|i| Signer::new(2 + i as u8)).collect();
        let host_salt = [7; 32];
        let mut owned: Vec<Vec<u16>> = vec![Vec::new(); players.len()];
        for (index, (cell, _)) in live.programs.iter().enumerate() {
            owned[index % players.len()].push(*cell);
        }
        let open = SessionOpen {
            realm: REALM,
            room: ROOM,
            manifest: live.manifest.hash(),
            ruleset: RulesetId::V1,
            seed_commitment: seed_commitment(&host_salt, live.manifest.world),
            authority: Authority::Host { key: host.public() },
            players: players
                .iter()
                .zip(&owned)
                .map(|(player, slots)| Player {
                    key: player.public(),
                    slots: slots.clone(),
                })
                .collect(),
            epoch: Epoch(0),
            nonce: [5; 32],
        };
        let session = Session::open(live.manifest.clone(), open, REALM).unwrap();
        let key = session.key();
        Self {
            host,
            players,
            owned,
            live,
            host_salt,
            session,
            receiver: Receiver::new(PlatonikV1, policy()),
            step: 0,
            log: Vec::new(),
            unsealed: Vec::new(),
            key,
        }
    }
    /// Admits a produced record into the host's own session and logs it.
    fn keep(&mut self, produced: Produced) -> Produced {
        self.step += 1;
        self.receiver
            .admit(&mut self.session, &produced.record, self.step)
            .unwrap_or_else(|error| panic!("the host admits its own record: {error:?}"));
        self.log.push(produced.clone());
        produced
    }
    fn emit_player(&mut self, player: usize, body: EventBody) -> Produced {
        let produced = self.players[player].event(self.key, self.session.epoch(), body);
        let produced = self.keep(produced);
        self.unsealed.push(produced.digest);
        produced
    }
    fn emit_host(&mut self, body: EventBody) -> Produced {
        let produced = self.host.event(self.key, self.session.epoch(), body);
        let produced = self.keep(produced);
        self.unsealed.push(produced.digest);
        produced
    }
    /// The bind, close, reveal opening every live session shares.
    fn open_and_reveal(&mut self) {
        let mut salts: Vec<(u16, [u8; 32])> = Vec::new();
        for player in 0..self.players.len() {
            for slot_index in 0..self.owned[player].len() {
                let slot = self.owned[player][slot_index];
                let salt = [(slot as u8).wrapping_add(0x40); 32];
                let program = self.program_of(slot);
                let commit = bind_commit(self.key, slot, &program, &salt);
                self.emit_player(player, EventBody::BindCommit { slot, commit });
                salts.push((slot, salt));
            }
        }
        salts.sort_by_key(|(slot, _)| *slot);
        let commits: Vec<(u16, [u8; 32])> = salts
            .iter()
            .map(|(slot, salt)| {
                let program = self.program_of(*slot);
                (*slot, bind_commit(self.key, *slot, &program, salt))
            })
            .collect();
        self.emit_host(EventBody::BindClose { commits });
        for player in 0..self.players.len() {
            for slot_index in 0..self.owned[player].len() {
                let slot = self.owned[player][slot_index];
                let salt = salts.iter().find(|(s, _)| *s == slot).unwrap().1;
                let program = self.program_of(slot);
                self.emit_player(
                    player,
                    EventBody::BindReveal {
                        slot,
                        program,
                        salt,
                    },
                );
            }
        }
        let slot_salts: Vec<[u8; 32]> = salts.iter().map(|(_, salt)| *salt).collect();
        let mut task = self.live.template.clone();
        for (index, case) in task.cases.iter_mut().enumerate() {
            case.seed = derive_seed(&self.host_salt, &slot_salts, index as u8);
        }
        self.emit_host(EventBody::Reveal {
            task,
            host_salt: self.host_salt,
        });
    }
    fn program_of(&self, slot: u16) -> Program {
        self.live
            .programs
            .iter()
            .find(|(cell, _)| *cell == slot)
            .unwrap()
            .1
            .clone()
    }
    /// One world input for case 0 from a player that may sign it.
    fn input_body(&self, player: usize, rng: &mut Rng, tick: u32) -> EventBody {
        let mut choices: Vec<EventKind> = self.owned[player]
            .iter()
            .map(|cell| EventKind::ClearMemory { cell: *cell })
            .collect();
        for id in &self.live.links {
            choices.push(EventKind::LinkEnabled {
                id: *id,
                enabled: rng.chance(50),
            });
        }
        for id in &self.live.valves {
            choices.push(EventKind::ValveEnabled {
                id: *id,
                enabled: rng.chance(50),
            });
        }
        let kind = choices[rng.below(choices.len() as u64) as usize];
        EventBody::Input {
            case: 0,
            tick,
            kind,
        }
    }
    fn seal(&mut self, segment: u8, through_tick: u32) -> Produced {
        let order = std::mem::take(&mut self.unsealed);
        let produced = self.host.seal(&self.session, segment, through_tick, order);
        self.keep(produced)
    }
}

// -------------------------------------------------------------------- relay

/// One receiver behind the relay.
struct Node {
    session: Session,
    receiver: Receiver<PlatonikV1>,
    step: u64,
    /// Indices into the log waiting to be delivered.
    queue: Vec<usize>,
    /// Highest per-author sequence this node has been handed.
    handed: BTreeMap<[u8; 32], u64>,
    /// Rounds this node stays partitioned for.
    partition: u32,
    /// Segment to the checkpoint this node accepted for it.
    accepted: BTreeMap<u8, CheckpointHash>,
    /// Every rejection this node answered with.
    rejections: Vec<Rejection>,
}

impl Node {
    fn new(manifest: &GameManifest, open: &SessionOpen) -> Self {
        Self {
            session: Session::open(manifest.clone(), open.clone(), REALM).unwrap(),
            receiver: Receiver::new(PlatonikV1, policy()),
            step: 0,
            queue: Vec::new(),
            handed: BTreeMap::new(),
            partition: 0,
            accepted: BTreeMap::new(),
            rejections: Vec::new(),
        }
    }
    /// Delivers one record and reports whether the session took it, which is
    /// what lets the relay advance that author's stream.
    fn deliver(&mut self, produced: &Produced) -> bool {
        self.step += 1;
        let outcome = self
            .receiver
            .admit(&mut self.session, &produced.record, self.step);
        let admitted = match outcome {
            Ok(Some(verified)) => {
                let previous = self.accepted.insert(verified.segment(), verified.hash());
                assert!(
                    previous.is_none(),
                    "no receiver accepts two checkpoints for one segment"
                );
                true
            }
            Ok(None) => true,
            Err(ReceiverError::Session(rejection)) => {
                self.rejections.push(rejection);
                rejection == Rejection::Duplicate
            }
            Err(error) => panic!("an honest schedule never refuses with {error:?}"),
        };
        if admitted {
            let handed = self.handed.entry(produced.author).or_insert(0);
            *handed = (*handed).max(produced.sequence);
        }
        admitted
    }
    /// Whether this node's transport would release the record now: a record
    /// is held while an earlier one from the same author has not been taken.
    /// The claim table's strictly increasing sequence is why the transport
    /// may not run ahead of it.
    fn releasable(&self, produced: &Produced) -> bool {
        produced.sequence <= self.handed.get(&produced.author).copied().unwrap_or(0) + 1
    }
}

/// Offers one record to a node: lost, delivered once, or duplicated.
fn offer(node: &mut Node, index: usize, rng: &mut Rng) {
    if rng.chance(20) {
        return;
    }
    node.queue.push(index);
    if rng.chance(15) {
        node.queue.push(index);
    }
}

/// One delivery round: a partitioned node receives nothing, and the rest is
/// delivered in a shuffled order that holds back out-of-order records.
fn round(node: &mut Node, log: &[Produced], rng: &mut Rng) {
    if node.partition > 0 {
        node.partition -= 1;
        return;
    }
    let mut queue = std::mem::take(&mut node.queue);
    for index in (1..queue.len()).rev() {
        queue.swap(index, rng.below(index as u64 + 1) as usize);
    }
    let mut held = Vec::new();
    for index in queue {
        if !node.releasable(&log[index]) {
            held.push(index);
            continue;
        }
        let produced = log[index].clone();
        if !node.deliver(&produced) {
            // A record the session refused on its state is retried, the way
            // a transport retries an unacknowledged record.
            held.push(index);
        }
    }
    node.queue = held;
}

/// The resend: the whole log, in production order, twice.
fn resend(node: &mut Node, log: &[Produced]) {
    for _ in 0..2 {
        for produced in log {
            node.deliver(produced);
        }
    }
}

/// Rejections an honest schedule may answer with. Everything else is a bug.
fn honest_rejection(rejection: Rejection) -> bool {
    matches!(
        rejection,
        Rejection::Duplicate
            | Rejection::Terminal
            | Rejection::WrongState
            | Rejection::SealOrderUnknown
            | Rejection::RevealBeforeClose
            | Rejection::RevealIncomplete
            | Rejection::BindCloseMismatch
            | Rejection::CommitMismatch
    )
}

// -------------------------------------------------------------- the schedule

/// What one schedule exercised, so the loop can show the schedule is not
/// vacuous.
#[derive(Default)]
struct Coverage {
    segments: usize,
    rejections: BTreeMap<String, usize>,
}

/// Drives one honest schedule and reports what it covered, once every record
/// has been resent.
fn honest_schedule(seed: u64) -> Coverage {
    let mut rng = Rng::new(seed);
    let two_players = rng.chance(50);
    let fixture = if two_players {
        "ark-plan-a"
    } else {
        "opening-normal"
    };
    let live_world = live(fixture, None);
    let ticks = live_world.ticks;
    let mut game = Game::open(live_world, if two_players { 2 } else { 1 });
    let mut nodes = [
        Node::new(game.session.manifest(), game.session.opening()),
        Node::new(game.session.manifest(), game.session.opening()),
    ];
    let mut delivered = 0;
    let segments = 2 + rng.below(3) as u8;
    game.open_and_reveal();
    let mut through = 0;
    for segment in 0..segments {
        let remaining = u32::from(segments - segment);
        let head_room = (ticks - through) / remaining;
        let next = if segment + 1 == segments {
            ticks
        } else {
            through + 1 + rng.below(u64::from(head_room.max(1))) as u32
        };
        for player in 0..game.players.len() {
            for _ in 0..rng.below(6) {
                let tick = through + 1 + rng.below(u64::from(ticks - through)) as u32;
                let body = game.input_body(player, &mut rng, tick);
                game.emit_player(player, body);
                while delivered < game.log.len() {
                    for node in &mut nodes {
                        offer(node, delivered, &mut rng);
                    }
                    delivered += 1;
                }
                for node in &mut nodes {
                    round(node, &game.log, &mut rng);
                }
            }
        }
        game.seal(segment, next);
        through = next;
        while delivered < game.log.len() {
            for node in &mut nodes {
                offer(node, delivered, &mut rng);
            }
            delivered += 1;
        }
        // A partition drops one node out for the next few rounds.
        if rng.chance(30) {
            nodes[rng.below(2) as usize].partition = 1 + rng.below(3) as u32;
        }
        for node in &mut nodes {
            round(node, &game.log, &mut rng);
        }
        agree_pairwise(&nodes, &game);
    }
    for node in &mut nodes {
        resend(node, &game.log);
    }
    agree_pairwise(&nodes, &game);
    let mut coverage = Coverage {
        segments: usize::from(segments),
        rejections: BTreeMap::new(),
    };
    for node in &nodes {
        assert_eq!(
            node.session.state(),
            State::Finished,
            "seed {seed}: every honest receiver finishes after the resend"
        );
        assert_eq!(node.session.segments(), game.session.segments());
        assert_eq!(node.accepted.len(), usize::from(segments));
        assert_eq!(node.session.pending(), 0, "every admitted event is sealed");
        assert!(node.session.retained().is_empty(), "no evidence retained");
        for rejection in &node.rejections {
            assert!(
                honest_rejection(*rejection),
                "seed {seed}: unexpected rejection {rejection:?}"
            );
            *coverage
                .rejections
                .entry(format!("{rejection:?}"))
                .or_default() += 1;
        }
    }
    assert_eq!(nodes[0].accepted, nodes[1].accepted);
    coverage
}

/// No two receivers ever hold different checkpoints for one segment, and
/// neither holds one the host did not seal.
fn agree_pairwise(nodes: &[Node; 2], game: &Game) {
    let sealed: BTreeMap<u8, CheckpointHash> = game
        .session
        .segments()
        .iter()
        .map(|(segment, _, hash)| (*segment, *hash))
        .collect();
    for node in nodes {
        for (segment, hash) in &node.accepted {
            assert_eq!(
                sealed.get(segment),
                Some(hash),
                "a receiver accepted a checkpoint for segment {segment} the host never sealed"
            );
        }
    }
    for (segment, hash) in &nodes[0].accepted {
        if let Some(other) = nodes[1].accepted.get(segment) {
            assert_eq!(hash, other, "two receivers disagree on segment {segment}");
        }
    }
}

#[test]
fn honest_schedules_converge_under_loss_reorder_duplication_and_partition() {
    let schedules = 24;
    let mut total = Coverage::default();
    for seed in 0..schedules {
        let coverage = honest_schedule(seed);
        total.segments += coverage.segments;
        for (rejection, count) in coverage.rejections {
            *total.rejections.entry(rejection).or_default() += count;
        }
    }
    println!(
        "spike5: {schedules} schedules, {} segments sealed, rejections {:?}",
        total.segments, total.rejections
    );
    for named in ["Duplicate", "SealOrderUnknown"] {
        assert!(
            total.rejections.contains_key(named),
            "the schedule never exercised {named}"
        );
    }
}

// ------------------------------------------------------------ the lying host

/// Two host-signed seals for one segment, delivered in both orders.
#[test]
fn two_seals_for_one_segment_end_both_receivers_unresolved() {
    let live_world = live("opening-normal", None);
    let ticks = live_world.ticks;
    let mut game = Game::open(live_world, 1);
    let mut nodes = [
        Node::new(game.session.manifest(), game.session.opening()),
        Node::new(game.session.manifest(), game.session.opening()),
    ];
    game.open_and_reveal();
    let body = game.input_body(0, &mut Rng::new(9), 3);
    game.emit_player(0, body);
    let prefix: Vec<Produced> = game.log.clone();
    for node in &mut nodes {
        for produced in &prefix {
            node.deliver(produced);
        }
    }
    // The host seals segment 0 twice: same order, two through ticks, so each
    // seal is admissible on its own and the two checkpoints differ.
    let order = game.unsealed.clone();
    let first = game
        .host
        .seal(&game.session, 0, ticks / 3, order.clone())
        .clone();
    let second = game.host.seal(&game.session, 0, ticks / 2, order);
    assert_ne!(first.digest, second.digest);
    assert!(
        second.sequence > first.sequence,
        "the loser of the two seals may carry either sequence"
    );
    // Receiver 0 sees the first seal first; receiver 1 sees the second first.
    nodes[0].deliver(&first);
    nodes[0].deliver(&second);
    nodes[1].deliver(&second);
    nodes[1].deliver(&first);
    for (index, node) in nodes.iter().enumerate() {
        assert_eq!(
            node.session.state(),
            State::Unresolved(ForkReason::CompetingSeals),
            "receiver {index}"
        );
        assert_eq!(
            node.rejections,
            vec![Rejection::CompetingSeals],
            "receiver {index} refuses exactly the second seal it saw"
        );
        assert_eq!(
            node.session.segments().len(),
            1,
            "neither seal is reapplied"
        );
    }
    // Both retain the same two seals, in the same order, whichever arrived
    // first, and each accepted only the one it saw first.
    let mut evidence = [first.digest.0, second.digest.0];
    evidence.sort_unstable();
    assert_eq!(nodes[0].session.retained(), evidence);
    assert_eq!(nodes[1].session.retained(), evidence);
    assert_ne!(
        nodes[0].accepted[&0], nodes[1].accepted[&0],
        "the fork is what the two receivers disagreed on, and both name it"
    );
    // Nothing further is admitted at either receiver.
    let late = game.input_body(0, &mut Rng::new(11), ticks);
    let produced = game.players[0].event(game.key, Epoch(0), late);
    for node in &mut nodes {
        node.deliver(&produced);
        assert_eq!(node.rejections.last(), Some(&Rejection::Terminal));
    }
}

/// A fork over the last segment: the seal the receiver already finished on
/// and a second seal naming a different checkpoint for it.
#[test]
fn a_second_seal_for_the_final_segment_is_a_fork_and_not_a_late_record() {
    let live_world = live("opening-normal", None);
    let ticks = live_world.ticks;
    let mut game = Game::open(live_world, 1);
    let mut node = Node::new(game.session.manifest(), game.session.opening());
    game.open_and_reveal();
    let order = game.unsealed.clone();
    let log = game.log.clone();
    for produced in &log {
        node.deliver(produced);
    }
    let first = game.seal(0, ticks);
    node.deliver(&first);
    assert_eq!(node.session.state(), State::Finished);
    // The same segment and order under a checkpoint the receiver never
    // reproduced. The fork verdict outranks the terminal state.
    let second = game.host.event(
        game.key,
        Epoch(0),
        EventBody::Seal {
            segment: 0,
            through_tick: ticks,
            order,
            checkpoint: CheckpointHash([9; 32]),
        },
    );
    node.deliver(&second);
    assert_eq!(
        node.session.state(),
        State::Unresolved(ForkReason::CompetingSeals)
    );
    assert_eq!(node.rejections, vec![Rejection::CompetingSeals]);
    let mut evidence = [first.digest.0, second.digest.0];
    evidence.sort_unstable();
    assert_eq!(node.session.retained(), evidence);
    assert_eq!(
        node.session.segments().len(),
        1,
        "the committed segment stands; history is never rewritten in place"
    );
}

// ------------------------------------------------------- the per-case cap

/// Sixty-four inputs for one case across three segments, then the sixty-fifth
/// at the gate, and a seal order that would take the case past the cap.
#[test]
fn the_case_event_cap_is_enforced_at_the_gate_and_in_the_seal_order() {
    let live_world = live("ark-plan-a", None);
    let ticks = live_world.ticks;
    let mut game = Game::open(live_world, 2);
    game.open_and_reveal();
    let mut rng = Rng::new(5);
    let mut sealed = 0_u32;
    // Segment 0 seals the opening, so every author's pending buffer is empty
    // before the inputs start.
    game.seal(0, 1);
    let mut through = 1;
    // Two more segments of thirty-two inputs, sixteen from each player: the
    // per-author pending cap is what forces the count across segments.
    for segment in 1..3_u8 {
        for player in 0..2 {
            for _ in 0..MAX_PENDING_PER_AUTHOR {
                let tick = through + 1 + rng.below(u64::from(ticks - through) - 2) as u32;
                let body = game.input_body(player, &mut rng, tick);
                game.emit_player(player, body);
            }
        }
        through += 1;
        game.seal(segment, through);
        sealed += 2 * MAX_PENDING_PER_AUTHOR as u32;
        assert_eq!(game.session.sealed_inputs(0), sealed);
    }
    assert_eq!(sealed, MAX_EVENTS as u32, "sixty-four inputs are sealed");
    // The gate refuses the sixty-fifth input on the sealed tally alone.
    let body = game.input_body(0, &mut rng, ticks);
    let event = game.players[0].unsigned(game.key, Epoch(0), body);
    let record = GameRecord::sign(
        RecordKind::Event,
        game.key,
        encode_game_event(&event),
        &game.players[0].key,
    )
    .unwrap();
    let before = game.session.pending();
    assert_eq!(
        game.session.admit(&record).err(),
        Some(Rejection::CaseEventLimit)
    );
    assert_eq!(game.session.pending(), before, "the gate changes nothing");

    // The seal-order form of the same cap, on a session that stopped one
    // input short: a seal whose order would take the case to sixty-five is
    // refused before the first append and leaves the ledger untouched.
    let live_world = live("ark-plan-a", None);
    let mut game = Game::open(live_world, 2);
    game.open_and_reveal();
    game.seal(0, 1);
    let mut through = 1;
    let mut segment = 1;
    for round_index in 0..2 {
        let per_player = if round_index == 0 {
            MAX_PENDING_PER_AUTHOR
        } else {
            15
        };
        for player in 0..2 {
            for _ in 0..per_player {
                let tick = through + 1 + rng.below(u64::from(ticks - through) - 2) as u32;
                let body = game.input_body(player, &mut rng, tick);
                game.emit_player(player, body);
            }
        }
        through += 1;
        game.seal(segment, through);
        segment += 1;
    }
    assert_eq!(game.session.sealed_inputs(0), 62);
    for player in 0..2 {
        for _ in 0..2 {
            let tick = through + 1 + rng.below(u64::from(ticks - through) - 2) as u32;
            let body = game.input_body(player, &mut rng, tick);
            game.emit_player(player, body);
        }
    }
    let order = game.unsealed.clone();
    assert_eq!(order.len(), 4, "sixty-two sealed plus four is sixty-six");
    // The seal is signed and admitted, not merely planned: the cap is an
    // admission rejection, refused before the first append rather than at
    // `SegmentManifest` construction.
    let draft = game.host.unsigned(
        game.key,
        Epoch(0),
        EventBody::Seal {
            segment,
            through_tick: through + 1,
            order,
            checkpoint: CheckpointHash([0; 32]),
        },
    );
    let produced = game.host.sign(draft);
    let height = game.session.ledger().height();
    let segments = game.session.segments().to_vec();
    let pending = game.session.pending();
    assert_eq!(
        game.session.admit(&produced.record).err(),
        Some(Rejection::SealOrderCaseEventLimit)
    );
    assert_eq!(game.session.ledger().height(), height, "nothing appended");
    assert_eq!(game.session.segments(), segments);
    assert_eq!(game.session.pending(), pending, "state is bit-identical");
    assert_eq!(game.session.sealed_inputs(0), 62);
    assert_eq!(game.session.state(), State::Running(segment));
    assert!(game.session.retained().is_empty());
    // A seal that stops at the cap is still accepted at the same segment.
    let order = game.unsealed[..2].to_vec();
    let produced = game.host.seal(&game.session, segment, through + 1, order);
    game.keep(produced);
    assert_eq!(game.session.sealed_inputs(0), MAX_EVENTS as u32);
    assert_eq!(game.session.state(), State::Running(segment + 1));
}

// ------------------------------------------------------------- pending caps

#[test]
fn the_pending_caps_refuse_without_changing_state() {
    let live_world = live("opening-normal", None);
    let ticks = live_world.ticks;
    let mut game = Game::open(live_world, 1);
    game.open_and_reveal();
    game.seal(0, 1);
    let mut rng = Rng::new(3);
    for _ in 0..MAX_PENDING_PER_AUTHOR {
        let tick = 2 + rng.below(u64::from(ticks - 1)) as u32;
        let body = game.input_body(0, &mut rng, tick);
        game.emit_player(0, body);
    }
    let pending = game.session.pending();
    let retained = game.session.retained().len();
    let body = game.input_body(0, &mut rng, ticks);
    let event = game.players[0].unsigned(game.key, Epoch(0), body);
    let record = GameRecord::sign(
        RecordKind::Event,
        game.key,
        encode_game_event(&event),
        &game.players[0].key,
    )
    .unwrap();
    assert_eq!(
        game.session.admit(&record).err(),
        Some(Rejection::AuthorPendingFull)
    );
    assert_eq!(game.session.pending(), pending, "state is bit-identical");
    assert_eq!(game.session.retained().len(), retained);
    assert_eq!(game.session.sealed_inputs(0), 0);
    // The session cap is a ceiling the per-author cap never lets a session
    // reach: at most the host and `MAX_PLAYERS` players buffer sixteen each,
    // which is 272 of the 512 the session cap allows, so `PendingFull` is
    // unreachable for any session an opening can express.
    assert_eq!((MAX_PLAYERS + 1) * MAX_PENDING_PER_AUTHOR, 272);
    assert_eq!(MAX_PENDING, 512);
}

// ------------------------------------------------------------------ resends

#[test]
fn an_exact_resend_after_a_seal_is_a_duplicate() {
    let live_world = live("opening-normal", None);
    let ticks = live_world.ticks;
    let mut game = Game::open(live_world, 1);
    let mut node = Node::new(game.session.manifest(), game.session.opening());
    game.open_and_reveal();
    let body = game.input_body(0, &mut Rng::new(2), 4);
    let input = game.emit_player(0, body);
    game.seal(0, ticks / 2);
    let log = game.log.clone();
    for produced in &log {
        node.deliver(produced);
    }
    assert_eq!(node.session.state(), State::Running(1));
    assert!(node.rejections.is_empty());
    for produced in &log {
        node.deliver(produced);
    }
    assert!(
        node.rejections.iter().all(|r| *r == Rejection::Duplicate),
        "an exact resend after a seal is a duplicate: {:?}",
        node.rejections
    );
    assert_eq!(node.rejections.len(), log.len());
    assert_eq!(node.session.state(), State::Running(1));
    assert_eq!(node.session.sealed_inputs(0), 1);
    assert_eq!(
        node.session.committed_seal(0),
        Some(log.last().unwrap().digest)
    );
    let _ = input;
}

#[test]
fn a_record_delivered_out_of_its_author_order_is_lost_to_that_receiver() {
    let live_world = live("opening-normal", None);
    let ticks = live_world.ticks;
    let mut game = Game::open(live_world, 1);
    let mut node = Node::new(game.session.manifest(), game.session.opening());
    game.open_and_reveal();
    let first = game.input_body(0, &mut Rng::new(4), 3);
    let first = game.emit_player(0, first);
    let second = game.input_body(0, &mut Rng::new(6), ticks / 2);
    let second = game.emit_player(0, second);
    for produced in &game.log.clone() {
        if produced.digest != first.digest && produced.digest != second.digest {
            node.deliver(produced);
        }
    }
    node.deliver(&second);
    node.deliver(&first);
    assert_eq!(
        node.rejections,
        vec![Rejection::SequenceNotIncreasing],
        "the claim table's strictly increasing sequence is what the relay's \
         per-author ordering exists to respect"
    );
}
