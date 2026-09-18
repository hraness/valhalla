//! Spike 3, the loading and slack schedule: does the live `loading_work` rule
//! keep every admissible input set valid, and does the per-seal slack rule
//! hold the sealed prefix?
//!
//! Over the six Platonik fixtures, converted through the oracle, each session
//! is a live game whose every world cell is an open slot: the players bind,
//! the host reveals a task whose per-case `loading_work` is `template_len +
//! max_events * INPUT_ENCODED_BYTES`, the players send random inputs at random
//! ticks inside the horizon, and the host seals at random increasing through
//! ticks. Each fixture runs twice, once on the corpus fuel budget and once on
//! a budget tightened to a measured tick, which is what makes the slack rule
//! fire at all. Nothing is lost or reordered here; spike 5 owns the relay.

use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use vhalla_core::{Epoch, RealmId, RoomId, Sequence};
use vhalla_game_platonik::engine::GameEngine;
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
};
use vhalla_game_platonik::wire::{
    encode_game_event, Authority, EventBody, GameEvent, Player, SessionOpen,
};
use vhalla_witness::bounds::MAX_EVENTS;
use vhalla_witness::codec;
use vhalla_witness::manifest::{ProgramSlot, TaskManifest, ValidManifest, WorkContract};
use vhalla_witness::model::Program;
use vhalla_witness::platform::{ReceiptBinding, WorkAllowance};
use vhalla_witness::vm::RunStatus;
use vhalla_witness::world::EventKind;

const REALM: RealmId = RealmId(3);
const ROOM: RoomId = RoomId(4);
/// Session limit on admitted events: the live loading rule's multiplier and,
/// through `SessionLedger::bound`, the per-epoch ledger capacity.
const MAX_SESSION_EVENTS: u32 = 128;
/// The six fixtures the plan's corpus parity runs over.
const FIXTURES: [&str; 6] = [
    "opening-normal",
    "opening-normal-resilient",
    "opening-wounded",
    "opening-wounded-fast",
    "ark-plan-a",
    "ark-plan-b",
];

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
    /// An honest host's seal: plan it against the session, derive the
    /// checkpoint the way a receiver does, then sign it.
    fn seal(
        &mut self,
        session: &Session,
        segment: u8,
        through_tick: u32,
        order: Vec<GameEventDigest>,
    ) -> GameRecord {
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
        self.sign(event).0
    }
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
    loading_work: u64,
    template_len: u64,
}

fn live(fixture: &str, max_events: u32, fuel: Option<u64>) -> Live {
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
    // The live loading rule. The encoding is fixed width, so writing the rule
    // back into the template does not change the length it was measured from.
    let template_len = codec::encode_manifest(&template).len() as u64;
    let loading_work = template_len + u64::from(max_events) * INPUT_ENCODED_BYTES;
    template.cases[0].loading_work = loading_work;
    assert_eq!(
        codec::encode_manifest(&template).len() as u64,
        template_len,
        "the loading rule is measured from the template it is written into"
    );
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
        loading_work: vec![loading_work],
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
        publisher: [11; 32],
    };
    Live {
        manifest,
        links: converted.task.world.links.iter().map(|l| l.id).collect(),
        valves: converted.task.world.valves.iter().map(|v| v.id).collect(),
        ticks: converted.task.cases[0].ticks,
        programs: converted.programs,
        template,
        loading_work,
        template_len,
    }
}

/// The case's cumulative ledger total at a tick with no input declared: what
/// the slack rule reads a seal's `slack_k` against.
fn base_total(live: &Live, tick: u32) -> u64 {
    let valid = ValidManifest::validate(live.template.clone()).unwrap();
    let evidence = PlatonikV1
        .replay(
            valid.hash(),
            &valid,
            live.programs.clone(),
            WorkAllowance {
                max_total: valid.fuel_total(),
            },
            tick,
            ReceiptBinding {
                challenge_id: [1; 32],
                subject_key: [2; 32],
            },
        )
        .unwrap();
    evidence.cases[0].ledger_total
}

// --------------------------------------------------------------- one session

/// What one driven session reports.
#[derive(Debug, Default)]
struct Run {
    segments: usize,
    inputs: u32,
    /// Seals after the slack rule closed the case's inputs.
    seals_after_close: usize,
    closed: bool,
    /// The seal the case's inputs closed at, if they did.
    closed_at: Option<u8>,
    terminal: bool,
}

/// Drives one lossless live session: bind, close, reveal, then rounds of
/// random inputs and a seal at a random increasing through tick.
fn drive(live_world: &Live, seed: u64, players: usize) -> Run {
    let mut rng = Rng::new(seed);
    let mut host = Signer::new(1);
    let mut signers: Vec<Signer> = (0..players).map(|i| Signer::new(2 + i as u8)).collect();
    let host_salt = [7; 32];
    let mut owned: Vec<Vec<u16>> = vec![Vec::new(); players];
    for (index, (cell, _)) in live_world.programs.iter().enumerate() {
        owned[index % players].push(*cell);
    }
    let open = SessionOpen {
        realm: REALM,
        room: ROOM,
        manifest: live_world.manifest.hash(),
        ruleset: RulesetId::V1,
        seed_commitment: seed_commitment(&host_salt, live_world.manifest.world),
        authority: Authority::Host { key: host.public() },
        players: signers
            .iter()
            .zip(&owned)
            .map(|(signer, slots)| Player {
                key: signer.public(),
                slots: slots.clone(),
            })
            .collect(),
        epoch: Epoch(0),
        nonce: [5; 32],
    };
    let mut session = Session::open(live_world.manifest.clone(), open, REALM).unwrap();
    let mut receiver = Receiver::new(PlatonikV1, policy());
    let key = session.key();
    let mut step = 0;
    let mut unsealed: Vec<GameEventDigest> = Vec::new();
    // Bind: every open slot commits, the host closes, every slot reveals.
    let mut salts: Vec<(u16, [u8; 32])> = Vec::new();
    for (player, slots) in owned.iter().enumerate() {
        for slot in slots {
            let salt = [(*slot as u8).wrapping_add(0x40); 32];
            let program = program_of(live_world, *slot);
            let commit = bind_commit(key, *slot, &program, &salt);
            let (record, digest) = signers[player].event(
                key,
                Epoch(0),
                EventBody::BindCommit {
                    slot: *slot,
                    commit,
                },
            );
            admit_ok(
                &mut session,
                &mut receiver,
                &record,
                &mut step,
                "a bind commit",
            );
            unsealed.push(digest);
            salts.push((*slot, salt));
        }
    }
    salts.sort_by_key(|(slot, _)| *slot);
    let commits: Vec<(u16, [u8; 32])> = salts
        .iter()
        .map(|(slot, salt)| {
            let program = program_of(live_world, *slot);
            (*slot, bind_commit(key, *slot, &program, salt))
        })
        .collect();
    let (record, digest) = host.event(key, Epoch(0), EventBody::BindClose { commits });
    admit_ok(
        &mut session,
        &mut receiver,
        &record,
        &mut step,
        "the bind close",
    );
    unsealed.push(digest);
    for (player, slots) in owned.iter().enumerate() {
        for slot in slots {
            let salt = salts.iter().find(|(s, _)| s == slot).unwrap().1;
            let program = program_of(live_world, *slot);
            let (record, digest) = signers[player].event(
                key,
                Epoch(0),
                EventBody::BindReveal {
                    slot: *slot,
                    program,
                    salt,
                },
            );
            admit_ok(
                &mut session,
                &mut receiver,
                &record,
                &mut step,
                "a bind reveal",
            );
            unsealed.push(digest);
        }
    }
    // Reveal: the loading rule and the fuel headroom are checked here, and a
    // well-formed live task never fails either.
    let mut task = live_world.template.clone();
    let slot_salts: Vec<[u8; 32]> = salts.iter().map(|(_, salt)| *salt).collect();
    for (index, case) in task.cases.iter_mut().enumerate() {
        case.seed = derive_seed(&host_salt, &slot_salts, index as u8);
    }
    let (record, digest) = host.event(key, Epoch(0), EventBody::Reveal { task, host_salt });
    admit_ok(
        &mut session,
        &mut receiver,
        &record,
        &mut step,
        "the reveal",
    );
    unsealed.push(digest);
    let mut run = Run::default();
    let segments = 2 + rng.below(4) as u8;
    let mut through = 0;
    for segment in 0..segments {
        let remaining = u32::from(segments - segment);
        let head_room = (live_world.ticks - through) / remaining;
        let next = if segment + 1 == segments {
            live_world.ticks
        } else {
            through + 1 + rng.below(u64::from(head_room.max(1))) as u32
        };
        for (player, signer) in signers.iter_mut().enumerate() {
            for _ in 0..rng.below(7) {
                if run.inputs >= MAX_EVENTS as u32 {
                    break;
                }
                let tick = through + 1 + rng.below(u64::from(live_world.ticks - through)) as u32;
                let body = input_body(live_world, &owned[player], &mut rng, tick);
                let (record, digest) = signer.event(key, Epoch(0), body);
                step += 1;
                match receiver.admit(&mut session, &record, step) {
                    Ok(_) => {
                        unsealed.push(digest);
                        run.inputs += 1;
                    }
                    Err(ReceiverError::Session(Rejection::CaseFuelSlack)) => {
                        assert!(
                            session.slack_closed(0),
                            "the slack rejection names the rule that closed the case"
                        );
                    }
                    Err(ReceiverError::Session(Rejection::CaseTerminal)) => {
                        run.terminal = true;
                    }
                    Err(error) => panic!("an honest input is refused as {error:?}"),
                }
            }
        }
        let order = std::mem::take(&mut unsealed);
        let record = host.seal(&session, segment, next, order);
        step += 1;
        let verified = match receiver.admit(&mut session, &record, step) {
            Ok(Some(verified)) => verified,
            Ok(None) => panic!("a seal always produces a checkpoint"),
            Err(ReceiverError::PrefixMismatch(case)) => {
                panic!("seal {segment} failed the prefix check for case {case}")
            }
            Err(ReceiverError::LedgerOffset(case)) => {
                panic!("seal {segment} failed the ledger offset for case {case}")
            }
            Err(ReceiverError::StatusRegressed(case)) => {
                panic!("seal {segment} regressed the status of case {case}")
            }
            Err(error) => panic!("an honest seal is refused as {error:?}"),
        };
        assert_eq!(verified.segment(), segment);
        assert_eq!(verified.through_tick(), next);
        if run.closed {
            run.seals_after_close += 1;
        } else if session.slack_closed(0) {
            run.closed = true;
            run.closed_at = Some(segment);
        }
        run.segments += 1;
        through = next;
        let status = session.last_case(0).unwrap().status;
        run.terminal |= status == RunStatus::FuelExhausted;
    }
    assert_eq!(session.state(), State::Finished);
    assert_eq!(session.sealed_inputs(0), run.inputs);
    run
}

/// Admits one record at the receiver and names what failed if it is refused.
fn admit_ok(
    session: &mut Session,
    receiver: &mut Receiver<PlatonikV1>,
    record: &GameRecord,
    step: &mut u64,
    what: &str,
) {
    *step += 1;
    if let Err(error) = receiver.admit(session, record, *step) {
        panic!("{what} is refused as {error:?}");
    }
}

fn program_of(live_world: &Live, slot: u16) -> Program {
    live_world
        .programs
        .iter()
        .find(|(cell, _)| *cell == slot)
        .unwrap()
        .1
        .clone()
}

/// One world input for case 0: a memory clear on a cell this player owns, or
/// a link or valve toggle where the world has one.
fn input_body(live_world: &Live, owned: &[u16], rng: &mut Rng, tick: u32) -> EventBody {
    let mut choices: Vec<EventKind> = owned
        .iter()
        .map(|cell| EventKind::ClearMemory { cell: *cell })
        .collect();
    for id in &live_world.links {
        choices.push(EventKind::LinkEnabled {
            id: *id,
            enabled: rng.chance(50),
        });
    }
    for id in &live_world.valves {
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

// --------------------------------------------------------------------- tests

/// The live loading rule, at every multiplier a publisher may declare and on
/// every fixture: the reveal never answers `LoadingRule` or `FuelHeadroom`.
#[test]
fn a_well_formed_live_reveal_never_fails_the_loading_rule_or_the_headroom() {
    for fixture in FIXTURES {
        for max_events in [1_u32, 16, 64, 128, 1024] {
            let live_world = live(fixture, max_events, None);
            assert_eq!(
                live_world.loading_work,
                live_world.template_len + u64::from(max_events) * INPUT_ENCODED_BYTES
            );
            let mut host = Signer::new(1);
            let mut player = Signer::new(2);
            let host_salt = [7; 32];
            let slots: Vec<u16> = live_world.programs.iter().map(|(cell, _)| *cell).collect();
            let open = SessionOpen {
                realm: REALM,
                room: ROOM,
                manifest: live_world.manifest.hash(),
                ruleset: RulesetId::V1,
                seed_commitment: seed_commitment(&host_salt, live_world.manifest.world),
                authority: Authority::Host { key: host.public() },
                players: vec![Player {
                    key: player.public(),
                    slots: slots.clone(),
                }],
                epoch: Epoch(0),
                nonce: [5; 32],
            };
            let mut session = Session::open(live_world.manifest.clone(), open, REALM).unwrap();
            let key = session.key();
            let mut salts = Vec::new();
            let mut commits = Vec::new();
            for slot in &slots {
                let salt = [(*slot as u8).wrapping_add(0x40); 32];
                let program = program_of(&live_world, *slot);
                let commit = bind_commit(key, *slot, &program, &salt);
                let (record, _) = player.event(
                    key,
                    Epoch(0),
                    EventBody::BindCommit {
                        slot: *slot,
                        commit,
                    },
                );
                session.admit(&record).unwrap();
                salts.push(salt);
                commits.push((*slot, commit));
            }
            let (record, _) = host.event(key, Epoch(0), EventBody::BindClose { commits });
            session.admit(&record).unwrap();
            for (index, slot) in slots.iter().enumerate() {
                let program = program_of(&live_world, *slot);
                let (record, _) = player.event(
                    key,
                    Epoch(0),
                    EventBody::BindReveal {
                        slot: *slot,
                        program,
                        salt: salts[index],
                    },
                );
                session.admit(&record).unwrap();
            }
            let mut task = live_world.template.clone();
            task.cases[0].seed = derive_seed(&host_salt, &salts, 0);
            let (record, _) = host.event(key, Epoch(0), EventBody::Reveal { task, host_salt });
            match session.admit(&record) {
                Ok(_) => {}
                Err(rejection) => panic!(
                    "{fixture} at max_events {max_events}: the reveal is refused as {rejection:?}"
                ),
            }
            assert_eq!(session.state(), State::Revealed);
        }
    }
}

/// Random admitted input sets over the six fixtures, on the corpus fuel and
/// on a tightened budget: every seal verifies, so no seal failed the prefix
/// check, the ledger offset, or the status order, and no segment manifest
/// failed the witness loading check.
#[test]
fn random_live_sessions_keep_the_sealed_prefix_on_every_fixture() {
    let mut sessions = 0;
    let mut closed = 0;
    let mut seals_after_close = 0;
    let mut inputs = 0;
    let mut closing_seal: BTreeMap<u8, usize> = BTreeMap::new();
    for fixture in FIXTURES {
        let corpus = live(fixture, MAX_SESSION_EVENTS, None);
        let players = if corpus.programs.len() > 1 { 2 } else { 1 };
        for seed in 0..4_u64 {
            // The corpus budget, then a budget tightened to a measured tick
            // so the slack rule has something to close.
            let mut rng = Rng::new(seed ^ 0xA5A5);
            let pivot = 1 + rng.below(u64::from(corpus.ticks) / 2) as u32;
            let tight = base_total(&corpus, pivot)
                .max(corpus.loading_work + 66)
                .saturating_add(30);
            for fuel in [None, Some(tight)] {
                let live_world = match fuel {
                    None => live(fixture, MAX_SESSION_EVENTS, None),
                    Some(fuel) => live(fixture, MAX_SESSION_EVENTS, Some(fuel)),
                };
                let run = drive(&live_world, seed, players);
                sessions += 1;
                inputs += run.inputs;
                if run.closed {
                    closed += 1;
                    seals_after_close += run.seals_after_close;
                    *closing_seal.entry(run.closed_at.unwrap()).or_default() += 1;
                }
            }
        }
    }
    println!(
        "spike3: {sessions} sessions, {inputs} admitted inputs; the slack rule closed a case \
         early in {closed} of them ({seals_after_close} later seals ran with the case closed), \
         by seal index {closing_seal:?}"
    );
    assert!(
        closed > 0,
        "the tightened budget must exercise the slack rule"
    );
    assert!(
        seals_after_close > 0,
        "a closed case must be carried through at least one later seal"
    );
}

/// A deliberately fuel-tight case: the run exhausts mid-run, the slack rule
/// closes the case's inputs before it does, and no later seal fails the
/// prefix check.
#[test]
fn a_fuel_tight_case_closes_its_inputs_and_keeps_the_prefix() {
    let probe = live("opening-normal", MAX_SESSION_EVENTS, None);
    let ticks = probe.ticks;
    // Frame 0 charges loading plus one checking unit per entity, spark, and
    // declared event, and each tick charges more, so a budget just past the
    // fifth tick's total leaves the run to exhaust a few ticks later.
    let fuel = base_total(&probe, 5) + 30;
    assert!(
        fuel > probe.loading_work + MAX_EVENTS as u64 + 1,
        "the reveal's fuel headroom check still passes"
    );
    let live_world = live("opening-normal", MAX_SESSION_EVENTS, Some(fuel));
    let slot = live_world.programs[0].0;
    let program = live_world.programs[0].1.clone();
    let mut host = Signer::new(1);
    let mut player = Signer::new(2);
    let host_salt = [7; 32];
    let open = SessionOpen {
        realm: REALM,
        room: ROOM,
        manifest: live_world.manifest.hash(),
        ruleset: RulesetId::V1,
        seed_commitment: seed_commitment(&host_salt, live_world.manifest.world),
        authority: Authority::Host { key: host.public() },
        players: vec![Player {
            key: player.public(),
            slots: vec![slot],
        }],
        epoch: Epoch(0),
        nonce: [5; 32],
    };
    let mut session = Session::open(live_world.manifest.clone(), open, REALM).unwrap();
    let mut receiver = Receiver::new(PlatonikV1, policy());
    let key = session.key();
    let salt = [3; 32];
    let commit = bind_commit(key, slot, &program, &salt);
    let mut order = Vec::new();
    let (record, digest) = player.event(key, Epoch(0), EventBody::BindCommit { slot, commit });
    receiver.admit(&mut session, &record, 1).unwrap();
    order.push(digest);
    let (record, digest) = host.event(
        key,
        Epoch(0),
        EventBody::BindClose {
            commits: vec![(slot, commit)],
        },
    );
    receiver.admit(&mut session, &record, 2).unwrap();
    order.push(digest);
    let (record, digest) = player.event(
        key,
        Epoch(0),
        EventBody::BindReveal {
            slot,
            program: program.clone(),
            salt,
        },
    );
    receiver.admit(&mut session, &record, 3).unwrap();
    order.push(digest);
    let mut task = live_world.template.clone();
    task.cases[0].seed = derive_seed(&host_salt, &[salt], 0);
    let (record, digest) = host.event(key, Epoch(0), EventBody::Reveal { task, host_salt });
    receiver
        .admit(&mut session, &record, 4)
        .expect("a fuel-tight task still passes the loading rule and the headroom check");
    order.push(digest);
    // Two inputs, then a seal well before the fuel stop: the case stays open.
    let mut step = 5;
    for tick in [1_u32, 2] {
        let (record, digest) = player.event(
            key,
            Epoch(0),
            EventBody::Input {
                case: 0,
                tick,
                kind: EventKind::ClearMemory { cell: slot },
            },
        );
        receiver.admit(&mut session, &record, step).unwrap();
        step += 1;
        order.push(digest);
    }
    let record = host.seal(&session, 0, 2, std::mem::take(&mut order));
    receiver.admit(&mut session, &record, step).unwrap();
    step += 1;
    assert!(
        !session.slack_closed(0),
        "a seal two ticks in leaves the case open"
    );
    assert_eq!(session.sealed_inputs(0), 2);
    // More inputs, then a seal past the pivot: the slack rule closes the case.
    for tick in [3_u32, 4] {
        let (record, digest) = player.event(
            key,
            Epoch(0),
            EventBody::Input {
                case: 0,
                tick,
                kind: EventKind::ClearMemory { cell: slot },
            },
        );
        receiver.admit(&mut session, &record, step).unwrap();
        step += 1;
        order.push(digest);
    }
    let record = host.seal(&session, 1, 5, std::mem::take(&mut order));
    receiver
        .admit(&mut session, &record, step)
        .expect("the seal that closes a case is still accepted: closing inputs preserves liveness");
    step += 1;
    assert!(
        session.slack_closed(0),
        "slack below the remaining admissible inputs closes the case"
    );
    let case = session.last_case(0).unwrap();
    assert!(
        fuel - case.ledger_total < MAX_EVENTS as u64 - u64::from(session.sealed_inputs(0)),
        "slack_k < remaining_k is exactly what closed it"
    );
    // The gate now refuses every further input for that case.
    let (record, _) = player.event(
        key,
        Epoch(0),
        EventBody::Input {
            case: 0,
            tick: 20,
            kind: EventKind::ClearMemory { cell: slot },
        },
    );
    let pending = session.pending();
    assert_eq!(
        receiver.admit(&mut session, &record, step).err(),
        Some(ReceiverError::Session(Rejection::CaseFuelSlack))
    );
    step += 1;
    assert_eq!(session.pending(), pending, "the refusal changes nothing");
    // Two later seals, one past the fuel stop and one at the horizon: neither
    // fails the prefix check, and the terminal case repeats its fields.
    let record = host.seal(&session, 2, 20, Vec::new());
    receiver
        .admit(&mut session, &record, step)
        .expect("no later seal fails the prefix check once the case is closed");
    step += 1;
    let after_stop = session.last_case(0).unwrap();
    assert_eq!(
        after_stop.status,
        RunStatus::FuelExhausted,
        "the run exhausts mid-run, well before the horizon"
    );
    let record = host.seal(&session, 3, ticks, Vec::new());
    receiver
        .admit(&mut session, &record, step)
        .expect("the final seal still reproduces the fuel-exhausted case");
    let final_case = session.last_case(0).unwrap();
    assert_eq!(
        (final_case.state, final_case.trace, final_case.ledger_total),
        (after_stop.state, after_stop.trace, after_stop.ledger_total),
        "a terminal case repeats its checkpoint fields unchanged"
    );
    assert_eq!(session.state(), State::Finished);
    println!(
        "spike3: the fuel-tight case closed at seal 1 with ledger_total {} of fuel {fuel}, \
         exhausted before tick {ticks}, and three later seals kept the prefix",
        case.ledger_total
    );
}
