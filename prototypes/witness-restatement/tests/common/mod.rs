//! Conversion between the pinned Platonik types and the restated types, the
//! bit-exact comparison, and a deterministic generator of valid v1 experiments.
#![allow(dead_code)]

use platonik_core::model as pk;
use witness_restatement::ledger::Ledger;
use witness_restatement::model::{
    Action, BitSource, Condition, Direction, MemoryWrite, Port, Program, Relative, Rule, Slot,
    ValveId,
};
use witness_restatement::vm::{
    self, ActionError, Activation, ActivationError, CellState, FrameView, Observer, RunResult,
    RunStatus, Signal, SignalEvent, SignalOutcome, State,
};
use witness_restatement::world::{
    Assignment, Beacon, Case, CaseSpec, CellBody, Depot, Endpoint, Event, EventKind, Link, Point,
    Source, Spark, Valve, World, WorldSpec,
};

pub const PROTOCOL: &str = "platonik-habitat-v1";

// ---------------------------------------------------------------------------
// Platonik -> restated
// ---------------------------------------------------------------------------

fn point(value: pk::Point) -> Point {
    Point {
        x: value.x,
        y: value.y,
    }
}
fn spark(value: pk::Spark) -> Spark {
    Spark {
        id: value.id,
        bit: value.bit,
    }
}
fn direction(value: pk::Direction) -> Direction {
    match value {
        pk::Direction::North => Direction::North,
        pk::Direction::East => Direction::East,
        pk::Direction::South => Direction::South,
        pk::Direction::West => Direction::West,
    }
}
fn relative(value: pk::Relative) -> Relative {
    match value {
        pk::Relative::Forward => Relative::Forward,
        pk::Relative::Left => Relative::Left,
        pk::Relative::Right => Relative::Right,
        pk::Relative::Back => Relative::Back,
    }
}
fn slot(value: u8) -> Slot {
    Slot::new(value).expect("validated slot")
}
fn port(value: u8) -> Port {
    Port::new(value).expect("validated port")
}
fn condition(value: &pk::Condition) -> Condition {
    match *value {
        pk::Condition::Carrying { value } => Condition::Carrying { value },
        pk::Condition::AtSource { value } => Condition::AtSource { value },
        pk::Condition::AtDepot { value } => Condition::AtDepot { value },
        pk::Condition::AtBeacon { value } => Condition::AtBeacon { value },
        pk::Condition::AtReceiver { value } => Condition::AtReceiver { value },
        pk::Condition::Blocked { direction, value } => Condition::Blocked {
            direction: relative(direction),
            value,
        },
        pk::Condition::HasMessage { port: p, value } => Condition::HasMessage {
            port: port(p),
            value,
        },
        pk::Condition::MessageBit { port: p, value } => Condition::MessageBit {
            port: port(p),
            value,
        },
        pk::Condition::Memory { slot: s, value } => Condition::Memory {
            slot: slot(s),
            value,
        },
        pk::Condition::Heading { direction: d } => Condition::Heading {
            direction: direction(d),
        },
        pk::Condition::HasMaterial { .. }
        | pk::Condition::AssemblyStage { .. }
        | pk::Condition::AssemblyEdits { .. } => panic!("not a v1 condition: {value:?}"),
    }
}
fn bit_source(value: &pk::BitSource) -> BitSource {
    match *value {
        pk::BitSource::Constant { value } => BitSource::Constant { value },
        pk::BitSource::Memory { slot: s } => BitSource::Memory { slot: slot(s) },
        pk::BitSource::Message { port: p } => BitSource::Message { port: port(p) },
    }
}
fn action(value: &pk::Action) -> Action {
    match value {
        pk::Action::Move { direction } => Action::Move {
            direction: relative(*direction),
        },
        pk::Action::Turn { direction } => Action::Turn {
            direction: relative(*direction),
        },
        pk::Action::Pickup => Action::Pickup,
        pk::Action::Drop => Action::Drop,
        pk::Action::Wait => Action::Wait,
        pk::Action::WriteMemory { slot: s, value } => Action::WriteMemory {
            slot: slot(*s),
            value: *value,
        },
        pk::Action::TakeMessage { port: p, slot: s } => Action::TakeMessage {
            port: port(*p),
            slot: slot(*s),
        },
        pk::Action::Send { port: p, bit } => Action::Send {
            port: port(*p),
            bit: bit_source(bit),
        },
        pk::Action::Route { valve, bit } => Action::Route {
            valve: ValveId::new(*valve),
            bit: bit_source(bit),
        },
        pk::Action::GatherMaterial { .. }
        | pk::Action::Build { .. }
        | pk::Action::Activate { .. }
        | pk::Action::EditDirection { .. } => panic!("not a v1 action: {value:?}"),
    }
}
pub fn program(value: &pk::Program) -> Program {
    Program::new(
        value
            .rules
            .iter()
            .map(|rule| {
                Rule::new(
                    rule.when.iter().map(condition).collect(),
                    action(&rule.action),
                    rule.remember
                        .as_ref()
                        .map(|write| MemoryWrite::new(slot(write.slot), write.value)),
                )
                .expect("validated rule")
            })
            .collect(),
    )
    .expect("validated program")
}
fn endpoint(value: &pk::Endpoint) -> Endpoint {
    match *value {
        pk::Endpoint::Cell { id, port: p } => Endpoint::Cell { id, port: port(p) },
        pk::Endpoint::Depot { id } => Endpoint::Depot { id },
    }
}
fn event_kind(value: &pk::EventKind) -> EventKind {
    match *value {
        pk::EventKind::LinkEnabled { id, enabled } => EventKind::LinkEnabled { id, enabled },
        pk::EventKind::ValveEnabled { id, enabled } => EventKind::ValveEnabled { id, enabled },
        pk::EventKind::ClearMemory { cell } => EventKind::ClearMemory { cell },
        pk::EventKind::EdgeBlocked { .. } => panic!("not a v1 event: {value:?}"),
    }
}

/// The restated inputs for one Platonik experiment.
pub struct Converted {
    pub world: World,
    pub case: Case,
    pub assignment: Assignment,
    pub loading_work: u64,
}

pub fn convert(experiment: &pk::Experiment) -> Converted {
    assert_eq!(experiment.version, pk::MODEL_VERSION, "only v1 is restated");
    assert!(experiment.construction.is_none());
    // Platonik charges loading from the compact JSON byte length of the whole
    // experiment (`sim.rs` run_through), programs and budgets included.
    let loading_work = serde_json::to_vec(experiment).unwrap().len() as u64;
    let world = World::new(WorldSpec {
        width: experiment.width,
        height: experiment.height,
        walls: experiment.walls.iter().copied().map(point).collect(),
        sources: experiment
            .sources
            .iter()
            .map(|source| Source {
                id: source.id,
                position: point(source.position),
                sparks: source.sparks.iter().copied().map(spark).collect(),
            })
            .collect(),
        depots: experiment
            .depots
            .iter()
            .map(|depot| Depot {
                id: depot.id,
                position: point(depot.position),
                capacity: depot.capacity,
            })
            .collect(),
        beacons: experiment
            .beacons
            .iter()
            .map(|beacon| Beacon {
                id: beacon.id,
                position: point(beacon.position),
                accepts: beacon.accepts,
                initial_charge: beacon.initial_charge,
                drain_every: beacon.drain_every,
                drain_amount: beacon.drain_amount,
                spark_charge: beacon.spark_charge,
                required_deliveries: beacon.required_deliveries,
            })
            .collect(),
        valves: experiment
            .valves
            .iter()
            .map(|valve| Valve {
                id: valve.id,
                position: point(valve.position),
                depot: valve.depot,
                beacon_zero: valve.beacon_zero,
                beacon_one: valve.beacon_one,
                enabled: valve.enabled,
            })
            .collect(),
        cells: experiment
            .cells
            .iter()
            .map(|cell| CellBody {
                id: cell.id,
                position: point(cell.position),
                heading: direction(cell.heading),
                mobile: cell.mobile,
                memory: cell.memory,
            })
            .collect(),
        links: experiment
            .links
            .iter()
            .map(|link| Link {
                id: link.id,
                from: endpoint(&link.from),
                to_cell: link.to_cell,
                to_port: port(link.to_port),
                delay: link.delay,
                enabled: link.enabled,
            })
            .collect(),
    })
    .expect("Platonik-valid world converts");
    let case = Case::new(
        &world,
        CaseSpec {
            seed: experiment.seed,
            ticks: experiment.ticks,
            fuel: experiment.fuel,
            activation_fuel: experiment.activation_fuel,
            events: experiment
                .events
                .iter()
                .map(|event| Event {
                    tick: event.tick,
                    event: event_kind(&event.event),
                })
                .collect(),
            loading_work,
        },
    )
    .expect("Platonik-valid case converts");
    let mut programs: Vec<(u16, Program)> = experiment
        .cells
        .iter()
        .map(|cell| (cell.id, program(&cell.program)))
        .collect();
    programs.sort_by_key(|(id, _)| *id);
    let assignment = Assignment::validate(&world, programs).expect("Platonik-valid programs");
    Converted {
        world,
        case,
        assignment,
        loading_work,
    }
}

// ---------------------------------------------------------------------------
// restated -> Platonik (for `assert_eq!` on the oracle's own types)
// ---------------------------------------------------------------------------

fn pk_point(value: Point) -> pk::Point {
    pk::Point {
        x: value.x,
        y: value.y,
    }
}
fn pk_spark(value: Spark) -> pk::Spark {
    pk::Spark {
        id: value.id,
        bit: value.bit,
    }
}
fn pk_direction(value: Direction) -> pk::Direction {
    match value {
        Direction::North => pk::Direction::North,
        Direction::East => pk::Direction::East,
        Direction::South => pk::Direction::South,
        Direction::West => pk::Direction::West,
    }
}
fn pk_relative(value: Relative) -> pk::Relative {
    match value {
        Relative::Forward => pk::Relative::Forward,
        Relative::Left => pk::Relative::Left,
        Relative::Right => pk::Relative::Right,
        Relative::Back => pk::Relative::Back,
    }
}
fn pk_bit_source(value: BitSource) -> pk::BitSource {
    match value {
        BitSource::Constant { value } => pk::BitSource::Constant { value },
        BitSource::Memory { slot } => pk::BitSource::Memory { slot: slot.get() },
        BitSource::Message { port } => pk::BitSource::Message { port: port.get() },
    }
}
fn pk_action(value: Action) -> pk::Action {
    match value {
        Action::Move { direction } => pk::Action::Move {
            direction: pk_relative(direction),
        },
        Action::Turn { direction } => pk::Action::Turn {
            direction: pk_relative(direction),
        },
        Action::Pickup => pk::Action::Pickup,
        Action::Drop => pk::Action::Drop,
        Action::Wait => pk::Action::Wait,
        Action::WriteMemory { slot, value } => pk::Action::WriteMemory {
            slot: slot.get(),
            value,
        },
        Action::TakeMessage { port, slot } => pk::Action::TakeMessage {
            port: port.get(),
            slot: slot.get(),
        },
        Action::Send { port, bit } => pk::Action::Send {
            port: port.get(),
            bit: pk_bit_source(bit),
        },
        Action::Route { valve, bit } => pk::Action::Route {
            valve: valve.get(),
            bit: pk_bit_source(bit),
        },
    }
}
fn pk_endpoint(value: Endpoint) -> pk::Endpoint {
    match value {
        Endpoint::Cell { id, port } => pk::Endpoint::Cell {
            id,
            port: port.get(),
        },
        Endpoint::Depot { id } => pk::Endpoint::Depot { id },
    }
}
fn pk_signal(value: Signal) -> pk::Signal {
    pk::Signal {
        id: value.id,
        link: value.link,
        from: pk_endpoint(value.from),
        to_cell: value.to_cell,
        to_port: value.to_port.get(),
        bit: value.bit,
        sent_tick: value.sent_tick,
        deliver_tick: value.deliver_tick,
        receipt_spark: value.receipt_spark,
    }
}
fn pk_outcome(value: SignalOutcome) -> &'static str {
    match value {
        SignalOutcome::Queued => "queued",
        SignalOutcome::Disabled => "disabled",
        SignalOutcome::NotAdjacent => "not_adjacent",
        SignalOutcome::Full => "full",
        SignalOutcome::Delivered => "delivered",
        SignalOutcome::Expired => "expired",
        SignalOutcome::Consumed => "consumed",
    }
}
fn pk_signal_event(value: &SignalEvent) -> pk::SignalEvent {
    pk::SignalEvent {
        signal: pk_signal(value.signal),
        outcome: pk_outcome(value.outcome).into(),
    }
}
fn pk_action_error(value: ActionError) -> &'static str {
    match value {
        ActionError::MovementBlocked => "movement_blocked",
        ActionError::CargoFull => "cargo_full",
        ActionError::NotAtSource => "not_at_source",
        ActionError::SourceEmpty => "source_empty",
        ActionError::CargoEmpty => "cargo_empty",
        ActionError::DepotFull => "depot_full",
        ActionError::BeaconRejectsBit => "beacon_rejects_bit",
        ActionError::NotAtReceiver => "not_at_receiver",
        ActionError::NoMessage => "no_message",
        ActionError::NoSignalQueued => "no_signal_queued",
        ActionError::UnknownValve => "unknown_valve",
        ActionError::ValveNotAdjacent => "valve_not_adjacent",
        ActionError::ValveDisabled => "valve_disabled",
        ActionError::DepotEmpty => "depot_empty",
    }
}
fn pk_activation(value: &Activation) -> pk::Activation {
    pk::Activation {
        cell: value.cell,
        rule: value.rule.map(usize::from),
        action: pk_action(value.action),
        success: value.success,
        error: value.error.map(|error| {
            match error {
                ActivationError::FuelExhausted => "fuel_exhausted",
                ActivationError::ActivationLimit => "activation_limit",
                ActivationError::Action(inner) => pk_action_error(inner),
            }
            .to_string()
        }),
        position_before: pk_point(value.position_before),
        position_after: pk_point(value.position_after),
        work_before: value.work_before,
        work_after: value.work_after,
    }
}
fn pk_cell(value: &CellState) -> pk::CellState {
    pk::CellState {
        id: value.id,
        position: pk_point(value.position),
        heading: pk_direction(value.heading),
        memory: value.memory,
        evidence: value.evidence,
        cargo: value.cargo.map(pk_spark),
        inbox: value.inbox.map(|slot| slot.map(pk_signal)),
        material: None,
    }
}
pub fn pk_state(value: &State) -> pk::State {
    pk::State {
        tick: value.tick,
        cells: value.cells.iter().map(pk_cell).collect(),
        sources: value
            .sources
            .iter()
            .map(|source| pk::SourceState {
                id: source.id,
                sparks: source.sparks.iter().copied().map(pk_spark).collect(),
            })
            .collect(),
        depots: value
            .depots
            .iter()
            .map(|depot| pk::DepotState {
                id: depot.id,
                sparks: depot.sparks.iter().copied().map(pk_spark).collect(),
            })
            .collect(),
        beacons: value
            .beacons
            .iter()
            .map(|beacon| pk::BeaconState {
                id: beacon.id,
                charge: beacon.charge,
                delivered: beacon.delivered,
                drained: beacon.drained,
                exhausted: beacon.exhausted,
            })
            .collect(),
        valves: value
            .valves
            .iter()
            .map(|entry| pk::EnabledState {
                id: entry.id,
                enabled: entry.enabled,
            })
            .collect(),
        links: value
            .links
            .iter()
            .map(|entry| pk::EnabledState {
                id: entry.id,
                enabled: entry.enabled,
            })
            .collect(),
        pending: value.pending.iter().copied().map(pk_signal).collect(),
        delivered: value
            .delivered
            .iter()
            .map(|delivery| pk::Delivery {
                tick: delivery.tick,
                spark: pk_spark(delivery.spark),
                beacon: delivery.beacon,
            })
            .collect(),
        next_signal: value.next_signal,
        closed_edges: Vec::new(),
        construction: None,
    }
}
pub fn pk_costs(value: &Ledger) -> pk::Costs {
    pk::Costs {
        loading: value.loading,
        scheduling: value.scheduling,
        conditions: value.conditions,
        sensors: value.sensors,
        memory_reads: value.memory_reads,
        memory_writes: value.memory_writes,
        actions: value.actions,
        messages: value.messages,
        transfers: value.transfers,
        checking: value.checking,
        draining: value.draining,
        copying: value.copying,
        construction: value.construction,
    }
}
fn pk_event_kind(value: EventKind) -> pk::EventKind {
    match value {
        EventKind::LinkEnabled { id, enabled } => pk::EventKind::LinkEnabled { id, enabled },
        EventKind::ValveEnabled { id, enabled } => pk::EventKind::ValveEnabled { id, enabled },
        EventKind::ClearMemory { cell } => pk::EventKind::ClearMemory { cell },
    }
}
fn pk_status(value: RunStatus) -> pk::RunStatus {
    match value {
        RunStatus::Complete => pk::RunStatus::Complete,
        RunStatus::FuelExhausted => pk::RunStatus::FuelExhausted,
        RunStatus::ActivationLimit => pk::RunStatus::ActivationLimit,
    }
}

/// Collects every frame as the oracle's `Frame` type.
#[derive(Default)]
pub struct Frames(pub Vec<pk::Frame>);

impl Observer for Frames {
    fn frame(&mut self, frame: &FrameView<'_>) {
        self.0.push(pk::Frame {
            tick: frame.tick,
            complete: frame.complete,
            events: frame.events.iter().copied().map(pk_event_kind).collect(),
            signals: frame.signals.iter().map(pk_signal_event).collect(),
            activations: frame.activations.iter().map(pk_activation).collect(),
            state: pk_state(frame.state),
            costs: pk_costs(frame.ledger),
        });
    }
}

pub fn pk_result(result: &RunResult, frames: Vec<pk::Frame>) -> pk::RunResult {
    pk::RunResult {
        protocol: PROTOCOL.into(),
        status: pk_status(result.status),
        ticks_completed: result.ticks_completed,
        initial_sparks: result.initial_sparks,
        costs: pk_costs(&result.ledger),
        outcome: pk::Outcome {
            all_beacons_positive: result.outcome.all_beacons_positive,
            quotas_met: result.outcome.quotas_met,
            conserved: result.outcome.conserved,
            passed: result.outcome.passed,
        },
        frames,
        final_state: pk_state(&result.final_state),
    }
}

/// Runs both engines and asserts every frame and the summary are equal.
/// Returns the oracle result for statistics.
pub fn assert_parity(experiment: &pk::Experiment, label: &str) -> pk::RunResult {
    let expected =
        platonik_core::run(experiment).unwrap_or_else(|error| panic!("{label}: oracle: {error}"));
    let converted = convert(experiment);
    let mut frames = Frames::default();
    let result = vm::run(
        &converted.world,
        &converted.assignment,
        &converted.case,
        &mut frames,
    )
    .unwrap_or_else(|error| panic!("{label}: restated engine: {error:?}"));
    let actual = pk_result(&result, frames.0);
    assert_eq!(
        actual.frames.len(),
        expected.frames.len(),
        "{label}: frame count"
    );
    for (mine, theirs) in actual.frames.iter().zip(&expected.frames) {
        let tick = theirs.tick;
        assert_eq!(mine.tick, theirs.tick, "{label}: tick");
        assert_eq!(
            mine.complete, theirs.complete,
            "{label} tick {tick}: complete"
        );
        assert_eq!(mine.events, theirs.events, "{label} tick {tick}: events");
        assert_eq!(mine.signals, theirs.signals, "{label} tick {tick}: signals");
        assert_eq!(
            mine.activations, theirs.activations,
            "{label} tick {tick}: activations"
        );
        assert_eq!(mine.state, theirs.state, "{label} tick {tick}: state");
        assert_eq!(mine.costs, theirs.costs, "{label} tick {tick}: costs");
    }
    assert_eq!(actual.status, expected.status, "{label}: status");
    assert_eq!(
        actual.ticks_completed, expected.ticks_completed,
        "{label}: ticks_completed"
    );
    assert_eq!(actual.costs, expected.costs, "{label}: total costs");
    assert_eq!(actual.outcome, expected.outcome, "{label}: outcome");
    assert_eq!(
        actual.final_state, expected.final_state,
        "{label}: final state"
    );
    assert_eq!(actual, expected, "{label}: whole result");
    expected
}

// ---------------------------------------------------------------------------
// Deterministic generator of valid v1 experiments
// ---------------------------------------------------------------------------

/// splitmix64.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    /// Uniform in `0..n` (`n > 0`).
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    pub fn range(&mut self, low: u64, high_inclusive: u64) -> u64 {
        low + self.below(high_inclusive - low + 1)
    }
    pub fn chance(&mut self, numerator: u64, denominator: u64) -> bool {
        self.below(denominator) < numerator
    }
    /// `low..=rare_high` with probability `numerator/denominator`, else `low..=common_high`.
    pub fn skewed(
        &mut self,
        low: u64,
        common_high: u64,
        rare_high: u64,
        numerator: u64,
        denominator: u64,
    ) -> u64 {
        let high = if self.chance(numerator, denominator) {
            rare_high
        } else {
            common_high
        };
        self.range(low, high)
    }
    pub fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len() as u64) as usize]
    }
    pub fn bool(&mut self) -> bool {
        self.chance(1, 2)
    }
}

const DIRECTIONS: [pk::Direction; 4] = [
    pk::Direction::North,
    pk::Direction::East,
    pk::Direction::South,
    pk::Direction::West,
];
const RELATIVES: [pk::Relative; 4] = [
    pk::Relative::Forward,
    pk::Relative::Left,
    pk::Relative::Right,
    pk::Relative::Back,
];

fn neighbors(point: pk::Point, width: u8, height: u8) -> Vec<pk::Point> {
    let mut out = Vec::new();
    if point.y > 0 {
        out.push(pk::Point {
            x: point.x,
            y: point.y - 1,
        });
    }
    if point.x + 1 < width {
        out.push(pk::Point {
            x: point.x + 1,
            y: point.y,
        });
    }
    if point.y + 1 < height {
        out.push(pk::Point {
            x: point.x,
            y: point.y + 1,
        });
    }
    if point.x > 0 {
        out.push(pk::Point {
            x: point.x - 1,
            y: point.y,
        });
    }
    out
}

fn random_condition(rng: &mut Rng) -> pk::Condition {
    match rng.below(10) {
        0 => pk::Condition::Carrying { value: rng.bool() },
        1 => pk::Condition::AtSource { value: rng.bool() },
        2 => pk::Condition::AtDepot { value: rng.bool() },
        3 => pk::Condition::AtBeacon { value: rng.bool() },
        4 => pk::Condition::AtReceiver { value: rng.bool() },
        5 => pk::Condition::Blocked {
            direction: rng.pick(&RELATIVES),
            value: rng.bool(),
        },
        6 => pk::Condition::HasMessage {
            port: rng.below(4) as u8,
            value: rng.bool(),
        },
        7 => pk::Condition::MessageBit {
            port: rng.below(4) as u8,
            value: rng.bool(),
        },
        8 => pk::Condition::Memory {
            slot: rng.below(4) as u8,
            value: if rng.chance(3, 4) {
                rng.below(2) as u8
            } else {
                rng.below(256) as u8
            },
        },
        _ => pk::Condition::Heading {
            direction: rng.pick(&DIRECTIONS),
        },
    }
}

fn random_bit(rng: &mut Rng) -> pk::BitSource {
    match rng.below(3) {
        0 => pk::BitSource::Constant { value: rng.bool() },
        1 => pk::BitSource::Memory {
            slot: rng.below(4) as u8,
        },
        _ => pk::BitSource::Message {
            port: rng.below(4) as u8,
        },
    }
}

fn random_action(rng: &mut Rng, valves: &[u16]) -> pk::Action {
    match rng.below(if valves.is_empty() { 8 } else { 9 }) {
        0 => pk::Action::Move {
            direction: rng.pick(&RELATIVES),
        },
        1 => pk::Action::Turn {
            direction: rng.pick(&RELATIVES),
        },
        2 => pk::Action::Pickup,
        3 => pk::Action::Drop,
        4 => pk::Action::Wait,
        5 => pk::Action::WriteMemory {
            slot: rng.below(4) as u8,
            value: rng.below(3) as u8,
        },
        6 => pk::Action::TakeMessage {
            port: rng.below(4) as u8,
            slot: rng.below(4) as u8,
        },
        7 => pk::Action::Send {
            port: rng.below(4) as u8,
            bit: random_bit(rng),
        },
        _ => pk::Action::Route {
            valve: rng.pick(valves),
            bit: random_bit(rng),
        },
    }
}

fn random_program(rng: &mut Rng, valves: &[u16]) -> pk::Program {
    let rule_count = rng.skewed(1, 6, 32, 1, 8);
    let rules = (0..rule_count)
        .map(|_| {
            let condition_count = rng.skewed(0, 3, 8, 1, 8);
            pk::Rule {
                when: (0..condition_count)
                    .map(|_| random_condition(rng))
                    .collect(),
                action: random_action(rng, valves),
                remember: if rng.chance(1, 3) {
                    Some(pk::MemoryWrite {
                        slot: rng.below(4) as u8,
                        value: rng.below(3) as u8,
                    })
                } else {
                    None
                },
            }
        })
        .collect();
    pk::Program { rules }
}

fn attempt(rng: &mut Rng) -> pk::Experiment {
    let big_grid = rng.chance(1, 8);
    let width = rng.range(3, if big_grid { 32 } else { 8 }) as u8;
    let height = rng.range(3, if big_grid { 32 } else { 8 }) as u8;
    let wall_permille = rng.pick(&[0u64, 80, 200, 350]);
    let mut walls = Vec::new();
    let mut usable = Vec::new();
    for y in 0..height {
        for x in 0..width {
            let point = pk::Point { x, y };
            if rng.chance(wall_permille, 1000) && walls.len() < 512 {
                walls.push(point);
            } else {
                usable.push(point);
            }
        }
    }
    if usable.len() < 8 {
        usable.append(&mut walls);
    }
    let mut free = usable.clone();
    let mut take_free = |rng: &mut Rng| -> Option<pk::Point> {
        if free.is_empty() {
            None
        } else {
            Some(free.swap_remove(rng.below(free.len() as u64) as usize))
        }
    };
    let cell_count = rng.skewed(1, 5, 16, 1, 6) as usize;
    let mut cell_positions = Vec::new();
    for _ in 0..cell_count {
        if let Some(point) = take_free(rng) {
            cell_positions.push(point);
        }
    }
    // Stations are distinct among themselves; cells may stand on them.
    let mut station_free = usable.clone();
    let mut take_station = |rng: &mut Rng| -> Option<pk::Point> {
        if station_free.is_empty() {
            None
        } else {
            Some(station_free.swap_remove(rng.below(station_free.len() as u64) as usize))
        }
    };
    let mut next_id: u16 = rng.range(0, 100) as u16;
    let mut id = |rng: &mut Rng| {
        next_id = next_id.wrapping_add(1 + rng.below(3) as u16);
        next_id
    };
    let mut sources = Vec::new();
    let mut depots = Vec::new();
    let mut beacons = Vec::new();
    let mut valves = Vec::new();
    let mut spark_id: u32 = rng.range(1, 1000) as u32;
    let mut spark_total = 0usize;
    for _ in 0..rng.range(0, 3) {
        if let Some(position) = take_station(rng) {
            let count = rng.range(0, 6) as usize;
            let mut sparks = Vec::new();
            for _ in 0..count {
                if spark_total >= 128 {
                    break;
                }
                spark_id += 1 + rng.below(2) as u32;
                spark_total += 1;
                sparks.push(pk::Spark {
                    id: spark_id,
                    bit: rng.bool(),
                });
            }
            sources.push(pk::Source {
                id: id(rng),
                position,
                sparks,
            });
        }
    }
    let random_beacon = |rng: &mut Rng, id: u16, position: pk::Point, accepts: bool| pk::Beacon {
        id,
        position,
        accepts,
        initial_charge: rng.skewed(1, 40, 10_000, 1, 8) as u32,
        drain_every: rng.skewed(1, 8, 128, 1, 8) as u32,
        drain_amount: rng.skewed(1, 4, 1024, 1, 8) as u32,
        spark_charge: rng.skewed(1, 8, 64, 1, 8) as u32,
        required_deliveries: rng.range(0, 3) as u32,
    };
    for _ in 0..rng.range(0, 2) {
        if let Some(position) = take_station(rng) {
            depots.push(pk::Depot {
                id: id(rng),
                position,
                capacity: rng.skewed(1, 4, 128, 1, 8) as u8,
            });
        }
    }
    for _ in 0..rng.range(1, 3) {
        if let Some(position) = take_station(rng) {
            let accepts = rng.bool();
            let beacon_id = id(rng);
            beacons.push(random_beacon(rng, beacon_id, position, accepts));
        }
    }
    if rng.chance(1, 2) {
        // A valve needs a depot and two outlet beacons on three distinct
        // adjacent free station squares.
        for _ in 0..16 {
            if station_free.len() < 4 {
                break;
            }
            let candidate = station_free[rng.below(station_free.len() as u64) as usize];
            let around: Vec<pk::Point> = neighbors(candidate, width, height)
                .into_iter()
                .filter(|point| station_free.contains(point))
                .collect();
            if around.len() < 3 {
                continue;
            }
            station_free.retain(|point| *point != candidate);
            let mut picks = around.clone();
            let mut chosen = Vec::new();
            for _ in 0..3 {
                let index = rng.below(picks.len() as u64) as usize;
                chosen.push(picks.swap_remove(index));
            }
            station_free.retain(|point| !chosen.contains(point));
            let depot_id = id(rng);
            depots.push(pk::Depot {
                id: depot_id,
                position: chosen[0],
                capacity: rng.range(1, 4) as u8,
            });
            let zero_id = id(rng);
            beacons.push(random_beacon(rng, zero_id, chosen[1], false));
            let one_id = id(rng);
            beacons.push(random_beacon(rng, one_id, chosen[2], true));
            valves.push(pk::Valve {
                id: id(rng),
                position: candidate,
                depot: depot_id,
                beacon_zero: zero_id,
                beacon_one: one_id,
                enabled: rng.chance(2, 3),
            });
            break;
        }
    }
    let valve_ids: Vec<u16> = valves.iter().map(|valve| valve.id).collect();
    let cells: Vec<pk::Cell> = cell_positions
        .iter()
        .map(|position| pk::Cell {
            id: id(rng),
            position: *position,
            heading: rng.pick(&DIRECTIONS),
            mobile: rng.chance(5, 6),
            memory: [
                rng.below(2) as u8,
                rng.below(2) as u8,
                if rng.chance(1, 4) {
                    rng.below(256) as u8
                } else {
                    0
                },
                0,
            ],
            program: random_program(rng, &valve_ids),
        })
        .collect();
    let mut links = Vec::new();
    for _ in 0..rng.range(0, 6) {
        let target = rng.pick(
            &cells
                .iter()
                .map(|cell| (cell.id, cell.position))
                .collect::<Vec<_>>(),
        );
        let mut origins: Vec<pk::Endpoint> = Vec::new();
        for cell in &cells {
            if cell.id != target.0 && cell.position.distance(target.1) == 1 {
                origins.push(pk::Endpoint::Cell {
                    id: cell.id,
                    port: rng.below(4) as u8,
                });
            }
        }
        for depot in &depots {
            if depot.position.distance(target.1) == 1 {
                origins.push(pk::Endpoint::Depot { id: depot.id });
            }
        }
        if origins.is_empty() {
            continue;
        }
        let origin = origins[rng.below(origins.len() as u64) as usize].clone();
        links.push(pk::Link {
            id: id(rng),
            from: origin,
            to_cell: target.0,
            to_port: rng.below(4) as u8,
            delay: rng.skewed(1, 3, 16, 1, 6) as u32,
            enabled: rng.chance(4, 5),
        });
    }
    let ticks = rng.skewed(1, 24, 128, 1, 6) as u32;
    let mut events = Vec::new();
    for _ in 0..rng.range(0, 5) {
        let tick = rng.range(1, ticks as u64) as u32;
        let event = match rng.below(3) {
            0 if !links.is_empty() => pk::EventKind::LinkEnabled {
                id: rng.pick(&links.iter().map(|link| link.id).collect::<Vec<_>>()),
                enabled: rng.bool(),
            },
            1 if !valves.is_empty() => pk::EventKind::ValveEnabled {
                id: rng.pick(&valve_ids),
                enabled: rng.bool(),
            },
            _ => pk::EventKind::ClearMemory {
                cell: rng.pick(&cells.iter().map(|cell| cell.id).collect::<Vec<_>>()),
            },
        };
        events.push(pk::Event { tick, event });
    }
    let fuel = match rng.below(5) {
        0 => pk::MAX_FUEL,
        1 => 20_000,
        2 => rng.below(400),
        3 => rng.range(300, 6000),
        _ => rng.below(pk::MAX_FUEL + 1),
    };
    let activation_fuel = if rng.chance(1, 3) {
        rng.range(1, 12) as u32
    } else {
        rng.range(1, 1024) as u32
    };
    pk::Experiment {
        version: pk::MODEL_VERSION,
        seed: rng.next(),
        width,
        height,
        walls,
        sources,
        depots,
        beacons,
        valves,
        cells,
        links,
        events,
        ticks,
        fuel,
        activation_fuel,
        construction: None,
    }
}

/// A valid v1 experiment; panics if the generator produced an invalid one so
/// generator bugs are visible rather than silently retried.
pub fn random_experiment(rng: &mut Rng) -> pk::Experiment {
    loop {
        let experiment = if rng.chance(1, 3) {
            mutated_fixture(rng)
        } else {
            attempt(rng)
        };
        if serde_json::to_vec(&experiment).unwrap().len() > pk::MAX_INPUT_BYTES {
            continue;
        }
        platonik_core::validate_experiment(&experiment).unwrap_or_else(|error| {
            panic!("generator produced an invalid experiment: {error}\n{experiment:?}")
        });
        return experiment;
    }
}

/// A bridge-v1 fixture with its seed, duration, fuel, and activation budget
/// perturbed, and sometimes one cell's program replaced, so the random corpus
/// also covers missions that pass, deliver sparks, and carry signals.
fn mutated_fixture(rng: &mut Rng) -> pk::Experiment {
    let names = platonik_core::fixtures::names();
    let name = names[rng.below(names.len() as u64) as usize];
    let mut experiment = platonik_core::fixtures::experiment(name).unwrap();
    if rng.chance(1, 2) {
        experiment.seed = rng.next();
    }
    if rng.chance(1, 3) {
        experiment.ticks = rng.range(1, u64::from(experiment.ticks)) as u32;
        let ticks = experiment.ticks;
        experiment.events.retain(|event| event.tick <= ticks);
    }
    match rng.below(4) {
        0 => experiment.fuel = rng.below(400),
        1 => experiment.fuel = rng.range(300, 20_000),
        _ => {}
    }
    if rng.chance(1, 4) {
        experiment.activation_fuel = rng.range(1, 12) as u32;
    }
    if rng.chance(1, 4) && !experiment.cells.is_empty() {
        let valves: Vec<u16> = experiment.valves.iter().map(|valve| valve.id).collect();
        let index = rng.below(experiment.cells.len() as u64) as usize;
        experiment.cells[index].program = random_program(rng, &valves);
    }
    experiment
}

/// The densest 16-cell, 128-tick case that fits Platonik's 64 KiB input bound:
/// nine rules of 8 satisfiable-then-failing conditions, then a `Send` over two
/// links, on a 32x32 grid with 8 beacons and 8 depots.
pub fn worst_case() -> pk::Experiment {
    let mut cells = Vec::new();
    let mut links = Vec::new();
    let mut link_id = 100;
    for index in 0..16u16 {
        let x = 10 + (index % 4) as u8;
        let y = 10 + (index / 4) as u8;
        let mut rules = Vec::new();
        for _ in 0..9 {
            let mut when = vec![
                pk::Condition::Heading {
                    direction: pk::Direction::East,
                };
                7
            ];
            when.push(pk::Condition::Carrying { value: true });
            rules.push(pk::Rule {
                when,
                action: pk::Action::Wait,
                remember: None,
            });
        }
        rules.push(pk::Rule {
            when: vec![],
            action: pk::Action::Send {
                port: 0,
                bit: pk::BitSource::Constant { value: true },
            },
            remember: Some(pk::MemoryWrite { slot: 0, value: 1 }),
        });
        cells.push(pk::Cell {
            id: index,
            position: pk::Point { x, y },
            heading: pk::Direction::East,
            mobile: false,
            memory: [0; 4],
            program: pk::Program { rules },
        });
    }
    for index in 0..16u16 {
        for target in [index + 1, index + 4] {
            if target < 16 && (index % 4 != 3 || target != index + 1) {
                links.push(pk::Link {
                    id: link_id,
                    from: pk::Endpoint::Cell { id: index, port: 0 },
                    to_cell: target,
                    to_port: (link_id % 4) as u8,
                    delay: 1,
                    enabled: true,
                });
                link_id += 1;
            }
        }
    }
    let beacons = (0..8u16)
        .map(|index| pk::Beacon {
            id: 200 + index,
            position: pk::Point {
                x: index as u8,
                y: 0,
            },
            accepts: index % 2 == 1,
            initial_charge: 10_000,
            drain_every: 1,
            drain_amount: 1,
            spark_charge: 1,
            required_deliveries: 0,
        })
        .collect();
    let depots = (0..8u16)
        .map(|index| pk::Depot {
            id: 300 + index,
            position: pk::Point {
                x: index as u8,
                y: 2,
            },
            capacity: 128,
        })
        .collect();
    let sources = (0..8u16)
        .map(|index| pk::Source {
            id: 400 + index,
            position: pk::Point {
                x: index as u8,
                y: 4,
            },
            sparks: (0..16)
                .map(|spark| pk::Spark {
                    id: u32::from(index) * 16 + spark,
                    bit: spark % 2 == 0,
                })
                .collect(),
        })
        .collect();
    pk::Experiment {
        version: pk::MODEL_VERSION,
        seed: 7,
        width: 32,
        height: 32,
        walls: (0..32u8).map(|x| pk::Point { x, y: 31 }).collect(),
        sources,
        depots,
        beacons,
        valves: vec![],
        cells,
        links,
        events: vec![],
        ticks: 128,
        fuel: pk::MAX_FUEL,
        activation_fuel: 1024,
        construction: None,
    }
}
