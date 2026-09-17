//! The tick loop: `sim.rs` `run`/`run_through` (without continuation) and
//! `policy.rs` `activate` restated for version 1.
//!
//! [`Machine::new`] allocates every vector to its static bound; [`Machine::run`]
//! allocates nothing. Per-tick data reaches the caller through an
//! [`Observer`] borrowed view so the loop never clones a frame.
//!
//! Transactional activations use a second pre-allocated [`State`] instead of
//! Platonik's `state.clone()`: the scratch copy receives the action, and it is
//! swapped in on success or action failure and discarded on a fuel or
//! activation stop, exactly like `*state = next`.

use alloc::vec::Vec;

use crate::bounds::*;
use crate::ledger::{Arithmetic, Category, Ledger, Meter, MeterError, Stop};
use crate::model::{face, Action, BitSource, Condition, Direction, Program, Relative};
use crate::world::{Assignment, Case, Endpoint, EventKind, Point, Spark, World};

/// A signal in flight or in an inbox (`model::Signal`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signal {
    /// Run-unique id from `next_signal`, assigned even when not queued.
    pub id: u64,
    /// Link id.
    pub link: u16,
    /// Origin.
    pub from: Endpoint,
    /// Recipient cell.
    pub to_cell: u16,
    /// Recipient port.
    pub to_port: crate::model::Port,
    /// Payload.
    pub bit: bool,
    /// Tick of emission.
    pub sent_tick: u32,
    /// `sent_tick + delay`.
    pub deliver_tick: u32,
    /// The spark whose deposit or memory evidence the bit derives from.
    pub receipt_spark: Option<u32>,
}

/// What happened to a signal (`SignalEvent::outcome` strings).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignalOutcome {
    /// Emitted and queued.
    Queued,
    /// Emitted or due over a disabled link.
    Disabled,
    /// Emitted or due between non-adjacent endpoints.
    NotAdjacent,
    /// The queue or the inbox port was full.
    Full,
    /// Placed in the inbox port.
    Delivered,
    /// Cleared from an inbox at the start of a tick.
    Expired,
    /// Taken into memory.
    Consumed,
}

/// A signal and its outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignalEvent {
    /// The signal.
    pub signal: Signal,
    /// The outcome.
    pub outcome: SignalOutcome,
}

/// The full per-cell state (`model::CellState` minus the v3 `material`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CellState {
    /// Cell id.
    pub id: u16,
    /// Position.
    pub position: Point,
    /// Heading.
    pub heading: Direction,
    /// Four byte registers.
    pub memory: [u8; 4],
    /// Per-slot spark evidence set by `TakeMessage`, cleared by writes.
    pub evidence: [Option<u32>; 4],
    /// Carried spark.
    pub cargo: Option<Spark>,
    /// Four inbox ports, cleared at the start of every tick.
    pub inbox: [Option<Signal>; 4],
}

/// Remaining sparks of a source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceState {
    /// Source id.
    pub id: u16,
    /// Remaining sparks, oldest first.
    pub sparks: Vec<Spark>,
}

/// Stored sparks of a depot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepotState {
    /// Depot id.
    pub id: u16,
    /// Stored sparks, oldest first.
    pub sparks: Vec<Spark>,
}

/// Beacon energy ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BeaconState {
    /// Beacon id.
    pub id: u16,
    /// Current charge.
    pub charge: u32,
    /// Deliveries credited.
    pub delivered: u32,
    /// Total drained.
    pub drained: u32,
    /// Set once the charge reaches zero by draining.
    pub exhausted: bool,
}

/// Enabled flag of a link or valve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnabledState {
    /// Id.
    pub id: u16,
    /// Enabled.
    pub enabled: bool,
}

/// A credited delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Delivery {
    /// Tick.
    pub tick: u32,
    /// Spark.
    pub spark: Spark,
    /// Beacon id.
    pub beacon: u16,
}

/// The world state (`model::State` minus v2 `closed_edges` and v3
/// `construction`, both absent in v1 receipts).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    /// Current tick.
    pub tick: u32,
    /// Cells in world order.
    pub cells: Vec<CellState>,
    /// Sources in world order.
    pub sources: Vec<SourceState>,
    /// Depots in world order.
    pub depots: Vec<DepotState>,
    /// Beacons in world order.
    pub beacons: Vec<BeaconState>,
    /// Valves in world order.
    pub valves: Vec<EnabledState>,
    /// Links in world order.
    pub links: Vec<EnabledState>,
    /// Queued signals in emission order.
    pub pending: Vec<Signal>,
    /// Credited deliveries in order.
    pub delivered: Vec<Delivery>,
    /// Next signal id, starting at 1.
    pub next_signal: u64,
}

impl State {
    fn allocated(world: &World) -> Self {
        let mut sources = Vec::with_capacity(MAX_SOURCES);
        for source in world.sources() {
            sources.push(SourceState {
                id: source.id,
                sparks: Vec::with_capacity(MAX_INITIAL_SPARKS),
            });
        }
        let mut depots = Vec::with_capacity(MAX_DEPOTS);
        for depot in world.depots() {
            depots.push(DepotState {
                id: depot.id,
                sparks: Vec::with_capacity(usize::from(MAX_DEPOT_CAPACITY)),
            });
        }
        Self {
            tick: 0,
            cells: Vec::with_capacity(MAX_CELLS),
            sources,
            depots,
            beacons: Vec::with_capacity(MAX_BEACONS),
            valves: Vec::with_capacity(MAX_VALVES),
            links: Vec::with_capacity(MAX_LINKS),
            pending: Vec::with_capacity(MAX_PENDING),
            delivered: Vec::with_capacity(MAX_DELIVERIES),
            next_signal: 1,
        }
    }

    fn initial(world: &World) -> Self {
        let mut state = Self::allocated(world);
        for cell in world.cells() {
            state.cells.push(CellState {
                id: cell.id,
                position: cell.position,
                heading: cell.heading,
                memory: cell.memory,
                evidence: [None; 4],
                cargo: None,
                inbox: [None; 4],
            });
        }
        for (entry, source) in state.sources.iter_mut().zip(world.sources()) {
            entry.sparks.extend_from_slice(&source.sparks);
        }
        for beacon in world.beacons() {
            state.beacons.push(BeaconState {
                id: beacon.id,
                charge: beacon.initial_charge,
                delivered: 0,
                drained: 0,
                exhausted: false,
            });
        }
        for valve in world.valves() {
            state.valves.push(EnabledState {
                id: valve.id,
                enabled: valve.enabled,
            });
        }
        for link in world.links() {
            state.links.push(EnabledState {
                id: link.id,
                enabled: link.enabled,
            });
        }
        state
    }

    /// Copies `other` into `self` without allocating; both come from the
    /// same world so every vector has enough capacity.
    fn copy_from(&mut self, other: &Self) {
        self.tick = other.tick;
        self.cells.clear();
        self.cells.extend_from_slice(&other.cells);
        for (entry, source) in self.sources.iter_mut().zip(&other.sources) {
            entry.id = source.id;
            entry.sparks.clear();
            entry.sparks.extend_from_slice(&source.sparks);
        }
        for (entry, depot) in self.depots.iter_mut().zip(&other.depots) {
            entry.id = depot.id;
            entry.sparks.clear();
            entry.sparks.extend_from_slice(&depot.sparks);
        }
        self.beacons.clear();
        self.beacons.extend_from_slice(&other.beacons);
        self.valves.clear();
        self.valves.extend_from_slice(&other.valves);
        self.links.clear();
        self.links.extend_from_slice(&other.links);
        self.pending.clear();
        self.pending.extend_from_slice(&other.pending);
        self.delivered.clear();
        self.delivered.extend_from_slice(&other.delivered);
        self.next_signal = other.next_signal;
    }
}

/// Why an action failed (`policy.rs` `Fault::Action` strings).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionError {
    /// `movement_blocked`
    MovementBlocked,
    /// `cargo_full`
    CargoFull,
    /// `not_at_source`
    NotAtSource,
    /// `source_empty`
    SourceEmpty,
    /// `cargo_empty`
    CargoEmpty,
    /// `depot_full`
    DepotFull,
    /// `beacon_rejects_bit`
    BeaconRejectsBit,
    /// `not_at_receiver`
    NotAtReceiver,
    /// `no_message`
    NoMessage,
    /// `no_signal_queued`
    NoSignalQueued,
    /// `unknown_valve`
    UnknownValve,
    /// `valve_not_adjacent`
    ValveNotAdjacent,
    /// `valve_disabled`
    ValveDisabled,
    /// `depot_empty`
    DepotEmpty,
}

/// Why an activation did not succeed (`Activation::error` strings).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivationError {
    /// `fuel_exhausted`: the run's fuel ran out; the activation was rolled back.
    FuelExhausted,
    /// `activation_limit`: the window ran out; the activation was rolled back.
    ActivationLimit,
    /// The action failed; the activation (including `remember`) was kept.
    Action(ActionError),
}

/// One cell's turn (`model::Activation`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Activation {
    /// Cell id.
    pub cell: u16,
    /// Index of the first matching rule, if any.
    pub rule: Option<u8>,
    /// The action executed (`Wait` when no rule matched).
    pub action: Action,
    /// Whether the action succeeded.
    pub success: bool,
    /// The failure, if any.
    pub error: Option<ActivationError>,
    /// Position before.
    pub position_before: Point,
    /// Position after.
    pub position_after: Point,
    /// Ledger total before.
    pub work_before: u64,
    /// Ledger total after.
    pub work_after: u64,
}

/// How a run ended (`model::RunStatus`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunStatus {
    /// Every tick completed and no activation hit its window.
    Complete,
    /// Loading or a tick ran out of fuel.
    FuelExhausted,
    /// At least one activation hit its window; the run still completed.
    ActivationLimit,
}

/// The mission outcome (`model::Outcome`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// Every beacon has charge and was never exhausted.
    pub all_beacons_positive: bool,
    /// Every beacon met its quota.
    pub quotas_met: bool,
    /// Every initial spark is still somewhere.
    pub conserved: bool,
    /// Complete, all of the above, and every tick ran.
    pub passed: bool,
}

/// The run summary (`model::RunResult` minus frames and protocol string).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunResult {
    /// Status.
    pub status: RunStatus,
    /// Completed ticks.
    pub ticks_completed: u32,
    /// Initial sparks.
    pub initial_sparks: u32,
    /// Final ledger.
    pub ledger: Ledger,
    /// Outcome.
    pub outcome: Outcome,
    /// Final state.
    pub final_state: State,
}

/// A run failure. None is reachable within the static bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunError {
    /// A checked operation overflowed.
    Arithmetic,
    /// A validated reference was missing at run time.
    Invariant,
    /// The assignment was validated against a different world.
    AssignmentMismatch,
}

impl From<Arithmetic> for RunError {
    fn from(_: Arithmetic) -> Self {
        Self::Arithmetic
    }
}

/// One tick's data, borrowed from the machine.
#[derive(Clone, Copy, Debug)]
pub struct FrameView<'a> {
    /// Tick; 0 is the loading frame.
    pub tick: u32,
    /// Whether the tick finished without a fuel stop.
    pub complete: bool,
    /// Events applied this tick.
    pub events: &'a [EventKind],
    /// Signal events this tick.
    pub signals: &'a [SignalEvent],
    /// Activations this tick in seeded order.
    pub activations: &'a [Activation],
    /// State at the end of the tick (partial when incomplete).
    pub state: &'a State,
    /// Ledger at the end of the tick.
    pub ledger: &'a Ledger,
}

/// Receives every frame during a run.
pub trait Observer {
    /// Called once per frame, including the loading frame.
    fn frame(&mut self, frame: &FrameView<'_>);
}

impl Observer for () {
    fn frame(&mut self, _: &FrameView<'_>) {}
}

enum Fault {
    Stop(Stop),
    Action(ActionError),
    Internal(RunError),
}

impl From<MeterError> for Fault {
    fn from(error: MeterError) -> Self {
        match error {
            MeterError::Stop(stop) => Self::Stop(stop),
            MeterError::Arithmetic => Self::Internal(RunError::Arithmetic),
        }
    }
}

impl From<Arithmetic> for Fault {
    fn from(_: Arithmetic) -> Self {
        Self::Internal(RunError::Arithmetic)
    }
}

impl From<RunError> for Fault {
    fn from(error: RunError) -> Self {
        Self::Internal(error)
    }
}

fn count(len: usize) -> Result<u64, RunError> {
    u64::try_from(len).map_err(|_| RunError::Arithmetic)
}

/// The splitmix64 finalizer used for activation order (`sim.rs` `order_ids`).
/// Wrapping is the hash definition, not an overflow.
pub const fn mix(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

/// `policy::destination`: the square one step in a relative direction.
pub fn destination(position: Point, heading: Direction, direction: Relative) -> Option<Point> {
    match face(heading, direction) {
        Direction::North => position
            .y
            .checked_sub(1)
            .map(|y| Point { x: position.x, y }),
        Direction::East => position
            .x
            .checked_add(1)
            .map(|x| Point { x, y: position.y }),
        Direction::South => position
            .y
            .checked_add(1)
            .map(|y| Point { x: position.x, y }),
        Direction::West => position
            .x
            .checked_sub(1)
            .map(|x| Point { x, y: position.y }),
    }
}

/// `policy::blocked` for v1 (no closed edges, no reserved construction sites).
pub fn blocked(world: &World, state: &State, index: usize, direction: Relative) -> bool {
    let actor = &state.cells[index];
    match destination(actor.position, actor.heading, direction) {
        None => true,
        Some(point) => {
            point.x >= world.width()
                || point.y >= world.height()
                || world.is_wall(point)
                || state
                    .cells
                    .iter()
                    .any(|other| other.id != actor.id && other.position == point)
        }
    }
}

fn origin_position(world: &World, state: &State, endpoint: Endpoint) -> Result<Point, RunError> {
    match endpoint {
        Endpoint::Cell { id, .. } => state
            .cells
            .iter()
            .find(|cell| cell.id == id)
            .map(|cell| cell.position)
            .ok_or(RunError::Invariant),
        Endpoint::Depot { id } => world
            .depots()
            .iter()
            .find(|depot| depot.id == id)
            .map(|depot| depot.position)
            .ok_or(RunError::Invariant),
    }
}

struct Ctx<'w, 'm> {
    world: &'w World,
    meter: &'m mut Meter,
    signals: &'m mut Vec<SignalEvent>,
}

fn emit(
    ctx: &mut Ctx<'_, '_>,
    state: &mut State,
    endpoint: Endpoint,
    bit: bool,
    evidence: Option<u32>,
) -> Result<u32, Fault> {
    let mut accepted = 0u32;
    for (index, link) in ctx
        .world
        .links()
        .iter()
        .enumerate()
        .filter(|(_, link)| link.from == endpoint)
    {
        ctx.meter.charge(Category::Messages, 1)?;
        ctx.meter.charge(Category::Checking, 1)?;
        let recipient = state
            .cells
            .iter()
            .find(|cell| cell.id == link.to_cell)
            .map(|cell| cell.position)
            .ok_or(RunError::Invariant)?;
        let signal = Signal {
            id: state.next_signal,
            link: link.id,
            from: endpoint,
            to_cell: link.to_cell,
            to_port: link.to_port,
            bit,
            sent_tick: state.tick,
            deliver_tick: state.tick.checked_add(link.delay).ok_or(Arithmetic)?,
            receipt_spark: evidence,
        };
        state.next_signal = state.next_signal.checked_add(1).ok_or(Arithmetic)?;
        let outcome = if !state.links[index].enabled {
            SignalOutcome::Disabled
        } else if origin_position(ctx.world, state, endpoint)?.distance(recipient) != 1 {
            SignalOutcome::NotAdjacent
        } else if state.pending.len() >= MAX_PENDING {
            SignalOutcome::Full
        } else {
            state.pending.push(signal);
            accepted = accepted.checked_add(1).ok_or(Arithmetic)?;
            SignalOutcome::Queued
        };
        ctx.signals.push(SignalEvent { signal, outcome });
    }
    Ok(accepted)
}

fn check_condition(
    ctx: &mut Ctx<'_, '_>,
    state: &State,
    index: usize,
    condition: Condition,
) -> Result<bool, Fault> {
    ctx.meter.charge(Category::Conditions, 1)?;
    let cell = &state.cells[index];
    if let Condition::Memory { slot, value } = condition {
        ctx.meter.charge(Category::MemoryReads, 1)?;
        return Ok(cell.memory[slot.index()] == value);
    }
    ctx.meter.charge(Category::Sensors, 1)?;
    let world = ctx.world;
    let at_depot = || {
        world
            .depots()
            .iter()
            .any(|depot| depot.position == cell.position)
    };
    let at_beacon = || {
        world
            .beacons()
            .iter()
            .any(|beacon| beacon.position == cell.position)
    };
    Ok(match condition {
        Condition::Carrying { value } => cell.cargo.is_some() == value,
        Condition::AtSource { value } => {
            world
                .sources()
                .iter()
                .any(|source| source.position == cell.position)
                == value
        }
        Condition::AtDepot { value } => at_depot() == value,
        Condition::AtBeacon { value } => at_beacon() == value,
        Condition::AtReceiver { value } => (at_depot() || at_beacon()) == value,
        // v2 charges `checking` once per closed edge here; v1 has none.
        Condition::Blocked { direction, value } => blocked(world, state, index, direction) == value,
        Condition::HasMessage { port, value } => cell.inbox[port.index()].is_some() == value,
        Condition::MessageBit { port, value } => cell.inbox[port.index()]
            .as_ref()
            .is_some_and(|signal| signal.bit == value),
        Condition::Heading { direction } => cell.heading == direction,
        Condition::Memory { .. } => return Err(Fault::Internal(RunError::Invariant)),
    })
}

fn read_bit(
    ctx: &mut Ctx<'_, '_>,
    cell: &CellState,
    source: BitSource,
) -> Result<(bool, Option<u32>), Fault> {
    match source {
        BitSource::Constant { value } => {
            ctx.meter.charge(Category::Checking, 1)?;
            Ok((value, None))
        }
        BitSource::Memory { slot } => {
            ctx.meter.charge(Category::MemoryReads, 1)?;
            Ok((cell.memory[slot.index()] != 0, cell.evidence[slot.index()]))
        }
        BitSource::Message { port } => {
            ctx.meter.charge(Category::Sensors, 1)?;
            cell.inbox[port.index()]
                .as_ref()
                .map(|signal| (signal.bit, signal.receipt_spark))
                .ok_or(Fault::Action(ActionError::NoMessage))
        }
    }
}

fn credit(
    ctx: &mut Ctx<'_, '_>,
    state: &mut State,
    beacon: usize,
    spark: Spark,
) -> Result<(), Fault> {
    ctx.meter.charge(Category::Transfers, 1)?;
    let specification = &ctx.world.beacons()[beacon];
    let entry = &mut state.beacons[beacon];
    entry.charge = entry
        .charge
        .checked_add(specification.spark_charge)
        .ok_or(Arithmetic)?;
    entry.delivered = entry.delivered.checked_add(1).ok_or(Arithmetic)?;
    state.delivered.push(Delivery {
        tick: state.tick,
        spark,
        beacon: specification.id,
    });
    Ok(())
}

fn execute(
    ctx: &mut Ctx<'_, '_>,
    state: &mut State,
    index: usize,
    action: Action,
) -> Result<(), Fault> {
    ctx.meter.charge(Category::Actions, 1)?;
    match action {
        Action::Wait => {}
        Action::Move { direction } => {
            ctx.meter.charge(Category::Checking, 1)?;
            // v2 charges `checking` once per closed edge here; v1 has none.
            if !ctx.world.cells()[index].mobile || blocked(ctx.world, state, index, direction) {
                return Err(Fault::Action(ActionError::MovementBlocked));
            }
            ctx.meter.charge(Category::Transfers, 1)?;
            let cell = &mut state.cells[index];
            cell.position =
                destination(cell.position, cell.heading, direction).ok_or(RunError::Invariant)?;
            cell.heading = face(cell.heading, direction);
        }
        Action::Turn { direction } => {
            ctx.meter.charge(Category::Transfers, 1)?;
            let cell = &mut state.cells[index];
            cell.heading = face(cell.heading, direction);
        }
        Action::Pickup => {
            ctx.meter.charge(Category::Checking, 1)?;
            if state.cells[index].cargo.is_some() {
                return Err(Fault::Action(ActionError::CargoFull));
            }
            let source = ctx
                .world
                .sources()
                .iter()
                .position(|source| source.position == state.cells[index].position)
                .ok_or(Fault::Action(ActionError::NotAtSource))?;
            if state.sources[source].sparks.is_empty() {
                return Err(Fault::Action(ActionError::SourceEmpty));
            }
            ctx.meter.charge(Category::Transfers, 1)?;
            state.cells[index].cargo = Some(state.sources[source].sparks.remove(0));
        }
        Action::Drop => {
            ctx.meter.charge(Category::Checking, 1)?;
            let spark = state.cells[index]
                .cargo
                .ok_or(Fault::Action(ActionError::CargoEmpty))?;
            let position = state.cells[index].position;
            if let Some(depot) = ctx
                .world
                .depots()
                .iter()
                .position(|depot| depot.position == position)
            {
                let capacity = usize::from(ctx.world.depots()[depot].capacity);
                if state.depots[depot].sparks.len() >= capacity {
                    return Err(Fault::Action(ActionError::DepotFull));
                }
                ctx.meter.charge(Category::Transfers, 1)?;
                state.cells[index].cargo = None;
                state.depots[depot].sparks.push(spark);
                let endpoint = Endpoint::Depot {
                    id: ctx.world.depots()[depot].id,
                };
                emit(ctx, state, endpoint, spark.bit, Some(spark.id))?;
            } else if let Some(beacon) = ctx
                .world
                .beacons()
                .iter()
                .position(|beacon| beacon.position == position)
            {
                if ctx.world.beacons()[beacon].accepts != spark.bit {
                    return Err(Fault::Action(ActionError::BeaconRejectsBit));
                }
                credit(ctx, state, beacon, spark)?;
                state.cells[index].cargo = None;
            } else {
                return Err(Fault::Action(ActionError::NotAtReceiver));
            }
        }
        Action::WriteMemory { slot, value } => {
            ctx.meter.charge(Category::MemoryWrites, 1)?;
            state.cells[index].memory[slot.index()] = value;
            state.cells[index].evidence[slot.index()] = None;
        }
        Action::TakeMessage { port, slot } => {
            ctx.meter.charge(Category::Sensors, 1)?;
            let signal = state.cells[index].inbox[port.index()]
                .ok_or(Fault::Action(ActionError::NoMessage))?;
            ctx.meter.charge(Category::MemoryWrites, 1)?;
            ctx.meter.charge(Category::Messages, 1)?;
            state.cells[index].memory[slot.index()] = u8::from(signal.bit);
            state.cells[index].evidence[slot.index()] = signal.receipt_spark;
            state.cells[index].inbox[port.index()] = None;
            ctx.signals.push(SignalEvent {
                signal,
                outcome: SignalOutcome::Consumed,
            });
        }
        Action::Send { port, bit } => {
            let (value, evidence) = read_bit(ctx, &state.cells[index], bit)?;
            let endpoint = Endpoint::Cell {
                id: state.cells[index].id,
                port,
            };
            let accepted = emit(ctx, state, endpoint, value, evidence)?;
            if accepted == 0 {
                return Err(Fault::Action(ActionError::NoSignalQueued));
            }
        }
        Action::Route { valve, bit } => {
            let (value, _) = read_bit(ctx, &state.cells[index], bit)?;
            ctx.meter.charge(Category::Checking, 1)?;
            let valve_index = ctx
                .world
                .valves()
                .iter()
                .position(|entry| entry.id == valve.get())
                .ok_or(Fault::Action(ActionError::UnknownValve))?;
            let specification = &ctx.world.valves()[valve_index];
            if state.cells[index].position.distance(specification.position) != 1 {
                return Err(Fault::Action(ActionError::ValveNotAdjacent));
            }
            if !state.valves[valve_index].enabled {
                return Err(Fault::Action(ActionError::ValveDisabled));
            }
            let depot = ctx
                .world
                .depots()
                .iter()
                .position(|depot| depot.id == specification.depot)
                .ok_or(RunError::Invariant)?;
            let spark = *state.depots[depot]
                .sparks
                .first()
                .ok_or(Fault::Action(ActionError::DepotEmpty))?;
            let beacon_id = if value {
                specification.beacon_one
            } else {
                specification.beacon_zero
            };
            let beacon = ctx
                .world
                .beacons()
                .iter()
                .position(|beacon| beacon.id == beacon_id)
                .ok_or(RunError::Invariant)?;
            if ctx.world.beacons()[beacon].accepts != spark.bit {
                return Err(Fault::Action(ActionError::BeaconRejectsBit));
            }
            credit(ctx, state, beacon, spark)?;
            state.depots[depot].sparks.remove(0);
        }
    }
    Ok(())
}

/// The body of `policy::activate`: select the first matching rule against the
/// committed state, execute against the scratch state, then apply `remember`
/// even when the action failed.
fn run_activation(
    ctx: &mut Ctx<'_, '_>,
    program: &Program,
    state: &State,
    scratch: &mut State,
    index: usize,
    record: &mut Activation,
) -> Result<(), Fault> {
    ctx.meter.charge(Category::Scheduling, 1)?;
    let mut selected = None;
    for (rule_index, rule) in program.rules().iter().enumerate() {
        ctx.meter.charge(Category::Checking, 1)?;
        let mut matches = true;
        for condition in rule.when() {
            if !check_condition(ctx, state, index, *condition)? {
                matches = false;
                break;
            }
        }
        if matches {
            selected = Some((rule_index, rule));
            break;
        }
    }
    record.rule = match selected {
        Some((rule_index, _)) => Some(u8::try_from(rule_index).map_err(|_| RunError::Arithmetic)?),
        None => None,
    };
    record.action = selected.map_or(Action::Wait, |(_, rule)| rule.action());
    let action_result = execute(ctx, scratch, index, record.action);
    if matches!(action_result, Err(Fault::Stop(_)) | Err(Fault::Internal(_))) {
        return action_result;
    }
    if let Some(write) = selected.and_then(|(_, rule)| rule.remember()) {
        ctx.meter.charge(Category::MemoryWrites, 1)?;
        scratch.cells[index].memory[write.slot().index()] = write.value();
        scratch.cells[index].evidence[write.slot().index()] = None;
    }
    action_result
}

fn activate(
    ctx: &mut Ctx<'_, '_>,
    case: &Case,
    program: &Program,
    state: &mut State,
    scratch: &mut State,
    index: usize,
) -> Result<(Activation, Option<Stop>), RunError> {
    let before = state.cells[index].position;
    let work_before = ctx.meter.total()?;
    let mut record = Activation {
        cell: state.cells[index].id,
        rule: None,
        action: Action::Wait,
        success: false,
        error: None,
        position_before: before,
        position_after: before,
        work_before,
        work_after: work_before,
    };
    ctx.meter.begin_activation(case.activation_fuel())?;
    scratch.copy_from(state);
    let signal_start = ctx.signals.len();
    let result = run_activation(ctx, program, state, scratch, index, &mut record);
    ctx.meter.end_activation();
    record.work_after = ctx.meter.total()?;
    match result {
        Err(Fault::Internal(error)) => Err(error),
        Err(Fault::Stop(stop)) => {
            record.error = Some(match stop {
                Stop::Fuel => ActivationError::FuelExhausted,
                Stop::Activation => ActivationError::ActivationLimit,
            });
            ctx.signals.truncate(signal_start);
            Ok((record, Some(stop)))
        }
        Ok(()) => {
            record.success = true;
            record.position_after = scratch.cells[index].position;
            core::mem::swap(state, scratch);
            Ok((record, None))
        }
        Err(Fault::Action(error)) => {
            record.error = Some(ActivationError::Action(error));
            record.position_after = scratch.cells[index].position;
            core::mem::swap(state, scratch);
            Ok((record, None))
        }
    }
}

/// A prepared run with every buffer allocated.
#[derive(Debug)]
pub struct Machine<'a> {
    world: &'a World,
    assignment: &'a Assignment,
    case: &'a Case,
    meter: Meter,
    state: State,
    scratch: State,
    signals: Vec<SignalEvent>,
    activations: Vec<Activation>,
    events: Vec<EventKind>,
    order: Vec<u16>,
    initial_sparks: u32,
    cell_count: u64,
    beacon_count: u64,
    status: RunStatus,
}

impl<'a> Machine<'a> {
    /// Allocates the run state to its static bounds. This is the only
    /// allocating step.
    pub fn new(
        world: &'a World,
        assignment: &'a Assignment,
        case: &'a Case,
    ) -> Result<Self, RunError> {
        if assignment.cells().len() != world.cells().len()
            || assignment
                .cells()
                .iter()
                .zip(world.cells())
                .any(|(id, cell)| *id != cell.id)
        {
            return Err(RunError::AssignmentMismatch);
        }
        let state = State::initial(world);
        let mut scratch = State::allocated(world);
        scratch.copy_from(&state);
        Ok(Self {
            world,
            assignment,
            case,
            meter: Meter::new(case.fuel()),
            state,
            scratch,
            signals: Vec::with_capacity(MAX_SIGNAL_EVENTS_PER_TICK),
            activations: Vec::with_capacity(MAX_CELLS),
            events: Vec::with_capacity(MAX_EVENTS),
            order: Vec::with_capacity(MAX_CELLS),
            initial_sparks: world.initial_sparks(),
            cell_count: count(world.cells().len())?,
            beacon_count: count(world.beacons().len())?,
            status: RunStatus::Complete,
        })
    }

    /// The committed state.
    pub fn state(&self) -> &State {
        &self.state
    }

    fn initial_checking(&self) -> Result<u64, RunError> {
        let world = self.world;
        let entities = [
            world.walls().len(),
            world.cells().len(),
            world.sources().len(),
            world.depots().len(),
            world.beacons().len(),
            world.valves().len(),
            world.links().len(),
            self.case.events().len(),
        ]
        .iter()
        .try_fold(0u64, |sum, len| {
            sum.checked_add(count(*len)?).ok_or(RunError::Arithmetic)
        })?;
        entities
            .checked_add(u64::from(self.initial_sparks))
            .ok_or(RunError::Arithmetic)
    }

    fn schedule(&mut self, tick: u32) {
        let seed = self.case.seed();
        self.order.clear();
        self.order
            .extend(self.state.cells.iter().map(|cell| cell.id));
        self.order
            .sort_unstable_by_key(|id| (mix(seed ^ (u64::from(tick) << 32) ^ u64::from(*id)), *id));
    }

    fn tick(&mut self, tick: u32) -> Result<(), Fault> {
        let Self {
            world,
            assignment,
            case,
            meter,
            state,
            scratch,
            signals,
            activations,
            events,
            order,
            initial_sparks,
            cell_count,
            beacon_count,
            status,
        } = self;
        let mut ctx = Ctx {
            world,
            meter,
            signals,
        };
        ctx.meter.charge(Category::Scheduling, 1)?;
        // Old inboxes are transient; only explicit byte registers keep a value.
        for cell in state.cells.iter_mut() {
            for port in cell.inbox.iter_mut() {
                if let Some(signal) = *port {
                    ctx.meter.charge(Category::Messages, 1)?;
                    ctx.signals.push(SignalEvent {
                        signal,
                        outcome: SignalOutcome::Expired,
                    });
                    *port = None;
                }
            }
        }
        for event in case.events().iter().filter(|event| event.tick == tick) {
            ctx.meter.charge(Category::Checking, 1)?;
            match event.event {
                EventKind::LinkEnabled { id, enabled } => {
                    ctx.meter.charge(Category::Actions, 1)?;
                    state
                        .links
                        .iter_mut()
                        .find(|link| link.id == id)
                        .ok_or(RunError::Invariant)?
                        .enabled = enabled;
                }
                EventKind::ValveEnabled { id, enabled } => {
                    ctx.meter.charge(Category::Actions, 1)?;
                    state
                        .valves
                        .iter_mut()
                        .find(|valve| valve.id == id)
                        .ok_or(RunError::Invariant)?
                        .enabled = enabled;
                }
                EventKind::ClearMemory { cell } => {
                    ctx.meter
                        .charge(Category::MemoryWrites, CLEAR_MEMORY_WRITES)?;
                    let actor = state
                        .cells
                        .iter_mut()
                        .find(|actor| actor.id == cell)
                        .ok_or(RunError::Invariant)?;
                    actor.memory = [0; 4];
                    actor.evidence = [None; 4];
                }
            }
            events.push(event.event);
        }
        // Due signals in queue order; nothing is queued during delivery, so
        // walking the queue equals Platonik's collected id list.
        let mut index = 0usize;
        while index < state.pending.len() {
            if state.pending[index].deliver_tick > tick {
                index = index.checked_add(1).ok_or(Arithmetic)?;
                continue;
            }
            ctx.meter.charge(Category::Messages, 1)?;
            ctx.meter.charge(Category::Checking, 1)?;
            let signal = state.pending.remove(index);
            let enabled = state
                .links
                .iter()
                .find(|link| link.id == signal.link)
                .ok_or(RunError::Invariant)?
                .enabled;
            let recipient = state
                .cells
                .iter()
                .position(|cell| cell.id == signal.to_cell)
                .ok_or(RunError::Invariant)?;
            let adjacent = origin_position(world, state, signal.from)?
                .distance(state.cells[recipient].position)
                == 1;
            let port = signal.to_port.index();
            let outcome = if !enabled {
                SignalOutcome::Disabled
            } else if !adjacent {
                SignalOutcome::NotAdjacent
            } else if state.cells[recipient].inbox[port].is_some() {
                SignalOutcome::Full
            } else {
                state.cells[recipient].inbox[port] = Some(signal);
                SignalOutcome::Delivered
            };
            ctx.signals.push(SignalEvent { signal, outcome });
        }
        for id in order.iter().copied() {
            let index = state
                .cells
                .iter()
                .position(|cell| cell.id == id)
                .ok_or(RunError::Invariant)?;
            let program = assignment
                .programs()
                .get(index)
                .ok_or(RunError::Invariant)?;
            let (record, limit) = activate(&mut ctx, case, program, state, scratch, index)?;
            activations.push(record);
            if let Some(stop) = limit {
                if stop == Stop::Fuel {
                    return Err(Fault::Stop(stop));
                }
                *status = RunStatus::ActivationLimit;
            }
        }
        for (index, beacon) in world.beacons().iter().enumerate() {
            ctx.meter.charge(Category::Checking, 1)?;
            if tick.checked_rem(beacon.drain_every).ok_or(Arithmetic)? == 0 {
                ctx.meter.charge(Category::Draining, 1)?;
                let entry = &mut state.beacons[index];
                let drained = entry.charge.min(beacon.drain_amount);
                entry.charge = entry.charge.checked_sub(drained).ok_or(Arithmetic)?;
                entry.drained = entry.drained.checked_add(drained).ok_or(Arithmetic)?;
                if entry.charge == 0 {
                    entry.exhausted = true;
                }
            }
        }
        // Reserve modeled checking work for identities and beacon energy.
        let end_checking = cell_count
            .checked_add(*beacon_count)
            .and_then(|sum| sum.checked_add(u64::from(*initial_sparks)))
            .ok_or(Arithmetic)?;
        ctx.meter.charge(Category::Checking, end_checking)?;
        Ok(())
    }

    fn outcome(&self) -> Result<Outcome, RunError> {
        let state = &self.state;
        let mut present = 0u64;
        for len in state
            .sources
            .iter()
            .map(|source| source.sparks.len())
            .chain(state.depots.iter().map(|depot| depot.sparks.len()))
            .chain(core::iter::once(
                state
                    .cells
                    .iter()
                    .filter(|cell| cell.cargo.is_some())
                    .count(),
            ))
            .chain(core::iter::once(state.delivered.len()))
        {
            present = present
                .checked_add(count(len)?)
                .ok_or(RunError::Arithmetic)?;
        }
        let all_beacons_positive = state
            .beacons
            .iter()
            .all(|beacon| beacon.charge > 0 && !beacon.exhausted);
        let quotas_met = self
            .world
            .beacons()
            .iter()
            .zip(&state.beacons)
            .all(|(goal, result)| result.delivered >= goal.required_deliveries);
        let conserved = present == u64::from(self.initial_sparks);
        Ok(Outcome {
            all_beacons_positive,
            quotas_met,
            conserved,
            passed: self.status == RunStatus::Complete
                && all_beacons_positive
                && quotas_met
                && conserved,
        })
    }

    /// Runs to the end without allocating, reporting every frame.
    pub fn run<O: Observer>(mut self, observer: &mut O) -> Result<RunResult, RunError> {
        let loading = self.case.loading_work();
        let initial_checking = self.initial_checking()?;
        // Loading charges every declared input byte, then one checking unit
        // per entity and spark; either stop leaves frame 0 incomplete.
        let loaded = match self
            .meter
            .charge(Category::Loading, loading)
            .and_then(|()| self.meter.charge(Category::Checking, initial_checking))
        {
            Ok(()) => true,
            Err(MeterError::Stop(_)) => false,
            Err(MeterError::Arithmetic) => return Err(RunError::Arithmetic),
        };
        self.status = if loaded {
            RunStatus::Complete
        } else {
            RunStatus::FuelExhausted
        };
        observer.frame(&FrameView {
            tick: 0,
            complete: loaded,
            events: &[],
            signals: &[],
            activations: &[],
            state: &self.state,
            ledger: self.meter.ledger(),
        });
        let mut ticks_completed = 0u32;
        if loaded {
            for tick in 1..=self.case.ticks() {
                self.schedule(tick);
                self.state.tick = tick;
                self.signals.clear();
                self.activations.clear();
                self.events.clear();
                let complete = match self.tick(tick) {
                    Ok(()) => true,
                    Err(Fault::Stop(_)) => false,
                    Err(Fault::Internal(error)) => return Err(error),
                    Err(Fault::Action(_)) => return Err(RunError::Invariant),
                };
                observer.frame(&FrameView {
                    tick,
                    complete,
                    events: &self.events,
                    signals: &self.signals,
                    activations: &self.activations,
                    state: &self.state,
                    ledger: self.meter.ledger(),
                });
                if !complete {
                    self.status = RunStatus::FuelExhausted;
                    break;
                }
                ticks_completed = ticks_completed.checked_add(1).ok_or(Arithmetic)?;
            }
        }
        let mut outcome = self.outcome()?;
        outcome.passed &= ticks_completed == self.case.ticks();
        Ok(RunResult {
            status: self.status,
            ticks_completed,
            initial_sparks: self.initial_sparks,
            ledger: *self.meter.ledger(),
            outcome,
            final_state: self.state,
        })
    }
}

/// Prepares and runs one case.
pub fn run<O: Observer>(
    world: &World,
    assignment: &Assignment,
    case: &Case,
    observer: &mut O,
) -> Result<RunResult, RunError> {
    Machine::new(world, assignment, case)?.run(observer)
}
