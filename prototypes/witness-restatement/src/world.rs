//! The platform-owned world: the Platonik `Experiment` minus cell programs
//! and fuel fields, plus the per-run [`Case`] and the validated
//! [`Assignment`] of programs to cells.
//!
//! Validation restates `sim.rs` `validate_experiment` for version 1 (the
//! JSON byte-length check is the caller's concern: it has no serializer
//! here). Declaration order of every entity list is preserved because the
//! engine iterates cells, links, and beacons in that order, which decides
//! signal event order and where fuel runs out.

use alloc::vec::Vec;

use crate::bounds::*;
use crate::model::{Action, Port, Program};

/// A grid position.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Point {
    /// Column.
    pub x: u8,
    /// Row.
    pub y: u8,
}

impl Point {
    /// Manhattan distance; two `u8` differences never exceed `u16`.
    pub fn distance(self, other: Self) -> u16 {
        u16::from(self.x.abs_diff(other.x)) + u16::from(self.y.abs_diff(other.y))
    }
}

/// A conserved token with a payload bit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Spark {
    /// Globally unique id.
    pub id: u32,
    /// Payload bit.
    pub bit: bool,
}

/// A cell body without its program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CellBody {
    /// Unique among cells.
    pub id: u16,
    /// Initial position.
    pub position: Point,
    /// Initial heading.
    pub heading: crate::model::Direction,
    /// Whether `Move` can succeed.
    pub mobile: bool,
    /// Initial memory.
    pub memory: [u8; 4],
}

/// A spark source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Source {
    /// Unique among sources.
    pub id: u16,
    /// Station position.
    pub position: Point,
    /// Initial sparks, picked up oldest first.
    pub sparks: Vec<Spark>,
}

/// A bounded spark store that reports deposits over links.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Depot {
    /// Unique among depots.
    pub id: u16,
    /// Station position.
    pub position: Point,
    /// Capacity 1..=128.
    pub capacity: u8,
}

/// A charged beacon that accepts sparks of one bit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Beacon {
    /// Unique among beacons.
    pub id: u16,
    /// Station position.
    pub position: Point,
    /// Accepted payload bit.
    pub accepts: bool,
    /// Initial charge 1..=10 000.
    pub initial_charge: u32,
    /// Drain period 1..=128.
    pub drain_every: u32,
    /// Drain amount 1..=1024.
    pub drain_amount: u32,
    /// Charge per delivery 1..=64.
    pub spark_charge: u32,
    /// Quota 0..=128.
    pub required_deliveries: u32,
}

/// A valve that routes a depot's first spark to one of two beacons.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Valve {
    /// Unique among valves.
    pub id: u16,
    /// Station position, adjacent to its depot and both beacons.
    pub position: Point,
    /// Depot id.
    pub depot: u16,
    /// Beacon for bit 0; must not accept.
    pub beacon_zero: u16,
    /// Beacon for bit 1; must accept.
    pub beacon_one: u16,
    /// Initial enabled state.
    pub enabled: bool,
}

/// A link origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endpoint {
    /// A cell's output port.
    Cell {
        /// Cell id.
        id: u16,
        /// Output port.
        port: Port,
    },
    /// A depot's deposit report.
    Depot {
        /// Depot id.
        id: u16,
    },
}

/// A delayed one-bit channel into a cell's inbox port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link {
    /// Unique among links.
    pub id: u16,
    /// Origin.
    pub from: Endpoint,
    /// Recipient cell.
    pub to_cell: u16,
    /// Recipient port.
    pub to_port: Port,
    /// Delay 1..=16.
    pub delay: u32,
    /// Initial enabled state.
    pub enabled: bool,
}

/// A scheduled world change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    /// Enable or disable a link.
    LinkEnabled {
        /// Link id.
        id: u16,
        /// New state.
        enabled: bool,
    },
    /// Enable or disable a valve.
    ValveEnabled {
        /// Valve id.
        id: u16,
        /// New state.
        enabled: bool,
    },
    /// Zero a cell's memory and evidence.
    ClearMemory {
        /// Cell id.
        cell: u16,
    },
}

/// An event at a tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event {
    /// Tick 1..=ticks.
    pub tick: u32,
    /// The change.
    pub event: EventKind,
}

/// Unvalidated world input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorldSpec {
    /// Width 3..=32.
    pub width: u8,
    /// Height 3..=32.
    pub height: u8,
    /// Distinct in-bounds walls.
    pub walls: Vec<Point>,
    /// Sources.
    pub sources: Vec<Source>,
    /// Depots.
    pub depots: Vec<Depot>,
    /// Beacons.
    pub beacons: Vec<Beacon>,
    /// Valves.
    pub valves: Vec<Valve>,
    /// Cell bodies.
    pub cells: Vec<CellBody>,
    /// Links.
    pub links: Vec<Link>,
}

/// Why a world, case, or assignment is invalid; each variant restates one
/// `require` in `sim.rs`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorldError {
    /// Grid dimensions must be 3..=32.
    GridDimensions,
    /// Invalid tick, fuel, or activation budget.
    Budget,
    /// Loading work exceeds the input byte bound.
    LoadingWork,
    /// World entity limits exceeded.
    EntityLimits,
    /// Walls must be distinct in-bounds positions.
    Walls,
    /// Entity ids must be unique within each kind.
    DuplicateId,
    /// Cells need distinct usable positions.
    CellPosition,
    /// Stations need distinct usable positions.
    StationPosition,
    /// Spark ids must be globally unique.
    DuplicateSpark,
    /// At most 128 initial sparks.
    TooManySparks,
    /// Depot capacity must be 1..=128.
    DepotCapacity,
    /// Invalid beacon charge, drain, or quota.
    BeaconParameters,
    /// Valve depot or beacon is missing.
    ValveTarget,
    /// Valve needs an adjacent depot and matching zero/one outlets.
    ValveGeometry,
    /// Link sender, depot, or recipient is missing.
    LinkTarget,
    /// Links require adjacent endpoints and delay 1..=16.
    LinkGeometry,
    /// Event tick is outside the run.
    EventTick,
    /// Event target does not exist.
    EventTarget,
    /// An assignment must name every world cell exactly once, sorted by id.
    AssignmentCells,
    /// A `Route` action names a valve the world does not have.
    UnknownValve,
}

fn unique(ids: impl Iterator<Item = u16> + Clone) -> bool {
    let mut seen: Vec<u16> = Vec::with_capacity(MAX_WALLS);
    ids.into_iter().all(|id| {
        if seen.contains(&id) {
            false
        } else {
            seen.push(id);
            true
        }
    })
}

/// A validated world with private fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct World {
    spec: WorldSpec,
    wall_rows: [u32; 32],
}

impl World {
    /// Validates a world (`validate_experiment` minus programs, budgets,
    /// events, and the JSON byte length).
    pub fn new(spec: WorldSpec) -> Result<Self, WorldError> {
        if !(MIN_SIDE..=MAX_SIDE).contains(&spec.width)
            || !(MIN_SIDE..=MAX_SIDE).contains(&spec.height)
        {
            return Err(WorldError::GridDimensions);
        }
        if spec.walls.len() > MAX_WALLS
            || spec.cells.len() < MIN_CELLS
            || spec.cells.len() > MAX_CELLS
            || spec.sources.len() > MAX_SOURCES
            || spec.depots.len() > MAX_DEPOTS
            || spec.beacons.len() < MIN_BEACONS
            || spec.beacons.len() > MAX_BEACONS
            || spec.valves.len() > MAX_VALVES
            || spec.links.len() > MAX_LINKS
        {
            return Err(WorldError::EntityLimits);
        }
        let on_grid = |point: Point| point.x < spec.width && point.y < spec.height;
        let mut wall_rows = [0u32; 32];
        for point in &spec.walls {
            if !on_grid(*point) {
                return Err(WorldError::Walls);
            }
            let bit = 1u32 << point.x;
            let row = &mut wall_rows[usize::from(point.y)];
            if *row & bit != 0 {
                return Err(WorldError::Walls);
            }
            *row |= bit;
        }
        let usable = |point: Point| {
            on_grid(point) && wall_rows[usize::from(point.y)] & (1u32 << point.x) == 0
        };
        if !(unique(spec.cells.iter().map(|entry| entry.id))
            && unique(spec.sources.iter().map(|entry| entry.id))
            && unique(spec.depots.iter().map(|entry| entry.id))
            && unique(spec.beacons.iter().map(|entry| entry.id))
            && unique(spec.valves.iter().map(|entry| entry.id))
            && unique(spec.links.iter().map(|entry| entry.id)))
        {
            return Err(WorldError::DuplicateId);
        }
        let mut positions: Vec<Point> = Vec::with_capacity(MAX_CELLS);
        for cell in &spec.cells {
            if !usable(cell.position) || positions.contains(&cell.position) {
                return Err(WorldError::CellPosition);
            }
            positions.push(cell.position);
        }
        let mut stations: Vec<Point> =
            Vec::with_capacity(MAX_SOURCES + MAX_DEPOTS + MAX_BEACONS + MAX_VALVES);
        for point in spec
            .sources
            .iter()
            .map(|entry| entry.position)
            .chain(spec.depots.iter().map(|entry| entry.position))
            .chain(spec.beacons.iter().map(|entry| entry.position))
            .chain(spec.valves.iter().map(|entry| entry.position))
        {
            if !usable(point) || stations.contains(&point) {
                return Err(WorldError::StationPosition);
            }
            stations.push(point);
        }
        let mut sparks: Vec<u32> = Vec::with_capacity(MAX_INITIAL_SPARKS);
        for spark in spec.sources.iter().flat_map(|source| &source.sparks) {
            if sparks.contains(&spark.id) {
                return Err(WorldError::DuplicateSpark);
            }
            if sparks.len() >= MAX_INITIAL_SPARKS {
                return Err(WorldError::TooManySparks);
            }
            sparks.push(spark.id);
        }
        for depot in &spec.depots {
            if !(MIN_DEPOT_CAPACITY..=MAX_DEPOT_CAPACITY).contains(&depot.capacity) {
                return Err(WorldError::DepotCapacity);
            }
        }
        for beacon in &spec.beacons {
            if !((MIN_BEACON_CHARGE..=MAX_BEACON_CHARGE).contains(&beacon.initial_charge)
                && (MIN_DRAIN_EVERY..=MAX_DRAIN_EVERY).contains(&beacon.drain_every)
                && (MIN_DRAIN_AMOUNT..=MAX_DRAIN_AMOUNT).contains(&beacon.drain_amount)
                && (MIN_SPARK_CHARGE..=MAX_SPARK_CHARGE).contains(&beacon.spark_charge)
                && beacon.required_deliveries <= MAX_REQUIRED_DELIVERIES)
            {
                return Err(WorldError::BeaconParameters);
            }
        }
        for valve in &spec.valves {
            let depot = spec
                .depots
                .iter()
                .find(|entry| entry.id == valve.depot)
                .ok_or(WorldError::ValveTarget)?;
            let zero = spec
                .beacons
                .iter()
                .find(|entry| entry.id == valve.beacon_zero)
                .ok_or(WorldError::ValveTarget)?;
            let one = spec
                .beacons
                .iter()
                .find(|entry| entry.id == valve.beacon_one)
                .ok_or(WorldError::ValveTarget)?;
            if !(valve.position.distance(depot.position) == 1
                && valve.position.distance(zero.position) == 1
                && valve.position.distance(one.position) == 1
                && !zero.accepts
                && one.accepts)
            {
                return Err(WorldError::ValveGeometry);
            }
        }
        for link in &spec.links {
            let target = spec
                .cells
                .iter()
                .find(|entry| entry.id == link.to_cell)
                .ok_or(WorldError::LinkTarget)?;
            let origin = match link.from {
                Endpoint::Cell { id, .. } => {
                    spec.cells
                        .iter()
                        .find(|entry| entry.id == id)
                        .ok_or(WorldError::LinkTarget)?
                        .position
                }
                Endpoint::Depot { id } => {
                    spec.depots
                        .iter()
                        .find(|entry| entry.id == id)
                        .ok_or(WorldError::LinkTarget)?
                        .position
                }
            };
            if !((MIN_LINK_DELAY..=MAX_LINK_DELAY).contains(&link.delay)
                && origin.distance(target.position) == 1)
            {
                return Err(WorldError::LinkGeometry);
            }
        }
        Ok(Self { spec, wall_rows })
    }

    /// Width.
    pub const fn width(&self) -> u8 {
        self.spec.width
    }
    /// Height.
    pub const fn height(&self) -> u8 {
        self.spec.height
    }
    /// Walls in declaration order.
    pub fn walls(&self) -> &[Point] {
        &self.spec.walls
    }
    /// Whether a point is a wall (`experiment.walls.contains`).
    pub fn is_wall(&self, point: Point) -> bool {
        point.y < MAX_SIDE
            && point.x < MAX_SIDE
            && self.wall_rows[usize::from(point.y)] & (1u32 << point.x) != 0
    }
    /// Sources in declaration order.
    pub fn sources(&self) -> &[Source] {
        &self.spec.sources
    }
    /// Depots in declaration order.
    pub fn depots(&self) -> &[Depot] {
        &self.spec.depots
    }
    /// Beacons in declaration order.
    pub fn beacons(&self) -> &[Beacon] {
        &self.spec.beacons
    }
    /// Valves in declaration order.
    pub fn valves(&self) -> &[Valve] {
        &self.spec.valves
    }
    /// Cell bodies in declaration order.
    pub fn cells(&self) -> &[CellBody] {
        &self.spec.cells
    }
    /// Links in declaration order.
    pub fn links(&self) -> &[Link] {
        &self.spec.links
    }
    /// Initial spark count across sources.
    pub fn initial_sparks(&self) -> u32 {
        let mut count = 0u32;
        for source in &self.spec.sources {
            for _ in &source.sparks {
                count = count.saturating_add(1);
            }
        }
        count
    }
}

/// Unvalidated per-run input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaseSpec {
    /// Activation-order seed.
    pub seed: u64,
    /// Ticks 1..=128.
    pub ticks: u32,
    /// Total fuel 0..=2 000 000.
    pub fuel: u64,
    /// Per-activation fuel 1..=1024.
    pub activation_fuel: u32,
    /// Scheduled events, at most 64, in declaration order.
    pub events: Vec<Event>,
    /// Declared loading work; the Platonik adapter sets it to the JSON byte
    /// length of the original experiment.
    pub loading_work: u64,
}

/// A validated case with private fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Case {
    spec: CaseSpec,
}

impl Case {
    /// Validates budgets and events against a world.
    pub fn new(world: &World, spec: CaseSpec) -> Result<Self, WorldError> {
        if !(MIN_TICKS..=MAX_TICKS).contains(&spec.ticks)
            || spec.fuel > MAX_FUEL
            || !(MIN_ACTIVATION_FUEL..=MAX_ACTIVATION_FUEL).contains(&spec.activation_fuel)
        {
            return Err(WorldError::Budget);
        }
        if spec.loading_work > MAX_LOADING_WORK {
            return Err(WorldError::LoadingWork);
        }
        if spec.events.len() > MAX_EVENTS {
            return Err(WorldError::EntityLimits);
        }
        for event in &spec.events {
            if !(MIN_TICKS..=spec.ticks).contains(&event.tick) {
                return Err(WorldError::EventTick);
            }
            let exists = match event.event {
                EventKind::LinkEnabled { id, .. } => {
                    world.links().iter().any(|entry| entry.id == id)
                }
                EventKind::ValveEnabled { id, .. } => {
                    world.valves().iter().any(|entry| entry.id == id)
                }
                EventKind::ClearMemory { cell } => {
                    world.cells().iter().any(|entry| entry.id == cell)
                }
            };
            if !exists {
                return Err(WorldError::EventTarget);
            }
        }
        Ok(Self { spec })
    }
    /// Seed.
    pub const fn seed(&self) -> u64 {
        self.spec.seed
    }
    /// Ticks.
    pub const fn ticks(&self) -> u32 {
        self.spec.ticks
    }
    /// Fuel.
    pub const fn fuel(&self) -> u64 {
        self.spec.fuel
    }
    /// Per-activation fuel.
    pub const fn activation_fuel(&self) -> u32 {
        self.spec.activation_fuel
    }
    /// Events in declaration order.
    pub fn events(&self) -> &[Event] {
        &self.spec.events
    }
    /// Declared loading work.
    pub const fn loading_work(&self) -> u64 {
        self.spec.loading_work
    }
}

/// Programs for every cell of one world, the only input `run` accepts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assignment {
    /// Indexed like `world.cells()`.
    programs: Vec<Program>,
    /// The cell ids in world order, so `run` can refuse a different world.
    cells: Vec<u16>,
}

impl Assignment {
    /// Validates `(cell id, program)` pairs sorted by cell id that cover every
    /// world cell exactly once, and checks every `Route` valve exists.
    pub fn validate(world: &World, programs: Vec<(u16, Program)>) -> Result<Self, WorldError> {
        if programs.len() != world.cells().len()
            || programs.windows(2).any(|pair| pair[0].0 >= pair[1].0)
        {
            return Err(WorldError::AssignmentCells);
        }
        let mut ordered: Vec<Program> = Vec::with_capacity(MAX_CELLS);
        let mut cells: Vec<u16> = Vec::with_capacity(MAX_CELLS);
        for cell in world.cells() {
            let program = programs
                .iter()
                .find(|(id, _)| *id == cell.id)
                .map(|(_, program)| program)
                .ok_or(WorldError::AssignmentCells)?;
            for rule in program.rules() {
                if let Action::Route { valve, .. } = rule.action() {
                    if !world.valves().iter().any(|entry| entry.id == valve.get()) {
                        return Err(WorldError::UnknownValve);
                    }
                }
            }
            ordered.push(program.clone());
            cells.push(cell.id);
        }
        Ok(Self {
            programs: ordered,
            cells,
        })
    }
    /// Programs in world cell order.
    pub fn programs(&self) -> &[Program] {
        &self.programs
    }
    /// Cell ids in world cell order.
    pub fn cells(&self) -> &[u16] {
        &self.cells
    }
}
