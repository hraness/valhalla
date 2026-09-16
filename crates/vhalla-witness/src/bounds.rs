//! Static bounds of the habitat-v1 model.
//!
//! Every value is copied from `platonik-core` `model.rs` constants or from the
//! ranges checked by `sim.rs` `validate_experiment` and `validate_program` at
//! commit `5eedec07`. Structural bounds are `usize` because they compare with
//! collection lengths; charged quantities never use them directly.

/// Programs need at least one rule (`validate_program`).
pub const MIN_RULES: usize = 1;
/// Programs have at most 32 rules (`validate_program`).
pub const MAX_RULES: usize = 32;
/// A rule has at most eight conditions (`validate_program`).
pub const MAX_CONDITIONS: usize = 8;
/// A cell owns four byte memory slots (`Cell::memory`, `CellState::memory`).
pub const MEMORY_SLOTS: u8 = 4;
/// A cell owns four inbox ports (`CellState::inbox`).
pub const PORTS: u8 = 4;
/// Grid sides are 3..=32 (`validate_experiment`).
pub const MIN_SIDE: u8 = 3;
/// Grid sides are 3..=32 (`validate_experiment`).
pub const MAX_SIDE: u8 = 32;
/// At most 512 walls.
pub const MAX_WALLS: usize = 512;
/// At least one cell.
pub const MIN_CELLS: usize = 1;
/// At most 16 cells.
pub const MAX_CELLS: usize = 16;
/// At most 8 sources.
pub const MAX_SOURCES: usize = 8;
/// At most 8 depots.
pub const MAX_DEPOTS: usize = 8;
/// At least one beacon.
pub const MIN_BEACONS: usize = 1;
/// At most 8 beacons.
pub const MAX_BEACONS: usize = 8;
/// At most 8 valves.
pub const MAX_VALVES: usize = 8;
/// At most 32 links.
pub const MAX_LINKS: usize = 32;
/// At most 64 events.
pub const MAX_EVENTS: usize = 64;
/// At most 128 initial sparks across all sources.
pub const MAX_INITIAL_SPARKS: usize = 128;
/// The pending signal queue holds at most 128 signals (`MAX_PENDING`).
pub const MAX_PENDING: usize = 128;
/// Deliveries consume sparks, so there are never more than the initial sparks.
pub const MAX_DELIVERIES: usize = MAX_INITIAL_SPARKS;
/// Runs last 1..=128 ticks (`MAX_TICKS`).
pub const MIN_TICKS: u32 = 1;
/// Runs last 1..=128 ticks (`MAX_TICKS`).
pub const MAX_TICKS: u32 = 128;
/// Fuel is at most 2 000 000 units (`MAX_FUEL`); zero is allowed.
pub const MAX_FUEL: u64 = 2_000_000;
/// Per-activation fuel is 1..=1024 for v1 (`validate_experiment`).
pub const MIN_ACTIVATION_FUEL: u32 = 1;
/// Per-activation fuel is 1..=1024 for v1 (`validate_experiment`).
pub const MAX_ACTIVATION_FUEL: u32 = 1024;
/// Loading work is bounded by Platonik's `MAX_INPUT_BYTES`.
pub const MAX_LOADING_WORK: u64 = 65_536;
/// Depot capacity is 1..=128.
pub const MIN_DEPOT_CAPACITY: u8 = 1;
/// Depot capacity is 1..=128.
pub const MAX_DEPOT_CAPACITY: u8 = 128;
/// Beacon initial charge is 1..=10 000.
pub const MIN_BEACON_CHARGE: u32 = 1;
/// Beacon initial charge is 1..=10 000.
pub const MAX_BEACON_CHARGE: u32 = 10_000;
/// Beacon drain period is 1..=128 ticks.
pub const MIN_DRAIN_EVERY: u32 = 1;
/// Beacon drain period is 1..=128 ticks.
pub const MAX_DRAIN_EVERY: u32 = MAX_TICKS;
/// Beacon drain amount is 1..=1024.
pub const MIN_DRAIN_AMOUNT: u32 = 1;
/// Beacon drain amount is 1..=1024.
pub const MAX_DRAIN_AMOUNT: u32 = 1024;
/// Beacon spark charge is 1..=64.
pub const MIN_SPARK_CHARGE: u32 = 1;
/// Beacon spark charge is 1..=64.
pub const MAX_SPARK_CHARGE: u32 = 64;
/// Beacon quota is at most 128 deliveries.
pub const MAX_REQUIRED_DELIVERIES: u32 = 128;
/// Link delay is 1..=16 ticks.
pub const MIN_LINK_DELAY: u32 = 1;
/// Link delay is 1..=16 ticks.
pub const MAX_LINK_DELAY: u32 = 16;
/// A `ClearMemory` event charges one memory write per slot (`sim.rs`).
pub const CLEAR_MEMORY_WRITES: u64 = 4;
/// Signal events recorded in one tick: every inbox port can expire, every
/// pending signal can be delivered, and every activation emits over at most
/// every link or consumes one message.
pub const MAX_SIGNAL_EVENTS_PER_TICK: usize =
    MAX_CELLS * PORTS as usize + MAX_PENDING + MAX_CELLS * MAX_LINKS;
