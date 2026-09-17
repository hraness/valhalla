//! The bit-exact comparison against the pinned Platonik engine: the reverse
//! mapping from restated results to Platonik frames, and `assert_parity`.
#![allow(dead_code)]

use platonik_core::model as pk;
#[allow(unused_imports)]
pub use witness_restatement::corpus::{
    convert, program, random_experiment, worst_case, Converted, Rng, PROTOCOL,
};
use witness_restatement::ledger::Ledger;
use witness_restatement::model::{Action, BitSource, Direction, Relative};
use witness_restatement::vm::{
    self, ActionError, Activation, ActivationError, CellState, FrameView, Observer, RunResult,
    RunStatus, Signal, SignalEvent, SignalOutcome, State,
};
use witness_restatement::world::{Endpoint, EventKind, Point, Spark};

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
