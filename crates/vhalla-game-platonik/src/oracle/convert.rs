//! Restates a Platonik `Experiment` as a witness `TaskManifest` template plus
//! its `Assignment`, with `loading_work` equal to the compact JSON byte length
//! Platonik charges. Restated from `prototypes/witness-restatement`'s corpus
//! module; never path depended on.

use platonik_core::model as pk;
use vhalla_witness::manifest::{ProgramSlot, TaskManifest, ValidManifest, WorkContract};
use vhalla_witness::model::{
    Action, BitSource, Condition, Direction, MemoryWrite, Port, Program, Relative, Rule, Slot,
    ValveId,
};
use vhalla_witness::world::{
    Beacon, CaseSpec, CellBody, Depot, Endpoint, Event, EventKind, Link, Point, Source, Spark,
    Valve, WorldSpec,
};

use crate::ids::{InnerArtifactId, InnerKind};

/// Why an experiment does not convert.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConvertError {
    /// Not model version 1, or carries construction.
    Version,
    /// The JSON could not be produced.
    Json,
    /// The world, case, or programs failed witness validation.
    Witness(String),
}

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

fn slot(value: u8) -> Option<Slot> {
    Slot::new(value)
}

fn port(value: u8) -> Option<Port> {
    Port::new(value)
}

fn condition(value: &pk::Condition) -> Option<Condition> {
    Some(match *value {
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
            port: port(p)?,
            value,
        },
        pk::Condition::MessageBit { port: p, value } => Condition::MessageBit {
            port: port(p)?,
            value,
        },
        pk::Condition::Memory { slot: s, value } => Condition::Memory {
            slot: slot(s)?,
            value,
        },
        pk::Condition::Heading { direction } => Condition::Heading {
            direction: direction_of(direction),
        },
        _ => return None,
    })
}

fn direction_of(value: pk::Direction) -> Direction {
    direction(value)
}

fn bit_source(value: &pk::BitSource) -> Option<BitSource> {
    Some(match *value {
        pk::BitSource::Constant { value } => BitSource::Constant { value },
        pk::BitSource::Memory { slot: s } => BitSource::Memory { slot: slot(s)? },
        pk::BitSource::Message { port: p } => BitSource::Message { port: port(p)? },
    })
}

fn action(value: &pk::Action) -> Option<Action> {
    Some(match *value {
        pk::Action::Move { direction } => Action::Move {
            direction: relative(direction),
        },
        pk::Action::Turn { direction } => Action::Turn {
            direction: relative(direction),
        },
        pk::Action::Pickup => Action::Pickup,
        pk::Action::Drop => Action::Drop,
        pk::Action::Wait => Action::Wait,
        pk::Action::WriteMemory { slot: s, value } => Action::WriteMemory {
            slot: slot(s)?,
            value,
        },
        pk::Action::TakeMessage { port: p, slot: s } => Action::TakeMessage {
            port: port(p)?,
            slot: slot(s)?,
        },
        pk::Action::Send { port: p, ref bit } => Action::Send {
            port: port(p)?,
            bit: bit_source(bit)?,
        },
        pk::Action::Route { valve, ref bit } => Action::Route {
            valve: ValveId::new(valve),
            bit: bit_source(bit)?,
        },
        _ => return None,
    })
}

/// Converts a v1 program.
pub fn program(value: &pk::Program) -> Result<Program, ConvertError> {
    let mut rules = Vec::with_capacity(value.rules.len());
    for rule in &value.rules {
        let when = rule
            .when
            .iter()
            .map(condition)
            .collect::<Option<Vec<_>>>()
            .ok_or(ConvertError::Version)?;
        let act = action(&rule.action).ok_or(ConvertError::Version)?;
        let remember = match &rule.remember {
            None => None,
            Some(write) => Some(MemoryWrite::new(
                slot(write.slot).ok_or(ConvertError::Version)?,
                write.value,
            )),
        };
        rules.push(
            Rule::new(when, act, remember).map_err(|e| ConvertError::Witness(format!("{e:?}")))?,
        );
    }
    Program::new(rules).map_err(|e| ConvertError::Witness(format!("{e:?}")))
}

fn endpoint(value: &pk::Endpoint) -> Option<Endpoint> {
    Some(match *value {
        pk::Endpoint::Cell { id, port: p } => Endpoint::Cell { id, port: port(p)? },
        pk::Endpoint::Depot { id } => Endpoint::Depot { id },
    })
}

fn event_kind(value: &pk::EventKind) -> Option<EventKind> {
    Some(match *value {
        pk::EventKind::LinkEnabled { id, enabled } => EventKind::LinkEnabled { id, enabled },
        pk::EventKind::ValveEnabled { id, enabled } => EventKind::ValveEnabled { id, enabled },
        pk::EventKind::ClearMemory { cell } => EventKind::ClearMemory { cell },
        _ => return None,
    })
}

/// A converted experiment: the open-slot task the witness corpus carries, the
/// fixed-slot template a `Replay` session hashes as its world digest, the
/// programs, and the inner artifact id of the experiment.
#[derive(Clone, Debug)]
pub struct Converted {
    /// The task as Platonik ran it with every slot open: real seed, real
    /// events, programs supplied as the candidate. Byte-identical to the
    /// witness corpus vectors.
    pub task: TaskManifest,
    /// The `Replay` template: every slot fixed with its program, seed 0, empty
    /// events. Its `ManifestHash` is the world digest.
    pub template: TaskManifest,
    /// `(cell, program)` pairs in ascending cell order.
    pub programs: Vec<(u16, Program)>,
    /// The compact JSON byte length Platonik charges as loading.
    pub loading_work: u64,
    /// `sha256:` of the compact JSON, as Platonik's `experiment_hash`.
    pub experiment: InnerArtifactId,
}

/// Converts a v1 experiment. Every slot is open in the returned manifests so
/// `ValidManifest::assign` takes the programs; a `Replay` session fixes them.
pub fn convert(experiment: &pk::Experiment) -> Result<Converted, ConvertError> {
    if experiment.version != pk::MODEL_VERSION || experiment.construction.is_some() {
        return Err(ConvertError::Version);
    }
    let json = serde_json::to_vec(experiment).map_err(|_| ConvertError::Json)?;
    let loading_work = json.len() as u64;
    let sha256: [u8; 32] = {
        use sha2::{Digest, Sha256};
        Sha256::digest(&json).into()
    };
    let world = WorldSpec {
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
            .map(|link| {
                Some(Link {
                    id: link.id,
                    from: endpoint(&link.from)?,
                    to_cell: link.to_cell,
                    to_port: port(link.to_port)?,
                    delay: link.delay,
                    enabled: link.enabled,
                })
            })
            .collect::<Option<Vec<_>>>()
            .ok_or(ConvertError::Version)?,
    };
    let mut programs: Vec<(u16, Program)> = experiment
        .cells
        .iter()
        .map(|cell| Ok((cell.id, program(&cell.program)?)))
        .collect::<Result<Vec<_>, ConvertError>>()?;
    programs.sort_by_key(|(id, _)| *id);
    let slots: Vec<ProgramSlot> = programs
        .iter()
        .map(|(cell, _)| ProgramSlot {
            cell: *cell,
            fixed: None,
        })
        .collect();
    let case = |seed: u64, events: Vec<Event>| CaseSpec {
        seed,
        ticks: experiment.ticks,
        fuel: experiment.fuel,
        activation_fuel: experiment.activation_fuel,
        events,
        loading_work,
    };
    let events = experiment
        .events
        .iter()
        .map(|event| {
            Some(Event {
                tick: event.tick,
                event: event_kind(&event.event)?,
            })
        })
        .collect::<Option<Vec<_>>>()
        .ok_or(ConvertError::Version)?;
    let contract = WorkContract {
        useful_floor: 0,
        total_ceiling: experiment.fuel,
        require_passed: false,
    };
    let task = TaskManifest {
        world: world.clone(),
        slots: slots.clone(),
        cases: vec![case(experiment.seed, events)],
        contract,
    };
    let template = TaskManifest {
        world,
        slots: programs
            .iter()
            .map(|(cell, program)| ProgramSlot {
                cell: *cell,
                fixed: Some(program.clone()),
            })
            .collect(),
        cases: vec![case(0, Vec::new())],
        contract,
    };
    ValidManifest::validate(task.clone()).map_err(|e| ConvertError::Witness(format!("{e:?}")))?;
    ValidManifest::validate(template.clone())
        .map_err(|e| ConvertError::Witness(format!("{e:?}")))?;
    Ok(Converted {
        task,
        template,
        programs,
        loading_work,
        experiment: InnerArtifactId {
            kind: InnerKind::PlatonikExperimentV1,
            sha256,
        },
    })
}
