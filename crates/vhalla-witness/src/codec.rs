//! Canonical binary encoding of every value that crosses a boundary.
//!
//! Fixed-width big-endian integers, `u8` counts bounded before use, `u8`
//! discriminants with 0 reserved, `Option` as a 0 or 1 tag byte, booleans as
//! exactly 0 or 1, no floats, no strings. Every decoder checks the total size
//! bound first, then the version and language bytes, reads with bounds-checked
//! slices, and rejects trailing bytes. `decode(encode(x)) == x` and
//! `encode(decode(raw)) == raw` are laws checked in the tests.

use alloc::vec::Vec;

use crate::bounds::*;
use crate::ledger::Ledger;
use crate::manifest::{ProgramSlot, TaskManifest, WorkContract};
use crate::model::{
    Action, BitSource, Condition, Direction, MemoryWrite, ModelError, Port, Program, Relative,
    Rule, Slot, ValveId,
};
use crate::platform::CaseResult;
use crate::vm::{
    BeaconState, CellState, Delivery, DepotState, EnabledState, Outcome, RunStatus, Signal,
    SourceState, State,
};
use crate::world::{
    Assignment, Beacon, CaseSpec, CellBody, Depot, Endpoint, Event, EventKind, Link, Point, Source,
    Spark, Valve, WorldSpec,
};

/// Encoding version byte; moves together with every domain tag.
pub const VERSION: u8 = 1;
/// The only admitted language: habitat-v1 finite-rule programs.
pub const LANGUAGE_FINITE_RULE_V1: u8 = 1;

/// Widest condition: tag plus two one-byte fields.
const MAX_CONDITION_BYTES: usize = 3;
/// Widest action: `Route` is a tag, a `u16` valve, and a two-byte `BitSource`.
const MAX_ACTION_BYTES: usize = 5;
/// Widest rule: count, eight conditions, an action, and a present `remember`.
const MAX_RULE_BYTES: usize = 1 + MAX_CONDITIONS * MAX_CONDITION_BYTES + MAX_ACTION_BYTES + 3;
/// A program body: rule count then rules.
const MAX_PROGRAM_BODY_BYTES: usize = 1 + MAX_RULES * MAX_RULE_BYTES;
/// A standalone program: version, language, body.
pub const MAX_PROGRAM_BYTES: usize = 2 + MAX_PROGRAM_BODY_BYTES;
/// An assignment: version, language, count, then `(cell id, body)` pairs.
pub const MAX_ASSIGNMENT_BYTES: usize = 3 + MAX_CELLS * (2 + MAX_PROGRAM_BODY_BYTES);
const MAX_SPARK_BYTES: usize = 5;
const MAX_WORLD_BYTES: usize = 2
    + (2 + MAX_WALLS * 2)
    + (1 + MAX_SOURCES * 5 + MAX_INITIAL_SPARKS * MAX_SPARK_BYTES)
    + (1 + MAX_DEPOTS * 5)
    + (1 + MAX_BEACONS * 25)
    + (1 + MAX_VALVES * 11)
    + (1 + MAX_CELLS * 10)
    + (1 + MAX_LINKS * 14);
const MAX_EVENT_BYTES: usize = 4 + 1 + 3;
const MAX_CASE_BYTES: usize = 8 + 4 + 8 + 4 + 1 + MAX_EVENTS * MAX_EVENT_BYTES + 8;
/// A manifest: version, language, world, slots, cases, contract.
pub const MAX_MANIFEST_BYTES: usize = 2
    + MAX_WORLD_BYTES
    + (1 + MAX_CELLS * (3 + MAX_PROGRAM_BODY_BYTES))
    + (1 + MAX_CASES * MAX_CASE_BYTES)
    + 17;
/// At most eight cases per manifest.
pub const MAX_CASES: usize = 8;
/// One signal: id, link, endpoint, target, port, bit, two ticks, receipt spark.
const SIGNAL_BYTES: usize = 8 + 2 + 4 + 2 + 1 + 1 + 4 + 4 + 5;
/// A final state encoding bound; asserted against every corpus state in tests.
pub const MAX_STATE_BYTES: usize = 4
    + (1 + MAX_CELLS * (2 + 2 + 1 + 4 + 4 * 5 + 6 + 4 * (1 + SIGNAL_BYTES)))
    + (1 + MAX_SOURCES * 3 + MAX_INITIAL_SPARKS * MAX_SPARK_BYTES)
    + (1 + MAX_DEPOTS * 3 + MAX_INITIAL_SPARKS * MAX_SPARK_BYTES)
    + (1 + MAX_BEACONS * 15)
    + (1 + MAX_VALVES * 3)
    + (1 + MAX_LINKS * 3)
    + (1 + MAX_PENDING * SIGNAL_BYTES)
    + (1 + MAX_DELIVERIES * 11)
    + 8;
/// Thirteen `u64` counters.
pub const LEDGER_BYTES: usize = 13 * 8;
/// One case result: status, ticks, four outcome flags, state hash, ledger, useful.
pub const CASE_RESULT_BYTES: usize = 1 + 4 + 4 + 32 + LEDGER_BYTES + 8;

/// Fields a truncated or malformed input can fail on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Field {
    Version,
    Language,
    Count,
    Bool,
    Slot,
    Port,
    Valve,
    Value,
    Direction,
    Relative,
    Condition,
    Action,
    BitSource,
    Remember,
    CellId,
    Point,
    Spark,
    Source,
    Depot,
    Beacon,
    ValveSpec,
    Cell,
    Link,
    Endpoint,
    Event,
    Case,
    Contract,
    Status,
    Hash,
    Ledger,
}

/// Stable failures of the bounded decoders.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodecError {
    /// The input exceeds the type's byte bound.
    TooLarge {
        /// Bytes supplied.
        actual: usize,
        /// Bytes accepted.
        limit: usize,
    },
    /// The input ended inside the named field.
    Truncated {
        /// Field that could not be read completely.
        field: Field,
    },
    /// Bytes remain after the complete value.
    TrailingBytes {
        /// Number of extra bytes.
        count: usize,
    },
    /// The version byte is not [`VERSION`].
    UnsupportedVersion {
        /// Version byte found.
        found: u8,
    },
    /// The language byte is not [`LANGUAGE_FINITE_RULE_V1`].
    UnsupportedLanguage {
        /// Language byte found.
        found: u8,
    },
    /// A discriminant, tag, or boolean byte is outside its closed set.
    Discriminant {
        /// Field the byte belongs to.
        field: Field,
        /// Byte found.
        found: u8,
    },
    /// A count or index exceeds its static bound.
    Bound {
        /// Field the value belongs to.
        field: Field,
    },
    /// Identifiers that must be strictly ascending are not.
    Unsorted {
        /// Field the identifiers belong to.
        field: Field,
    },
    /// The decoded value violates a program structure rule.
    Model(ModelError),
}

impl From<ModelError> for CodecError {
    fn from(error: ModelError) -> Self {
        Self::Model(error)
    }
}

/// Appends fixed-width big-endian fields.
#[derive(Debug, Default)]
pub struct Writer {
    out: Vec<u8>,
}

impl Writer {
    /// A writer with room for `capacity` bytes.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            out: Vec::with_capacity(capacity),
        }
    }
    /// The bytes written so far.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.out
    }
    /// Bytes written so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.out.len()
    }
    /// Whether nothing has been written.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.out.is_empty()
    }
    /// One byte.
    pub fn u8(&mut self, value: u8) {
        self.out.push(value);
    }
    /// Two bytes, big-endian.
    pub fn u16(&mut self, value: u16) {
        self.out.extend_from_slice(&value.to_be_bytes());
    }
    /// Four bytes, big-endian.
    pub fn u32(&mut self, value: u32) {
        self.out.extend_from_slice(&value.to_be_bytes());
    }
    /// Eight bytes, big-endian.
    pub fn u64(&mut self, value: u64) {
        self.out.extend_from_slice(&value.to_be_bytes());
    }
    /// Exactly 0 or 1.
    pub fn bool(&mut self, value: bool) {
        self.out.push(u8::from(value));
    }
    /// Raw bytes (a digest).
    pub fn bytes(&mut self, value: &[u8]) {
        self.out.extend_from_slice(value);
    }
}

/// Reads fixed-width big-endian fields with bounds checks.
#[derive(Debug)]
pub struct Reader<'a> {
    raw: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// A reader over `raw` after checking it is at most `limit` bytes.
    pub fn bounded(raw: &'a [u8], limit: usize) -> Result<Self, CodecError> {
        if raw.len() > limit {
            return Err(CodecError::TooLarge {
                actual: raw.len(),
                limit,
            });
        }
        Ok(Self { raw, pos: 0 })
    }
    fn take(&mut self, len: usize, field: Field) -> Result<&'a [u8], CodecError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(CodecError::Truncated { field })?;
        let bytes = self
            .raw
            .get(self.pos..end)
            .ok_or(CodecError::Truncated { field })?;
        self.pos = end;
        Ok(bytes)
    }
    /// One byte.
    pub fn u8(&mut self, field: Field) -> Result<u8, CodecError> {
        Ok(self.take(1, field)?[0])
    }
    /// Two bytes, big-endian.
    pub fn u16(&mut self, field: Field) -> Result<u16, CodecError> {
        let bytes = self.take(2, field)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
    /// Four bytes, big-endian.
    pub fn u32(&mut self, field: Field) -> Result<u32, CodecError> {
        let bytes = self.take(4, field)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
    /// Eight bytes, big-endian.
    pub fn u64(&mut self, field: Field) -> Result<u64, CodecError> {
        let bytes = self.take(8, field)?;
        let mut value = [0_u8; 8];
        value.copy_from_slice(bytes);
        Ok(u64::from_be_bytes(value))
    }
    /// Exactly 0 or 1.
    pub fn bool(&mut self, field: Field) -> Result<bool, CodecError> {
        match self.u8(field)? {
            0 => Ok(false),
            1 => Ok(true),
            found => Err(CodecError::Discriminant { field, found }),
        }
    }
    /// A 32-byte digest.
    pub fn hash(&mut self) -> Result<[u8; 32], CodecError> {
        let bytes = self.take(32, Field::Hash)?;
        let mut value = [0_u8; 32];
        value.copy_from_slice(bytes);
        Ok(value)
    }
    /// A count at most `limit`.
    pub fn count(&mut self, limit: usize, field: Field) -> Result<usize, CodecError> {
        let count = usize::from(self.u8(field)?);
        if count > limit {
            return Err(CodecError::Bound { field });
        }
        Ok(count)
    }
    /// Rejects any byte after the complete value.
    pub fn finish(self) -> Result<(), CodecError> {
        let count = self.raw.len().saturating_sub(self.pos);
        if count > 0 {
            return Err(CodecError::TrailingBytes { count });
        }
        Ok(())
    }
}

fn header(reader: &mut Reader<'_>) -> Result<(), CodecError> {
    let found = reader.u8(Field::Version)?;
    if found != VERSION {
        return Err(CodecError::UnsupportedVersion { found });
    }
    let found = reader.u8(Field::Language)?;
    if found != LANGUAGE_FINITE_RULE_V1 {
        return Err(CodecError::UnsupportedLanguage { found });
    }
    Ok(())
}

fn direction_tag(direction: Direction) -> u8 {
    match direction {
        Direction::North => 1,
        Direction::East => 2,
        Direction::South => 3,
        Direction::West => 4,
    }
}

fn direction(reader: &mut Reader<'_>) -> Result<Direction, CodecError> {
    Ok(match reader.u8(Field::Direction)? {
        1 => Direction::North,
        2 => Direction::East,
        3 => Direction::South,
        4 => Direction::West,
        found => {
            return Err(CodecError::Discriminant {
                field: Field::Direction,
                found,
            })
        }
    })
}

fn relative_tag(relative: Relative) -> u8 {
    match relative {
        Relative::Forward => 1,
        Relative::Left => 2,
        Relative::Right => 3,
        Relative::Back => 4,
    }
}

fn relative(reader: &mut Reader<'_>) -> Result<Relative, CodecError> {
    Ok(match reader.u8(Field::Relative)? {
        1 => Relative::Forward,
        2 => Relative::Left,
        3 => Relative::Right,
        4 => Relative::Back,
        found => {
            return Err(CodecError::Discriminant {
                field: Field::Relative,
                found,
            })
        }
    })
}

fn slot(reader: &mut Reader<'_>) -> Result<Slot, CodecError> {
    Slot::new(reader.u8(Field::Slot)?).ok_or(CodecError::Bound { field: Field::Slot })
}

fn port(reader: &mut Reader<'_>) -> Result<Port, CodecError> {
    Port::new(reader.u8(Field::Port)?).ok_or(CodecError::Bound { field: Field::Port })
}

fn put_condition(writer: &mut Writer, condition: Condition) {
    match condition {
        Condition::Carrying { value } => {
            writer.u8(1);
            writer.bool(value);
        }
        Condition::AtSource { value } => {
            writer.u8(2);
            writer.bool(value);
        }
        Condition::AtDepot { value } => {
            writer.u8(3);
            writer.bool(value);
        }
        Condition::AtBeacon { value } => {
            writer.u8(4);
            writer.bool(value);
        }
        Condition::AtReceiver { value } => {
            writer.u8(5);
            writer.bool(value);
        }
        Condition::Blocked { direction, value } => {
            writer.u8(6);
            writer.u8(relative_tag(direction));
            writer.bool(value);
        }
        Condition::HasMessage { port, value } => {
            writer.u8(7);
            writer.u8(port.get());
            writer.bool(value);
        }
        Condition::MessageBit { port, value } => {
            writer.u8(8);
            writer.u8(port.get());
            writer.bool(value);
        }
        Condition::Memory { slot, value } => {
            writer.u8(9);
            writer.u8(slot.get());
            writer.u8(value);
        }
        Condition::Heading { direction } => {
            writer.u8(10);
            writer.u8(direction_tag(direction));
        }
    }
}

fn get_condition(reader: &mut Reader<'_>) -> Result<Condition, CodecError> {
    Ok(match reader.u8(Field::Condition)? {
        1 => Condition::Carrying {
            value: reader.bool(Field::Bool)?,
        },
        2 => Condition::AtSource {
            value: reader.bool(Field::Bool)?,
        },
        3 => Condition::AtDepot {
            value: reader.bool(Field::Bool)?,
        },
        4 => Condition::AtBeacon {
            value: reader.bool(Field::Bool)?,
        },
        5 => Condition::AtReceiver {
            value: reader.bool(Field::Bool)?,
        },
        6 => Condition::Blocked {
            direction: relative(reader)?,
            value: reader.bool(Field::Bool)?,
        },
        7 => Condition::HasMessage {
            port: port(reader)?,
            value: reader.bool(Field::Bool)?,
        },
        8 => Condition::MessageBit {
            port: port(reader)?,
            value: reader.bool(Field::Bool)?,
        },
        9 => Condition::Memory {
            slot: slot(reader)?,
            value: reader.u8(Field::Value)?,
        },
        10 => Condition::Heading {
            direction: direction(reader)?,
        },
        found => {
            return Err(CodecError::Discriminant {
                field: Field::Condition,
                found,
            })
        }
    })
}

fn put_bit_source(writer: &mut Writer, bit: BitSource) {
    match bit {
        BitSource::Constant { value } => {
            writer.u8(1);
            writer.bool(value);
        }
        BitSource::Memory { slot } => {
            writer.u8(2);
            writer.u8(slot.get());
        }
        BitSource::Message { port } => {
            writer.u8(3);
            writer.u8(port.get());
        }
    }
}

fn get_bit_source(reader: &mut Reader<'_>) -> Result<BitSource, CodecError> {
    Ok(match reader.u8(Field::BitSource)? {
        1 => BitSource::Constant {
            value: reader.bool(Field::Bool)?,
        },
        2 => BitSource::Memory {
            slot: slot(reader)?,
        },
        3 => BitSource::Message {
            port: port(reader)?,
        },
        found => {
            return Err(CodecError::Discriminant {
                field: Field::BitSource,
                found,
            })
        }
    })
}

fn put_action(writer: &mut Writer, action: Action) {
    match action {
        Action::Move { direction } => {
            writer.u8(1);
            writer.u8(relative_tag(direction));
        }
        Action::Turn { direction } => {
            writer.u8(2);
            writer.u8(relative_tag(direction));
        }
        Action::Pickup => writer.u8(3),
        Action::Drop => writer.u8(4),
        Action::Wait => writer.u8(5),
        Action::WriteMemory { slot, value } => {
            writer.u8(6);
            writer.u8(slot.get());
            writer.u8(value);
        }
        Action::TakeMessage { port, slot } => {
            writer.u8(7);
            writer.u8(port.get());
            writer.u8(slot.get());
        }
        Action::Send { port, bit } => {
            writer.u8(8);
            writer.u8(port.get());
            put_bit_source(writer, bit);
        }
        Action::Route { valve, bit } => {
            writer.u8(9);
            writer.u16(valve.get());
            put_bit_source(writer, bit);
        }
    }
}

fn get_action(reader: &mut Reader<'_>) -> Result<Action, CodecError> {
    Ok(match reader.u8(Field::Action)? {
        1 => Action::Move {
            direction: relative(reader)?,
        },
        2 => Action::Turn {
            direction: relative(reader)?,
        },
        3 => Action::Pickup,
        4 => Action::Drop,
        5 => Action::Wait,
        6 => Action::WriteMemory {
            slot: slot(reader)?,
            value: reader.u8(Field::Value)?,
        },
        7 => Action::TakeMessage {
            port: port(reader)?,
            slot: slot(reader)?,
        },
        8 => Action::Send {
            port: port(reader)?,
            bit: get_bit_source(reader)?,
        },
        9 => Action::Route {
            valve: ValveId::new(reader.u16(Field::Valve)?),
            bit: get_bit_source(reader)?,
        },
        found => {
            return Err(CodecError::Discriminant {
                field: Field::Action,
                found,
            })
        }
    })
}

fn put_program_body(writer: &mut Writer, program: &Program) {
    writer.u8(program.rules().len() as u8);
    for rule in program.rules() {
        writer.u8(rule.when().len() as u8);
        for condition in rule.when() {
            put_condition(writer, *condition);
        }
        put_action(writer, rule.action());
        match rule.remember() {
            None => writer.u8(0),
            Some(write) => {
                writer.u8(1);
                writer.u8(write.slot().get());
                writer.u8(write.value());
            }
        }
    }
}

fn get_program_body(reader: &mut Reader<'_>) -> Result<Program, CodecError> {
    let rule_count = reader.count(MAX_RULES, Field::Count)?;
    let mut rules = Vec::with_capacity(rule_count);
    for _ in 0..rule_count {
        let condition_count = reader.count(MAX_CONDITIONS, Field::Count)?;
        let mut when = Vec::with_capacity(condition_count);
        for _ in 0..condition_count {
            when.push(get_condition(reader)?);
        }
        let action = get_action(reader)?;
        let remember = match reader.u8(Field::Remember)? {
            0 => None,
            1 => Some(MemoryWrite::new(slot(reader)?, reader.u8(Field::Value)?)),
            found => {
                return Err(CodecError::Discriminant {
                    field: Field::Remember,
                    found,
                })
            }
        };
        rules.push(Rule::new(when, action, remember)?);
    }
    Ok(Program::new(rules)?)
}

/// A standalone program: version, language, body.
#[must_use]
pub fn encode_program(program: &Program) -> Vec<u8> {
    let mut writer = Writer::with_capacity(MAX_PROGRAM_BYTES);
    writer.u8(VERSION);
    writer.u8(LANGUAGE_FINITE_RULE_V1);
    put_program_body(&mut writer, program);
    writer.finish()
}

/// Decodes a standalone program.
pub fn decode_program(raw: &[u8]) -> Result<Program, CodecError> {
    let mut reader = Reader::bounded(raw, MAX_PROGRAM_BYTES)?;
    header(&mut reader)?;
    let program = get_program_body(&mut reader)?;
    reader.finish()?;
    Ok(program)
}

/// The candidate programs: version, language, count, then `(cell id, body)`
/// pairs in strictly ascending cell order. `ProgramHash` is over these bytes.
#[must_use]
pub fn encode_assignment(assignment: &Assignment) -> Vec<u8> {
    encode_candidate(
        &assignment
            .cells()
            .iter()
            .copied()
            .zip(assignment.programs().iter().cloned())
            .collect::<Vec<_>>(),
    )
}

/// Encodes `(cell id, program)` pairs that are already sorted; used for both
/// validated assignments and candidate programs for open slots.
#[must_use]
pub fn encode_candidate(programs: &[(u16, Program)]) -> Vec<u8> {
    let mut writer = Writer::with_capacity(MAX_ASSIGNMENT_BYTES);
    writer.u8(VERSION);
    writer.u8(LANGUAGE_FINITE_RULE_V1);
    writer.u8(programs.len() as u8);
    for (cell, program) in programs {
        writer.u16(*cell);
        put_program_body(&mut writer, program);
    }
    writer.finish()
}

/// Decodes candidate `(cell id, program)` pairs; they are data until
/// `ValidManifest::assign` binds them to a manifest.
pub fn decode_candidate(raw: &[u8]) -> Result<Vec<(u16, Program)>, CodecError> {
    let mut reader = Reader::bounded(raw, MAX_ASSIGNMENT_BYTES)?;
    header(&mut reader)?;
    let count = reader.count(MAX_CELLS, Field::Count)?;
    let mut programs = Vec::with_capacity(count);
    let mut previous: Option<u16> = None;
    for _ in 0..count {
        let cell = reader.u16(Field::CellId)?;
        if previous.is_some_and(|last| cell <= last) {
            return Err(CodecError::Unsorted {
                field: Field::CellId,
            });
        }
        previous = Some(cell);
        programs.push((cell, get_program_body(&mut reader)?));
    }
    reader.finish()?;
    Ok(programs)
}

fn put_point(writer: &mut Writer, point: Point) {
    writer.u8(point.x);
    writer.u8(point.y);
}

fn get_point(reader: &mut Reader<'_>) -> Result<Point, CodecError> {
    Ok(Point {
        x: reader.u8(Field::Point)?,
        y: reader.u8(Field::Point)?,
    })
}

fn put_spark(writer: &mut Writer, spark: Spark) {
    writer.u32(spark.id);
    writer.bool(spark.bit);
}

fn get_spark(reader: &mut Reader<'_>) -> Result<Spark, CodecError> {
    Ok(Spark {
        id: reader.u32(Field::Spark)?,
        bit: reader.bool(Field::Spark)?,
    })
}

fn put_endpoint(writer: &mut Writer, endpoint: Endpoint) {
    match endpoint {
        Endpoint::Cell { id, port } => {
            writer.u8(1);
            writer.u16(id);
            writer.u8(port.get());
        }
        Endpoint::Depot { id } => {
            writer.u8(2);
            writer.u16(id);
        }
    }
}

fn get_endpoint(reader: &mut Reader<'_>) -> Result<Endpoint, CodecError> {
    Ok(match reader.u8(Field::Endpoint)? {
        1 => Endpoint::Cell {
            id: reader.u16(Field::CellId)?,
            port: port(reader)?,
        },
        2 => Endpoint::Depot {
            id: reader.u16(Field::Depot)?,
        },
        found => {
            return Err(CodecError::Discriminant {
                field: Field::Endpoint,
                found,
            })
        }
    })
}

fn put_world(writer: &mut Writer, world: &WorldSpec) {
    writer.u8(world.width);
    writer.u8(world.height);
    writer.u16(world.walls.len() as u16);
    for wall in &world.walls {
        put_point(writer, *wall);
    }
    writer.u8(world.sources.len() as u8);
    for source in &world.sources {
        writer.u16(source.id);
        put_point(writer, source.position);
        writer.u8(source.sparks.len() as u8);
        for spark in &source.sparks {
            put_spark(writer, *spark);
        }
    }
    writer.u8(world.depots.len() as u8);
    for depot in &world.depots {
        writer.u16(depot.id);
        put_point(writer, depot.position);
        writer.u8(depot.capacity);
    }
    writer.u8(world.beacons.len() as u8);
    for beacon in &world.beacons {
        writer.u16(beacon.id);
        put_point(writer, beacon.position);
        writer.bool(beacon.accepts);
        writer.u32(beacon.initial_charge);
        writer.u32(beacon.drain_every);
        writer.u32(beacon.drain_amount);
        writer.u32(beacon.spark_charge);
        writer.u32(beacon.required_deliveries);
    }
    writer.u8(world.valves.len() as u8);
    for valve in &world.valves {
        writer.u16(valve.id);
        put_point(writer, valve.position);
        writer.u16(valve.depot);
        writer.u16(valve.beacon_zero);
        writer.u16(valve.beacon_one);
        writer.bool(valve.enabled);
    }
    writer.u8(world.cells.len() as u8);
    for cell in &world.cells {
        writer.u16(cell.id);
        put_point(writer, cell.position);
        writer.u8(direction_tag(cell.heading));
        writer.bool(cell.mobile);
        writer.bytes(&cell.memory);
    }
    writer.u8(world.links.len() as u8);
    for link in &world.links {
        writer.u16(link.id);
        put_endpoint(writer, link.from);
        writer.u16(link.to_cell);
        writer.u8(link.to_port.get());
        writer.u32(link.delay);
        writer.bool(link.enabled);
    }
}

fn get_world(reader: &mut Reader<'_>) -> Result<WorldSpec, CodecError> {
    let width = reader.u8(Field::Point)?;
    let height = reader.u8(Field::Point)?;
    let wall_count = usize::from(reader.u16(Field::Count)?);
    if wall_count > MAX_WALLS {
        return Err(CodecError::Bound {
            field: Field::Count,
        });
    }
    let mut walls = Vec::with_capacity(wall_count);
    for _ in 0..wall_count {
        walls.push(get_point(reader)?);
    }
    let count = reader.count(MAX_SOURCES, Field::Count)?;
    let mut sources = Vec::with_capacity(count);
    let mut spark_total = 0_usize;
    for _ in 0..count {
        let id = reader.u16(Field::Source)?;
        let position = get_point(reader)?;
        let spark_count = reader.count(MAX_INITIAL_SPARKS, Field::Count)?;
        spark_total = spark_total.saturating_add(spark_count);
        if spark_total > MAX_INITIAL_SPARKS {
            return Err(CodecError::Bound {
                field: Field::Spark,
            });
        }
        let mut sparks = Vec::with_capacity(spark_count);
        for _ in 0..spark_count {
            sparks.push(get_spark(reader)?);
        }
        sources.push(Source {
            id,
            position,
            sparks,
        });
    }
    let count = reader.count(MAX_DEPOTS, Field::Count)?;
    let mut depots = Vec::with_capacity(count);
    for _ in 0..count {
        depots.push(Depot {
            id: reader.u16(Field::Depot)?,
            position: get_point(reader)?,
            capacity: reader.u8(Field::Depot)?,
        });
    }
    let count = reader.count(MAX_BEACONS, Field::Count)?;
    let mut beacons = Vec::with_capacity(count);
    for _ in 0..count {
        beacons.push(Beacon {
            id: reader.u16(Field::Beacon)?,
            position: get_point(reader)?,
            accepts: reader.bool(Field::Beacon)?,
            initial_charge: reader.u32(Field::Beacon)?,
            drain_every: reader.u32(Field::Beacon)?,
            drain_amount: reader.u32(Field::Beacon)?,
            spark_charge: reader.u32(Field::Beacon)?,
            required_deliveries: reader.u32(Field::Beacon)?,
        });
    }
    let count = reader.count(MAX_VALVES, Field::Count)?;
    let mut valves = Vec::with_capacity(count);
    for _ in 0..count {
        valves.push(Valve {
            id: reader.u16(Field::ValveSpec)?,
            position: get_point(reader)?,
            depot: reader.u16(Field::ValveSpec)?,
            beacon_zero: reader.u16(Field::ValveSpec)?,
            beacon_one: reader.u16(Field::ValveSpec)?,
            enabled: reader.bool(Field::ValveSpec)?,
        });
    }
    let count = reader.count(MAX_CELLS, Field::Count)?;
    let mut cells = Vec::with_capacity(count);
    for _ in 0..count {
        let id = reader.u16(Field::Cell)?;
        let position = get_point(reader)?;
        let heading = direction(reader)?;
        let mobile = reader.bool(Field::Cell)?;
        let mut memory = [0_u8; 4];
        for slot in &mut memory {
            *slot = reader.u8(Field::Cell)?;
        }
        cells.push(CellBody {
            id,
            position,
            heading,
            mobile,
            memory,
        });
    }
    let count = reader.count(MAX_LINKS, Field::Count)?;
    let mut links = Vec::with_capacity(count);
    for _ in 0..count {
        links.push(Link {
            id: reader.u16(Field::Link)?,
            from: get_endpoint(reader)?,
            to_cell: reader.u16(Field::Link)?,
            to_port: port(reader)?,
            delay: reader.u32(Field::Link)?,
            enabled: reader.bool(Field::Link)?,
        });
    }
    Ok(WorldSpec {
        width,
        height,
        walls,
        sources,
        depots,
        beacons,
        valves,
        cells,
        links,
    })
}

fn put_case(writer: &mut Writer, case: &CaseSpec) {
    writer.u64(case.seed);
    writer.u32(case.ticks);
    writer.u64(case.fuel);
    writer.u32(case.activation_fuel);
    writer.u8(case.events.len() as u8);
    for event in &case.events {
        writer.u32(event.tick);
        match event.event {
            EventKind::LinkEnabled { id, enabled } => {
                writer.u8(1);
                writer.u16(id);
                writer.bool(enabled);
            }
            EventKind::ValveEnabled { id, enabled } => {
                writer.u8(2);
                writer.u16(id);
                writer.bool(enabled);
            }
            EventKind::ClearMemory { cell } => {
                writer.u8(3);
                writer.u16(cell);
            }
        }
    }
    writer.u64(case.loading_work);
}

fn get_case(reader: &mut Reader<'_>) -> Result<CaseSpec, CodecError> {
    let seed = reader.u64(Field::Case)?;
    let ticks = reader.u32(Field::Case)?;
    let fuel = reader.u64(Field::Case)?;
    let activation_fuel = reader.u32(Field::Case)?;
    let count = reader.count(MAX_EVENTS, Field::Count)?;
    let mut events = Vec::with_capacity(count);
    for _ in 0..count {
        let tick = reader.u32(Field::Event)?;
        let event = match reader.u8(Field::Event)? {
            1 => EventKind::LinkEnabled {
                id: reader.u16(Field::Event)?,
                enabled: reader.bool(Field::Event)?,
            },
            2 => EventKind::ValveEnabled {
                id: reader.u16(Field::Event)?,
                enabled: reader.bool(Field::Event)?,
            },
            3 => EventKind::ClearMemory {
                cell: reader.u16(Field::Event)?,
            },
            found => {
                return Err(CodecError::Discriminant {
                    field: Field::Event,
                    found,
                })
            }
        };
        events.push(Event { tick, event });
    }
    let loading_work = reader.u64(Field::Case)?;
    Ok(CaseSpec {
        seed,
        ticks,
        fuel,
        activation_fuel,
        events,
        loading_work,
    })
}

/// A task manifest: version, language, world, slots, cases, contract.
#[must_use]
pub fn encode_manifest(manifest: &TaskManifest) -> Vec<u8> {
    let mut writer = Writer::with_capacity(MAX_MANIFEST_BYTES);
    writer.u8(VERSION);
    writer.u8(LANGUAGE_FINITE_RULE_V1);
    put_world(&mut writer, &manifest.world);
    writer.u8(manifest.slots.len() as u8);
    for slot in &manifest.slots {
        writer.u16(slot.cell);
        match &slot.fixed {
            None => writer.u8(0),
            Some(program) => {
                writer.u8(1);
                put_program_body(&mut writer, program);
            }
        }
    }
    writer.u8(manifest.cases.len() as u8);
    for case in &manifest.cases {
        put_case(&mut writer, case);
    }
    writer.u64(manifest.contract.useful_floor);
    writer.u64(manifest.contract.total_ceiling);
    writer.bool(manifest.contract.require_passed);
    writer.finish()
}

/// Decodes a task manifest; it is data until `ValidManifest::validate`.
pub fn decode_manifest(raw: &[u8]) -> Result<TaskManifest, CodecError> {
    let mut reader = Reader::bounded(raw, MAX_MANIFEST_BYTES)?;
    header(&mut reader)?;
    let world = get_world(&mut reader)?;
    let count = reader.count(MAX_CELLS, Field::Count)?;
    let mut slots = Vec::with_capacity(count);
    let mut previous: Option<u16> = None;
    for _ in 0..count {
        let cell = reader.u16(Field::CellId)?;
        if previous.is_some_and(|last| cell <= last) {
            return Err(CodecError::Unsorted {
                field: Field::CellId,
            });
        }
        previous = Some(cell);
        let fixed = match reader.u8(Field::Remember)? {
            0 => None,
            1 => Some(get_program_body(&mut reader)?),
            found => {
                return Err(CodecError::Discriminant {
                    field: Field::Remember,
                    found,
                })
            }
        };
        slots.push(ProgramSlot { cell, fixed });
    }
    let count = reader.count(MAX_CASES, Field::Count)?;
    let mut cases = Vec::with_capacity(count);
    for _ in 0..count {
        cases.push(get_case(&mut reader)?);
    }
    let contract = WorkContract {
        useful_floor: reader.u64(Field::Contract)?,
        total_ceiling: reader.u64(Field::Contract)?,
        require_passed: reader.bool(Field::Contract)?,
    };
    reader.finish()?;
    Ok(TaskManifest {
        world,
        slots,
        cases,
        contract,
    })
}

fn put_signal(writer: &mut Writer, signal: &Signal) {
    writer.u64(signal.id);
    writer.u16(signal.link);
    put_endpoint(writer, signal.from);
    writer.u16(signal.to_cell);
    writer.u8(signal.to_port.get());
    writer.bool(signal.bit);
    writer.u32(signal.sent_tick);
    writer.u32(signal.deliver_tick);
    match signal.receipt_spark {
        None => writer.u8(0),
        Some(id) => {
            writer.u8(1);
            writer.u32(id);
        }
    }
}

fn put_cell_state(writer: &mut Writer, cell: &CellState) {
    writer.u16(cell.id);
    put_point(writer, cell.position);
    writer.u8(direction_tag(cell.heading));
    writer.bytes(&cell.memory);
    for evidence in &cell.evidence {
        match evidence {
            None => writer.u8(0),
            Some(id) => {
                writer.u8(1);
                writer.u32(*id);
            }
        }
    }
    match cell.cargo {
        None => writer.u8(0),
        Some(spark) => {
            writer.u8(1);
            put_spark(writer, spark);
        }
    }
    for inbox in &cell.inbox {
        match inbox {
            None => writer.u8(0),
            Some(signal) => {
                writer.u8(1);
                put_signal(writer, signal);
            }
        }
    }
}

fn put_source_state(writer: &mut Writer, source: &SourceState) {
    writer.u16(source.id);
    writer.u8(source.sparks.len() as u8);
    for spark in &source.sparks {
        put_spark(writer, *spark);
    }
}

fn put_depot_state(writer: &mut Writer, depot: &DepotState) {
    writer.u16(depot.id);
    writer.u8(depot.sparks.len() as u8);
    for spark in &depot.sparks {
        put_spark(writer, *spark);
    }
}

fn put_beacon_state(writer: &mut Writer, beacon: &BeaconState) {
    writer.u16(beacon.id);
    writer.u32(beacon.charge);
    writer.u32(beacon.delivered);
    writer.u32(beacon.drained);
    writer.bool(beacon.exhausted);
}

fn put_enabled(writer: &mut Writer, entry: &EnabledState) {
    writer.u16(entry.id);
    writer.bool(entry.enabled);
}

fn put_delivery(writer: &mut Writer, delivery: &Delivery) {
    writer.u32(delivery.tick);
    put_spark(writer, delivery.spark);
    writer.u16(delivery.beacon);
}

/// A final state, for `StateHash`. States are produced only by the run, so
/// there is no decoder.
#[must_use]
pub fn encode_state(state: &State) -> Vec<u8> {
    let mut writer = Writer::with_capacity(MAX_STATE_BYTES);
    writer.u32(state.tick);
    writer.u8(state.cells.len() as u8);
    for cell in &state.cells {
        put_cell_state(&mut writer, cell);
    }
    writer.u8(state.sources.len() as u8);
    for source in &state.sources {
        put_source_state(&mut writer, source);
    }
    writer.u8(state.depots.len() as u8);
    for depot in &state.depots {
        put_depot_state(&mut writer, depot);
    }
    writer.u8(state.beacons.len() as u8);
    for beacon in &state.beacons {
        put_beacon_state(&mut writer, beacon);
    }
    writer.u8(state.valves.len() as u8);
    for valve in &state.valves {
        put_enabled(&mut writer, valve);
    }
    writer.u8(state.links.len() as u8);
    for link in &state.links {
        put_enabled(&mut writer, link);
    }
    writer.u8(state.pending.len() as u8);
    for signal in &state.pending {
        put_signal(&mut writer, signal);
    }
    writer.u8(state.delivered.len() as u8);
    for delivery in &state.delivered {
        put_delivery(&mut writer, delivery);
    }
    writer.u64(state.next_signal);
    writer.finish()
}

/// Appends the thirteen counters in declaration order.
pub fn put_ledger(writer: &mut Writer, ledger: &Ledger) {
    for value in [
        ledger.loading,
        ledger.scheduling,
        ledger.conditions,
        ledger.sensors,
        ledger.memory_reads,
        ledger.memory_writes,
        ledger.actions,
        ledger.messages,
        ledger.transfers,
        ledger.checking,
        ledger.draining,
        ledger.copying,
        ledger.construction,
    ] {
        writer.u64(value);
    }
}

/// Reads the thirteen counters in declaration order.
pub fn get_ledger(reader: &mut Reader<'_>) -> Result<Ledger, CodecError> {
    Ok(Ledger {
        loading: reader.u64(Field::Ledger)?,
        scheduling: reader.u64(Field::Ledger)?,
        conditions: reader.u64(Field::Ledger)?,
        sensors: reader.u64(Field::Ledger)?,
        memory_reads: reader.u64(Field::Ledger)?,
        memory_writes: reader.u64(Field::Ledger)?,
        actions: reader.u64(Field::Ledger)?,
        messages: reader.u64(Field::Ledger)?,
        transfers: reader.u64(Field::Ledger)?,
        checking: reader.u64(Field::Ledger)?,
        draining: reader.u64(Field::Ledger)?,
        copying: reader.u64(Field::Ledger)?,
        construction: reader.u64(Field::Ledger)?,
    })
}

fn status_tag(status: RunStatus) -> u8 {
    match status {
        RunStatus::Complete => 1,
        RunStatus::FuelExhausted => 2,
        RunStatus::ActivationLimit => 3,
    }
}

fn get_status(reader: &mut Reader<'_>) -> Result<RunStatus, CodecError> {
    Ok(match reader.u8(Field::Status)? {
        1 => RunStatus::Complete,
        2 => RunStatus::FuelExhausted,
        3 => RunStatus::ActivationLimit,
        found => {
            return Err(CodecError::Discriminant {
                field: Field::Status,
                found,
            })
        }
    })
}

/// Appends one case result.
pub fn put_case_result(writer: &mut Writer, result: &CaseResult) {
    writer.u8(status_tag(result.status));
    writer.u32(result.ticks_completed);
    writer.bool(result.outcome.all_beacons_positive);
    writer.bool(result.outcome.quotas_met);
    writer.bool(result.outcome.conserved);
    writer.bool(result.outcome.passed);
    writer.bytes(&result.final_state.0);
    put_ledger(writer, &result.ledger);
    writer.u64(result.useful);
}

/// Reads one case result.
pub fn get_case_result(reader: &mut Reader<'_>) -> Result<CaseResult, CodecError> {
    Ok(CaseResult {
        status: get_status(reader)?,
        ticks_completed: reader.u32(Field::Status)?,
        outcome: Outcome {
            all_beacons_positive: reader.bool(Field::Bool)?,
            quotas_met: reader.bool(Field::Bool)?,
            conserved: reader.bool(Field::Bool)?,
            passed: reader.bool(Field::Bool)?,
        },
        final_state: crate::hash::StateHash(reader.hash()?),
        ledger: get_ledger(reader)?,
        useful: reader.u64(Field::Ledger)?,
    })
}

/// Every case result in order, for `OutputHash`.
#[must_use]
pub fn encode_output(results: &[CaseResult]) -> Vec<u8> {
    let mut writer = Writer::with_capacity(1 + results.len() * CASE_RESULT_BYTES);
    writer.u8(results.len() as u8);
    for result in results {
        put_case_result(&mut writer, result);
    }
    writer.finish()
}

/// Decodes case results.
pub fn decode_output(raw: &[u8]) -> Result<Vec<CaseResult>, CodecError> {
    let mut reader = Reader::bounded(raw, 1 + MAX_CASES * CASE_RESULT_BYTES)?;
    let count = reader.count(MAX_CASES, Field::Count)?;
    let mut results = Vec::with_capacity(count);
    for _ in 0..count {
        results.push(get_case_result(&mut reader)?);
    }
    reader.finish()?;
    Ok(results)
}
