//! The application language: the habitat-v1 cell program restated with
//! validated newtypes and private-field constructors.
//!
//! Only the v1 surface is present. `HasMaterial`, `AssemblyStage`,
//! `AssemblyEdits`, `GatherMaterial`, `Build`, `Activate`, and
//! `EditDirection` are v3/v4 and are rejected by Platonik's own validator for
//! version 1, so the restated enums have no variant for them.

use alloc::vec::Vec;

use crate::bounds::{MAX_CONDITIONS, MAX_RULES, MEMORY_SLOTS, MIN_RULES, PORTS};

/// A validated memory slot index in `0..4`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Slot(u8);

impl Slot {
    /// Accepts `0..4`.
    pub const fn new(index: u8) -> Option<Self> {
        if index < MEMORY_SLOTS {
            Some(Self(index))
        } else {
            None
        }
    }
    /// The slot index.
    pub const fn get(self) -> u8 {
        self.0
    }
    pub(crate) const fn index(self) -> usize {
        self.0 as usize
    }
}

/// A validated inbox port index in `0..4`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Port(u8);

impl Port {
    /// Accepts `0..4`.
    pub const fn new(index: u8) -> Option<Self> {
        if index < PORTS {
            Some(Self(index))
        } else {
            None
        }
    }
    /// The port index.
    pub const fn get(self) -> u8 {
        self.0
    }
    pub(crate) const fn index(self) -> usize {
        self.0 as usize
    }
}

/// A valve identifier named by a `Route` action; existence is checked when an
/// [`crate::world::Assignment`] is validated against a world.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ValveId(u16);

impl ValveId {
    /// Wraps a valve id.
    pub const fn new(id: u16) -> Self {
        Self(id)
    }
    /// The valve id.
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// An absolute heading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Decreasing `y`.
    North,
    /// Increasing `x`.
    East,
    /// Increasing `y`.
    South,
    /// Decreasing `x`.
    West,
}

/// A heading relative to the cell's own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Relative {
    /// Same heading.
    Forward,
    /// Counter-clockwise quarter turn.
    Left,
    /// Clockwise quarter turn.
    Right,
    /// Half turn.
    Back,
}

/// A leaf sensor. Every condition costs one `conditions` unit plus one
/// `memory_reads` unit (`Memory`) or one `sensors` unit (everything else).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Condition {
    /// Whether the cell carries a spark.
    Carrying {
        /// Expected value.
        value: bool,
    },
    /// Whether the cell stands on a source.
    AtSource {
        /// Expected value.
        value: bool,
    },
    /// Whether the cell stands on a depot.
    AtDepot {
        /// Expected value.
        value: bool,
    },
    /// Whether the cell stands on a beacon.
    AtBeacon {
        /// Expected value.
        value: bool,
    },
    /// Whether the cell stands on a depot or a beacon.
    AtReceiver {
        /// Expected value.
        value: bool,
    },
    /// Whether movement in a relative direction is blocked.
    Blocked {
        /// Direction relative to the heading.
        direction: Relative,
        /// Expected value.
        value: bool,
    },
    /// Whether an inbox port holds a message.
    HasMessage {
        /// Inbox port.
        port: Port,
        /// Expected value.
        value: bool,
    },
    /// Whether an inbox port holds a message with the given bit; false when
    /// the port is empty.
    MessageBit {
        /// Inbox port.
        port: Port,
        /// Expected bit.
        value: bool,
    },
    /// Whether a memory slot equals a byte.
    Memory {
        /// Memory slot.
        slot: Slot,
        /// Expected byte.
        value: u8,
    },
    /// Whether the cell faces a direction.
    Heading {
        /// Expected heading.
        direction: Direction,
    },
}

/// Where a sent or routed bit comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitSource {
    /// A literal; costs one `checking` unit.
    Constant {
        /// The bit.
        value: bool,
    },
    /// A memory slot read as non-zero; costs one `memory_reads` unit and
    /// carries the slot's evidence.
    Memory {
        /// Memory slot.
        slot: Slot,
    },
    /// The bit of the message in an inbox port; costs one `sensors` unit and
    /// fails with `no_message` when empty.
    Message {
        /// Inbox port.
        port: Port,
    },
}

/// A typed effect on platform-owned state. Every action costs one `actions`
/// unit before anything else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Step one square and face that way; charges `transfers` on success.
    Move {
        /// Direction relative to the heading.
        direction: Relative,
    },
    /// Rotate in place; charges `transfers`.
    Turn {
        /// Direction relative to the heading.
        direction: Relative,
    },
    /// Take the oldest spark from the source underfoot.
    Pickup,
    /// Deposit the carried spark on the depot or beacon underfoot.
    Drop,
    /// Do nothing.
    Wait,
    /// Store a byte and clear that slot's evidence.
    WriteMemory {
        /// Memory slot.
        slot: Slot,
        /// The byte.
        value: u8,
    },
    /// Move a message bit and its evidence from a port into a slot.
    TakeMessage {
        /// Inbox port.
        port: Port,
        /// Memory slot.
        slot: Slot,
    },
    /// Emit a bit over every link leaving this cell's port.
    Send {
        /// Output port.
        port: Port,
        /// Bit source.
        bit: BitSource,
    },
    /// Spend the first spark of a valve's depot on the beacon selected by a bit.
    Route {
        /// The valve.
        valve: ValveId,
        /// Bit source.
        bit: BitSource,
    },
}

/// A byte written after the action, whether or not the action succeeded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryWrite {
    slot: Slot,
    value: u8,
}

impl MemoryWrite {
    /// Builds a write.
    pub const fn new(slot: Slot, value: u8) -> Self {
        Self { slot, value }
    }
    /// The slot.
    pub const fn slot(&self) -> Slot {
        self.slot
    }
    /// The byte.
    pub const fn value(&self) -> u8 {
        self.value
    }
}

/// Structural errors of a program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModelError {
    /// A program needs at least one rule.
    NoRules,
    /// A program has at most [`MAX_RULES`] rules.
    TooManyRules,
    /// A rule has at most [`MAX_CONDITIONS`] conditions.
    TooManyConditions,
}

/// A first-match rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    when: Vec<Condition>,
    action: Action,
    remember: Option<MemoryWrite>,
}

impl Rule {
    /// Builds a rule with at most [`MAX_CONDITIONS`] conditions.
    pub fn new(
        when: Vec<Condition>,
        action: Action,
        remember: Option<MemoryWrite>,
    ) -> Result<Self, ModelError> {
        if when.len() > MAX_CONDITIONS {
            return Err(ModelError::TooManyConditions);
        }
        Ok(Self {
            when,
            action,
            remember,
        })
    }
    /// The conditions, all of which must hold.
    pub fn when(&self) -> &[Condition] {
        &self.when
    }
    /// The action.
    pub const fn action(&self) -> Action {
        self.action
    }
    /// The optional post-action write.
    pub const fn remember(&self) -> Option<MemoryWrite> {
        self.remember
    }
}

/// A cell program: 1..=32 rules tried in order on every activation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    rules: Vec<Rule>,
}

impl Program {
    /// Builds a program with [`MIN_RULES`]..=[`MAX_RULES`] rules.
    pub fn new(rules: Vec<Rule>) -> Result<Self, ModelError> {
        if rules.len() < MIN_RULES {
            return Err(ModelError::NoRules);
        }
        if rules.len() > MAX_RULES {
            return Err(ModelError::TooManyRules);
        }
        Ok(Self { rules })
    }
    /// The rules in match order.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }
}

/// `policy::face`: rotate a heading by a relative direction.
pub const fn face(heading: Direction, relative: Relative) -> Direction {
    const HEADINGS: [Direction; 4] = [
        Direction::North,
        Direction::East,
        Direction::South,
        Direction::West,
    ];
    let start = match heading {
        Direction::North => 0,
        Direction::East => 1,
        Direction::South => 2,
        Direction::West => 3,
    };
    let offset = match relative {
        Relative::Forward => 0,
        Relative::Right => 1,
        Relative::Back => 2,
        Relative::Left => 3,
    };
    HEADINGS[(start + offset) % 4]
}
