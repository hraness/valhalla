//! The `GameManifest`: the published description of a game, hashed into every
//! session. Its world digest is the `ManifestHash` of a `TaskManifest`
//! template with seed 0 and empty events; the template itself travels in the
//! `Reveal` event.

use vhalla_witness::bounds::MAX_CELLS;
use vhalla_witness::codec::MAX_CASES;
use vhalla_witness::hash::{ManifestHash, ProgramHash};
use vhalla_witness::manifest::WorkContract;
use vhalla_witness::platform::WorkAllowance;

use crate::ids::{GameManifestHash, InnerArtifactId, RulesetId};
use crate::wire;

/// Most inner artifact ids a manifest names.
pub const MAX_ARTIFACT_IDS: usize = 4;
/// Session ceiling on admitted events; the per-case cap of 64 is separate.
pub const MAX_SESSION_EVENTS: u32 = 1024;
/// Most seals across every epoch of one session.
pub const MAX_SEGMENTS: u8 = 8;
/// Most replays one session may charge a receiver.
pub const MAX_REPLAYS: u32 = 64;
/// Most event bytes one session may deliver to a receiver.
pub const MAX_SESSION_EVENT_BYTES: u64 = 1024 * wire::MAX_GAME_EVENT_BYTES as u64;
/// Most bytes one artifact assembly may retain.
pub const MAX_ARTIFACT_BYTES: u64 = 8 * 1024 * 1024;

/// What a slot of the world is in a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotRole {
    /// The template fixes the program; no player binds it.
    Fixed,
    /// A player binds it; a missing player may be filled with the fallback.
    Open {
        /// The manifest's declared fallback program, if `Fill` is allowed.
        fallback: Option<ProgramHash>,
    },
}

/// One world cell and its role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GameSlot {
    /// The world cell id.
    pub cell: u16,
    /// Fixed or open.
    pub role: SlotRole,
}

/// What happens when an open slot's player never binds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MissingMember {
    /// The session pauses and ends unresolved.
    Pause = 1,
    /// The host fills the slot with the declared fallback.
    Fill = 2,
}

/// Replay of a published experiment, or a live session with player binds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionKind {
    /// Seeds and programs come from the template; bit-exact with Platonik.
    Replay = 1,
    /// Seeds derive from committed salts; players bind programs.
    Live = 2,
}

/// What a session may charge a receiver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerificationAllowance {
    /// At most [`MAX_REPLAYS`].
    pub max_replays: u32,
    /// Total replay work.
    pub max_work: u64,
    /// At most [`MAX_SESSION_EVENT_BYTES`].
    pub max_event_bytes: u64,
    /// Peak retained artifact bytes, at most [`MAX_ARTIFACT_BYTES`].
    pub max_artifact_bytes: u64,
}

/// Session limits declared by the publisher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionLimits {
    /// At most [`MAX_SESSION_EVENTS`].
    pub max_events: u32,
    /// At most [`MAX_SEGMENTS`].
    pub max_segments: u8,
    /// Allowance for each segment replay.
    pub replay: WorkAllowance,
    /// What the whole session may charge a receiver.
    pub verification: VerificationAllowance,
    /// Missing-member policy.
    pub missing_member: MissingMember,
    /// Replay or live.
    pub kind: SessionKind,
}

/// The published game.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GameManifest {
    /// Codec, language, protocol.
    pub ruleset: RulesetId,
    /// `ManifestHash` of the template `TaskManifest` (seed 0, empty events).
    pub world: ManifestHash,
    /// One entry per world cell, strictly ascending.
    pub slots: Vec<GameSlot>,
    /// The work contract every settlement is judged by.
    pub contract: WorkContract,
    /// Declared loading work per case, `1..=8` cases.
    pub loading_work: Vec<u64>,
    /// Inner artifact ids the session may move, at most four.
    pub artifacts: Vec<InnerArtifactId>,
    /// Limits.
    pub limits: SessionLimits,
    /// The publisher's full key.
    pub publisher: [u8; 32],
}

/// Why a manifest is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManifestError {
    /// The ruleset is not v1.
    Ruleset,
    /// Slots are empty, above `MAX_CELLS`, or not strictly ascending.
    Slots,
    /// Case count outside `1..=8`.
    Cases,
    /// More than four artifact ids, or two of the same kind.
    Artifacts,
    /// A limit exceeds its ceiling or is zero.
    Limits,
    /// The contract ceiling is zero.
    Contract,
}

impl GameManifest {
    /// Structural validation; the world digest itself is checked at `Reveal`.
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.ruleset != RulesetId::V1 {
            return Err(ManifestError::Ruleset);
        }
        if self.slots.is_empty()
            || self.slots.len() > MAX_CELLS
            || self
                .slots
                .windows(2)
                .any(|pair| pair[0].cell >= pair[1].cell)
        {
            return Err(ManifestError::Slots);
        }
        if self.loading_work.is_empty() || self.loading_work.len() > MAX_CASES {
            return Err(ManifestError::Cases);
        }
        if self.artifacts.len() > MAX_ARTIFACT_IDS
            || self
                .artifacts
                .iter()
                .enumerate()
                .any(|(i, a)| self.artifacts[..i].iter().any(|b| b.kind == a.kind))
        {
            return Err(ManifestError::Artifacts);
        }
        let limits = self.limits;
        if limits.max_events == 0
            || limits.max_events > MAX_SESSION_EVENTS
            || limits.max_segments == 0
            || limits.max_segments > MAX_SEGMENTS
            || limits.replay.max_total == 0
            || limits.verification.max_replays == 0
            || limits.verification.max_replays > MAX_REPLAYS
            || limits.verification.max_event_bytes > MAX_SESSION_EVENT_BYTES
            || limits.verification.max_artifact_bytes > MAX_ARTIFACT_BYTES
        {
            return Err(ManifestError::Limits);
        }
        if self.contract.total_ceiling == 0 {
            return Err(ManifestError::Contract);
        }
        Ok(())
    }
    /// The manifest identity.
    #[must_use]
    pub fn hash(&self) -> GameManifestHash {
        GameManifestHash::of(&wire::encode_game_manifest(self))
    }
    /// Cells a player must bind: the open slots in order.
    pub fn open_slots(&self) -> impl Iterator<Item = u16> + '_ {
        self.slots
            .iter()
            .filter(|slot| matches!(slot.role, SlotRole::Open { .. }))
            .map(|slot| slot.cell)
    }
}
