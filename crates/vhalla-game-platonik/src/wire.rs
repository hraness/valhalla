//! Canonical encodings of every game object over the witness `Writer` and
//! `Reader`: version byte first, fixed-width big-endian, `u8` discriminants
//! with 0 reserved, `Option` as a 0/1 tag, no strings, no floats, bound checked
//! before decode, `finish()` rejects trailing bytes. An object's encoding is
//! its signature body and its hash preimage.

use vhalla_core::{Epoch, RealmId, RoomId, Sequence};
use vhalla_ledger::{Checkpoint as LedgerCheckpoint, EventDigest, StateRoot};
use vhalla_witness::bounds::MAX_CELLS;
use vhalla_witness::codec::{
    self, CodecError, Field, Reader, Writer, MAX_CASES, MAX_MANIFEST_BYTES, MAX_PROGRAM_BYTES,
};
use vhalla_witness::hash::{ManifestHash, ProgramHash, StateHash};
use vhalla_witness::manifest::{TaskManifest, WorkContract};
use vhalla_witness::model::Program;
use vhalla_witness::platform::{ClaimedReceipt, WorkAllowance, RECEIPT_BYTES};
use vhalla_witness::vm::RunStatus;
use vhalla_witness::world::EventKind;

use crate::ids::{
    ArtifactManifestHash, CheckpointHash, GameEventDigest, GameManifestHash, InnerArtifactId,
    InnerKind, RulesetId, SessionKey,
};
use crate::manifest::{
    GameManifest, GameSlot, MissingMember, SessionKind, SessionLimits, SlotRole,
    VerificationAllowance, MAX_ARTIFACT_IDS,
};

/// Encoding version of every game object.
pub const VERSION: u8 = 1;
/// Most players in a session.
pub const MAX_PLAYERS: usize = 16;
/// Most parent digests an event names.
pub const MAX_PARENTS: usize = 4;
/// Most event digests one `Seal` orders; tied to the 512 pending cap.
pub const MAX_SEAL_ORDER: usize = 512;
/// Most heads an unresolved settlement names.
pub const MAX_FORK_HEADS: usize = 4;
/// Most evidence digests an unresolved settlement carries.
pub const MAX_FORK_EVIDENCE: usize = 8;
/// Most blocks an artifact manifest lists.
pub const MAX_BLOCKS: usize = 128;
/// Fixed block length.
pub const BLOCK_LEN: u32 = 65_536;

/// One inner artifact id: kind byte plus 32.
const INNER_ID_BYTES: usize = 33;
/// A game manifest: version, ruleset, world, slots, contract, cases,
/// artifacts, limits, publisher.
pub const MAX_GAME_MANIFEST_BYTES: usize = 1
    + 3
    + 32
    + (1 + MAX_CELLS * (2 + 1 + 1 + 32))
    + 17
    + (1 + MAX_CASES * 8)
    + (1 + MAX_ARTIFACT_IDS * INNER_ID_BYTES)
    + (4 + 1 + 8 + (4 + 8 + 8 + 8) + 1 + 1)
    + 32;
/// A session opening: version, realm, room, manifest, ruleset, seed
/// commitment, authority, players, epoch, nonce.
pub const MAX_SESSION_OPEN_BYTES: usize =
    1 + 16 + 16 + 32 + 3 + 32 + (1 + 32) + (1 + MAX_PLAYERS * (32 + 1 + MAX_CELLS * 2)) + 8 + 32;
/// The common event header: version, session, epoch, author, sequence,
/// parents, body discriminant.
pub const EVENT_HEADER_BYTES: usize = 1 + 32 + 8 + 32 + 8 + (1 + MAX_PARENTS * 32) + 1;
/// The widest `Seal` body: segment, through tick, order, checkpoint.
pub const MAX_SEAL_BODY_BYTES: usize = 1 + 4 + (2 + MAX_SEAL_ORDER * 32) + 32;
/// The widest `Reveal` body: a full task manifest and the host salt.
pub const MAX_REVEAL_BODY_BYTES: usize = 2 + MAX_MANIFEST_BYTES + 32;
/// Bound on one encoded game event; the widest variant is asserted in tests.
pub const MAX_GAME_EVENT_BYTES: usize = 24_576;
/// Bound on one encoded checkpoint.
pub const MAX_CHECKPOINT_BYTES: usize = 1024;
/// Bound on one encoded settlement.
pub const MAX_SETTLEMENT_BYTES: usize = 1024;
/// An artifact request: version, session, id, max bytes, nonce.
pub const MAX_ARTIFACT_REQUEST_BYTES: usize = 1 + 32 + INNER_ID_BYTES + 8 + 32;
/// An artifact manifest: version, id, total, block length, digests, decompressed.
pub const MAX_ARTIFACT_MANIFEST_BYTES: usize =
    1 + INNER_ID_BYTES + 8 + 4 + (1 + MAX_BLOCKS * 32) + 8;
/// A block: version, manifest digest, index, offset, bytes.
pub const MAX_BLOCK_BYTES: usize = 1 + 32 + 1 + 8 + 4 + BLOCK_LEN as usize;

fn version(reader: &mut Reader<'_>) -> Result<(), CodecError> {
    let found = reader.u8(Field::Version)?;
    if found != VERSION {
        return Err(CodecError::UnsupportedVersion { found });
    }
    Ok(())
}

fn put_u128(writer: &mut Writer, value: u128) {
    writer.bytes(&value.to_be_bytes());
}

fn get_u128(reader: &mut Reader<'_>) -> Result<u128, CodecError> {
    let hi = reader.u64(Field::Value)?;
    let lo = reader.u64(Field::Value)?;
    Ok((u128::from(hi) << 64) | u128::from(lo))
}

fn put_ruleset(writer: &mut Writer, ruleset: RulesetId) {
    writer.u8(ruleset.codec);
    writer.u8(ruleset.language);
    writer.u8(ruleset.protocol);
}

fn get_ruleset(reader: &mut Reader<'_>) -> Result<RulesetId, CodecError> {
    Ok(RulesetId {
        codec: reader.u8(Field::Version)?,
        language: reader.u8(Field::Language)?,
        protocol: reader.u8(Field::Version)?,
    })
}

fn put_inner_id(writer: &mut Writer, id: InnerArtifactId) {
    writer.u8(id.kind as u8);
    writer.bytes(&id.sha256);
}

fn get_inner_id(reader: &mut Reader<'_>) -> Result<InnerArtifactId, CodecError> {
    let found = reader.u8(Field::Value)?;
    let kind = InnerKind::from_u8(found).ok_or(CodecError::Discriminant {
        field: Field::Value,
        found,
    })?;
    Ok(InnerArtifactId {
        kind,
        sha256: reader.hash()?,
    })
}

fn put_option_hash(writer: &mut Writer, value: Option<[u8; 32]>) {
    match value {
        None => writer.u8(0),
        Some(hash) => {
            writer.u8(1);
            writer.bytes(&hash);
        }
    }
}

fn get_option_hash(reader: &mut Reader<'_>) -> Result<Option<[u8; 32]>, CodecError> {
    match reader.u8(Field::Remember)? {
        0 => Ok(None),
        1 => Ok(Some(reader.hash()?)),
        found => Err(CodecError::Discriminant {
            field: Field::Remember,
            found,
        }),
    }
}

fn put_contract(writer: &mut Writer, contract: WorkContract) {
    writer.u64(contract.useful_floor);
    writer.u64(contract.total_ceiling);
    writer.bool(contract.require_passed);
}

fn get_contract(reader: &mut Reader<'_>) -> Result<WorkContract, CodecError> {
    Ok(WorkContract {
        useful_floor: reader.u64(Field::Contract)?,
        total_ceiling: reader.u64(Field::Contract)?,
        require_passed: reader.bool(Field::Contract)?,
    })
}

fn ascending_u16(reader: &mut Reader<'_>, limit: usize) -> Result<Vec<u16>, CodecError> {
    let count = reader.count(limit, Field::Count)?;
    let mut out = Vec::with_capacity(count);
    let mut previous: Option<u16> = None;
    for _ in 0..count {
        let value = reader.u16(Field::CellId)?;
        if previous.is_some_and(|last| value <= last) {
            return Err(CodecError::Unsorted {
                field: Field::CellId,
            });
        }
        previous = Some(value);
        out.push(value);
    }
    Ok(out)
}

fn hashes(reader: &mut Reader<'_>, limit: usize) -> Result<Vec<[u8; 32]>, CodecError> {
    let count = reader.count(limit, Field::Count)?;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(reader.hash()?);
    }
    Ok(out)
}

fn sorted_unique_hashes(
    reader: &mut Reader<'_>,
    limit: usize,
) -> Result<Vec<[u8; 32]>, CodecError> {
    let out = hashes(reader, limit)?;
    if out.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(CodecError::Unsorted { field: Field::Hash });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// GameManifest
// ---------------------------------------------------------------------------

/// Canonical bytes of a game manifest.
#[must_use]
pub fn encode_game_manifest(manifest: &GameManifest) -> Vec<u8> {
    let mut writer = Writer::with_capacity(MAX_GAME_MANIFEST_BYTES);
    writer.u8(VERSION);
    put_ruleset(&mut writer, manifest.ruleset);
    writer.bytes(&manifest.world.0);
    writer.u8(manifest.slots.len() as u8);
    for slot in &manifest.slots {
        writer.u16(slot.cell);
        match slot.role {
            SlotRole::Fixed => {
                writer.u8(1);
                writer.u8(0);
            }
            SlotRole::Open { fallback } => {
                writer.u8(2);
                put_option_hash(&mut writer, fallback.map(|hash| hash.0));
            }
        }
    }
    put_contract(&mut writer, manifest.contract);
    writer.u8(manifest.loading_work.len() as u8);
    for work in &manifest.loading_work {
        writer.u64(*work);
    }
    writer.u8(manifest.artifacts.len() as u8);
    for id in &manifest.artifacts {
        put_inner_id(&mut writer, *id);
    }
    let limits = manifest.limits;
    writer.u32(limits.max_events);
    writer.u8(limits.max_segments);
    writer.u64(limits.replay.max_total);
    writer.u32(limits.verification.max_replays);
    writer.u64(limits.verification.max_work);
    writer.u64(limits.verification.max_event_bytes);
    writer.u64(limits.verification.max_artifact_bytes);
    writer.u8(limits.missing_member as u8);
    writer.u8(limits.kind as u8);
    writer.bytes(&manifest.publisher);
    writer.finish()
}

/// Decodes a game manifest; it is data until `GameManifest::validate`.
pub fn decode_game_manifest(raw: &[u8]) -> Result<GameManifest, CodecError> {
    let mut reader = Reader::bounded(raw, MAX_GAME_MANIFEST_BYTES)?;
    version(&mut reader)?;
    let ruleset = get_ruleset(&mut reader)?;
    let world = ManifestHash(reader.hash()?);
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
        let role = match reader.u8(Field::Cell)? {
            1 => {
                if reader.u8(Field::Remember)? != 0 {
                    return Err(CodecError::Bound {
                        field: Field::Remember,
                    });
                }
                SlotRole::Fixed
            }
            2 => SlotRole::Open {
                fallback: get_option_hash(&mut reader)?.map(ProgramHash),
            },
            found => {
                return Err(CodecError::Discriminant {
                    field: Field::Cell,
                    found,
                })
            }
        };
        slots.push(GameSlot { cell, role });
    }
    let contract = get_contract(&mut reader)?;
    let count = reader.count(MAX_CASES, Field::Count)?;
    let mut loading_work = Vec::with_capacity(count);
    for _ in 0..count {
        loading_work.push(reader.u64(Field::Case)?);
    }
    let count = reader.count(MAX_ARTIFACT_IDS, Field::Count)?;
    let mut artifacts = Vec::with_capacity(count);
    for _ in 0..count {
        artifacts.push(get_inner_id(&mut reader)?);
    }
    let limits = SessionLimits {
        max_events: reader.u32(Field::Count)?,
        max_segments: reader.u8(Field::Count)?,
        replay: WorkAllowance {
            max_total: reader.u64(Field::Ledger)?,
        },
        verification: VerificationAllowance {
            max_replays: reader.u32(Field::Count)?,
            max_work: reader.u64(Field::Ledger)?,
            max_event_bytes: reader.u64(Field::Ledger)?,
            max_artifact_bytes: reader.u64(Field::Ledger)?,
        },
        missing_member: match reader.u8(Field::Status)? {
            1 => MissingMember::Pause,
            2 => MissingMember::Fill,
            found => {
                return Err(CodecError::Discriminant {
                    field: Field::Status,
                    found,
                })
            }
        },
        kind: match reader.u8(Field::Status)? {
            1 => SessionKind::Replay,
            2 => SessionKind::Live,
            found => {
                return Err(CodecError::Discriminant {
                    field: Field::Status,
                    found,
                })
            }
        },
    };
    let publisher = reader.hash()?;
    reader.finish()?;
    Ok(GameManifest {
        ruleset,
        world,
        slots,
        contract,
        loading_work,
        artifacts,
        limits,
        publisher,
    })
}

// ---------------------------------------------------------------------------
// SessionOpen
// ---------------------------------------------------------------------------

/// Who orders and includes events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Authority {
    /// One explicit session host with ordering and inclusion authority only.
    Host {
        /// The host's full key.
        key: [u8; 32],
    },
    /// Reserved: decode-only until the `quorum` feature lands.
    Quorum {
        /// The certificate scheme's identity.
        scheme: [u8; 32],
    },
}

/// One player and the open slots it binds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Player {
    /// Full key.
    pub key: [u8; 32],
    /// Open slot cells this player binds, ascending.
    pub slots: Vec<u16>,
}

/// The opening of a session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionOpen {
    /// Realm.
    pub realm: RealmId,
    /// Room.
    pub room: RoomId,
    /// The game.
    pub manifest: GameManifestHash,
    /// Ruleset, repeated for cheap refusal.
    pub ruleset: RulesetId,
    /// Commitment to the host salt (live) or zero (replay).
    pub seed_commitment: [u8; 32],
    /// Authority.
    pub authority: Authority,
    /// Players sorted by key, disjoint slots covering every open slot.
    pub players: Vec<Player>,
    /// Always epoch 0 at opening.
    pub epoch: Epoch,
    /// 32 injected random bytes.
    pub nonce: [u8; 32],
}

impl SessionOpen {
    /// The session key.
    #[must_use]
    pub fn key(&self) -> SessionKey {
        SessionKey::of(&encode_session_open(self))
    }
}

/// Canonical bytes of a session opening.
#[must_use]
pub fn encode_session_open(open: &SessionOpen) -> Vec<u8> {
    let mut writer = Writer::with_capacity(MAX_SESSION_OPEN_BYTES);
    writer.u8(VERSION);
    put_u128(&mut writer, open.realm.0);
    put_u128(&mut writer, open.room.0);
    writer.bytes(&open.manifest.0);
    put_ruleset(&mut writer, open.ruleset);
    writer.bytes(&open.seed_commitment);
    match open.authority {
        Authority::Host { key } => {
            writer.u8(1);
            writer.bytes(&key);
        }
        Authority::Quorum { scheme } => {
            writer.u8(2);
            writer.bytes(&scheme);
        }
    }
    writer.u8(open.players.len() as u8);
    for player in &open.players {
        writer.bytes(&player.key);
        writer.u8(player.slots.len() as u8);
        for slot in &player.slots {
            writer.u16(*slot);
        }
    }
    writer.u64(open.epoch.0);
    writer.bytes(&open.nonce);
    writer.finish()
}

/// Decodes a session opening.
pub fn decode_session_open(raw: &[u8]) -> Result<SessionOpen, CodecError> {
    let mut reader = Reader::bounded(raw, MAX_SESSION_OPEN_BYTES)?;
    version(&mut reader)?;
    let realm = RealmId(get_u128(&mut reader)?);
    let room = RoomId(get_u128(&mut reader)?);
    let manifest = GameManifestHash(reader.hash()?);
    let ruleset = get_ruleset(&mut reader)?;
    let seed_commitment = reader.hash()?;
    let authority = match reader.u8(Field::Status)? {
        1 => Authority::Host {
            key: reader.hash()?,
        },
        2 => Authority::Quorum {
            scheme: reader.hash()?,
        },
        found => {
            return Err(CodecError::Discriminant {
                field: Field::Status,
                found,
            })
        }
    };
    let count = reader.count(MAX_PLAYERS, Field::Count)?;
    let mut players = Vec::with_capacity(count);
    let mut previous: Option<[u8; 32]> = None;
    for _ in 0..count {
        let key = reader.hash()?;
        if previous.is_some_and(|last| key <= last) {
            return Err(CodecError::Unsorted { field: Field::Hash });
        }
        previous = Some(key);
        let slots = ascending_u16(&mut reader, MAX_CELLS)?;
        players.push(Player { key, slots });
    }
    let epoch = Epoch(reader.u64(Field::Value)?);
    let nonce = reader.hash()?;
    reader.finish()?;
    Ok(SessionOpen {
        realm,
        room,
        manifest,
        ruleset,
        seed_commitment,
        authority,
        players,
        epoch,
        nonce,
    })
}

// ---------------------------------------------------------------------------
// GameEvent
// ---------------------------------------------------------------------------

/// Pending-claim evidence a `Fill` commits to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FillEvidence {
    /// The slot's last admitted author, or zero.
    pub author: [u8; 32],
    /// The slot's last admitted sequence, or zero.
    pub sequence: Sequence,
    /// The segment at which the slot was still unbound.
    pub segment: u8,
}

/// An event body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventBody {
    /// A player commits to a program and salt for a slot.
    BindCommit {
        /// Slot cell.
        slot: u16,
        /// Commitment digest.
        commit: [u8; 32],
    },
    /// A player reveals its program and salt.
    BindReveal {
        /// Slot cell.
        slot: u16,
        /// The program.
        program: Program,
        /// The salt.
        salt: [u8; 32],
    },
    /// The host closes the commit set: sorted `(slot, digest)` pairs.
    BindClose {
        /// Sorted by slot.
        commits: Vec<(u16, [u8; 32])>,
    },
    /// The host reveals the task manifest and its salt.
    Reveal {
        /// The revealed template with derived seeds and empty events.
        task: TaskManifest,
        /// The host salt whose commitment the opening carried.
        host_salt: [u8; 32],
    },
    /// A world input for one case at one tick.
    Input {
        /// Case index.
        case: u8,
        /// Tick.
        tick: u32,
        /// The world event.
        kind: EventKind,
    },
    /// The host seals a segment.
    Seal {
        /// Segment index.
        segment: u8,
        /// Session-wide through tick.
        through_tick: u32,
        /// Admitted event digests in order.
        order: Vec<GameEventDigest>,
        /// The checkpoint this seal commits.
        checkpoint: CheckpointHash,
    },
    /// The host replaces a member with the same program.
    Replace {
        /// Slot cell.
        slot: u16,
        /// Old key.
        old: [u8; 32],
        /// New key.
        new: [u8; 32],
    },
    /// The host fills an unbound slot with the declared fallback.
    Fill {
        /// Slot cell.
        slot: u16,
        /// Must equal the manifest's declared fallback.
        program_hash: ProgramHash,
        /// Pending-claim evidence.
        evidence: FillEvidence,
    },
}

/// A game event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GameEvent {
    /// Session.
    pub session: SessionKey,
    /// Epoch.
    pub epoch: Epoch,
    /// Author's full key.
    pub author: [u8; 32],
    /// Per-author sequence from 1.
    pub sequence: Sequence,
    /// At most four sorted unique parent digests.
    pub parents: Vec<GameEventDigest>,
    /// The body.
    pub body: EventBody,
}

impl GameEvent {
    /// The event identity.
    #[must_use]
    pub fn digest(&self) -> GameEventDigest {
        GameEventDigest::of(&encode_game_event(self))
    }
}

fn put_event_kind(writer: &mut Writer, kind: EventKind) {
    match kind {
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

fn get_event_kind(reader: &mut Reader<'_>) -> Result<EventKind, CodecError> {
    Ok(match reader.u8(Field::Event)? {
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
    })
}

/// Canonical bytes of a game event.
#[must_use]
pub fn encode_game_event(event: &GameEvent) -> Vec<u8> {
    let mut writer = Writer::with_capacity(EVENT_HEADER_BYTES + 64);
    writer.u8(VERSION);
    writer.bytes(&event.session.0);
    writer.u64(event.epoch.0);
    writer.bytes(&event.author);
    writer.u64(event.sequence.0);
    writer.u8(event.parents.len() as u8);
    for parent in &event.parents {
        writer.bytes(&parent.0);
    }
    match &event.body {
        EventBody::BindCommit { slot, commit } => {
            writer.u8(1);
            writer.u16(*slot);
            writer.bytes(commit);
        }
        EventBody::BindReveal {
            slot,
            program,
            salt,
        } => {
            writer.u8(2);
            writer.u16(*slot);
            let bytes = codec::encode_program(program);
            writer.u16(bytes.len() as u16);
            writer.bytes(&bytes);
            writer.bytes(salt);
        }
        EventBody::BindClose { commits } => {
            writer.u8(3);
            writer.u8(commits.len() as u8);
            for (slot, digest) in commits {
                writer.u16(*slot);
                writer.bytes(digest);
            }
        }
        EventBody::Reveal { task, host_salt } => {
            writer.u8(4);
            let bytes = codec::encode_manifest(task);
            writer.u16(bytes.len() as u16);
            writer.bytes(&bytes);
            writer.bytes(host_salt);
        }
        EventBody::Input { case, tick, kind } => {
            writer.u8(5);
            writer.u8(*case);
            writer.u32(*tick);
            put_event_kind(&mut writer, *kind);
        }
        EventBody::Seal {
            segment,
            through_tick,
            order,
            checkpoint,
        } => {
            writer.u8(6);
            writer.u8(*segment);
            writer.u32(*through_tick);
            writer.u16(order.len() as u16);
            for digest in order {
                writer.bytes(&digest.0);
            }
            writer.bytes(&checkpoint.0);
        }
        EventBody::Replace { slot, old, new } => {
            writer.u8(7);
            writer.u16(*slot);
            writer.bytes(old);
            writer.bytes(new);
        }
        EventBody::Fill {
            slot,
            program_hash,
            evidence,
        } => {
            writer.u8(8);
            writer.u16(*slot);
            writer.bytes(&program_hash.0);
            writer.bytes(&evidence.author);
            writer.u64(evidence.sequence.0);
            writer.u8(evidence.segment);
        }
    }
    writer.finish()
}

/// Decodes a game event; it is data until admission.
pub fn decode_game_event(raw: &[u8]) -> Result<GameEvent, CodecError> {
    let mut reader = Reader::bounded(raw, MAX_GAME_EVENT_BYTES)?;
    version(&mut reader)?;
    let session = SessionKey(reader.hash()?);
    let epoch = Epoch(reader.u64(Field::Value)?);
    let author = reader.hash()?;
    let sequence = Sequence(reader.u64(Field::Value)?);
    let parents = sorted_unique_hashes(&mut reader, MAX_PARENTS)?
        .into_iter()
        .map(GameEventDigest)
        .collect();
    let body = match reader.u8(Field::Event)? {
        1 => EventBody::BindCommit {
            slot: reader.u16(Field::CellId)?,
            commit: reader.hash()?,
        },
        2 => {
            let slot = reader.u16(Field::CellId)?;
            let len = usize::from(reader.u16(Field::Count)?);
            if len > MAX_PROGRAM_BYTES {
                return Err(CodecError::Bound {
                    field: Field::Count,
                });
            }
            let mut bytes = Vec::with_capacity(len);
            for _ in 0..len {
                bytes.push(reader.u8(Field::Cell)?);
            }
            let program = codec::decode_program(&bytes)?;
            EventBody::BindReveal {
                slot,
                program,
                salt: reader.hash()?,
            }
        }
        3 => {
            let count = reader.count(MAX_CELLS, Field::Count)?;
            let mut commits = Vec::with_capacity(count);
            let mut previous: Option<u16> = None;
            for _ in 0..count {
                let slot = reader.u16(Field::CellId)?;
                if previous.is_some_and(|last| slot <= last) {
                    return Err(CodecError::Unsorted {
                        field: Field::CellId,
                    });
                }
                previous = Some(slot);
                commits.push((slot, reader.hash()?));
            }
            EventBody::BindClose { commits }
        }
        4 => {
            let len = usize::from(reader.u16(Field::Count)?);
            if len > MAX_MANIFEST_BYTES {
                return Err(CodecError::Bound {
                    field: Field::Count,
                });
            }
            let mut bytes = Vec::with_capacity(len);
            for _ in 0..len {
                bytes.push(reader.u8(Field::Cell)?);
            }
            let task = codec::decode_manifest(&bytes)?;
            EventBody::Reveal {
                task,
                host_salt: reader.hash()?,
            }
        }
        5 => EventBody::Input {
            case: reader.u8(Field::Case)?,
            tick: reader.u32(Field::Event)?,
            kind: get_event_kind(&mut reader)?,
        },
        6 => {
            let segment = reader.u8(Field::Count)?;
            let through_tick = reader.u32(Field::Event)?;
            let count = usize::from(reader.u16(Field::Count)?);
            if count > MAX_SEAL_ORDER {
                return Err(CodecError::Bound {
                    field: Field::Count,
                });
            }
            let mut order = Vec::with_capacity(count);
            for _ in 0..count {
                order.push(GameEventDigest(reader.hash()?));
            }
            EventBody::Seal {
                segment,
                through_tick,
                order,
                checkpoint: CheckpointHash(reader.hash()?),
            }
        }
        7 => EventBody::Replace {
            slot: reader.u16(Field::CellId)?,
            old: reader.hash()?,
            new: reader.hash()?,
        },
        8 => EventBody::Fill {
            slot: reader.u16(Field::CellId)?,
            program_hash: ProgramHash(reader.hash()?),
            evidence: FillEvidence {
                author: reader.hash()?,
                sequence: Sequence(reader.u64(Field::Value)?),
                segment: reader.u8(Field::Count)?,
            },
        },
        found => {
            return Err(CodecError::Discriminant {
                field: Field::Event,
                found,
            })
        }
    };
    reader.finish()?;
    Ok(GameEvent {
        session,
        epoch,
        author,
        sequence,
        parents,
        body,
    })
}

// ---------------------------------------------------------------------------
// Checkpoint
// ---------------------------------------------------------------------------

/// One case's identity at its checkpoint read tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaseCheckpoint {
    /// State hash at the read tick.
    pub state: StateHash,
    /// Trace head over frames `0..=T`.
    pub trace: [u8; 32],
    /// Ledger total the producing replay reached at the read tick.
    pub ledger_total: u64,
    /// Status derived at the read tick.
    pub status: RunStatus,
}

/// Work over every case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkSummary {
    /// Delivered sparks.
    pub useful: u64,
    /// Total work.
    pub total: u64,
}

/// A segment checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    /// Session.
    pub session: SessionKey,
    /// The ledger checkpoint at the pre-seal tip.
    pub ledger: LedgerCheckpoint,
    /// The previous checkpoint, or zero for segment 0.
    pub parent: [u8; 32],
    /// Segment index.
    pub segment: u8,
    /// The segment manifest hash (a checkpoint field, never a trace input).
    pub segment_manifest: ManifestHash,
    /// The assignment replayed.
    pub program: ProgramHash,
    /// Session-wide through tick.
    pub through_tick: u32,
    /// Per case.
    pub cases: Vec<CaseCheckpoint>,
    /// Work summary.
    pub work: WorkSummary,
}

impl Checkpoint {
    /// The checkpoint identity.
    #[must_use]
    pub fn hash(&self) -> CheckpointHash {
        CheckpointHash::of(&encode_checkpoint(self))
    }
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

/// Canonical bytes of a checkpoint.
#[must_use]
pub fn encode_checkpoint(checkpoint: &Checkpoint) -> Vec<u8> {
    let mut writer = Writer::with_capacity(MAX_CHECKPOINT_BYTES);
    writer.u8(VERSION);
    writer.bytes(&checkpoint.session.0);
    put_u128(&mut writer, checkpoint.ledger.realm.0);
    writer.u64(checkpoint.ledger.epoch.0);
    writer.bytes(&checkpoint.ledger.head.0);
    writer.bytes(&checkpoint.ledger.state_root.0);
    writer.u64(checkpoint.ledger.height);
    writer.bytes(&checkpoint.parent);
    writer.u8(checkpoint.segment);
    writer.bytes(&checkpoint.segment_manifest.0);
    writer.bytes(&checkpoint.program.0);
    writer.u32(checkpoint.through_tick);
    writer.u8(checkpoint.cases.len() as u8);
    for case in &checkpoint.cases {
        writer.bytes(&case.state.0);
        writer.bytes(&case.trace);
        writer.u64(case.ledger_total);
        writer.u8(status_tag(case.status));
    }
    writer.u64(checkpoint.work.useful);
    writer.u64(checkpoint.work.total);
    writer.finish()
}

/// Decodes a checkpoint; it is data until the receiver reproduces it.
pub fn decode_checkpoint(raw: &[u8]) -> Result<Checkpoint, CodecError> {
    let mut reader = Reader::bounded(raw, MAX_CHECKPOINT_BYTES)?;
    version(&mut reader)?;
    let session = SessionKey(reader.hash()?);
    let ledger = LedgerCheckpoint {
        realm: RealmId(get_u128(&mut reader)?),
        epoch: Epoch(reader.u64(Field::Value)?),
        head: EventDigest(reader.hash()?),
        state_root: StateRoot(reader.hash()?),
        height: reader.u64(Field::Value)?,
    };
    let parent = reader.hash()?;
    let segment = reader.u8(Field::Count)?;
    let segment_manifest = ManifestHash(reader.hash()?);
    let program = ProgramHash(reader.hash()?);
    let through_tick = reader.u32(Field::Event)?;
    let count = reader.count(MAX_CASES, Field::Count)?;
    let mut cases = Vec::with_capacity(count);
    for _ in 0..count {
        cases.push(CaseCheckpoint {
            state: StateHash(reader.hash()?),
            trace: reader.hash()?,
            ledger_total: reader.u64(Field::Ledger)?,
            status: get_status(&mut reader)?,
        });
    }
    let work = WorkSummary {
        useful: reader.u64(Field::Ledger)?,
        total: reader.u64(Field::Ledger)?,
    };
    reader.finish()?;
    Ok(Checkpoint {
        session,
        ledger,
        parent,
        segment,
        segment_manifest,
        program,
        through_tick,
        cases,
        work,
    })
}

// ---------------------------------------------------------------------------
// Settlement
// ---------------------------------------------------------------------------

/// Why a session ended without a result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
#[allow(missing_docs)]
pub enum ForkReason {
    CompetingSeals = 1,
    Equivocation = 2,
    RevealMissing = 3,
    MemberMissing = 4,
    BudgetExhausted = 5,
    ReplayMismatch = 6,
    HostSilent = 7,
    Cancelled = 8,
}

impl ForkReason {
    fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::CompetingSeals,
            2 => Self::Equivocation,
            3 => Self::RevealMissing,
            4 => Self::MemberMissing,
            5 => Self::BudgetExhausted,
            6 => Self::ReplayMismatch,
            7 => Self::HostSilent,
            8 => Self::Cancelled,
            _ => return None,
        })
    }
}

/// A session's end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Settlement {
    /// A reproduced result.
    Result {
        /// Session.
        session: SessionKey,
        /// Final epoch.
        epoch: Epoch,
        /// Final checkpoint.
        checkpoint: CheckpointHash,
        /// Receipt bound to `challenge_id = SessionKey`, `subject_key = host`.
        receipt: ClaimedReceipt,
        /// Whether the contract passed.
        passed: bool,
    },
    /// An explicit unresolved fork.
    Unresolved {
        /// Session.
        session: SessionKey,
        /// Epoch.
        epoch: Epoch,
        /// Why.
        reason: ForkReason,
        /// At most four heads.
        heads: Vec<[u8; 32]>,
        /// At most eight evidence digests.
        evidence: Vec<[u8; 32]>,
    },
}

/// Canonical bytes of a settlement.
#[must_use]
pub fn encode_settlement(settlement: &Settlement) -> Vec<u8> {
    let mut writer = Writer::with_capacity(MAX_SETTLEMENT_BYTES);
    writer.u8(VERSION);
    match settlement {
        Settlement::Result {
            session,
            epoch,
            checkpoint,
            receipt,
            passed,
        } => {
            writer.u8(1);
            writer.bytes(&session.0);
            writer.u64(epoch.0);
            writer.bytes(&checkpoint.0);
            writer.bytes(&receipt.encode());
            writer.bool(*passed);
        }
        Settlement::Unresolved {
            session,
            epoch,
            reason,
            heads,
            evidence,
        } => {
            writer.u8(2);
            writer.bytes(&session.0);
            writer.u64(epoch.0);
            writer.u8(*reason as u8);
            writer.u8(heads.len() as u8);
            for head in heads {
                writer.bytes(head);
            }
            writer.u8(evidence.len() as u8);
            for digest in evidence {
                writer.bytes(digest);
            }
        }
    }
    writer.finish()
}

/// Decodes a settlement; it is data until the receiver resolves it.
pub fn decode_settlement(raw: &[u8]) -> Result<Settlement, CodecError> {
    let mut reader = Reader::bounded(raw, MAX_SETTLEMENT_BYTES)?;
    version(&mut reader)?;
    let settlement = match reader.u8(Field::Status)? {
        1 => {
            let session = SessionKey(reader.hash()?);
            let epoch = Epoch(reader.u64(Field::Value)?);
            let checkpoint = CheckpointHash(reader.hash()?);
            let mut bytes = [0_u8; RECEIPT_BYTES];
            for byte in &mut bytes {
                *byte = reader.u8(Field::Hash)?;
            }
            let receipt = ClaimedReceipt::decode(&bytes)?;
            Settlement::Result {
                session,
                epoch,
                checkpoint,
                receipt,
                passed: reader.bool(Field::Bool)?,
            }
        }
        2 => {
            let session = SessionKey(reader.hash()?);
            let epoch = Epoch(reader.u64(Field::Value)?);
            let found = reader.u8(Field::Status)?;
            let reason = ForkReason::from_u8(found).ok_or(CodecError::Discriminant {
                field: Field::Status,
                found,
            })?;
            let heads = hashes(&mut reader, MAX_FORK_HEADS)?;
            let evidence = hashes(&mut reader, MAX_FORK_EVIDENCE)?;
            Settlement::Unresolved {
                session,
                epoch,
                reason,
                heads,
                evidence,
            }
        }
        found => {
            return Err(CodecError::Discriminant {
                field: Field::Status,
                found,
            })
        }
    };
    reader.finish()?;
    Ok(settlement)
}

// ---------------------------------------------------------------------------
// Artifacts
// ---------------------------------------------------------------------------

/// A request for one inner artifact's bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArtifactRequest {
    /// Session.
    pub session: SessionKey,
    /// Which artifact.
    pub id: InnerArtifactId,
    /// At most `MAX_ARTIFACT_BYTES`.
    pub max_bytes: u64,
    /// Requester nonce.
    pub nonce: [u8; 32],
}

/// The holder's description of an artifact's blocks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactManifest {
    /// Which artifact.
    pub id: InnerArtifactId,
    /// Total bytes.
    pub total_len: u64,
    /// Always [`BLOCK_LEN`].
    pub block_len: u32,
    /// Plain SHA-256 of each block, at most [`MAX_BLOCKS`].
    pub blocks: Vec<[u8; 32]>,
    /// Must equal `total_len` (no compression in v1).
    pub decompressed_len: u64,
}

impl ArtifactManifest {
    /// The manifest identity.
    #[must_use]
    pub fn hash(&self) -> ArtifactManifestHash {
        ArtifactManifestHash::of(&encode_artifact_manifest(self))
    }
}

/// One block of an artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    /// The artifact manifest this block belongs to.
    pub manifest: ArtifactManifestHash,
    /// Block index.
    pub index: u8,
    /// Must equal `index * block_len`.
    pub offset: u64,
    /// At most [`BLOCK_LEN`] bytes.
    pub bytes: Vec<u8>,
}

/// Canonical bytes of an artifact request.
#[must_use]
pub fn encode_artifact_request(request: &ArtifactRequest) -> Vec<u8> {
    let mut writer = Writer::with_capacity(MAX_ARTIFACT_REQUEST_BYTES);
    writer.u8(VERSION);
    writer.bytes(&request.session.0);
    put_inner_id(&mut writer, request.id);
    writer.u64(request.max_bytes);
    writer.bytes(&request.nonce);
    writer.finish()
}

/// Decodes an artifact request.
pub fn decode_artifact_request(raw: &[u8]) -> Result<ArtifactRequest, CodecError> {
    let mut reader = Reader::bounded(raw, MAX_ARTIFACT_REQUEST_BYTES)?;
    version(&mut reader)?;
    let request = ArtifactRequest {
        session: SessionKey(reader.hash()?),
        id: get_inner_id(&mut reader)?,
        max_bytes: reader.u64(Field::Value)?,
        nonce: reader.hash()?,
    };
    reader.finish()?;
    Ok(request)
}

/// Canonical bytes of an artifact manifest.
#[must_use]
pub fn encode_artifact_manifest(manifest: &ArtifactManifest) -> Vec<u8> {
    let mut writer = Writer::with_capacity(MAX_ARTIFACT_MANIFEST_BYTES);
    writer.u8(VERSION);
    put_inner_id(&mut writer, manifest.id);
    writer.u64(manifest.total_len);
    writer.u32(manifest.block_len);
    writer.u8(manifest.blocks.len() as u8);
    for block in &manifest.blocks {
        writer.bytes(block);
    }
    writer.u64(manifest.decompressed_len);
    writer.finish()
}

/// Decodes an artifact manifest.
pub fn decode_artifact_manifest(raw: &[u8]) -> Result<ArtifactManifest, CodecError> {
    let mut reader = Reader::bounded(raw, MAX_ARTIFACT_MANIFEST_BYTES)?;
    version(&mut reader)?;
    let id = get_inner_id(&mut reader)?;
    let total_len = reader.u64(Field::Value)?;
    let block_len = reader.u32(Field::Value)?;
    let blocks = hashes(&mut reader, MAX_BLOCKS)?;
    let decompressed_len = reader.u64(Field::Value)?;
    reader.finish()?;
    Ok(ArtifactManifest {
        id,
        total_len,
        block_len,
        blocks,
        decompressed_len,
    })
}

/// Canonical bytes of a block.
#[must_use]
pub fn encode_block(block: &Block) -> Vec<u8> {
    let mut writer = Writer::with_capacity(46 + block.bytes.len());
    writer.u8(VERSION);
    writer.bytes(&block.manifest.0);
    writer.u8(block.index);
    writer.u64(block.offset);
    writer.u32(block.bytes.len() as u32);
    writer.bytes(&block.bytes);
    writer.finish()
}

/// Decodes a block.
pub fn decode_block(raw: &[u8]) -> Result<Block, CodecError> {
    let mut reader = Reader::bounded(raw, MAX_BLOCK_BYTES)?;
    version(&mut reader)?;
    let manifest = ArtifactManifestHash(reader.hash()?);
    let index = reader.u8(Field::Count)?;
    let offset = reader.u64(Field::Value)?;
    let len = reader.u32(Field::Count)?;
    if len > BLOCK_LEN {
        return Err(CodecError::Bound {
            field: Field::Count,
        });
    }
    let mut bytes = Vec::with_capacity(len as usize);
    for _ in 0..len {
        bytes.push(reader.u8(Field::Cell)?);
    }
    reader.finish()?;
    Ok(Block {
        manifest,
        index,
        offset,
        bytes,
    })
}
